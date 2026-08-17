package cli

// THE L3 SWAP, END TO END, ON THE SEAM THAT ACTUALLY SHIPS.
//
// The wizard drives L3 by shelling out to `daal-deploy floating-ip
// assign` / `floating-ip release`, so a guard that is not on these two
// verbs is on no path a user can reach. What these tests hold down is
// the ORDER, because every ordering mistake here has a distinct and
// expensive failure:
//
//   - capability probe after the attach ⇒ a reserved, billing address
//     attached to a relay that can never answer on it;
//   - bind after the probe ⇒ the probe always fails (the 2026-08-17
//     hardware finding, made permanent);
//   - bind over the NEW address ⇒ the request that brings an address up
//     is delivered over the address it is bringing up, and never
//     arrives;
//   - commit before the probe ⇒ every pack re-signed onto a dead
//     address, reported as success;
//   - release before unbind ⇒ an address handed back to the provider
//     pool while a live box still claims it locally.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/publisher/deploy/health"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
)

// THE ORDERING ASSERTION. capabilities → bind → probe, and the record
// is only written after all three.
func TestAssignFIP_ProbesTheBoxThenBindsThenChecksItAnswers(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}

	want := []string{"capabilities", "reserve", "attach fip-reserved", "bind 203.0.113.5", "probe 203.0.113.5"}
	if strings.Join(box.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("call order = %v, want %v", box.calls, want)
	}
	// The bind travelled over the address the relay still answers on,
	// not the one it is bringing up.
	if len(box.bound) != 1 || box.bound[0][0] != "198.51.100.7" || box.bound[0][1] != "203.0.113.5" {
		t.Errorf("bind (control,target) = %v, want [198.51.100.7 203.0.113.5]", box.bound)
	}
	// And only then is the record written.
	body, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["public_ip"] != "203.0.113.5" {
		t.Errorf("record public_ip = %v after a successful swap", wire["public_ip"])
	}
}

// A relay whose pinned mgmt binary predates the bind endpoint can never
// answer on a floating IP. It must be refused BEFORE anything is
// reserved or attached: the operator should not be billed for an address
// in order to discover this, and an attached address on a box that
// ignores it is a relay that looks healthy and is not.
func TestAssignFIP_RefusesAnOlderBoxBeforeTouchingTheCloud(t *testing.T) {
	box := newFakeBox()
	// The Step-7 shape: split rotation, no address binding.
	box.caps = &mgmt.BoxCapabilities{
		OK:             true,
		MgmtAPIVersion: mgmt.MgmtAPIVersionSplitRotation,
		Capabilities:   []string{mgmt.CapRotateCredentialsScoped, mgmt.CapRotateTLSScoped},
	}
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)
	before, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr)
	if rc != exitCapabilityUnsupported {
		t.Fatalf("rc=%d, want %d (terminal for this relay, not a retry)", rc, exitCapabilityUnsupported)
	}
	if f.created != 0 {
		t.Errorf("reserved %d addresses for a relay that can never answer on one", f.created)
	}
	if len(f.assigned) != 0 {
		t.Errorf("attached %v to a relay that cannot bind it", f.assigned)
	}
	if len(box.calls) != 1 || box.calls[0] != "capabilities" {
		t.Errorf("calls = %v, want the probe and nothing else", box.calls)
	}
	// The operator has to be told what to DO, not just that it failed.
	for _, want := range []string{"interface", "Re-release daal-relay-mgmt", "reprovision"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("refusal does not mention %q: %s", want, stderr.String())
		}
	}
	after, _ := os.ReadFile(recordFile)
	if string(after) != string(before) {
		t.Error("the record was rewritten despite the refusal")
	}
}

// A bind that fails leaves an address reserved and attached for no
// reason. Give it back — the same leak class as an orphaned server —
// and do not write the record.
func TestAssignFIP_ReservedAddressIsReturnedWhenTheBindFails(t *testing.T) {
	box := newFakeBox()
	box.bindErr = errors.New("ip addr add: RTNETLINK answers: permission denied")
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)
	before, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("a relay that did not bind the address must not exit 0")
	}
	if len(f.released) != 1 || f.released[0] != "fip-reserved" {
		t.Errorf("released = %v, want the reserved address handed back", f.released)
	}
	// The probe never ran: there was nothing to probe.
	for _, c := range box.calls {
		if strings.HasPrefix(c, "probe") {
			t.Errorf("probed an address the relay never bound: %v", box.calls)
		}
	}
	after, _ := os.ReadFile(recordFile)
	if string(after) != string(before) {
		t.Error("the record was rewritten despite the failed bind")
	}
}

// The probe is what proves the bind actually worked, and it stays even
// though the box reported success — the whole hardware finding was a
// case where every layer that could report success did. When it fails
// the bind must be undone: an address left on the interface of a relay
// whose record no longer names it is one the box will still source
// traffic from.
func TestAssignFIP_UnbindsAndGivesBackWhenTheAddressDoesNotServe(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	prev := l3AddressServes
	l3AddressServes = func(ip net.IP, _ int, _ time.Duration) error {
		box.calls = append(box.calls, "probe "+ip.String())
		return errors.New("l3: the new address does not serve: timeout")
	}
	t.Cleanup(func() { l3AddressServes = prev })

	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("an address the relay does not answer on must not be committed")
	}
	want := []string{"capabilities", "reserve", "attach fip-reserved", "bind 203.0.113.5",
		"probe 203.0.113.5", "unbind 203.0.113.5", "release fip-reserved"}
	if strings.Join(box.calls, "|") != strings.Join(want, "|") {
		t.Errorf("call order = %v, want %v", box.calls, want)
	}
	if len(f.released) != 1 || f.released[0] != "fip-reserved" {
		t.Errorf("released = %v, want the reserved address handed back", f.released)
	}
}

// The bind cannot be delivered over the address it is bringing up, so a
// record with no working address is a record this verb cannot act on.
// Better to say so than to attach an address and then discover there is
// no route to ask the box about it.
func TestAssignFIP_RefusesARecordWithNoWorkingAddress(t *testing.T) {
	withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	// Strip the address the relay currently answers on.
	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.PublicIP = nil
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(stderr.String(), "no working address") {
		t.Errorf("the refusal does not name the problem: %q", stderr.String())
	}
	if len(f.released) != 1 {
		t.Errorf("released = %v, want the reserved address handed back", f.released)
	}
}

// The verb cannot finish without the signing material, and it says so
// before it reserves anything rather than after it has attached an
// address the box will never answer on.
func TestAssignFIP_RefusesWithoutTheSigningMaterial(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true}
	withFakeProvider(t, f)
	recordFile, tokenFile, _ := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "assign", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr)
	if rc != 2 {
		t.Fatalf("rc=%d, want 2 (bad flags)", rc)
	}
	if f.created != 0 || len(f.assigned) != 0 || len(box.calls) != 0 {
		t.Errorf("a flag error touched the cloud: created=%d assigned=%v calls=%v", f.created, f.assigned, box.calls)
	}
	if !strings.Contains(stderr.String(), "--priv-key") || !strings.Contains(stderr.String(), "--helper-ip") {
		t.Errorf("the error does not name the missing flags: %q", stderr.String())
	}
}

// --- release -------------------------------------------------------

// UNBIND THEN RELEASE. A released address goes back to the provider's
// pool and may be issued to another customer tomorrow; a box that still
// has it configured keeps choosing it as a source address for its own
// traffic. The detach comes first so the record has fallen back to an
// address that survives the unbind.
func TestReleaseFIP_UnbindsBeforeHandingTheAddressBack(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	// The record is on the floating IP being released.
	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-old"
	rec.PublicIP = net.ParseIP("203.0.113.9")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if len(box.unbound) != 1 || box.unbound[0][1] != "203.0.113.9" {
		t.Fatalf("unbound = %v, want the address being released", box.unbound)
	}
	want := []string{"detach", "unbind 203.0.113.9", "release fip-old"}
	if strings.Join(box.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("call order = %v, want %v — the relay must be told to drop the address BEFORE it goes back to the provider pool", box.calls, want)
	}
	if len(f.released) != 1 || f.released[0] != "fip-old" {
		t.Errorf("released = %v", f.released)
	}
	// The unbind travelled over the address the record fell back to,
	// never over the address it was removing.
	if box.unbound[0][0] == "203.0.113.9" {
		t.Error("the unbind was delivered over the address it removes")
	}
}

// An unbind that fails stops the release. The address stays reserved
// (costing money, visibly) rather than being handed to a stranger while
// a live box still claims it.
func TestReleaseFIP_DoesNotHandBackAnAddressTheRelayStillClaims(t *testing.T) {
	box := newFakeBox()
	box.unbindErr = errors.New("relay says the address is still on eth0")
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-old"
	rec.PublicIP = net.ParseIP("203.0.113.9")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("a failed unbind must not report a clean release")
	}
	if len(f.released) != 0 {
		t.Errorf("released = %v, want nothing handed back while the relay still claims the address", f.released)
	}
	if !strings.Contains(stderr.String(), "still billing") || !strings.Contains(stderr.String(), "--skip-unbind") {
		t.Errorf("the operator is not told the cost or the way out: %q", stderr.String())
	}
}

// A relay too old to bind never bound anything, so there is nothing to
// remove and the release is safe. Refusing here would strand an address
// on every relay provisioned before this wave.
func TestReleaseFIP_ReleasesAnywayWhenTheRelayIsTooOldToHaveBound(t *testing.T) {
	box := newFakeBox()
	box.unbindErr = mgmt.ErrCapabilityUnsupported
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-old"
	rec.PublicIP = net.ParseIP("203.0.113.9")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if len(f.released) != 1 || f.released[0] != "fip-old" {
		t.Errorf("released = %v, want the address given back", f.released)
	}
}

// --skip-unbind is for a relay that is already gone. It must say out
// loud what it is trading away, because on a LIVE box it hands an
// address back to the pool while the box still claims it.
func TestReleaseFIP_SkipUnbindNeedsNoKeyAndWarns(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, _ := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--fip-id", "fip-orphan", "--skip-unbind"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if len(box.unbound) != 0 {
		t.Errorf("--skip-unbind still called the box: %v", box.unbound)
	}
	if !strings.Contains(stderr.String(), "--skip-unbind") {
		t.Errorf("the trade is not stated: %q", stderr.String())
	}
}

// `unassign` leaves the address reserved to this operator, so nobody
// else can be issued it — the leftover binding only costs this relay a
// stale outbound source address. That is worth saying out loud when the
// caller cannot fix it here, and worth fixing when they can.
func TestUnassignFIP_SaysWhenTheRelayStillHoldsTheAddress(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-old"
	rec.PublicIP = net.ParseIP("203.0.113.9")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without the signing material: detach, and say what is left behind.
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"floating-ip", "unassign", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if len(box.unbound) != 0 {
		t.Errorf("unbound without a key: %v", box.unbound)
	}
	if !strings.Contains(stderr.String(), "still configured on the box") {
		t.Errorf("the leftover binding was not reported: %q", stderr.String())
	}

	// With it: drop the address on the relay too.
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if rc := Run([]string{"floating-ip", "unassign", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if len(box.unbound) != 1 || box.unbound[0][1] != "203.0.113.9" {
		t.Errorf("unbound = %v, want the detached address", box.unbound)
	}
}

// --- the rotation-shaped release ------------------------------------
//
// THE SHAPE EVERY SECOND-AND-LATER L3 ACTUALLY HAS, and the one the
// first round of these tests missed by giving the record the id it was
// releasing.
//
// The wizard swaps the address, writes the record with the swap's
// OUTPUT (the NEW id and the NEW address), and only then releases the
// PRIOR id. So `--fip-id` and the record disagree by construction, the
// address being released is nowhere in the record, and the release used
// to resolve nothing, warn on stderr and hand the address back to the
// provider — unbinding nothing. The old address stayed configured on
// eth0 with a live persistence record re-asserted at every reboot,
// while the provider was free to issue it to another customer; four of
// those and the box's 4-address cap kills L3 on that relay for good.

// The prior address is named by --fip-address, so it IS unbound, and
// the order is still unbind-then-release.
func TestReleaseFIP_UnbindsThePriorAddressGivenOnTheFlag(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	// The record is on the NEW address, exactly as rotate_execute_inner
	// leaves it before the release leg runs.
	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-new"
	rec.PublicIP = net.ParseIP("203.0.113.5")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4",
		"--fip-id", "fip-old", "--fip-address", "203.0.113.9"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if len(box.unbound) != 1 || box.unbound[0][1] != "203.0.113.9" {
		t.Fatalf("unbound = %v, want the PRIOR address 203.0.113.9", box.unbound)
	}
	// Delivered over the address the relay is on now, never over the
	// one being removed.
	if box.unbound[0][0] != "203.0.113.5" {
		t.Errorf("unbind travelled over %s, want the current address", box.unbound[0][0])
	}
	want := []string{"unbind 203.0.113.9", "release fip-old"}
	if strings.Join(box.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("call order = %v, want %v", box.calls, want)
	}
	if len(f.released) != 1 || f.released[0] != "fip-old" {
		t.Errorf("released = %v", f.released)
	}
}

// And with no way to resolve the address, the release REFUSES. This is
// the branch that used to be a warning followed by a release; a warning
// on stderr does not stop an address a live box still holds from being
// issued to somebody else.
func TestReleaseFIP_RefusesWhenTheAddressCannotBeResolved(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-new"
	rec.PublicIP = net.ParseIP("203.0.113.5")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4", "--fip-id", "fip-old"}, &stdout, &stderr)
	if rc != 2 {
		t.Fatalf("rc=%d, want 2 — an address that cannot be unbound must not be handed back", rc)
	}
	if len(f.released) != 0 {
		t.Errorf("released = %v while the relay was never told to drop it", f.released)
	}
	if len(box.unbound) != 0 {
		t.Errorf("unbound = %v", box.unbound)
	}
	for _, want := range []string{"--fip-address", "--skip-unbind"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the refusal does not offer %s: %q", want, stderr.String())
		}
	}
}

// A --fip-address that contradicts the record is a caller confused
// about which address it is operating on, and one of the two is about
// to be acted on wrongly.
func TestReleaseFIP_RefusesAnAddressThatContradictsTheRecord(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.FloatingIPID = "fip-old"
	rec.PublicIP = net.ParseIP("203.0.113.9")
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4",
		"--fip-id", "fip-old", "--fip-address", "203.0.113.77"}, &stdout, &stderr)
	if rc != 2 {
		t.Fatalf("rc=%d, want 2", rc)
	}
	if len(f.released) != 0 || len(box.unbound) != 0 {
		t.Errorf("acted on a contradiction: released=%v unbound=%v", f.released, box.unbound)
	}
}

// THE ROLLBACK OF A FAILED SWAP MUST NOT GIVE THE ADDRESS AWAY EITHER.
//
// `giveBack` does not merely detach — it DELETES the reservation, so
// the address goes into the provider's pool for another customer. When
// the probe fails the CLI unbinds first; if that unbind fails, the box
// may still hold the address, and deleting the reservation then is the
// same harm the release path refuses to commit. It stays reserved,
// billing, with the id printed.
func TestAssignFIP_KeepsTheAddressReservedWhenTheRollbackUnbindFails(t *testing.T) {
	box := newFakeBox()
	box.unbindErr = errors.New("relay says: RTNETLINK answers: Operation not permitted")
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	prev := l3AddressServes
	l3AddressServes = func(ip net.IP, _ int, _ time.Duration) error {
		box.calls = append(box.calls, "probe "+ip.String())
		return errors.New("dial tcp 203.0.113.5:443: i/o timeout: the relay does not serve there")
	}
	t.Cleanup(func() { l3AddressServes = prev })
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("an unreachable address must not be committed")
	}
	if len(f.released) != 0 {
		t.Fatalf("released = %v — the address went back to the provider pool while the relay may still hold it", f.released)
	}
	for _, want := range []string{"still reserved and still billing", "--fip-address"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the operator is not told %q: %s", want, stderr.String())
		}
	}
}

// The same rollback with a WORKING unbind still gives the address back:
// nothing is holding it, so leaving it on the bill would be the wrong
// trade.
func TestAssignFIP_HandsTheAddressBackWhenTheRollbackUnbindSucceeds(t *testing.T) {
	box := newFakeBox()
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	prev := l3AddressServes
	l3AddressServes = func(ip net.IP, _ int, _ time.Duration) error {
		box.calls = append(box.calls, "probe "+ip.String())
		return errors.New("the relay does not serve there")
	}
	t.Cleanup(func() { l3AddressServes = prev })
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("an unreachable address must not be committed")
	}
	if len(f.released) != 1 || f.released[0] != "fip-reserved" {
		t.Errorf("released = %v, want the reserved address handed back", f.released)
	}
}

// --- the ordering, proved CAUSALLY rather than by transcript --------
//
// Every other ordering test here reads a list of recorded calls, which
// proves the CLI made them in that order and nothing more. This one
// makes the reachability post-condition a REAL dial against a REAL
// local listener that does not exist until the box is told to bind, so
// "bind before probe" is enforced by the network rather than by an
// assertion on a slice. It is the closest this suite gets to the
// hardware finding of 2026-08-17, where every layer reported success
// and the box answered on nothing.
func TestAssignFIP_TheProbeIsARealDialThatOnlyPassesAfterTheBind(t *testing.T) {
	// A port nothing is listening on yet.
	seed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := seed.Addr().(*net.TCPAddr).Port
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	box := newFakeBox()
	withFakeBox(t, box)
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)

	var mu sync.Mutex
	var ln net.Listener
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
	})

	prevBind, prevServes := l3BindAddress, l3AddressServes
	// THE GUEST-OS HALF, simulated honestly: the address starts
	// answering only because the box was told to configure it.
	l3BindAddress = func(_ context.Context, _ provider.Provider, _ *provider.OperatorRecord, _ ed25519.PrivateKey, _ string, controlIP, target net.IP) (*mgmt.BindAddressResp, error) {
		box.calls = append(box.calls, "bind "+target.String())
		box.bound = append(box.bound, [2]string{controlIP.String(), target.String()})
		mu.Lock()
		defer mu.Unlock()
		l, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if lerr != nil {
			return nil, lerr
		}
		ln = l
		return &mgmt.BindAddressResp{IP: target.String(), Persisted: true, Interface: "eth0"}, nil
	}
	// The real prober, pointed at the loopback stand-in for the relay's
	// new address. No stub: this dials.
	l3AddressServes = func(ip net.IP, _ int, timeout time.Duration) error {
		box.calls = append(box.calls, "probe "+ip.String())
		return health.AddressServes(net.ParseIP("127.0.0.1"), port, timeout)
	}
	t.Cleanup(func() { l3BindAddress, l3AddressServes = prevBind, prevServes })

	recordFile, tokenFile, keyFile := l3Fixture(t)
	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	want := []string{"capabilities", "reserve", "attach fip-reserved", "bind 203.0.113.5", "probe 203.0.113.5"}
	if strings.Join(box.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("call order = %v, want %v", box.calls, want)
	}
}

// The same rig with a bind that LIES — it reports success and the
// address still answers nowhere. That is the 2026-08-17 hardware
// finding exactly, and it must not commit: the swap fails, the box is
// told to drop the address, and the reservation goes back.
func TestAssignFIP_ABindThatClaimsSuccessAndAnswersNowhereIsRefused(t *testing.T) {
	seed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := seed.Addr().(*net.TCPAddr).Port
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	box := withFakeBox(t, newFakeBox()) // its bind reports success and opens nothing
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, box: box}
	withFakeProvider(t, f)
	prev := l3AddressServes
	l3AddressServes = func(ip net.IP, _ int, timeout time.Duration) error {
		box.calls = append(box.calls, "probe "+ip.String())
		return health.AddressServes(net.ParseIP("127.0.0.1"), port, timeout)
	}
	t.Cleanup(func() { l3AddressServes = prev })

	recordFile, tokenFile, keyFile := l3Fixture(t)
	before, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("a relay that answers on nothing was committed")
	}
	if len(box.unbound) != 1 || box.unbound[0][1] != "203.0.113.5" {
		t.Errorf("unbound = %v, want the address dropped again", box.unbound)
	}
	if len(f.released) != 1 || f.released[0] != "fip-reserved" {
		t.Errorf("released = %v, want the reservation handed back", f.released)
	}
	after, _ := os.ReadFile(recordFile)
	if string(after) != string(before) {
		t.Error("the record was rewritten for a swap that never worked")
	}
}
