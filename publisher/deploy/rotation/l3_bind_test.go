package rotation

// THE GUEST-OS HALF OF AN ADDRESS SWAP.
//
// Attaching a floating IP routes packets to the server at the provider's
// network layer; the operating system does not reply on the address
// until it is configured on an interface. Measured on real hardware
// 2026-08-17: the cloud API reported the address attached with both
// ownership labels while a TLS probe to it timed out and the old address
// kept serving.
//
// So an L3 has an extra step, and the ORDER of it is the whole
// correctness argument:
//
//	attach → BIND → verify → sign → store → UNBIND OLD → release OLD
//
// Each test below breaks exactly one link of that chain.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// seq records every side-effecting step in the order it happened, so
// "bind before verify" and "unbind before release" are assertions on one
// list rather than three booleans.
type seq struct {
	steps []string
}

func (s *seq) add(step string) { s.steps = append(s.steps, step) }

func (s *seq) joined() string { return strings.Join(s.steps, "|") }

// seqProvider is a mockProvider that logs its address calls into a
// shared sequence.
type seqProvider struct {
	*mockProvider
	s *seq
}

func (p *seqProvider) AssignFloatingIP(ctx context.Context, rec *provider.OperatorRecord, fipID string) error {
	p.s.add("attach " + fipID)
	return p.mockProvider.AssignFloatingIP(ctx, rec, fipID)
}

func (p *seqProvider) ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, id string) (bool, error) {
	p.s.add("release " + id)
	return p.mockProvider.ReleaseFloatingIP(ctx, rec, id)
}

// bindExecutor wires an executor whose bind/verify/store steps all log
// into s. bindErr and verifyErr inject the two failures that matter.
func bindExecutor(t *testing.T, s *seq, bindErr, verifyErr error) (*Executor, *seqProvider, *memStore) {
	t.Helper()
	prov := &seqProvider{mockProvider: &mockProvider{releaseOwned: true}, s: s}
	st := &memStore{}
	clk := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	exec := newExecutor(prov, &mockBinder{res: okBinderRes()}, st, clk)
	exec.BindAddress = func(_ context.Context, _ *provider.OperatorRecord, controlIP, target net.IP) error {
		s.add("bind " + target.String() + " via " + controlIP.String())
		return bindErr
	}
	exec.UnbindAddress = func(_ context.Context, _ *provider.OperatorRecord, controlIP, target net.IP) error {
		s.add("unbind " + target.String() + " via " + controlIP.String())
		return nil
	}
	exec.VerifyReachable = func(_ context.Context, rec *provider.OperatorRecord) error {
		s.add("verify " + rec.PublicIP.String())
		return verifyErr
	}
	return exec, prov, st
}

// THE ORDERING. The bind goes after the attach (there is nothing to bind
// before it) and before the verify (the bind is what makes the address
// answer), and the record is only committed after both. The old address
// is unbound before it is released, and both happen after the commit.
func TestL3_BindHappensAfterTheAttachAndBeforeTheProbe(t *testing.T) {
	s := &seq{}
	exec, _, st := bindExecutor(t, s, nil, nil)
	rec := newRecord("fip-old")
	prior := rec.PublicIP.String()

	res, err := rotateL3(t, exec, rec, "fip-new")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	newIP := rec.PublicIP.String()
	want := "attach fip-new|bind " + newIP + " via " + prior + "|verify " + newIP +
		"|unbind " + prior + " via " + newIP + "|release fip-old"
	if s.joined() != want {
		t.Fatalf("order =\n  %s\nwant\n  %s", s.joined(), want)
	}
	if st.committed != 1 {
		t.Errorf("commits = %d, want 1", st.committed)
	}
	if !res.L3.PriorReleased {
		t.Error("the prior address should be reported released")
	}
	if len(res.L3.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.L3.Warnings)
	}
}

// The bind travels over the address the relay still ANSWERS on. Sending
// it to the new address would deadlock the swap on itself: the request
// that brings an address up cannot be delivered over the address it is
// bringing up.
func TestL3_BindTravelsOverThePreSwapAddress(t *testing.T) {
	s := &seq{}
	exec, _, _ := bindExecutor(t, s, nil, nil)
	rec := newRecord("fip-old")
	prior := rec.PublicIP.String()

	var control, target net.IP
	exec.BindAddress = func(_ context.Context, _ *provider.OperatorRecord, c, tgt net.IP) error {
		control, target = c, tgt
		return nil
	}
	if _, err := rotateL3(t, exec, rec, "fip-new"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if control.String() != prior {
		t.Errorf("bind delivered over %s, want the pre-swap %s", control, prior)
	}
	if target.String() != rec.PublicIP.String() {
		t.Errorf("bind target = %s, want the new address %s", target, rec.PublicIP)
	}
}

// A relay that will not configure the address is a relay that will never
// answer on it. Nothing may be signed or committed, the record goes back
// to the address that works, and the address we reserved is handed back.
func TestL3_BindFailureUnwindsTheSwapCompletely(t *testing.T) {
	s := &seq{}
	exec, prov, st := bindExecutor(t, s, errors.New("relay refused: ip addr add failed"), nil)
	rec := newRecord("fip-old")
	prior := rec.PublicIP.String()

	_, err := rotateL3(t, exec, rec, "fip-new")
	if err == nil {
		t.Fatal("a relay that did not bind the address must fail the rotation")
	}
	if b, ok := exec.Binder.(*mockBinder); ok && b.calls != 0 {
		t.Errorf("Bind ran %d times; no pack may be signed against an address the relay will not answer on", b.calls)
	}
	if st.committed != 0 {
		t.Errorf("committed %d rows, want 0", st.committed)
	}
	if rec.PublicIP.String() != prior {
		t.Errorf("record left on %s, want the pre-swap %s", rec.PublicIP, prior)
	}
	if rec.FloatingIPID != "fip-old" {
		t.Errorf("record.FloatingIPID = %s, want the pre-swap fip-old", rec.FloatingIPID)
	}
	if err := CheckRecordAddressConsistent(rec); err != nil {
		t.Errorf("record left inconsistent: %v", err)
	}
	// The verify never ran — there was nothing to verify.
	for _, step := range s.steps {
		if strings.HasPrefix(step, "verify") {
			t.Errorf("probed an address the relay never bound: %v", s.steps)
		}
	}
	// The old address is NOT released: the relay never moved off it.
	if len(prov.releasedIDs) != 0 && prov.releasedIDs[0] == "fip-old" {
		t.Errorf("released the address the relay is still serving on: %v", prov.releasedIDs)
	}
}

// The bind reports success and the probe still fails: the exact shape of
// the 2026-08-17 finding, one layer down. The address must come back off
// the relay's interface, or the box keeps sourcing traffic from an
// address its record no longer names.
func TestL3_ProbeFailureUnbindsWhatTheBindPutThere(t *testing.T) {
	s := &seq{}
	exec, _, st := bindExecutor(t, s, nil, errors.New("l3: the new address does not serve"))
	rec := newRecord("fip-old")
	prior := rec.PublicIP.String()

	if _, err := rotateL3(t, exec, rec, "fip-new"); err == nil {
		t.Fatal("an address that does not serve must fail the rotation")
	}
	var unbound string
	for _, step := range s.steps {
		if strings.HasPrefix(step, "unbind") {
			unbound = step
		}
	}
	if unbound == "" {
		t.Fatalf("the failed swap left the address on the relay's interface: %v", s.steps)
	}
	if st.committed != 0 {
		t.Errorf("committed %d rows, want 0", st.committed)
	}
	if rec.PublicIP.String() != prior {
		t.Errorf("record left on %s, want the pre-swap %s", rec.PublicIP, prior)
	}
}

// An address handed back to the provider pool while a live box still has
// it configured is one another customer may be issued tomorrow, with our
// relay still sourcing traffic from it. So a failed unbind stops the
// release: the address stays reserved, visibly billing, and the operator
// is told.
func TestL3_AFailedUnbindStopsTheReleaseAndSaysWhy(t *testing.T) {
	s := &seq{}
	exec, prov, _ := bindExecutor(t, s, nil, nil)
	exec.UnbindAddress = func(_ context.Context, _ *provider.OperatorRecord, _, target net.IP) error {
		s.add("unbind " + target.String())
		return errors.New("relay says it is still on eth0")
	}

	res, err := rotateL3(t, exec, newRecord("fip-old"), "fip-new")
	if err != nil {
		t.Fatalf("a failed unbind must not fail a committed rotation: %v", err)
	}
	if len(prov.releasedIDs) != 0 {
		t.Errorf("released %v while the relay still claims the address", prov.releasedIDs)
	}
	if res.L3.PriorReleased {
		t.Error("outcome claims the prior address was released")
	}
	if len(res.L3.Warnings) == 0 {
		t.Fatal("a retained, billing address must be reported")
	}
	if !strings.Contains(res.L3.Warnings[0], "still billing") {
		t.Errorf("warning does not name the cost: %q", res.L3.Warnings[0])
	}
}

// An executor that can PUT addresses on a relay and cannot take them off
// is asymmetrically wired, and it is the shape that quietly accumulates
// addresses claimed by boxes that no longer own them. It must not
// release.
func TestL3_ABindSeamWithoutAnUnbindSeamRefusesToRelease(t *testing.T) {
	s := &seq{}
	exec, prov, _ := bindExecutor(t, s, nil, nil)
	exec.UnbindAddress = nil

	res, err := rotateL3(t, exec, newRecord("fip-old"), "fip-new")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(prov.releasedIDs) != 0 {
		t.Errorf("released %v with no way to tell the relay to drop it", prov.releasedIDs)
	}
	if len(res.L3.Warnings) == 0 {
		t.Fatal("the retained address must be reported")
	}
}
