package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// --- test harness ------------------------------------------------------

// fakeIface is an in-memory stand-in for a network interface.
//
// It exists so the tests drive the REAL handlers, the real validation,
// the real persistence and the real reconciliation logic, with only the
// two calls that need CAP_NET_ADMIN replaced. Anything less would test a
// mock of the thing that broke on the hardware.
type fakeIface struct {
	name string
	live []net.IP
	// addCalls / delCalls record the exact arguments that reached the
	// privileged layer. The injection table asserts against these:
	// "was rejected" is only meaningful if we can also prove nothing
	// was executed.
	addCalls  []string
	delCalls  []string
	addErr    error
	delErr    error
	addSilent bool // pretend success but do not actually add (the L3 hardware failure, in miniature)
}

func (f *fakeIface) list(iface string) ([]net.IP, error) {
	if iface != f.name {
		return nil, fmt.Errorf("no such interface %q", iface)
	}
	out := make([]net.IP, len(f.live))
	copy(out, f.live)
	return out, nil
}

func (f *fakeIface) add(iface string, ip net.IP) error {
	f.addCalls = append(f.addCalls, iface+" "+ip.String())
	if f.addErr != nil {
		return f.addErr
	}
	if f.addSilent {
		return nil
	}
	if !containsIP(f.live, ip) {
		f.live = append(f.live, ip)
	}
	return nil
}

func (f *fakeIface) del(iface string, ip net.IP) error {
	f.delCalls = append(f.delCalls, iface+" "+ip.String())
	if f.delErr != nil {
		return f.delErr
	}
	out := f.live[:0]
	for _, got := range f.live {
		if !got.Equal(ip) {
			out = append(out, got)
		}
	}
	f.live = out
	return nil
}

// newAddrTestServer wires a server whose address plumbing points at a
// temp tree and a fake interface. The boot-unit paths are real files in
// the temp dir, so ensureBootUnit's actual install code runs.
func newAddrTestServer(t *testing.T) (*server, ed25519.PrivateKey, *fakeIface, string) {
	t.Helper()
	srv, _, priv, _ := newTestServer(t)
	dir := t.TempDir()
	fi := &fakeIface{name: "eth0", live: []net.IP{net.ParseIP("203.0.113.9").To4()}}

	srv.boundAddrDir = filepath.Join(dir, "bound-addresses")
	srv.bootUnitPath = filepath.Join(dir, "systemd", bootUnitName)
	srv.bootUnitWantsPath = filepath.Join(dir, "systemd", "multi-user.target.wants", bootUnitName)
	srv.addrList = fi.list
	srv.addrAdd = fi.add
	srv.addrDel = fi.del
	srv.primaryIface = func() (string, error) { return "eth0", nil }
	// systemctl must never be executed by a unit test: daemon-reload on
	// a developer machine is a real side effect.
	srv.systemdReload = func() error { return nil }
	srv.systemdStart = func(string) error { return fmt.Errorf("systemd not available in tests") }
	srv.addrCapability = func() (bool, string) { return true, "test: capable" }
	return srv, priv, fi, dir
}

func doAddrCall(t *testing.T, srv *server, priv ed25519.PrivateKey, path, ip string) *httptest.ResponseRecorder {
	t.Helper()
	op := strings.TrimPrefix(path, "/")
	body, err := json.Marshal(map[string]string{"ip": ip})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, op, srv.now().Unix()))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

func decodeBind(t *testing.T, rec *httptest.ResponseRecorder) bindAddressResp {
	t.Helper()
	var got bindAddressResp
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode bind response %q: %v", rec.Body.String(), err)
	}
	return got
}

func decodeUnbind(t *testing.T, rec *httptest.ResponseRecorder) unbindAddressResp {
	t.Helper()
	var got unbindAddressResp
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode unbind response %q: %v", rec.Body.String(), err)
	}
	return got
}

// --- the happy paths ---------------------------------------------------

// TestBindAddressConfiguresAndPersists is the whole point of the wave in
// one test: the address ends up ON the interface (which is what the
// hardware finding proved was missing) AND in a persistence record
// (which is what stops it being lost at the next reboot).
func TestBindAddressConfiguresAndPersists(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
	}
	got := decodeBind(t, rec)

	if !containsIP(fi.live, net.ParseIP("5.161.100.7")) {
		t.Fatal("the address is not on the interface — this is exactly the hardware failure being fixed")
	}
	if got.IP != "5.161.100.7" {
		t.Errorf("ip = %q; the publisher refuses a box that answers about a different address", got.IP)
	}
	if !got.Persisted {
		t.Error("persisted = false: the publisher warns the operator this relay dies at the next reboot")
	}
	if got.AlreadyBound {
		t.Error("already_bound = true on a first bind")
	}
	if got.Interface != "eth0" {
		t.Errorf("interface = %q want eth0", got.Interface)
	}
	if len(got.BoundAddresses) != 1 || got.BoundAddresses[0] != "5.161.100.7" {
		t.Errorf("bound_addresses = %v want [5.161.100.7]", got.BoundAddresses)
	}

	// The persistence artifact must exist and hold the CANONICAL value.
	recs, warns, err := listBoundRecords(srv.boundAddrDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected record warnings: %v", warns)
	}
	if len(recs) != 1 || recs[0].String() != "5.161.100.7" {
		t.Fatalf("records = %v want [5.161.100.7]", recs)
	}
	if _, err := os.Stat(got.PersistPath); err != nil {
		t.Errorf("persist_path %q does not exist: %v", got.PersistPath, err)
	}
}

// TestBindInstallsAndEnablesTheBootUnit pins the OTHER half of
// persistence. A record with nothing to re-apply it is the silent
// 3am-reboot death this requirement exists to prevent, so the unit and
// its enablement symlink are asserted as artifacts, not assumed.
func TestBindInstallsAndEnablesTheBootUnit(t *testing.T) {
	srv, priv, _, _ := newAddrTestServer(t)

	if rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); rec.Code != 200 {
		t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
	}

	body, err := os.ReadFile(srv.bootUnitPath)
	if err != nil {
		t.Fatalf("boot unit not installed: %v", err)
	}
	unit := string(body)
	for _, want := range []string{
		"-reapply-addresses",                // it must run the reconciler
		"After=network-online.target",       // ...after the network exists
		"AmbientCapabilities=CAP_NET_ADMIN", // ...with the capability this service is denied
		"WantedBy=multi-user.target",        // ...and at every boot
		"Type=oneshot",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("boot unit missing %q:\n%s", want, unit)
		}
	}
	// Enablement is a symlink we create ourselves rather than relying on
	// `systemctl enable` succeeding.
	target, err := os.Readlink(srv.bootUnitWantsPath)
	if err != nil {
		t.Fatalf("boot unit not enabled: %v", err)
	}
	if target != srv.bootUnitPath {
		t.Errorf("enable symlink -> %q want %q", target, srv.bootUnitPath)
	}
}

// TestBindIsIdempotent: rotations are retried, so binding an address the
// box already holds must be a quiet success, not an error, and must not
// write a second record or issue a second `ip addr add`.
func TestBindIsIdempotent(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)

	if rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); rec.Code != 200 {
		t.Fatalf("first bind: %d %q", rec.Code, rec.Body.String())
	}
	firstAdds := len(fi.addCalls)

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("second bind must succeed quietly, got %d %q", rec.Code, rec.Body.String())
	}
	got := decodeBind(t, rec)
	if !got.AlreadyBound {
		t.Error("already_bound = false on a repeat bind")
	}
	if !got.Persisted {
		t.Error("persisted must stay true on a repeat bind")
	}
	if len(fi.addCalls) != firstAdds {
		t.Errorf("repeat bind issued another `ip addr add` (%v)", fi.addCalls)
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 1 {
		t.Errorf("repeat bind wrote a duplicate record: %v", recs)
	}
}

// TestBindReAppliesAStaleRecord: the record survived but something
// flushed the address off the interface (a networkd reconfigure is the
// documented way this happens). A re-bind must heal it — and must NOT
// report already_bound, because the operator should see that this call
// had work to do.
func TestBindReAppliesAStaleRecord(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	if rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); rec.Code != 200 {
		t.Fatalf("first bind: %d", rec.Code)
	}
	fi.live = []net.IP{net.ParseIP("203.0.113.9").To4()} // flushed

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("re-bind: %d %q", rec.Code, rec.Body.String())
	}
	if got := decodeBind(t, rec); got.AlreadyBound {
		t.Error("already_bound = true although the address had to be re-applied")
	}
	if !containsIP(fi.live, net.ParseIP("5.161.100.7")) {
		t.Error("re-bind did not restore the address")
	}
}

// TestUnbindRemovesLiveAndPersistence checks both halves come off. A
// live removal with the record left behind means the box re-claims, at
// its next reboot, an address the provider has already re-issued to
// another customer.
func TestUnbindRemovesLiveAndPersistence(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	if rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); rec.Code != 200 {
		t.Fatalf("bind: %d", rec.Code)
	}

	rec := doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("unbind: %d %q", rec.Code, rec.Body.String())
	}
	got := decodeUnbind(t, rec)
	if !got.WasBound || !got.Removed || !got.PersistenceRemoved {
		t.Errorf("was_bound=%t removed=%t persistence_removed=%t; all three must be true",
			got.WasBound, got.Removed, got.PersistenceRemoved)
	}
	if containsIP(fi.live, net.ParseIP("5.161.100.7")) {
		t.Error("address still on the interface after unbind")
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Errorf("persistence record survived the unbind: %v — it comes back at the next reboot", recs)
	}
	if len(got.BoundAddresses) != 0 {
		t.Errorf("bound_addresses = %v want empty", got.BoundAddresses)
	}
}

// TestUnbindIsIdempotent: unbinding an address the box does not hold is
// the state the caller asked for, so it is a success. The publisher
// reads was_bound=false + removed=false as the no-op.
func TestUnbindIsIdempotent(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)

	rec := doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("unbind of an unheld address must succeed, got %d %q", rec.Code, rec.Body.String())
	}
	got := decodeUnbind(t, rec)
	if got.WasBound || got.Removed {
		t.Errorf("was_bound=%t removed=%t; the no-op is false/false", got.WasBound, got.Removed)
	}
	if len(fi.delCalls) != 0 {
		t.Errorf("idempotent unbind touched the interface: %v", fi.delCalls)
	}

	// And again after a real bind/unbind cycle.
	if r := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); r.Code != 200 {
		t.Fatalf("bind: %d", r.Code)
	}
	if r := doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7"); r.Code != 200 {
		t.Fatalf("unbind: %d", r.Code)
	}
	if r := doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7"); r.Code != 200 {
		t.Fatalf("second unbind must succeed quietly, got %d %q", r.Code, r.Body.String())
	}
}

// --- the security properties -------------------------------------------

// TestUnbindRefusesAnAddressItDidNotBind is T4, the sharpest control in
// the file. `ip addr del <primary> dev eth0` on a relay with no SSH is a
// permanent, unrecoverable outage — worse than anything bind can do — so
// unbind is gated on the persistence record set and the primary address
// is never in it.
func TestUnbindRefusesAnAddressItDidNotBind(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	primary := "203.0.113.9" // on the interface, never bound by us

	rec := doAddrCall(t, srv, priv, "/unbind-address", primary)
	if rec.Code != 200 {
		t.Fatalf("status = %d %q (this is an idempotent no-op, not an error)", rec.Code, rec.Body.String())
	}
	if len(fi.delCalls) != 0 {
		t.Fatalf("THE BOX'S PRIMARY ADDRESS WAS PASSED TO `ip addr del` (%v) — that is an unrecoverable outage", fi.delCalls)
	}
	if !containsIP(fi.live, net.ParseIP(primary)) {
		t.Fatal("primary address removed from the interface")
	}
	got := decodeUnbind(t, rec)
	if got.WasBound || got.Removed {
		t.Errorf("was_bound=%t removed=%t; an address we did not bind is neither", got.WasBound, got.Removed)
	}
	if len(got.Warnings) == 0 {
		t.Error("a live address we refused to remove must be said out loud in warnings")
	}
}

// TestBindRefusesToAdoptTheAddressTheBoxAlreadyHOLDS is the OTHER half
// of T4, and the one that was missing.
//
// The record gate makes unbind safe only because the primary address is
// never a record. Nothing enforced that: binding an address the box
// already held wrote a record for it (validation passes for any public
// unicast address, and the live half answered "already" without
// touching anything), and a record is exactly what makes an address
// removable. Two signed calls — bind(primary), unbind(primary) — then
// ran `ip addr del` on the box's own address, which on a relay with no
// SSH is permanent.
//
// So the pair is asserted here together: the adoption is refused, and
// the unbind that would have followed still cannot touch the interface.
func TestBindRefusesToAdoptTheAddressTheBoxAlreadyHolds(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	primary := "203.0.113.9" // the fixture's interface address

	rec := doAddrCall(t, srv, priv, "/bind-address", primary)
	if rec.Code != 409 {
		t.Fatalf("status = %d %q, want 409 — adopting a live address makes it removable through /unbind-address",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already configured") {
		t.Errorf("the refusal does not say why: %q", rec.Body.String())
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Fatalf("a record was written for an address we refused to adopt: %v — that is the unbind gate opened", recs)
	}

	// The attack this exists to stop, run to completion.
	un := doAddrCall(t, srv, priv, "/unbind-address", primary)
	if un.Code != 200 {
		t.Fatalf("unbind status = %d %q (still an idempotent no-op)", un.Code, un.Body.String())
	}
	if len(fi.delCalls) != 0 {
		t.Fatalf("THE BOX'S PRIMARY ADDRESS REACHED `ip addr del` (%v) — bind-then-unbind is an unrecoverable outage", fi.delCalls)
	}
	if !containsIP(fi.live, net.ParseIP(primary)) {
		t.Fatal("primary address removed from the interface")
	}
	if got := decodeUnbind(t, un); !got.StillConfigured {
		t.Error("still_configured=false for an address that IS on the interface: the publisher would release it")
	}
}

// A re-bind of an address we DID bind is unaffected by the adoption
// refusal — it is the idempotent path every retried rotation takes.
func TestAdoptionRefusalDoesNotBreakIdempotentReBind(t *testing.T) {
	srv, priv, _, _ := newAddrTestServer(t)
	for i := 0; i < 3; i++ {
		if rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); rec.Code != 200 {
			t.Fatalf("bind %d: %d %q", i, rec.Code, rec.Body.String())
		}
	}
}

// TestUnbindReportsStillConfiguredMachineReadably. The box's only way
// of saying "that address is on my interface and I did NOT remove it"
// used to be a Warnings string, and every publisher call site discarded
// the response — after which `floating-ip release` handed the address
// back to the provider's pool while this box still answered on it.
func TestUnbindReportsStillConfiguredMachineReadably(t *testing.T) {
	srv, priv, _, _ := newAddrTestServer(t)

	got := decodeUnbind(t, doAddrCall(t, srv, priv, "/unbind-address", "203.0.113.9"))
	if !got.StillConfigured {
		t.Error("still_configured must be true for a live address this service did not bind")
	}
	// And false for one that genuinely is not there, so the field can
	// be used as a hard stop without stranding the ordinary no-op.
	got = decodeUnbind(t, doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7"))
	if got.StillConfigured {
		t.Error("still_configured must be false for an address the box does not hold")
	}
}

// TestAddressTokenIsSingleUse. The token signs nonce:ts:op and NOT the
// body, so one captured token would otherwise authorise an unbounded
// number of binds of ARBITRARY addresses for the rest of its window —
// each of them persisted across reboot.
func TestAddressTokenIsSingleUse(t *testing.T) {
	srv, priv, _, _ := newAddrTestServer(t)
	tok := mintToken(priv, "bind-address", srv.now().Unix())

	call := func(ip string) int {
		body, _ := json.Marshal(map[string]string{"ip": ip})
		req := httptest.NewRequest("POST", "/bind-address", bytes.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := call("5.161.100.7"); code != 200 {
		t.Fatalf("first use = %d, want 200", code)
	}
	// The replay that matters is not a repeat of the same request: it
	// is the SAME token pointed at a DIFFERENT address.
	if code := call("5.161.100.8"); code != 401 {
		t.Fatalf("replayed token bound a second address (%d) — one captured token must not configure the host repeatedly", code)
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 1 {
		t.Errorf("records = %v, want just the first bind", recs)
	}
}

// TestRejectedAddressClasses is the T1 validation table. Every class
// that must never be configured on this host, each asserted to be
// refused with a 400 AND to have executed nothing.
func TestRejectedAddressClasses(t *testing.T) {
	cases := []struct {
		ip   string
		why  string
		want string // a fragment the error must name, so the operator can act on it
	}{
		{"0.0.0.0", "unspecified", "0.0.0.0/8"},
		{"0.1.2.3", "this-network", "0.0.0.0/8"},
		{"10.0.0.1", "RFC1918", "10.0.0.0/8"},
		{"10.255.255.254", "RFC1918 upper", "10.0.0.0/8"},
		{"100.64.0.1", "CGNAT", "100.64.0.0/10"},
		{"100.127.255.254", "CGNAT upper", "100.64.0.0/10"},
		{"127.0.0.1", "loopback", "127.0.0.0/8"},
		{"127.255.255.255", "loopback upper", "127.0.0.0/8"},
		{"169.254.1.1", "link-local", "169.254.0.0/16"},
		{"169.254.169.254", "cloud metadata service", "169.254.0.0/16"},
		{"172.16.0.1", "RFC1918", "172.16.0.0/12"},
		{"172.31.255.254", "RFC1918 upper", "172.16.0.0/12"},
		{"192.0.0.1", "IETF protocol assignments", "192.0.0.0/24"},
		{"192.88.99.1", "6to4 relay anycast", "192.88.99.0/24"},
		{"192.168.1.1", "RFC1918", "192.168.0.0/16"},
		{"198.18.0.1", "benchmarking", "198.18.0.0/15"},
		{"224.0.0.1", "multicast", "224.0.0.0/4"},
		{"239.255.255.250", "multicast upper (SSDP)", "224.0.0.0/4"},
		{"240.0.0.1", "reserved", "240.0.0.0/4"},
		{"255.255.255.255", "broadcast", "240.0.0.0/4"},
		{"::", "v6 unspecified", "unspecified"},
		{"::1", "v6 loopback", "loopback"},
		{"::ffff:127.0.0.1", "v4-mapped loopback in v6 clothing", "IPv4-mapped"},
		{"::ffff:8.8.8.8", "v4-mapped public", "IPv4-mapped"},
		{"64:ff9b::1", "NAT64", "64:ff9b::/96"},
		{"100::1", "discard-only", "100::/64"},
		{"2001::1", "Teredo", "2001::/32"},
		{"2002::1", "6to4", "2002::/16"},
		{"fc00::1", "unique-local", "fc00::/7"},
		{"fd12:3456::1", "unique-local (fd half)", "fc00::/7"},
		{"fe80::1", "v6 link-local", "fe80::/10"},
		{"ff02::1", "v6 multicast", "ff00::/8"},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			// Unit level: the validator itself.
			if _, err := validateBindAddress(tc.ip); err == nil {
				t.Fatalf("validateBindAddress(%s) accepted a %s address", tc.ip, tc.why)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q — an operator on a box with no SSH cannot act on it", err, tc.want)
			}
			// Handler level: 400, and nothing executed.
			srv, priv, fi, _ := newAddrTestServer(t)
			rec := doAddrCall(t, srv, priv, "/bind-address", tc.ip)
			if rec.Code != 400 {
				t.Fatalf("/bind-address %s (%s) = %d want 400: %q", tc.ip, tc.why, rec.Code, rec.Body.String())
			}
			if len(fi.addCalls) != 0 {
				t.Fatalf("a rejected address still reached the privileged layer: %v", fi.addCalls)
			}
			if _, err := os.Stat(srv.boundAddrDir); err == nil {
				if recs, _, _ := listBoundRecords(srv.boundAddrDir); len(recs) != 0 {
					t.Fatalf("a rejected address was persisted: %v", recs)
				}
			}
		})
	}
}

// TestPublicAddressesAreAccepted is the negative control for the table
// above: a validator that rejects everything would pass every test in
// TestRejectedAddressClasses and ship a dead feature.
func TestPublicAddressesAreAccepted(t *testing.T) {
	for _, ip := range []string{
		"1.1.1.1",
		"8.8.8.8",
		"5.161.0.1",       // Hetzner v4 space
		"95.216.1.2",      // Hetzner v4 space
		"2a01:4f9::1",     // Hetzner v6 space
		"2606:4700::1",    // public v6
		"172.32.0.1",      // just ABOVE the RFC1918 172.16/12 block
		"172.15.255.254",  // just BELOW it
		"100.63.255.255",  // just below CGNAT
		"100.128.0.0",     // just above CGNAT
		"198.20.0.1",      // just above the benchmarking block
		"223.255.255.255", // last address before multicast
		// THE DOCUMENTATION RANGES, accepted on purpose. They are the
		// reconciliation with publisher/deploy/mgmt.BindableAddress —
		// the two validators must agree and this is the agreed
		// direction; see the note on rejectedRanges. They are also the
		// only addresses a reachability test can dial while being
		// certain nobody answers, which is why the tree's fixtures use
		// them everywhere (including this file's own "primary"
		// address, 203.0.113.9).
		"192.0.2.5",    // TEST-NET-1
		"198.51.100.7", // TEST-NET-2
		"203.0.113.5",  // TEST-NET-3
		"2001:db8::1",  // v6 documentation
	} {
		t.Run(ip, func(t *testing.T) {
			got, err := validateBindAddress(ip)
			if err != nil {
				t.Fatalf("validateBindAddress(%s) rejected a public unicast address: %v", ip, err)
			}
			if !got.Equal(net.ParseIP(ip)) {
				t.Errorf("canonicalised %s to %s", ip, got)
			}
		})
	}
}

// TestInjectionAttemptsAreRefused is the T2 table.
//
// Every row must be refused with a 400 AND must leave the privileged
// layer untouched — "it was rejected" is only worth asserting alongside
// "nothing ran", because a validator that rejects after shelling out has
// already lost.
func TestInjectionAttemptsAreRefused(t *testing.T) {
	attempts := []struct {
		payload string
		why     string
	}{
		{"1.2.3.4; rm -rf /", "command chaining with ;"},
		{"1.2.3.4 && reboot", "command chaining with &&"},
		{"1.2.3.4 || reboot", "command chaining with ||"},
		{"1.2.3.4 | tee /etc/passwd", "pipe"},
		{"1.2.3.4\nreboot", "newline as a command separator"},
		{"1.2.3.4\rreboot", "carriage return"},
		{"$(reboot)", "command substitution"},
		{"`reboot`", "backtick substitution"},
		{"1.2.3.4$(id)", "substitution appended to a valid address"},
		{"${IFS}1.2.3.4", "IFS expansion"},
		{"1.2.3.4 dev lo", "extra argv words to retarget the interface"},
		{"1.2.3.4/0 dev eth0", "prefix length that would claim the whole internet"},
		{"1.2.3.4/32", "prefix length appended"},
		{"8.8.8.8%eth0", "zone identifier"},
		{"fe80::1%eth0", "v6 zone identifier"},
		{"-4", "an argv flag instead of an address"},
		{"--help", "a long flag"},
		{"1.2.3.4 -j DROP", "iptables-shaped argument smuggling"},
		{"'1.2.3.4'", "quoting"},
		{"\"1.2.3.4\"", "double quoting"},
		{"1.2.3.4\x00reboot", "NUL truncation"},
		{"", "empty"},
		{"   ", "whitespace only"},
		{"localhost", "a name rather than an address"},
		{"example.com", "a hostname that would be resolved by something else"},
		{"1.2.3.4,5.6.7.8", "two addresses"},
		{"1.2.3.4:443", "host:port"},
		{"999.999.999.999", "out-of-range octets"},
		{"1.2.3.4.5", "five octets"},
		{"0x01020304", "hex-packed IPv4 that inet_aton would accept"},
		{"016909060", "octal-packed IPv4 that inet_aton would accept"},
		{"3232235777", "decimal-packed IPv4 that inet_aton would accept"},
		{"1.2.3.04", "leading-zero octet (octal ambiguity)"},
		{"../../etc/passwd", "path traversal aimed at the record filename"},
		{"..", "path traversal, minimal"},
		{"/etc/passwd", "absolute path"},
		{"1.2.3.4/../../root", "traversal appended to a valid address"},
		{strings.Repeat("1", 4096), "oversized input"},
	}
	for _, tc := range attempts {
		t.Run(tc.why, func(t *testing.T) {
			// The validator refuses it...
			if _, err := validateBindAddress(tc.payload); err == nil {
				t.Fatalf("validateBindAddress accepted %q (%s)", tc.payload, tc.why)
			}
			// ...and so does the handler, with nothing executed and
			// nothing written.
			for _, path := range []string{"/bind-address", "/unbind-address"} {
				srv, priv, fi, _ := newAddrTestServer(t)
				rec := doAddrCall(t, srv, priv, path, tc.payload)
				if rec.Code != 400 {
					t.Errorf("%s %q (%s) = %d want 400: %q", path, tc.payload, tc.why, rec.Code, rec.Body.String())
				}
				if len(fi.addCalls) != 0 || len(fi.delCalls) != 0 {
					t.Errorf("%s %q reached the privileged layer: add=%v del=%v",
						path, tc.payload, fi.addCalls, fi.delCalls)
				}
				if entries, err := os.ReadDir(srv.boundAddrDir); err == nil && len(entries) != 0 {
					t.Errorf("%s %q wrote a record: %v", path, tc.payload, entries)
				}
			}
		})
	}
}

// TestRejectedInputIsNotEchoed: the refusal for a malformed address must
// not reflect the caller's bytes. This error reaches an operator's
// terminal and the journal, and a validator that echoes arbitrary input
// is an injection vector for whatever renders its output.
func TestRejectedInputIsNotEchoed(t *testing.T) {
	payload := "1.2.3.4;\x1b[31mreboot"
	_, err := validateBindAddress(payload)
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), "reboot") || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("error echoes the rejected input: %q", err)
	}
}

// TestBoundAddressCapIsEnforcedFromDisk is T3. The cap is checked
// against the PERSISTED set, so a restart cannot reset it — which is
// what makes it a bound rather than a speed bump.
func TestBoundAddressCapIsEnforcedFromDisk(t *testing.T) {
	srv, priv, _, _ := newAddrTestServer(t)
	addrs := []string{"5.161.0.1", "5.161.0.2", "5.161.0.3", "5.161.0.4", "5.161.0.5", "5.161.0.6"}
	accepted := 0
	for _, a := range addrs {
		rec := doAddrCall(t, srv, priv, "/bind-address", a)
		switch rec.Code {
		case 200:
			accepted++
		case 409:
			if !strings.Contains(rec.Body.String(), "maximum") {
				t.Errorf("refusal does not explain the limit: %q", rec.Body.String())
			}
		default:
			t.Fatalf("bind %s = %d %q", a, rec.Code, rec.Body.String())
		}
	}
	if accepted != maxBoundAddresses {
		t.Fatalf("accepted %d addresses, cap is %d", accepted, maxBoundAddresses)
	}
	// A fresh server over the SAME directory (i.e. after a restart)
	// must still refuse: the cap lives on disk, not in memory.
	srv2, priv2, _, _ := newAddrTestServer(t)
	srv2.boundAddrDir = srv.boundAddrDir
	srv2.bootUnitPath = srv.bootUnitPath
	srv2.bootUnitWantsPath = srv.bootUnitWantsPath
	if rec := doAddrCall(t, srv2, priv2, "/bind-address", "5.161.0.9"); rec.Code != 409 {
		t.Fatalf("after a restart the cap = %d want 409: %q", rec.Code, rec.Body.String())
	}
	// Re-binding an address already recorded is not a new address and
	// must not be refused by the cap.
	if rec := doAddrCall(t, srv2, priv2, "/bind-address", "5.161.0.1"); rec.Code != 200 {
		t.Fatalf("re-bind of an already recorded address = %d want 200: %q", rec.Code, rec.Body.String())
	}
}

// TestMaxBoundAddressesMatchesThePublisher pins the shared number. The
// publisher refuses a box reporting more than mgmt.MaxBoundAddresses, so
// a box with a larger cap produces loud refusals of legitimate binds and
// a box with a smaller one silently under-serves. Separate go.mod files
// mean nothing catches the drift at compile time.
func TestMaxBoundAddressesMatchesThePublisher(t *testing.T) {
	const publisherMaxBoundAddresses = 4 // publisher/deploy/mgmt.MaxBoundAddresses
	if maxBoundAddresses != publisherMaxBoundAddresses {
		t.Fatalf("maxBoundAddresses = %d but publisher/deploy/mgmt.MaxBoundAddresses = %d",
			maxBoundAddresses, publisherMaxBoundAddresses)
	}
}

// --- failure semantics of the two halves -------------------------------

// TestBindUndoesPersistenceWhenTheLiveHalfFails is T5. A refused bind
// must leave NOTHING behind: a surviving record would make this box
// claim, at its next reboot, an address the publisher has already handed
// back to the provider pool and that may by then belong to someone else.
func TestBindUndoesPersistenceWhenTheLiveHalfFails(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	fi.addErr = fmt.Errorf("RTNETLINK answers: Operation not permitted")

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 500 {
		t.Fatalf("status = %d want 500: %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "persistence record removed") {
		t.Errorf("the refusal must state that nothing was left behind: %q", rec.Body.String())
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Fatalf("a failed bind left a persistence record behind: %v — this box claims that address at its next reboot", recs)
	}
}

// TestBindRefusesWhenTheApplySilentlyDoesNothing is the hardware failure
// in miniature, one layer down. `ip addr add` exits zero and the address
// is not there. Success is decided by re-reading the interface, never by
// an exit status — that is the exact mistake L3 made at the provider API
// layer and it must not be repeated inside the box.
func TestBindRefusesWhenTheApplySilentlyDoesNothing(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	fi.addSilent = true

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 500 {
		t.Fatalf("status = %d want 500 (the address is not on the interface): %q", rec.Code, rec.Body.String())
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Errorf("record left behind: %v", recs)
	}
}

// TestBindStandsWhenTheBootUnitFailsOverAnUnrelatedRecord.
//
// `systemctl restart` returns a verdict about the UNIT, and the unit
// fails if ANY record could not be applied. Believing that verdict
// failed the bind and then UNDID the persistence for an address that
// was live — leaving it configured with no record, which the record
// gate makes permanently unremovable through this API while the
// publisher hands the floating IP back to the provider. Success is
// decided by looking, on the failing branch too.
func TestBindStandsWhenTheBootUnitFailsOverAnUnrelatedRecord(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	want := net.ParseIP("5.161.100.7").To4()
	// No in-process capability: the direct add fails, as it does on a
	// box whose unit was launched without CAP_NET_ADMIN.
	fi.addErr = errors.New("RTNETLINK answers: Operation not permitted")
	// The delegated reconcile applies OUR address and then trips over
	// somebody else's stale record, so it exits non-zero.
	srv.systemdStart = func(string) error {
		fi.live = append(fi.live, want)
		return errors.New("Job for daal-bound-addresses.service failed")
	}

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("status = %d %q — the address IS on the interface, so the bind stands", rec.Code, rec.Body.String())
	}
	got := decodeBind(t, rec)
	if !got.Persisted {
		t.Error("persisted=false for a bind that stands")
	}
	if len(got.Warnings) == 0 {
		t.Error("the unit's failure must still be said out loud")
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 1 {
		t.Fatalf("records = %v — the persistence for a LIVE address was undone; it can never be unbound again", recs)
	}
}

// TestBindRefusesWhenPersistenceCannotBeInstalled: a box that cannot
// host the boot unit must refuse rather than bind and lie about
// surviving a reboot. Persistence is a requirement, so its absence is a
// refusal, not a warning.
func TestBindRefusesWhenPersistenceCannotBeInstalled(t *testing.T) {
	srv, priv, fi, dir := newAddrTestServer(t)
	// Make the unit path un-creatable by putting a FILE where the
	// directory has to be.
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.bootUnitPath = filepath.Join(blocked, bootUnitName)
	srv.bootUnitWantsPath = filepath.Join(blocked, "wants", bootUnitName)

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 500 {
		t.Fatalf("status = %d want 500: %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "reboot") {
		t.Errorf("the refusal must name the reason (lost at the next reboot): %q", rec.Body.String())
	}
	if len(fi.addCalls) != 0 {
		t.Errorf("the live half ran despite persistence being unavailable: %v", fi.addCalls)
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Errorf("record written despite persistence being unavailable: %v", recs)
	}
}

// TestBindRefusesWhenSystemdRejectsTheUnit: a unit file systemd has
// never seen neither runs at boot nor can be started now, so the
// persistence promise cannot be kept and the bind must refuse rather
// than answer persisted=true over it.
func TestBindRefusesWhenSystemdRejectsTheUnit(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	srv.systemdReload = func() error { return fmt.Errorf("Failed to reload daemon: Connection refused") }

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != 500 {
		t.Fatalf("status = %d want 500: %q", rec.Code, rec.Body.String())
	}
	if len(fi.addCalls) != 0 {
		t.Errorf("the live half ran although persistence could not be promised: %v", fi.addCalls)
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Errorf("record written although persistence could not be promised: %v", recs)
	}
	// A steady-state re-bind must not pay for the reload: once the unit
	// on disk already matches, there is nothing for systemd to learn.
	srv2, priv2, _, _ := newAddrTestServer(t)
	if r := doAddrCall(t, srv2, priv2, "/bind-address", "5.161.100.7"); r.Code != 200 {
		t.Fatalf("first bind: %d %q", r.Code, r.Body.String())
	}
	srv2.systemdReload = func() error { return fmt.Errorf("would fail if it were called") }
	if r := doAddrCall(t, srv2, priv2, "/bind-address", "5.161.100.8"); r.Code != 200 {
		t.Fatalf("second bind re-ran daemon-reload for an unchanged unit: %d %q", r.Code, r.Body.String())
	}
}

// TestUnbindRemovesTheRecordEvenWhenTheLiveRemovalFails: unbind never
// stops halfway. If `ip addr del` fails, the record still has to go, or
// the address is re-asserted at the next reboot on top of a failure the
// operator was already told about. The call reports 500 — both halves
// attempted, both outcomes stated.
func TestUnbindRemovesTheRecordEvenWhenTheLiveRemovalFails(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	if rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7"); rec.Code != 200 {
		t.Fatalf("bind: %d", rec.Code)
	}
	fi.delErr = fmt.Errorf("RTNETLINK answers: Operation not permitted")

	rec := doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7")
	if rec.Code != 500 {
		t.Fatalf("status = %d want 500: %q", rec.Code, rec.Body.String())
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Fatalf("the record survived a failed live removal: %v — the address comes back at the next reboot", recs)
	}
}

// TestUnbindOfARecordThatWasNeverLive reports removed=true, because the
// statement "the address is not configured here" is true. Reporting
// false would send the publisher down its "still configured on its
// interface" error path for a box that is in exactly the asked-for
// state.
func TestUnbindOfARecordThatWasNeverLive(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	if err := writeBoundRecord(srv.boundAddrDir, net.ParseIP("5.161.100.7")); err != nil {
		t.Fatal(err)
	}

	rec := doAddrCall(t, srv, priv, "/unbind-address", "5.161.100.7")
	if rec.Code != 200 {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	got := decodeUnbind(t, rec)
	if !got.WasBound {
		t.Error("was_bound = false for an address that had a record")
	}
	if !got.Removed {
		t.Error("removed = false although the address is not configured on the interface")
	}
	if !got.PersistenceRemoved {
		t.Error("persistence_removed = false")
	}
	if len(fi.delCalls) != 0 {
		t.Errorf("called `ip addr del` for an address that was not live: %v", fi.delCalls)
	}
}

// --- the boot path ------------------------------------------------------

// TestApplyBoundRecordsRestoresEverything is the reboot, simulated: the
// records survive, the interface does not, and the reconciler puts them
// back. Same function the live path uses, so validation cannot drift
// between "bound now" and "bound after a reboot".
func TestApplyBoundRecordsRestoresEverything(t *testing.T) {
	srv, _, fi, _ := newAddrTestServer(t)
	for _, a := range []string{"5.161.0.1", "2a01:4f9::5"} {
		if err := writeBoundRecord(srv.boundAddrDir, net.ParseIP(a)); err != nil {
			t.Fatal(err)
		}
	}
	fi.live = []net.IP{net.ParseIP("203.0.113.9").To4()} // fresh boot: only the primary

	applied, warns, err := srv.applyBoundRecords("eth0")
	if err != nil {
		t.Fatalf("applyBoundRecords: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %d records want 2", len(applied))
	}
	for _, a := range []string{"5.161.0.1", "2a01:4f9::5"} {
		if !containsIP(fi.live, net.ParseIP(a)) {
			t.Errorf("%s not restored after the simulated reboot", a)
		}
	}
	// It must never REMOVE: the primary address is not a record and
	// must survive reconciliation untouched.
	if !containsIP(fi.live, net.ParseIP("203.0.113.9")) {
		t.Fatal("reconciliation removed the primary address")
	}
	// And it is idempotent: a second pass issues no further adds.
	before := len(fi.addCalls)
	if _, _, err := srv.applyBoundRecords("eth0"); err != nil {
		t.Fatal(err)
	}
	if len(fi.addCalls) != before {
		t.Errorf("second reconcile re-added addresses: %v", fi.addCalls)
	}
}

// TestBootPathSkipsRecordsThatWouldNotValidate: a hand-edited or
// corrupted record must not become a privileged action at boot. The boot
// path re-validates with exactly the rules the API enforces, so an
// address that could not be bound through the API cannot be applied by
// a reboot either.
func TestBootPathSkipsRecordsThatWouldNotValidate(t *testing.T) {
	srv, _, fi, _ := newAddrTestServer(t)
	if err := os.MkdirAll(srv.boundAddrDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"good.addr":     "5.161.0.1\n",
		"loopback.addr": "127.0.0.1\n",
		"private.addr":  "192.168.1.1\n",
		"garbage.addr":  "not-an-address\n",
		"inject.addr":   "1.2.3.4; reboot\n",
		"ignored.txt":   "8.8.8.8\n", // wrong suffix: not a record at all
	} {
		if err := os.WriteFile(filepath.Join(srv.boundAddrDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	records, warns, err := listBoundRecords(srv.boundAddrDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].String() != "5.161.0.1" {
		t.Fatalf("records = %v want only [5.161.0.1]", records)
	}
	if len(warns) != 4 {
		t.Errorf("warnings = %v; every skipped record must be named", warns)
	}
	applied, _, err := srv.applyBoundRecords("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied %v want only the valid record", applied)
	}
	for _, call := range fi.addCalls {
		if !strings.Contains(call, "5.161.0.1") {
			t.Errorf("an invalid record reached the privileged layer: %q", call)
		}
	}
}

// TestReapplyBootUnitBodyIsFullyConstant: the unit is written in
// response to a remote request, so nothing caller-derived may appear in
// it. The only variable is the executable path, which comes from
// os.Executable.
func TestBootUnitBodyIsFullyConstant(t *testing.T) {
	body := bootUnitBody("/usr/local/bin/daal-relay-mgmt")
	if !strings.Contains(body, "ExecStart=/usr/local/bin/daal-relay-mgmt -reapply-addresses") {
		t.Errorf("unexpected ExecStart:\n%s", body)
	}
	// One ExecStart, one argument, nothing appended.
	if strings.Count(body, "ExecStart=") != 1 {
		t.Errorf("more than one ExecStart:\n%s", body)
	}
}

// --- persistence records ------------------------------------------------

// TestRecordFilenamesAreDerivedFromParsedBytes: the record filename is
// built from the CANONICAL rendering, so no caller-supplied byte can
// reach a path even if the charset filter were ever loosened.
func TestRecordFilenamesAreDerivedFromParsedBytes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ in, wantBase string }{
		{"5.161.0.1", "5.161.0.1.addr"},
		{"2A01:4F9:0:0::5", "2a01_4f9__5.addr"}, // upper-case and long form both normalise
	} {
		ip, err := validateBindAddress(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		got := boundRecordFile(dir, ip)
		if filepath.Base(got) != tc.wantBase {
			t.Errorf("boundRecordFile(%s) = %s want base %s", tc.in, got, tc.wantBase)
		}
		if filepath.Dir(got) != dir {
			t.Errorf("record escaped its directory: %s", got)
		}
	}
}

// TestRecordRoundTripsCanonically: two spellings of one address must
// produce ONE record, or an unbind of the canonical form would leave the
// other spelling behind to be re-applied at the next reboot.
func TestRecordRoundTripsCanonically(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	for _, spelling := range []string{"2a01:4f9::5", "2A01:04F9:0000::0005"} {
		ip, err := validateBindAddress(spelling)
		if err != nil {
			t.Fatalf("%s: %v", spelling, err)
		}
		if err := writeBoundRecord(dir, ip); err != nil {
			t.Fatal(err)
		}
	}
	recs, _, err := listBoundRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %v want one canonical record", recs)
	}
	removed, err := removeBoundRecord(dir, net.ParseIP("2a01:4f9::5"))
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("removeBoundRecord did not remove the canonical record")
	}
	recs, _, _ = listBoundRecords(dir)
	if len(recs) != 0 {
		t.Errorf("records survived removal: %v", recs)
	}
}

// TestRecordDirectoryIsNotWorldReadable: the record set decides which
// address this host claims at its next boot. A world-writable directory
// would turn any local unprivileged bug into that decision.
func TestRecordPermissionsAreTight(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	if err := writeBoundRecord(dir, net.ParseIP("5.161.0.1")); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("record dir mode = %o want 700", di.Mode().Perm())
	}
	fi, err := os.Stat(boundRecordFile(dir, net.ParseIP("5.161.0.1")))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %o want 600", fi.Mode().Perm())
	}
}

// TestNoTempFilesSurvive: writeBoundRecord uses temp-then-rename, and a
// leftover .tmp must never be read as a record.
func TestNoTempFilesSurvive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	if err := writeBoundRecord(dir, net.ParseIP("5.161.0.1")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) != 1 || names[0] != "5.161.0.1.addr" {
		t.Errorf("directory contents = %v want exactly one record file", names)
	}
}

// --- capability advertisement -------------------------------------------

// TestHealthAdvertisesBindAddressWhenCapable pins the wire token the
// publisher's interlock reads. The literal is the contract, not the
// constant name: publisher/deploy/mgmt fails CLOSED, so a drift here
// makes it refuse every L3 swap against correct boxes, silently at
// compile time (separate go.mod files, no shared symbol).
func TestHealthAdvertisesBindAddressWhenCapable(t *testing.T) {
	srv, _, _, _ := newAddrTestServer(t)
	srv.addrCapability = func() (bool, string) { return true, "test: capable" }

	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		OK              bool     `json:"ok"`
		MgmtAPIVersion  int      `json:"mgmt_api_version"`
		Capabilities    []string `json:"capabilities"`
		CapabilityNotes []string `json:"capability_notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.OK {
		t.Error(`"ok" must stay true — the liveness probe reads it`)
	}
	found := false
	for _, c := range got.Capabilities {
		if c == "bind-address" { // the literal, spelled out
			found = true
		}
	}
	if !found {
		t.Errorf("capabilities %v missing %q — the publisher will refuse every L3 swap against this box",
			got.Capabilities, "bind-address")
	}
	// The rotation tokens must survive alongside it.
	for _, want := range []string{"rotate-credentials-scoped", "rotate-tls-scoped"} {
		if !containsString(got.Capabilities, want) {
			t.Errorf("capabilities %v lost %q", got.Capabilities, want)
		}
	}
	// mgmt_api_version must NOT move. publisher/deploy/mgmt defines
	// MgmtAPIVersionAddressBinding=3 as a version fallback for this
	// verb; this box never emitting 3 is what keeps that fallback
	// unreachable, which is required because the capability depends on
	// how the service was LAUNCHED (CAP_NET_ADMIN) and not on which
	// binary is running.
	if got.MgmtAPIVersion != 2 {
		t.Errorf("mgmt_api_version = %d want 2 — bumping it makes every relay claim bind-address from its version alone, "+
			"including the ones that cannot do it", got.MgmtAPIVersion)
	}
}

// TestHealthOmitsBindAddressWhenIncapable is the honesty half, and the
// one that matters on every relay provisioned before Wave 3c: those run
// this service with CapabilityBoundingSet=CAP_NET_BIND_SERVICE, so a
// relay can be running this exact binary and still be unable to
// configure an address — and, more sharply, unable to REMOVE one, which
// the boot-unit delegation can never do for it. Advertising anyway
// would move the failure into the middle of a swap.
func TestHealthOmitsBindAddressWhenIncapable(t *testing.T) {
	srv, _, _, _ := newAddrTestServer(t)
	srv.addrCapability = func() (bool, string) {
		return false, "address binding unavailable: this service holds no CAP_NET_ADMIN"
	}

	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Capabilities    []string `json:"capabilities"`
		CapabilityNotes []string `json:"capability_notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if containsString(got.Capabilities, "bind-address") {
		t.Error("advertised bind-address on a box that cannot bind — the publisher would half-apply an L3 swap")
	}
	// The rotation verbs are unaffected: this box rotates fine.
	if !containsString(got.Capabilities, "rotate-credentials-scoped") {
		t.Error("an incapable-of-binding box must still advertise the rotation verbs")
	}
	// The reason must be readable: "old binary" and "no CAP_NET_ADMIN"
	// have different remedies and an unexplained absence sends the
	// operator to the wrong one.
	if len(got.CapabilityNotes) == 0 || !strings.Contains(strings.Join(got.CapabilityNotes, " "), "CAP_NET_ADMIN") {
		t.Errorf("capability_notes = %v; must name the reason", got.CapabilityNotes)
	}
}

// TestBindRefusesOnAnIncapableBox: a publisher that ignored the
// capability must still be refused BEFORE anything is applied, rather
// than half-applying.
func TestBindRefusesOnAnIncapableBox(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	srv.addrCapability = func() (bool, string) {
		return false, "address binding unavailable: the `ip` utility is not installed on this box"
	}

	rec := doAddrCall(t, srv, priv, "/bind-address", "5.161.100.7")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d want 501: %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not installed") {
		t.Errorf("refusal must name the reason: %q", rec.Body.String())
	}
	if len(fi.addCalls) != 0 {
		t.Errorf("applied something on an incapable box: %v", fi.addCalls)
	}
	recs, _, _ := listBoundRecords(srv.boundAddrDir)
	if len(recs) != 0 {
		t.Errorf("persisted something on an incapable box: %v", recs)
	}
}

// --- auth and routing ---------------------------------------------------

// TestAddressRoutesRequireSignature: these are privileged network
// configuration, so an unsigned or wrongly-scoped token must not reach
// the handler. The op string is signed, so a token minted for
// /users/list must not open /bind-address.
func TestAddressRoutesRequireSignature(t *testing.T) {
	srv, priv, fi, _ := newAddrTestServer(t)
	body := []byte(`{"ip":"5.161.100.7"}`)

	for _, path := range []string{"/bind-address", "/unbind-address"} {
		// No token at all.
		req := httptest.NewRequest("POST", path, bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("%s unsigned = %d want 401", path, rec.Code)
		}
		// A valid signature for a DIFFERENT op.
		req = httptest.NewRequest("POST", path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, "users-list", srv.now().Unix()))
		rec = httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("%s with a users-list token = %d want 401", path, rec.Code)
		}
	}
	if len(fi.addCalls) != 0 || len(fi.delCalls) != 0 {
		t.Errorf("an unauthorised request reached the privileged layer: add=%v del=%v", fi.addCalls, fi.delCalls)
	}
}

// TestAddressRoutesRejectNonPOST keeps the surface tight.
func TestAddressRoutesRejectNonPOST(t *testing.T) {
	srv, priv, _, _ := newAddrTestServer(t)
	for _, path := range []string{"/bind-address", "/unbind-address"} {
		op := strings.TrimPrefix(path, "/")
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Daal-Mgmt-Token "+mintToken(priv, op, srv.now().Unix()))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != 405 {
			t.Errorf("GET %s = %d want 405", path, rec.Code)
		}
	}
}

// --- interface selection -------------------------------------------------

// TestIsVirtualIfaceName keeps container plumbing out of the
// private-address fallback: configuring a floating IP on docker0 would
// look like success and be unreachable from the internet.
func TestIsVirtualIfaceName(t *testing.T) {
	for _, name := range []string{"docker0", "veth1234", "br-abc", "tun0", "wg0", "lo", "virbr0", "cni0"} {
		if !isVirtualIfaceName(name) {
			t.Errorf("%s should be excluded from primary-interface selection", name)
		}
	}
	for _, name := range []string{"eth0", "ens3", "enp1s0", "eno1"} {
		if isVirtualIfaceName(name) {
			t.Errorf("%s is a plausible primary interface and must not be excluded", name)
		}
	}
}

// TestPrefixLenIsAlwaysAHostRoute: an address added with the interface's
// subnet prefix would rewrite the on-link route the box needs to reach
// its gateway. Every bind is a host route.
func TestPrefixLenIsAlwaysAHostRoute(t *testing.T) {
	if got := prefixLen(net.ParseIP("5.161.0.1")); got != 32 {
		t.Errorf("v4 prefix = %d want 32", got)
	}
	if got := prefixLen(net.ParseIP("2a01:4f9::5")); got != 128 {
		t.Errorf("v6 prefix = %d want 128", got)
	}
}

// TestReadPathWorksAgainstTheRealHost exercises the UNPRIVILEGED half
// against this machine's actual interfaces: interface selection and
// address listing are pure Go over netlink and need no capability, and
// they are what every apply is VERIFIED with. A verifier that cannot
// read the interface would make every bind report failure on a box
// where it worked, so it is worth one test against real kernel data
// rather than only against the fake.
//
// Skips rather than fails where there is no candidate interface (a
// network-less container), because the absence of a NIC is not a defect
// in this code.
func TestReadPathWorksAgainstTheRealHost(t *testing.T) {
	iface, err := detectPrimaryInterface()
	if err != nil {
		t.Skipf("no candidate interface on this host: %v", err)
	}
	if !ifaceNameRe.MatchString(iface) {
		t.Fatalf("detectPrimaryInterface returned %q, which would be refused as an argv element", iface)
	}
	if isVirtualIfaceName(iface) {
		t.Errorf("selected %q, a virtual/container interface", iface)
	}
	addrs, err := defaultAddrList(iface)
	if err != nil {
		t.Fatalf("defaultAddrList(%s): %v", iface, err)
	}
	if len(addrs) == 0 {
		t.Errorf("defaultAddrList(%s) returned nothing, but the interface was chosen for holding an address", iface)
	}
	// containsIP is the comparison every verification depends on; it has
	// to work across the 4-byte / 16-byte representations net.IP mixes.
	for _, a := range addrs {
		if !containsIP(addrs, a) {
			t.Errorf("containsIP cannot find %s in the list it came from", a)
		}
	}
}

// TestCapabilityProbeIsHonestOnThisHost: the probe must never report
// capable without a reason that holds. It is allowed to say either
// thing here — a developer machine usually has systemctl and no
// CAP_NET_ADMIN — but the note must always explain which.
func TestCapabilityProbeIsHonestOnThisHost(t *testing.T) {
	ok, note := probeAddressBinding()
	if note == "" {
		t.Fatal("probeAddressBinding returned no note; an operator with no SSH has nothing to act on")
	}
	if ok && !strings.Contains(note, "available") {
		t.Errorf("capable but the note does not say so: %q", note)
	}
	if !ok && !strings.Contains(note, "unavailable") {
		t.Errorf("incapable but the note does not say so: %q", note)
	}
	// THE RULE THE CAPABILITY TOKEN NOW MEANS. One token covers bind
	// AND unbind. The systemd delegation can only ADD (applyBoundRecords
	// only adds — at boot the interface holds the primary address, which
	// is not a record), so a box that reported capable off the presence
	// of systemctl promised two verbs and could perform one: every
	// unbind was a guaranteed 500, which is the rollback of a failed
	// swap and the whole of `floating-ip release`. Advertising the
	// capability therefore requires the capability IN THIS PROCESS.
	if ok && !holdsCapNetAdmin() {
		t.Errorf("reported capable without CAP_NET_ADMIN: %q — this box could bind and never unbind", note)
	}
	if !ok && !holdsCapNetAdmin() && !strings.Contains(note, "CAP_NET_ADMIN") {
		t.Errorf("refused without naming the missing capability, so an operator with no SSH cannot act: %q", note)
	}
}

// TestCapabilityProbeNeedsBothTools: the probe is also the gate on
// PERSISTENCE, which is a systemd oneshot. A box that could configure
// an address now but not carry it across a reboot must refuse before
// the swap, not report a bind that dies at 3am.
func TestCapabilityProbeNeedsBothTools(t *testing.T) {
	if !haveBinary("ip") && !haveBinary("systemctl") {
		t.Skip("host has neither tool; nothing to assert")
	}
	ok, note := probeAddressBinding()
	if ok && (!haveBinary("ip") || !haveBinary("systemctl")) {
		t.Errorf("capable without both `ip` and `systemctl`: %q", note)
	}
}

func containsString(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}
