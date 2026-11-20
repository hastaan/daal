package cli

// The standby verbs, on the seam the wizard drives. What these hold
// down is the money rule and the order: probe the box before renting;
// rent → bind (over the address the relay answers on) → pin check and
// probe over the standby; on any failure unbind, then release — and keep
// (billing, named) rather than release an address the box could not be
// told to drop.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/providers/hetzner"
)

type fakeStandbyProvider struct {
	providerFace // nil: anything else panics
	box          *fakeBox

	ensure    *hetzner.StandbyResult
	ensureErr error
	strays    []provider.StandbyAddress
	removed   []string
	removeErr error
	price     hetzner.StandbyPrice
}

func (f *fakeStandbyProvider) log(s string) { f.box.calls = append(f.box.calls, s) }

func (f *fakeStandbyProvider) EnsureStandby(_ context.Context, _ *provider.OperatorRecord) (*hetzner.StandbyResult, error) {
	f.log("rent")
	return f.ensure, f.ensureErr
}

func (f *fakeStandbyProvider) PromoteStandby(_ context.Context, rec *provider.OperatorRecord) (string, net.IP, error) {
	f.log("promote")
	prior, priorIP := rec.FloatingIPID, append(net.IP(nil), rec.PublicIP...)
	rec.FloatingIPID = rec.Standby.FloatingIPID
	provider.AdoptPublicIP(rec, rec.Standby.IP)
	rec.Standby = nil
	return prior, priorIP, nil
}

func (f *fakeStandbyProvider) RemoveStandby(_ context.Context, rec *provider.OperatorRecord, id string) (bool, error) {
	f.log("release " + id)
	if f.removeErr != nil {
		return false, f.removeErr
	}
	f.removed = append(f.removed, id)
	if rec.Standby != nil && rec.Standby.FloatingIPID == id {
		rec.Standby = nil
	}
	return true, nil
}

func (f *fakeStandbyProvider) StandbyStrays(_ context.Context, _ *provider.OperatorRecord) ([]provider.StandbyAddress, error) {
	return f.strays, nil
}

func (f *fakeStandbyProvider) StandbyMonthlyPrice(_ context.Context, loc string) (hetzner.StandbyPrice, error) {
	p := f.price
	p.Location = loc
	return p, nil
}

func standbyFixture(t *testing.T, mutate func(*provider.OperatorRecord)) (recordFile, tokenFile, keyFile string) {
	t.Helper()
	recordFile, tokenFile, keyFile = l3Fixture(t)
	rec, err := readRecord(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	rec.Candidates = []provider.CandidateMeta{{Family: "vless-reality", ExposureMode: "direct_vps", Port: 443,
		PublicRiskTags: []string{"public_ip:198.51.100.7"}}}
	if mutate != nil {
		mutate(rec)
	}
	body, _ := json.Marshal(rec)
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

func newStandbyFake(box *fakeBox) *fakeStandbyProvider {
	return &fakeStandbyProvider{box: box,
		ensure: &hetzner.StandbyResult{Standby: provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20").To4()}, Created: true},
		price:  hetzner.StandbyPrice{Currency: "EUR", VATRate: "19.00", MonthlyNet: "3.0000000000", MonthlyGross: "3.5700000000"},
	}
}

func standbyAddArgs(recordFile, tokenFile, keyFile string, extra ...string) []string {
	return append([]string{"standby", "add", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, extra...)
}

func decodeStandbyOut(t *testing.T, b []byte) standbyOut {
	t.Helper()
	var out standbyOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("stdout is not the standby JSON: %v\n%s", err, b)
	}
	return out
}

func TestStandbyAdd_OrderAndResult(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := newStandbyFake(box)
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, nil)

	var stdout, stderr bytes.Buffer
	if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	want := []string{"capabilities", "rent", "bind 203.0.113.20", "capabilities", "probe 203.0.113.20"}
	if strings.Join(box.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", box.calls, want)
	}
	if box.bound[0][0] != "198.51.100.7" {
		t.Errorf("bind travelled over %s, want the address the relay answers on", box.bound[0][0])
	}
	out := decodeStandbyOut(t, stdout.Bytes())
	sb := out.Record.Standby
	if sb == nil || sb.FloatingIPID != "fip-sb" || sb.Mode != "sealed" || !sb.IP.Equal(net.ParseIP("203.0.113.20")) {
		t.Fatalf("record standby = %+v", sb)
	}
	if !out.Record.PublicIP.Equal(net.ParseIP("198.51.100.7")) || out.Record.FloatingIPID != "" {
		t.Errorf("the standby was adopted: %+v", out.Record)
	}
	if len(strings.ReplaceAll(out.Key, " ", "")) != 26 || !out.Created {
		t.Errorf("key %q created %v", out.Key, out.Created)
	}
	if out.Price == nil || out.Price.MonthlyNetCents != 300 || out.Price.MonthlyGrossCents != 357 {
		t.Errorf("price = %+v", out.Price)
	}
	// --record-file is read, never written.
	rec, _ := readRecord(recordFile)
	if rec.Standby != nil {
		t.Error("the record file was rewritten")
	}
}

// A relay too old to bind must not be billed for an address to find out.
func TestStandbyAdd_OldBoxRefusedBeforeRenting(t *testing.T) {
	b := newFakeBox()
	b.caps = &mgmt.BoxCapabilities{OK: true, MgmtAPIVersion: mgmt.MgmtAPIVersionSplitRotation,
		Capabilities: []string{mgmt.CapRotateCredentialsScoped}}
	box := withFakeBox(t, b)
	f := newStandbyFake(box)
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc != exitCapabilityUnsupported {
		t.Fatalf("rc=%d", rc)
	}
	if strings.Join(box.calls, "|") != "capabilities" {
		t.Errorf("calls = %v", box.calls)
	}
}

func TestStandbyAdd_ShadowsocksOnlyRelayRefused(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	withFakeProvider(t, newStandbyFake(box))
	recordFile, tokenFile, keyFile := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Candidates = []provider.CandidateMeta{{Family: "shadowsocks", ExposureMode: "direct_vps"}}
	})
	var stdout, stderr bytes.Buffer
	if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("accepted")
	}
	if len(box.calls) != 0 {
		t.Errorf("calls = %v, want none", box.calls)
	}
}

// ROLLBACK. Every failure after the rent: unbind (when the box may hold
// it), then release. Nothing stays billing.
func TestStandbyAdd_RollsBackOnEveryLateFailure(t *testing.T) {
	cases := map[string]struct {
		setup func(*fakeBox, *fakeStandbyProvider)
		want  []string
	}{
		"assign": {
			setup: func(b *fakeBox, f *fakeStandbyProvider) { f.ensureErr = errors.New("assign: locked") },
			want:  []string{"capabilities", "rent", "release fip-sb"},
		},
		"bind": {
			setup: func(b *fakeBox, f *fakeStandbyProvider) { b.bindErr = errors.New("permission denied") },
			want:  []string{"capabilities", "rent", "bind 203.0.113.20", "unbind 203.0.113.20", "release fip-sb"},
		},
		"probe": {
			setup: func(b *fakeBox, f *fakeStandbyProvider) {
				prev := l3AddressServes
				l3AddressServes = func(ip net.IP, _ int, _ time.Duration) error {
					b.calls = append(b.calls, "probe "+ip.String())
					return errors.New("does not serve")
				}
				t.Cleanup(func() { l3AddressServes = prev })
			},
			want: []string{"capabilities", "rent", "bind 203.0.113.20", "capabilities", "probe 203.0.113.20",
				"unbind 203.0.113.20", "release fip-sb"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			box := withFakeBox(t, newFakeBox())
			f := newStandbyFake(box)
			tc.setup(box, f)
			withFakeProvider(t, f)
			recordFile, tokenFile, keyFile := standbyFixture(t, nil)
			var stdout, stderr bytes.Buffer
			if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
				t.Fatal("a failed add exited 0")
			}
			if strings.Join(box.calls, "|") != strings.Join(tc.want, "|") {
				t.Errorf("calls = %v\nwant    %v", box.calls, tc.want)
			}
			out := decodeStandbyOut(t, stdout.Bytes())
			if out.Record != nil || len(out.StillBilling) != 0 || len(out.Released) != 1 {
				t.Errorf("out = %+v", out)
			}
			if !strings.Contains(stderr.String(), "nothing is billing") {
				t.Errorf("stderr = %s", stderr.String())
			}
		})
	}
}

// The box could not be told to drop it: keep it reserved, name it.
func TestStandbyAdd_KeepsWhatTheBoxMayStillHold(t *testing.T) {
	b := newFakeBox()
	b.bindErr = errors.New("timeout")
	b.unbindErr = errors.New("timeout")
	box := withFakeBox(t, b)
	f := newStandbyFake(box)
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("exited 0")
	}
	if len(f.removed) != 0 {
		t.Error("released an address the box may still answer on")
	}
	out := decodeStandbyOut(t, stdout.Bytes())
	if len(out.StillBilling) != 1 || out.StillBilling[0].FloatingIPID != "fip-sb" {
		t.Errorf("still_billing = %+v", out.StillBilling)
	}
	if !strings.Contains(stderr.String(), "still reserved and billing") {
		t.Errorf("stderr = %s", stderr.String())
	}
}

// A standby the record already named is an earlier add's, and a failed
// repair does not release it.
func TestStandbyAdd_FailedRepairKeepsTheExistingStandby(t *testing.T) {
	b := newFakeBox()
	b.bindErr = errors.New("permission denied")
	box := withFakeBox(t, b)
	f := newStandbyFake(box)
	f.ensure.Created = false
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Standby = &provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	})
	var stdout, stderr bytes.Buffer
	_ = Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr)
	if len(f.removed) != 0 {
		t.Errorf("released the record's own standby: %v", f.removed)
	}
}

func TestStandbyAdd_LimitIsItsOwnExit(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := newStandbyFake(box)
	f.ensure, f.ensureErr = nil, hetzner.ErrStandbyLimit
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc != exitStandbyLimit {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.HasPrefix(stderr.String(), "E_STANDBY_LIMIT:") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// Strays from killed runs are released on the way.
func TestStandbyAdd_ReleasesStrays(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := newStandbyFake(box)
	f.ensure.Created, f.ensure.Adopted = false, true
	f.ensure.Strays = []provider.StandbyAddress{{FloatingIPID: "fip-old", IP: net.ParseIP("203.0.113.21")}}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, nil)
	var stdout, stderr bytes.Buffer
	if rc := Run(standbyAddArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	tail := strings.Join(box.calls[len(box.calls)-2:], "|")
	if tail != "unbind 203.0.113.21|release fip-old" {
		t.Errorf("calls = %v", box.calls)
	}
	out := decodeStandbyOut(t, stdout.Bytes())
	if !out.Adopted || out.Record.Standby.FloatingIPID != "fip-sb" {
		t.Errorf("out = %+v", out)
	}
}

func TestStandbyPromote(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	withFakeProvider(t, newStandbyFake(box))
	recordFile, tokenFile, _ := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Standby = &provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	})
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"standby", "promote", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	out := decodeStandbyOut(t, stdout.Bytes())
	if out.Key != "000G40 R40M3 0E209 185WP 03H2G" {
		t.Errorf("key = %q", out.Key)
	}
	if !out.Record.PublicIP.Equal(net.ParseIP("203.0.113.20")) || out.Record.Standby != nil || out.PriorAddress != "198.51.100.7" {
		t.Errorf("out = %+v", out)
	}
	if strings.Join(box.calls, "|") != "probe 203.0.113.20|promote" {
		t.Errorf("calls = %v", box.calls)
	}
}

func TestStandbyPromote_RefusesADeadStandby(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	withFakeProvider(t, newStandbyFake(box))
	prev := l3AddressServes
	l3AddressServes = func(net.IP, int, time.Duration) error { return errors.New("dead") }
	t.Cleanup(func() { l3AddressServes = prev })
	recordFile, tokenFile, _ := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Standby = &provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	})
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"standby", "promote", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr); rc == 0 {
		t.Fatal("promoted onto a dead address")
	}
}

func TestStandbyRemove_UnbindsThenReleasesEverything(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := newStandbyFake(box)
	f.strays = []provider.StandbyAddress{{FloatingIPID: "fip-old", IP: net.ParseIP("203.0.113.21")}}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Standby = &provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	})
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"standby", "remove", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	want := "unbind 203.0.113.20|release fip-sb|unbind 203.0.113.21|release fip-old"
	if strings.Join(box.calls, "|") != want {
		t.Errorf("calls = %v", box.calls)
	}
	if box.unbound[0][0] != "198.51.100.7" {
		t.Errorf("unbind travelled over %s", box.unbound[0][0])
	}
	out := decodeStandbyOut(t, stdout.Bytes())
	if out.Record.Standby != nil || len(out.Released) != 2 {
		t.Errorf("out = %+v", out)
	}
}

func TestStandbyRemove_UnbindFailureKeepsItAndSaysSo(t *testing.T) {
	b := newFakeBox()
	b.unbindErr = errors.New("timeout")
	box := withFakeBox(t, b)
	f := newStandbyFake(box)
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Standby = &provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	})
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"standby", "remove", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr)
	if rc != exitAddressStillReserved {
		t.Fatalf("rc=%d", rc)
	}
	if len(f.removed) != 0 {
		t.Error("released while the box may still hold it")
	}
}

// --skip-unbind needs no key: for a relay that is gone.
func TestStandbyRemove_SkipUnbind(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := newStandbyFake(box)
	withFakeProvider(t, f)
	recordFile, tokenFile, _ := standbyFixture(t, func(r *provider.OperatorRecord) {
		r.Standby = &provider.StandbyAddress{FloatingIPID: "fip-sb", IP: net.ParseIP("203.0.113.20")}
	})
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"standby", "remove", "--record-file", recordFile, "--token-file", tokenFile, "--skip-unbind"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	if strings.Join(box.calls, "|") != "release fip-sb" {
		t.Errorf("calls = %v", box.calls)
	}
}

func TestStandbyPrice(t *testing.T) {
	box := &fakeBox{}
	f := newStandbyFake(box)
	prev := buildStandbyPriceFn
	buildStandbyPriceFn = func(string) (standbyProvider, error) { return f, nil }
	t.Cleanup(func() { buildStandbyPriceFn = prev })
	_, tokenFile, _ := standbyFixture(t, nil)
	var stdout, stderr bytes.Buffer
	// --progress-json is what the wizard's generic runner always adds.
	if rc := Run([]string{"standby", "price", "--token-file", tokenFile, "--region", "nbg1", "--progress-json"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	var got standbyPriceOut
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Location != "nbg1" || got.MonthlyNetCents != 300 || got.MonthlyGrossCents != 357 || got.Currency != "EUR" {
		t.Errorf("price = %+v", got)
	}
}

func TestDecimalCents(t *testing.T) {
	for in, want := range map[string]int64{"3.0000000000": 300, "3.5700000000": 357, "0.505": 51, "0.504": 50, "x": -1, "-1": -1} {
		if got := decimalCents(in); got != want {
			t.Errorf("decimalCents(%q) = %d, want %d", in, got, want)
		}
	}
}
