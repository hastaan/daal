package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Phase 3A bundle-format widening tests. See
// specs/sbp-v1.md "Phase 3A field semantics" and
// specs/transport-families-v1.md.

func TestSBPv1_WebTunnelFamilyAccepted(t *testing.T) {
	m := baseManifest(t, "experimental", "webtunnel", time.Now().Add(24*time.Hour))
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSBPv1_3AReservedFamiliesAccepted(t *testing.T) {
	for _, fam := range []string{"psiphon", "conjure", "transport_module", "lifeline_relay"} {
		m := baseManifest(t, "experimental", fam, time.Now().Add(24*time.Hour))
		data := mustSignedBundle(t, m, nil)
		b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("%s parse: %v", fam, err)
		}
		if err := VerifyBundle(b); err != nil {
			t.Fatalf("%s verify: %v", fam, err)
		}
	}
}

func TestSBPv1_FamilySpecificConfigRoundTrip(t *testing.T) {
	m := baseManifest(t, "experimental", "webtunnel", time.Now().Add(24*time.Hour))
	m.Routes[0].FamilySpecificConfig = json.RawMessage(`{"webtunnel_secret_path":"abc","webtunnel_alpn":["http/1.1"]}`)
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	got := string(b.Manifest.Routes[0].FamilySpecificConfig)
	if got == "" {
		t.Fatalf("family_specific_config did not round-trip")
	}
}

func TestSBPv1_FamilySpecificConfigNonObjectRejected(t *testing.T) {
	for _, body := range []string{`[]`, `123`, `"hello"`, `null`} {
		m := baseManifest(t, "experimental", "webtunnel", time.Now().Add(24*time.Hour))
		m.Routes[0].FamilySpecificConfig = json.RawMessage(body)
		data := mustSignedBundle(t, m, nil)
		b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyBundle(b); !errors.Is(err, ErrFamilySpecificConfigShape) {
			t.Errorf("body %q: want ErrFamilySpecificConfigShape, got %v", body, err)
		}
	}
}

func TestSBPv1_ExperimentalMinVersionAcceptsValidSemver(t *testing.T) {
	for _, v := range []string{"0.7.0", "1.0.0", "0.0.1", "v0.7.0", "1.2.3-rc1", "1.2.3-rc.1"} {
		m := baseManifest(t, "experimental", "webtunnel", time.Now().Add(24*time.Hour))
		m.Routes[0].ExperimentalMinEngineVersion = v
		data := mustSignedBundle(t, m, nil)
		b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyBundle(b); err != nil {
			t.Errorf("semver %q: want accept, got %v", v, err)
		}
	}
}

func TestSBPv1_ExperimentalMinVersionRejectsInvalid(t *testing.T) {
	for _, v := range []string{"0.7", "1.0.0.0", "abc", "01.0.0", "1.0", ""} {
		if v == "" {
			continue // empty is the explicit "no minimum" sentinel; skip
		}
		m := baseManifest(t, "experimental", "webtunnel", time.Now().Add(24*time.Hour))
		m.Routes[0].ExperimentalMinEngineVersion = v
		data := mustSignedBundle(t, m, nil)
		b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyBundle(b); !errors.Is(err, ErrInvalidExperimentalMinVersion) {
			t.Errorf("semver %q: want ErrInvalidExperimentalMinVersion, got %v", v, err)
		}
	}
}

func TestSBPv1_WebTunnelBulkCapableRejected(t *testing.T) {
	m := baseManifest(t, "bulk-capable", "webtunnel", time.Now().Add(24*time.Hour))
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrWebTunnelBulkCapable) {
		t.Fatalf("want ErrWebTunnelBulkCapable, got %v", err)
	}
}

func TestSBPv1_OtherFamilyStillAcceptedAtParse(t *testing.T) {
	// V0 forward-compat: `other` is accepted at parse time.
	// (The path manager refuses to select it; that is enforced at
	// the routestore taxonomy layer, not the parser.)
	m := baseManifest(t, "normal", "other", time.Now().Add(24*time.Hour))
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Errorf("other family must still parse-verify; got %v", err)
	}
}

func TestSBPv1_KillSwitchesEmptyArrayRoundTrips(t *testing.T) {
	// 3A reservation: the parser accepts an empty array.
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.KillSwitches = []KillSwitchEntry{}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Manifest.KillSwitches == nil {
		// JSON round-trip may produce empty slice or nil; both are
		// acceptable as "no entries".
		t.Logf("kill_switches absent on round-trip; fine — 3A reserves the slot.")
	}
}
