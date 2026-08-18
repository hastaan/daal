package bundle

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------
// WAVE 5 — the wire-compatibility contract for adding a transport
// family, tested from both sides of the break.
//
// Adding `anytls` to the enum is wire-breaking, and the break is at
// PACK granularity on every client already in the field: an unknown
// transport_family fails the whole bundle, not the one route. These
// tests pin what that means, what the spec-version gate buys, and what
// changes from spec_version 5 onward.
// ---------------------------------------------------------------

// preWave5Families is the transport-family list EXACTLY as every client
// shipped before Wave 5 carries it — validTransport minus TransportAnyTLS.
var preWave5Families = map[string]bool{
	"vless-reality": true, "naive": true, "websocket-tls": true,
	"hysteria2": true, "tuic": true, "snowflake": true, "webtunnel": true,
	"masque": true, "shadowsocks": true, "tor-bridge": true,
	"wireguard": true, "amneziawg": true, "psiphon": true, "conjure": true,
	"transport_module": true, "lifeline_relay": true, "other": true,
}

// verifyAsPreWave5 MODELS the verifier every already-distributed client
// runs. It is not the real old binary — we cannot link one — but it is a
// faithful transcription of the two decisions that matter, both of which
// are still visible in this file's history:
//
//	spec gate:  switch spec { case 1,2,3,4: default: ErrUnsupportedSpec }
//	route loop: for each route { if !validTransport(f) { return ErrInvalidEnum } }
//
// with the route loop returning on the FIRST failure, so one bad route
// takes the whole pack. bundle-rs/src/sbp.rs made the identical two
// decisions, so this models both language clients at once.
//
// It exists so the claims in the TransportAnyTLS doc comment are
// assertions rather than assurances.
func verifyAsPreWave5(b *Bundle) error {
	switch b.Manifest.SpecVersion {
	case 1, 2, 3, 4:
	default:
		return ErrUnsupportedSpec
	}
	for _, r := range b.Manifest.Routes {
		if !preWave5Families[r.TransportFamily] {
			return ErrInvalidEnum
		}
	}
	return nil
}

func parseOrFail(t *testing.T, data []byte) *Bundle {
	t.Helper()
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return b
}

// routeAt clones the manifest's template route under a new id/family.
func routeAt(m Manifest, id, family string) RouteManifestEntry {
	r := m.Routes[0]
	r.ID = id
	r.TransportFamily = family
	return r
}

// TestOldPackWithoutAnyTLSImportsUnchanged is the "we broke nothing"
// test, and it is the one that matters most.
//
// Adding a family to the enum must not disturb a single already-
// distributed pack. Such a pack declares spec_version 1-4 and names only
// families the old list knew, so BOTH the modelled old verifier and the
// current one must accept it, and the current one must not silently drop
// any of its routes.
func TestOldPackWithoutAnyTLSImportsUnchanged(t *testing.T) {
	for _, spec := range []int{1, 2, 3, 4} {
		m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
		m.SpecVersion = spec
		m.Routes = append(m.Routes,
			routeAt(m, "route-hy2", "hysteria2"),
			routeAt(m, "route-ws", "websocket-tls"),
			routeAt(m, "route-naive", "naive"),
		)
		b := parseOrFail(t, mustSignedBundle(t, m, nil))

		if err := verifyAsPreWave5(b); err != nil {
			t.Fatalf("spec %d: a pre-Wave-5 client rejected an old pack: %v", spec, err)
		}
		if err := VerifyBundle(b); err != nil {
			t.Fatalf("spec %d: current verifier rejected an old pack: %v", spec, err)
		}
		if got := len(UsableRoutes(b)); got != 4 {
			t.Fatalf("spec %d: %d usable routes, want all 4 — the new rule dropped a route it should not have",
				spec, got)
		}
	}
}

// TestAnyTLSPackIsRefusedByOldClientAsSpecNotCorruption is the honest
// statement of the cost, and it is deliberately not dressed up.
//
// An old client cannot use a pack containing anytls. Nothing recovers
// that; the family did not exist when the binary was built. The ONLY
// thing the spec-version gate buys is WHICH refusal it gives — and that
// is worth having, because the two failures send the user to completely
// different places:
//
//	spec_version 4 + anytls -> ErrInvalidEnum   -> "bundle_corrupted"
//	                                              (go re-download it; the
//	                                               file was never damaged)
//	spec_version 5 + anytls -> ErrUnsupportedSpec -> "your build is too old"
//	                                                 (true and actionable)
//
// The gate also runs BEFORE the route loop, so the answer does not
// depend on where in routes[] the anytls entry happens to sit.
func TestAnyTLSPackIsRefusedByOldClientAsSpecNotCorruption(t *testing.T) {
	// What a naive implementation would have shipped: the new family on
	// the old spec_version.
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 4
	m.Routes = append(m.Routes, routeAt(m, "route-anytls", "anytls"))
	naive := parseOrFail(t, mustSignedBundle(t, m, nil))

	if err := verifyAsPreWave5(naive); !errors.Is(err, ErrInvalidEnum) {
		t.Fatalf("old client on a spec-4 anytls pack: got %v, want ErrInvalidEnum "+
			"(this is the misleading 'bundle_corrupted' path)", err)
	}
	// And the current verifier refuses to let a publisher mint it at all,
	// so that pack never reaches anyone.
	if err := VerifyBundle(naive); !errors.Is(err, ErrAnyTLSSpecVersionTooOld) {
		t.Fatalf("spec-4 anytls pack: got %v, want ErrAnyTLSSpecVersionTooOld", err)
	}

	// What we actually ship: spec_version 5.
	m2 := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m2.SpecVersion = SpecVersionAnyTLS
	m2.Routes = append(m2.Routes, routeAt(m2, "route-anytls", "anytls"))
	shipped := parseOrFail(t, mustSignedBundle(t, m2, nil))

	if err := verifyAsPreWave5(shipped); !errors.Is(err, ErrUnsupportedSpec) {
		t.Fatalf("old client on a spec-5 pack: got %v, want ErrUnsupportedSpec", err)
	}
	if err := VerifyBundle(shipped); err != nil {
		t.Fatalf("current verifier rejected a spec-5 anytls pack: %v", err)
	}
	if got := len(UsableRoutes(shipped)); got != 2 {
		t.Fatalf("usable routes = %d, want 2", got)
	}
}

// TestUnknownFamilyDegradesToOneRouteFromSpec5 is the forward-looking
// half: the rule that makes the NEXT family cheap.
//
// A spec-5 client handed a pack naming a family from a later build keeps
// every route it does understand and loses only the one it does not.
// This is the property that could not be backported into the binaries
// already in the field, and paying for it is what the anytls bump bought.
func TestUnknownFamilyDegradesToOneRouteFromSpec5(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = SpecVersionAnyTLS
	m.Routes = append(m.Routes,
		routeAt(m, "route-anytls", "anytls"),
		routeAt(m, "route-future", "some-family-from-2027"),
		routeAt(m, "route-hy2", "hysteria2"),
	)
	b := parseOrFail(t, mustSignedBundle(t, m, nil))

	if err := VerifyBundle(b); err != nil {
		t.Fatalf("one unknown family took the whole pack down: %v", err)
	}
	usable := UsableRoutes(b)
	if len(usable) != 3 {
		t.Fatalf("usable routes = %d, want 3 (only the future family drops)", len(usable))
	}
	for _, r := range usable {
		if r.ID == "route-future" {
			t.Fatal("an unknown-family route survived into the usable set")
		}
	}
}

// TestUnknownFamilyStillFatalAtOldSpec pins the behaviour we did NOT
// change. Packs at spec_version <= 4 must keep failing exactly as they
// always have, with exactly the same error — that is what keeps the
// cross-language fixture corpus and every shipped importer honest.
func TestUnknownFamilyStillFatalAtOldSpec(t *testing.T) {
	for _, spec := range []int{1, 2, 3, 4} {
		m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
		m.SpecVersion = spec
		m.Routes = append(m.Routes, routeAt(m, "route-future", "some-family-from-2027"))
		b := parseOrFail(t, mustSignedBundle(t, m, nil))
		if err := VerifyBundle(b); !errors.Is(err, ErrInvalidEnum) {
			t.Fatalf("spec %d: got %v, want ErrInvalidEnum (unchanged legacy behaviour)", spec, err)
		}
	}
}

// TestAllUnknownFamiliesIsAnErrorNotAnEmptyImport.
//
// Degradation must not turn into a silent nothing. A pack whose every
// route is unusable has failed at the only job a pack has, and saying
// "imported, 0 routes" would leave the recipient staring at an empty
// list with no hint that a newer build would help.
func TestAllUnknownFamiliesIsAnErrorNotAnEmptyImport(t *testing.T) {
	m := baseManifest(t, "normal", "some-family-from-2027", time.Now().Add(24*time.Hour))
	m.SpecVersion = SpecVersionAnyTLS
	m.Routes = append(m.Routes, routeAt(m, "route-future-2", "another-future-family"))
	b := parseOrFail(t, mustSignedBundle(t, m, nil))
	if err := VerifyBundle(b); !errors.Is(err, ErrNoUsableRoutes) {
		t.Fatalf("got %v, want ErrNoUsableRoutes", err)
	}
}

// TestDegradationNeverSkipsASafetyCheck is the security half of the
// degradation rule, and the reason validateRoute checks the family LAST.
//
// If the family check ran first — where it used to — a route naming an
// unknown family would return before its own unsafe-path, expiry and
// revocation checks ever ran, and at spec 5 that route would then be
// quietly dropped. A future-sounding family string would have become a
// way to smuggle a zip-slip config path or a revoked route ID past the
// verifier without the pack failing. Each case below must still fail the
// WHOLE pack, with its own specific error rather than being degraded.
func TestDegradationNeverSkipsASafetyCheck(t *testing.T) {
	mk := func(mutate func(*RouteManifestEntry), rev *RevocationList) *Bundle {
		m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
		m.SpecVersion = SpecVersionAnyTLS
		bad := routeAt(m, "route-hostile", "some-family-from-2027")
		mutate(&bad)
		m.Routes = append(m.Routes, bad)
		b := parseOrFail(t, mustSignedBundle(t, m, nil))
		b.Revocation = rev
		return b
	}

	t.Run("unsafe path", func(t *testing.T) {
		b := mk(func(r *RouteManifestEntry) { r.ConfigPath = "../../etc/passwd" }, nil)
		if err := VerifyBundle(b); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("got %v, want ErrUnsafePath — an unknown family must not buy a route "+
				"a pass on the archive-path check", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		b := mk(func(r *RouteManifestEntry) {
			r.ValidUntil = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		}, nil)
		if err := VerifyBundle(b); !errors.Is(err, ErrExpiredRoute) {
			t.Fatalf("got %v, want ErrExpiredRoute", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		b := mk(func(r *RouteManifestEntry) {}, &RevocationList{RevokedRoutes: []string{"route-hostile"}})
		if err := VerifyBundle(b); !errors.Is(err, ErrRevokedRoute) {
			t.Fatalf("got %v, want ErrRevokedRoute — revocation is never weakened by degradation", err)
		}
	})

	t.Run("missing profile", func(t *testing.T) {
		b := mk(func(r *RouteManifestEntry) { r.ConfigPath = "profiles/absent.json" }, nil)
		if err := VerifyBundle(b); !errors.Is(err, ErrMissingProfile) {
			t.Fatalf("got %v, want ErrMissingProfile", err)
		}
	})
}

// TestSpec5IsAcceptedAndAnyTLSIsInTheEnum guards the two one-line facts
// the whole wave rests on, so a careless revert is a red test rather
// than a family that mints into packs nothing accepts.
func TestSpec5IsAcceptedAndAnyTLSIsInTheEnum(t *testing.T) {
	if SpecVersionAnyTLS != 5 {
		t.Fatalf("SpecVersionAnyTLS = %d; bundle-rs's SPEC_VERSION_ANYTLS must move with it",
			SpecVersionAnyTLS)
	}
	if !validTransport(string(TransportAnyTLS)) {
		t.Fatal("anytls is not in validTransport")
	}
	if preWave5Families[string(TransportAnyTLS)] {
		t.Fatal("the pre-Wave-5 model knows anytls; it must not, or these tests prove nothing")
	}
}
