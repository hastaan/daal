// bundle-rs-fixtures generates `.sbp` and oracle JSON files used by
// bundle-rs's parity tests. Output lands in
// client-shell/tauri/bundle-rs/tests/fixtures/ by default.
//
// Usage from the bundle/go module:
//
//	go run ./cmd/bundle-rs-fixtures -out ../../client-shell/tauri/bundle-rs/tests/fixtures
//
// The generator covers every variant in bundle/go/bundle/sbp_test.go
// plus a couple of v2-specific cases plus signed revocation vectors.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/publisher"
)

type oracle struct {
	Vector       string `json:"vector"`
	Description  string `json:"description"`
	SbpFile      string `json:"sbp_file"`
	PublisherPub string `json:"publisher_pub_hex"`
	ExpectParse  string `json:"expect_parse"`
	ExpectVerify string `json:"expect_verify"`
}

func main() {
	out := flag.String("out", "../../client-shell/tauri/bundle-rs/tests/fixtures",
		"output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		panic(err)
	}

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	future := now.Add(72 * time.Hour)
	past := now.Add(-1 * time.Hour)

	seed := sha256.Sum256([]byte("daal-bundle-rs-fixtures-v1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	fp := bundle.PublisherFingerprint(pub)

	mkRoute := func(validUntil time.Time, transport, scarcity string) bundle.Manifest {
		return bundle.Manifest{
			SpecVersion: 2,
			Publisher: bundle.PublisherInfo{
				Name:              "Parity Test Publisher",
				KeyFingerprintHex: fp.Hex,
				KeyCreatedAt:      now.Format(time.RFC3339),
				TrustClass:        "unknown",
			},
			Bundle: bundle.BundleInfo{
				ID:             "bundle-parity",
				Type:           "provider",
				CreatedAt:      now.Format(time.RFC3339),
				ExpiresAt:      future.Format(time.RFC3339),
				SupersedesKeys: []string{},
			},
			Routes: []bundle.RouteManifestEntry{{
				ID:              "route-parity",
				ScarcityClass:   scarcity,
				TransportFamily: transport,
				ConfigPath:      "profiles/route.json",
				ValidFrom:       now.Format(time.RFC3339),
				ValidUntil:      validUntil.Format(time.RFC3339),
			}},
		}
	}

	profiles := map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}

	type vectorBuilder struct {
		name, desc       string
		mutateManifest   func(m *bundle.Manifest)
		corruptSignature bool
		expectParse      string
		expectVerify     string
		profilesOverride map[string][]byte
	}

	vectors := []vectorBuilder{
		{name: "valid-v2", desc: "spec_version=2, valid signature, future expiry",
			mutateManifest: func(m *bundle.Manifest) {}, expectParse: "ok", expectVerify: "ok"},
		{name: "valid-v1", desc: "spec_version=1 (legacy), valid signature",
			mutateManifest: func(m *bundle.Manifest) { m.SpecVersion = 1 },
			expectParse:    "ok", expectVerify: "ok"},
		// spec_version 3 (RelayPack), 4 (sub-key cert chain) and 5 (anytls)
		// ARE accepted by bundle.VerifyBundle — see sbp.go's
		// `case 1, 2, 3, 4, SpecVersionAnyTLS`. This vector used to assert v3
		// was rejected, which stopped being true when FRP-7.5 widened the
		// gate; because nothing on the Go side checks the generator's
		// expectations against Go's own verifier, and the committed fixtures
		// were never regenerated, the contradiction stayed invisible until a
		// parity run in 2026-08. It then became "v5 is rejected", which Wave 5
		// spent on anytls. Always use the LOWEST genuinely unsupported
		// version — matching bundle/v2_test.go's TestSpecV6Rejected — and
		// move it in the same commit that widens the gate.
		{name: "invalid-spec-v6", desc: "spec_version=6 is beyond the supported range and must be rejected",
			mutateManifest: func(m *bundle.Manifest) { m.SpecVersion = 6 },
			expectParse:    "ok", expectVerify: "ErrUnsupportedSpec"},
		// WAVE 5 — the wire-compatibility contract for a new family, pinned
		// in the corpus BOTH parsers are checked against.
		//
		// An unknown family at spec_version <= 4 still rejects the whole
		// bundle with ErrInvalidEnum: that is what every already-distributed
		// client does, and the "unknown-transport" vector below covers it.
		// From spec_version 5 the same route is DROPPED and the pack still
		// verifies, so a recipient keeps the routes it does understand.
		{name: "v5-unknown-transport-degrades", desc: "spec_version=5: an unknown transport_family drops that route, the pack still verifies",
			mutateManifest: func(m *bundle.Manifest) {
				m.SpecVersion = 5
				extra := m.Routes[0]
				extra.ID = "route-from-the-future"
				extra.TransportFamily = "family-from-a-later-build"
				m.Routes = append(m.Routes, extra)
			},
			expectParse: "ok", expectVerify: "ok"},
		// Degradation is not a licence to import nothing. A pack whose every
		// route is unknown has failed at the only job a pack has, and says so.
		{name: "v5-all-unknown-transports", desc: "spec_version=5: every route unknown is ErrNoUsableRoutes, not a silent empty import",
			mutateManifest: func(m *bundle.Manifest) {
				m.SpecVersion = 5
				m.Routes[0].TransportFamily = "family-from-a-later-build"
			},
			expectParse: "ok", expectVerify: "ErrNoUsableRoutes"},
		// anytls may not ride an older spec_version: such a pack is rejected
		// WHOLE by every pre-Wave-5 client and reported as corrupted, so the
		// publisher is stopped here instead.
		{name: "anytls-on-spec-v4", desc: "transport_family=anytls at spec_version=4 must be refused",
			mutateManifest: func(m *bundle.Manifest) {
				m.SpecVersion = 4
				m.Routes[0].TransportFamily = "anytls"
			},
			expectParse: "ok", expectVerify: "ErrAnyTLSSpecVersionTooOld"},
		{name: "anytls-on-spec-v5", desc: "transport_family=anytls at spec_version=5 verifies",
			mutateManifest: func(m *bundle.Manifest) {
				m.SpecVersion = 5
				m.Routes[0].TransportFamily = "anytls"
			},
			expectParse: "ok", expectVerify: "ok"},
		{name: "invalid-signature", desc: "manifest.sig flipped",
			mutateManifest:   func(m *bundle.Manifest) {},
			corruptSignature: true, expectParse: "ok", expectVerify: "ErrInvalidSignature"},
		{name: "expired-route", desc: "route ValidUntil in the past",
			mutateManifest: func(m *bundle.Manifest) { m.Routes[0].ValidUntil = past.Format(time.RFC3339) },
			expectParse:    "ok", expectVerify: "ErrExpiredRoute"},
		{name: "expired-bundle", desc: "bundle ExpiresAt in the past",
			mutateManifest: func(m *bundle.Manifest) { m.Bundle.ExpiresAt = past.Format(time.RFC3339) },
			expectParse:    "ok", expectVerify: "ErrExpiredBundle"},
		{name: "unknown-transport", desc: "transport_family=unknown-family",
			mutateManifest: func(m *bundle.Manifest) { m.Routes[0].TransportFamily = "unknown-family" },
			expectParse:    "ok", expectVerify: "ErrInvalidEnum"},
		{name: "unknown-scarcity", desc: "scarcity_class=unknown",
			mutateManifest: func(m *bundle.Manifest) { m.Routes[0].ScarcityClass = "unknown-class" },
			expectParse:    "ok", expectVerify: "ErrInvalidEnum"},
		{name: "missing-profile", desc: "manifest references missing profile",
			mutateManifest:   func(m *bundle.Manifest) {},
			profilesOverride: map[string][]byte{},
			expectParse:      "ok", expectVerify: "ErrMissingProfile"},
		{name: "fingerprint-mismatch", desc: "manifest declares wrong KeyFingerprintHex",
			mutateManifest: func(m *bundle.Manifest) { m.Publisher.KeyFingerprintHex = "deadbeef" },
			expectParse:    "ok", expectVerify: "ErrFingerprintMismatch"},
		{name: "v2-pointer-rotation-ref", desc: "v2 directory bundle with pointer_rotation_ref present",
			mutateManifest: func(m *bundle.Manifest) {
				m.Bundle.Type = "directory"
				m.Bundle.PointerRotation = &bundle.PointerRotationRef{Path: "trust/pointer-rotation.json"}
			}, expectParse: "ok", expectVerify: "ok"},
	}

	oracles := []oracle{}
	for _, v := range vectors {
		manifest := mkRoute(future, "vless-reality", "normal")
		v.mutateManifest(&manifest)
		profilesForBundle := profiles
		if v.profilesOverride != nil {
			profilesForBundle = v.profilesOverride
		}
		data, err := bundle.BuildSignedBundleDeterministic(manifest, profilesForBundle, nil, pub, priv)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", v.name, err))
		}
		if v.corruptSignature {
			data = corruptManifestSig(data)
		}
		fname := v.name + ".sbp"
		path := filepath.Join(*out, fname)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			panic(err)
		}
		oracles = append(oracles, oracle{
			Vector:       v.name,
			Description:  v.desc,
			SbpFile:      fname,
			PublisherPub: hex.EncodeToString(pub),
			ExpectParse:  v.expectParse,
			ExpectVerify: v.expectVerify,
		})
	}

	// Signed revocation vectors.
	{
		_, body, err := publisher.BuildSignedRevocationList(priv,
			now.Format(time.RFC3339),
			[]string{fp.Hex}, []string{"route-x"}, "key compromised")
		if err != nil {
			panic(err)
		}
		path := filepath.Join(*out, "signed-revocation-ok.json")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			panic(err)
		}
		oracles = append(oracles, oracle{
			Vector:       "signed-revocation-ok",
			Description:  "valid SignedRevocation v=1",
			SbpFile:      "signed-revocation-ok.json",
			PublisherPub: hex.EncodeToString(pub),
			ExpectParse:  "ok",
			ExpectVerify: "ok",
		})

		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			panic(err)
		}
		sig, _ := doc["signature_hex"].(string)
		if len(sig) > 4 {
			runes := []byte(sig)
			if runes[0] == '0' {
				runes[0] = '1'
			} else {
				runes[0] = '0'
			}
			doc["signature_hex"] = string(runes)
		}
		bad2, _ := json.Marshal(doc)
		path2 := filepath.Join(*out, "signed-revocation-tampered.json")
		if err := os.WriteFile(path2, bad2, 0o644); err != nil {
			panic(err)
		}
		oracles = append(oracles, oracle{
			Vector:       "signed-revocation-tampered",
			Description:  "SignedRevocation with corrupted signature_hex",
			SbpFile:      "signed-revocation-tampered.json",
			PublisherPub: hex.EncodeToString(pub),
			ExpectParse:  "ok",
			ExpectVerify: "ErrInvalidSignature",
		})
	}

	idx, err := json.MarshalIndent(oracles, "", "  ")
	if err != nil {
		panic(err)
	}
	idx = append(idx, '\n')
	if err := os.WriteFile(filepath.Join(*out, "oracles.json"), idx, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(oracles), *out)
}

// corruptManifestSig parses the deterministic input bundle, flips a byte
// in manifest.sig, then rebuilds the bundle via the deterministic builder
// so the output is byte-stable across runs (sorted ZIP entries, zero
// mtime, Store compression). Map iteration order MUST NOT leak into the
// bytes here.
func corruptManifestSig(data []byte) []byte {
	b, err := bundle.ParseSBP(byteReaderAt(data), int64(len(data)))
	if err != nil {
		panic(err)
	}
	b.Signature[0] ^= 0xff
	// Splice the corrupted sig + publisher.pub + profiles back through
	// the deterministic builder. Pass the corrupted sig as an "extra"
	// override of the canonical manifest.sig that
	// BuildSignedBundleDeterministic would otherwise compute.
	out, err := buildBundleWithCorruptedSig(b.Manifest, b.Profiles, b.PublisherPub, b.Signature)
	if err != nil {
		panic(err)
	}
	return out
}

// buildBundleWithCorruptedSig is a deterministic local rebuilder used
// only to produce the invalid-signature parity fixture. It mirrors
// bundle.BuildSignedBundleDeterministic's layout (sorted entries, zero
// mtime, Store compression) but takes a precomputed (corrupted)
// signature instead of computing one.
func buildBundleWithCorruptedSig(manifest bundle.Manifest, profiles map[string][]byte, pub, sig []byte) ([]byte, error) {
	manifestBytes, err := bundle.CanonicalManifestJSON(manifest)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"manifest.json": manifestBytes,
		"manifest.sig":  append([]byte(nil), sig...),
		"publisher.pub": append([]byte(nil), pub...),
	}
	for name, data := range profiles {
		files[name] = append([]byte(nil), data...)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zeroTime := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range names {
		hdr := &zip.FileHeader{
			Name:     name,
			Method:   zip.Store,
			Modified: zeroTime,
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, fmt.Errorf("eof")
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, fmt.Errorf("short read")
	}
	return n, nil
}
