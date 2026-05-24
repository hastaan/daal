// bundle-subkey-sample emits the canonical FRP-7.5 sample
// artefact `subkey-signed-A.sbp` referenced by
// `specs/sbp-v1.md` "Sub-key cert chain". The artefact is a
// .sbp produced by signing with a sub-key whose cert was signed
// by `samples/keys-A/publisher.priv` (the existing sample root
// from Phase 1A).
//
// Usage from the bundle/go module:
//
//	go run ./cmd/bundle-subkey-sample \
//	   -keys-dir ../../specs/test-vectors/bundles/samples/keys-A \
//	   -out ../../specs/test-vectors/bundles/samples/subkey-signed-A.sbp
//
// The generator is deterministic at the bundle layer (uses
// `bundle.BuildSignedBundleDeterministic` + a fixed `now`) but
// the sub-key keypair is freshly minted on every run because
// the root key never sees the sub-key's secret half. To make
// the artefact reproducible across runs, the sub-key seed is
// derived from a fixed string at startup.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"daal/bundle-go/bundle"
)

const (
	// Pinned `now` so the artefact is byte-stable across runs.
	// Choice rationale: 2026-05-03T00:00:00Z = 1777795200, the
	// FRP-7.5 ship date. The 90-day cert window therefore runs
	// from 2026-05-02T23:00:00Z to 2026-08-01T00:00:00Z. Tests
	// that re-verify the artefact only need their wall-clock to
	// be inside that 90-day window.
	pinnedNowUnix = int64(1_777_795_200) // 2026-05-03T00:00:00Z
	// Deterministic sub-key seed (label) — only the bundle
	// authors know this and it does not leak any production
	// material.
	sampleSubkeySeedLabel = "daal-frp-7.5-sample-subkey-seed-v1"
)

func deterministicSubkey() (ed25519.PublicKey, ed25519.PrivateKey) {
	h := sha256.Sum256([]byte(sampleSubkeySeedLabel))
	priv := ed25519.NewKeyFromSeed(h[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func main() {
	keysDir := flag.String("keys-dir", "specs/test-vectors/bundles/samples/keys-A",
		"directory containing publisher.priv + publisher.pub")
	out := flag.String("out", "specs/test-vectors/bundles/samples/subkey-signed-A.sbp",
		"output .sbp path")
	flag.Parse()

	rootPubBytes, err := os.ReadFile(filepath.Join(*keysDir, "publisher.pub"))
	if err != nil {
		fail(err)
	}
	rootPrivBytes, err := os.ReadFile(filepath.Join(*keysDir, "publisher.priv"))
	if err != nil {
		fail(err)
	}
	if len(rootPubBytes) != ed25519.PublicKeySize || len(rootPrivBytes) != ed25519.PrivateKeySize {
		fail(fmt.Errorf("root key sizes wrong: pub=%d priv=%d", len(rootPubBytes), len(rootPrivBytes)))
	}
	rootPub := ed25519.PublicKey(rootPubBytes)
	rootPriv := ed25519.PrivateKey(rootPrivBytes)

	// Deterministic sub-key for reproducibility.
	subPub, subPriv := deterministicSubkey()

	// Pinned now for deterministic build.
	now := time.Unix(pinnedNowUnix, 0).UTC()
	validFrom := now.Add(-time.Hour)
	validUntil := now.Add(90 * 24 * time.Hour)

	// Cert.
	cert := map[string]any{
		"v":                    1,
		"kind":                 "subkey_cert",
		"root_fingerprint_hex": bundle.PublisherFingerprint(rootPub).Hex,
		"subkey_pub_hex":       hex.EncodeToString(subPub),
		"valid_from":           validFrom.Format(time.RFC3339),
		"valid_until":          validUntil.Format(time.RFC3339),
		"label":                "frp-7.5-sample-subkey",
	}
	body := canonicalJSON(cert)
	cert["signature_hex"] = hex.EncodeToString(ed25519.Sign(rootPriv, body))
	certBytes, _ := json.MarshalIndent(cert, "", "  ")

	// Manifest mirrors samples/work/manifest-A.json shape, but
	// with spec_version=4 (sub-key chain floor).
	manifest := bundle.Manifest{
		SpecVersion: 4,
		Publisher: bundle.PublisherInfo{
			Name:              "Sample Publisher A (FRP-7.5 sub-key)",
			KeyFingerprintHex: bundle.PublisherFingerprint(rootPub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "community",
		},
		Bundle: bundle.BundleInfo{
			ID:             "frp-7-5-subkey-signed-A",
			Type:           "provider",
			CreatedAt:      now.Format(time.RFC3339),
			ExpiresAt:      now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			SupersedesKeys: []string{},
		},
		Routes: []bundle.RouteManifestEntry{{
			ID:              "sample-route-1",
			ScarcityClass:   "normal",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/route-1.json",
			ValidFrom:       now.Format(time.RFC3339),
			ValidUntil:      now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
		}},
	}

	profiles := map[string][]byte{
		"profiles/route-1.json": []byte(`{"type":"vless","tag":"sample-r"}`),
	}

	extras := map[string][]byte{
		"trust/subkey-cert.json": certBytes,
	}

	sbpBytes, err := bundle.BuildSignedBundleDeterministic(
		manifest, profiles, extras, rootPub, subPriv,
	)
	if err != nil {
		fail(err)
	}

	// Self-verify.
	parsed, err := bundle.ParseSBP(bytes.NewReader(sbpBytes), int64(len(sbpBytes)))
	if err != nil {
		fail(err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		fail(err)
	}
	if len(parsed.SubkeyCertJSON) == 0 {
		fail(fmt.Errorf("sample missing trust/subkey-cert.json"))
	}

	if err := os.WriteFile(*out, sbpBytes, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s (%d bytes); spec_version=%d; root_fp=%s; sub_fp=%s\n",
		*out, len(sbpBytes), parsed.Manifest.SpecVersion,
		bundle.PublisherFingerprint(rootPub).Hex[:16],
		bundle.PublisherFingerprint(subPub).Hex[:16],
	)
}

func canonicalJSON(v any) []byte {
	// The canonical-JSON form the publisher uses: keys sorted
	// alphabetically, no whitespace. We re-emit through the
	// stdlib json package then re-sort. For this small object
	// we hand-write the same algorithm publisher's
	// writeCanonical does.
	raw, err := json.Marshal(v)
	if err != nil {
		fail(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		fail(err)
	}
	if obj, ok := doc.(map[string]any); ok {
		delete(obj, "signature_hex")
	}
	var buf bytes.Buffer
	writeCanon(&buf, doc)
	return buf.Bytes()
}

func writeCanon(buf *bytes.Buffer, value any) {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		if v == float64(int64(v)) {
			fmt.Fprintf(buf, "%d", int64(v))
		} else {
			fmt.Fprintf(buf, "%g", v)
		}
	case int:
		fmt.Fprintf(buf, "%d", v)
	case string:
		b, _ := json.Marshal(v)
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanon(buf, item)
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// Sort.
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
				keys[j-1], keys[j] = keys[j], keys[j-1]
			}
		}
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kj, _ := json.Marshal(k)
			buf.Write(kj)
			buf.WriteByte(':')
			writeCanon(buf, v[k])
		}
		buf.WriteByte('}')
	default:
		fail(fmt.Errorf("unsupported canonical type %T", value))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "bundle-subkey-sample:", err)
	os.Exit(1)
}
