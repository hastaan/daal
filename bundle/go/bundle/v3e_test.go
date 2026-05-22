package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// Phase 3E bundle-format widening tests. See
// specs/sbp-v1.md "Phase 3E widening" and
// specs/wasm-transport-v1.md.

// goodModuleBlob returns a deterministic byte stream of length n
// suitable for a `transport_modules[]` entry. The fixed-pattern
// content is meaningless to a real WASM runtime — the bundle
// parser only enforces hash + size, not WASM well-formedness
// (the engine's wasm package handles that at activation time).
func goodModuleBlob(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i * 31) & 0xff)
	}
	return out
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestSBPv1_TransportModulesRoundTrip — a well-formed module
// entry round-trips through Build → Parse → Verify on a route
// whose family is `transport_module`.
func TestSBPv1_TransportModulesRoundTrip(t *testing.T) {
	body := goodModuleBlob(4096)
	m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
	m.Routes[0].TransportModuleSlug = "hello-https"
	m.TransportModules = []TransportModuleEntry{{
		Slug:             "hello-https",
		SHA256Hex:        sumHex(body),
		WASMBlobB64:      base64.StdEncoding.EncodeToString(body),
		MinEngineVersion: "0.8.0",
	}}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := b.Manifest.Routes[0].TransportModuleSlug; got != "hello-https" {
		t.Errorf("slug round-trip: %q", got)
	}
	if len(b.Manifest.TransportModules) != 1 {
		t.Fatalf("modules len = %d; want 1", len(b.Manifest.TransportModules))
	}
}

// TestSBPv1_TransportModuleSlugOnNonModuleRouteRejected — a slug
// on a `vless-reality` route is rejected at verify time.
func TestSBPv1_TransportModuleSlugOnNonModuleRouteRejected(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Routes[0].TransportModuleSlug = "hello-https"
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrTransportModuleSlugOnNonModuleRoute) {
		t.Fatalf("got %v, want ErrTransportModuleSlugOnNonModuleRoute", err)
	}
}

// TestSBPv1_TransportModuleSlugMalformedRejected — slugs failing
// the `[a-z0-9_-]{3,32}` regex are rejected.
func TestSBPv1_TransportModuleSlugMalformedRejected(t *testing.T) {
	for _, slug := range []string{"AB", "a", "x" + strings.Repeat("y", 32), "WITH SPACE", "Bad!"} {
		t.Run(slug, func(t *testing.T) {
			m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
			m.Routes[0].TransportModuleSlug = slug
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrTransportModuleSlugMalformed) {
				t.Errorf("got %v, want ErrTransportModuleSlugMalformed", err)
			}
		})
	}
}

// TestSBPv1_TransportModulesEntryMalformed — entry with a bad
// slug, a short sha256, an unparseable blob, or a malformed
// min_engine_version rejects with ErrTransportModulesEntryMalformed.
func TestSBPv1_TransportModulesEntryMalformed(t *testing.T) {
	body := goodModuleBlob(2048)
	good := TransportModuleEntry{
		Slug:        "hello-https",
		SHA256Hex:   sumHex(body),
		WASMBlobB64: base64.StdEncoding.EncodeToString(body),
	}
	cases := map[string]TransportModuleEntry{
		"bad slug":     {Slug: "BAD!", SHA256Hex: good.SHA256Hex, WASMBlobB64: good.WASMBlobB64},
		"short sha256": {Slug: "hi-mod", SHA256Hex: "deadbeef", WASMBlobB64: good.WASMBlobB64},
		"empty blob":   {Slug: "hi-mod", SHA256Hex: good.SHA256Hex, WASMBlobB64: ""},
		"unparse blob": {Slug: "hi-mod", SHA256Hex: good.SHA256Hex, WASMBlobB64: "@@@!!!"},
		"bad min ver":  {Slug: "hi-mod", SHA256Hex: good.SHA256Hex, WASMBlobB64: good.WASMBlobB64, MinEngineVersion: "not-a-version"},
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
			m.Routes[0].TransportModuleSlug = "hi-mod"
			m.TransportModules = []TransportModuleEntry{entry}
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrTransportModulesEntryMalformed) {
				t.Errorf("got %v, want ErrTransportModulesEntryMalformed", err)
			}
		})
	}
}

// TestSBPv1_TransportModuleHashMismatch — entry whose SHA-256
// does not match the decoded blob is rejected.
func TestSBPv1_TransportModuleHashMismatch(t *testing.T) {
	body := goodModuleBlob(1024)
	m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
	m.Routes[0].TransportModuleSlug = "hello-https"
	m.TransportModules = []TransportModuleEntry{{
		Slug:        "hello-https",
		SHA256Hex:   strings.Repeat("0", 64),
		WASMBlobB64: base64.StdEncoding.EncodeToString(body),
	}}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrTransportModuleHashMismatch) {
		t.Errorf("got %v, want ErrTransportModuleHashMismatch", err)
	}
}

// TestSBPv1_TransportModuleOversize_PerEntry — a single entry
// over the 4 MiB cap rejects with ErrTransportModuleOversize.
func TestSBPv1_TransportModuleOversize_PerEntry(t *testing.T) {
	body := goodModuleBlob(4*1024*1024 + 1)
	m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
	m.Routes[0].TransportModuleSlug = "huge"
	m.TransportModules = []TransportModuleEntry{{
		Slug:        "huge",
		SHA256Hex:   sumHex(body),
		WASMBlobB64: base64.StdEncoding.EncodeToString(body),
	}}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrTransportModuleOversize) {
		t.Errorf("got %v, want ErrTransportModuleOversize", err)
	}
}

// TestSBPv1_TransportModuleOversize_BundleTotal — five entries
// each at 3.5 MiB exceeds the 16 MiB bundle total cap.
func TestSBPv1_TransportModuleOversize_BundleTotal(t *testing.T) {
	body := goodModuleBlob(int(3.5 * 1024 * 1024))
	entries := make([]TransportModuleEntry, 0, 5)
	for i := 0; i < 5; i++ {
		entries = append(entries, TransportModuleEntry{
			Slug:        "mod-" + string(rune('a'+i)) + "x",
			SHA256Hex:   sumHex(body),
			WASMBlobB64: base64.StdEncoding.EncodeToString(body),
		})
	}
	m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
	m.Routes[0].TransportModuleSlug = "mod-ax"
	m.TransportModules = entries
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrTransportModuleOversize) {
		t.Errorf("got %v, want ErrTransportModuleOversize", err)
	}
}

// TestSBPv1_TransportModuleSoftValidation — a transport_module
// route with an EMPTY slug is accepted at parse time. The
// soft-validation discipline is locked at 3E to match 3C/3D.
func TestSBPv1_TransportModuleSoftValidation(t *testing.T) {
	m := baseManifest(t, "normal", "transport_module", time.Now().Add(24*time.Hour))
	// transport_module_slug deliberately empty.
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("soft-validation: empty slug must be accepted; got %v", err)
	}
}
