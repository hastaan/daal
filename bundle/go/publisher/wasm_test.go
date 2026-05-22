package publisher

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWasmModule_HappyPath — a small `.wasm` file produces
// both a `transport_modules[]` entry and a paired `routes[]`
// stub.
func TestWasmModule_HappyPath(t *testing.T) {
	dir := t.TempDir()
	wasmBytes := make([]byte, 1024)
	for i := range wasmBytes {
		wasmBytes[i] = byte(i)
	}
	wasmPath := filepath.Join(dir, "hello.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	outMod := filepath.Join(dir, "module.json")
	outRoute := filepath.Join(dir, "route.json")

	entry, route, prefix, err := WasmModule(WasmModuleOptions{
		WasmPath:      wasmPath,
		Slug:          "hello-https",
		OutModulePath: outMod,
		OutRoutePath:  outRoute,
	})
	if err != nil {
		t.Fatalf("WasmModule: %v", err)
	}
	if entry.Slug != "hello-https" {
		t.Errorf("slug: %q", entry.Slug)
	}
	want := sha256.Sum256(wasmBytes)
	if entry.SHA256Hex != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 mismatch")
	}
	if entry.MinEngineVersion != "0.8.0" {
		t.Errorf("min_engine_version default: %q", entry.MinEngineVersion)
	}
	if route.TransportFamily != "transport_module" {
		t.Errorf("route family: %q", route.TransportFamily)
	}
	if route.TransportModuleSlug != "hello-https" {
		t.Errorf("route slug ref: %q", route.TransportModuleSlug)
	}
	if route.ID != "tm-hello-https" {
		t.Errorf("default route ID: %q", route.ID)
	}
	if route.ScarcityClass != "experimental" {
		t.Errorf("default scarcity: %q", route.ScarcityClass)
	}
	if prefix != entry.SHA256Hex[:16] {
		t.Errorf("returned prefix: %q", prefix)
	}

	// Files written with mode 0600.
	for _, p := range []string{outMod, outRoute} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode: %v", p, info.Mode().Perm())
		}
	}

	// Re-parse the module entry to confirm the shape.
	body, _ := os.ReadFile(outMod)
	var parsedEntry struct {
		Slug                 string   `json:"slug"`
		SHA256Hex            string   `json:"sha256"`
		WASMBlobB64          string   `json:"wasm_blob_b64"`
		MinEngineVersion     string   `json:"min_engine_version"`
		OptionalCapabilities []string `json:"optional_capabilities"`
	}
	if err := json.Unmarshal(body, &parsedEntry); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(parsedEntry.WASMBlobB64)
	if err != nil || len(decoded) != len(wasmBytes) {
		t.Errorf("blob round-trip: len=%d err=%v", len(decoded), err)
	}
}

// TestWasmModule_BadSlugRejected — slug that fails the regex
// is rejected.
func TestWasmModule_BadSlugRejected(t *testing.T) {
	dir := t.TempDir()
	wasm := filepath.Join(dir, "x.wasm")
	_ = os.WriteFile(wasm, []byte{0, 1, 2}, 0o600)
	for _, slug := range []string{"", "AB", "Bad!", strings.Repeat("y", 33)} {
		_, _, _, err := WasmModule(WasmModuleOptions{
			WasmPath:      wasm,
			Slug:          slug,
			OutModulePath: filepath.Join(dir, "m.json"),
			OutRoutePath:  filepath.Join(dir, "r.json"),
		})
		if err == nil {
			t.Errorf("slug %q: expected rejection", slug)
		}
	}
}

// TestWasmModule_OversizeRejected — > 4 MiB rejects.
func TestWasmModule_OversizeRejected(t *testing.T) {
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "huge.wasm")
	body := make([]byte, 4*1024*1024+1)
	if err := os.WriteFile(wasmPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := WasmModule(WasmModuleOptions{
		WasmPath:      wasmPath,
		Slug:          "huge",
		OutModulePath: filepath.Join(dir, "m.json"),
		OutRoutePath:  filepath.Join(dir, "r.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Errorf("got %v, want 4 MiB cap rejection", err)
	}
}

// TestWasmModule_EmergencyScarcityRejected — emergency is
// reserved for the bootstrap pool.
func TestWasmModule_EmergencyScarcityRejected(t *testing.T) {
	dir := t.TempDir()
	wasm := filepath.Join(dir, "x.wasm")
	_ = os.WriteFile(wasm, []byte{0, 1}, 0o600)
	_, _, _, err := WasmModule(WasmModuleOptions{
		WasmPath:      wasm,
		Slug:          "ok-slug",
		ScarcityClass: "emergency",
		OutModulePath: filepath.Join(dir, "m.json"),
		OutRoutePath:  filepath.Join(dir, "r.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "emergency") {
		t.Errorf("got %v, want emergency-scarcity rejection", err)
	}
}

// TestWasmKillswitch_HappyPath — sign + emit + verify via the
// engine-side canonical payload (we recompute it here).
func TestWasmKillswitch_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	keyPath := filepath.Join(dir, "ks.key")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "delta.json")

	entry, fp, err := WasmKillswitch(WasmKillswitchOptions{
		Slug:       "evil-mod",
		SHA256Hex:  strings.Repeat("a", 64),
		Generation: 7,
		KeyPath:    keyPath,
		OutPath:    out,
	})
	if err != nil {
		t.Fatalf("WasmKillswitch: %v", err)
	}
	if entry.Generation != 7 {
		t.Errorf("generation: %d", entry.Generation)
	}
	if !strings.HasPrefix(hex.EncodeToString(pub[:8]), fp[:8]) {
		t.Errorf("fp: %q vs %q", fp, hex.EncodeToString(pub[:8]))
	}

	// Recompute the canonical payload and verify.
	payload := canonicalKillswitchPayload(entry.Slug, entry.SHA256Hex, entry.Generation)
	sig, err := base64.RawStdEncoding.DecodeString(entry.SignatureB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		t.Error("signature does not verify against the canonical payload")
	}

	// File mode 0600.
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("output mode: %v", info.Mode().Perm())
	}
}

// TestWasmKillswitch_HexKeyAccepted — hex-encoded private
// keys round-trip just like raw 64-byte keys.
func TestWasmKillswitch_HexKeyAccepted(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "ks.hex")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "delta.json")
	entry, _, err := WasmKillswitch(WasmKillswitchOptions{
		Slug:       "ok-mod",
		SHA256Hex:  strings.Repeat("b", 64),
		Generation: 1,
		KeyPath:    keyPath,
		OutPath:    out,
	})
	if err != nil {
		t.Fatalf("WasmKillswitch (hex key): %v", err)
	}
	payload := canonicalKillswitchPayload(entry.Slug, entry.SHA256Hex, entry.Generation)
	sig, _ := base64.RawStdEncoding.DecodeString(entry.SignatureB64)
	if !ed25519.Verify(pub, payload, sig) {
		t.Error("hex key path: signature does not verify")
	}
}

// TestWasmKillswitch_GenerationZeroRejected — generation 0 is
// reserved (the engine watermark starts there).
func TestWasmKillswitch_GenerationZeroRejected(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "ks.key")
	_ = os.WriteFile(keyPath, priv, 0o600)
	_, _, err := WasmKillswitch(WasmKillswitchOptions{
		Slug:       "ok-mod",
		SHA256Hex:  strings.Repeat("c", 64),
		Generation: 0,
		KeyPath:    keyPath,
		OutPath:    filepath.Join(dir, "delta.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "> 0") {
		t.Errorf("got %v, want generation>0 rejection", err)
	}
}

// TestWasmKillswitch_BadSlugAndSHARejected — slug regex and
// 64-hex sha256 enforced at sign time so a malformed delta
// cannot reach the engine.
func TestWasmKillswitch_BadSlugAndSHARejected(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "ks.key")
	_ = os.WriteFile(keyPath, priv, 0o600)
	out := filepath.Join(dir, "delta.json")

	cases := []WasmKillswitchOptions{
		{Slug: "BAD!", SHA256Hex: strings.Repeat("a", 64), Generation: 1, KeyPath: keyPath, OutPath: out},
		{Slug: "ok-mod", SHA256Hex: "tooshort", Generation: 1, KeyPath: keyPath, OutPath: out},
		{Slug: "ok-mod", SHA256Hex: strings.Repeat("z", 64), Generation: 1, KeyPath: keyPath, OutPath: out},
	}
	for i, opts := range cases {
		if _, _, err := WasmKillswitch(opts); err == nil {
			t.Errorf("case %d: expected rejection for %+v", i, opts)
		}
	}
}
