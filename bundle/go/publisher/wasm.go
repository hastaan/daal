package publisher

// Phase 3E. Helpers for the `daal-publish wasm-module` and
// `daal-publish wasm-killswitch` subcommands. The CLI surface
// is documented in specs/publisher-cli-v1.md "Phase 3E" and
// specs/wasm-transport-v1.md.
//
// daal-publish never opens a network socket. These helpers
// only read local files and emit signed JSON to disk.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// --- wasm-module -----------------------------------------------------

// WasmModuleOptions are the inputs to the wasm-module
// subcommand. The subcommand wraps a `.wasm` blob into a
// `transport_modules[]` entry stub plus a paired `routes[]`
// entry stub. The route stub points at the module by slug;
// callers splice both into the manifest before `daal-publish
// bundle`.
type WasmModuleOptions struct {
	WasmPath                     string        // path to the compiled .wasm file (REQUIRED)
	Slug                         string        // module slug (REQUIRED; [a-z0-9_-]{3,32})
	RouteID                      string        // optional; default tm-<slug>
	Validity                     time.Duration // optional; default 7d
	ScarcityClass                string        // optional; default "experimental"; "emergency" rejected
	CaveatFAIR                   string
	ExperimentalMinEngineVersion string
	MinEngineVersion             string // module's own min-engine-version pin (optional; defaults to engine version 0.8.0)
	OutModulePath                string // where to write the module-entry stub JSON (REQUIRED)
	OutRoutePath                 string // where to write the paired route-stub JSON (REQUIRED)
}

// WasmModuleRouteStub is the route entry pointing at a WASM
// module. Same shape as the manifest's `routes[]` entry.
type WasmModuleRouteStub struct {
	ID                           string `json:"id"`
	ScarcityClass                string `json:"scarcity_class"`
	TransportFamily              string `json:"transport_family"`
	ConfigPath                   string `json:"config_path"`
	ValidFrom                    string `json:"valid_from"`
	ValidUntil                   string `json:"valid_until"`
	TransportModuleSlug          string `json:"transport_module_slug"`
	CaveatFAIR                   string `json:"caveat_fa_ir,omitempty"`
	ExperimentalMinEngineVersion string `json:"experimental_min_engine_version,omitempty"`
}

// WasmModule wraps a `.wasm` file into a transport_modules[]
// entry stub + paired route stub. Returns the entry, the route
// stub, and the truncated SHA-256 prefix (first 8 bytes hex)
// for log surfaces.
func WasmModule(opts WasmModuleOptions) (*bundle.TransportModuleEntry, *WasmModuleRouteStub, string, error) {
	if strings.TrimSpace(opts.WasmPath) == "" {
		return nil, nil, "", errors.New("wasm-module: --wasm is required")
	}
	if !validSlug3E(opts.Slug) {
		return nil, nil, "", errors.New("wasm-module: --slug must match [a-z0-9_-]{3,32}")
	}
	if opts.OutModulePath == "" || opts.OutRoutePath == "" {
		return nil, nil, "", errors.New("wasm-module: --out-module and --out-route are required")
	}
	if opts.ScarcityClass == "" {
		opts.ScarcityClass = "experimental"
	}
	if opts.ScarcityClass == "emergency" {
		return nil, nil, "", errors.New("wasm-module: --scarcity emergency is not allowed for transport_module routes")
	}
	blob, err := os.ReadFile(opts.WasmPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("wasm-module: read wasm: %w", err)
	}
	if len(blob) > 4*1024*1024 {
		return nil, nil, "", fmt.Errorf("wasm-module: wasm blob %d bytes exceeds 4 MiB cap", len(blob))
	}

	sum := sha256.Sum256(blob)
	full := hex.EncodeToString(sum[:])
	prefix := full[:16] // 8 bytes hex prefix

	minVer := opts.MinEngineVersion
	if minVer == "" {
		minVer = "0.8.0"
	}

	entry := &bundle.TransportModuleEntry{
		Slug:             opts.Slug,
		SHA256Hex:        full,
		WASMBlobB64:      base64.StdEncoding.EncodeToString(blob),
		MinEngineVersion: minVer,
	}

	routeID := opts.RouteID
	if routeID == "" {
		routeID = "tm-" + opts.Slug
	}
	validity := opts.Validity
	if validity == 0 {
		validity = 7 * 24 * time.Hour
	}
	now := time.Now().UTC()
	route := &WasmModuleRouteStub{
		ID:                           routeID,
		ScarcityClass:                opts.ScarcityClass,
		TransportFamily:              string(bundle.TransportTransportModule),
		ConfigPath:                   "profiles/" + routeID + ".json",
		ValidFrom:                    now.Format(time.RFC3339),
		ValidUntil:                   now.Add(validity).Format(time.RFC3339),
		TransportModuleSlug:          opts.Slug,
		CaveatFAIR:                   opts.CaveatFAIR,
		ExperimentalMinEngineVersion: opts.ExperimentalMinEngineVersion,
	}

	if err := writeJSON(opts.OutModulePath, entry); err != nil {
		return nil, nil, "", fmt.Errorf("wasm-module: write %s: %w", opts.OutModulePath, err)
	}
	if err := writeJSON(opts.OutRoutePath, route); err != nil {
		return nil, nil, "", fmt.Errorf("wasm-module: write %s: %w", opts.OutRoutePath, err)
	}
	return entry, route, prefix, nil
}

// --- wasm-killswitch -------------------------------------------------

// WasmKillswitchOptions are the inputs to the wasm-killswitch
// subcommand. The subcommand signs a single (slug, sha256,
// generation) tuple under the project-controlled WASM kill-
// switch private key (CC.4 hardware-token custody) and emits
// the canonical signed JSON.
type WasmKillswitchOptions struct {
	Slug       string
	SHA256Hex  string
	Generation uint64
	KeyPath    string // path to the Ed25519 private key (raw 64-byte seed+pub OR hex)
	OutPath    string // where to write the signed delta JSON (REQUIRED)
}

// SignedKillswitchEntry is the wire shape emitted to disk;
// shape-equivalent to bundle.KillSwitchEntry but lives in the
// publisher package so the public CLI surface is self-
// contained.
type SignedKillswitchEntry struct {
	Slug         string `json:"slug"`
	SHA256Hex    string `json:"sha256"`
	Generation   uint64 `json:"generation"`
	SignatureB64 string `json:"signature"`
}

// WasmKillswitch signs (slug, sha256, generation) under the
// supplied private key and emits the canonical JSON. Returns
// the signed entry plus the publisher fingerprint (hex prefix
// of the corresponding pubkey) for log surfaces.
func WasmKillswitch(opts WasmKillswitchOptions) (*SignedKillswitchEntry, string, error) {
	if !validSlug3E(opts.Slug) {
		return nil, "", errors.New("wasm-killswitch: --slug must match [a-z0-9_-]{3,32}")
	}
	if len(opts.SHA256Hex) != 64 || !validHexLen64(opts.SHA256Hex) {
		return nil, "", errors.New("wasm-killswitch: --sha256 must be 64 hex chars")
	}
	if opts.Generation == 0 {
		return nil, "", errors.New("wasm-killswitch: --generation must be > 0 (monotonic counter)")
	}
	if opts.KeyPath == "" || opts.OutPath == "" {
		return nil, "", errors.New("wasm-killswitch: --key and --out are required")
	}
	priv, err := loadKillswitchKey(opts.KeyPath)
	if err != nil {
		return nil, "", err
	}
	payload := canonicalKillswitchPayload(opts.Slug, opts.SHA256Hex, opts.Generation)
	sig := ed25519.Sign(priv, payload)
	entry := &SignedKillswitchEntry{
		Slug:         opts.Slug,
		SHA256Hex:    opts.SHA256Hex,
		Generation:   opts.Generation,
		SignatureB64: base64.RawStdEncoding.EncodeToString(sig),
	}
	if err := writeJSON(opts.OutPath, entry); err != nil {
		return nil, "", fmt.Errorf("wasm-killswitch: write %s: %w", opts.OutPath, err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fp := hex.EncodeToString(pub[:8])
	return entry, fp, nil
}

// canonicalKillswitchPayload mirrors the engine-side helper in
// `core/wasm.canonicalEntryBytes`. The two functions MUST
// agree byte-for-byte; a regression test in
// `bundle/go/publisher/wasm_test.go` round-trips a signed
// entry through the engine's verifier.
func canonicalKillswitchPayload(slug, sha256Hex string, gen uint64) []byte {
	var sb strings.Builder
	sb.WriteString(`{"slug":`)
	if b, err := json.Marshal(slug); err == nil {
		sb.Write(b)
	}
	sb.WriteString(`,"sha256":`)
	if b, err := json.Marshal(sha256Hex); err == nil {
		sb.Write(b)
	}
	fmt.Fprintf(&sb, `,"generation":%d}`, gen)
	return []byte(sb.String())
}

// loadKillswitchKey accepts either a 64-byte raw Ed25519
// private key OR a hex-encoded version of the same. Hardware-
// token integration is reserved (CC.4) — at 3E the publisher
// runs against an offline air-gapped key.
func loadKillswitchKey(path string) (ed25519.PrivateKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wasm-killswitch: read key %s: %w", path, err)
	}
	// Try the raw-64-byte interpretation BEFORE any trimming. The
	// previous implementation TrimSpace'd unconditionally, which
	// truncated raw keys whose first or last byte happened to be
	// 0x20 / 0x09 / 0x0A / 0x0D — about 1.6% of randomly generated
	// keys per byte position, so the test flaked on real Ed25519
	// output.
	if len(body) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), body...)), nil
	}
	trimmed := strings.TrimSpace(string(body))
	if decoded, err := hex.DecodeString(trimmed); err == nil &&
		len(decoded) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(decoded), nil
	}
	return nil, errors.New("wasm-killswitch: key file must be 64 raw bytes or 128 hex chars")
}

// --- shared helpers --------------------------------------------------

// validSlug3E is the publisher-side mirror of the locked-at-3E
// `[a-z0-9_-]{3,32}` regex; duplicated rather than imported
// from `core/wasm` because the bundle module is its own go.mod.
func validSlug3E(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isSym := c == '_' || c == '-'
		if !(isLower || isDigit || isSym) {
			return false
		}
	}
	return true
}

// validHexLen64 returns true iff s is exactly 64 hex chars.
func validHexLen64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		isDigit := c >= '0' && c <= '9'
		if !(isLower || isUpper || isDigit) {
			return false
		}
	}
	return true
}

func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}
