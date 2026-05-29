package publisher

// Phase 3D. Helpers for the `daal-publish psiphon-bundle`
// subcommand. The CLI surface is documented in
// specs/publisher-cli-v1.md "Phase 3D" and
// specs/psiphon-route-v1.md.
//
// daal-publish never opens a network socket. The
// psiphon-bundle subcommand wraps an upstream Psiphon publisher
// bundle (produced out-of-band by Psiphon Inc.'s tooling) into
// a Daal `routes[]` entry stub. It does NOT validate the
// Psiphon bundle's internal structure — that is the upstream
// library's responsibility — only the Daal-layer size sanity
// envelope (256 bytes ≤ size ≤ 65536 bytes, locked at 3D).

import (
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

// PsiphonBundleOptions are the inputs to the psiphon-bundle
// subcommand.
type PsiphonBundleOptions struct {
	BlobPath                     string        // path to the upstream Psiphon publisher bundle bytes (REQUIRED)
	RouteID                      string        // optional; default ps-<bundle-checksum-prefix>
	Validity                     time.Duration // optional; default 7d
	ScarcityClass                string        // optional; default "normal"; "emergency" rejected
	CaveatFAIR                   string        // optional; Persian region caveat
	ExperimentalMinEngineVersion string        // optional; semver pin
	OutPath                      string        // path to write the route-stub JSON
}

// PsiphonRouteStub is the JSON shape emitted to disk. Same
// shape as the manifest's `routes[]` entry, ready to splice
// into a full manifest.json before `daal-publish bundle`.
type PsiphonRouteStub struct {
	ID                           string          `json:"id"`
	ScarcityClass                string          `json:"scarcity_class"`
	TransportFamily              string          `json:"transport_family"`
	ConfigPath                   string          `json:"config_path"`
	ValidFrom                    string          `json:"valid_from"`
	ValidUntil                   string          `json:"valid_until"`
	PsiphonBundleBlobB64         string          `json:"psiphon_bundle_blob_b64"`
	FamilySpecificConfig         json.RawMessage `json:"family_specific_config"`
	CaveatFAIR                   string          `json:"caveat_fa_ir,omitempty"`
	ExperimentalMinEngineVersion string          `json:"experimental_min_engine_version,omitempty"`
}

// PsiphonBundle reads the upstream blob from disk, applies the
// 3D size envelope, and emits a route stub. Returns the stub
// plus the truncated blob checksum (used to derive a default
// route ID when one was not supplied).
func PsiphonBundle(opts PsiphonBundleOptions) (*PsiphonRouteStub, string, error) {
	if strings.TrimSpace(opts.BlobPath) == "" {
		return nil, "", errors.New("psiphon-bundle: --psiphon-blob is required")
	}
	if opts.ScarcityClass == "" {
		opts.ScarcityClass = "normal"
	}
	// Locked at 3D: psiphon routes MUST NOT be marked emergency
	// — emergency-class capacity is the bootstrap pool, and a
	// Psiphon route cannot share that budget without burning
	// the publisher's quota.
	if opts.ScarcityClass == "emergency" {
		return nil, "", errors.New("psiphon-bundle: --scarcity emergency is not allowed for psiphon routes")
	}
	blob, err := os.ReadFile(opts.BlobPath)
	if err != nil {
		return nil, "", fmt.Errorf("psiphon-bundle: read blob: %w", err)
	}
	if len(blob) < 256 || len(blob) > 65536 {
		return nil, "", fmt.Errorf("psiphon-bundle: blob size %d out of range [256, 65536]", len(blob))
	}

	sum := sha256.Sum256(blob)
	checksum := hex.EncodeToString(sum[:8]) // first 8 bytes of SHA-256, hex

	id := opts.RouteID
	if id == "" {
		id = "ps-" + checksum
	}
	validity := opts.Validity
	if validity == 0 {
		validity = 7 * 24 * time.Hour
	}

	now := time.Now().UTC()
	stub := &PsiphonRouteStub{
		ID:                           id,
		ScarcityClass:                opts.ScarcityClass,
		TransportFamily:              string(bundle.TransportPsiphon),
		ConfigPath:                   "profiles/" + id + ".json",
		ValidFrom:                    now.Format(time.RFC3339),
		ValidUntil:                   now.Add(validity).Format(time.RFC3339),
		PsiphonBundleBlobB64:         base64.StdEncoding.EncodeToString(blob),
		FamilySpecificConfig:         json.RawMessage(`{}`),
		CaveatFAIR:                   opts.CaveatFAIR,
		ExperimentalMinEngineVersion: opts.ExperimentalMinEngineVersion,
	}
	if opts.OutPath != "" {
		body, err := json.MarshalIndent(stub, "", "  ")
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(opts.OutPath, append(body, '\n'), 0o600); err != nil {
			return nil, "", fmt.Errorf("psiphon-bundle: write %s: %w", opts.OutPath, err)
		}
	}
	return stub, checksum, nil
}
