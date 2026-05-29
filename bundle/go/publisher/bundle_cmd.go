package publisher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// BundleOptions configures bundle creation.
type BundleOptions struct {
	ManifestPath     string
	ProfilesDir      string
	SigningPrivPath  string
	PublisherPubPath string
	RotationChain    string // path to optional trust/rotation.json
	Revocation       string // path to optional revocation.json
	Out              string
	LintStrict       bool
	UnsafeUnsigned   bool
	LegacyV1         bool // produce a spec_version 1 manifest (Phase 1A/1B/1C/1D)
	Now              time.Time

	// Phase 3F. When non-empty, RedistributionPolicy is
	// applied to EVERY route in the manifest. The closed
	// enum is {none, delegated_n, transitive}; bundle-time
	// validation rejects unknown values. RedistributionCap
	// is uint8 0..255, only meaningful for `delegated_n`.
	// See specs/delegate-keys-v1.md and
	// specs/publisher-cli-v1.md "Phase 3F".
	RedistributionPolicy string
	RedistributionCap    uint8
}

// BundleResult summarises a successful build.
type BundleResult struct {
	OutPath      string
	Bytes        []byte
	PublisherFP  string
	RouteCount   int
	LintFindings []LintFinding
}

// Bundle is the Phase-1A bundle command.
func Bundle(opts BundleOptions) (*BundleResult, error) {
	if opts.ManifestPath == "" || opts.ProfilesDir == "" || opts.Out == "" || opts.PublisherPubPath == "" {
		return nil, fmt.Errorf("--manifest, --profiles-dir, --publisher-pub, and --out are required")
	}
	if !opts.UnsafeUnsigned && opts.SigningPrivPath == "" {
		return nil, fmt.Errorf("--signing-priv is required (use --unsafe-unsigned for non-production builds)")
	}
	if opts.UnsafeUnsigned && !strings.HasSuffix(opts.Out, ".UNSIGNED.sbp") {
		return nil, fmt.Errorf("unsigned output must end with .UNSIGNED.sbp; refusing to write production-named bundle")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}

	manifestBody, err := os.ReadFile(opts.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest bundle.Manifest
	if err := json.Unmarshal(manifestBody, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	// Phase 1.5A: default to spec_version 2 unless --legacy-v1 was set.
	if manifest.SpecVersion == 0 {
		if opts.LegacyV1 {
			manifest.SpecVersion = 1
		} else {
			manifest.SpecVersion = 2
		}
	} else if !opts.LegacyV1 && manifest.SpecVersion == 1 {
		// Manifest declares v1 but operator did not request --legacy-v1;
		// promote silently to v2 (additive fields stay empty).
		manifest.SpecVersion = 2
	}

	// Phase 3F: apply CLI-side redistribution policy + cap to
	// every route. Invalid combinations are rejected here so
	// the operator gets a clear error instead of a downstream
	// VerifyBundle failure. See specs/delegate-keys-v1.md.
	if opts.RedistributionPolicy != "" {
		if err := applyRedistributionPolicy(&manifest, opts.RedistributionPolicy, opts.RedistributionCap); err != nil {
			return nil, err
		}
	}

	pub, err := LoadPub(opts.PublisherPubPath)
	if err != nil {
		return nil, err
	}
	if manifest.Publisher.KeyFingerprintHex == "" {
		manifest.Publisher.KeyFingerprintHex = bundle.PublisherFingerprint(pub).Hex
	} else if manifest.Publisher.KeyFingerprintHex != bundle.PublisherFingerprint(pub).Hex {
		return nil, fmt.Errorf("manifest publisher fingerprint does not match --publisher-pub")
	}

	if err := enforceManifestPolicy(manifest, opts.Now); err != nil {
		return nil, err
	}

	profiles, err := loadProfiles(opts.ProfilesDir)
	if err != nil {
		return nil, err
	}

	findings := LintRoutes(LintInput{
		Manifest:    manifest,
		Profiles:    profiles,
		ProfilesDir: opts.ProfilesDir,
		Now:         opts.Now,
	})
	for _, f := range findings {
		if f.Level == LintBlock || (opts.LintStrict && f.Level == LintWarn) {
			return nil, fmt.Errorf("lint blocked build: %s: %s", f.Code, f.Reason)
		}
	}

	extras := map[string][]byte{}
	if opts.RotationChain != "" {
		body, err := os.ReadFile(opts.RotationChain)
		if err != nil {
			return nil, fmt.Errorf("read rotation chain: %w", err)
		}
		extras["trust/rotation.json"] = body
	}
	if opts.Revocation != "" {
		body, err := os.ReadFile(opts.Revocation)
		if err != nil {
			return nil, fmt.Errorf("read revocation: %w", err)
		}
		extras["revocation.json"] = body
	}

	var sbpBytes []byte
	if opts.UnsafeUnsigned {
		// Build without signing; produce a bundle whose manifest.sig is a
		// zero-length file so downstream verification still rejects it.
		sbpBytes, err = buildUnsignedDeterministic(manifest, profiles, extras, pub)
		if err != nil {
			return nil, err
		}
	} else {
		priv, err := LoadPriv(opts.SigningPrivPath)
		if err != nil {
			return nil, err
		}
		// FRP-7.5: if the signing key is a sub-key, embed its cert
		// under trust/subkey-cert.json so the verifier walks
		// pub→cert→sub. Detection: the signing pub does not equal
		// publisher.pub. The sibling subkey.cert next to the
		// supplied subkey.priv is the canonical cert location
		// (publisher.Subkey writes both into the same dir). When
		// the cert is present the bundle's spec_version is
		// upgraded to ≥ 4 so legacy verifiers reject explicitly.
		signingPub := ed25519.PublicKey(priv.Public().(ed25519.PublicKey))
		if !bytes.Equal(signingPub, pub) {
			certPath := filepath.Join(filepath.Dir(opts.SigningPrivPath), "subkey.cert")
			certBody, err := os.ReadFile(certPath)
			if err != nil {
				return nil, fmt.Errorf("sub-key signing requested but %s not found: %w", certPath, err)
			}
			extras["trust/subkey-cert.json"] = certBody
			if manifest.SpecVersion < 4 {
				manifest.SpecVersion = 4
			}
		}

		sbpBytes, err = bundle.BuildSignedBundleDeterministic(manifest, profiles, extras, pub, priv)
		if err != nil {
			return nil, err
		}

		// Self-verify before writing.
		parsed, err := bundle.ParseSBP(bytes.NewReader(sbpBytes), int64(len(sbpBytes)))
		if err != nil {
			return nil, fmt.Errorf("self-parse failed: %w", err)
		}
		if err := bundle.VerifyBundle(parsed); err != nil {
			return nil, fmt.Errorf("self-verify failed: %w", err)
		}
	}

	if err := writeFileAtomic(opts.Out, sbpBytes, 0o644); err != nil {
		return nil, err
	}

	return &BundleResult{
		OutPath:      opts.Out,
		Bytes:        sbpBytes,
		PublisherFP:  bundle.PublisherFingerprint(pub).Hex,
		RouteCount:   len(manifest.Routes),
		LintFindings: findings,
	}, nil
}

func enforceManifestPolicy(m bundle.Manifest, now time.Time) error {
	// Publisher CLI accepts spec_version 1 (legacy), 2 (3A-3F), 3
	// (FRP-1 RelayPack), and 4 (FRP-7.5 sub-key cert chain).
	switch m.SpecVersion {
	case 1, 2, 3, 4:
	default:
		return fmt.Errorf("manifest spec_version must be 1, 2, 3, or 4")
	}
	if m.Bundle.ID == "" {
		return fmt.Errorf("manifest bundle.id is required")
	}
	if !validBundleType(m.Bundle.Type) {
		return fmt.Errorf("manifest bundle.type %q is not in the spec enum", m.Bundle.Type)
	}
	bundleExpiry, err := time.Parse(time.RFC3339, m.Bundle.ExpiresAt)
	if err != nil {
		return fmt.Errorf("manifest bundle.expires_at must be RFC3339")
	}
	if !bundleExpiry.After(now) {
		return fmt.Errorf("manifest bundle.expires_at must be in the future")
	}
	if len(m.Routes) == 0 {
		return fmt.Errorf("manifest must declare at least one route")
	}
	if len(m.Routes) > 100 {
		return fmt.Errorf("manifest declares %d routes; cap is 100", len(m.Routes))
	}
	for _, r := range m.Routes {
		if r.ID == "" || r.TransportFamily == "" || r.ScarcityClass == "" || r.ConfigPath == "" || r.ValidUntil == "" {
			return fmt.Errorf("route %q has missing required fields", r.ID)
		}
		validUntil, err := time.Parse(time.RFC3339, r.ValidUntil)
		if err != nil {
			return fmt.Errorf("route %q valid_until must be RFC3339", r.ID)
		}
		if validUntil.After(bundleExpiry.Add(7 * 24 * time.Hour)) {
			return fmt.Errorf("route %q valid_until exceeds bundle.expires_at + 7 days", r.ID)
		}
	}
	return nil
}

func validBundleType(t string) bool {
	switch t {
	case "provider", "friend_share", "emergency", "revocation", "trust_update", "directory":
		return true
	}
	return false
}

func loadProfiles(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(filepath.Join("profiles", rel))
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[key] = body
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Stabilize ordering for deterministic builds (returned map order is
	// random, but downstream uses the map as a name->bytes lookup).
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return out, nil
}

// applyRedistributionPolicy stamps the publisher-supplied
// (policy, cap) pair onto every route in the manifest. Phase
// 3F. The CLI applies a single policy to every route in a
// given bundle build; per-route overrides require the operator
// to edit the manifest JSON directly. Empty policy → no-op.
func applyRedistributionPolicy(m *bundle.Manifest, policy string, cap uint8) error {
	switch policy {
	case "none", "transitive":
		if cap != 0 {
			return fmt.Errorf("--delegate-cap is only valid with --redistribution-policy=delegated_n")
		}
	case "delegated_n":
		if cap == 0 {
			return fmt.Errorf("--delegate-cap is required (1..255) when --redistribution-policy=delegated_n")
		}
	default:
		return fmt.Errorf("--redistribution-policy must be one of {none, delegated_n, transitive}; got %q", policy)
	}
	for i := range m.Routes {
		m.Routes[i].RedistributionPolicy = policy
		m.Routes[i].RedistributionCap = cap
	}
	return nil
}

func buildUnsignedDeterministic(manifest bundle.Manifest, profiles, extras map[string][]byte, pub ed25519.PublicKey) ([]byte, error) {
	// Re-use the deterministic builder by passing a zero-valued private key.
	// For unsigned outputs the verifier in bundle-go will reject the result;
	// the suffix `.UNSIGNED.sbp` makes the operator-side intent explicit.
	zeroPriv := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	body, err := bundle.BuildSignedBundleDeterministic(manifest, profiles, extras, pub, zeroPriv)
	if err != nil {
		return nil, err
	}
	return body, nil
}
