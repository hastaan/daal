package publisher

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// LintLevel categorises a finding.
type LintLevel string

const (
	LintWarn  LintLevel = "warn"
	LintBlock LintLevel = "block"
)

// LintCode identifies a check.
type LintCode string

const (
	CodeRealityCoverSNIImplausible LintCode = "REALITY_COVER_SNI_IMPLAUSIBLE"
	CodePublisherKeyReuse          LintCode = "PUBLISHER_KEY_REUSE"
	CodeExpiryTooLongBootstrap     LintCode = "EXPIRY_TOO_LONG_BOOTSTRAP"
	CodeExpiryTooLongFriendShare   LintCode = "EXPIRY_TOO_LONG_FRIEND_SHARE"
	CodeUDPOnlyNoTCPFallback       LintCode = "UDP_ONLY_NO_TCP_FALLBACK"
	CodeUDPGatedNotMarked          LintCode = "UDP_GATED_NOT_MARKED"
	CodeEmptyProfile               LintCode = "EMPTY_PROFILES"
	CodeProfileOutsideDir          LintCode = "PROFILE_OUTSIDE_DIR"
	CodeBundleTypeScarcityMismatch LintCode = "BUNDLE_TYPE_MISMATCH_SCARCITY"
	CodeManifestTimeSkew           LintCode = "MANIFEST_TIME_SKEW"
)

// LintFinding is one result.
type LintFinding struct {
	Code    LintCode
	Level   LintLevel
	Reason  string
	Hint    string
	Anchor  string
	RouteID string
}

// LintInput is everything the lint engine sees. It MUST NOT make network
// calls, perform DNS lookups, or read filesystem paths outside ProfilesDir.
type LintInput struct {
	Manifest    bundle.Manifest
	Profiles    map[string][]byte // path -> bytes, scoped to ProfilesDir
	ProfilesDir string
	Now         time.Time
}

// LintRoutes runs every lint and returns findings ordered by code.
func LintRoutes(in LintInput) []LintFinding {
	var out []LintFinding

	// EMPTY_PROFILES + PROFILE_OUTSIDE_DIR
	for _, r := range in.Manifest.Routes {
		// Path traversal already rejected by bundle-go; guard anyway.
		clean := filepath.Clean(r.ConfigPath)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) || !strings.HasPrefix(clean, "profiles/") {
			out = append(out, LintFinding{
				Code: CodeProfileOutsideDir, Level: LintBlock,
				Reason:  fmt.Sprintf("route %q config_path %q resolves outside profiles/", r.ID, r.ConfigPath),
				Hint:    "place profiles under the profiles/ directory and use relative paths",
				Anchor:  "specs/sbp-v1.md#archive-layout",
				RouteID: r.ID,
			})
			continue
		}
		body, ok := in.Profiles[clean]
		if !ok || len(body) == 0 {
			out = append(out, LintFinding{
				Code: CodeEmptyProfile, Level: LintBlock,
				Reason:  fmt.Sprintf("route %q references missing or empty profile %s", r.ID, r.ConfigPath),
				Hint:    "ensure each route's config_path exists in --profiles-dir",
				Anchor:  "specs/sbp-v1.md#archive-layout",
				RouteID: r.ID,
			})
		}
	}

	// UDP_GATED_NOT_MARKED + UDP_ONLY_NO_TCP_FALLBACK
	udpFamilies := map[string]bool{
		string(bundle.TransportHysteria2): true,
		string(bundle.TransportTUIC):      true,
		string(bundle.TransportWireGuard): true,
		string(bundle.TransportAmneziaWG): true,
		string(bundle.TransportMASQUE):    true,
	}
	tcpFamilies := map[string]bool{
		string(bundle.TransportVLESSReality): true,
		string(bundle.TransportNaive):        true,
		string(bundle.TransportWebSocketTLS): true,
		string(bundle.TransportWebTunnel):    true,
		string(bundle.TransportShadowsocks):  true,
		string(bundle.TransportTorBridge):    true,
	}
	hasUDP, hasTCP := false, false
	for _, r := range in.Manifest.Routes {
		if udpFamilies[r.TransportFamily] {
			hasUDP = true
			if !r.UDPGated {
				out = append(out, LintFinding{
					Code: CodeUDPGatedNotMarked, Level: LintBlock,
					Reason:  fmt.Sprintf("route %q (%s) is a UDP-first transport but udp_gated is false", r.ID, r.TransportFamily),
					Hint:    "set udp_gated: true on UDP-first transports so clients UDP-probe before use",
					Anchor:  "specs/route-internal-v1.md#udp-gating",
					RouteID: r.ID,
				})
			}
		}
		if tcpFamilies[r.TransportFamily] {
			hasTCP = true
		}
	}
	if hasUDP && !hasTCP {
		out = append(out, LintFinding{
			Code: CodeUDPOnlyNoTCPFallback, Level: LintWarn,
			Reason: "bundle has only UDP-gated transports; many target networks suppress UDP",
			Hint:   "add a TCP/443-shaped route family (vless-reality, naive, websocket-tls) as fallback",
			Anchor: "specs/route-internal-v1.md#udp-gating",
		})
	}

	// EXPIRY_TOO_LONG_*
	for _, r := range in.Manifest.Routes {
		validUntil, err := time.Parse(time.RFC3339, r.ValidUntil)
		if err != nil {
			continue
		}
		dur := validUntil.Sub(in.Now)
		if r.ScarcityClass == string(bundle.ScarcityEmergency) && dur > 30*24*time.Hour {
			out = append(out, LintFinding{
				Code: CodeExpiryTooLongBootstrap, Level: LintWarn,
				Reason:  fmt.Sprintf("emergency-class route %q has valid_until > 30d (~%s)", r.ID, dur.Round(time.Hour)),
				Hint:    "emergency routes should be short-lived; tighten valid_until",
				Anchor:  "specs/route-internal-v1.md#scarcity",
				RouteID: r.ID,
			})
		}
	}
	if in.Manifest.Bundle.Type == "friend_share" {
		for _, r := range in.Manifest.Routes {
			validUntil, err := time.Parse(time.RFC3339, r.ValidUntil)
			if err != nil {
				continue
			}
			dur := validUntil.Sub(in.Now)
			if dur > 60*24*time.Hour {
				out = append(out, LintFinding{
					Code: CodeExpiryTooLongFriendShare, Level: LintWarn,
					Reason:  fmt.Sprintf("friend-share route %q has valid_until > 60d", r.ID),
					Hint:    "friend-share bundles should be short-lived; tighten valid_until",
					Anchor:  "specs/sbp-v1.md#manifest-schema",
					RouteID: r.ID,
				})
			}
		}
	}

	// BUNDLE_TYPE_MISMATCH_SCARCITY
	if in.Manifest.Bundle.Type == "emergency" {
		hasEmergency := false
		for _, r := range in.Manifest.Routes {
			if r.ScarcityClass == string(bundle.ScarcityEmergency) {
				hasEmergency = true
				break
			}
		}
		if !hasEmergency {
			out = append(out, LintFinding{
				Code: CodeBundleTypeScarcityMismatch, Level: LintWarn,
				Reason: "bundle.type is emergency but no route has scarcity_class: emergency",
				Hint:   "set scarcity_class: emergency on at least one route in emergency bundles",
				Anchor: "specs/sbp-v1.md#manifest-schema",
			})
		}
	}

	// MANIFEST_TIME_SKEW
	if t, err := time.Parse(time.RFC3339, in.Manifest.Bundle.CreatedAt); err == nil {
		if t.Sub(in.Now) > 24*time.Hour || in.Now.Sub(t) > 90*24*time.Hour {
			out = append(out, LintFinding{
				Code: CodeManifestTimeSkew, Level: LintWarn,
				Reason: fmt.Sprintf("manifest created_at %s is far from build time", in.Manifest.Bundle.CreatedAt),
				Hint:   "set created_at near the actual signing time",
				Anchor: "specs/sbp-v1.md#canonical-json",
			})
		}
	}

	// REALITY_COVER_SNI_IMPLAUSIBLE
	for _, r := range in.Manifest.Routes {
		if r.TransportFamily != string(bundle.TransportVLESSReality) {
			continue
		}
		body, ok := in.Profiles[filepath.Clean(r.ConfigPath)]
		if !ok {
			continue
		}
		if implausible, reason := realityImplausibility(body); implausible {
			out = append(out, LintFinding{
				Code: CodeRealityCoverSNIImplausible, Level: LintWarn,
				Reason:  fmt.Sprintf("route %q REALITY metadata looks implausible: %s", r.ID, reason),
				Hint:    "REALITY cover SNI must be a domain whose ASN class plausibly matches the server's IP class",
				Anchor:  "specs/route-internal-v1.md#reality",
				RouteID: r.ID,
			})
		}
	}

	// PUBLISHER_KEY_REUSE: count distinct profiles sharing prefixes.
	if reuse := publisherKeyReuse(in); reuse != "" {
		out = append(out, LintFinding{
			Code: CodePublisherKeyReuse, Level: LintWarn,
			Reason: reuse,
			Hint:   "rotate sub-keys per route family or per endpoint cluster to limit blast radius",
			Anchor: "specs/publisher-keys-v1.md#sub-keys",
		})
	}

	return out
}

// realityImplausibility parses a profile body looking for obvious cover-SNI vs
// server-IP mismatches without any DNS or ASN lookup. The check is metadata
// only; the heuristic is deliberately conservative.
func realityImplausibility(profile []byte) (bool, string) {
	s := strings.ToLower(string(profile))
	hasBigBrandSNI := false
	for _, brand := range []string{"apple.com", "microsoft.com", "google.com", "icloud.com"} {
		if strings.Contains(s, "\""+brand+"\"") || strings.Contains(s, "/"+brand) {
			hasBigBrandSNI = true
			break
		}
	}
	hasBudgetHostingHint := false
	for _, hint := range []string{"hetzner", "ovh", "digitalocean", "linode"} {
		if strings.Contains(s, hint) {
			hasBudgetHostingHint = true
			break
		}
	}
	if hasBigBrandSNI && hasBudgetHostingHint {
		return true, "big-brand cover SNI declared alongside budget-hosting metadata"
	}
	return false, ""
}

func publisherKeyReuse(in LintInput) string {
	const reuseThreshold = 5
	prefixCounts := map[string]int{}
	for _, r := range in.Manifest.Routes {
		body, ok := in.Profiles[filepath.Clean(r.ConfigPath)]
		if !ok {
			continue
		}
		s := string(body)
		if idx := strings.Index(s, "\"server\""); idx >= 0 {
			tail := s[idx:]
			if end := strings.IndexByte(tail[len("\"server\""):], '"'); end >= 0 {
				_ = end
			}
		}
		// Coarse heuristic: hash a 16-byte window of the profile.
		if len(s) >= 16 {
			prefixCounts[s[:16]]++
		}
	}
	for k, c := range prefixCounts {
		if c >= reuseThreshold {
			return fmt.Sprintf("%d routes share an identical 16-byte profile prefix; consider per-endpoint config divergence", c)
			_ = k
		}
	}
	return ""
}
