// Package diagnostics maps engine-level errors and probe results onto the
// V0.3 failure taxonomy. The mapping table is locked at this phase; new
// engine outputs that don't match a known pattern fall back to "unknown".
package diagnostics

import (
	"strings"
)

// Category mirrors specs/failure-taxonomy-v1.md.
type Category string

const (
	DNSPoisoned                Category = "dns_poisoned"
	DNSTimeout                 Category = "dns_timeout"
	TCPConnectTimeout          Category = "tcp_connect_timeout"
	TCPReset                   Category = "tcp_reset"
	TLSHandshakeFailed         Category = "tls_handshake_failed"
	TLSSNIOrCertBlockSuspected Category = "tls_sni_or_cert_block_suspected"
	UDPUnavailable             Category = "udp_unavailable"
	QUICUnavailable            Category = "quic_unavailable"
	AuthFailed                 Category = "auth_failed"
	RouteExpired               Category = "route_expired"
	PublisherRevoked           Category = "publisher_revoked"
	PublisherKeyChanged        Category = "publisher_key_changed"
	SubscriptionUnreachable    Category = "subscription_unreachable"
	EngineCrash                Category = "engine_crash"
	BundleSignatureInvalid     Category = "bundle_signature_invalid"
	BundleCorrupted            Category = "bundle_corrupted"
	NetworkOffline             Category = "network_offline"
	Unknown                    Category = "unknown"

	// FRP-3 (Phase 31) additions. Five of the nine v2.3.4 selector
	// signals are also classifiable from error strings; they get
	// dedicated diagnostics.Category constants. The remaining four
	// (protocol_whitelist_mode, cdn_hostname_blocked, cdn_wide_failure,
	// stateful_reassembly_present) are probe-derived state aggregations
	// and live exclusively in core/internal/selection/signals.go.
	//
	// DNSBogon is narrower than DNSPoisoned: the resolver returned
	// RFC-1918 / loopback / 0.0.0.0 for a known-popular hostname, a
	// classic bogon-injection probe.
	DNSBogon Category = "dns_bogon"
	// UDPCollapsed is the explicit selector signal for "UDP probe
	// fails" — mirrored to align with selection.SignalUDPCollapsed.
	// Distinct from the legacy generic UDPUnavailable.
	UDPCollapsed Category = "udp_collapsed"
	// QUICCollapsed is QUIC-version-negotiation failure with TCP/443
	// still working. Distinct from the legacy generic QUICUnavailable.
	QUICCollapsed Category = "quic_collapsed"
	// SNIRst is a narrower variant of TLSSNIOrCertBlockSuspected:
	// TLS-RST immediately on ClientHello (no ServerHello observed).
	SNIRst Category = "sni_rst"
	// OriginUnhealthy is a CDN-edge 522/525/526 response. Operator
	// hygiene per supplement §13.4 — NOT a censorship event;
	// excluded from IsCensorshipClass below.
	OriginUnhealthy Category = "origin_unhealthy"
)

// Classify maps a free-form error string from sing-box (or another driver)
// to a V0.3 category. The matcher uses substring rules in a deterministic
// order; the *first* match wins.
//
// FRP-3 additions: the 5 selector-relevant categories
// (DNSBogon, UDPCollapsed, QUICCollapsed, SNIRst, OriginUnhealthy) are
// inserted BEFORE their legacy generic counterparts so a matching
// substring promotes to the more-specific category.
func Classify(errMessage string) Category {
	m := strings.ToLower(errMessage)
	switch {
	case contains(m, "auth ", "authentication failed", "credentials rejected", "user rejected"):
		return AuthFailed
	case contains(m, "panic:", "engine died", "process exit", "signal: killed"):
		return EngineCrash
	case contains(m, "no such host", "dns: no such", "dns: server misbehaving"):
		return DNSTimeout
	// FRP-3: more-specific bogon classifier promotes DNSPoisoned for
	// known-popular-host probes. "dns bogon" is the explicit driver
	// keyword; "rfc1918"/"sinkhole" are kept on DNSPoisoned for
	// back-compat.
	case contains(m, "dns bogon", "dns_bogon", "bogon detected"):
		return DNSBogon
	case contains(m, "rfc1918", "bogon resolver", "10.10.34.34", "sinkhole"):
		return DNSPoisoned
	case contains(m, "i/o timeout") && contains(m, "tcp"):
		return TCPConnectTimeout
	case contains(m, "i/o timeout") && contains(m, "dns"):
		return DNSTimeout
	// FRP-3: Cloudflare 522/525/526 are origin-health responses, not
	// censorship signals. Hit BEFORE generic TCP/TLS failure rules.
	case contains(m, "522", "525", "526") && contains(m, "cloudflare", "cdn", "origin"):
		return OriginUnhealthy
	case contains(m, "origin unhealthy", "origin_unhealthy"):
		return OriginUnhealthy
	case contains(m, "connection reset by peer") || contains(m, "rst received"):
		return TCPReset
	// FRP-3: SNIRst is "RST mid-ClientHello, no ServerHello observed".
	// Matches BEFORE TLSSNIOrCertBlockSuspected.
	case contains(m, "sni_rst", "sni reset", "rst before serverhello", "client hello rst"):
		return SNIRst
	case contains(m, "tls: no application protocol") || contains(m, "tls handshake interrupted by rst"):
		return TLSSNIOrCertBlockSuspected
	case contains(m, "tls: handshake failure") || contains(m, "tls handshake error"):
		return TLSHandshakeFailed
	// FRP-3: explicit QUIC-version-negotiation failure → QUICCollapsed.
	case contains(m, "quic_collapsed", "quic: version negotiation"):
		return QUICCollapsed
	case contains(m, "quic:") && contains(m, "udp"):
		return QUICUnavailable
	case contains(m, "quic:"):
		return QUICUnavailable
	// FRP-3: explicit "udp_collapsed" wins over generic UDPUnavailable.
	case contains(m, "udp_collapsed", "udp collapse"):
		return UDPCollapsed
	case contains(m, "udp ", "udp probe failed", "udp blackhole"):
		return UDPUnavailable
	case contains(m, "route expired"):
		return RouteExpired
	case contains(m, "publisher revoked"):
		return PublisherRevoked
	case contains(m, "publisher key changed"):
		return PublisherKeyChanged
	case contains(m, "subscription unreachable", "directory unreachable"):
		return SubscriptionUnreachable
	case contains(m, "bundle signature invalid"):
		return BundleSignatureInvalid
	case contains(m, "bundle corrupted", "bundle parse"):
		return BundleCorrupted
	case contains(m, "network is unreachable", "no route to host", "no network"):
		return NetworkOffline
	}
	return Unknown
}

// IsCensorshipClass reports whether category should trigger cooldown.
// Per V0.3, auth_failed must NEVER cool down — that is the explicit rule.
//
// FRP-3 additions:
//   - DNSBogon, UDPCollapsed, QUICCollapsed, SNIRst → censorship class
//     (true; default fall-through).
//   - OriginUnhealthy → operator-hygiene per supplement §13.4. NOT a
//     censorship event. Excluded explicitly here.
func IsCensorshipClass(c Category) bool {
	switch c {
	case AuthFailed, RouteExpired, PublisherRevoked, PublisherKeyChanged,
		BundleCorrupted, BundleSignatureInvalid, NetworkOffline, Unknown,
		OriginUnhealthy:
		return false
	}
	return true
}

func contains(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
