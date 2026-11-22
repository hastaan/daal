// Package uri parses every external route format the V0 internal-route
// spec accepts and converts each to a sing-box outbound JSON dict.
//
// All parsers MUST be deterministic, side-effect-free, and produce a
// minimal sing-box outbound: enough fields for sing-box to dial, no more.
// Parser output is the canonical byte stream the importer wraps in a
// transient single-route .sbp via uri.Wrap.
package uri

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Profile is a single decoded outbound. TransportFamily mirrors
// bundle.TransportFamily strings; we keep it as a plain string here to
// avoid pulling bundle into uri (which has no other reason to depend on
// it).
type Profile struct {
	TransportFamily string         // e.g. "vless-reality", "shadowsocks", "wireguard"
	Outbound        map[string]any // sing-box outbound JSON
	Tag             string         // human label parsed from the URI's # fragment

	// ManualOnly means "dial this route only when the person picks it;
	// never race it in an automatic connect", whatever its family's
	// maturity. The family stays truthful about what goes on the wire
	// (a downgraded AmneziaWG conf IS WireGuard), so this cannot be
	// carried by the family alone. Today only the AmneziaWG junk-only
	// downgrade sets it (NoticeAmneziaDowngraded): one automatic attempt
	// sends the exact WireGuard handshake Iran's operators throttle and
	// then block, from the person's SIM-linked address.
	//
	// The importer that stores the route must keep this bit and the
	// path manager must honour it; a host that cannot store it must not
	// import a ManualOnly profile as an ordinary route. MarshalOutbound
	// drops it (it is not part of the outbound). core/abi URIImport
	// keeps it (routestore RouteRow.ManualOnly, written through the
	// route's meta before the import) and the automatic connect refuses
	// such a route (refusal chosen_only) before any family rule, with
	// experimental routes on too. URIImport also stores EVERY pasted
	// WireGuard conf as manual-only, for the same reason.
	ManualOnly bool
}

// Provenance records what was parsed and any vendor extensions detected.
type Provenance struct {
	Scheme       string   // "vless", "vmess", "ss", ... or "subscription", "clash", "sip008", "wireguard", "amneziawg", "tor-bridge"
	HadAmnezia   bool     // AmneziaWG-only fields present in WG conf
	HadReality   bool     // Reality-flavored vless extension
	BareSchemes  []string // for base64 envelopes: list of inner schemes
	WarningCount int

	// DroppedParams names vendor extensions that were recognised and
	// then NOT carried into the sing-box config because the shipped
	// engine has no field for them. Today this is only AmneziaWG's
	// obfuscation knobs; see parseWireGuard.
	DroppedParams []string

	// Downgrade is a sentence an importer may show verbatim when the
	// parsed route is weaker than what the user handed over. It exists
	// because "we imported your config" and "we imported a
	// strictly-less-resistant version of your config" must not look the
	// same to someone choosing a route under censorship. Empty when
	// nothing was lost.
	Downgrade string

	// Notice is a stable token for the host's own copy of Downgrade
	// ("" when there is nothing to say). See the Notice* constants.
	Notice string
}

// Provenance.Notice values.
const (
	// An AmneziaWG conf with junk-packet fields only, imported as plain
	// WireGuard. It connects only where WireGuard is not blocked, and
	// an attempt sends a WireGuard handshake: it must not be tried
	// automatically, so the Profile carries ManualOnly; see
	// parseWireGuard.
	NoticeAmneziaDowngraded = "amneziawg_downgraded"
	// An AmneziaWG conf whose server would ignore plain WireGuard,
	// imported under the unsupported "amneziawg" family.
	NoticeAmneziaUnsupported = "amneziawg_unsupported"
)

// ErrNoMatch means the caller's input doesn't look like any known format.
var ErrNoMatch = errors.New("uri: no matching parser")

// ParseURI dispatches to a single-URI parser based on the scheme prefix.
// Multi-line / file inputs go through ParseAny.
func ParseURI(s string) (Profile, Provenance, error) {
	s = lowerScheme(strings.TrimSpace(s))
	if s == "" {
		return Profile{}, Provenance{}, ErrNoMatch
	}
	switch {
	case strings.HasPrefix(s, "vless://"):
		return parseVLESS(s)
	case strings.HasPrefix(s, "vmess://"):
		return parseVMess(s)
	case strings.HasPrefix(s, "trojan://"):
		return parseTrojan(s)
	case strings.HasPrefix(s, "ss://"):
		return parseSS(s)
	case strings.HasPrefix(s, "hysteria2://"), strings.HasPrefix(s, "hy2://"):
		return parseHy2(s)
	case strings.HasPrefix(s, "tuic://"):
		return parseTUIC(s)
	}
	return Profile{}, Provenance{}, ErrNoMatch
}

// lowerScheme lower-cases a link's scheme ("VLESS://…" → "vless://…"):
// schemes are case-insensitive (RFC 3986 §3.1), and messengers and
// phone keyboards capitalise the first letter of a pasted line. Only
// the scheme: the rest (a password, a base64 body) keeps its case.
func lowerScheme(s string) string {
	i := strings.Index(s, "://")
	if i <= 0 {
		return s
	}
	for _, c := range s[:i] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return s
		}
	}
	return strings.ToLower(s[:i]) + s[i:]
}

// ParseAny tries every known format. For multi-profile inputs (subscription
// envelopes, Clash YAML, SIP008) it returns one Profile per outbound.
//
// Caller may pass a content-type hint; "" means autodetect.
func ParseAny(body []byte, hint string) ([]Profile, Provenance, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return nil, Provenance{}, ErrNoMatch
	}
	switch hint {
	case "application/yaml", "text/yaml", "yaml", "clash":
		return parseClashYAML(body)
	case "application/json", "json":
		// Could be SIP008 or a single sing-box outbound.
		if profs, prov, err := parseSIP008(body); err == nil {
			return profs, prov, nil
		}
	case "wireguard", "amneziawg":
		p, prov, err := parseWireGuard(body)
		if err != nil {
			return nil, prov, err
		}
		return []Profile{p}, prov, nil
	case "tor-bridge":
		profs, prov, err := parseTorBridges(body)
		return profs, prov, err
	}

	// Auto-detection (try cheapest first).
	switch {
	case strings.HasPrefix(text, "[Interface]"), strings.Contains(text, "PrivateKey ="):
		p, prov, err := parseWireGuard(body)
		if err != nil {
			return nil, prov, err
		}
		return []Profile{p}, prov, nil
	case strings.HasPrefix(text, "{"):
		if profs, prov, err := parseSIP008(body); err == nil {
			return profs, prov, nil
		}
	case strings.HasPrefix(text, "proxies:"), strings.Contains(text, "\nproxies:"):
		return parseClashYAML(body)
	case looksLikeTorBridges(text):
		return parseTorBridges(body)
	}

	// Try multi-line URI list (plain or base64-wrapped).
	if profs, prov, err := parseSubscriptionEnvelope(body); err == nil {
		return profs, prov, nil
	}

	// Try a single URI line.
	if p, prov, err := ParseURI(text); err == nil {
		return []Profile{p}, prov, nil
	}
	return nil, Provenance{}, ErrNoMatch
}

// MarshalOutbound returns canonical JSON for a sing-box outbound. Used by
// uri.Wrap to embed parser output in a transient .sbp.
func MarshalOutbound(p Profile) ([]byte, error) {
	if p.Outbound == nil {
		return nil, fmt.Errorf("uri: empty outbound")
	}
	return json.Marshal(p.Outbound)
}
