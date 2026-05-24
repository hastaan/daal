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
}

// Provenance records what was parsed and any vendor extensions detected.
type Provenance struct {
	Scheme       string   // "vless", "vmess", "ss", ... or "subscription", "clash", "sip008", "wireguard", "amneziawg", "tor-bridge"
	HadAmnezia   bool     // AmneziaWG-only fields present in WG conf
	HadReality   bool     // Reality-flavored vless extension
	BareSchemes  []string // for base64 envelopes: list of inner schemes
	WarningCount int
}

// ErrNoMatch means the caller's input doesn't look like any known format.
var ErrNoMatch = errors.New("uri: no matching parser")

// ParseURI dispatches to a single-URI parser based on the scheme prefix.
// Multi-line / file inputs go through ParseAny.
func ParseURI(s string) (Profile, Provenance, error) {
	s = strings.TrimSpace(s)
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
	case strings.HasPrefix(text, "Bridge ") || strings.HasPrefix(text, "obfs4 ") || strings.HasPrefix(text, "webtunnel "):
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
