package refresh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"daal/bundle-go/uri"
)

// ParsedRoute is a transport-agnostic route as extracted from a
// subscription body. Its ID is POSITIONAL ("sub-<hint>-<n>", the n-th
// entry of the body), not a hash of the outbound: a refresh that brings
// the same entries in the same order overwrites the same rows. Entries
// the importer refuses keep their slot (see the parsers below) so a
// refusal does not renumber the rest. Reordering the subscription
// still renumbers; nothing prunes an id the body no longer has.
type ParsedRoute struct {
	RouteID         string
	DisplayName     string
	TransportFamily string
	OutboundJSON    []byte // sing-box-shaped {type:..., server:..., ...}
	UsedNames       []string
}

// ParsedSubscription is the full result of parsing a subscription body.
type ParsedSubscription struct {
	Format       string // "base64" | "sip008" | "clash" | "uri-list"
	ProfileTitle string
	SupportURL   string
	Routes       []ParsedRoute
}

// ParseSubscriptionBody auto-detects the body format and returns its
// parsed routes. Recognized formats:
//   - base64 (mass-delimited list of vmess://, vless://, ss:// URIs;
//     either base64-encoded or raw)
//   - SIP008 JSON (Shadowsocks subscription)
//   - Clash YAML (a small parser is sufficient for the proxies: section)
//
// Phase 1.5A's parser is deliberately strict: anything ambiguous is
// rejected as bundle_corrupted; the user re-imports manually.
func ParseSubscriptionBody(body []byte, displayHint string) (ParsedSubscription, error) {
	if len(body) == 0 {
		return ParsedSubscription{}, errors.New("subscription body empty")
	}
	trimmed := bytes.TrimSpace(body)
	switch {
	case bytes.HasPrefix(trimmed, []byte("{")):
		return parseSIP008(trimmed, displayHint)
	case bytes.HasPrefix(trimmed, []byte("proxies:")) ||
		bytes.Contains(trimmed, []byte("\nproxies:")) ||
		bytes.HasPrefix(trimmed, []byte("port:")):
		return parseClash(trimmed, displayHint)
	default:
		return parseBase64OrURIList(trimmed, displayHint)
	}
}

func parseBase64OrURIList(body []byte, displayHint string) (ParsedSubscription, error) {
	// Try base64 decode first; if that fails, treat as raw URI list.
	decoded := tryBase64Decode(body)
	if decoded == nil {
		decoded = body
	}
	scanner := bufioScanner(decoded)
	out := ParsedSubscription{Format: "base64", ProfileTitle: displayHint}
	idx := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prof, _, err := uri.ParseURI(line)
		if err != nil {
			// A link the importer REFUSES still takes its slot. Route ids
			// are positional, and health, cooldown and network memory
			// are keyed by id: without the slot, a link refused since
			// the last refresh (plaintext VLESS, xhttp) would hand every
			// later id, and its history, to a different server.
			if uri.RefusalCode(err) != "" {
				idx++
			}
			continue
		}
		ob, err := uri.MarshalOutbound(prof)
		if err != nil {
			idx++
			continue
		}
		idx++
		nm := prof.Tag
		if nm == "" {
			nm = fmt.Sprintf("%s-%d", prof.TransportFamily, idx)
		}
		out.Routes = append(out.Routes, ParsedRoute{
			RouteID:         fmt.Sprintf("sub-%s-%d", abbrev(displayHint), idx),
			DisplayName:     nm,
			TransportFamily: prof.TransportFamily,
			OutboundJSON:    ob,
		})
	}
	if len(out.Routes) == 0 {
		return ParsedSubscription{}, errors.New("subscription: no routes recognized")
	}
	return out, nil
}

func parseSIP008(body []byte, displayHint string) (ParsedSubscription, error) {
	var doc struct {
		Version int    `json:"version"`
		Title   string `json:"title"`
		Servers []struct {
			ID         string `json:"id"`
			Remarks    string `json:"remarks"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			Password   string `json:"password"`
			Method     string `json:"method"`
			Plugin     string `json:"plugin,omitempty"`
			PluginOpts string `json:"plugin_opts,omitempty"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ParsedSubscription{}, fmt.Errorf("sip008 parse: %w", err)
	}
	out := ParsedSubscription{Format: "sip008", ProfileTitle: choose(doc.Title, displayHint)}
	for i, s := range doc.Servers {
		// method none is a plaintext proxy; refused as ss:// is
		// (bundle/go/uri ssPlaintextMethod). The id stays i+1 for the
		// rest, so skipping it moves nobody else's history.
		switch strings.ToLower(strings.TrimSpace(s.Method)) {
		case "none", "plain", "dummy":
			continue
		}
		ob := map[string]any{
			"type":        "shadowsocks",
			"tag":         choose(s.Remarks, fmt.Sprintf("ss-%d", i+1)),
			"server":      s.Server,
			"server_port": s.ServerPort,
			"method":      s.Method,
			"password":    s.Password,
		}
		if s.Plugin != "" {
			ob["plugin"] = s.Plugin
			ob["plugin_opts"] = s.PluginOpts
		}
		body, _ := json.Marshal(ob)
		out.Routes = append(out.Routes, ParsedRoute{
			RouteID:         fmt.Sprintf("sub-%s-%d", abbrev(displayHint), i+1),
			DisplayName:     choose(s.Remarks, fmt.Sprintf("sip008-%d", i+1)),
			TransportFamily: "shadowsocks",
			OutboundJSON:    body,
		})
	}
	if len(out.Routes) == 0 {
		return ParsedSubscription{}, errors.New("sip008: no servers")
	}
	return out, nil
}

// parseClash extracts the `proxies:` block from a Clash config. We do not
// pull in a YAML library; the hand-rolled scanner here recognizes the
// standard "- name: ..., type: ..., server: ..., port: ..." shape that
// every well-known Clash subscription emits, inline or block style.
//
// Each entry is converted by uri.ProfileFromClashEntry, the same Clash
// mapping the URI importer uses. This used to store the Clash entry
// itself as the route's "outbound" (name/port/cipher keys sing-box has
// never heard of, rejected by the engine's strict parse at connect) and
// to pick the family from `type:` alone: every vless entry became
// vless-reality and every trojan entry websocket-tls — the stable badge
// of Daal's own VLESS+WebSocket tier on a stranger's Trojan server. An
// entry the importer refuses (plaintext, a transport the engine cannot
// carry) is skipped, as an unrecognised one always was.
func parseClash(body []byte, displayHint string) (ParsedSubscription, error) {
	out := ParsedSubscription{Format: "clash", ProfileTitle: displayHint}
	lines := strings.Split(string(body), "\n")
	in := false
	var current map[string]string
	// Route ids are positional, and health, cooldown and network memory
	// are keyed by id. slot counts every entry of a type this reader
	// has always taken (clashSlotTypes), refused or not, so an entry
	// refused now (plaintext VLESS, an h2 transport) does not hand the
	// ids after it, and their history, to different servers. Types it
	// used to drop (vmess) count separately under their own id form.
	slot, extra := 0, 0
	flush := func() {
		if current == nil || current["server"] == "" {
			return
		}
		var id string
		if clashSlotTypes[current["type"]] {
			slot++
			id = fmt.Sprintf("sub-%s-%d", abbrev(displayHint), slot)
		} else {
			extra++
			id = fmt.Sprintf("sub-%s-x%d", abbrev(displayHint), extra)
		}
		prof, err := uri.ProfileFromClashEntry(current)
		if err != nil {
			return
		}
		raw, err := uri.MarshalOutbound(prof)
		if err != nil {
			return
		}
		idx := len(out.Routes) + 1
		out.Routes = append(out.Routes, ParsedRoute{
			RouteID:         id,
			DisplayName:     choose(prof.Tag, fmt.Sprintf("clash-%d", idx)),
			TransportFamily: prof.TransportFamily,
			OutboundJSON:    raw,
		})
	}
	for _, ln := range lines {
		raw := strings.TrimRight(ln, "\r")
		trim := strings.TrimSpace(raw)
		if strings.HasPrefix(trim, "proxies:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if strings.HasPrefix(trim, "- ") {
			flush()
			current = map[string]string{}
			rest := strings.TrimPrefix(trim, "- ")
			for _, kv := range splitClashInline(rest) {
				k, v, ok := splitKV(kv)
				if ok {
					current[k] = stripQuotes(v)
				}
			}
			continue
		}
		if strings.HasPrefix(raw, "  ") && current != nil {
			k, v, ok := splitKV(strings.TrimSpace(raw))
			if ok {
				current[k] = stripQuotes(v)
			}
			continue
		}
		// Outside the proxies block.
		if strings.HasSuffix(trim, ":") && in {
			break
		}
	}
	flush()
	if len(out.Routes) == 0 {
		return ParsedSubscription{}, errors.New("clash: no proxies recognized")
	}
	return out, nil
}

// clashSlotTypes are the Clash types the reader took before it used
// uri.ProfileFromClashEntry (its old transportFromClash), whose ids
// existing installs already hold.
var clashSlotTypes = map[string]bool{
	"vless": true, "ss": true, "shadowsocks": true, "hysteria2": true,
	"tuic": true, "trojan": true, "wireguard": true,
}

func splitClashInline(s string) []string {
	// "{name: foo, type: ss, server: 1.1.1.1, port: 443}"
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = s[1 : len(s)-1]
	}
	out := []string{}
	depth := 0
	last := 0
	for i, r := range s {
		switch r {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[last:i]))
				last = i + 1
			}
		}
	}
	if last < len(s) {
		out = append(out, strings.TrimSpace(s[last:]))
	}
	return out
}

func splitKV(s string) (string, string, bool) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
		(strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
		return s[1 : len(s)-1]
	}
	return s
}

func tryBase64Decode(b []byte) []byte {
	cleaned := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\r' || c == '\n' || c == ' ' || c == '\t' {
			continue
		}
		cleaned = append(cleaned, c)
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		out, err := enc.DecodeString(string(cleaned))
		if err == nil && len(out) > 0 && bytes.ContainsAny(out, "\n\r:") {
			return out
		}
	}
	return nil
}

func choose(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func abbrev(s string) string {
	out := strings.Builder{}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		}
		if out.Len() >= 8 {
			break
		}
	}
	if out.Len() == 0 {
		return "x"
	}
	return strings.ToLower(out.String())
}

// bufioScanner is a tiny wrapper around bufio.Scanner that returns a
// scanner pre-bound to bytes. Splitting it out keeps parse.go importing
// only encoding/json + uri.
func bufioScanner(b []byte) *lineScanner { return &lineScanner{rest: b} }

type lineScanner struct {
	rest []byte
	cur  string
}

func (s *lineScanner) Scan() bool {
	if len(s.rest) == 0 {
		return false
	}
	idx := bytes.IndexByte(s.rest, '\n')
	if idx < 0 {
		s.cur = string(s.rest)
		s.rest = nil
		return true
	}
	s.cur = string(bytes.TrimRight(s.rest[:idx], "\r"))
	s.rest = s.rest[idx+1:]
	return true
}
func (s *lineScanner) Text() string { return s.cur }
