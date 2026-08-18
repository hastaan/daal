package uri

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TorBridgeLine is a validated Tor bridge line, decomposed.
//
// A bridge line is the wire format the Tor Project hands users out of
// band (BridgeDB at bridges.torproject.org, the email autoresponder, or
// Telegram). Its grammar (tor(1), "Bridge" option) is:
//
//	Bridge [<transport>] <IP>:<ORPort> [<fingerprint>] [<k>=<v> ...]
//
// The leading transport name is OPTIONAL: a line that begins with an
// address is a "vanilla" bridge, dialled by tor directly with no
// pluggable transport. Everything after the fingerprint is transport
// specific and MUST be passed through verbatim — `cert=` for obfs4 is a
// base64 blob whose padding is significant, and `url=` for webtunnel is
// a URL. We never re-encode these; we carry the original substring.
type TorBridgeLine struct {
	// Transport is the pluggable-transport name ("obfs4", "webtunnel",
	// "snowflake", "meek_lite", ...) or "" for a vanilla bridge.
	Transport string
	Host      string
	Port      int
	// Fingerprint is the relay identity SHA-1 hex, or "" if the line
	// omitted it (legal, though BridgeDB always includes one).
	Fingerprint string
	// Raw is the canonical bridge line WITHOUT any "Bridge " keyword —
	// exactly the token sing-box must hand tor as the value of a
	// `--Bridge` argument. Reproduced from the original text, not
	// re-serialised from the fields above.
	Raw string
}

// PTName is the transport this bridge needs a ClientTransportPlugin for,
// or "" when the bridge is vanilla and needs no plugin.
func (b TorBridgeLine) PTName() string { return b.Transport }

// ParseTorBridgeLine parses ONE bridge line. It is exported because the
// engine re-derives the required pluggable transports from the
// `--Bridge` arguments it is handed (see core/engine/torconfig.go);
// keeping one parser means the importer and the dialer can never
// disagree about what transport a line asks for.
func ParseTorBridgeLine(line string) (TorBridgeLine, error) {
	line = strings.TrimSpace(line)
	// Tolerate a torrc-style "Bridge " keyword: users paste whole
	// torrc fragments at least as often as bare lines.
	if rest, ok := cutPrefixFold(line, "bridge "); ok {
		line = strings.TrimSpace(rest)
	}
	if line == "" {
		return TorBridgeLine{}, fmt.Errorf("uri: empty bridge line")
	}
	fields := strings.Fields(line)
	var b TorBridgeLine
	idx := 0
	// Decide whether field 0 is a transport name or an endpoint. An
	// endpoint always contains a ':' with a numeric port after the LAST
	// colon (IPv6 literals are bracketed). A transport name never does.
	if _, _, err := splitBridgeEndpoint(fields[0]); err != nil {
		b.Transport = fields[0]
		idx = 1
		if len(fields) < 2 {
			return TorBridgeLine{}, fmt.Errorf("uri: bridge line %q has a transport but no address", line)
		}
	}
	host, port, err := splitBridgeEndpoint(fields[idx])
	if err != nil {
		return TorBridgeLine{}, fmt.Errorf("uri: bridge line %q: %w", line, err)
	}
	b.Host, b.Port = host, port
	idx++
	// A fingerprint is 40 hex chars. Anything else at this position is
	// already a k=v parameter, so do not consume it.
	if idx < len(fields) && isHexFingerprint(fields[idx]) {
		b.Fingerprint = fields[idx]
	}
	b.Raw = strings.Join(fields, " ")
	return b, nil
}

// splitBridgeEndpoint accepts "1.2.3.4:443" and "[2001:db8::1]:443".
func splitBridgeEndpoint(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("bad endpoint %q", s)
	}
	if host == "" {
		return "", 0, fmt.Errorf("bad endpoint %q: no host", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad endpoint %q: bad port", s)
	}
	return host, port, nil
}

func isHexFingerprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func cutPrefixFold(s, lowerPrefix string) (string, bool) {
	if len(s) < len(lowerPrefix) {
		return s, false
	}
	if strings.ToLower(s[:len(lowerPrefix)]) != lowerPrefix {
		return s, false
	}
	return s[len(lowerPrefix):], true
}

// TorOutboundForBridge builds the sing-box `tor` outbound for one bridge
// line.
//
// WHY "tor" AND NOT "tor-bridge". Until Wave 5 this file emitted
// `"type":"tor-bridge"`, which is not a sing-box outbound type at all —
// sing-box 1.13.12's registry (include/registry.go:88) registers `tor`,
// and its strict decoder answers a `tor-bridge` outbound with "unknown
// outbound type: tor-bridge". Every tor route this importer has ever
// produced was undialable for that one word. See
// core/routestore/family.go, which graded the family Unsupported for
// exactly this reason.
//
// WHY THE DEVICE PATHS ARE ABSENT. sing-box's tor outbound
// (option/tor.go) also takes `executable_path` and `data_directory`.
// Both are properties of the DEVICE, not of the bridge: the tor binary
// lives in the app's native-library directory, whose path contains an
// install-specific hash, and the data directory must sit inside the app
// sandbox. A parser is deterministic and side-effect-free (see the
// package doc), so it cannot and must not resolve either. The engine
// fills them in at config-build time — core/engine/torconfig.go — and
// FAILS CLOSED when it cannot. The outbound emitted here is still valid
// sing-box JSON: with no `executable_path`, bine falls back to `tor` on
// PATH, which is the correct behaviour on a desktop where the user has
// tor installed.
//
// WHY ONE OUTBOUND PER BRIDGE. tor itself would happily take a dozen
// `Bridge` lines in one instance and pick among them. Daal's unit of
// selection, ranking, cooldown and burn-tracking is a ROUTE, so folding
// twelve bridges into one route would make twelve independently
// blockable endpoints share a single reputation — burn one and the path
// manager retires all twelve. One bridge per route keeps the accounting
// honest. The cost is that switching bridges restarts tor; the shared
// `data_directory` the engine injects keeps the cached consensus so the
// restart is a re-bootstrap, not a cold start.
func TorOutboundForBridge(b TorBridgeLine) map[string]any {
	// Order matters and is asserted by test: bine appends ExtraArgs
	// verbatim to tor's argv (bine/tor/tor.go startProcess), so these
	// arrive as command-line options in exactly this sequence.
	// `UseBridges 1` must be present or tor ignores Bridge lines
	// entirely and connects to the public network directly — which for
	// a user who asked for a bridge is a privacy failure, not a
	// fallback.
	args := []string{
		"--UseBridges", "1",
		"--Bridge", b.Raw,
	}
	return map[string]any{
		"type":       "tor",
		"extra_args": args,
	}
}

// parseTorBridges accepts a list of plain Tor bridge lines, one per
// line — the format BridgeDB, the bridges@torproject.org autoresponder
// and the Telegram bot all hand out, and the format a user pastes.
//
// Blank lines and '#' comments are skipped. A malformed line increments
// Provenance.WarningCount and is dropped rather than failing the whole
// paste: bridge sets arrive copy-pasted out of email clients that wrap
// long lines, and losing three good bridges because the fourth got
// mangled would be the wrong trade.
func parseTorBridges(body []byte) ([]Profile, Provenance, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	prov := Provenance{Scheme: "tor-bridge"}
	var profiles []Profile
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := ParseTorBridgeLine(line)
		if err != nil {
			prov.WarningCount++
			continue
		}
		label := b.Transport
		if label == "" {
			label = "vanilla"
		}
		profiles = append(profiles, Profile{
			TransportFamily: "tor-bridge",
			Outbound:        TorOutboundForBridge(b),
			Tag:             fmt.Sprintf("tor-%s-%s", label, net.JoinHostPort(b.Host, strconv.Itoa(b.Port))),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, prov, err
	}
	if len(profiles) == 0 {
		return nil, prov, ErrNoMatch
	}
	return profiles, prov, nil
}

// looksLikeTorBridges reports whether a pasted blob is a set of Tor
// bridge lines.
//
// The previous detector matched three literal prefixes — "Bridge ",
// "obfs4 " and "webtunnel " — which silently rejected two of the three
// transports the Tor Project actually recommends for Iran. A user who
// pasted the snowflake lines BridgeDB gave them got "no matching
// parser" and no way to learn why. It also rejected vanilla bridges
// (which begin with an address) and any paste whose first line is a
// comment, which is how the email autoresponder formats its reply.
//
// The test is now structural rather than lexical: find the first line
// that is neither blank nor a comment, and ask the real parser. To keep
// this from claiming unrelated pastes, a match additionally requires
// EITHER a recognised transport name OR a 40-hex fingerprint — a bare
// "host:port" alone is too weak a signal to outrank the parsers that
// run after this one.
func looksLikeTorBridges(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := ParseTorBridgeLine(line)
		if err != nil {
			return false
		}
		return b.Transport != "" || b.Fingerprint != ""
	}
	return false
}
