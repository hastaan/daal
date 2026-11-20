package uri

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// amneziaFields are the AmneziaWG-only [Interface] knobs. Their
// presence is what distinguishes an AmneziaWG conf from a wg-quick one
// — and, as of sing-box 1.13.12, nothing about them can be honoured.
// See parseWireGuard.
//
//   - 1.x: junk-packet count and sizes (Jc/Jmin/Jmax), the
//     init/response paddings (S1/S2) and the magic-header rewrites
//     (H1..H4).
//   - 2.0: cookie/transport paddings (S3/S4), the signature packets
//     I1..I5, the controlled-junk packets J1..J3 and their timer ITIME
//     (research/protocol-level-anatomy.md:79).
//
// Matching is case-insensitive: AmneziaVPN writes "Jc", some exporters
// "JC" or "Itime".
var amneziaFields = []string{
	"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4",
	"S3", "S4", "I1", "I2", "I3", "I4", "I5", "J1", "J2", "J3", "ITIME",
}

// amneziaJunkOnly are the fields a plain WireGuard server never sees
// the effect of: junk packets sent BEFORE the handshake, which the
// server drops as garbage. A conf whose only AmneziaWG fields are these
// still speaks the WireGuard handshake byte for byte, so it can be
// downgraded honestly ("backward compatibility holds if only
// Jc/Jmin/Jmax are set", research/protocol-level-anatomy.md:79).
var amneziaJunkOnly = map[string]bool{"Jc": true, "Jmin": true, "Jmax": true}

// amneziaNeutral is the value at which a header/padding field changes
// nothing on the wire: S1..S4 = 0 adds no padding, and H1..H4 = 1..4
// ARE WireGuard's own message types. amneziawg-go uses exactly these as
// its defaults, and AmneziaVPN exports them explicitly.
var amneziaNeutral = map[string]string{
	"S1": "0", "S2": "0", "S3": "0", "S4": "0",
	"H1": "1", "H2": "2", "H3": "3", "H4": "4",
}

// amneziaWireCompatible reports whether a server configured with these
// AmneziaWG fields would still accept a plain WireGuard handshake.
// True only when every field set is junk-only or at its neutral value.
// Any non-neutral S/H value changes the packet a server accepts, and
// I1..I5/J1..J3/ITIME are treated as incompatible because nothing here
// has verified that a 2.0 server accepts a peer that never sends them.
func amneziaWireCompatible(set map[string]string) bool {
	for k, v := range set {
		if amneziaJunkOnly[k] {
			continue
		}
		if n, ok := amneziaNeutral[k]; ok && strings.TrimSpace(v) == n {
			continue
		}
		return false
	}
	return true
}

// parseWireGuard parses a wg-quick-style .conf, including AmneziaWG's
// Iran-flavoured extensions, into a sing-box WireGuard ENDPOINT.
//
// # What changed, and why the previous shape could never dial
//
// This used to emit `{"type":"wireguard", "server":…, "server_port":…,
// "private_key":…, "peer_public_key":…, "local_address":[…]}` as an
// OUTBOUND, and `{"type":"amnezia-wg", …}` when Amnezia fields were
// present. Verified against the shipped engine (sing-box 1.13.12), both
// were dead on arrival:
//
//   - There is no WireGuard outbound any more. include/registry.go
//     registers C.TypeWireGuard through registerStubForRemovedOutbounds,
//     whose entire body returns "WireGuard outbound is deprecated in
//     sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard
//     endpoint instead". The config still PARSES, which is why nothing
//     caught this earlier; the route dies at dial.
//   - "amnezia-wg" is not a registered type of any kind — `grep -ri
//     amnezia` over sing-box 1.13.12 returns nothing at all — so that
//     branch produced "unknown outbound type" at parse time.
//   - The field names were from the 1.x outbound schema.
//     option.WireGuardEndpointOptions has `address` (not
//     `local_address`), and the remote peer lives in `peers[]` with
//     `address`/`port`/`public_key`/`allowed_ips`, not in flat
//     `server`/`server_port`/`peer_public_key` keys.
//   - `AllowedIPs` was written into `reserved`. `reserved` is the
//     three-byte WARP header field (option.WireGuardPeer.Reserved
//     []uint8); allowed-IPs are a routing table. Putting one in the
//     other is not a naming quibble, it is a different wire field.
//
// # AmneziaWG DEGRADES TO PLAIN WIREGUARD, and that is not a footnote
//
// sing-box 1.13.12 has no AmneziaWG support whatsoever, so there is
// nowhere to put Jc/Jmin/Jmax/S1/S2/H1..H4. The obfuscation those knobs
// provide IS the reason AmneziaWG works where WireGuard does not: the
// corpus rates it the most resilient thing measured in Iran during the
// June 2025 blackout, and it works in China too. Strip them and what is
// left is a WireGuard handshake — which the adversary document names as
// an explicit, immediate-block target, over UDP, which the same
// document states the intent to block completely and permanently.
//
// So the import does not pretend, and what it does depends on whether
// a WireGuard handshake would still be ACCEPTED by the server
// (amneziaWireCompatible):
//
//   - Junk-only (Jc/Jmin/Jmax, with any S/H field at its neutral
//     value): the server accepts WireGuard, so the route is imported as
//     "wireguard" — never "amneziawg", because WireGuard is what goes
//     on the wire and the badge, the maturity label and the selector
//     all key off the family. Notice = NoticeAmneziaDowngraded.
//   - Anything else (non-neutral S1..S4 / H1..H4, or any 2.0 field):
//     the server discards a WireGuard initiation, so the downgraded
//     route could never connect anywhere. It is imported under the
//     "amneziawg" family, which this build labels unsupported and
//     never offers. Notice = NoticeAmneziaUnsupported.
//   - Either way Provenance.Scheme is "amneziawg", HadAmnezia is true,
//     DroppedParams names the fields and Downgrade carries a sentence
//     an importer can show verbatim.
//
// KNOWN AND STATED: nothing in this repository currently CALLS
// ParseAny, so the Downgrade text has no UI to reach yet — ParseURI
// (share.go, refresh/parse.go) handles single-line URI schemes only and
// a wg-quick conf is not one. The parser is correct and provable; the
// import surface that shows the warning is not built here. Do not read
// "AmneziaWG imports cleanly" into this.
func parseWireGuard(body []byte) (Profile, Provenance, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	section := ""
	iface := map[string]string{}
	peer := map[string]string{}
	prov := Provenance{Scheme: "wireguard"}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		switch section {
		case "interface":
			iface[k] = v
		case "peer":
			peer[k] = v
		}
	}
	if iface["PrivateKey"] == "" || peer["PublicKey"] == "" || peer["Endpoint"] == "" {
		return Profile{}, prov, fmt.Errorf("wireguard: missing required fields")
	}
	host, port, err := splitEndpoint(peer["Endpoint"])
	if err != nil {
		return Profile{}, prov, err
	}
	// `[2001:db8::1]:51820` — strip the brackets wg-quick requires and
	// sing-box does not: option.WireGuardPeer.Address is a bare host or
	// address string handed to M.ParseSocksaddrHostPort alongside Port.
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if port < 1 || port > 65535 {
		return Profile{}, prov, fmt.Errorf("wireguard: endpoint port %d out of range", port)
	}

	// `address` is REQUIRED by option.WireGuardEndpointOptions (no
	// omitempty) and is a list of PREFIXES. wg-quick's Address is
	// normally already `10.0.0.2/32`, but a bare address is common in
	// hand-written confs and netip.Prefix will not parse one, so widen
	// it to a host route rather than emitting a config sing-box rejects.
	addrs, err := prefixList(iface["Address"])
	if err != nil {
		return Profile{}, prov, fmt.Errorf("wireguard: Address: %w", err)
	}
	if len(addrs) == 0 {
		return Profile{}, prov, fmt.Errorf("wireguard: missing Address (sing-box requires the endpoint's local address)")
	}

	peerObj := map[string]any{
		"address":    host,
		"port":       port,
		"public_key": peer["PublicKey"],
	}
	if v := peer["PresharedKey"]; v != "" {
		peerObj["pre_shared_key"] = v
	}
	// AllowedIPs is the peer's routing table, and it belongs in
	// `allowed_ips` — NOT in `reserved`, which is the three-byte WARP
	// header. An endpoint with no allowed_ips carries no traffic, so a
	// conf that omits it (unusual, but legal) gets the default-route
	// pair a tunnel-everything client would have written.
	allowed, err := prefixList(peer["AllowedIPs"])
	if err != nil {
		return Profile{}, prov, fmt.Errorf("wireguard: AllowedIPs: %w", err)
	}
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	peerObj["allowed_ips"] = allowed
	if v := peer["PersistentKeepalive"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			peerObj["persistent_keepalive_interval"] = n
		}
	}

	out := map[string]any{
		"type":        "wireguard",
		"address":     addrs,
		"private_key": iface["PrivateKey"],
		"peers":       []any{peerObj},
	}
	if v := iface["MTU"]; v != "" {
		if mtu, err := strconv.Atoi(v); err == nil && mtu > 0 {
			out["mtu"] = mtu
		}
	}
	// [Interface] DNS is deliberately dropped: sing-box resolves through
	// its own dns block, and WireGuardEndpointOptions has no field for
	// it. Silently keeping it would mean inventing one.

	set := map[string]string{}
	for k, v := range iface {
		if canon := amneziaField(k); canon != "" && strings.TrimSpace(v) != "" {
			set[canon] = v
		}
	}
	family := "wireguard"
	if len(set) > 0 {
		dropped := make([]string, 0, len(set))
		for k := range set {
			dropped = append(dropped, k)
		}
		sort.Strings(dropped)
		prov.HadAmnezia = true
		prov.Scheme = "amneziawg"
		prov.DroppedParams = dropped
		prov.WarningCount++
		if amneziaWireCompatible(set) {
			// Junk packets only: the handshake is WireGuard's, so the
			// route connects wherever WireGuard is allowed — and only
			// there. AUTO-CONNECT MUST NOT RACE IT: an attempt sends the
			// exact WireGuard handshake Iran's operators throttle and
			// then block within minutes, from the person's SIM-linked
			// address. Nothing in this build can mark one route
			// "connect only when the person picks it"; today the only
			// thing keeping it out of automatic connects is that
			// `wireguard` is experimental (off unless the person turns
			// experimental routes on). See NoticeAmneziaDowngraded.
			prov.Notice = NoticeAmneziaDowngraded
			prov.Downgrade = "This is an AmneziaWG configuration. The engine in this build " +
				"(sing-box 1.13.12) has no AmneziaWG support, so its junk-packet parameters (" +
				strings.Join(dropped, ", ") + ") were dropped and the route was imported as plain " +
				"WireGuard. It will still connect where WireGuard is allowed. It will NOT survive a " +
				"network that blocks WireGuard-shaped traffic — which is what AmneziaWG exists to " +
				"defeat, and what Iran's operators block on sight."
		} else {
			// The server expects a different packet than WireGuard's
			// (non-default H1..H4 or S1..S4, or 2.0 signature/junk
			// packets): a WireGuard handshake is discarded and the route
			// can never connect anywhere. Import it under its real,
			// unsupported family so the person sees it and sees that
			// this build cannot dial it. The endpoint below stays a
			// strictly valid sing-box object so the store and the
			// engine's parse never choke on it; the FAMILY is what keeps
			// it from being offered.
			family = "amneziawg"
			prov.Notice = NoticeAmneziaUnsupported
			prov.Downgrade = "This is an AmneziaWG configuration whose settings (" +
				strings.Join(dropped, ", ") + ") change the WireGuard handshake. The engine in this " +
				"build (sing-box 1.13.12) has no AmneziaWG support and a server with these settings " +
				"ignores plain WireGuard, so the route was saved but cannot connect."
		}
	}

	return Profile{
		// "wireguard" for plain and junk-only AmneziaWG confs: the family
		// names what is on the wire, and what is on the wire is
		// WireGuard. "amneziawg" (unsupported, unselectable) when no
		// WireGuard handshake would be accepted.
		TransportFamily: family,
		Outbound:        out,
		Tag:             "",
	}, prov, nil
}

// amneziaField returns the canonical spelling of an AmneziaWG
// [Interface] key, or "" when k is not one.
func amneziaField(k string) string {
	for _, f := range amneziaFields {
		if strings.EqualFold(k, f) {
			return f
		}
	}
	return ""
}

// prefixList parses a comma-separated wg-quick address/allowed-ips list
// into CIDR strings sing-box's netip.Prefix decoder accepts. A bare
// address is widened to its host route (/32 or /128) — wg-quick tolerates
// it and netip.Prefix does not.
func prefixList(s string) ([]string, error) {
	parts := splitCSV(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.Contains(p, "/") {
			if _, err := netip.ParsePrefix(p); err != nil {
				return nil, fmt.Errorf("%q: %w", p, err)
			}
			out = append(out, p)
			continue
		}
		addr, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		out = append(out, fmt.Sprintf("%s/%d", addr.String(), addr.BitLen()))
	}
	return out, nil
}

func splitEndpoint(s string) (string, int, error) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("wireguard: bad endpoint %q", s)
	}
	host := s[:idx]
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, fmt.Errorf("wireguard: bad endpoint port: %w", err)
	}
	return host, port, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
