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

// amneziaFields are the AmneziaWG-only [Interface] knobs: junk-packet
// counts and sizes (Jc/Jmin/Jmax), the magic-header rewrites (H1..H4)
// and the init/response packet paddings (S1/S2). Their presence is what
// distinguishes an AmneziaWG conf from a wg-quick one — and, as of
// sing-box 1.13.12, nothing else about them can be honoured. See
// parseWireGuard.
var amneziaFields = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"}

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
// So the import does not fail, and it does not pretend either:
//
//   - The route's family is "wireguard", never "amneziawg", because
//     WireGuard is what goes on the wire. The badge, the maturity label
//     and the selector all key off the family; calling this amneziawg
//     would promise the user resilience this build cannot deliver.
//   - Provenance.Scheme stays "amneziawg" and HadAmnezia stays true, so
//     nothing loses the fact that an AmneziaWG conf was what arrived.
//   - Provenance.Downgrade carries a sentence an importer can show
//     verbatim, and DroppedParams names the fields, so "why did my
//     Amnezia config become WireGuard" has an answer at the point of
//     import.
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

	dropped := []string{}
	for _, k := range amneziaFields {
		if v, ok := iface[k]; ok && strings.TrimSpace(v) != "" {
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		sort.Strings(dropped)
		prov.HadAmnezia = true
		prov.Scheme = "amneziawg"
		prov.DroppedParams = dropped
		prov.Downgrade = "This is an AmneziaWG configuration. The engine in this build " +
			"(sing-box 1.13.12) has no AmneziaWG support, so its obfuscation parameters (" +
			strings.Join(dropped, ", ") + ") were dropped and the route was imported as plain " +
			"WireGuard. It will still connect where WireGuard is allowed. It will NOT survive a " +
			"network that blocks WireGuard-shaped traffic — which is what AmneziaWG exists to " +
			"defeat, and what Iran's operators block on sight."
		prov.WarningCount++
	}

	return Profile{
		// "wireguard", even for an AmneziaWG conf: the family names what
		// is on the wire, and what is on the wire is WireGuard.
		TransportFamily: "wireguard",
		Outbound:        out,
		Tag:             "",
	}, prov, nil
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
