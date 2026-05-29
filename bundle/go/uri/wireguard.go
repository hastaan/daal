package uri

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// parseWireGuard parses a wg-quick-style .conf, including AmneziaWG's
// Iran-flavored extensions (Jc/Jmin/Jmax/H1..H4). The result is a sing-box
// outbound; family is "amneziawg" if any Amnezia field appears, else
// "wireguard".
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
	out := map[string]any{
		"type":            "wireguard",
		"server":          host,
		"server_port":     port,
		"private_key":     iface["PrivateKey"],
		"peer_public_key": peer["PublicKey"],
	}
	if v := iface["Address"]; v != "" {
		out["local_address"] = splitCSV(v)
	}
	if v := iface["MTU"]; v != "" {
		if mtu, err := strconv.Atoi(v); err == nil {
			out["mtu"] = mtu
		}
	}
	if v := peer["PresharedKey"]; v != "" {
		out["pre_shared_key"] = v
	}
	if v := peer["AllowedIPs"]; v != "" {
		out["reserved"] = splitCSV(v) // sing-box uses this for routing hints
	}
	// AmneziaWG extensions.
	family := "wireguard"
	amnezia := map[string]any{}
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"} {
		if v, ok := iface[k]; ok && v != "" {
			n, err := strconv.Atoi(v)
			if err == nil {
				amnezia[strings.ToLower(k)] = n
			}
		}
	}
	if len(amnezia) > 0 {
		out["amnezia"] = amnezia
		prov.HadAmnezia = true
		prov.Scheme = "amneziawg"
		family = "amneziawg"
		out["type"] = "amnezia-wg"
	}
	return Profile{
		TransportFamily: family,
		Outbound:        out,
		Tag:             "",
	}, prov, nil
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
