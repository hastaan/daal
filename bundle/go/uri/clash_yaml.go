package uri

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// parseClashYAML implements a *minimal* hand-rolled YAML reader for Clash
// proxy lists. We deliberately avoid pulling in a full YAML dependency:
// the surface we need is the well-known Clash proxy block. Lines outside
// the proxies: section are ignored.
//
// Supported proxy types: ss, vmess, trojan, vless, hysteria2, tuic.
func parseClashYAML(body []byte) ([]Profile, Provenance, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	inProxies := false
	prov := Provenance{Scheme: "clash"}
	var profiles []Profile
	var current map[string]string
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimRight(raw, " \t")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "proxies:") {
			inProxies = true
			continue
		}
		if !inProxies {
			continue
		}
		// New section: end proxies.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") && strings.Contains(line, ":") {
			inProxies = false
			if current != nil {
				if p, err := profileFromClashEntry(current); err == nil {
					profiles = append(profiles, p)
				} else {
					prov.WarningCount++
				}
				current = nil
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "- ") {
			// Flush previous proxy.
			if current != nil {
				if p, err := profileFromClashEntry(current); err == nil {
					profiles = append(profiles, p)
				} else {
					prov.WarningCount++
				}
			}
			current = map[string]string{}
			rest := strings.TrimSpace(line)[2:]
			if k, v, ok := splitYAMLKV(rest); ok {
				current[k] = v
			}
			continue
		}
		// Continuation line within current proxy.
		t := strings.TrimSpace(line)
		if k, v, ok := splitYAMLKV(t); ok && current != nil {
			current[k] = v
		}
	}
	if current != nil {
		if p, err := profileFromClashEntry(current); err == nil {
			profiles = append(profiles, p)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, prov, err
	}
	if len(profiles) == 0 {
		return nil, prov, ErrNoMatch
	}
	return profiles, prov, nil
}

func splitYAMLKV(s string) (string, string, bool) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", false
	}
	k := strings.TrimSpace(s[:idx])
	v := strings.TrimSpace(s[idx+1:])
	v = strings.Trim(v, "\"'")
	return k, v, true
}

func profileFromClashEntry(e map[string]string) (Profile, error) {
	typ := e["type"]
	host := firstNonEmpty(e["server"], e["address"])
	port, err := strconv.Atoi(e["port"])
	if err != nil || port == 0 || host == "" {
		return Profile{}, fmt.Errorf("clash: missing host/port")
	}
	tag := firstNonEmpty(e["name"], e["ps"])
	switch typ {
	case "ss":
		return Profile{
			TransportFamily: "shadowsocks",
			Outbound: map[string]any{
				"type":        "shadowsocks",
				"server":      host,
				"server_port": port,
				"method":      e["cipher"],
				"password":    e["password"],
			},
			Tag: tag,
		}, nil
	case "trojan":
		out := map[string]any{
			"type":        "trojan",
			"server":      host,
			"server_port": port,
			"password":    e["password"],
		}
		tls := map[string]any{"enabled": true}
		if sni := e["sni"]; sni != "" {
			tls["server_name"] = sni
		}
		out["tls"] = tls
		return Profile{TransportFamily: "other", Outbound: out, Tag: tag}, nil
	case "vmess":
		alterID, _ := strconv.Atoi(e["alterId"])
		out := map[string]any{
			"type":        "vmess",
			"server":      host,
			"server_port": port,
			"uuid":        e["uuid"],
			"alter_id":    alterID,
			"security":    firstNonEmpty(e["cipher"], "auto"),
		}
		return Profile{TransportFamily: "other", Outbound: out, Tag: tag}, nil
	case "vless":
		out := map[string]any{
			"type":        "vless",
			"server":      host,
			"server_port": port,
			"uuid":        e["uuid"],
		}
		if e["flow"] != "" {
			out["flow"] = e["flow"]
		}
		family := "other"
		if e["servername"] != "" || e["sni"] != "" {
			tls := map[string]any{"enabled": true, "server_name": firstNonEmpty(e["servername"], e["sni"])}
			out["tls"] = tls
		}
		if strings.EqualFold(e["network"], "reality") || e["public-key"] != "" || e["public_key"] != "" {
			family = "vless-reality"
			tls, _ := out["tls"].(map[string]any)
			if tls == nil {
				tls = map[string]any{"enabled": true}
				out["tls"] = tls
			}
			tls["reality"] = map[string]any{
				"enabled":    true,
				"public_key": firstNonEmpty(e["public-key"], e["public_key"]),
				"short_id":   firstNonEmpty(e["short-id"], e["short_id"]),
			}
		}
		return Profile{TransportFamily: family, Outbound: out, Tag: tag}, nil
	case "hysteria2":
		out := map[string]any{
			"type":        "hysteria2",
			"server":      host,
			"server_port": port,
			"password":    firstNonEmpty(e["password"], e["auth"]),
		}
		tls := map[string]any{"enabled": true}
		if sni := e["sni"]; sni != "" {
			tls["server_name"] = sni
		}
		out["tls"] = tls
		return Profile{TransportFamily: "hysteria2", Outbound: out, Tag: tag}, nil
	case "tuic":
		out := map[string]any{
			"type":        "tuic",
			"server":      host,
			"server_port": port,
			"uuid":        e["uuid"],
			"password":    e["password"],
		}
		if e["congestion-controller"] != "" {
			out["congestion_control"] = e["congestion-controller"]
		}
		tls := map[string]any{"enabled": true}
		if sni := e["sni"]; sni != "" {
			tls["server_name"] = sni
		}
		out["tls"] = tls
		return Profile{TransportFamily: "tuic", Outbound: out, Tag: tag}, nil
	}
	return Profile{}, fmt.Errorf("clash: unsupported type %q", typ)
}

func firstNonEmpty(args ...string) string {
	for _, s := range args {
		if s != "" {
			return s
		}
	}
	return ""
}
