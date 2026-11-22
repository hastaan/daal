package uri

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
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

// ProfileFromClashEntry converts one flattened Clash/mihomo proxy entry
// (keys as they appear in the YAML, nested maps flattened, values
// unquoted) into a sing-box outbound. It is the one Clash mapping:
// core/refresh's subscription reader calls it too, so a Clash entry
// gets the same outbound and the same family whichever path read it.
//
// The rules are the URI parsers' (refuse.go): REALITY defaults to
// fp=chrome, plaintext VLESS/Trojan is refused, a network: the engine
// cannot carry is refused rather than dropped.
func ProfileFromClashEntry(e map[string]string) (Profile, error) {
	return profileFromClashEntry(e)
}

func profileFromClashEntry(e map[string]string) (Profile, error) {
	typ := e["type"]
	host := firstNonEmpty(e["server"], e["address"])
	port, err := strconv.Atoi(e["port"])
	if err != nil || port < 1 || port > 65535 || host == "" {
		return Profile{}, fmt.Errorf("clash: missing host/port: %w", ErrMalformed)
	}
	tag := firstNonEmpty(e["name"], e["ps"])
	switch typ {
	case "ss":
		if ssPlaintextMethod(e["cipher"]) {
			return Profile{}, fmt.Errorf("clash ss: cipher=none: %w", ErrPlaintext)
		}
		// plugin: obfs / v2ray-plugin / shadow-tls with plugin-opts is
		// not carried by this mapping; dropping it would dial bare
		// Shadowsocks at a server that expects the plugin's framing.
		if e["plugin"] != "" {
			return Profile{}, fmt.Errorf("clash ss: plugin: %w", ErrTransportUnsupported)
		}
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
		if e["public-key"] != "" || e["public_key"] != "" {
			return Profile{}, fmt.Errorf("clash: trojan reality: %w", ErrTransportUnsupported)
		}
		out := map[string]any{
			"type":        "trojan",
			"server":      host,
			"server_port": port,
			"password":    e["password"],
		}
		out["tls"] = clashTLS(e)
		if err := clashTransport("clash trojan", e, out, false); err != nil {
			return Profile{}, err
		}
		// "other", as for trojan:// links: a stranger's Trojan server
		// is not Daal's websocket-tls tier.
		return Profile{TransportFamily: "other", Outbound: out, Tag: tag}, nil
	case "vmess":
		// Same rules as vmess:// (vmess.go): tls, network and its opts
		// are carried or the entry is refused, and a cipher that
		// encrypts nothing is refused unless TLS wraps it.
		if e["public-key"] != "" || e["public_key"] != "" {
			return Profile{}, fmt.Errorf("clash vmess: reality: %w", ErrTransportUnsupported)
		}
		tlsOn := e["tls"] == "true"
		security, err := vmessSecurity("clash vmess", e["cipher"], tlsOn)
		if err != nil {
			return Profile{}, err
		}
		alterID, _ := strconv.Atoi(e["alterId"])
		out := map[string]any{
			"type":        "vmess",
			"server":      host,
			"server_port": port,
			"uuid":        e["uuid"],
			"alter_id":    alterID,
			"security":    security,
		}
		if tlsOn {
			out["tls"] = clashTLS(e)
		}
		if err := clashTransport("clash vmess", e, out, true); err != nil {
			return Profile{}, err
		}
		return Profile{TransportFamily: "other", Outbound: out, Tag: tag}, nil
	case "vless":
		out := map[string]any{
			"type":        "vless",
			"server":      host,
			"server_port": port,
			"uuid":        e["uuid"],
		}
		switch flow := e["flow"]; flow {
		case "":
		case "xtls-rprx-vision":
			out["flow"] = flow
		default:
			return Profile{}, fmt.Errorf("clash vless: flow=%s: %w", safeToken(flow), ErrFlowUnsupported)
		}
		if v := strings.TrimSpace(e["encryption"]); v != "" && v != "none" {
			return Profile{}, fmt.Errorf("clash vless: encryption: %w", ErrEncryptionUnsupported)
		}
		family := "other"
		pbk := firstNonEmpty(e["public-key"], e["public_key"])
		switch {
		case strings.EqualFold(e["network"], "reality") || pbk != "":
			family = "vless-reality"
			if k, err := base64.RawURLEncoding.DecodeString(pbk); err != nil || len(k) != 32 {
				return Profile{}, fmt.Errorf("clash vless: reality public key: %w", ErrMalformed)
			}
			tls := clashTLS(e)
			if _, has := tls["utls"]; !has {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			}
			reality := map[string]any{"enabled": true, "public_key": pbk}
			sid := firstNonEmpty(e["short-id"], e["short_id"])
			if err := checkRealityShortID("clash vless", sid); err != nil {
				return Profile{}, err
			}
			if sid != "" {
				reality["short_id"] = sid
			}
			tls["reality"] = reality
			out["tls"] = tls
		case e["tls"] == "true" || e["servername"] != "" || e["sni"] != "":
			out["tls"] = clashTLS(e)
		default:
			return Profile{}, fmt.Errorf("clash vless: no tls: %w", ErrPlaintext)
		}
		if err := clashTransport("clash vless", e, out, true); err != nil {
			return Profile{}, err
		}
		if err := checkVisionFlow("clash vless", out); err != nil {
			return Profile{}, err
		}
		return Profile{TransportFamily: family, Outbound: out, Tag: tag}, nil
	case "hysteria2":
		out := map[string]any{
			"type":        "hysteria2",
			"server":      host,
			"server_port": port,
			"password":    firstNonEmpty(e["password"], e["auth"]),
		}
		if ports := e["ports"]; ports != "" {
			ranges, err := parsePortSpec(ports)
			if err != nil {
				return Profile{}, err
			}
			out["server_ports"] = ranges
			hop, err := hopInterval(e["hop-interval"])
			if err != nil {
				return Profile{}, err
			}
			out["hop_interval"] = hop
		}
		tls := map[string]any{"enabled": true}
		if sni := e["sni"]; sni != "" {
			tls["server_name"] = sni
		}
		out["tls"] = tls
		if obfs := e["obfs"]; obfs != "" && obfs != "none" {
			o := map[string]any{"type": obfs}
			if pw := e["obfs-password"]; pw != "" {
				o["password"] = pw
			}
			out["obfs"] = o
		}
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
	return Profile{}, fmt.Errorf("clash: unsupported type %q", safeToken(typ))
}

// clashTLS is the tls block for a Clash vless/trojan/vmess entry: SNI,
// ALPN (inline "[h2, http/1.1]" or "h2,http/1.1") and
// client-fingerprint.
func clashTLS(e map[string]string) map[string]any {
	tls := map[string]any{"enabled": true}
	if sni := firstNonEmpty(e["servername"], e["sni"]); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := splitALPN(strings.Trim(e["alpn"], "[]")); len(alpn) > 0 {
		for i := range alpn {
			alpn[i] = strings.Trim(alpn[i], "\"'")
		}
		tls["alpn"] = alpn
	}
	if fp, ok := utlsFingerprint(e["client-fingerprint"]); ok {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return tls
}

// clashTransport maps Clash's network: (with ws-opts path/headers.Host
// and grpc-opts grpc-service-name flattened into the entry) through the
// same v2rayTransport the URI parsers use.
func clashTransport(scheme string, e map[string]string, out map[string]any, allowGRPC bool) error {
	network := e["network"]
	if strings.EqualFold(network, "reality") {
		network = ""
	}
	q := url.Values{}
	q.Set("type", network)
	q.Set("path", firstNonEmpty(e["path"], e["ws-path"])) // ws-path: pre-ws-opts Clash
	q.Set("host", firstNonEmpty(e["Host"], e["host"]))
	q.Set("serviceName", e["grpc-service-name"])
	t, err := v2rayTransport(scheme, q, allowGRPC)
	if err != nil {
		return err
	}
	if t != nil {
		out["transport"] = t
	}
	return nil
}

func firstNonEmpty(args ...string) string {
	for _, s := range args {
		if s != "" {
			return s
		}
	}
	return ""
}
