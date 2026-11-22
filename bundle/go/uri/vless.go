package uri

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// parseVLESS handles vless://uuid@host:port?params#name including the
// REALITY flow (pbk/sid + flow=xtls-rprx-vision).
//
// Every field it writes must survive sing-box 1.13.12's strict option
// decoder (DisallowUnknownFields, option/options.go), and every link it
// cannot carry faithfully is refused with a named error (refuse.go)
// rather than imported weaker. What changed and why:
//
//   - spx (REALITY spiderX) is dropped. OutboundRealityOptions has
//     only enabled/public_key/short_id; writing spider_x made the
//     engine reject the whole config. spiderX is a client-side crawl
//     path the server never checks, so dropping it changes nothing on
//     the wire that matters.
//   - REALITY without fp= gets fp=chrome. sing-box's REALITY client
//     refuses to start without uTLS (common/tls/reality_client.go).
//   - encryption= is never written (VLESSOutboundOptions has no such
//     field). "none" is the only value sing-box speaks; anything else
//     is Xray's VLESS encryption and is refused.
//   - alpn= is split on commas.
//   - type= goes through v2rayTransport: ws (with ?ed= early data),
//     httpupgrade, grpc, raw TCP; xhttp/splithttp/h2/anything else is
//     refused instead of silently becoming plain TCP.
//   - security=none (or absent) is refused: plaintext VLESS shows the
//     DPI box every destination.
func parseVLESS(raw string) (Profile, Provenance, error) {
	u, err := parseLink("vless", raw)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, Provenance{}, fmt.Errorf("vless: missing uuid: %w", ErrMalformed)
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, Provenance{}, fmt.Errorf("vless: invalid port: %w", ErrMalformed)
	}
	q := u.Query()
	out := map[string]any{
		"type":        "vless",
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	switch flow := q.Get("flow"); flow {
	case "":
	case "xtls-rprx-vision":
		out["flow"] = flow
	default:
		// xtls-rprx-vision-udp443 included: sing-vmess accepts only
		// "" and xtls-rprx-vision (vless/client.go).
		return Profile{}, Provenance{}, fmt.Errorf("vless: flow=%s: %w", safeToken(flow), ErrFlowUnsupported)
	}
	if v := strings.TrimSpace(q.Get("encryption")); v != "" && v != "none" {
		return Profile{}, Provenance{}, fmt.Errorf("vless: encryption: %w", ErrEncryptionUnsupported)
	}

	transport, err := v2rayTransport("vless", q, true)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	if err := checkVisionFlow("vless", out); err != nil {
		return Profile{}, Provenance{}, err
	}

	// TLS / REALITY.
	prov := Provenance{Scheme: "vless"}
	security := strings.ToLower(q.Get("security"))
	switch security {
	case "tls":
		tls := map[string]any{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		}
		if alpn := splitALPN(q.Get("alpn")); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		if fp, ok := utlsFingerprint(q.Get("fp")); ok {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		out["tls"] = tls
	case "reality":
		prov.HadReality = true
		pbk := q.Get("pbk")
		if k, err := base64.RawURLEncoding.DecodeString(pbk); err != nil || len(k) != 32 {
			return Profile{}, Provenance{}, fmt.Errorf("vless: reality public key: %w", ErrMalformed)
		}
		sid := q.Get("sid")
		if err := checkRealityShortID("vless", sid); err != nil {
			return Profile{}, Provenance{}, err
		}
		tls := map[string]any{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		}
		fp, ok := utlsFingerprint(q.Get("fp"))
		if !ok {
			fp = "chrome"
		}
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		reality := map[string]any{"enabled": true, "public_key": pbk}
		if sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
		out["tls"] = tls
	case "", "none":
		return Profile{}, Provenance{}, fmt.Errorf("vless: security=none: %w", ErrPlaintext)
	default:
		// xtls (pre-2023 Xray) and anything newer.
		return Profile{}, Provenance{}, fmt.Errorf("vless: security=%s: %w", safeToken(security), ErrTransportUnsupported)
	}

	return Profile{
		TransportFamily: pickVLESSFamily(security),
		Outbound:        out,
		Tag:             u.Fragment,
	}, prov, nil
}

func pickVLESSFamily(security string) string {
	if security == "reality" {
		return "vless-reality"
	}
	return "other"
}
