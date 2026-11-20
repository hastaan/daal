package uri

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// vmess:// is base64-encoded JSON per the 2dust wiki.
type vmessLink struct {
	V     string      `json:"v"`
	PS    string      `json:"ps"`
	Add   string      `json:"add"`
	Port  any         `json:"port"`
	ID    string      `json:"id"`
	Aid   any         `json:"aid"`
	Scy   string      `json:"scy"`
	Net   string      `json:"net"`
	Type  string      `json:"type"`
	Host  string      `json:"host"`
	Path  string      `json:"path"`
	TLS   string      `json:"tls"`
	SNI   string      `json:"sni"`
	ALPN  string      `json:"alpn"`
	Fp    string      `json:"fp"`
	Extra interface{} `json:"-"`
}

func parseVMess(raw string) (Profile, Provenance, error) {
	body := strings.TrimPrefix(raw, "vmess://")
	dec, err := base64Decode(body)
	if err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("vmess: base64 decode: %w", ErrMalformed)
	}
	var link vmessLink
	if err := json.Unmarshal(dec, &link); err != nil {
		// json's error text can quote a fragment of the body (the uuid).
		return Profile{}, Provenance{}, fmt.Errorf("vmess: bad inner JSON: %w", ErrMalformed)
	}
	port, err := toInt(link.Port)
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, Provenance{}, fmt.Errorf("vmess: invalid port: %w", ErrMalformed)
	}
	var tlsOn bool
	switch strings.ToLower(strings.TrimSpace(link.TLS)) {
	case "", "none":
	case "tls":
		tlsOn = true
	default:
		// "reality" and anything else: not a VMess shape sing-box has.
		return Profile{}, Provenance{}, fmt.Errorf("vmess: tls=%s: %w", safeToken(strings.ToLower(link.TLS)), ErrTransportUnsupported)
	}
	// none/zero encrypt nothing: without TLS the payload crosses the
	// DPI box in clear (refuse.go vmessSecurity).
	security, err := vmessSecurity("vmess", link.Scy, tlsOn)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	aid, _ := toInt(link.Aid)
	out := map[string]any{
		"type":        "vmess",
		"server":      link.Add,
		"server_port": port,
		"uuid":        link.ID,
		"alter_id":    aid,
		"security":    security,
	}
	// The transport goes through the same v2rayTransport as vless:// and
	// trojan://, so an xhttp/h2/kcp vmess link is refused instead of
	// silently becoming plain TCP. In the 2dust format `type` is the
	// header type and a gRPC service name rides in `path`.
	q := url.Values{}
	q.Set("type", link.Net)
	q.Set("headerType", link.Type)
	q.Set("path", link.Path)
	q.Set("host", link.Host)
	q.Set("serviceName", link.Path)
	transport, err := v2rayTransport("vmess", q, true)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	if tlsOn {
		tls := map[string]any{"enabled": true}
		if link.SNI != "" {
			tls["server_name"] = link.SNI
		} else if link.Host != "" {
			tls["server_name"] = link.Host
		}
		if alpn := splitALPN(link.ALPN); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		if fp, ok := utlsFingerprint(link.Fp); ok {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		out["tls"] = tls
	}
	return Profile{
		TransportFamily: "other",
		Outbound:        out,
		Tag:             link.PS,
	}, Provenance{Scheme: "vmess"}, nil
}

func toInt(v any) (int, error) {
	switch x := v.(type) {
	case float64:
		return int(x), nil
	case string:
		return strconv.Atoi(x)
	case int:
		return x, nil
	case nil:
		return 0, nil
	}
	return 0, fmt.Errorf("not a number: %T", v)
}

// base64Decode accepts both standard and URL-safe encodings, with or
// without padding.
func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(s); err == nil {
			return dec, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}
