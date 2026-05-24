package uri

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
		return Profile{}, Provenance{}, fmt.Errorf("vmess: base64 decode: %w", err)
	}
	var link vmessLink
	if err := json.Unmarshal(dec, &link); err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("vmess: bad inner JSON: %w", err)
	}
	port, err := toInt(link.Port)
	if err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("vmess: invalid port: %w", err)
	}
	aid, _ := toInt(link.Aid)
	out := map[string]any{
		"type":        "vmess",
		"server":      link.Add,
		"server_port": port,
		"uuid":        link.ID,
		"alter_id":    aid,
	}
	if link.Scy != "" {
		out["security"] = link.Scy
	} else {
		out["security"] = "auto"
	}
	switch link.Net {
	case "ws":
		t := map[string]any{"type": "ws"}
		if link.Path != "" {
			t["path"] = link.Path
		}
		if link.Host != "" {
			t["headers"] = map[string]any{"Host": link.Host}
		}
		out["transport"] = t
	case "grpc":
		t := map[string]any{"type": "grpc"}
		if link.Path != "" {
			t["service_name"] = link.Path
		}
		out["transport"] = t
	}
	if link.TLS == "tls" {
		tls := map[string]any{"enabled": true}
		if link.SNI != "" {
			tls["server_name"] = link.SNI
		} else if link.Host != "" {
			tls["server_name"] = link.Host
		}
		if link.ALPN != "" {
			tls["alpn"] = strings.Split(link.ALPN, ",")
		}
		if link.Fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": link.Fp}
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
