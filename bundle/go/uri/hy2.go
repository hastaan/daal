package uri

import (
	"fmt"
	"net/url"
	"strconv"
)

// parseHy2 handles both hysteria2:// and hy2:// per apernet's URI scheme.
func parseHy2(raw string) (Profile, Provenance, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("hy2: bad URL: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, Provenance{}, fmt.Errorf("hy2: missing auth")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port == 0 {
		return Profile{}, Provenance{}, fmt.Errorf("hy2: invalid port")
	}
	q := u.Query()
	out := map[string]any{
		"type":        "hysteria2",
		"server":      u.Hostname(),
		"server_port": port,
		"password":    u.User.Username(),
	}
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	if v := q.Get("insecure"); v == "1" || v == "true" {
		tls["insecure"] = true
	}
	out["tls"] = tls
	if obfs := q.Get("obfs"); obfs != "" {
		o := map[string]any{"type": obfs}
		if pw := q.Get("obfs-password"); pw != "" {
			o["password"] = pw
		}
		out["obfs"] = o
	}
	return Profile{
		TransportFamily: "hysteria2",
		Outbound:        out,
		Tag:             u.Fragment,
	}, Provenance{Scheme: "hy2"}, nil
}
