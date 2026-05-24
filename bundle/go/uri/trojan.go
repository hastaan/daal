package uri

import (
	"fmt"
	"net/url"
	"strconv"
)

func parseTrojan(raw string) (Profile, Provenance, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("trojan: bad URL: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, Provenance{}, fmt.Errorf("trojan: missing password")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port == 0 {
		return Profile{}, Provenance{}, fmt.Errorf("trojan: invalid port")
	}
	q := u.Query()
	out := map[string]any{
		"type":        "trojan",
		"server":      u.Hostname(),
		"server_port": port,
		"password":    u.User.Username(),
	}
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = []string{alpn}
	}
	out["tls"] = tls
	if q.Get("type") == "ws" {
		t := map[string]any{"type": "ws"}
		if path := q.Get("path"); path != "" {
			t["path"] = path
		}
		if host := q.Get("host"); host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		out["transport"] = t
	}
	return Profile{
		TransportFamily: "other",
		Outbound:        out,
		Tag:             u.Fragment,
	}, Provenance{Scheme: "trojan"}, nil
}
