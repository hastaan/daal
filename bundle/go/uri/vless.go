package uri

import (
	"fmt"
	"net/url"
	"strconv"
)

// parseVLESS handles vless://uuid@host:port?params#name including the
// Reality flow (pbk/sid/spx + flow=xtls-rprx-vision).
func parseVLESS(raw string) (Profile, Provenance, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("vless: bad URL: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, Provenance{}, fmt.Errorf("vless: missing uuid")
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil || port == 0 {
		return Profile{}, Provenance{}, fmt.Errorf("vless: invalid port")
	}
	q := u.Query()
	out := map[string]any{
		"type":        "vless",
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	if v := q.Get("flow"); v != "" {
		out["flow"] = v
	}
	if v := q.Get("encryption"); v != "" && v != "none" {
		out["encryption"] = v
	}

	// Transport.
	switch q.Get("type") {
	case "ws":
		t := map[string]any{"type": "ws"}
		if path := q.Get("path"); path != "" {
			t["path"] = path
		}
		if hostHdr := q.Get("host"); hostHdr != "" {
			t["headers"] = map[string]any{"Host": hostHdr}
		}
		out["transport"] = t
	case "grpc":
		t := map[string]any{"type": "grpc"}
		if v := q.Get("serviceName"); v != "" {
			t["service_name"] = v
		}
		out["transport"] = t
	}

	// TLS / Reality.
	prov := Provenance{Scheme: "vless"}
	security := q.Get("security")
	switch security {
	case "tls":
		tls := map[string]any{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = []string{alpn}
		}
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		out["tls"] = tls
	case "reality":
		prov.HadReality = true
		tls := map[string]any{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		reality := map[string]any{"enabled": true}
		if pbk := q.Get("pbk"); pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			reality["short_id"] = sid
		}
		if spx := q.Get("spx"); spx != "" {
			reality["spider_x"] = spx
		}
		tls["reality"] = reality
		out["tls"] = tls
	}

	tag := u.Fragment
	return Profile{
		TransportFamily: pickVLESSFamily(security),
		Outbound:        out,
		Tag:             tag,
	}, prov, nil
}

func pickVLESSFamily(security string) string {
	if security == "reality" {
		return "vless-reality"
	}
	return "other"
}
