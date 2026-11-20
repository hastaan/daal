package uri

import (
	"fmt"
	"strconv"
)

// parseTUIC handles tuic://uuid:password@host:port?params#name per
// sing-box's convention.
func parseTUIC(raw string) (Profile, Provenance, error) {
	// parseLink, not url.Parse: url.Error quotes the whole link, and
	// its userinfo is the route's uuid and password.
	u, err := parseLink("tuic", raw)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if u.User == nil {
		return Profile{}, Provenance{}, fmt.Errorf("tuic: missing userinfo: %w", ErrMalformed)
	}
	uuid := u.User.Username()
	pwd, _ := u.User.Password()
	if uuid == "" {
		return Profile{}, Provenance{}, fmt.Errorf("tuic: missing uuid: %w", ErrMalformed)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, Provenance{}, fmt.Errorf("tuic: invalid port: %w", ErrMalformed)
	}
	q := u.Query()
	out := map[string]any{
		"type":        "tuic",
		"server":      u.Hostname(),
		"server_port": port,
		"uuid":        uuid,
		"password":    pwd,
	}
	if cc := q.Get("congestion_control"); cc != "" {
		out["congestion_control"] = cc
	}
	if v := q.Get("udp_relay_mode"); v != "" {
		out["udp_relay_mode"] = v
	}
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = splitALPN(alpn)
	}
	out["tls"] = tls
	return Profile{
		TransportFamily: "tuic",
		Outbound:        out,
		Tag:             u.Fragment,
	}, Provenance{Scheme: "tuic"}, nil
}
