package uri

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseSS handles SIP002 ss://method:password@host:port#name AND the
// SIP022 AEAD-2022 variant ss://2022-blake3-aes-128-gcm:psk@host:port.
//
// We also handle the legacy form ss://base64(method:password)@host:port.
func parseSS(raw string) (Profile, Provenance, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Profile{}, Provenance{}, fmt.Errorf("ss: bad URL: %w", err)
	}
	host := u.Hostname()
	port, perr := strconv.Atoi(u.Port())
	if perr != nil || port == 0 {
		return Profile{}, Provenance{}, fmt.Errorf("ss: invalid port")
	}

	var method, password string
	if u.User != nil {
		if pwd, ok := u.User.Password(); ok {
			method = u.User.Username()
			password = pwd
		} else {
			// Legacy: base64(method:password)
			dec, err := base64Decode(u.User.Username())
			if err != nil {
				return Profile{}, Provenance{}, fmt.Errorf("ss: base64 userinfo: %w", err)
			}
			parts := strings.SplitN(string(dec), ":", 2)
			if len(parts) != 2 {
				return Profile{}, Provenance{}, fmt.Errorf("ss: malformed userinfo")
			}
			method = parts[0]
			password = parts[1]
		}
	}
	if method == "" || password == "" {
		return Profile{}, Provenance{}, fmt.Errorf("ss: missing method/password")
	}

	out := map[string]any{
		"type":        "shadowsocks",
		"server":      host,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	q := u.Query()
	if plug := q.Get("plugin"); plug != "" {
		// e.g. "v2ray-plugin;mode=websocket;tls;host=x"
		out["plugin"] = strings.SplitN(plug, ";", 2)[0]
		if rest := strings.TrimPrefix(plug, out["plugin"].(string)); rest != "" {
			out["plugin_opts"] = strings.TrimPrefix(rest, ";")
		}
	}

	return Profile{
		TransportFamily: "shadowsocks",
		Outbound:        out,
		Tag:             u.Fragment,
	}, Provenance{Scheme: "ss"}, nil
}
