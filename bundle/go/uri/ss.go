package uri

import (
	"fmt"
	"strconv"
	"strings"
)

// parseSS handles SIP002 ss://method:password@host:port#name AND the
// SIP022 AEAD-2022 variant ss://2022-blake3-aes-128-gcm:psk@host:port.
//
// We also handle the legacy form ss://base64(method:password)@host:port.
func parseSS(raw string) (Profile, Provenance, error) {
	// parseLink, not url.Parse: url.Error quotes the whole link, and
	// its userinfo is the method and password.
	u, err := parseLink("ss", raw)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	host := u.Hostname()
	port, perr := strconv.Atoi(u.Port())
	if perr != nil || port < 1 || port > 65535 {
		return Profile{}, Provenance{}, fmt.Errorf("ss: invalid port: %w", ErrMalformed)
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
				return Profile{}, Provenance{}, fmt.Errorf("ss: base64 userinfo: %w", ErrMalformed)
			}
			parts := strings.SplitN(string(dec), ":", 2)
			if len(parts) != 2 {
				return Profile{}, Provenance{}, fmt.Errorf("ss: malformed userinfo: %w", ErrMalformed)
			}
			method = parts[0]
			password = parts[1]
		}
	}
	if method == "" || password == "" {
		return Profile{}, Provenance{}, fmt.Errorf("ss: missing method/password: %w", ErrMalformed)
	}
	if ssPlaintextMethod(method) {
		return Profile{}, Provenance{}, fmt.Errorf("ss: method=none: %w", ErrPlaintext)
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
