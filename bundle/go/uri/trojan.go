package uri

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTrojan handles trojan://password@host:port?params#name.
//
// Trojan is TLS by definition, so the link's security= may only be tls
// (or absent, meaning tls). security=reality is refused (sing-box's
// trojan outbound would run REALITY, but a Trojan-REALITY server is an
// Xray-only arrangement nothing here has been checked against), and so
// is security=none: the Trojan request carries the password and every
// destination in clear.
//
// fp= is honoured (without it the hello is Go crypto/tls's, which looks
// like no browser), alpn= is split on commas, type= goes through
// v2rayTransport with gRPC refused.
//
// The family is "other", here and in the Clash path
// (core/refresh/parse.go used to say websocket-tls, which is the
// stable Daal VLESS+WebSocket tier, not a stranger's Trojan server).
func parseTrojan(raw string) (Profile, Provenance, error) {
	u, err := parseLink("trojan", raw)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, Provenance{}, fmt.Errorf("trojan: missing password: %w", ErrMalformed)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, Provenance{}, fmt.Errorf("trojan: invalid port: %w", ErrMalformed)
	}
	q := u.Query()
	switch security := strings.ToLower(q.Get("security")); security {
	case "", "tls":
	case "none":
		return Profile{}, Provenance{}, fmt.Errorf("trojan: security=none: %w", ErrPlaintext)
	default:
		return Profile{}, Provenance{}, fmt.Errorf("trojan: security=%s: %w", safeToken(security), ErrTransportUnsupported)
	}
	out := map[string]any{
		"type":        "trojan",
		"server":      u.Hostname(),
		"server_port": port,
		"password":    u.User.Username(),
	}
	tls := map[string]any{"enabled": true}
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer")); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := splitALPN(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fp, ok := utlsFingerprint(q.Get("fp")); ok {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	out["tls"] = tls
	transport, err := v2rayTransport("trojan", q, false)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	return Profile{
		TransportFamily: "other",
		Outbound:        out,
		Tag:             u.Fragment,
	}, Provenance{Scheme: "trojan"}, nil
}
