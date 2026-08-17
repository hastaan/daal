package relaypack

// client_outbound.go — FRP-14 Tier-2: assemble a real client-side
// sing-box outbound JSON per route from the box connection material +
// per-recipient credentials.
//
// Before Tier-2 the per-route `profiles/<id>.json` in a pack carried
// only RelayPack *metadata* ({port, _relaypack}); the recipient
// engine's BuildSingBoxConfig wrapped that as the active outbound,
// producing a typeless outbound that sing-box rejects — so
// engine_set_route always failed. This package produces the missing
// outbound so the tunnel can actually come up.
//
// The families map to the box inbounds provisioned by
// cmd/daal-relay-mgmt (vless-in / hy2-in / naive-in / ws-in):
//   - vless-reality: no cert needed (REALITY borrows a real TLS
//     handshake to server_name); works on a bare-IP VPS.
//   - websocket-tls / hysteria2 / naive: TLS to a self-signed leaf on
//     a bare IP; pinned client-side via TLSCertSHA256, never insecure.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RealityServerName is the TLS name the box's vless-in REALITY inbound
// performs its handshake against (see cloudinit v2 defaultSingBoxConfig).
// The client outbound MUST match it.
const RealityServerName = "www.cloudflare.com"

// ClientConnParams is everything needed to render a client outbound for
// one recipient on one box. Box-wide fields (server, RealityPublicKey,
// TLSCertSHA256) are identical across a box's recipients; the rest are
// the per-recipient creds minted by /users/provision.
type ClientConnParams struct {
	Server           string // box public IP or hostname
	Name             string // recipient name (r<id>); the naive proxy username
	VLESSUUID        string
	RealityShortID   string
	RealityPublicKey string // base64 x25519; required for vless-reality
	Hy2Password      string
	NaivePassword    string
	WSPath           string // "/r<id>/<hex>"
	TLSCertSHA256    string // base64 SHA-256 of the leaf SPKI, for ws/hy2 pinning
	TLSCertPEM       string // full leaf cert PEM, naive's trusted root (Cronet)
}

// ClientOutboundForFamily returns the sing-box outbound JSON bytes for
// the given transport family, or an error if the params are missing a
// field that family needs, or the family has no client renderer yet.
//
// The returned object always carries `"tag":"active"` (the tag the
// recipient engine's BuildSingBoxConfig / route.final expects) and a
// concrete `"type"`, so it is a directly usable sing-box outbound.
func ClientOutboundForFamily(family string, port int, p ClientConnParams) ([]byte, error) {
	if strings.TrimSpace(p.Server) == "" {
		return nil, fmt.Errorf("client outbound: empty server for family %q", family)
	}
	var ob map[string]any
	switch family {
	case "vless-reality":
		if p.VLESSUUID == "" || p.RealityShortID == "" || p.RealityPublicKey == "" {
			return nil, fmt.Errorf("vless-reality needs uuid, short_id and reality_public_key")
		}
		ob = map[string]any{
			"type":        "vless",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			"uuid":        p.VLESSUUID,
			"flow":        "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": RealityServerName,
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": p.RealityPublicKey,
					"short_id":   p.RealityShortID,
				},
			},
		}
	case "websocket-tls":
		if p.VLESSUUID == "" || p.WSPath == "" {
			return nil, fmt.Errorf("websocket-tls needs uuid and ws_path")
		}
		ob = map[string]any{
			"type":        "vless",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			"uuid":        p.VLESSUUID,
			"transport":   map[string]any{"type": "ws", "path": p.WSPath},
			"tls":         pinnedTLS(p.Server, p.TLSCertSHA256),
		}
	case "hysteria2":
		if p.Hy2Password == "" {
			return nil, fmt.Errorf("hysteria2 needs hy2_password")
		}
		ob = map[string]any{
			"type":        "hysteria2",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			"password":    p.Hy2Password,
			// hysteria2 is QUIC: it uses its own TLS stack and rejects a
			// uTLS block ("unsupported usage for uTLS"), so pin without it.
			"tls": pinnedTLSNoUTLS(p.Server, p.TLSCertSHA256),
		}
	case "naive":
		if p.NaivePassword == "" || p.Name == "" {
			return nil, fmt.Errorf("naive needs naive_password and name")
		}
		// naive rides Cronet, which verifies against a trusted-root set
		// (no CA, no uTLS, no SPKI pin): install the box's leaf as the
		// trusted root. server_name must match its iPAddress SAN.
		naiveTLS := map[string]any{
			"enabled":     true,
			"server_name": p.Server,
		}
		if p.TLSCertPEM != "" {
			naiveTLS["certificate"] = []any{p.TLSCertPEM}
		}
		// An empty PEM means the box predates the data-plane cert (it is
		// minted by cloud-init at first boot and returned by
		// /users/provision; a relay provisioned before that change has
		// neither). Emitting the outbound without a trusted root leaves
		// Cronet on the system root set, so this route fails closed at
		// connect — exactly what ws/hy2 already do when TLSCertSHA256 is
		// absent, and never `insecure: true`. Erroring instead would
		// fail the WHOLE rewrite (RewriteProfilesForRecipient returns
		// the first renderer error), which killed every pack for every
		// pre-existing relay: no recipient could be added at all, and
		// the raw Go string was what the publisher saw.
		ob = map[string]any{
			// The real naive protocol (HTTP/2 CONNECT) — a plain "http"
			// outbound cannot speak it. Requires the engine to be built
			// with the with_naive_outbound tag.
			"type":        "naive",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			// username MUST match the box's naive-in user (appendNaiveUser
			// sets it to the recipient name), or auth fails.
			"username": p.Name,
			"password": p.NaivePassword,
			"tls":      naiveTLS,
		}
	default:
		return nil, fmt.Errorf("no client outbound renderer for family %q", family)
	}
	return json.Marshal(ob)
}

// pinnedTLS builds a client TLS block for a bare-IP self-signed leaf:
// SNI is the server itself and the leaf is pinned by SHA-256 rather
// than trusting a CA (there is none) or disabling verification. If no
// pin is available the block omits the pin (the recipient import will
// still fail closed at connect, surfacing the missing pin) — we never
// emit `insecure: true`.
func pinnedTLS(server, certSHA256 string) map[string]any {
	return pinnedTLSOpts(server, certSHA256, true)
}

// pinnedTLSNoUTLS is pinnedTLS without the uTLS ClientHello mimicry, for
// transports whose TLS stack rejects it (hysteria2/QUIC).
func pinnedTLSNoUTLS(server, certSHA256 string) map[string]any {
	return pinnedTLSOpts(server, certSHA256, false)
}

func pinnedTLSOpts(server, certSHA256 string, withUTLS bool) map[string]any {
	tls := map[string]any{
		"enabled":     true,
		"server_name": server,
	}
	if withUTLS {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	}
	if certSHA256 != "" {
		// sing-box pins via base64 SHA-256 of the leaf SPKI. The
		// option is Listable[[]byte]; a single base64 string decodes
		// to the pin bytes, and the recipient engine accepts it as a
		// one-element list.
		tls["certificate_public_key_sha256"] = certSHA256
	}
	return tls
}
