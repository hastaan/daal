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

// legacyRealityCoverSNI is the cover host EVERY relay provisioned before
// Wave 2 baked into cloud-init (`tls.server_name` AND
// `reality.handshake.server`), because this file used to declare it as a
// compile-time constant that the whole fleet shared. That is precisely
// the failure the corpus warns about: one free string match burns every
// Daal relay at once, and Irancell blocked all Cloudflare IPs outright on
// 16 Apr 2023, which would have taken the fleet down with them.
//
// It survives ONLY as the fallback for packs minted before CoverSNI
// existed: those packs' relays really do handshake against this name, so
// rendering anything else would break a working route. DELETE IT once no
// relay provisioned before Wave 2 is still in service — i.e. when every
// OperatorRecord in the field carries a per-relay CoverSNI. It must never
// be used as a default for a NEW relay; the provisioner picks from
// publisher/deploy/sni's pool instead.
const legacyRealityCoverSNI = "www.cloudflare.com"

// ClientConnParams is everything needed to render a client outbound for
// one recipient on one box. Box-wide fields (server, RealityPublicKey,
// TLSCertSHA256, CoverSNI, Multiplex) are identical across a box's
// recipients; the rest are the per-recipient creds minted by
// /users/provision.
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

	// CoverSNI is THIS relay's REALITY cover host — the name its
	// vless-in inbound borrows a handshake from, chosen per relay by the
	// provisioner (publisher/deploy/sni) and carried through
	// ProvisionArgs → cloud-init → OperatorRecord → here. One value, one
	// source: the client's advertised server_name and the box's
	// reality.handshake.server MUST be the same string or an active prober
	// gets exactly the mismatch REALITY exists to prevent.
	//
	// Empty means "pack minted before this field existed"; see
	// legacyRealityCoverSNI.
	CoverSNI string

	// Multiplex is the per-family (in a Daal pack, per-route: one route
	// per family) stream-multiplexing knob, sourced from the toolbox
	// profile — see MultiplexFromProfile. A nil map or a missing entry
	// means NO multiplex block is emitted, which is both the pre-Wave-2
	// wire shape and the only safe default: a mux client talking to a
	// relay whose inbound has no `multiplex` is routed to the literal
	// mux sentinel destination and fails. Only a caller that knows the
	// box was provisioned with mux inbounds may turn this on.
	Multiplex map[string]MuxPolicy
}

// coverSNI is the REALITY server_name to advertise for this pack.
func (p ClientConnParams) coverSNI() string {
	if s := strings.TrimSpace(p.CoverSNI); s != "" {
		return s
	}
	return legacyRealityCoverSNI
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
				"server_name": p.coverSNI(),
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": p.RealityPublicKey,
					"short_id":   p.RealityShortID,
				},
			},
		}
		addMultiplex(ob, family, p)
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
		addMultiplex(ob, family, p)
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
			// No `multiplex` here, deliberately, even if a profile asks
			// for it (familyCarriesMultiplex says no): sing-mux is a
			// stream layer over ONE TCP-like connection, so it hands a
			// QUIC-native transport the head-of-line blocking QUIC was
			// designed to remove — and option/hysteria2.go has no
			// Multiplex field at all, so the strict parser would reject
			// the outbound outright.
			//
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

// KNOWN, UNFIXED, RECORDED SO THE NEXT WAVE DOES NOT ASSUME IT WAS
// CONSIDERED AND ACCEPTED — an IP literal in `server_name`.
//
// `server` here is the box's public IP, so websocket-tls (pinnedTLS),
// hysteria2 (pinnedTLSNoUTLS) and naive (naiveTLS) all set
// tls.server_name to a bare address. Go's crypto/tls and uTLS both
// STRIP an IP literal from the SNI extension (hostnameInSNI), so what
// actually goes on the wire for those three tiers is: TLS 1.3, Chrome
// uTLS fingerprint, NO SNI at all, destination a hosting-provider /32
// on 8444 or 8445. That is identical on every relay and for every
// recipient — a fleet-wide correlate the per-relay cover-SNI work does
// not touch, because it lives on the REALITY tier only. A censor keying
// on "Chrome-fingerprinted ClientHello with no SNI to hosting address
// space" catches three tiers at once without ever looking at a cover
// host. publisher/deploy/sni/rule.go says as much in its own R1: an IP
// literal is illegal per RFC 6066 and a loud anomaly.
//
// Why it is still here: the pin is SPKI-based, so the presented name
// does not have to match anything, which means the fix is cheap in code
// (hand these three a per-relay hostname from the same pool) and NOT
// cheap in confidence — it changes the wire shape of three shipped
// tiers and cannot be validated by a unit test. It needs the same
// two-relay on-wire check Step 4 needs. Do it in the wave that owns the
// port strategy (Step 6), since both change what these three tiers look
// like from outside and should be measured together.
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
