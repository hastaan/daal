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
//   - shadowsocks (Wave 5): no TLS at all — no cert, no pin, no
//     handshake. That is the point of it; see the case below.

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

	// TUICUUID / TUICPassword are the tuic tier's credential pair.
	// tuic authenticates on BOTH, so both are required and neither has
	// a default; empty means this relay does not serve tuic (or its
	// mgmt binary is too old to know it does), and the renderer refuses
	// rather than emitting a route that cannot authenticate.
	TUICUUID     string
	TUICPassword string

	// SSPassword / SSMethod are the shadowsocks-2022 pair, and
	// SSPassword is NOT a secret this side assembles: it arrives from
	// the box already in the exact form the outbound needs,
	// "<box iPSK>:<recipient uPSK>". SS-2022 multi-user carries a
	// two-level key — one box-wide iPSK that says "this relay", one
	// per-recipient uPSK that says "this recipient" — and the client
	// presents both, colon-joined, in one field. Splitting the
	// concatenation across two processes is how the halves get swapped
	// or the separator gets lost, so exactly one place knows the rule:
	// the box (cmd/daal-relay-mgmt ssClientPassword).
	//
	// Both empty means this relay does not serve the family. The
	// renderer refuses rather than guessing — an SS route minted
	// without a key is a route the recipient will select and lose.
	SSPassword string
	SSMethod   string

	// AnyTLSPassword is the anytls tier's per-recipient password, from
	// the box's live anytls-in inbound. Empty means this relay does not
	// serve anytls — its mgmt binary predates the family, or the inbound
	// is absent — and the renderer refuses rather than minting a route
	// that cannot authenticate.
	//
	// There is deliberately no padding-scheme parameter beside it: the
	// scheme is per-relay and the client LEARNS it in band on its first
	// session (sing-anytls session/session.go:264-278). The client
	// outbound has no `padding_scheme` option at all — see
	// option.AnyTLSOutboundOptions, which carries only password, the
	// idle-session knobs, and the usual dialer/server/TLS containers.
	AnyTLSPassword string

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
	case "tuic":
		// TUIC IS DIVERSITY, NOT A LIFELINE — and the label, the copy
		// and this comment must all keep saying so. It rides UDP on
		// 8443, and in the primary target country neither half survives:
		// 8443 is outside the 53/80/443 egress whitelist, and the
		// adversary document states the intent as complete and permanent
		// blocking of outbound IPv6, UDP and ICMP. Daal already ships one
		// UDP tier (hysteria2); a second one falls to the same rule at the
		// same moment. What tuic buys is a differently-shaped QUIC
		// handshake on networks where UDP still works, i.e. correlation
		// breaking elsewhere — never a new way through the whitelist.
		//
		// Requires the recipient engine to be built with `with_quic`
		// (tools/build-engine-android.sh has it), same as hysteria2.
		if p.TUICUUID == "" || p.TUICPassword == "" {
			return nil, fmt.Errorf("tuic needs tuic_uuid and tuic_password: this relay did not " +
				"report them, which means either its toolbox profile does not enable tuic or its " +
				"daal-relay-mgmt binary predates the family (rebuild, re-sign, re-upload, bump the " +
				"hash pin in publisher/deploy/cloudinit/artifacts.go, and reprovision)")
		}
		ob = map[string]any{
			"type":        "tuic",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			"uuid":        p.TUICUUID,
			"password":    p.TUICPassword,
			// bbr matches what the box's inbound is configured with;
			// congestion control must agree end to end or the session
			// stalls rather than fails, which is the worse failure.
			"congestion_control": "bbr",
			// No `multiplex`, for the same two reasons as hysteria2:
			// option/tuic.go's TUICOutboundOptions has no Multiplex
			// field at all (the strict parser would reject the outbound
			// outright), and smux over a QUIC-native transport re-adds
			// the head-of-line blocking QUIC exists to remove.
			//
			// QUIC brings its own TLS stack, so pin without uTLS —
			// hysteria2 rejects a uTLS block outright and tuic has no
			// use for one either.
			//
			// ALPN IS MANDATORY HERE, unlike hysteria2, and that is a
			// difference between two families that otherwise look alike.
			// sing-quic's hysteria2 client and service both default
			// NextProtos to "h3" when the config leaves it empty
			// (hysteria2/client.go:83, service.go:88). Its tuic client
			// and service never touch NextProtos at all, and quic-go
			// requires the TLS config to define an application protocol
			// on both ends. So a tuic route with no `alpn` does not
			// degrade — it fails the QUIC handshake outright. tuicTLS
			// sets ["h3"], which must stay equal to the box inbound's.
			"tls": tuicTLS(p.Server, p.TLSCertSHA256),
		}
	case "shadowsocks":
		// SHADOWSOCKS-2022 IS CORRELATION-BREAKING DIVERSITY, AND IT IS
		// WEAK ALONE. Both halves, every time this family is described.
		//
		// The first half is why it is worth the port. vless-reality,
		// websocket-tls and naive all open with a TLS handshake, so the
		// Xue et al. (USENIX Security 2024) nested-TLS classifier —
		// >70% TPR at 0.054% FPR, REALITY+Vision included — threatens
		// all three SIMULTANEOUSLY: they are three draws from one urn,
		// not three independent bets. Shadowsocks-2022 has no TLS
		// handshake anywhere in it; its first bytes are an
		// AEAD-encrypted, uniformly random header. That classifier
		// cannot reach it, structurally, and no amount of retraining
		// changes that. It is the only tier Daal ships whose failure is
		// uncorrelated with the other three.
		//
		// The second half is why it is not a promotion. Shadowsocks is
		// the most-studied protocol in the entropy and flow-shape
		// literature, and the GFW has publicly demonstrated both active
		// probing and packet-length classification against it. The 2022
		// construction closes the replay and redirect probes the older
		// AEAD ciphers fell to, but "high-entropy payload from byte
		// one" is still exactly the signature entropy classifiers key
		// on, and a fixed port makes the flow easy to isolate first.
		// This route's job is to fail at a DIFFERENT time and for a
		// DIFFERENT reason than the TLS tiers. It is not a stronger
		// tier and must never be labelled as one.
		//
		// Two more caveats that belong with it, not buried elsewhere:
		// 8446 is outside the target country's 53/80/443 egress
		// whitelist, so this route is worth zero inside Iran (see
		// relayports.go); and it is the third member of a fleet-wide
		// constant port set that one `drop tcp dport 8444,8445,8446`
		// takes down at once.
		if p.SSPassword == "" || p.SSMethod == "" {
			return nil, fmt.Errorf("shadowsocks needs ss_password and ss_method: this relay did " +
				"not report them, which means its daal-relay-mgmt binary predates the family " +
				"(rebuild, re-sign, re-upload, bump the hash pin in " +
				"publisher/deploy/cloudinit/artifacts.go, and reprovision)")
		}
		ob = map[string]any{
			"type":        "shadowsocks",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			// The METHOD the box reported, never a constant assumed
			// here: the PSK length follows from it (16 bytes for
			// 2022-blake3-aes-128-gcm) and a mismatch is not a slow
			// route, it is an outbound sing-box refuses to construct.
			"method": p.SSMethod,
			// Already "<iPSK>:<uPSK>". sing-shadowsocks2's
			// shadowaead_2022 method splits this on ":" and
			// base64.StdEncoding-decodes each half, so neither the
			// separator nor the padding is cosmetic.
			"password": p.SSPassword,
			// UDP OVER TCP, AND WHY IT COSTS THE MULTIPLEX BLOCK.
			//
			// The box's ss-in inbound is `"network":"tcp"` on a single
			// opened port (relayports.ExtraFirewallPorts opens 8446/tcp
			// and no UDP), so without this the route carries no UDP at
			// all — no DNS, no QUIC. UoT v2 tunnels it over the same
			// TCP connection and sing-box's shadowsocks inbound handles
			// the magic UoT destination unconditionally
			// (protocol/shadowsocks wraps its router in uot.NewRouter),
			// so no box-side switch is needed.
			//
			// The cost is exact and is the reason familyCarriesMultiplex
			// says no for this family: the sing-box shadowsocks outbound
			// builds a UoT client OR a mux client and never both
			// (protocol/shadowsocks/outbound.go — the mux dialer is
			// constructed only `if !uotOptions.Enabled`). A `multiplex`
			// object here would not be rejected; it would be silently
			// IGNORED, which is the worse failure, because the pack
			// would claim a mitigation it is not applying.
			"udp_over_tcp": map[string]any{"enabled": true, "version": 2},
			// NO `tls` block, and that absence is the feature. There is
			// nothing to pin because there is no certificate and no
			// handshake — which is precisely why this family survives a
			// classifier the other three do not.
		}
	case "anytls":
		// ANYTLS IS THE PADDING TIER, and that is the only thing it is
		// better at — the label and the copy must both keep saying so.
		//
		// What it genuinely has that no other family here has: length
		// padding and session reuse INSIDE the protocol rather than
		// bolted on. What it does not have: any advantage against the
		// nested-TLS classifier. Its handshake is an ordinary TLS
		// handshake to a hosting-provider address, so Xue et al. reaches
		// it exactly as it reaches vless-reality and websocket-tls; the
		// padding changes what the tunnel's records look like, not
		// whether a tunnel is visible. It is also young, with nothing
		// like REALITY's or shadowsocks' deployment history.
		//
		// And the caveat that belongs with it rather than buried
		// elsewhere: 8447 is outside the target country's 53/80/443
		// egress whitelist, so this route is worth zero inside Iran
		// (see relayports.go), and it is the fourth member of a
		// fleet-wide constant port set that one
		// `drop tcp dport 8444,8445,8446,8447` takes down at once.
		if p.AnyTLSPassword == "" {
			return nil, fmt.Errorf("anytls needs anytls_password: this relay did not report one, " +
				"which means its daal-relay-mgmt binary predates the family (rebuild, re-sign, " +
				"re-upload, bump the hash pin in publisher/deploy/cloudinit/artifacts.go, and " +
				"reprovision)")
		}
		ob = map[string]any{
			"type":        "anytls",
			"tag":         "active",
			"server":      p.Server,
			"server_port": port,
			"password":    p.AnyTLSPassword,
			// NATIVE SESSION REUSE — the outbound half of what makes
			// this family worth adding, and the reason it must never
			// also carry a `multiplex` block (familyCarriesMultiplex
			// says no). anytls keeps idle sessions alive and runs new
			// streams over them, so a request does not begin with a
			// fresh TCP+TLS handshake; that both removes the per-request
			// handshake shape a classifier can count and is the layer
			// the padding scheme is applied over. Stacking sing-mux on
			// top would be two multiplexers deep over one connection.
			//
			// The three knobs are exactly option.AnyTLSOutboundOptions'
			// (badoption.Duration decodes these strings). One idle
			// session held open is enough to remove the cold-start
			// handshake without keeping a conspicuous bundle of
			// connections parked against the relay; 30s/30s matches the
			// library's own documented defaults closely enough to avoid
			// being a distinguishing value in itself.
			"min_idle_session":            1,
			"idle_session_check_interval": "30s",
			"idle_session_timeout":        "30s",
			// Ordinary TLS to the box's self-signed leaf on a bare IP,
			// pinned by SPKI SHA-256 exactly like websocket-tls. anytls
			// uses sing-box's standard TLS stack
			// (OutboundTLSOptionsContainer), so uTLS applies here —
			// unlike hysteria2, whose QUIC stack rejects it.
			"tls": pinnedTLS(p.Server, p.TLSCertSHA256),
			// NO `padding_scheme` key here. It is not that we chose not
			// to set it: option.AnyTLSOutboundOptions has no such field,
			// because the scheme is the SERVER's to choose and the
			// client adopts it over the wire. The per-relay scheme the
			// box generates therefore reaches this client with nothing
			// carried in the pack. See cmd/daal-relay-mgmt/singbox_anytls.go.
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

// tuicTLS is pinnedTLSNoUTLS plus the mandatory ALPN. See the comment at
// the tuic case for why the list cannot be omitted and why it must equal
// the box inbound's.
func tuicTLS(server, certSHA256 string) map[string]any {
	tls := pinnedTLSNoUTLS(server, certSHA256)
	tls["alpn"] = []string{"h3"}
	return tls
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
