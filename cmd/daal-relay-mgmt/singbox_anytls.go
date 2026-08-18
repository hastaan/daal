// WAVE 5 — anytls on the box.
//
// WHY THIS FAMILY. Every other TLS family Daal serves bolts its
// countermeasures on from outside: sing-mux supplies multiplexing for
// vless-reality and websocket-tls, and nothing supplies length padding
// at all. anytls is the one family where BOTH are in the protocol —
// `padding_scheme` on the inbound (option/anytls.go), and native
// session reuse via `min_idle_session` / `idle_session_timeout` on the
// outbound. Against an adversary doing record-length and burst-shape
// fingerprinting that is the closest thing to a purpose-built answer
// available here, and it costs no new dependency: sing-box 1.13.12
// registers the anytls outbound unconditionally (include/registry.go:92).
//
// AND THE OTHER HALF, which travels with the first wherever this family
// is described: anytls is young. It has nothing like the deployment
// history of REALITY or shadowsocks, its TLS handshake is an ordinary
// one (so the Xue et al. nested-TLS classifier reaches it exactly as it
// reaches vless-reality and websocket-tls — the padding changes what is
// INSIDE the tunnel, not that a tunnel is there), and on the relay it
// listens on 8447, which is outside the target country's 53/80/443
// egress whitelist. Inside Iran this route is worth zero until port
// sharing on 443 lands. See relayports.For("anytls") for that accounting.
//
// THE PADDING SCHEME IS PER-RELAY, and that is the interesting choice.
//
// The scheme is a server-side value that the client LEARNS IN BAND:
// the client opens with the library default, announces `padding-md5` in
// its settings frame, and the server replies with cmdUpdatePaddingScheme
// carrying the raw scheme whenever the hashes differ
// (sing-anytls session/session.go:89, 264-278, 314-325). Two
// consequences, both load-bearing:
//
//  1. A per-relay scheme costs NOTHING on the client side. Unlike the
//     REALITY cover SNI — which must match byte-for-byte on both ends or
//     the handshake fails, and therefore has to be carried box →
//     publisher → pack → client — the padding scheme needs no plumbing
//     at all. It is deliberately absent from mgmt.UserCreds; see the
//     note on AnyTLSPassword there.
//  2. Therefore the DEFAULT scheme is the wrong choice, and it is the
//     wrong choice twice over. Every anytls deployment on earth that
//     never set `padding_scheme` shares one byte-identical record-size
//     distribution, so it is the first thing any analyst characterises;
//     and a single Daal-wide custom scheme would merely swap a global
//     constant for a fleet-wide one — precisely the failure the Wave-2
//     cover-SNI work existed to remove, re-introduced on the length
//     axis. The padding shapes TLS RECORD SIZES, which are visible on
//     the wire even though the negotiation that chose them is not.
//
// So each relay generates its own at the moment it first creates the
// inbound, and keeps it in its sing-box config, exactly as it keeps its
// ws path. Rotating it later is free by the same in-band mechanism (no
// pack is invalidated, no recipient needs anything re-sent) — that is
// worth wiring into /rotate-tls and is NOT wired here.
//
// HONEST LIMIT ON WHAT THE PER-RELAY SCHEME BUYS. The very first record
// a client ever sends to a relay is padded from the client's own
// starting scheme — the library default — because that byte goes out
// before the settings exchange has happened (sing-anytls client.go:42,
// 70-76). So the first flight is default-shaped on every relay; only
// the traffic after the first settings exchange carries this relay's
// shape. A censor who only ever looks at the first record sees the
// default and learns nothing about which relay this is, which is
// harmless, but it also means the per-relay scheme is not a defence
// against first-packet classification. It is a defence against
// cross-relay CORRELATION over a session.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

const (
	// tagAnyTLS is the single shared anytls inbound. Same shape as
	// ws-in, naive-in and ss-in: ONE inbound on ONE port, recipients
	// told apart by their password. Per-user inbounds would collide on
	// the port.
	tagAnyTLS = "anytls-in"

	// anytlsListenPort mirrors relayports.For("anytls").Port. Local copy
	// for the same reason wsListenPort / naiveListenPort are local:
	// relay-mgmt is a separate module and importing the publisher
	// package would drag the whole publisher dependency tree onto the
	// box. Keep the two numbers in lockstep.
	anytlsListenPort = 8447
)

// capAnyTLSInbound is the /health capability token for this family.
//
// It is a wire contract with publisher/deploy/mgmt.CapAnyTLSInbound;
// the two literals must stay identical or the interlock silently stops
// interlocking. It advertises that THIS BINARY creates anytls-in when
// it provisions a recipient — which is a property of the binary, so it
// is asserted unconditionally, unlike capBindAddress whose answer
// depends on the service unit's privileges.
//
// It does NOT get a mgmt_api_version fallback on the publisher side.
// The capability rides the hash-pinned artifact, and a relay is
// perfectly capable of running an old mgmt binary while reporting a
// current api version; inferring the family from the version number is
// how a box comes to claim it serves something it does not.
const capAnyTLSInbound = "anytls-inbound"

// appendAnyTLSUser adds the recipient to the shared anytls-in inbound,
// creating the inbound (and this relay's padding scheme) on first use.
//
// Like naive-in and unlike vless-in, this inbound must never exist with
// an empty users[]: the anytls service authenticates against its user
// list and an inbound nobody can authenticate to is a listener that
// only serves probes. It is created with its first user and dropped
// with its last (see removeAnyTLSUser).
//
// Idempotent: re-provisioning a name already present is a no-op rather
// than a duplicate row.
//
// A MISSING PASSWORD SKIPS THIS FAMILY, IT DOES NOT FAIL THE PROVISION.
// addUserToSingbox is all-or-nothing across every inbound, so returning
// an error here would mean one absent anytls credential costs the
// recipient vless-reality, hysteria2, naive, ws and shadowsocks as
// well — the same shape of mistake as failing the whole pack over one
// unrenderable route, which client_outbound.go already records having
// made once. Skipping leaves no anytls row, readAnyTLSPassword then
// returns "", and the publisher declines to mint the route. The family
// goes missing; the recipient does not.
func appendAnyTLSUser(doc map[string]any, c userCreds) error {
	if c.AnyTLSPassword == "" {
		return nil
	}
	if in := findInboundByTag(doc, tagAnyTLS); in != nil {
		users, _ := in["users"].([]any)
		for _, raw := range users {
			u, _ := raw.(map[string]any)
			if n, _ := u["name"].(string); n == c.Name {
				return nil // already present
			}
		}
		in["users"] = append(users, map[string]any{
			"name":     c.Name,
			"password": c.AnyTLSPassword,
		})
		return nil
	}
	scheme, err := generatePaddingScheme()
	if err != nil {
		return fmt.Errorf("anytls: padding scheme: %w", err)
	}
	inbound := map[string]any{
		"type":        "anytls",
		"tag":         tagAnyTLS,
		"listen":      "0.0.0.0",
		"listen_port": anytlsListenPort,
		"users": []any{
			map[string]any{
				"name":     c.Name,
				"password": c.AnyTLSPassword,
			},
		},
		// option.AnyTLSInboundOptions.PaddingScheme is
		// badoption.Listable[string]: the wire form is a JSON array of
		// lines, which the inbound joins with "\n" before handing to
		// the padding parser (protocol/anytls/inbound.go:56-58). Emitting
		// one newline-joined string would also decode — Listable accepts
		// a bare string — but as a SINGLE line, which then fails to parse
		// into a scheme and takes the relay down at boot. Array form.
		"padding_scheme": scheme,
		// No `multiplex` block, deliberately, and NOT for the hysteria2
		// reason. option.AnyTLSInboundOptions has no Multiplex field at
		// all, so the key would be a fatal `json: unknown field` at boot
		// — but even if it existed it would be wrong here: anytls has
		// its own session layer (the same one the padding rides on), and
		// stacking sing-mux on top would be two multiplexers deep.
		"tls": map[string]any{
			"enabled":          true,
			"certificate_path": tlsCertPath,
			"key_path":         tlsKeyPath,
		},
	}
	inbounds, _ := doc["inbounds"].([]any)
	doc["inbounds"] = append(inbounds, inbound)
	return nil
}

// removeAnyTLSUser removes the recipient from anytls-in, dropping the
// whole inbound when the last user leaves.
//
// Dropping it also discards this relay's padding scheme, so the next
// recipient provisioned generates a fresh one. That is a feature, not
// an accident: a relay that has emptied out and refilled presents a
// different record-size distribution than it did before, for free.
func removeAnyTLSUser(doc map[string]any, name string) bool {
	in := findInboundByTag(doc, tagAnyTLS)
	if in == nil {
		return false
	}
	users, _ := in["users"].([]any)
	out := make([]any, 0, len(users))
	removed := false
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		if n, _ := u["name"].(string); n == name {
			removed = true
			continue
		}
		out = append(out, raw)
	}
	if !removed {
		return false
	}
	if len(out) == 0 {
		inbounds, _ := doc["inbounds"].([]any)
		kept := make([]any, 0, len(inbounds))
		for _, raw := range inbounds {
			ib, _ := raw.(map[string]any)
			if t, _ := ib["tag"].(string); t == tagAnyTLS {
				continue
			}
			kept = append(kept, raw)
		}
		doc["inbounds"] = kept
		return true
	}
	in["users"] = out
	return true
}

// readAnyTLSPassword returns the password this recipient actually has
// in the live anytls-in inbound, or "" when the family is not served
// here.
//
// READ BACK FROM DISK, never returned from what appendAnyTLSUser
// intended to write. Empty is the publisher's only signal that this
// relay does not serve anytls — because its mgmt binary predates the
// family, or because an operator removed the inbound — and an inferred
// value would make that signal lie. Same discipline as
// readSSClientPassword and tuicUserPresent.
func readAnyTLSPassword(path, name string) string {
	doc, err := loadSingboxDoc(path)
	if err != nil {
		return ""
	}
	in := findInboundByTag(doc, tagAnyTLS)
	if in == nil {
		return ""
	}
	users, _ := in["users"].([]any)
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		if n, _ := u["name"].(string); n == name {
			pw, _ := u["password"].(string)
			return pw
		}
	}
	return ""
}

// paddingSchemeStopMin / Max bound how many packets into a session the
// padding keeps applying. The library default is 8. Going lower saves
// bytes and shortens the shaped prefix; going much higher pads traffic
// long past the handshake burst that actually carries the distinguishing
// shape, for overhead on every flow. 8..13 keeps the choice inside the
// range the protocol was designed around while making the value itself
// one more thing that differs per relay.
const (
	paddingSchemeStopMin = 8
	paddingSchemeStopMax = 13
)

// generatePaddingScheme builds THIS relay's anytls padding scheme.
//
// Output is the `padding_scheme` array: one "key=value" line per entry,
// in the format sing-anytls parses (padding/padding.go):
//
//	stop=N          padding applies to packets 0..N-1
//	0=a-b           packet 0's record payload sizes; "a-b" is an
//	                inclusive random range, "a-a" a fixed size
//	2=x-y,c,z-w     "c" is a check mark: flush the record here, so one
//	                logical packet becomes several TLS records
//
// SHAPE, NOT NOISE. The layout deliberately mirrors the structure of
// the default scheme — a small fixed size for packet 0, a modest range
// for packet 1, a multi-record split for packet 2 where the request
// burst lands, and steady mid-size ranges after that — while
// randomising every number and the number of splits. The structure is
// what makes the traffic look like a plausible application; the
// randomisation is what stops two Daal relays looking like each other.
// A uniformly random scheme would achieve the second and lose the first.
//
// Every value is > 0 and every range has min <= max, which is what
// padding.NewPaddingFactory requires to return non-nil; a nil factory
// there is a FATAL at sing-box start, i.e. a relay that does not come
// up. writeSingboxDoc's validate hook runs `sing-box check` over the
// candidate config before it replaces the live one, so a scheme this
// function got wrong is caught before the relay is touched — but the
// generator is unit-tested directly (see the padding tests) rather than
// relying on that.
func generatePaddingScheme() ([]string, error) {
	stop, err := randRange(paddingSchemeStopMin, paddingSchemeStopMax)
	if err != nil {
		return nil, err
	}
	lines := []string{fmt.Sprintf("stop=%d", stop)}

	// Packet 0 is the pre-session padding length the client writes as a
	// literal uint16 before anything is negotiated. A fixed size (a-a),
	// like the default's 30-30.
	p0, err := randRange(24, 64)
	if err != nil {
		return nil, err
	}
	lines = append(lines, fmt.Sprintf("0=%d-%d", p0, p0))

	// Packet 1: one modest range.
	lo1, err := randRange(80, 260)
	if err != nil {
		return nil, err
	}
	span1, err := randRange(150, 420)
	if err != nil {
		return nil, err
	}
	lines = append(lines, fmt.Sprintf("1=%d-%d", lo1, lo1+span1))

	// Packet 2 is where the client's request burst lands, so it gets the
	// multi-record split: 2..4 segments separated by check marks, which
	// is what turns one logical write into several TLS records of
	// unrelated sizes.
	segs, err := randRange(2, 4)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 0, segs*2)
	for i := 0; i < segs; i++ {
		lo, err := randRange(320, 620)
		if err != nil {
			return nil, err
		}
		span, err := randRange(180, 520)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			parts = append(parts, "c")
		}
		parts = append(parts, fmt.Sprintf("%d-%d", lo, lo+span))
	}
	lines = append(lines, "2="+strings.Join(parts, ","))

	// Packets 3..stop-1: steady mid-size ranges.
	for i := 3; i < stop; i++ {
		lo, err := randRange(300, 700)
		if err != nil {
			return nil, err
		}
		span, err := randRange(200, 600)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("%d=%d-%d", i, lo, lo+span))
	}
	return lines, nil
}

// randRange returns a uniform int in [lo, hi] using crypto/rand.
// Panic-free for lo <= hi; callers pass compile-time-sane bounds.
func randRange(lo, hi int) (int, error) {
	if hi < lo {
		lo, hi = hi, lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, err
	}
	return lo + int(n.Int64()), nil
}

// newAnyTLSPassword mints one recipient's anytls password.
//
// anytls treats the password as an opaque string (it is hashed into the
// session key by the library), so unlike shadowsocks-2022 there is no
// decoder on the far end dictating an encoding, and unlike the SS uPSK
// there is no fixed length requirement. 32 random bytes in base64-URL,
// matching the shape of Hy2Password / NaivePassword, is well past any
// guessing concern and keeps one generator idiom in this binary.
func newAnyTLSPassword() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
