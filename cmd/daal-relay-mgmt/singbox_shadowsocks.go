// WAVE 5 — shadowsocks-2022 on the box.
//
// WHY THIS FAMILY EXISTS AT ALL, and it is not "one more tier".
//
// Every family Daal served before this one — vless-reality,
// websocket-tls, naive — opens with a TLS handshake. Xue et al. (USENIX
// Security 2024) classify nested-TLS proxies, REALITY+Vision included,
// at >70% TPR for 0.054% FPR, and that one classifier therefore
// threatens ALL THREE AT ONCE: they are not independent bets, they are
// three draws from the same urn. shadowsocks-2022 has no TLS handshake
// anywhere in it — its first bytes are an AEAD-encrypted, uniformly
// random header — so it is structurally outside that classifier's
// reach. That is the whole value: correlation-breaking DIVERSITY.
//
// AND THE OTHER HALF, which must travel with the first sentence
// wherever this family is labelled: shadowsocks is NOT a stronger tier.
// It is the most-studied protocol in the entropy/flow-shape literature
// and the one the GFW has publicly demonstrated active-probing and
// length-distribution attacks against; 2022-blake3 fixes the
// replay/redirect probes of the older AEAD construction but leaves the
// "high-entropy payload from byte one" signature that entropy
// classifiers key on. It is weak ALONE. Its job is to fail at a
// different time, for a different reason, than the TLS tiers — not to
// outlive them.
//
// WHAT IS SERVED. Exactly one method: 2022-blake3-aes-128-gcm. Not a
// legacy AEAD (aes-128-gcm, chacha20-ietf-poly1305 — no replay
// protection, probe-vulnerable), not a stream cipher, and not
// 2022-blake3-chacha20-poly1305, because that method refuses multi-user
// EIH outright (sing-shadowsocks2 shadowaead_2022/method.go: `if
// len(m.pskList) > 1 { return nil, ErrNoEIH }`) and per-recipient
// credentials are non-negotiable here.
//
// CREDENTIAL SHAPE — the part that is easy to get wrong. SS-2022
// multi-user is two-level:
//
//	inbound.password        = iPSK, the BOX-wide server key
//	inbound.users[].password = uPSK, one per recipient
//	client outbound.password = "<iPSK>:<uPSK>"
//
// Both halves are base64 STANDARD encoding (padded) of exactly 16 raw
// bytes for aes-128-gcm — base64.StdEncoding.DecodeString on both ends
// (sing-shadowsocks shadowaead_2022/service_multi.go:43,109 for the
// server; sing-shadowsocks2 shadowaead_2022/method.go:60-67 for the
// client, which splits on ":"). RawURLEncoding — what Hy2Password and
// NaivePassword use — does NOT decode there, so this family cannot
// reuse their generator.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

const (
	// tagSS is the single shared shadowsocks-2022 inbound. Same shape as
	// ws-in and naive-in: ONE inbound on ONE port, recipients told apart
	// by their uPSK. Per-user inbounds on one port do not work — that
	// bug has been shipped once already (see the ws note in
	// singbox_users.go) and SS is no different.
	tagSS = "ss-in"

	// ssListenPort mirrors relayports.For("shadowsocks").Port. Local
	// copy for the same reason wsListenPort/naiveListenPort are: this
	// binary must not import the publisher's dependency tree. The port
	// decision and its cost are argued in relayports.go; the short
	// version is that a shadowsocks connection carries no TLS
	// ClientHello, so REALITY's fallback on 443/tcp cannot demultiplex
	// it, and 8446 is NOT whitelisted egress in the primary target
	// country.
	ssListenPort = 8446

	// ssMethod is the ONE method this relay serves. Changing it is a
	// wire break for every distributed pack: the client's outbound
	// carries the method name and both sides derive keys from it.
	ssMethod = "2022-blake3-aes-128-gcm"

	// ssKeyBytes is the raw PSK length required by ssMethod
	// (shadowaead_2022 method.go: keySaltLength=16 for
	// 2022-blake3-aes-128-gcm). A key of any other length is refused at
	// service construction — "bad key length, required 16" — which is a
	// FATAL at sing-box start, i.e. a bricked relay.
	ssKeyBytes = 16
)

// capShadowsocks2022 is the /health capability token for this family.
//
// It is asserted UNCONDITIONALLY, like the two rotation verbs and unlike
// capBindAddress, and the distinction is the one main.go already draws:
// this token describes what the BINARY does, not what the host grants it.
// A relay running this binary creates ss-in the next time a recipient is
// provisioned, with no privilege, no cloud-init field and no profile
// switch in between — so if the binary is here, the capability is here.
//
// The token is the EARLY half of the interlock. The late half is
// userCreds.SSPassword coming back empty, which is what actually stops a
// dead route being minted; this one exists so a publisher can find out
// before it provisions, instead of after. mgmt_api_version deliberately
// does NOT move: a version bump would let a box claim the family from a
// number, and publisher/deploy/mgmt gives this token no version fallback
// for exactly that reason.
//
// It is a wire contract with publisher/deploy/mgmt.CapShadowsocks2022.
// Changing one end alone re-breaks the interlock silently.
const capShadowsocks2022 = "shadowsocks-2022"

// genSSKey returns a fresh base64-std PSK of the exact length ssMethod
// requires.
func genSSKey() (string, error) {
	buf := make([]byte, ssKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// StdEncoding, WITH padding, deliberately: the server and the client
	// both call base64.StdEncoding.DecodeString on this string, and
	// RawURLEncoding output fails there.
	return base64.StdEncoding.EncodeToString(buf), nil
}

// appendSSUser adds the recipient to the single shared ss-in inbound,
// creating the inbound (and minting the box-wide iPSK) on first use.
//
// Like naive-in and unlike vless-in/hy2-in, this inbound cannot be
// baked into cloud-init empty — and for a reason far worse than naive's
// startup FATAL. sing-box picks the shadowsocks inbound implementation
// from the users list at construction time
// (protocol/shadowsocks/inbound.go NewInbound): with users[] non-empty
// it builds the MULTI-user service, which authenticates each recipient
// by their own uPSK; with users[] EMPTY it silently builds the
// SINGLE-user service, which accepts anyone holding the inbound's
// `password` — the iPSK, which is half of every password this relay has
// ever handed out. An empty ss-in is therefore not a dead inbound, it
// is an OPEN RELAY for every past recipient including revoked ones.
// That is why removeSSUser drops the whole inbound with its last user
// and why nothing here ever writes an ss inbound with no users.
//
// Idempotent: a recipient already present is left alone.
func appendSSUser(doc map[string]any, c userCreds) error {
	if c.SSUserPSK == "" {
		// Minted by mintCreds; empty means a caller built userCreds by
		// hand. Serving the recipient without their own uPSK is not an
		// option (see the open-relay note above), so skip rather than
		// write a broken row.
		return nil
	}
	if in := findInboundByTag(doc, tagSS); in != nil {
		users, _ := in["users"].([]any)
		for _, raw := range users {
			u, _ := raw.(map[string]any)
			if n, _ := u["name"].(string); n == c.Name {
				return nil // already present
			}
		}
		in["users"] = append(users, map[string]any{
			"name":     c.Name,
			"password": c.SSUserPSK,
		})
		return nil
	}
	// First shadowsocks recipient on this box: mint the box-wide iPSK
	// and create the inbound around them.
	ipsk, err := genSSKey()
	if err != nil {
		return err
	}
	inbound := map[string]any{
		"type":        "shadowsocks",
		"tag":         tagSS,
		"listen":      "0.0.0.0",
		"listen_port": ssListenPort,
		// TCP ONLY, and the client compensates with udp_over_tcp.
		// Opening 8446/udp as well would add a second fleet-wide
		// constant on a port that is not whitelisted egress in the
		// target country anyway, for UDP that hysteria2 already carries
		// natively where UDP survives at all. relayports.ExtraFirewallPorts
		// opens 8446/tcp and nothing else, so a UDP listener here would
		// bind a socket no packet can reach.
		"network":  "tcp",
		"method":   ssMethod,
		"password": ipsk,
		"users": []any{
			map[string]any{
				"name":     c.Name,
				"password": c.SSUserPSK,
			},
		},
		// NO `multiplex` block, and that is a protocol fact rather than
		// a preference. The client outbound must carry udp_over_tcp to
		// have any UDP at all on a TCP-only inbound, and sing-box's
		// shadowsocks outbound builds a UoT client OR a mux client and
		// never both (protocol/shadowsocks/outbound.go:64-77: the mux
		// dialer is constructed only `if !uotOptions.Enabled`). A
		// `multiplex` object alongside udp_over_tcp is not rejected —
		// it is silently IGNORED, which is worse. See
		// relaypack/multiplex.go familyCarriesMultiplex.
	}
	inbounds, _ := doc["inbounds"].([]any)
	doc["inbounds"] = append(inbounds, inbound)
	return nil
}

// removeSSUser removes the recipient's row from ss-in, dropping the
// whole inbound when the last user leaves.
//
// Dropping it is mandatory, not tidiness: an ss inbound with an empty
// users[] degrades to the single-user service keyed on the box-wide
// iPSK, which every pack this relay ever minted carries the first half
// of. "Revoke the last recipient" would then mean "open this relay to
// everyone previously revoked". See appendSSUser.
func removeSSUser(doc map[string]any, name string) bool {
	in := findInboundByTag(doc, tagSS)
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
			i, _ := raw.(map[string]any)
			if t, _ := i["tag"].(string); t == tagSS {
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

// ssInboundPSK returns the box-wide iPSK from the live ss-in inbound,
// or "" when the relay serves no shadowsocks.
//
// Read from the config rather than remembered, for the same reason
// coverSNI and wsInboundPath are: the config is what the box actually
// serves. The iPSK is minted once, at first-recipient time, and never
// rotated per recipient — rotating it would invalidate the shadowsocks
// half of EVERY distributed pack, which is a box-wide operation and not
// something a targeted revocation may do.
func ssInboundPSK(doc map[string]any) string {
	in := findInboundByTag(doc, tagSS)
	if in == nil {
		return ""
	}
	p, _ := in["password"].(string)
	return p
}

// ssUserPSK returns the named recipient's uPSK from the live ss-in
// inbound, or "" if the relay serves no shadowsocks or has no such row.
func ssUserPSK(doc map[string]any, name string) string {
	in := findInboundByTag(doc, tagSS)
	if in == nil {
		return ""
	}
	users, _ := in["users"].([]any)
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		if n, _ := u["name"].(string); n != name {
			continue
		}
		p, _ := u["password"].(string)
		return p
	}
	return ""
}

// ssClientPassword assembles the value the CLIENT outbound's `password`
// field must literally contain: "<iPSK>:<uPSK>". Returns "" unless BOTH
// halves are present, because a half-assembled password is a route that
// mints and cannot be dialled.
//
// The publisher never sees the two halves separately and never has to
// know the concatenation rule — this box is the only place that rule
// lives, exactly as the shared ws path is resolved here and echoed
// rather than recomputed there.
func ssClientPassword(doc map[string]any, name string) string {
	ipsk := ssInboundPSK(doc)
	upsk := ssUserPSK(doc, name)
	if ipsk == "" || upsk == "" {
		return ""
	}
	return ipsk + ":" + upsk
}

// readSSClientPassword loads the config and returns the recipient's
// assembled client password, or "" when it cannot be determined.
func readSSClientPassword(path, name string) string {
	doc, err := loadSingboxDoc(path)
	if err != nil {
		return ""
	}
	return ssClientPassword(doc, name)
}

// ssUserPresent reports whether the live config carries a shadowsocks
// row for this recipient. Used by the provision handler to decide
// whether to advertise ss_method at all: the publisher's rule is that a
// value the box does not send means "not served", never an inference
// from a value it does send.
func ssUserPresent(path, name string) bool {
	return readSSClientPassword(path, name) != ""
}

// ssMethodValid reports whether a method string is one this binary is
// willing to write into a config. Deliberately a whitelist of one: the
// operator-facing failure of a wrong method is a relay that does not
// boot.
func ssMethodValid(m string) bool {
	return strings.TrimSpace(m) == ssMethod
}
