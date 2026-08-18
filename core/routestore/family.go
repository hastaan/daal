package routestore

// Phase 3A. Family taxonomy + maturity table.
//
// Locked at the start of Phase 3A per
// specs/transport-families-v1.md. The set of valid family values
// is a CLOSED list; adding a value is a roadmap-level decision and
// requires a fresh soak run. The bundle parser
// (`bundle/go/bundle/sbp.go::validTransport`) is the gatekeeper.
//
// Every family enters at Experimental maturity. The experimental
// gate is consulted by `core/pathmanager/family_filter.go` before
// the trust / budget / network-memory layers; with the gate OFF,
// experimental-maturity routes are filtered out of selection
// entirely, but remain visible in `ListRoutes` (so the UI can
// render the Experimental badge on the route card).
//
// The V0 `other` value remains accepted at parse time for forward
// compatibility but is never selected by the path manager — its
// maturity is `Unhandled` here, distinct from `Stable`.

// Maturity is the per-family lifecycle level governing whether
// the family is selectable without the user-toggled experimental
// gate.
type Maturity int

const (
	// MaturityUnhandled is the entry for the V0 `other` value.
	// The bundle parser accepts it (forward compatibility) but
	// the path manager never selects it — there is no engine-side
	// handler.
	MaturityUnhandled Maturity = iota

	// MaturityUnsupported means: this build physically cannot dial
	// the family. The value exists so the UI can say "this build
	// cannot dial it" instead of the misleading "experimental",
	// which invites the user to flip the experimental gate and
	// watch every route of that family fail identically.
	//
	// The distinction from MaturityUnhandled is provenance, not
	// behaviour: `Unhandled` is the forward-compat slot for a
	// family value this build has never heard of; `Unsupported` is
	// a family this build knows by name and has verified it cannot
	// carry. Both are unselectable.
	MaturityUnsupported

	// MaturityExperimental is the entry maturity for every new
	// V3+ family. Routes are filtered out of selection unless
	// the per-engine experimental gate is enabled. Auto-promotion
	// (2G) cannot promote into a network whose only available
	// routes are experimental.
	MaturityExperimental

	// MaturityPromotionCandidate is reserved at 3A. No family
	// ships at this level until a roadmap-level decision; the
	// constant exists so 3B–3G ship into a stable shape.
	MaturityPromotionCandidate

	// MaturityStable is the V1 baseline level. Family is
	// selectable in any build with the appropriate handler
	// compiled in.
	MaturityStable
)

// String renders a maturity value as the diagnostics-stable
// snake-case label.
func (m Maturity) String() string {
	switch m {
	case MaturityUnhandled:
		return "unhandled"
	case MaturityUnsupported:
		return "unsupported"
	case MaturityExperimental:
		return "experimental"
	case MaturityPromotionCandidate:
		return "promotion-candidate"
	case MaturityStable:
		return "stable"
	default:
		return "unknown"
	}
}

// familyMaturity is the locked V3 taxonomy. The map's keys
// correspond 1:1 with the closed enum exposed by the bundle
// parser; missing keys (a family present in the bundle parser
// but not here) is a build-time bug, asserted by the
// TestFamilyTaxonomyMatchesBundleParser regression.
//
// Phase 3A locks this map. Adding a family requires:
//  1. A roadmap-level decision.
//  2. A new entry here at MaturityExperimental.
//  3. A widening of the bundle parser's validTransport list.
//  4. A fresh soak run.
var familyMaturity = map[string]Maturity{
	// The four field-proven tiers. Each has a publisher-side client
	// outbound renderer (`publisher/deploy/relaypack/client_outbound.go`
	// has a `case` for exactly these four), a relay inbound, a port
	// assignment, and has carried real traffic on-device.
	"vless-reality": MaturityStable,
	"naive":         MaturityStable,
	"websocket-tls": MaturityStable,
	"hysteria2":     MaturityStable,

	// Demoted from Stable in the Wave-1 honesty pass, and STILL
	// Experimental after Wave 5 — for a reason that changed underneath
	// them, so read the current one rather than the remembered one.
	//
	// The Wave-1 reason was that nothing minted these: no
	// `client_outbound.go` renderer, no relay inbound. That is no
	// longer true of shadowsocks. Wave 5 built the whole chain —
	// ss-in on the box (2022-blake3-aes-128-gcm, per-recipient uPSKs),
	// 8446/tcp in both firewalls, a client outbound the strict parser
	// accepts, rotation — so a shadowsocks route now mints and is
	// dialable.
	//
	// It stays Experimental anyway, and PROMOTING IT WOULD BE A LIE OF
	// THE EXACT KIND THIS TABLE EXISTS TO PREVENT. Stable asserts a
	// track record: real traffic, on real devices, over time. This
	// family has carried none. It also has a specific, known weakness
	// the other tiers do not — shadowsocks is the most-studied protocol
	// in the entropy and packet-length classification literature, and
	// 2022-blake3 closes the active-probing hole without touching the
	// "high-entropy from byte one" signature. Its value is that it has
	// no TLS handshake, so it fails INDEPENDENTLY of the three TLS
	// tiers when a nested-TLS classifier comes for them; that is
	// diversity, not strength, and the badge must not say otherwise.
	//
	// tuic's reason changed too, and in the same direction. Wave 5 built
	// its chain as well — an opt-in tuic-in inbound on the box
	// (8443/udp, uuid+password per recipient, mandatory h3 ALPN because
	// sing-quic's tuic — unlike its hysteria2 — sets no default and
	// quic-go refuses a TLS config without one), 8443/udp opened in both
	// firewalls only on relays that serve it, a client outbound the
	// strict parser accepts, rotation. So tuic now mints and is dialable
	// too.
	//
	// IT STAYS EXPERIMENTAL, AND IN THE PRIMARY TARGET COUNTRY IT IS
	// WORTH APPROXIMATELY NOTHING. Two independent reasons, both
	// structural:
	//   - Port. 8443 is outside the 53/80/443 egress whitelist, exactly
	//     like naive on 8444 and websocket-tls on 8445. relayports says
	//     so in its own words.
	//   - Protocol. It is UDP, and the adversary document states the
	//     intent as complete and permanent blocking of outbound IPv6,
	//     UDP and ICMP. Daal already ships one UDP tier — hysteria2 —
	//     and a second one falls to the same rule at the same moment,
	//     so this is not a second lifeline, it is the same lifeline
	//     twice.
	// What tuic buys is a differently-shaped QUIC handshake on networks
	// where UDP still works: correlation-breaking diversity ELSEWHERE.
	// Any user-visible copy that implies a new way through the
	// whitelist is wrong.
	//
	// NOTE what this does and does not change. It changes the badge the
	// UI draws and the posture abi.go:368 selects. It does NOT stop the
	// selector picking these routes: the 3A experimental filter
	// (pathmanager/family_filter.go ExperimentalFilter /
	// RankWithExperimentalGate) has no production caller — only tests —
	// so `experimental_families_enabled` is a stored preference nothing
	// consults at rank time. Wiring that is selection work; do not
	// assume it happened.
	"tuic":        MaturityExperimental,
	"shadowsocks": MaturityExperimental,

	// Wave 5. wireguard was Unsupported because the config this build
	// writes could not express it at all: sing-box models WireGuard as
	// an `endpoints[]` adapter and SingBoxConfig had no Endpoints
	// field, while the importer emitted the 1.x OUTBOUND shape that
	// sing-box 1.13.0 removed (include/registry.go answers it with
	// "WireGuard outbound is deprecated … use WireGuard endpoint
	// instead"). Both halves are fixed: core/engine/config.go has the
	// Endpoints slot and routes an endpoint-typed profile into it, and
	// bundle/go/uri/wireguard.go emits a real WireGuardEndpointOptions
	// object (address/private_key/peers[] with allowed_ips — not the
	// old `reserved`, which is the three-byte WARP header). The shipped
	// Android engine is built with `with_wireguard`
	// (tools/build-engine-android.sh), so the endpoint is registered
	// for real; without that tag include/wireguard_stub.go refuses at
	// dial with a message naming the missing tag.
	//
	// EXPERIMENTAL, AND THE LABEL HAS TO CARRY BOTH FACTS AT ONCE:
	//   - The corpus rates AmneziaWG (WireGuard plus obfuscation) the
	//     most resilient transport measured in Iran, working there AND
	//     in China, and the one thing that survived the June 2025
	//     blackout. That is the good half, and it is real.
	//   - The adversary document names WireGuard-shaped traffic as an
	//     explicit, immediate-block target, and WireGuard is UDP, which
	//     the same document states the intent to block completely and
	//     permanently. PLAIN WireGuard — which is all this build can
	//     dial — is the half of that pair with none of the obfuscation
	//     that earned the good half its reputation.
	// So: a WireGuard route is worth having where WireGuard is allowed,
	// and is among the FIRST things to die where it is not. No copy may
	// borrow AmneziaWG's Iran track record for it.
	//
	// Daal does not SERVE this family: there is no relay inbound, no
	// per-recipient credential, no firewall rule and no toolbox-profile
	// candidate. It exists only for a route the user pasted or imported
	// from somewhere else.
	"wireguard": MaturityExperimental,

	// amneziawg STAYS UNSUPPORTED, and this is the honest answer rather
	// than the convenient one. sing-box 1.13.12 contains no AmneziaWG
	// code whatsoever — `grep -ri amnezia` over the module returns
	// nothing — so there is no field to put Jc/Jmin/Jmax/S1/S2/H1..H4
	// in and no way to produce the obfuscation that IS the family.
	// The importer therefore degrades an AmneziaWG conf to a plain
	// WireGuard endpoint and says so loudly (uri.Provenance.Downgrade,
	// DroppedParams); the resulting route is labelled `wireguard`,
	// because WireGuard is what goes on the wire.
	//
	// Keeping the value at Unsupported means: a pack that DECLARES the
	// amneziawg family is unselectable and the UI says this build
	// cannot dial it — which is true, and is a much better outcome than
	// an amneziawg badge over a WireGuard-shaped flow. Promoting it
	// requires an engine that actually implements AmneziaWG, not a
	// relabelling.
	"amneziawg": MaturityUnsupported,

	// Wave 5. Promoted out of Unsupported: the importer now emits
	// sing-box's real `tor` outbound instead of the invented
	// `"type":"tor-bridge"` that the strict parser rejected, and the
	// engine materialises the device paths tor needs
	// (core/engine/torconfig.go). The shipped engine registers the
	// outbound unconditionally — sing-box 1.13.12 include/registry.go:88,
	// no build tag — so the CLIENT half is real.
	//
	// STILL UNSUPPORTED, AND THIS IS THE REPAIR PASS CORRECTING THE TOR
	// LANE'S OWN LABEL. The client CODE is real; the client ARTIFACT is
	// not. The `tor` outbound execs a tor binary, and no build this
	// repository can produce contains one:
	//
	//   - jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64} contain only
	//     libcronet, libdaalcore, libdaal_deploy and the Tauri lib. No
	//     libtor.so, liblyrebird.so, libwebtunnel.so or libsnowflake.so
	//     for any ABI.
	//   - tools/build-tor-android.sh is invoked by no build script, no
	//     gradle file and no CI step, and says in its own header
	//     "STATUS: NEVER RUN" and "libtor.so is NOT built by this
	//     script".
	//   - On desktop the resolver was broken too — it looked for the
	//     Android-shaped name `libtor.so` next to the executable and
	//     could never reach its own documented "fall back to `tor` on
	//     PATH" branch. The repair pass fixed that
	//     (core/engine/torbin.go lookDesktopBinary), so a Linux desktop
	//     with the distro `tor` and `lyrebird` packages installed can
	//     now resolve the binaries.
	//
	// THE LABEL IS ONE GLOBAL VALUE AND ANDROID IS THE PLATFORM WE
	// SHIP. A desktop that happens to have tor installed is not an
	// artifact Daal distributes; the APK is, and it cannot dial this
	// family at all. Grading Experimental on the strength of a
	// dependency the user may have installed themselves would put a ⚡
	// badge in front of every phone user for whom the route is
	// guaranteed to fail. That is this table's definition of
	// Unsupported — "this build physically cannot dial the family" —
	// and the MaturityUnsupported doc comment names precisely this
	// case: Experimental invites the user to flip the experimental gate
	// and watch every route fail identically.
	//
	// FLIP THIS TO Experimental IN THE SAME COMMIT THAT PACKAGES THE
	// BINARIES, not before and not in advance of them — the same
	// discipline publisher/deploy/profiles/loader.go applies to the
	// relay artifact pin. What has to become true: libtor.so plus the
	// PT binaries, position-independent executables, present in jniLibs
	// for every shipped ABI (see the PACKAGING REQUIREMENT block in
	// core/engine/torbin.go), and a desktop resolver that can find a
	// system `tor`.
	//
	// Note this family is PUBLISHER-INDEPENDENT: no relay inbound, no
	// per-recipient credentials, no firewall rule. It is the only route
	// Daal could offer with no Daal relay in existence — which is why
	// it is worth finishing, and why mislabelling it early costs more
	// than waiting.
	"tor-bridge": MaturityUnsupported,

	// The V3 families, ALL demoted from Experimental to
	// Unsupported in the Wave-5 honesty pass. This is the same
	// correction Wave 1 applied to wireguard, amneziawg and
	// tor-bridge — two of which other Wave-5 lanes have since
	// repaired for real — and it is the larger half of it: seven
	// families were sitting
	// at Experimental — a label that means "unproven, may fail" —
	// when the truth is "cannot be dialled by this build at all,
	// and in three cases cannot be dialled by any build we could
	// ship". Experimental invites the user to flip the
	// experimental gate; there is nothing behind it to flip on.
	//
	// The engine's outbound registry is the arbiter, not the
	// roadmap. sing-box 1.13.12 `include/registry.go` registers:
	// direct, block, selector, urltest, socks, http, shadowsocks,
	// vmess, trojan, naive, tor, ssh, shadowtls, vless, anytls,
	// plus hysteria/hysteria2/tuic under `with_quic` (which the
	// android/ios build scripts do pass). Nothing else exists.
	//
	//   - webtunnel: no webtunnel outbound, and it will never get
	//     one, because it is a Tor PLUGGABLE TRANSPORT rather than
	//     a protocol of its own. It DOES arrive in this build —
	//     as `Bridge webtunnel ...` inside a `tor-bridge` route,
	//     dispatched to libwebtunnel.so by core/engine/torbin.go.
	//     So the capability is reachable and the FAMILY VALUE is
	//     not: a pack declaring `transport_family: "webtunnel"`
	//     has no dialer, while the identical bridge declared as
	//     `tor-bridge` works. Separately re-scoped downward:
	//     webtunnel is effective in China and FAILS in Iran, our
	//     primary target.
	//   - snowflake: exactly the same shape — no snowflake
	//     outbound, reachable only as `Bridge snowflake ...` under
	//     `tor-bridge` (libsnowflake.so). The Phase 3B WebRTC
	//     state machine that would have made it a first-class
	//     family was deleted in Wave 5; we are not vendoring
	//     pion/webrtc into core/go.mod for a transport the tor
	//     outbound already carries.
	//   - masque: no masque outbound in 1.13.12, AND nothing worth
	//     serving — MASQUE's value is riding a large provider's
	//     CONNECT-UDP infrastructure, which a self-hosted
	//     publisher does not have.
	//   - psiphon: a third party's proprietary NETWORK. You can
	//     hand off to it; you cannot host it. No server side
	//     exists for a publisher to run, and psiphon-tunnel-core
	//     has never been in `core/go.mod`.
	//   - conjure: refraction networking needs a COOPERATING ISP
	//     running a station on a transit link. A publisher renting
	//     a VPS has no link to tap and no space to phantom into.
	//     gotapdance has never been in `core/go.mod` either.
	//   - transport_module: the wazero runtime IS real and IS
	//     compiled in (`core/wasm`), which makes this the one
	//     genuine "not yet" of the six — but `core/wasm.Dial` has
	//     no production caller (only tests), and nothing turns a
	//     module into a sing-box outbound the engine config can
	//     hold. Until something does, a transport_module route
	//     cannot carry a byte.
	//   - lifeline_relay: `core/lifelinerelay` does not exist. The
	//     3G plan is partner-operated and conditional; there is no
	//     code at all.
	//
	// psiphon, conjure and masque are STRUCTURAL — they stay
	// Unsupported until an external relationship changes, not
	// until we write code. The reasons are on the enum values in
	// `bundle/go/bundle/types.go` so they are not re-litigated.
	// webtunnel and snowflake are permanent at this value for a
	// different reason: their capability lives under `tor-bridge`,
	// so the right fix for a user holding a webtunnel bridge is to
	// import it as a tor-bridge route, never to teach the engine a
	// second spelling. transport_module moves when core/wasm gets
	// a production dial path.
	"webtunnel":        MaturityUnsupported,
	"snowflake":        MaturityUnsupported,
	"masque":           MaturityUnsupported,
	"psiphon":          MaturityUnsupported,
	"conjure":          MaturityUnsupported,
	"transport_module": MaturityUnsupported,
	"lifeline_relay":   MaturityUnsupported,

	// Wave 5. anytls — the only family whose length padding and
	// session reuse are protocol features rather than add-ons
	// (option/anytls.go). The shipped engine registers the outbound
	// unconditionally (sing-box 1.13.12 include/registry.go:92, no
	// build tag), the publisher mints per-recipient credentials, the
	// box serves an anytls-in inbound, and relayports assigns it a
	// port — so unlike tuic/shadowsocks-before-Wave-5 the whole chain
	// exists.
	//
	// EXPERIMENTAL, NOT STABLE, and the missing piece is a track
	// record, not code: nothing in this repository has dialled an
	// anytls route on a device. "Stable" in this table means the four
	// tiers that have carried real traffic, and claiming it here would
	// be exactly the overstatement the Wave-1 honesty pass removed
	// from tuic and shadowsocks. Promote only after a soak.
	"anytls": MaturityExperimental,

	// V0 forward-compat slot.
	"other": MaturityUnhandled,
}

// familyOpportunistic is the locked-at-3D opportunistic-family
// table. Auto-promotion (2G) consults this map: a network whose
// only available family is opportunistic is treated as having
// no auto-promotable routes.
//
// The defaults reflect the per-family operational posture:
//   - MASQUE (3C): opportunistic — sub-modes degrade through
//     UDP probing; never the steady-state choice on a network
//     where another family works.
//   - Conjure (3D): opportunistic — phantom-IPv6 stations are
//     partner-operated and capacity-rated for displacement,
//     not for steady state.
//   - Psiphon (3D): NOT opportunistic — Psiphon-the-org's
//     protocol-class is battle-tested at scale; auto-promotion
//     into a Psiphon-only network is acceptable.
//   - All other families default to NOT opportunistic.
//
// Locked at Phase 3D per `specs/transport-families-v1.md` 3D
// amendment. Re-classifying a family is a roadmap-level
// decision.
var familyOpportunistic = map[string]bool{
	"masque":  true, // 3C; retroactively annotated at 3D.
	"conjure": true, // 3D.
}

// IsOpportunisticFamily reports whether a family is treated as
// opportunistic by the 2G auto-promotion detector. Unknown
// families return false; treating an unknown family as
// non-opportunistic is the conservative default (auto-promotion
// considers it eligible, which means burn-pressure detection
// runs normally).
func IsOpportunisticFamily(family string) bool {
	return familyOpportunistic[family]
}

// FamilyMaturity returns the maturity for a given family value.
// Unknown families return MaturityUnhandled — the path manager
// treats unknown families as unselectable, so an out-of-sync
// older client that imported a future-family bundle simply
// skips the route rather than crashing.
func FamilyMaturity(family string) Maturity {
	if m, ok := familyMaturity[family]; ok {
		return m
	}
	return MaturityUnhandled
}

// IsExperimentalFamily is the hot-path predicate consulted by
// the pathmanager's experimental filter. Equivalent to
// `FamilyMaturity(f) == MaturityExperimental`; the dedicated
// helper exists so the filter site reads cleanly.
func IsExperimentalFamily(family string) bool {
	return FamilyMaturity(family) == MaturityExperimental
}

// IsUnsupportedFamily reports whether this build knows the family
// by name and has verified it cannot dial it. Distinct from
// "unknown family" (MaturityUnhandled) so the UI can render a
// definite "this build cannot dial it" rather than a hedged
// "experimental" or a silent omission.
func IsUnsupportedFamily(family string) bool {
	return FamilyMaturity(family) == MaturityUnsupported
}

// IsSelectableFamily reports whether a family is even
// in-principle selectable by the path manager, ignoring the
// experimental gate. False for the V0 `other` slot, for families
// this build cannot dial (MaturityUnsupported), and for any
// family the bundle parser has accepted but the engine doesn't
// know about.
func IsSelectableFamily(family string) bool {
	m := FamilyMaturity(family)
	return m == MaturityExperimental ||
		m == MaturityPromotionCandidate ||
		m == MaturityStable
}

// KnownFamilies returns a stable-sorted list of every family in
// the locked taxonomy. Used by the regression test that asserts
// the routestore taxonomy and the bundle parser's accepted-enum
// list never drift apart.
func KnownFamilies() []string {
	out := make([]string, 0, len(familyMaturity))
	for f := range familyMaturity {
		out = append(out, f)
	}
	// Stable order so test diffs are readable.
	sortStrings(out)
	return out
}

// sortStrings is a stdlib-free string sort kept here so this
// file has no transitive imports beyond the package — the
// taxonomy is consulted from many call sites and we keep its
// import graph minimal.
func sortStrings(s []string) {
	// Insertion sort; the list is ~17 entries.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
