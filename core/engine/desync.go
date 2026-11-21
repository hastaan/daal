package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"daal/bundle-go/bundle"
	"daal/core/desync"
	"daal/core/routestore"
)

// Hello desync (plan T2, core/desync) is wired into the config here, in
// the builder every connect goes through (BuildSingBoxConfig). Whether a
// route's connections are cut is decided, in this order:
//
//  1. a strategy handed to this one build (BuildSingBoxConfigWithDesync):
//     a side probe or a ladder attempt that must not change what the
//     main tunnel does next;
//  2. the run-time choice remembered for the route ON THE CURRENT
//     NETWORK (SetRouteDesync, SetDesyncNetwork): what the selection
//     ladder settled on for the network the phone is on — a strategy, or
//     Off to force it off where it was seen to hurt. A choice made on
//     another network is ignored (and dropped when the network changes);
//  3. otherwise OFF. A signed pack offer (family_specific_config._desync,
//     core/desync/pack.go) is only made AVAILABLE to the ladder
//     (PackDesyncOffer) — "apply": "always" included, which is held as an
//     offer while packAlwaysAllowed is false (below).
//
// With none of these the config is byte-for-byte what it was before this
// file existed: no route changes behaviour unless something turns desync
// on for it.
//
// Turned on, it is one extra outbound and one field: the route's
// outbound gets `"detour": "daal-desync"`, and outbounds[] gains
// `{"type":"daal-desync","tag":"daal-desync","strategy":{…}}`, which
// dials the relay and cuts the first flight (the TLS ClientHello) below
// the outbound's TLS library. The route outbound's own dialer options
// move onto the desync outbound with it (sing-box ignores them on an
// outbound that has a detour).

func init() { desync.SetLogger(LogInfo) }

// packAlwaysAllowed gates a pack's "apply": "always". The plan's rule
// (docs/blackout-tier-plan.md T2): the cut pattern is itself
// classifiable, so it is used in the ladder and remembered per network,
// never as a fleet-wide default — and the tls_fragment modifier
// (specs/modifiers/tls_fragment.md) has no PASS record yet. Until it
// does, "always" is read as "offer" and said so in the log. Flipping
// this is a reviewed change, not a pack's decision.
var packAlwaysAllowed = false

type desyncChoice struct {
	network string
	s       desync.Strategy
}

var routeDesync = struct {
	mu      sync.Mutex
	network string // the network the remembered choices belong to
	m       map[string]desyncChoice
}{m: map[string]desyncChoice{}}

// SetDesyncNetwork says which network the phone is on (the core calls
// it wherever it switches the path manager's active network). Choices
// remembered for another network stop applying and are dropped.
func SetDesyncNetwork(networkID string) {
	routeDesync.mu.Lock()
	defer routeDesync.mu.Unlock()
	if networkID == routeDesync.network {
		return
	}
	routeDesync.network = networkID
	for id, ch := range routeDesync.m {
		if ch.network != networkID {
			delete(routeDesync.m, id)
		}
	}
}

// SetRouteDesync remembers the run-time desync choice for one route on
// the current network (SetDesyncNetwork), until ClearRouteDesync or a
// network change. desync.Off forces desync off for the route. It applies
// from the route's next connect (the config is built per connect); a
// connected route is not touched. A side probe or a single attempt does
// NOT use this — it hands its strategy to BuildSingBoxConfigWithDesync,
// so the main tunnel's next reconnect is not changed by it.
func SetRouteDesync(routeID string, s desync.Strategy) error {
	n, err := s.Normalized()
	if err != nil {
		return err
	}
	routeDesync.mu.Lock()
	defer routeDesync.mu.Unlock()
	routeDesync.m[routeID] = desyncChoice{network: routeDesync.network, s: n}
	return nil
}

// ClearRouteDesync drops the run-time choice: the route goes back to
// OFF.
func ClearRouteDesync(routeID string) {
	routeDesync.mu.Lock()
	defer routeDesync.mu.Unlock()
	delete(routeDesync.m, routeID)
}

// ClearAllRouteDesync drops every run-time choice (a test, a reset).
func ClearAllRouteDesync() {
	routeDesync.mu.Lock()
	defer routeDesync.mu.Unlock()
	routeDesync.m = map[string]desyncChoice{}
}

func routeDesyncChoice(routeID string) (desync.Strategy, bool) {
	routeDesync.mu.Lock()
	defer routeDesync.mu.Unlock()
	ch, ok := routeDesync.m[routeID]
	if !ok || ch.network != routeDesync.network {
		return desync.Off, false
	}
	return ch.s, true
}

// PackDesyncOffer is the strategy the route's signed pack offers, for
// the ladder to try. desync.ErrNoOffer when the pack has none.
func PackDesyncOffer(row routestore.RouteRow) (desync.Offer, error) {
	return desync.OfferFromFamilyConfig([]byte(row.FamilySpecificConfigJSON))
}

// RouteCanDesync reports whether turning desync on for this route can
// change what a censor sees of its TLS hello — so the ladder, answering
// a tls_sni_or_cert_block_suspected failure, does not spend an attempt
// where nothing would change. RouteDesyncReason says why not.
func RouteCanDesync(row routestore.RouteRow, profile []byte) bool {
	return RouteDesyncReason(row, profile) == ""
}

// RouteDesyncReason is "" when the route's outbound can be put behind
// the desync detour AND opens with a TLS hello; otherwise a closed word
// (desyncApplicable's — "header_in_one_read" for shadowsocks, which a
// cut breaks — or "no_tls_hello" for an outbound that can be cut but
// sends no hello: plain vmess, ssh, socks, http).
func RouteDesyncReason(row routestore.RouteRow, profile []byte) string {
	var ob map[string]any
	if json.Unmarshal(profile, &ob) != nil {
		return "profile"
	}
	if why := desyncApplicable(row, ob); why != "" {
		return why
	}
	if !sendsTLSHello(ob) {
		return "no_tls_hello"
	}
	return ""
}

// sendsTLSHello: the outbound's connection opens with a TLS ClientHello
// (its own tls block, or a type whose protocol is a TLS handshake).
func sendsTLSHello(ob map[string]any) bool {
	switch ob["type"] {
	case "anytls", "shadowtls":
		return true
	}
	tls, _ := ob["tls"].(map[string]any)
	return tls != nil && tls["enabled"] == true
}

// desyncTypes are the outbound types whose connection to the relay is
// one TCP connection opened through sing-box's own dialer, which is what
// honours `detour`. Not here: naive (Cronet opens its own sockets), tor
// (a tor process), the UDP families (hysteria2, tuic: no TCP hello),
// endpoints (wireguard), and every type not named. shadowsocks is here
// (its dialer would honour the detour) and is still refused, by
// desyncApplicable: a cut first flight is one its server refuses.
var desyncTypes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	"anytls": true, "shadowtls": true, "http": true, "socks": true, "ssh": true,
}

// movedDialerKeys are the route outbound's dialer options
// (option.DialerOptions, sing-box 1.13.12) that sing-box IGNORES once the
// outbound has a detour (common/dialer NewWithOptions builds only the
// detour dialer then). They move to the desync outbound, which does the
// dialling. Not here: detour (ours), domain_resolver and the deprecated
// domain_strategy (the outer dialer still resolves with them), and
// tcp_fast_open (a reason not to apply: the first Write would ride the
// SYN, uncut). fallback_delay is copied, not moved: the outer resolver
// reads it too.
var movedDialerKeys = []string{
	"bind_interface", "inet4_bind_address", "inet6_bind_address", "bind_address_no_port",
	"protect_path", "routing_mark", "reuse_addr", "netns", "connect_timeout",
	"tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive", "tcp_keep_alive_interval",
	"udp_fragment", "network_strategy", "network_type", "fallback_network_type",
}

// desyncApplicable is "" when the outbound can be put behind the desync
// detour, else why not (a closed set of words, safe to log).
func desyncApplicable(row routestore.RouteRow, ob map[string]any) string {
	t, _ := ob["type"].(string)
	switch {
	case isUDPFamily(bundle.TransportFamily(row.TransportFamily)):
		return "udp_family"
	case endpointTypes[t]:
		return "endpoint"
	case !desyncTypes[t]:
		return "type_not_supported"
	case t == "shadowsocks":
		// Not merely nothing to gain (no hello: the stream is random
		// bytes from the first one, which no SNI filter can read): a cut
		// BREAKS the route. A shadowsocks-2022 server reads the client's
		// fixed-length request header with ONE Read and refuses the
		// connection when that Read returns less (sing-shadowsocks
		// shadowaead_2022 service.go newConnection and service_multi.go
		// NewConnection0: `n < len(header)` → ErrBadHeader, by design
		// against probing). Every preset sends a 1-byte first segment,
		// so the server's first Read sees 1 byte and resets: the censor
		// lab saw tcp_reset on 8446 for split1, sni-cut and chain while
		// the same route connected uncut. So no source — a ladder attempt,
		// a remembered choice, an explicit strategy, a pack offer —
		// may put it behind the detour.
		return "header_in_one_read"
	}
	if d, ok := ob["detour"]; ok && d != desync.Tag {
		return "already_detoured"
	}
	if tr, _ := ob["transport"].(map[string]any); tr != nil && tr["type"] == "quic" {
		return "quic_transport"
	}
	if ob["tcp_fast_open"] == true {
		return "tcp_fast_open"
	}
	// sing-box's own fragmenter (tls.fragment / tls.record_fragment)
	// writes the hello straight to the TCP socket under any wrapper
	// (common/tlsfragment unwraps to *net.TCPConn): desync would never
	// see the hello, and would cut the next record instead.
	if tls, _ := ob["tls"].(map[string]any); tls != nil && (tls["fragment"] == true || tls["record_fragment"] == true) {
		return "stock_fragment"
	}
	return ""
}

// desyncFor decides the strategy for one connect and names where it came
// from: "explicit", "override", or "" (OFF).
func desyncFor(row routestore.RouteRow, explicit *desync.Strategy) (desync.Strategy, string) {
	if explicit != nil {
		if !explicit.Enabled() {
			return desync.Off, ""
		}
		return *explicit, "explicit"
	}
	if s, ok := routeDesyncChoice(row.RouteID); ok {
		if !s.Enabled() {
			return desync.Off, ""
		}
		return s, "override"
	}
	o, err := PackDesyncOffer(row)
	if err != nil {
		if !errors.Is(err, desync.ErrNoOffer) {
			// Present and unusable: OFF, said once per connect. The
			// error is about the publisher's strategy, never a secret,
			// but only its class goes in the log, as everywhere here.
			LogInfo(fmt.Sprintf("desync: route=%s pack offer refused class=%s", LogID(row.RouteID), errorClassOf(err)))
		}
		return desync.Off, ""
	}
	if o.Apply == desync.ApplyAlways {
		if packAlwaysAllowed {
			return o.StrategyValue(), "pack"
		}
		LogInfo(fmt.Sprintf("desync: route=%s pack apply=always held as offer: modifier_not_passed", LogID(row.RouteID)))
	}
	return desync.Off, ""
}

// applyDesync puts the route's outbound behind the desync detour when
// desyncFor says so and the outbound allows it. It returns what it did
// ("applied", a desyncApplicable reason, or "" for OFF).
//
// A profile that names the desync outbound as its own detour (profile
// bytes are outside the pack signature) has that detour removed first:
// only this function puts it there, and only together with the outbound
// it names.
func applyDesync(cfg *SingBoxConfig, row routestore.RouteRow, ob map[string]any, explicit *desync.Strategy) string {
	if ob["detour"] == desync.Tag {
		delete(ob, "detour")
	}
	s, source := desyncFor(row, explicit)
	if source == "" {
		return ""
	}
	if why := desyncApplicable(row, ob); why != "" {
		LogInfo(fmt.Sprintf("desync: route=%s source=%s not applied: %s", LogID(row.RouteID), source, why))
		return why
	}
	strategy, err := strategyJSON(s)
	if err != nil {
		LogInfo(fmt.Sprintf("desync: route=%s source=%s not applied: render", LogID(row.RouteID), source))
		return "render"
	}
	ds := map[string]any{
		"type":     desync.Type,
		"tag":      desync.Tag,
		"strategy": strategy,
	}
	for _, k := range movedDialerKeys {
		if v, ok := ob[k]; ok {
			ds[k] = v
			delete(ob, k)
		}
	}
	delete(ob, "tcp_fast_open") // only a false one is left here
	if v, ok := ob["fallback_delay"]; ok {
		ds["fallback_delay"] = v
	}
	ob["detour"] = desync.Tag
	cfg.Outbounds = append(cfg.Outbounds, ds)
	LogInfo(fmt.Sprintf("desync: route=%s source=%s applied", LogID(row.RouteID), source))
	return "applied"
}

func strategyJSON(s desync.Strategy) (map[string]any, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

// ownDesyncDetour reports whether an outbound's detour is the engine's
// own desync outbound in the same config — which, unlike a detour to
// another proxy, adds no hop and no shared state: a side instance or a
// diagnosis twin of the outbound is as private as one without it.
func ownDesyncDetour(ob map[string]any, outbounds []map[string]any) bool {
	if ob["detour"] != desync.Tag {
		return false
	}
	for _, o := range outbounds {
		if o["tag"] == desync.Tag && o["type"] == desync.Type {
			return true
		}
	}
	return false
}

// errorClassOf is the Go type of the innermost error: a name, never a
// value.
func errorClassOf(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return fmt.Sprintf("%T", err)
		}
		err = inner
	}
}

// objects is the JSON-object members of a decoded JSON array.
func objects(list []any) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
