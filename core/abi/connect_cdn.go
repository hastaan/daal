package abi

// connect_cdn.go — the way in through Cloudflare on the recipient
// (optional add-ons B-6, B-6b; docs/optional-addons-plan.md §2.2, §4;
// specs/relaypack-v1.md "The CDN-fronted endpoint").
//
// A CDN-fronted route is an ordinary websocket-tls route in the store —
// its outbound unwrapped, its commitment the `_cdn_endpoint` object
// under endpoint:<id> (bundle.IsCDNCommitment tells it from a direct
// one). Three things set it apart in the automatic pass:
//
//  1. IT GOES LAST (cdnLast). After every direct route and after every
//     standby attempt: it is the one path a third party (the CDN) sees,
//     and the one that shows the CDN pattern on a network. The single
//     exception is position 1 of the plan's order — the route that
//     carried on this network last is tried first, whatever it is.
//
//  2. ITS EDGE ADDRESS IS PICKED ON THE DEVICE (core/edgepick). The
//     outbound's `server` is an address inside the signed edge seeds;
//     the attempt dials the edge this network last passed through
//     (cdnEdgeProfileLocked), and only when that address stops
//     answering — a connect timeout, a hello left unanswered, an
//     `address_blocked` refinement, or a connection cut after the
//     handshake — does the pass make one fresh pick (ladderRepick →
//     cdnRepickLocked): a few candidate addresses inside the seeds,
//     each probed with a neutral TLS name and an exchange of more than
//     ten packets, the first that carries it taken. Probes count
//     against the network's hourly side-probe allowance; the pick is
//     remembered per network (encrypted, edgepick:<network>).
//
//  3. ITS HELLO ORDER IS ITS OWN (cdnHelloList, B-6b): the route as
//     stored (ECH with the committed configuration); then the same ECH
//     hello with the outer hello split (tls.record_fragment +
//     tls.fragment); then stop. A plain hello — which shows the zone
//     name — only when the signed `plain_fallback` is set (owner
//     decision D-2), and last. No desync preset, no cover name.
//
// Every one of these moves the outbound, so the set-route guard runs
// again on what is dialled (variantBodyLocked): the edge must be inside
// the signed seeds, the hello must be the committed ECH configuration
// or a plain one the signature allows. Nothing signed is relaxed.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/diagnostics"
	"daal/core/edgepick"
	"daal/core/engine"
	"daal/core/fieldprobe"
	"daal/core/routestore"
	"daal/core/trust"
)

// The hellos of a CDN-fronted route besides its own (routeVariant.hello).
const (
	helloSplit = "split"
	helloPlain = "plain"
)

const (
	// cdnEdgeMemoryPrefix: the secrets_kv key (encrypted) of one
	// network's edge memory (edgepick.Memory).
	cdnEdgeMemoryPrefix = "edgepick:"
	// cdnProbeTimeout bounds one edge probe.
	cdnProbeTimeout = 4 * time.Second
)

// cdnEndpointLocked reads the route's stored commitment when it is a
// CDN-fronted one. Every reader of endpoint:<id> asks
// bundle.IsCDNCommitment first; one that is not CDN (or does not parse
// as one) is false here.
func (c *Core) cdnEndpointLocked(row routestore.RouteRow) (*bundle.CDNEndpoint, bool) {
	if c.store == nil {
		return nil, false
	}
	raw, err := c.store.GetSecret(trust.RouteEndpointKey(row.RouteID))
	if err != nil || len(raw) == 0 || !bundle.IsCDNCommitment(raw) {
		return nil, false
	}
	ep, err := bundle.ParseCDNEndpointJSON(row.TransportFamily, raw)
	if err != nil {
		return nil, false
	}
	return ep, true
}

// profileECH: the outbound has tls.ech.enabled.
func profileECH(profile []byte) bool {
	var ob struct {
		TLS *struct {
			ECH *struct {
				Enabled bool `json:"enabled"`
			} `json:"ech"`
		} `json:"tls"`
	}
	return json.Unmarshal(profile, &ob) == nil && ob.TLS != nil && ob.TLS.ECH != nil && ob.TLS.ECH.Enabled
}

// cdnHelloList is a CDN-fronted route's ladder after its own hello: the
// split ECH hello, then — only with the signed plain_fallback, and only
// when the route's own hello was an ECH one — a plain hello.
func cdnHelloList(lr ladderRoute) []routeVariant {
	if lr.cdn == nil {
		return nil
	}
	out := []routeVariant{{hello: helloSplit}}
	if lr.cdn.PlainFallback && lr.ech {
		out = append(out, routeVariant{hello: helloPlain})
	}
	return out
}

// variantOutbound is the outbound a standby or hello variant dials (the
// route's own for every other variant; buildVariant changes those at
// the config level). errVariantUnusable when the route has no such
// variant.
func variantOutbound(lr ladderRoute, v routeVariant) ([]byte, error) {
	switch {
	case v.standby:
		if v.hello != "" || v.preset != "" || v.name != 0 || lr.standby == "" || lr.cdn != nil {
			return nil, errVariantUnusable
		}
		return patchServer(lr.profile, lr.standby)
	case v.hello != "":
		if v.preset != "" || v.name != 0 || lr.cdn == nil {
			return nil, errVariantUnusable
		}
		return patchHello(lr, v.hello)
	}
	return lr.profile, nil
}

// patchHello is a CDN-fronted outbound with its first flight changed:
// split — the outer hello cut across records and segments; plain — no
// ECH, only when the signed endpoint allows it.
func patchHello(lr ladderRoute, hello string) ([]byte, error) {
	var ob map[string]any
	if err := json.Unmarshal(lr.profile, &ob); err != nil {
		return nil, errVariantUnusable
	}
	tls, _ := ob["tls"].(map[string]any)
	if tls == nil || tls["enabled"] != true {
		return nil, errVariantUnusable
	}
	switch hello {
	case helloSplit:
		tls["record_fragment"] = true
		tls["fragment"] = true
	case helloPlain:
		if !lr.cdn.PlainFallback || !lr.ech {
			return nil, errVariantUnusable
		}
		delete(tls, "ech")
	default:
		return nil, errVariantUnusable
	}
	return json.Marshal(ob)
}

// ---- the edge address -------------------------------------------------

// cdnEdges caches each network's edge memory for the Core that read it.
var cdnEdges = struct {
	mu   sync.Mutex
	core *Core
	mem  map[string]*edgepick.Memory
}{}

// cdnEdgeMemLocked is the edge memory of the network the device is on
// (a copy the caller may change and hand back with cdnEdgeSaveLocked).
func (c *Core) cdnEdgeMemLocked() *edgepick.Memory {
	net := activeNetworkID()
	cdnEdges.mu.Lock()
	defer cdnEdges.mu.Unlock()
	if cdnEdges.core != c {
		cdnEdges.core, cdnEdges.mem = c, map[string]*edgepick.Memory{}
	}
	if m, ok := cdnEdges.mem[net]; ok {
		return m.Clone()
	}
	var raw []byte
	if c.store != nil {
		raw, _ = c.store.GetSecret(cdnEdgeMemoryPrefix + net)
	}
	m := edgepick.Unmarshal(raw)
	cdnEdges.mem[net] = m
	return m.Clone()
}

// cdnEdgeSaveLocked keeps m as the network's edge memory (best effort:
// a store that cannot be written never fails a connect).
func (c *Core) cdnEdgeSaveLocked(m *edgepick.Memory) {
	net := activeNetworkID()
	cdnEdges.mu.Lock()
	if cdnEdges.core != c {
		cdnEdges.core, cdnEdges.mem = c, map[string]*edgepick.Memory{}
	}
	cdnEdges.mem[net] = m.Clone()
	cdnEdges.mu.Unlock()
	if c.store != nil {
		_ = c.store.PutSecret(cdnEdgeMemoryPrefix+net, m.Marshal())
	}
}

// cdnEdgeLocked is the edge address a CDN-fronted route dials on this
// network: the one that last passed here, inside the route's seeds.
func (c *Core) cdnEdgeLocked(ep *bundle.CDNEndpoint) (string, bool) {
	a, ok := c.cdnEdgeMemLocked().GoodIn(ep.EdgeSeedPrefixes(), nowUTC())
	if !ok || !ep.InEdgeSeeds(a.String()) {
		return "", false
	}
	return a.String(), true
}

// cdnEdgeProfileLocked is the route's outbound at the edge address
// picked for this network, when there is one and it differs from the
// stored one.
func (c *Core) cdnEdgeProfileLocked(lr ladderRoute) ([]byte, bool) {
	edge, ok := c.cdnEdgeLocked(lr.cdn)
	if !ok {
		return nil, false
	}
	if host, _, _ := profileRelay(lr.profile); host == edge {
		return nil, false
	}
	moved, err := patchServer(lr.profile, edge)
	if err != nil {
		return nil, false
	}
	return moved, true
}

// cdnDialAddrLocked is the edge address the route's attempts dial on
// this network now (the picked one, else the stored outbound's).
func (c *Core) cdnDialAddrLocked(routeID string) (netip.Addr, *bundle.CDNEndpoint, []byte, bool) {
	row, profile, ok := c.routeRowProfile(routeID)
	if !ok {
		return netip.Addr{}, nil, nil, false
	}
	ep, ok := c.cdnEndpointLocked(row)
	if !ok {
		return netip.Addr{}, nil, nil, false
	}
	host, _, _ := profileRelay(profile)
	if edge, ok := c.cdnEdgeLocked(ep); ok {
		host = edge
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, ep, profile, false
	}
	return a, ep, profile, true
}

// cdnEdgeCarriedLocked: a CDN-fronted route carried; the edge it went
// through is this network's good one.
func (c *Core) cdnEdgeCarriedLocked(routeID string) {
	a, _, _, ok := c.cdnDialAddrLocked(routeID)
	if !ok {
		return
	}
	m := c.cdnEdgeMemLocked()
	m.Note(a, true, nowUTC())
	c.cdnEdgeSaveLocked(m)
}

// cdnEdgeShaped: the attempt says the EDGE address stopped answering —
// not the name (a reset at the hello is the hello ladder's).
func cdnEdgeShaped(o autoObs, refined string) bool {
	if o.udp || o.unplaced || o.result != AutoResultNotCarrying {
		return false
	}
	switch {
	case o.synUnanswered(), refined == AutoRefinedAddressBlocked:
		return true
	case o.stoppedAtHello() && o.obs.Timeout && !o.obs.Reset && !o.obs.Closed:
		return true
	case o.obs.Phase == diagnostics.PhaseCarry && (o.obs.Reset || o.obs.Timeout || o.obs.Closed):
		// Through the handshake, then cut: the grey budget some edge
		// addresses get.
		return true
	}
	return false
}

// ladderRepick returns the one fresh-edge attempt of a CDN-fronted
// route whose attempt o says its edge stopped answering. The pick
// itself is made when the attempt comes up (cdnRepickLocked), with the
// lock released. Counted against the per-pass and hourly limits here.
func (p *autoPass) ladderRepick(rl *routeLadder, o autoObs, refined string) (autoCandidate, bool) {
	if rl.repicked || !cdnEdgeShaped(o, refined) {
		return autoCandidate{}, false
	}
	p.ladderBuild(rl, p.c.routeMemory(), nowUTC())
	if rl.lr.cdn == nil {
		return autoCandidate{}, false
	}
	rl.repicked = true
	l := p.ladderState()
	if l.variants >= ladderPerPass || !p.c.ladderBudgetLocked() {
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s edge stop=budget", engine.LogID(rl.base.routeID)))
		return autoCandidate{}, false
	}
	p.c.ladderNoteLocked()
	l.variants++
	cd := rl.base
	cd.variant, cd.ladder, cd.why, cd.proved, cd.repick = routeVariant{}, true, AutoWhyLadder, false, true
	engine.LogInfo(fmt.Sprintf("auto ladder route=%s next edge=pick", engine.LogID(rl.base.routeID)))
	return cd, true
}

// cdnProber is the real edge prober; a variable so a test can stand in
// for the network.
var cdnProber = func(c *Core, roots *x509.CertPool) edgepick.Prober {
	n := fieldprobe.SysNet{Protect: fieldProbeProtect(c)}
	return edgepick.Exchange{Dial: n.DialTCP, Roots: roots}
}

// cdnRepickLocked makes the fresh edge pick of a repick attempt: the
// address its last attempt dialled is noted as failed on this network,
// and a recorded pass inside the seeds, or else a probed candidate, is
// the route's edge from now on. Called with Core.mu held; RELEASES it
// for the probes (a pass already releases it for every connection
// check), and registers the probes as the pass's race so whoever takes
// the engine stops them (cancelRaceLocked). false: nothing passed, or
// the pass is no longer in charge (p.cancelled is then set).
func (p *autoPass) cdnRepickLocked(cd autoCandidate) bool {
	c := p.c
	failed, ep, profile, _ := c.cdnDialAddrLocked(cd.routeID)
	if ep == nil {
		return false
	}
	// Probes left in this network's hourly allowance.
	left := 0
	for left < edgepick.DefaultMaxProbes && c.ladderBudgetN(left+1) {
		left++
	}
	mem := c.cdnEdgeMemLocked()
	in := edgepick.PickInput{
		Seeds:        ep.EdgeSeedPrefixes(),
		Port:         ep.Port,
		Salt:         cdnPickSalt(cd.routeID),
		Failed:       failed,
		Mem:          mem,
		Prober:       cdnProber(c, rootsOf(profile)),
		MaxProbes:    left,
		ProbeTimeout: cdnProbeTimeout,
		Now:          nowUTC(),
	}
	if left == 0 {
		// Only a recorded pass may be used: nothing is probed.
		in.Prober = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.race = &raceHandle{cancel: cancel}
	gen := p.gen
	c.mu.Unlock()
	res, err := edgepick.Pick(ctx, in)
	c.mu.Lock()
	cancel()
	if c.race != nil && c.auto.gen == gen {
		c.race = nil
	}
	for i := 0; i < res.Probed; i++ {
		c.ladderNoteLocked()
	}
	if !p.mine() {
		p.abandon(cd)
		return false
	}
	c.cdnEdgeSaveLocked(mem)
	if err != nil || !res.OK || !ep.InEdgeSeeds(res.Addr.String()) {
		engine.LogInfo(fmt.Sprintf("auto ladder route=%s edge=none probed=%d", engine.LogID(cd.routeID), res.Probed))
		return false
	}
	engine.LogInfo(fmt.Sprintf("auto ladder route=%s edge=picked probed=%d remembered=%t", engine.LogID(cd.routeID), res.Probed, res.FromMemory))
	return true
}

// ladderBudgetN: n more side probes fit in this network's hourly
// allowance (the ladder's count, which works without a side prober).
func (c *Core) ladderBudgetN(n int) bool {
	net, now := activeNetworkID(), nowUTC()
	k := 0
	for _, t := range c.side.perNet[net] {
		if now.Sub(t) < time.Hour {
			k++
		}
	}
	return k+n <= sideProbesPerHour
}

// cdnPickSalt makes a route's candidate list this network's: a digest
// of both (never shown).
func cdnPickSalt(routeID string) string {
	sum := sha256.Sum256([]byte("daal/edge-salt|" + activeNetworkID() + "|" + routeID))
	return hex.EncodeToString(sum[:8])
}

// rootsOf is the pool of the roots a CDN-fronted outbound installs
// (tls.certificate): the edge must prove itself with exactly those to
// pass a probe. nil when it installs none (the platform's then).
func rootsOf(profile []byte) *x509.CertPool {
	var ob struct {
		TLS *struct {
			Certificate json.RawMessage `json:"certificate"`
		} `json:"tls"`
	}
	if json.Unmarshal(profile, &ob) != nil || ob.TLS == nil || len(ob.TLS.Certificate) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(ob.TLS.Certificate, &list) != nil {
		var one string
		if json.Unmarshal(ob.TLS.Certificate, &one) != nil {
			return nil
		}
		list = []string{one}
	}
	pool := x509.NewCertPool()
	rest := []byte(strings.Join(list, "\n"))
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
			pool.AddCert(cert)
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return pool
}

// cdnLast moves the CDN-fronted candidates of a pass after every other
// one, keeping each group's order — except a CDN-fronted route that is
// the pass's first candidate because it carried on this network last
// (plan §4 position 1).
func cdnLast(cands []autoCandidate) []autoCandidate {
	var direct, cdn []autoCandidate
	for i, cd := range cands {
		if cd.cdn && !(i == 0 && cd.why == AutoWhyCarriedHere) {
			cdn = append(cdn, cd)
			continue
		}
		direct = append(direct, cd)
	}
	return append(direct, cdn...)
}
