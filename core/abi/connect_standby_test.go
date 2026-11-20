package abi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/trust"
)

// The standby address on the recipient (connect_standby.go, standby.go).

// The test vector of specs/relaypack-v1.md: salt 00..0b, 203.0.113.20.
const (
	sbKeyText = "000G40 R40M3 0E209 185WP 03H2G"
	sbCommit  = "oLKATgHpOx6iddfCqnGCuDAi1XSE7ysXDZ1tUmE5HHY="
	sbAddr    = "203.0.113.20"
	sbSealed  = `{"v":1,"mode":"sealed","commit":"` + sbCommit + `"}`
	sbOpen    = `{"v":1,"mode":"open","server":"` + sbAddr + `"}`
)

const (
	sbPrimaryREALITY = `{"type":"vless","server":"198.51.100.10","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"cover.example","reality":{"enabled":true,"public_key":"pk","short_id":"ab"}}}`
	sbOtherREALITY   = `{"type":"vless","server":"198.51.100.30","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"cover.example","reality":{"enabled":true,"public_key":"pk2","short_id":"ab"}}}`
	sbShadowsocks    = `{"type":"shadowsocks","server":"198.51.100.10","server_port":8446,"method":"2022-blake3-aes-128-gcm","password":"a:b"}`
)

// packRoute makes a seeded route part of a RelayPack and stores its
// signed endpoint, as an import does.
func packRoute(t *testing.T, c *Core, id, pack string) {
	t.Helper()
	row, err := c.store.GetRoute(id)
	if err != nil {
		t.Fatal(err)
	}
	row.RelayPackID = pack
	if err := c.store.UpsertRoute(row); err != nil {
		t.Fatal(err)
	}
	profile, err := c.store.GetSecret("route:" + id)
	if err != nil {
		t.Fatal(err)
	}
	var ep []byte
	if row.TransportFamily == "shadowsocks" {
		ep, _ = json.Marshal(bundle.Endpoint{V: bundle.EndpointVersion, Server: "198.51.100.10", Port: 8446,
			SSMethod: "2022-blake3-aes-128-gcm", SSServerKeySHA256: bundle.SSServerKeyDigest("a")})
	} else {
		ep = endpointOf(t, row.TransportFamily, profile)
	}
	if err := c.store.PutSecret(trust.RouteEndpointKey(id), ep); err != nil {
		t.Fatal(err)
	}
}

func putStandby(t *testing.T, c *Core, id, sb string) {
	t.Helper()
	if err := c.store.PutSecret(bundle.StandbyStoreKey(id), []byte(sb)); err != nil {
		t.Fatal(err)
	}
}

func standbyKeyCall(t *testing.T, pack, key string) StandbyKeyResult {
	t.Helper()
	body, err := StandbyKey(pack, key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, sbAddr) || strings.Contains(body, strings.ReplaceAll(sbKeyText, " ", "")) {
		t.Fatalf("the answer echoes the key or the address: %s", body)
	}
	var res StandbyKeyResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// engine_standby_key: a key is kept on every held route whose sealed
// commitment it opens (never on shadowsocks), and the answer is a
// closed word and a count.
func TestStandbyKey_KeepsAKeyOnlyWhereItOpensTheCommitment(t *testing.T) {
	rig := newAutoRig(t, [][3]string{
		{"r1", "vless-reality", sbPrimaryREALITY},
		{"r2", "shadowsocks", sbShadowsocks},
		{"r3", "vless-reality", sbOtherREALITY},
	})
	c := rig.c
	for _, id := range []string{"r1", "r2", "r3"} {
		packRoute(t, c, id, "p1")
	}
	if got := standbyKeyCall(t, "", sbKeyText); got.Outcome != StandbyKeyNoStandby {
		t.Fatalf("no standby held: %+v", got)
	}
	putStandby(t, c, "r1", sbSealed)
	putStandby(t, c, "r2", sbSealed) // the store never holds one for shadowsocks; ignored anyway
	if got := standbyKeyCall(t, "", "not a key"); got.Outcome != StandbyKeyMalformed {
		t.Fatalf("malformed: %+v", got)
	}
	// Another salt for the same address: no commitment matches.
	other := bundle.StandbyKeyBytes{0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 203, 0, 113, 20}
	if got := standbyKeyCall(t, "", other.Text()); got.Outcome != StandbyKeyNoMatch {
		t.Fatalf("a key for another commitment: %+v", got)
	}
	if got := standbyKeyCall(t, "p2", sbKeyText); got.Outcome != StandbyKeyNoStandby {
		t.Fatalf("another file: %+v", got)
	}
	// Typed the way a person does: lower case, dashes.
	typed := strings.ToLower(strings.ReplaceAll(sbKeyText, " ", "-"))
	if got := standbyKeyCall(t, "p1", typed); got.Outcome != StandbyKeyAccepted || got.Routes != 1 {
		t.Fatalf("accepted: %+v", got)
	}
	if kb, err := c.store.GetSecret(bundle.StandbyKeyStoreKey("r1")); err != nil || len(kb) != bundle.StandbyKeyLen {
		t.Fatalf("key not kept on r1: %v", err)
	}
	for _, id := range []string{"r2", "r3"} {
		if _, err := c.store.GetSecret(bundle.StandbyKeyStoreKey(id)); err == nil {
			t.Fatalf("key kept on %s", id)
		}
	}
	// The route may now be dialled at the address inside the key.
	row, _ := c.store.GetRoute("r1")
	if addr, ok := routeStandbyAddress(c.store, row); !ok || addr != sbAddr {
		t.Fatalf("standby address after the key: %q %v", addr, ok)
	}
	// The refresh walk's hook is the same check on the raw bytes.
	k, _ := bundle.ParseStandbyKeyText(sbKeyText)
	if n, err := (StandbyKeySink{}).AcceptStandbyKey("p1", k[:]); err != nil || n != 1 {
		t.Fatalf("sink: %d %v", n, err)
	}
	if n, _ := (StandbyKeySink{}).AcceptStandbyKey("p1", []byte{1, 2, 3}); n != 0 {
		t.Fatal("the sink kept a short key")
	}
}

// standbyRig answers each attempt by the address its active outbound
// dials: `alive` addresses carry, every other address is dead at the
// SYN.
type standbyRig struct {
	*autoRig
	alive   map[string]bool
	started []string
}

func newStandbyRig(t *testing.T, routes [][3]string) *standbyRig {
	rig := &standbyRig{autoRig: newAutoRig(t, routes), alive: map[string]bool{}}
	rig.stub.SetProofHook(func(ctx context.Context, cfg engine.ProofConfig) engine.ProofResult {
		id, _ := rig.c.activeRouteFromMemory()
		server := activeServer(t, rig.stub.LastConfig())
		rig.mu.Lock()
		rig.started = append(rig.started, id+"@"+server)
		ok := rig.alive[server]
		rig.mu.Unlock()
		if ok {
			return engine.ProofResult{OK: true, Attempts: 1}
		}
		return deadSYN()
	})
	return rig
}

func activeServer(t *testing.T, cfg []byte) string {
	t.Helper()
	var c struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		t.Fatalf("config: %v", err)
	}
	for _, ob := range c.Outbounds {
		if ob["tag"] == "active" {
			s, _ := ob["server"].(string)
			return s
		}
	}
	return ""
}

// The plan's order §4: a route whose address stops answering gets its
// standby — after the other direct routes, before the way in through
// Cloudflare — and nothing was fetched to find it. It is remembered for
// the network and is the route's variant in use.
func TestStandby_AddressStopGetsTheStandbyAfterTheDirectRoutes(t *testing.T) {
	cdn := newCDNFixture(t)
	rig := newStandbyRig(t, [][3]string{
		{"r1", "vless-reality", sbPrimaryREALITY},
		{"r2", "vless-reality", sbOtherREALITY},
		{"r3", "websocket-tls", cdn.profile},
	})
	for _, id := range []string{"r1", "r2", "r3"} {
		packRoute(t, rig.c, id, "p1")
	}
	cdn.store(t, rig.c, "r3")
	putStandby(t, rig.c, "r1", sbOpen)
	rig.alive[sbAddr] = true
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r1" || res.Variant != variantStandbyWord {
		t.Fatalf("got %+v", res)
	}
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r2//not_carrying", "r1/a:standby/carried"}) {
		t.Fatalf("tried %v (started %v)", got, rig.started)
	}
	if rig.started[len(rig.started)-1] != "r1@"+sbAddr {
		t.Fatalf("the standby attempt dialled %v", rig.started)
	}
	mem := netmemStore().LookupRouteMemory(activeNetworkID())
	if !mem["r1#a:standby"].CarriedLast() {
		t.Fatalf("standby not remembered: %v", mem)
	}
	if !canAttempt(rig.c, "r1", "vless-reality") {
		t.Fatal("the route that carried at its standby is cooling down")
	}
}

// No standby without an address-shaped stop; none for a sealed standby
// without a key; and a key that opens it makes it dialable.
func TestStandby_SealedNeedsAKey(t *testing.T) {
	rig := newStandbyRig(t, [][3]string{{"r1", "vless-reality", sbPrimaryREALITY}})
	packRoute(t, rig.c, "r1", "p1")
	putStandby(t, rig.c, "r1", sbSealed)
	rig.alive[sbAddr] = true
	res := rig.connectAuto()
	if res.Connected {
		t.Fatalf("a sealed standby was dialled without a key: %+v", res)
	}
	for _, s := range rig.started {
		if strings.HasSuffix(s, "@"+sbAddr) {
			t.Fatalf("dialled the sealed standby: %v", rig.started)
		}
	}
	if got := standbyKeyCall(t, "p1", sbKeyText); got.Outcome != StandbyKeyAccepted {
		t.Fatalf("key: %+v", got)
	}
	rig.c.pm.Forgive("r1")
	res = rig.connectAuto()
	if !res.Connected || res.Variant != variantStandbyWord {
		t.Fatalf("after the key: %+v (started %v)", res, rig.started)
	}
}

// A reset at the hello is about the name: no standby for it.
func TestStandby_NameStopMovesNoAddress(t *testing.T) {
	rig2 := newLadderRig(t, [][3]string{{"r1", "vless-reality", sbPrimaryREALITY}})
	packRoute(t, rig2.c, "r1", "p1")
	putStandby(t, rig2.c, "r1", sbOpen)
	res := rig2.connectAuto()
	for _, tr := range res.Tried {
		if tr.Variant == variantStandbyWord {
			t.Fatalf("a name-shaped stop moved the address: %v", variants(res.Tried))
		}
	}
}

// The variant is held to the signed endpoint like the route: the
// guard runs on the moved outbound, and a standby the store no longer
// names (or one on shadowsocks) is never dialled.
func TestStandby_GuardRunsOnTheMovedOutbound(t *testing.T) {
	rig := newAutoRig(t, [][3]string{
		{"r1", "vless-reality", sbPrimaryREALITY},
		{"r2", "shadowsocks", sbShadowsocks},
	})
	c := rig.c
	packRoute(t, c, "r1", "p1")
	packRoute(t, c, "r2", "p1")
	putStandby(t, c, "r1", sbOpen)
	putStandby(t, c, "r2", sbOpen)
	sb := routeVariant{standby: true}
	c.mu.Lock()
	_, _, err := c.prepareRouteVariant("r1", false, false, &sb)
	c.mu.Unlock()
	if err != nil {
		t.Fatalf("the open standby was refused: %v", err)
	}
	c.mu.Lock()
	_, _, err = c.prepareRouteVariant("r2", false, false, &sb)
	c.mu.Unlock()
	if err == nil {
		t.Fatal("a shadowsocks route was given a standby variant")
	}
	// The standby goes (a newer pack without `_standby`): the variant
	// with it, even as the variant in use.
	c.setVariantInUse("r1", sb)
	_ = c.store.DeleteSecret(bundle.StandbyStoreKey("r1"))
	c.mu.Lock()
	_, _, err = c.prepareRouteVariant("r1", false, false, &sb)
	c.mu.Unlock()
	if err == nil {
		t.Fatal("a standby the store no longer names was built")
	}
	c.mu.Lock()
	_, body, err := c.prepareRouteVariant("r1", false, false, nil)
	c.mu.Unlock()
	if err != nil || activeServer(t, body) != "198.51.100.10" {
		t.Fatalf("the route did not fall back to its committed server: %v", err)
	}
	if parsed, ok := parseVariantSuffix(variantStandbyWord); !ok || !parsed.standby {
		t.Fatal("the standby word does not read back")
	}
	if _, ok := parseVariantSuffix("a:standby" + netmem.VariantSep + "d:sni-cut"); ok {
		t.Fatal("a standby combined with a preset reads back")
	}
}

// The worldbox's `standby-open` in small: connected on a one-route file,
// the relay's address stops answering — the engine's own fall-over pass
// moves to the standby, with nothing fetched and nobody asked.
func TestStandby_FallOverMovesToTheStandbyWhileConnected(t *testing.T) {
	rig := newStandbyRig(t, [][3]string{{"r1", "vless-reality", sbPrimaryREALITY}})
	fastRecheck(rig.c)
	packRoute(t, rig.c, "r1", "p1")
	putStandby(t, rig.c, "r1", sbOpen)
	rig.mu.Lock()
	rig.alive["198.51.100.10"] = true
	rig.mu.Unlock()
	if res := rig.connectAuto(); !res.Connected || res.Variant != "" {
		t.Fatalf("got %+v", res)
	}
	rig.mu.Lock()
	rig.alive = map[string]bool{sbAddr: true}
	rig.mu.Unlock()
	rig.c.kickLiveness()
	waitFor(t, "the engine to be connected on r1 at its standby", func() bool {
		a := autoBlock(t)
		st, _ := rig.c.check.get()
		return a["state"] == AutoStateConnected && a["route_id"] == "r1" && a["variant"] == variantStandbyWord && st == RouteCheckOK
	})
}
