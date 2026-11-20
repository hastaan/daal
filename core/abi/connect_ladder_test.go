package abi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/netmem"
	"daal/core/pathmanager"
	"daal/core/routestore"
	"daal/core/trust"
)

// The connect ladder (connect_ladder.go). The stub driver is scripted
// by what the started config IS — the cut its desync outbound carries
// and the name its active outbound presents — so each variant of one
// route can be told apart.

const ladderREALITY = `{"type":"vless","server":"relay-a.example","server_port":443,"tls":{"enabled":true,"server_name":"cover.example","reality":{"enabled":true,"public_key":"pk"}}}`

// ladderShape is what a started config does to the first flight:
// "<preset>|<name>" ("" preset: no cut).
func ladderShape(t *testing.T, cfg []byte) string {
	t.Helper()
	var c struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		t.Fatalf("config: %v", err)
	}
	preset, name := "", ""
	for _, ob := range c.Outbounds {
		if ob["tag"] == "active" {
			if tls, _ := ob["tls"].(map[string]any); tls != nil {
				name, _ = tls["server_name"].(string)
			}
		}
		if ob["type"] == "daal-desync" {
			st, _ := json.Marshal(ob["strategy"])
			s := string(st)
			switch {
			case strings.Contains(s, `"record_sni_cut":true`):
				preset = "tlsrec-sni"
			case strings.Contains(s, `"chunk":6`):
				preset = "chain"
			case strings.Contains(s, `"sni_cut":true`):
				preset = "sni-cut"
			default:
				preset = "split1"
			}
		}
	}
	return preset + "|" + name
}

type ladderRig struct {
	*autoRig
	// carries: route -> shapes that carry; every other attempt of the
	// route is reset at its hello.
	carries map[string]map[string]bool
	fails   map[string]func() engine.ProofResult
	started []string
}

func newLadderRig(t *testing.T, routes [][3]string) *ladderRig {
	t.Helper()
	rig := &ladderRig{autoRig: newAutoRig(t, routes), carries: map[string]map[string]bool{}, fails: map[string]func() engine.ProofResult{}}
	rig.stub.SetProofHook(func(ctx context.Context, cfg engine.ProofConfig) engine.ProofResult {
		id, _ := rig.c.activeRouteFromMemory()
		shape := ladderShape(t, rig.stub.LastConfig())
		rig.mu.Lock()
		rig.started = append(rig.started, id+"="+shape)
		ok := rig.carries[id][shape]
		f := rig.fails[id]
		rig.mu.Unlock()
		if ok {
			return engine.ProofResult{OK: true, Attempts: 1}
		}
		if f != nil {
			return f()
		}
		return resetHello()
	})
	return rig
}

func (r *ladderRig) carry(id string, shapes ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.carries[id] == nil {
		r.carries[id] = map[string]bool{}
	}
	for _, s := range shapes {
		r.carries[id][s] = true
	}
}

func (r *ladderRig) startedShapes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.started...)
}

func (r *ladderRig) setFSC(id, fsc string) {
	r.t.Helper()
	row, err := r.c.store.GetRoute(id)
	if err != nil {
		r.t.Fatal(err)
	}
	row.FamilySpecificConfigJSON = fsc
	if err := r.c.store.UpsertRoute(row); err != nil {
		r.t.Fatal(err)
	}
}

// sign stores the route's signed endpoint, made from its own profile —
// what an import of a RelayPack leaves (cover names are offered only for
// a route the endpoint guard holds to one).
func (r *ladderRig) sign(id string) {
	r.t.Helper()
	profile, err := r.c.store.GetSecret("route:" + id)
	if err != nil {
		r.t.Fatal(err)
	}
	row, _ := r.c.store.GetRoute(id)
	r.c.store.PutSecret(trust.RouteEndpointKey(id), endpointOf(r.t, row.TransportFamily, profile))
}

func endpointOf(t *testing.T, family string, profile []byte) []byte {
	t.Helper()
	var ob struct {
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		TLS        struct {
			ServerName string   `json:"server_name"`
			Pins       []string `json:"certificate_public_key_sha256"`
			Reality    struct {
				PublicKey string `json:"public_key"`
			} `json:"reality"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(profile, &ob); err != nil {
		t.Fatal(err)
	}
	ep := bundle.Endpoint{V: bundle.EndpointVersion, Server: ob.Server, Port: ob.ServerPort}
	if family == "vless-reality" {
		ep.ServerName, ep.RealityPublicKey = ob.TLS.ServerName, ob.TLS.Reality.PublicKey
	} else if len(ob.TLS.Pins) > 0 {
		ep.TLSSPKISHA256 = ob.TLS.Pins[0]
	}
	b, _ := json.Marshal(ep)
	return b
}

// onNetwork moves the rig off the shared "no network reported" bucket,
// where no cover name is ever shown.
func onNetwork(t *testing.T, ssid string) {
	t.Helper()
	if _, err := NetworkChanged("wifi", "", ssid); err != nil {
		t.Fatal(err)
	}
}

// logTap collects every engine log line until the test ends.
func logTap(t *testing.T) func() string {
	var mu sync.Mutex
	var b strings.Builder
	restore := engine.SetLogTapForTest(func(_ int, line string) {
		mu.Lock()
		b.WriteString(line + "\n")
		mu.Unlock()
	})
	t.Cleanup(restore)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return b.String()
	}
}

// testPin is a well-formed key pin (the SHA-256 of nothing).
const testPin = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

var (
	helloTimeout = func() engine.ProofResult {
		return failedProof(context.DeadlineExceeded, diagnostics.PhaseHandshake, false, true)
	}
	// serverReset: a reset at the hello that came back no sooner than
	// the relay could have sent it (measured).
	serverReset = func() engine.ProofResult {
		r := resetHello()
		r.Observation.DialMs, r.Observation.ConnectMs = 210, 100
		r.Failed[0] = r.Observation
		return r
	}
)

func variants(tried []AutoTried) []string {
	out := []string{}
	for _, t := range tried {
		out = append(out, t.RouteID+"/"+t.Variant+"/"+t.Result)
	}
	return out
}

func canAttempt(c *Core, id, family string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok, _ := c.pm.CanAttempt(id, family)
	return ok
}

// The route's hello is reset; the same route with sni-cut carries. The
// pass finds it by itself, says which variant it is on in closed words,
// remembers it for this network — and the route, its family and its
// durable record are left as if the plain hello had never failed.
func TestLadder_HelloStoppedTriesTheSplit(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	rig.carry("r1", "sni-cut|cover.example")
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r1" || res.Variant != "d:sni-cut" {
		t.Fatalf("got %+v", res)
	}
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:sni-cut/carried"}) {
		t.Fatalf("tried %v", got)
	}
	if res.Tried[1].Why != AutoWhyLadder {
		t.Fatalf("why = %q", res.Tried[1].Why)
	}
	if a := autoBlock(t); a["variant"] != "d:sni-cut" || a["route_id"] != "r1" {
		t.Fatalf("auto block: %v", a)
	}
	if !canAttempt(rig.c, "r1", "vless-reality") || !canAttempt(rig.c, "r9", "vless-reality") {
		t.Fatal("a route that carried through its variant is cooling down, or its family is")
	}
	mem := netmemStore().LookupRouteMemory(activeNetworkID())
	if !mem["r1#d:sni-cut"].CarriedLast() {
		t.Fatalf("variant not remembered: %v", mem)
	}
	if m, ok := mem["r1"]; ok && m.FailedSeq != 0 {
		t.Fatalf("the plain route's failure was remembered although the route carried: %+v", m)
	}
	if row, _ := rig.c.store.GetRoute("r1"); row.LastFailureCategory != "" {
		t.Fatalf("durable failure row written: %q", row.LastFailureCategory)
	}
	// A reconnect of the route (the person's pick) starts the variant in
	// use on this network.
	_ = ClearRoute()
	if err := SetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	if got := ladderShape(t, rig.stub.LastConfig()); got != "sni-cut|cover.example" {
		t.Fatalf("manual reconnect started %q", got)
	}
}

// Names: a REALITY route offers only names its relay answers for; the
// name that carries is reported by position, the plain hello is refined
// to name_blocked, and the name never appears in the result.
func TestLadder_NameVariant(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	logs := logTap(t)
	onNetwork(t, "home")
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[
		{"id":1,"name":"other.example","class":"foreign"},
		{"id":2,"name":"answered.example","class":"mirror","reality":true}]}}`)
	rig.carry("r1", "|answered.example")
	res := rig.connectAuto()
	if !res.Connected || res.Variant != "n:2" {
		t.Fatalf("got %+v", res)
	}
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:sni-cut/not_carrying", "r1/n:2/carried"}) {
		t.Fatalf("tried %v", got)
	}
	if res.Tried[0].Refined != AutoRefinedNameBlocked {
		t.Fatalf("plain hello refined %q, want name_blocked", res.Tried[0].Refined)
	}
	for _, s := range rig.startedShapes() {
		if strings.Contains(s, "other.example") {
			t.Fatal("a name the REALITY relay does not answer for was tried")
		}
	}
	body, _ := json.Marshal(res)
	diag, _ := ExportDiagnostics()
	for what, text := range map[string]string{"the result": string(body), "the log": logs(), "the diagnostics": diag} {
		for _, name := range []string{"answered.example", "other.example"} {
			if strings.Contains(text, name) {
				t.Fatalf("%s names the cover name %q", what, name)
			}
		}
	}
}

// A name variant's failure text is not published: an error can quote
// the name it presented.
func TestLadder_NameVariantFailureTextIsDropped(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	logs := logTap(t)
	onNetwork(t, "home")
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[{"id":4,"name":"answered.example","class":"mirror","reality":true}]}}`)
	rig.mu.Lock()
	rig.fails["r1"] = func() engine.ProofResult {
		if strings.HasSuffix(ladderShape(t, rig.stub.LastConfig()), "|answered.example") {
			return failedProof(errors.New("read: connection reset by peer (hello for answered.example)"), diagnostics.PhaseHandshake, false, true)
		}
		return resetHello()
	}
	rig.mu.Unlock()
	res := rig.connectAuto()
	sawName := false
	for _, tr := range res.Tried {
		sawName = sawName || tr.Variant == "n:4"
	}
	if !sawName {
		t.Fatalf("the name was not tried: %v", variants(res.Tried))
	}
	diag, _ := ExportDiagnostics()
	for what, text := range map[string]string{"the log": logs(), "the diagnostics": diag} {
		if strings.Contains(text, "answered.example") {
			t.Fatalf("%s names the cover name", what)
		}
	}
}

// A pinned-certificate route may use any listed name; desync and name
// combine once the singles are used up (and only as far as the
// budget goes).
func TestLadder_PinnedFamilyAnyNameAndPackOfferFirst(t *testing.T) {
	ws := `{"type":"vless","server":"relay-b.example","server_port":8445,"tls":{"enabled":true,"server_name":"own.example","certificate_public_key_sha256":["` + testPin + `"]},"transport":{"type":"ws"}}`
	rig := newLadderRig(t, [][3]string{{"w1", "websocket-tls", ws}})
	onNetwork(t, "home")
	rig.sign("w1")
	rig.setFSC("w1", `{"_desync":{"v":1,"strategy":{"preset":"chain"}},"_cover_names":{"v":1,"names":[
		{"id":1,"name":"cdn.example","class":"cdn","cdn":"fastly"},{"id":2,"name":"any.example","class":"foreign"}]}}`)
	rig.carry("w1", "|any.example")
	res := rig.connectAuto()
	// The pack's offer is the first rung; the listed name the second (a
	// CDN-hosted name is never shown to a VPS address).
	if got := variants(res.Tried); !eq(got, []string{"w1//not_carrying", "w1/d:chain/not_carrying", "w1/n:2/carried"}) {
		t.Fatalf("tried %v (%+v)", got, res)
	}
}

// At most two variants per route per pass; each counts against the
// network's hourly side-probe allowance; none once it is spent. The
// route's own failure is charged as always; the variants' are not.
func TestLadder_BudgetIsRespected(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	res := rig.connectAuto()
	if res.Connected {
		t.Fatalf("got %+v", res)
	}
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:sni-cut/not_carrying", "r1/d:tlsrec-sni/not_carrying"}) {
		t.Fatalf("tried %v", got)
	}
	rig.c.mu.Lock()
	n := len(rig.c.side.perNet[activeNetworkID()])
	rig.c.mu.Unlock()
	if n != 2 {
		t.Fatalf("hourly allowance counted %d variants, want 2", n)
	}
	mem := netmemStore().LookupRouteMemory(activeNetworkID())
	if !mem["r1#d:sni-cut"].BlockedAt(nowUTC()) || !mem["r1#d:tlsrec-sni"].BlockedAt(nowUTC()) {
		t.Fatalf("variant failures not remembered: %v", mem)
	}
	if mem["r1"].FailedCategory != string(diagnostics.TLSSNIOrCertBlockSuspected) {
		t.Fatalf("the route's own failure: %+v", mem["r1"])
	}

	// Next pass: the blocked variants are skipped, chain is the one left.
	clearCooldowns(rig.c)
	res = rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:chain/not_carrying"}) {
		t.Fatalf("second pass tried %v", got)
	}

	// The hourly allowance spent: no variant at all.
	clearCooldowns(rig.c)
	rig.c.mu.Lock()
	for i := 0; i < sideProbesPerHour; i++ {
		rig.c.ladderNoteLocked()
	}
	rig.c.mu.Unlock()
	_ = netmemStore().ForgetRoute("r1")
	res = rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying"}) {
		t.Fatalf("with the allowance spent: %v", got)
	}
}

// At most ladderNamesPerRelay distinct names per (network, relay) ever:
// with three already shown to the address from here, no new name is
// shown to it — forgetting the route does not reset the count, and
// another network is not held to it.
func TestLadder_NamesPerRelayCap(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	onNetwork(t, "home")
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[{"id":1,"name":"answered.example","class":"mirror","reality":true}]}}`)
	net := activeNetworkID()
	for _, n := range []string{"a.example", "b.example", "c.example"} {
		_ = netmemStore().RecordCoverNameShown(net, netmem.ShownKey(net, "relay-a.example"), netmem.ShownKey(net, n), nowUTC())
	}
	rig.carry("r1", "|answered.example")
	noName := func(res AutoResult) {
		t.Helper()
		for _, tr := range res.Tried {
			if strings.HasPrefix(tr.Variant, "n:") {
				t.Fatalf("a fourth name was shown to the relay: %v", variants(res.Tried))
			}
		}
	}
	noName(rig.connectAuto())
	_ = netmemStore().ForgetRoute("r1")
	clearCooldowns(rig.c)
	noName(rig.connectAuto())

	onNetwork(t, "elsewhere")
	clearCooldowns(rig.c)
	res := rig.connectAuto()
	if !res.Connected || res.Variant != "n:1" {
		t.Fatalf("on another network: %v", variants(res.Tried))
	}
}

// No cover name on the shared bucket of a host that has reported no
// network, nor for a route without a signed endpoint, nor for one whose
// outbound is not proved by a key.
func TestLadder_NamesNeedANetworkASignatureAndAKey(t *testing.T) {
	list := `{"_cover_names":{"v":1,"names":[{"id":1,"name":"answered.example","class":"mirror","reality":true}]}}`
	try := func(t *testing.T, rig *ladderRig) {
		t.Helper()
		rig.setFSC("r1", list)
		rig.carry("r1", "|answered.example")
		for _, tr := range rig.connectAuto().Tried {
			if strings.HasPrefix(tr.Variant, "n:") {
				t.Fatalf("a name was shown: %v", tr)
			}
		}
	}
	t.Run("no network reported", func(t *testing.T) {
		rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
		rig.sign("r1")
		try(t, rig)
	})
	t.Run("unsigned", func(t *testing.T) {
		rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
		onNetwork(t, "home")
		try(t, rig)
	})
	t.Run("pinned family without a pin", func(t *testing.T) {
		ws := `{"type":"vless","server":"relay-b.example","server_port":8445,"tls":{"enabled":true,"server_name":"own.example","insecure":true},"transport":{"type":"ws"}}`
		rig := newLadderRig(t, [][3]string{{"r1", "websocket-tls", ws}})
		onNetwork(t, "home")
		rig.c.store.PutSecret(trust.RouteEndpointKey("r1"), []byte(`{"v":1}`))
		rig.setFSC("r1", list)
		lr, _ := rig.c.ladderRouteByID("r1")
		if len(lr.names) != 0 || lr.namesRefused != "not_key_proved" {
			t.Fatalf("names %v refused %q", lr.names, lr.namesRefused)
		}
	})
}

// What carried on one network is the route's first attempt THERE, and
// nowhere else.
func TestLadder_MemoryPreferredOnTheSameNetworkOnly(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	if _, err := NetworkChanged("wifi", "", "home"); err != nil {
		t.Fatal(err)
	}
	rig.carry("r1", "sni-cut|cover.example")
	if res := rig.connectAuto(); res.Variant != "d:sni-cut" {
		t.Fatalf("got %+v", res)
	}
	_ = ClearRoute()

	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1/d:sni-cut/carried"}) || res.Tried[0].Why != AutoWhyCarriedHere {
		t.Fatalf("same network: %v (%+v)", got, res.Tried)
	}
	_ = ClearRoute()

	if _, err := NetworkChanged("cell", "carrier", ""); err != nil {
		t.Fatal(err)
	}
	res = rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:sni-cut/carried"}) {
		t.Fatalf("another network starts plain: %v", got)
	}
}

// A variant's failure never cools the route, its relay or its family:
// the remembered variant fails at its hello (a family-class category,
// were it charged), the plain route then fails on its own, and only the
// plain route's own failure is charged.
func TestLadder_VariantFailureDoesNotCoolTheRoute(t *testing.T) {
	other := `{"type":"vless","server":"relay-a.example","server_port":8443,"tls":{"enabled":true,"server_name":"own.example"}}`
	rig := newLadderRig(t, [][3]string{
		{"r1", "vless-reality", ladderREALITY},
		{"r2", "vless-reality", other},
	})
	_ = netmemStore().RecordRouteCarried(activeNetworkID(), "r1#d:sni-cut", nowUTC())
	rig.mu.Lock()
	rig.fails["r1"] = func() engine.ProofResult {
		if strings.HasPrefix(ladderShape(t, rig.stub.LastConfig()), "sni-cut") {
			return resetHello()
		}
		return deadSYN()
	}
	rig.mu.Unlock()
	rig.carry("r2", "|own.example")
	res := rig.connectAuto()
	if !res.Connected || res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	if got := variants(res.Tried[:2]); !eq(got, []string{"r1/d:sni-cut/not_carrying", "r1//not_carrying"}) {
		t.Fatalf("tried %v", variants(res.Tried))
	}
	// The family was not cooled (r2 of the same family was tried and
	// carried; a third route of it may be tried too).
	if !canAttempt(rig.c, "r9", "vless-reality") {
		t.Fatal("the variant's hello failure cooled the family")
	}
	mem := netmemStore().LookupRouteMemory(activeNetworkID())
	if mem["r1"].FailedCategory != string(diagnostics.TCPConnectTimeout) {
		t.Fatalf("the route was charged with %q, want only its own failure", mem["r1"].FailedCategory)
	}
	if !mem["r1#d:sni-cut"].BlockedAt(nowUTC()) {
		t.Fatalf("the variant's failure was not remembered: %+v", mem["r1#d:sni-cut"])
	}
	if mem["r1#d:sni-cut"].VariantBlockedAt(nowUTC()) {
		t.Fatal("one stopped hello blocked a variant that had carried here")
	}
	if row, _ := rig.c.store.GetRoute("r1"); row.LastFailureCategory != string(diagnostics.TCPConnectTimeout) {
		t.Fatalf("durable row: %q", row.LastFailureCategory)
	}
}

// A route whose address is silent gets no variant: no first flight
// fares better against a dead address.
func TestLadder_SilenceEndsTheLadder(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	rig.mu.Lock()
	rig.fails["r1"] = deadSYN
	rig.mu.Unlock()
	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying"}) {
		t.Fatalf("tried %v", got)
	}
}

// Domestic cover names are refused at parse: a list that holds one
// offers no name at all. UDP families and outbounds the split cannot
// sit under get nothing they cannot use. Names go by their signed id, in
// the list's order.
func TestLadderList_RefusesWhatCannotHelp(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[{"id":1,"name":"ok.example","class":"foreign","reality":true},{"id":2,"name":"www.example.ir","class":"foreign","reality":true}]}}`)
	lr, _ := rig.c.ladderRouteByID("r1")
	for _, v := range ladderList(lr) {
		if v.name > 0 {
			t.Fatalf("a name from a list holding a domestic name was offered: %v", v)
		}
	}
	if lr.namesRefused != "domestic" {
		t.Fatalf("refused %q", lr.namesRefused)
	}
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[{"id":7,"name":"ok.example","class":"foreign","reality":true},{"id":3,"name":"two.example","class":"foreign","reality":true}]}}`)
	lr, _ = rig.c.ladderRouteByID("r1")
	got := []string{}
	for _, v := range ladderList(lr) {
		got = append(got, v.suffix())
	}
	if !eq(got, []string{"d:sni-cut", "n:7", "d:tlsrec-sni", "n:3", "d:chain", "d:sni-cut#n:7", "d:sni-cut#n:3"}) {
		t.Fatalf("order %v", got)
	}
	hy := ladderRoute{row: routestore.RouteRow{RouteID: "h", TransportFamily: "hysteria2"},
		profile: []byte(`{"type":"hysteria2","server":"a","server_port":443,"tls":{"enabled":true}}`)}
	if l := ladderList(hy); len(l) != 0 {
		t.Fatalf("UDP family offered %v", l)
	}
	ss := ladderRoute{row: routestore.RouteRow{RouteID: "s", TransportFamily: "shadowsocks"},
		profile: []byte(`{"type":"shadowsocks","server":"a","server_port":443}`)}
	if l := ladderList(ss); len(l) != 0 {
		t.Fatalf("an outbound with no TLS hello offered %v", l)
	}
}

// The pack's own offer gets a word of its own, which changes with the
// offer: a remembered outcome of one offer is never read as another's.
func TestPackPresetWord_FollowsTheOffer(t *testing.T) {
	row := routestore.RouteRow{RouteID: "p", FamilySpecificConfigJSON: `{"_desync":{"v":1,"strategy":{"split_at":[1,5]}}}`}
	o, err := engine.PackDesyncOffer(row)
	if err != nil {
		t.Fatal(err)
	}
	w := packPresetWord(o)
	if !isPackWord(w) {
		t.Fatalf("word %q", w)
	}
	if _, err := variantStrategy(row, w); err != nil {
		t.Fatalf("its own word: %v", err)
	}
	row.FamilySpecificConfigJSON = `{"_desync":{"v":1,"strategy":{"split_at":[1,6]}}}`
	if _, err := variantStrategy(row, w); err == nil {
		t.Fatal("a changed offer answered to the old offer's word")
	}
	row.FamilySpecificConfigJSON = `{"_desync":{"v":1,"strategy":{"preset":"chain"}}}`
	if o, _ := engine.PackDesyncOffer(row); packPresetWord(o) != "chain" {
		t.Fatalf("a named preset: %q", packPresetWord(o))
	}
}

func TestVariantSuffix_RoundTrip(t *testing.T) {
	for _, s := range []string{"d:sni-cut", "n:3", "n:9", "n:9999", "d:pack-1a2b3c#n:1", "d:tlsrec-sni#n:8"} {
		v, ok := parseVariantSuffix(s)
		if !ok || v.suffix() != s {
			t.Fatalf("%q -> %+v %v", s, v, ok)
		}
	}
	for _, s := range []string{"", "d:nope", "d:pack", "d:pack-1a2b3g", "d:pack-1a2b3c4", "n:0", "n:01", "n:10000", "n:1#d:sni-cut", "x:1"} {
		if _, ok := parseVariantSuffix(s); ok {
			t.Fatalf("%q accepted", s)
		}
	}
	if netmem.VariantKey("r1", routeVariant{}.suffix()) != "r1" {
		t.Fatal("the zero variant's key is the route's")
	}
}

// The live route starts being reset at its hello: the fall-over pass
// tries the same route with its hello cut FIRST, finds it, and the route
// and family it had been charged with by the liveness check are let off.
// Then the cut stops working too and the plain hello works again: the
// variant's liveness failure charges nothing to the route, and the pass
// goes back to the route as it is.
func TestLadder_FallOverTriesTheVariantOfTheLiveRoute(t *testing.T) {
	other := `{"type":"vless","server":"relay-a.example","server_port":8443,"tls":{"enabled":true,"server_name":"own.example"}}`
	rig := newLadderRig(t, [][3]string{
		{"r1", "vless-reality", ladderREALITY},
		{"r2", "websocket-tls", other},
	})
	fastRecheck(rig.c)
	// A fall-over is the engine's own pass: it uses only what carried on
	// this network before. The cut did, two days ago.
	_ = netmemStore().RecordRouteCarried(activeNetworkID(), "r1#d:sni-cut", nowUTC().Add(-48*time.Hour))
	rig.carry("r1", "|cover.example")
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r1" || res.Variant != "" {
		t.Fatalf("got %+v", res)
	}
	rig.mu.Lock()
	rig.carries["r1"] = map[string]bool{"sni-cut|cover.example": true}
	rig.fails["r2"] = deadSYN
	rig.mu.Unlock()
	rig.c.kickLiveness()
	waitFor(t, "the engine to be connected on r1 with the cut", func() bool {
		a := autoBlock(t)
		st, _ := rig.c.check.get()
		return a["state"] == AutoStateConnected && a["route_id"] == "r1" && a["variant"] == "d:sni-cut" && st == RouteCheckOK
	})
	tried := autoBlock(t)["tried"].([]any)
	if v := tried[1].(map[string]any); v["route_id"] != "r1" || v["variant"] != "d:sni-cut" || v["result"] != AutoResultCarried {
		t.Fatalf("tried = %v", tried)
	}
	if !canAttempt(rig.c, "r9", "vless-reality") {
		t.Fatal("the family stays cooled although its route carried with the cut")
	}

	rig.mu.Lock()
	rig.carries["r1"] = map[string]bool{"|cover.example": true}
	rig.mu.Unlock()
	rig.c.kickLiveness()
	waitFor(t, "the engine to be back on the plain route", func() bool {
		a := autoBlock(t)
		st, _ := rig.c.check.get()
		return a["state"] == AutoStateConnected && a["route_id"] == "r1" && a["variant"] == "" && st == RouteCheckOK
	})
	mem := netmemStore().LookupRouteMemory(activeNetworkID())
	if !mem["r1#d:sni-cut"].BlockedAt(nowUTC()) {
		t.Fatalf("the variant's failure was not remembered: %+v", mem["r1#d:sni-cut"])
	}
	if !canAttempt(rig.c, "r1", "vless-reality") {
		t.Fatal("the variant's liveness failure cooled the route")
	}
}

// A one-route file: the live route's hello starts being reset and there
// is no other route at all. Its variant is still something to try.
func TestLadder_FallOverWithNoOtherRoute(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	fastRecheck(rig.c)
	_ = netmemStore().RecordRouteCarried(activeNetworkID(), "r1#d:sni-cut", nowUTC().Add(-48*time.Hour))
	rig.carry("r1", "|cover.example")
	if res := rig.connectAuto(); !res.Connected {
		t.Fatalf("got %+v", res)
	}
	rig.mu.Lock()
	rig.carries["r1"] = map[string]bool{"sni-cut|cover.example": true}
	rig.mu.Unlock()
	rig.c.kickLiveness()
	waitFor(t, "the engine to be connected on r1 with the cut", func() bool {
		a := autoBlock(t)
		st, _ := rig.c.check.get()
		return a["state"] == AutoStateConnected && a["variant"] == "d:sni-cut" && st == RouteCheckOK
	})
}

// The engine's own fall-over shows the network nothing new: with no cut
// that carried here before, the live route's hello being reset gets no
// variant from it.
func TestLadder_FallOverShowsNothingNew(t *testing.T) {
	other := `{"type":"vless","server":"relay-c.example","server_port":8443,"tls":{"enabled":true,"server_name":"own.example"}}`
	rig := newLadderRig(t, [][3]string{
		{"r1", "vless-reality", ladderREALITY},
		{"r2", "websocket-tls", other},
	})
	fastRecheck(rig.c)
	rig.carry("r1", "|cover.example")
	if res := rig.connectAuto(); !res.Connected || res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	rig.mu.Lock()
	rig.carries["r1"] = map[string]bool{"sni-cut|cover.example": true}
	rig.carries["r2"] = map[string]bool{"|own.example": true}
	rig.mu.Unlock()
	rig.c.kickLiveness()
	waitFor(t, "the engine to move to r2", func() bool {
		a := autoBlock(t)
		return a["state"] == AutoStateConnected && a["route_id"] == "r2"
	})
	for _, s := range rig.startedShapes() {
		if strings.HasPrefix(s, "r1=sni-cut") {
			t.Fatalf("the fall-over tried a cut never seen to carry here: %v", rig.startedShapes())
		}
	}
}

// Two names to the same address and port stopped alike: the name is not
// what the network reads. The pass stops showing names to the route at
// once; once two names to the relay carry a blocked mark, no new one is
// shown to it at all.
func TestLadder_AddressBlockedStopsNames(t *testing.T) {
	// tcp_fast_open: no cut can sit under it, so only names are left.
	prof := `{"type":"vless","server":"relay-a.example","server_port":443,"tcp_fast_open":true,"tls":{"enabled":true,"server_name":"cover.example","reality":{"enabled":true,"public_key":"pk"}}}`
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", prof}})
	onNetwork(t, "home")
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[
		{"id":1,"name":"one.example","class":"mirror","reality":true},
		{"id":2,"name":"two.example","class":"mirror","reality":true},
		{"id":3,"name":"three.example","class":"mirror","reality":true}]}}`)
	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/n:1/not_carrying"}) {
		t.Fatalf("first pass %v", got)
	}
	if res.Verdict != AutoVerdictAddressBlocked {
		t.Fatalf("verdict %q", res.Verdict)
	}
	clearCooldowns(rig.c)
	res = rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/n:2/not_carrying"}) {
		t.Fatalf("second pass %v", got)
	}
	clearCooldowns(rig.c)
	res = rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying"}) {
		t.Fatalf("third pass: two names stopped alike, a third was shown: %v", got)
	}
	net := activeNetworkID()
	if n := len(netmemStore().CoverNamesShownTo(net, netmem.ShownKey(net, "relay-a.example"))); n != 2 {
		t.Fatalf("names shown to the relay: %d", n)
	}
}

// A hello left unanswered is what an address default-denied looks like
// as much as a name: one preset at most, and no name.
func TestLadder_HelloTimeoutGetsOnePresetAndNoName(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	onNetwork(t, "home")
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[{"id":1,"name":"one.example","class":"mirror","reality":true}]}}`)
	rig.mu.Lock()
	rig.fails["r1"] = helloTimeout
	rig.mu.Unlock()
	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:sni-cut/not_carrying"}) {
		t.Fatalf("tried %v", got)
	}
	// Silence says nothing about the cut: it is not marked blocked.
	if m, ok := netmemStore().LookupRouteMemory(activeNetworkID())["r1#d:sni-cut"]; ok && m.FailedSeq != 0 {
		t.Fatalf("a silent variant failure was remembered: %+v", m)
	}
}

// Every TCP route of the pass timed out at its hello: the ladder is off
// for the rest of the pass.
func TestLadder_SilentEverywhereTurnsTheLadderOff(t *testing.T) {
	other := `{"type":"vless","server":"relay-c.example","server_port":443,"tls":{"enabled":true,"server_name":"own.example","reality":{"enabled":true,"public_key":"pk2"}}}`
	rig := newLadderRig(t, [][3]string{
		{"r1", "vless-reality", ladderREALITY},
		{"r2", "vless-reality", other},
	})
	rig.mu.Lock()
	rig.fails["r1"], rig.fails["r2"] = helloTimeout, helloTimeout
	rig.mu.Unlock()
	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1//not_carrying", "r1/d:sni-cut/not_carrying", "r2//not_carrying"}) {
		t.Fatalf("tried %v", got)
	}
}

// A stop measured as the relay's own (it came back no sooner than the
// relay could have sent it) gets no variant: the relay refused, not the
// network.
func TestLadder_ServerStopGetsNoVariant(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	rig.mu.Lock()
	rig.fails["r1"] = serverReset
	rig.mu.Unlock()
	if got := variants(rig.connectAuto().Tried); !eq(got, []string{"r1//not_carrying"}) {
		t.Fatalf("tried %v", got)
	}
}

// A variant stopped at its hello in some way that says nothing (silence)
// is not marked; one reset at its hello is.
func TestLadder_OnlyAHelloStopMarksAVariant(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	rig.mu.Lock()
	rig.fails["r1"] = func() engine.ProofResult {
		if strings.HasPrefix(ladderShape(t, rig.stub.LastConfig()), "sni-cut") {
			return helloTimeout()
		}
		return resetHello()
	}
	rig.mu.Unlock()
	rig.connectAuto()
	mem := netmemStore().LookupRouteMemory(activeNetworkID())
	if m, ok := mem["r1#d:sni-cut"]; ok && m.FailedSeq != 0 {
		t.Fatalf("a silent variant failure was marked: %+v", m)
	}
}

// The live route's variant fails a liveness check in a way a changed
// first flight cannot answer: that is the ROUTE's failure (its relay may
// be what died), and the variant's record is left alone. A hello-shaped
// failure is the variant's.
func TestLadder_LiveVariantFailureOfAnotherKindChargesTheRoute(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	rig.c.mu.Lock()
	defer rig.c.mu.Unlock()
	rig.c.setVariantInUse("r1", routeVariant{preset: "sni-cut"})
	if rig.c.liveVariantDownLocked("r1", "vless-reality", diagnostics.TCPConnectTimeout, "x") {
		t.Fatal("a silent liveness failure was filed as the variant's")
	}
	if !rig.c.liveVariantDownLocked("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected, "x") {
		t.Fatal("a hello-shaped liveness failure was not the variant's")
	}
	if ok, _ := rig.c.pm.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatal("the variant's hello failure cooled the route")
	}
}

// After a pass whose last attempt was a variant that did not carry, the
// path manager is not left saying the route is being checked.
func TestLadder_PathManagerAfterTheLastRungFails(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	res := rig.connectAuto()
	if n := len(res.Tried); n < 2 || res.Tried[n-1].Variant == "" {
		t.Fatalf("the last attempt was not a variant: %v", variants(res.Tried))
	}
	rig.c.mu.Lock()
	st, why := rig.c.pm.State(), rig.c.pm.LastReason()
	rig.c.mu.Unlock()
	if st == pathmanager.StateVerifying || st == pathmanager.StateConnecting || strings.Contains(why, "checking that") {
		t.Fatalf("pm state %v reason %q", st, why)
	}
}

// Memory names an entry by its signed id: a list that drops an entry
// and reorders the rest still finds the name that carried. And when the
// route's signed endpoint moves, every variant record of it is dropped.
func TestLadder_IdsSurviveAListEditAndAMovedRelayForgets(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	onNetwork(t, "home")
	rig.sign("r1")
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[
		{"id":1,"name":"other.example","class":"mirror","reality":true},
		{"id":2,"name":"answered.example","class":"mirror","reality":true}]}}`)
	rig.carry("r1", "|answered.example")
	rig.mu.Lock()
	rig.fails["r1"] = resetHello
	rig.mu.Unlock()
	// Seed: n:2 carried here, recently.
	_ = netmemStore().RecordRouteCarried(activeNetworkID(), "r1#n:2", nowUTC())
	// The publisher retires id 1 and puts a new entry first.
	rig.setFSC("r1", `{"_cover_names":{"v":1,"names":[
		{"id":5,"name":"new.example","class":"mirror","reality":true},
		{"id":2,"name":"answered.example","class":"mirror","reality":true}]}}`)
	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"r1/n:2/carried"}) {
		t.Fatalf("after the list edit: %v", got)
	}
	if got := ladderShape(t, rig.stub.LastConfig()); got != "|answered.example" {
		t.Fatalf("started %q", got)
	}
	_ = ClearRoute()

	// The relay moves (a refresh, a recovery): a new signed endpoint.
	moved := strings.Replace(ladderREALITY, "relay-a.example", "relay-z.example", 1)
	rig.c.store.PutSecret("route:r1", []byte(moved))
	rig.sign("r1")
	clearCooldowns(rig.c)
	res = rig.connectAuto()
	if len(res.Tried) == 0 || res.Tried[0].Variant != "" {
		t.Fatalf("after the move the remembered name was the first attempt: %v", variants(res.Tried))
	}
	if v := netmem.VariantsOf(netmemStore().LookupRouteMemory(activeNetworkID()), "r1"); v["n:2"].CarriedSeq != 0 && v["n:2"].CarriedLast() {
		t.Fatalf("the old relay's record survived: %+v", v)
	}
}

// lifeline-strict shows the network nothing new: only a variant that
// carried here before is used.
func TestLadder_LifelineStrictUsesOnlyKnownVariants(t *testing.T) {
	rig := newLadderRig(t, [][3]string{{"r1", "vless-reality", ladderREALITY}})
	if err := SetMode("lifeline-strict"); err != nil {
		t.Fatal(err)
	}
	if got := variants(rig.connectAuto().Tried); !eq(got, []string{"r1//not_carrying"}) {
		t.Fatalf("lifeline-strict tried %v", got)
	}
	_ = netmemStore().RecordRouteCarried(activeNetworkID(), "r1#d:tlsrec-sni", nowUTC().Add(-48*time.Hour))
	clearCooldowns(rig.c)
	if got := variants(rig.connectAuto().Tried); !eq(got, []string{"r1//not_carrying", "r1/d:tlsrec-sni/not_carrying"}) {
		t.Fatalf("lifeline-strict with a known cut tried %v", got)
	}
}

// The real import path: a signed RelayPack whose route carries
// `_cover_names` and `_desync` is imported through the production ABI,
// and the ladder reads both — while the row keeps no address or key.
func TestLadder_ThroughTheRealImport(t *testing.T) {
	rig := newLadderRig(t, nil)
	onNetwork(t, "home")
	body := ladderPack(t)
	path := t.TempDir() + "/pack.sbp"
	if err := writeFile(path, body); err != nil {
		t.Fatal(err)
	}
	out, err := ImportSBP(path)
	if err != nil {
		t.Fatalf("import: %v %s", err, out)
	}
	var v struct {
		Fingerprint string `json:"fingerprint"`
	}
	_ = json.Unmarshal([]byte(out), &v)
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatal(err)
	}
	row, err := rig.c.store.GetRoute("rA")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(row.FamilySpecificConfigJSON, "_cover_names") || !strings.Contains(row.FamilySpecificConfigJSON, "_desync") {
		t.Fatalf("the row lost the engine's config: %s", row.FamilySpecificConfigJSON)
	}
	for _, leak := range []string{"_endpoint", "5.75.0.1", "fixture-reality-public-key", "_relaypack"} {
		if strings.Contains(row.FamilySpecificConfigJSON, leak) {
			t.Fatalf("the row holds %q: %s", leak, row.FamilySpecificConfigJSON)
		}
	}
	rig.carry("rA", "|answered.example")
	res := rig.connectAuto()
	if got := variants(res.Tried); !eq(got, []string{"rA//not_carrying", "rA/d:chain/not_carrying", "rA/n:3/carried"}) {
		t.Fatalf("tried %v (%+v)", got, res)
	}
}

func writeFile(path string, body []byte) error { return os.WriteFile(path, body, 0o600) }

// ladderPack is a signed RelayPack of one vless-reality route whose
// family_specific_config carries, beside `_relaypack` and `_endpoint`,
// a `_desync` offer and a `_cover_names` list (one entry its relay does
// not answer for, one CDN-hosted, one it answers for).
func ladderPack(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ep := bundle.Endpoint{V: bundle.EndpointVersion, Server: "5.75.0.1", Port: 443,
		ServerName: "cover.example", RealityPublicKey: "fixture-reality-public-key"}
	entry := bundle.RelayPackEntry{ExposureMode: "direct_vps", FamilyClass: "vps-native", ProbingRiskClass: "low",
		PublicRiskTags: []string{"public_ip:5.75.0.1"}, OriginRiskTags: []string{}}
	fsc, _ := json.Marshal(map[string]any{
		"_relaypack":       entry,
		bundle.EndpointKey: ep,
		"_desync":          map[string]any{"v": 1, "strategy": map[string]any{"preset": "chain"}},
		bundle.CoverNamesKey: map[string]any{"v": 1, "names": []map[string]any{
			{"id": 1, "name": "other.example", "class": "foreign"},
			{"id": 2, "name": "static.example", "class": "cdn", "cdn": "fastly"},
			{"id": 3, "name": "answered.example", "class": "mirror", "reality": true},
		}},
	})
	m := bundle.Manifest{
		SpecVersion: 3,
		Publisher: bundle.PublisherInfo{Name: "Ladder Test", KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt: now.Format(time.RFC3339), TrustClass: "unknown"},
		Bundle: bundle.BundleInfo{ID: "bundle-ladder-test", Type: "provider", CreatedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), SupersedesKeys: []string{}},
		RelayPack: &bundle.RelayPack{RelayPackID: "rp-ladder-test",
			SharedRiskGraph: []bundle.SharedRiskEdge{{Tag: "public_ip:5.75.0.1", Members: []string{"rA", "rB"}}}},
	}
	for _, id := range []string{"rA", "rB"} {
		m.Routes = append(m.Routes, bundle.RouteManifestEntry{ID: id, ScarcityClass: "normal", TransportFamily: "vless-reality",
			ConfigPath: "profiles/" + id + ".json", ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339),
			FamilySpecificConfig: json.RawMessage(fsc)})
	}
	profile := []byte(`{"type":"vless","tag":"active","server":"5.75.0.1","server_port":443,` +
		`"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",` +
		`"tls":{"enabled":true,"server_name":"cover.example",` +
		`"utls":{"enabled":true,"fingerprint":"chrome"},` +
		`"reality":{"enabled":true,"public_key":"fixture-reality-public-key","short_id":"abcd"}}}`)
	body, err := bundle.BuildSignedBundle(m, map[string][]byte{"profiles/rA.json": profile, "profiles/rB.json": profile}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
