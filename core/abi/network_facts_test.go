package abi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/core/netmem"
)

// Network facts from the host (network_facts.go).

func facts(t *testing.T, kind, id string, validated, metered int) map[string]any {
	t.Helper()
	body, err := NetworkFacts(kind, id, validated, metered)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// grepDir reports every file under dir whose bytes contain needle.
func grepDir(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if body, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(body), needle) {
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}

// The id the host hands over is hashed on entry: it is in no file of
// the state directory, no log line, no answer and no diagnostics blob —
// and the hash it becomes is the key of this network's memory.
func TestNetworkFacts_TheClearIDIsNeverStoredLoggedOrReturned(t *testing.T) {
	const clear = "HomeGateway-3c:7a:11:22:33:44-netHandle-432902426637"
	dir := filepath.Join(t.TempDir(), "daal-state")
	rig := newAutoRigIn(t, dir, autoFourRoutes)
	lc := captureLog(t)

	out := facts(t, NetKindWiFi, clear, 1, 0)
	hashed, _ := out["network_id"].(string)
	if len(hashed) != 16 || strings.Contains(clear, hashed) || hashed == netmem.SentinelUnset {
		t.Fatalf("network_id = %q", hashed)
	}
	if hashed != netmem.HashID(netmem.KindWiFi, netFactsDomain, clear) {
		t.Fatal("the id is not hashed with the engine's existing network hash")
	}
	if out["changed"] != true || out["fresh"] != true || out["validated"] != float64(1) || out["metered"] != float64(0) {
		t.Fatalf("answer: %v", out)
	}
	// Something is remembered under it, and written to disk.
	if res := rig.connectAuto(); !res.Connected {
		t.Fatalf("got %+v", res)
	}
	if activeNetworkID() != hashed {
		t.Fatal("the hashed id is not the engine's network")
	}
	if _, err := rig.c.store.GetSecret("netmem:" + hashed); err != nil {
		t.Fatalf("nothing stored under the hashed id: %v", err)
	}
	blobBody, _ := ExportDiagnostics()
	explain, _ := DiagnosticsExplain()
	for what, text := range map[string]string{"the answer": mustJSON(out), "the diagnostics blob": blobBody, "diagnostics_explain": explain} {
		for _, piece := range []string{clear, "HomeGateway", "3c:7a:11", "432902426637"} {
			if strings.Contains(text, piece) {
				t.Fatalf("%s carries the clear id (%q)", what, piece)
			}
		}
	}
	for _, line := range lc.all() {
		for _, piece := range []string{clear, "HomeGateway", "3c:7a:11", "432902426637"} {
			if strings.Contains(line, piece) {
				t.Fatalf("a log line carries the clear id: %q", line)
			}
		}
	}
	keys, _ := rig.c.store.ListSecretKeys("")
	for _, k := range keys {
		raw, _ := rig.c.store.GetSecret(k)
		if strings.Contains(k, "HomeGateway") || strings.Contains(string(raw), "HomeGateway") {
			t.Fatalf("the clear id is in the secrets store under %s", k)
		}
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	for _, piece := range []string{clear, "HomeGateway", "432902426637"} {
		if hits := grepDir(t, dir, piece); len(hits) != 0 {
			t.Fatalf("the clear id (%q) is in the state directory: %v", piece, hits)
		}
	}
	// The premise of the grep: the directory does hold the store.
	if hits := grepDir(t, dir, "SQLite"); len(hits) == 0 {
		t.Fatal("premise: found no store file to grep")
	}

	// The same id is the same network after a restart; another id is not.
	rig = newAutoRigIn(t, dir, nil)
	again := facts(t, NetKindWiFi, clear, 1, 0)
	if again["network_id"] != hashed || again["fresh"] != false {
		t.Fatalf("after a restart: %v", again)
	}
	if m := rig.c.routeMemory(); len(m) == 0 {
		t.Fatal("the network's memory was not found again under the hashed id")
	}
	other := facts(t, NetKindWiFi, "another-network", 1, 0)
	if other["network_id"] == hashed || other["fresh"] != true {
		t.Fatalf("another id: %v", other)
	}
	if m := rig.c.routeMemory(); len(m) != 0 {
		t.Fatalf("another network inherited this one's memory: %+v", m)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestNetworkFacts_RejectsAnUnknownKindWithoutEchoingIt(t *testing.T) {
	newAutoRig(t, nil)
	_, err := NetworkFacts("MyHomeWifiName", "x", 1, 1)
	if err == nil || strings.Contains(err.Error(), "MyHomeWifiName") {
		t.Fatalf("err = %v", err)
	}
	if hostFacts().seen {
		t.Fatal("a refused report was recorded")
	}
	// Anything but 0 and 1 is "unknown".
	out := facts(t, NetKindOther, "", 7, -3)
	if out["validated"] != float64(-1) || out["metered"] != float64(-1) {
		t.Fatalf("answer: %v", out)
	}
	n := diagBlob(t)["network"].(map[string]any)
	if n["from_host"] != true || n["kind"] != NetKindOther || n["validated"] != float64(-1) {
		t.Fatalf("network block: %v", n)
	}
}

// What was remembered when the kind was the whole identity is taken
// over by the first network of that kind the host names — once.
func TestNetworkFacts_AdoptsTheOldKindOnlyMemoryOnce(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	// The page's call, as it was: the kind and nothing else.
	if _, err := NetworkChanged("wifi", "", ""); err != nil {
		t.Fatal(err)
	}
	legacy := activeNetworkID()
	rig.fail("r1", answeredReset())
	if res := rig.connectAuto(); res.RouteID != "r2" {
		t.Fatalf("got %+v", res)
	}
	_ = ClearRoute()

	home := facts(t, NetKindWiFi, "home", 1, 0)
	if home["network_id"] == legacy {
		t.Fatal("a named network kept the kind-only key")
	}
	mem := rig.c.routeMemory()
	if !mem["r2"].CarriedLast() || mem["r1"].Failed != 1 {
		t.Fatalf("the first named wifi did not take over what was remembered: %+v", mem)
	}
	if _, err := rig.c.store.GetSecret("netmem:" + legacy); err == nil {
		t.Fatal("the kind-only record is still there")
	}
	// So the remembered route is still tried first, alone.
	clearCooldowns(rig.c)
	if res := rig.connectAuto(); res.RouteID != "r2" || res.Tried[0].Why != AutoWhyCarriedHere {
		t.Fatalf("got %+v", res)
	}
	_ = ClearRoute()

	office := facts(t, NetKindWiFi, "office", 1, 0)
	if office["fresh"] != true {
		t.Fatalf("answer: %v", office)
	}
	if m := rig.c.routeMemory(); len(m) != 0 {
		t.Fatalf("a second named network adopted the same memory: %+v", m)
	}
	// And back home it is all still there.
	facts(t, NetKindWiFi, "home", 1, 0)
	if m := rig.c.routeMemory(); !m["r2"].CarriedLast() {
		t.Fatalf("home's memory after a round trip to the office: %+v", m)
	}
}

// An engine nobody ever told anything remembered under the "unset"
// record; that is adopted too.
func TestNetworkFacts_AdoptsTheMemoryOfAnEngineThatWasToldNothing(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	_ = ClearRoute()
	facts(t, NetKindCellular, "operator-1", 1, 1)
	if m := rig.c.routeMemory(); !m["r1"].CarriedLast() {
		t.Fatalf("memory: %+v", m)
	}
}

// Once the host reports, the page's call changes nothing: two callers
// naming one network two ways would split its memory.
func TestNetworkFacts_SupersedesThePagesCall(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	hashed := facts(t, NetKindWiFi, "home", 1, 0)["network_id"]
	body, err := NetworkChanged("wifi", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	if out["network_id"] != hashed || out["superseded"] != true || activeNetworkID() != hashed {
		t.Fatalf("the page's call moved the engine to another network: %v (active %s)", out, activeNetworkID())
	}
	if _, err := NetworkChanged("nonsense", "", ""); err == nil {
		t.Fatal("an invalid kind is still an error")
	}
	_ = rig
}

func proofCount(rig *autoRig) int { return len(rig.provedRoutes()) }

// A change is checked NOW, not at the three-minute tick; a report that
// changes nothing checks nothing; going down checks nothing.
func TestNetworkFacts_AChangeKicksTheLivenessCheckAtOnce(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.c.mu.Lock()
	rig.c.proofCfg.LivenessInterval = time.Hour
	rig.c.proofCfg.RecheckInterval = time.Hour
	rig.c.mu.Unlock()
	facts(t, NetKindWiFi, "home", 1, 0)
	if res := rig.connectAuto(); !res.Connected {
		t.Fatalf("got %+v", res)
	}
	settle := func() int {
		time.Sleep(60 * time.Millisecond)
		return proofCount(rig)
	}
	n := settle()

	facts(t, NetKindWiFi, "home", 1, 0)
	if got := settle(); got != n {
		t.Fatalf("the same report again started %d check(s)", got-n)
	}
	// Another network.
	facts(t, NetKindCellular, "operator-1", 1, 1)
	waitFor(t, "a check after the network changed", func() bool { return proofCount(rig) == n+1 })
	n = settle()
	// No network: nothing to check with.
	out := facts(t, NetKindNone, "", -1, -1)
	if got := settle(); got != n {
		t.Fatalf("going offline started %d check(s)", got-n)
	}
	if out["network_id"] != activeNetworkID() || out["validated"] != float64(0) {
		t.Fatalf("answer for none: %v", out)
	}
	// Back on the SAME network: checked, although its id did not change.
	facts(t, NetKindCellular, "operator-1", 0, 1)
	waitFor(t, "a check after the network came back", func() bool { return proofCount(rig) == n+1 })
	n = settle()
	// It has just become validated.
	facts(t, NetKindCellular, "operator-1", 1, 1)
	waitFor(t, "a check after the network was validated", func() bool { return proofCount(rig) == n+1 })
	n = settle()
	// Only the metered flag changed: nothing to check.
	facts(t, NetKindCellular, "operator-1", 1, 0)
	if got := settle(); got != n {
		t.Fatalf("a metered flag started %d check(s)", got-n)
	}
}

// AUTO-1 / AC-18: nothing answered. With the host saying the phone is
// on NO NETWORK the verdict is network_down; without that word — nothing
// said, or only "not validated" — the same silence stays what it was.
func TestNetworkFacts_NothingAnsweredAndTheHostSaysDownIsNetworkDown(t *testing.T) {
	silence := func(rig *autoRig) {
		for _, id := range []string{"r1", "r2", "r3"} {
			rig.fail(id, deadSYN())
		}
		rig.fail("r4", silentUDP())
	}
	cases := []struct {
		name  string
		setup func(t *testing.T)
		want  string
	}{
		{"no host report", func(*testing.T) {}, AutoVerdictRelayUnreachable},
		{"validated", func(t *testing.T) { facts(t, NetKindWiFi, "home", 1, 0) }, AutoVerdictRelayUnreachable},
		{"validation unknown", func(t *testing.T) { facts(t, NetKindWiFi, "home", -1, 0) }, AutoVerdictRelayUnreachable},
		// A network the platform has not validated is NOT "no internet":
		// one that filters the platform's own check is never validated
		// and carries everything else. The silence stays what it was.
		{"not validated", func(t *testing.T) { facts(t, NetKindWiFi, "home", 0, 0) }, AutoVerdictRelayUnreachable},
		{"not validated, cellular", func(t *testing.T) { facts(t, NetKindCellular, "sub1", 0, 1) }, AutoVerdictRelayUnreachable},
		{"no network", func(t *testing.T) { facts(t, NetKindNone, "", -1, -1) }, AutoVerdictNetworkDown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rig := newAutoRig(t, autoFourRoutes)
			c.setup(t)
			silence(rig)
			res := rig.connectAuto()
			if res.Connected || res.Verdict != c.want {
				t.Fatalf("verdict %q, want %q (%+v)", res.Verdict, c.want, res.Tried)
			}
			if autoBlock(t)["verdict"] != c.want {
				t.Fatalf("auto block: %v", autoBlock(t))
			}
			// Either way nothing is resting: nothing answered.
			if ok, _ := rig.c.pm.CanAttempt("r1", "vless-reality"); !ok {
				t.Fatal("r1 is cooling down after a pass in which nothing answered")
			}
			_ = Shutdown()
		})
	}

	// Something ANSWERED and failed: the host's "not validated" does not
	// turn that into "no internet" (a network that blocks the platform's
	// own check is never validated).
	rig := newAutoRig(t, autoFourRoutes)
	facts(t, NetKindWiFi, "home", 0, 0)
	silence(rig)
	rig.fail("r2", answeredReset())
	if res := rig.connectAuto(); res.Verdict == AutoVerdictNetworkDown {
		t.Fatalf("a route was answered and the verdict is still network_down: %+v", res)
	}
}

// With no network at all the engine starts no fall-over pass by itself;
// with a network that is merely not validated it still does.
func TestNetworkFacts_NoNetworkStartsNoFallOverPass(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	fastRecheck(rig.c)
	facts(t, NetKindWiFi, "home", 1, 0)
	if res := rig.connectAuto(); res.RouteID != "r1" {
		t.Fatalf("got %+v", res)
	}
	facts(t, NetKindNone, "", -1, -1)
	rig.fail("r1", deadSYN())
	rig.c.kickLiveness()
	waitFor(t, "r1 to be failed", func() bool { st, _ := rig.c.check.get(); return st == RouteCheckFailed })
	time.Sleep(150 * time.Millisecond) // several rechecks
	for _, id := range rig.provedRoutes() {
		if id != "r1" {
			t.Fatalf("with no network the engine started %s by itself", id)
		}
	}
	if r, _ := rig.c.activeRouteFromMemory(); r != "r1" {
		t.Fatalf("active = %s", r)
	}
	// A network that is there and not validated: the engine moves on.
	facts(t, NetKindWiFi, "home", 0, 0)
	waitFor(t, "the engine to have moved to r2", func() bool {
		r, _ := rig.c.activeRouteFromMemory()
		st, _ := rig.c.check.get()
		return r == "r2" && st == RouteCheckOK
	})
}

// Seen on a phone (2026-11-19, mobile data -> Wi-Fi): the check that
// follows a network change ran on connections left on the network the
// phone had just left, failed twice and the engine moved off a route
// that was fine. A change of network drops the instance's connections
// BEFORE that check; a report that changes nothing, a flag, or going
// down drops nothing.
func TestNetworkFacts_AChangeOfNetworkDropsTheOldConnectionsFirst(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes)
	rig.c.mu.Lock()
	rig.c.proofCfg.LivenessInterval = time.Hour
	rig.c.proofCfg.RecheckInterval = time.Hour
	rig.c.mu.Unlock()
	facts(t, NetKindWiFi, "home", 1, 0)
	if res := rig.connectAuto(); !res.Connected {
		t.Fatalf("got %+v", res)
	}
	base := rig.stub.ResetCount()

	facts(t, NetKindWiFi, "home", 1, 0)
	facts(t, NetKindWiFi, "home", 1, 1)
	if got := rig.stub.ResetCount(); got != base {
		t.Fatalf("no change of network, yet %d reset(s)", got-base)
	}
	n := proofCount(rig)
	facts(t, NetKindCellular, "operator-1", 1, 1)
	if got := rig.stub.ResetCount(); got != base+1 {
		t.Fatalf("wifi -> cellular: %d reset(s), want 1", got-base)
	}
	waitFor(t, "the check after the reset", func() bool { return proofCount(rig) == n+1 })
	facts(t, NetKindNone, "", -1, -1)
	if got := rig.stub.ResetCount(); got != base+1 {
		t.Fatalf("going down reset %d more time(s)", got-base-1)
	}
	facts(t, NetKindWiFi, "home", 1, 0)
	if got := rig.stub.ResetCount(); got != base+2 {
		t.Fatalf("cellular -> wifi: %d reset(s) in all, want 2", got-base)
	}
}
