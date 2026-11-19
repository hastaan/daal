package abi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"daal/core/diagnostics"
	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/routestore"
)

// Tests for what the first real-phone pass (2026-11-19) found. Each one
// names the observation it pins.

func diagBlob(t *testing.T) map[string]any {
	t.Helper()
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	var blob map[string]any
	if err := json.Unmarshal([]byte(body), &blob); err != nil {
		t.Fatal(err)
	}
	return blob
}

// breakStore makes every read of the open route store fail, the way it
// failed on the phone: the file under the open connection stops being a
// database.
func breakStore(t *testing.T, c *Core) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(c.stateDir, "daal.db"), bytes.Repeat([]byte("not a database "), 2000), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.GetRoute("r-st"); err == nil {
		t.Fatal("premise: the store still answers after its file was overwritten")
	}
}

// captureLog collects every engine log line for the test.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	lc := &logCapture{}
	restore := engine.SetLogTapForTest(func(level int, line string) {
		lc.mu.Lock()
		lc.lines = append(lc.lines, line)
		lc.mu.Unlock()
	})
	t.Cleanup(restore)
	return lc
}

func (lc *logCapture) all() []string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return append([]string(nil), lc.lines...)
}

func (lc *logCapture) has(sub string) bool {
	for _, l := range lc.all() {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// ---- A3: the active route comes from memory ---------------------------

// Observation: after a route switch the tunnel carried traffic while the
// Connection page said "No route selected" and the Network page marked
// no row. Both pages learned the active route only through calls that
// read the route store, and the store had stopped answering.
//
// ExportDiagnostics must name the running route and its family from the
// engine's memory, and DiagnosticsExplain must still return active_route
// and a pick with the route id, when the store cannot be read at all.
func TestActiveRoute_ServedFromMemoryWhenTheStoreFails(t *testing.T) {
	c, _ := checkInit(t, "r-st")
	blob := diagBlob(t)
	if blob["active_route"] != "" || blob["active_route_family"] != "" {
		t.Fatalf("before any connect: active_route=%v family=%v, want both \"\"", blob["active_route"], blob["active_route_family"])
	}
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	breakStore(t, c)

	blob = diagBlob(t)
	if blob["active_route"] != "r-st" {
		t.Fatalf("ExportDiagnostics active_route = %v with a failing store, want r-st", blob["active_route"])
	}
	if blob["active_route_family"] != "vless-reality" {
		t.Fatalf("ExportDiagnostics active_route_family = %v with a failing store, want vless-reality", blob["active_route_family"])
	}
	if blob["route_check"] != RouteCheckOK || blob["route_running"] != true {
		t.Fatalf("route_check=%v route_running=%v: the tunnel is up", blob["route_check"], blob["route_running"])
	}

	body, err := DiagnosticsExplain()
	if err != nil {
		t.Fatalf("DiagnosticsExplain with a failing store: %v", err)
	}
	var exp struct {
		ActiveRoute string `json:"active_route"`
		Pick        struct {
			RouteID string `json:"route_id"`
			Family  string `json:"family"`
		} `json:"pick"`
	}
	if err := json.Unmarshal([]byte(body), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.ActiveRoute != "r-st" {
		t.Fatalf("DiagnosticsExplain active_route = %q with a failing store, want r-st", exp.ActiveRoute)
	}
	if exp.Pick.RouteID != "r-st" {
		t.Fatalf("DiagnosticsExplain pick.route_id = %q with a failing store, want r-st (the app finds the active route through it)", exp.Pick.RouteID)
	}
	if exp.Pick.Family != "vless-reality" {
		t.Fatalf("DiagnosticsExplain pick.family = %q, want vless-reality", exp.Pick.Family)
	}

	// And it follows the engine: disconnect, and it is "" again.
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if got := diagBlob(t)["active_route"]; got != "" {
		t.Fatalf("active_route = %v after disconnect", got)
	}
}

// The field tracks every way a route stops running, and a failed
// connect leaves nothing "active".
func TestActiveRoute_FollowsTheEngine(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if err := SetRoute("r-two"); err != nil {
		t.Fatal(err)
	}
	if got := diagBlob(t)["active_route"]; got != "r-two" {
		t.Fatalf("active_route = %v after a switch, want r-two", got)
	}
	// A liveness failure keeps the instance, so the route stays active.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	CheckActiveRoute()
	blob := diagBlob(t)
	if blob["active_route"] != "r-two" || blob["route_running"] != true {
		t.Fatalf("a lost connection: active_route=%v route_running=%v", blob["active_route"], blob["route_running"])
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	// A connect that fails its proof is torn down: nothing is active.
	stub.InjectProof(failedProof(errSYNTimeout, diagnostics.PhaseHandshake, false, true))
	if err := SetRoute("r-st"); !errors.Is(err, ErrRouteNotCarrying) {
		t.Fatalf("SetRoute = %v", err)
	}
	blob = diagBlob(t)
	if blob["active_route"] != "" || blob["active_route_family"] != "" {
		t.Fatalf("after a failed connect: active_route=%v family=%v, want \"\"", blob["active_route"], blob["active_route_family"])
	}
}

// ---- A2: the polled read path does not write --------------------------

// Observation (root cause 2a): DiagnosticsExplain wrote a row on every
// UI poll, twice a second, for as long as a page was open.
func TestDiagnosticsExplain_WritesOnlyWhenTheRecordChanges(t *testing.T) {
	c, _ := checkInit(t, "r-st")
	if _, err := DiagnosticsExplain(); err != nil {
		t.Fatal(err)
	}
	// The first call persisted the record, as before.
	if n, err := c.store.CountDiagnosticsExplain(); err != nil || n != 1 {
		t.Fatalf("after the first call: %d rows, err %v; want 1", n, err)
	}
	before := c.store.DiagnosticsExplainWrites()
	for i := 0; i < 25; i++ {
		if _, err := DiagnosticsExplain(); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.store.DiagnosticsExplainWrites() - before; n != 0 {
		t.Fatalf("25 polls of DiagnosticsExplain with nothing changed took %d write transactions on the route store, want 0", n)
	}

	// A change is still persisted: the behaviour the row exists for.
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if _, err := DiagnosticsExplain(); err != nil {
		t.Fatal(err)
	}
	_, why, _, err := c.store.LatestDiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(why, "r-st") {
		t.Fatalf("the stored record was not updated after the route changed: %q", why)
	}
	if n := c.store.DiagnosticsExplainWrites() - before; n != 1 {
		t.Fatalf("one change of the record took %d writes, want 1", n)
	}
}

// ---- A4: a damaged store does not fail Init ---------------------------

// The notice must not depend on a file that is written best-effort: on
// a nearly full disk the damaged store is renamed aside, the empty one
// opens, and the marker that remembers it cannot be created. The
// person's routes are gone from the list either way and they must be
// told, at least for this run.
func TestInit_DamagedStoreIsReportedEvenWhenTheMarkerCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "daal.db"), bytes.Repeat([]byte("damaged damaged damaged "), 500), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routestore.SetRecoveryMarkerWriterForTest(func(string, []byte, os.FileMode) error {
		return errors.New("no space left on device")
	}))
	if err := Init(dir, "warn"); err != nil {
		t.Fatalf("Init failed on a damaged route store: %v", err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	if _, err := os.Lstat(filepath.Join(dir, "daal.db.recovered")); err == nil {
		t.Fatal("premise: the marker was written")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "daal.db.damaged-*")); len(matches) != 1 {
		t.Fatalf("premise: set-aside files: %v, want exactly one", matches)
	}
	if got := diagBlob(t)["store_recovered"]; got != true {
		t.Fatalf("store_recovered = %v after a store was set aside in this very Init, want true", got)
	}
}

// Observation (2e): the shell treats a failed engine_init as fatal, so
// a damaged route store would crash the app on every launch.
func TestInit_DamagedStoreIsSetAsideAndReported(t *testing.T) {
	dir := t.TempDir()
	garbage := bytes.Repeat([]byte("damaged damaged damaged "), 500)
	if err := os.WriteFile(filepath.Join(dir, "daal.db"), garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatalf("Init failed on a damaged route store: %v", err)
	}
	t.Cleanup(func() { _ = Shutdown() })

	// Kept, under a dated name, byte for byte.
	matches, _ := filepath.Glob(filepath.Join(dir, "daal.db.damaged-*"))
	if len(matches) != 1 {
		t.Fatalf("set-aside files: %v, want exactly one", matches)
	}
	if got, _ := os.ReadFile(matches[0]); !bytes.Equal(got, garbage) {
		t.Fatal("the set-aside file is not the damaged file")
	}
	blob := diagBlob(t)
	if blob["store_recovered"] != true {
		t.Fatalf("store_recovered = %v after a recovery, want true", blob["store_recovered"])
	}
	if blob["route_count"] != float64(0) {
		t.Fatalf("route_count = %v in the new store", blob["route_count"])
	}

	// Still reported after a restart: the person may not have looked.
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	if got := diagBlob(t)["store_recovered"]; got != true {
		t.Fatalf("store_recovered = %v after a restart with nothing imported, want true", got)
	}
	// Until they have routes again.
	seedStableRoute(t, mustCore(), "r-st")
	if got := diagBlob(t)["store_recovered"]; got != false {
		t.Fatalf("store_recovered = %v once routes exist again, want false", got)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	if got := diagBlob(t)["store_recovered"]; got != false {
		t.Fatalf("store_recovered = %v on the launch after the re-import, want false", got)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "daal.db.damaged-*")); len(m) != 1 {
		t.Fatalf("the set-aside file must stay on disk: %v", m)
	}
}

func TestInit_HealthyStoreIsUntouched(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	seedStableRoute(t, mustCore(), "r-st")
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	blob := diagBlob(t)
	if blob["store_recovered"] != false {
		t.Fatalf("store_recovered = %v on a healthy store, want false", blob["store_recovered"])
	}
	if blob["route_count"] != float64(1) {
		t.Fatalf("route_count = %v: a healthy store lost its routes across a restart", blob["route_count"])
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "daal.db.damaged-*")); len(m) != 0 {
		t.Fatalf("a healthy store was set aside: %v", m)
	}
}

// An error that is not damage still fails Init, and moves nothing.
func TestInit_OrdinaryStoreErrorStillFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "daal.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err == nil {
		_ = Shutdown()
		t.Fatal("Init succeeded although the store could not be opened")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "daal.db.damaged-*")); len(m) != 0 {
		t.Fatalf("files were set aside for an error that is not damage: %v", m)
	}
}

// ---- A5: errors are diagnosable ---------------------------------------

// Observation: three screens failed and nothing — not the page, not the
// shell, not logcat — could say why.
func TestRecentErrors_RecordedLoggedAndScrubbed(t *testing.T) {
	checkInit(t, "r-st")
	resetRecentErrorsForTest()
	t.Cleanup(resetRecentErrorsForTest)
	lc := captureLog(t)

	const (
		addr   = "203.0.113.77:8443"
		host   = "relay-7.example.org"
		uuid   = "5f1c0f3e-9a41-4f7b-8f55-0d5c3a1b2c9d"
		secret = "hunter2-very-secret"
		key    = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
		url    = "https://sub.example.net/api/v1/pack?token=abcdef"
	)
	noteExportError("engine_subscription_list", fmt.Errorf(
		"dial tcp %s: connection refused (host %s, uuid %s, password=%q, key %s, from %s)",
		addr, host, uuid, secret, key, url))

	errs, _ := diagBlob(t)["recent_errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("recent_errors has %d entries, want 1: %v", len(errs), errs)
	}
	entry, _ := errs[0].(map[string]any)
	text, _ := entry["text"].(string)
	if entry["call"] != "engine_subscription_list" || text == "" || entry["time"] == "" {
		t.Fatalf("entry = %v", entry)
	}
	if !strings.Contains(text, "connection refused") {
		t.Fatalf("the text lost the error class: %q", text)
	}
	line := ""
	for _, l := range lc.all() {
		if strings.HasPrefix(l, "engine_subscription_list: ") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no \"engine_subscription_list: …\" line reached the engine log: %v", lc.all())
	}
	for _, leaked := range []string{addr, "203.0.113.77", host, "example.org", uuid, secret, key, "sub.example.net", "token=abcdef"} {
		if strings.Contains(text, leaked) {
			t.Errorf("recent_errors text leaks %q: %q", leaked, text)
		}
		if strings.Contains(line, leaked) {
			t.Errorf("log line leaks %q: %q", leaked, line)
		}
	}

	// The low-level entry scrubs too: nothing reaches the ring raw.
	noteExportFailure("engine_x", "failed talking to "+addr)
	if all := recentErrors(); strings.Contains(all[len(all)-1].Text, "203.0.113.77") {
		t.Fatalf("noteExportFailure kept an address: %q", all[len(all)-1].Text)
	}

	// A call that is handed secrets keeps none of its error text.
	noteExportError("engine_uri_import", fmt.Errorf("uri: cannot parse %q", "vless://"+uuid+"@"+host+":443"))
	last := recentErrors()
	if got := last[len(last)-1].Text; strings.Contains(got, "vless") || strings.Contains(got, "cannot parse") || !strings.Contains(got, "class=") {
		t.Fatalf("a secret-handling call kept error text: %q", got)
	}

	// A poll that fails every time is one entry and does not flood the
	// log; the ring is bounded.
	resetRecentErrorsForTest()
	before := len(lc.all())
	for i := 0; i < 1000; i++ {
		noteExportError("engine_diagnostics_explain", errors.New("abi: not initialized"))
	}
	got := recentErrors()
	if len(got) != 1 || got[0].Count != 1000 {
		t.Fatalf("1000 identical failures: %d entries, count %d; want 1 entry with count 1000", len(got), got[0].Count)
	}
	if n := len(lc.all()) - before; n > 12 {
		t.Fatalf("1000 identical failures wrote %d log lines", n)
	}
	// Two polls failing in turn are two entries, not two thousand.
	resetRecentErrorsForTest()
	before = len(lc.all())
	for i := 0; i < 1000; i++ {
		noteExportError("engine_stats_redacted", errors.New("engine: not connected"))
		noteExportError("engine_diagnostics_explain", errors.New("abi: not initialized"))
	}
	if got := recentErrors(); len(got) != 2 || got[0].Count != 1000 || got[1].Count != 1000 {
		t.Fatalf("two alternating failures: %v", got)
	}
	if n := len(lc.all()) - before; n > 24 {
		t.Fatalf("two alternating failures wrote %d log lines", n)
	}
	for i := 0; i < 3*recentErrorsMax; i++ {
		noteExportFailure(fmt.Sprintf("engine_call_%d", i), "failed")
	}
	got = recentErrors()
	if len(got) != recentErrorsMax {
		t.Fatalf("ring holds %d entries, want %d", len(got), recentErrorsMax)
	}
	if got[len(got)-1].Call != fmt.Sprintf("engine_call_%d", 3*recentErrorsMax-1) {
		t.Fatalf("the newest entry is not last: %v", got[len(got)-1])
	}
}

// A failed engine_set_route is reduced to the route id and a closed
// code. None of the error's own text may be used: a proof failure's
// text carries the relay's address.
func TestRecentErrors_SetRouteKeepsOnlyCodes(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	resetRecentErrorsForTest()
	t.Cleanup(resetRecentErrorsForTest)

	record := func(id string) string {
		t.Helper()
		err := SetRoute(id)
		if err == nil {
			t.Fatalf("SetRoute(%s) succeeded", id)
		}
		noteRouteError("engine_set_route", id, err)
		all := recentErrors()
		return all[len(all)-1].Text
	}

	if got := record("no-such-route"); got != "route=no-such-route result=refused code=other" {
		t.Fatalf("unknown route: %q", got)
	}
	// A proof failure whose text names an address.
	stub.InjectProof(failedProof(errors.New("dial tcp 198.51.100.9:443: i/o timeout"), diagnostics.PhaseHandshake, false, true))
	got := record("r-st")
	if cat, ok := strings.CutPrefix(got, "route=r-st result=not_carrying category="); !ok || cat == "" || strings.ContainsAny(cat, " .:") {
		t.Fatalf("failed proof: %q", got)
	}
	// A cooling route.
	coolDown(t, c, "r-st")
	if got := record("r-st"); got != "route=r-st result=refused code=cooldown" {
		t.Fatalf("cooling route: %q", got)
	}
	// The engine could not start the instance at all.
	seedStableRoute(t, c, "r-two")
	stub.InjectFailure(errors.New("box.New: dial 198.51.100.9:443: connection refused"))
	if got := record("r-two"); !strings.HasPrefix(got, "route=r-two result=start_failed category=") || strings.Contains(got, "198.51.100.9") {
		t.Fatalf("start failure: %q", got)
	}
	// A hostile id cannot put text in the log.
	noteRouteError("engine_set_route", "x\n password=abc https://a.example/p", errors.New("abi: nope"))
	all := recentErrors()
	if got := all[len(all)-1].Text; strings.ContainsAny(got, "\n/") || strings.Contains(got, "password=abc") {
		t.Fatalf("the route id was not reduced: %q", got)
	}
}

// Every C-ABI wrapper reports its failure through the helper. Checked
// on the source, because a cgo file cannot be called from a test: an
// exported function must not return a negative literal directly.
func TestEveryExportWrapperReportsItsFailure(t *testing.T) {
	files, err := filepath.Glob("*_export.go")
	if err != nil || len(files) < 15 {
		t.Fatalf("export files: %v (%v)", files, err)
	}
	fset := token.NewFileSet()
	wrappers := 0
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "engine_") {
				continue
			}
			wrappers++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, r := range ret.Results {
					if u, ok := r.(*ast.UnaryExpr); ok && u.Op == token.SUB {
						t.Errorf("%s: %s returns a bare negative code at %s; use exportFail / exportFailCode / exportNotReady so the failure is logged and kept in recent_errors",
							name, fn.Name.Name, fset.Position(ret.Pos()))
					}
				}
				return true
			})
		}
	}
	if wrappers < 50 {
		t.Fatalf("only %d export wrappers were examined; the scan is not seeing the files", wrappers)
	}
}

// One Info line for route up, switch, refused and down — and none of
// them carries anything from the route's profile.
func TestRouteLifecycleIsLogged(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	lc := captureLog(t)

	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	if !lc.has("route up route=r-st family=vless-reality result=ok") {
		t.Fatalf("no route-up line: %v", lc.all())
	}
	// Liveness checks that change nothing add no lines.
	n := len(lc.all())
	CheckActiveRoute()
	CheckActiveRoute()
	if len(lc.all()) != n {
		t.Fatalf("an unchanged liveness check logged: %v", lc.all()[n:])
	}
	if err := SetRoute("r-two"); err != nil {
		t.Fatal(err)
	}
	if !lc.has("route switch from=r-st to=r-two family=vless-reality") || !lc.has("route up route=r-two") {
		t.Fatalf("no switch / up lines: %v", lc.all())
	}
	_ = SetRoute("no-such-route")
	if !lc.has("route refused route=no-such-route code=other still_running=r-two") {
		t.Fatalf("no refused line: %v", lc.all())
	}
	stub.InjectProof(failedProof(fmt.Errorf("dial tcp 198.51.100.9:443: %w", errSYNTimeout), diagnostics.PhaseHandshake, false, true))
	CheckActiveRoute()
	if !lc.has("route down route=r-two family=vless-reality result=failed category=tcp_connect_timeout running=true") {
		t.Fatalf("no route-down line for a lost connection: %v", lc.all())
	}
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	if !lc.has("route down route=r-two family=vless-reality result=disconnected") {
		t.Fatalf("no disconnect line: %v", lc.all())
	}
	for _, l := range lc.all() {
		for _, leaked := range []string{"example.invalid", "198.51.100.9", "server_port"} {
			if strings.Contains(l, leaked) {
				t.Errorf("log line leaks %q: %q", leaked, l)
			}
		}
	}
}

// ---- A6: a refused switch ---------------------------------------------

func coolDown(t *testing.T, c *Core, routeID string) {
	t.Helper()
	c.mu.Lock()
	c.pm.Failed(routeID, "vless-reality", diagnostics.TCPConnectTimeout)
	c.mu.Unlock()
	if ok, _ := c.pm.CanAttempt(routeID, "vless-reality"); ok {
		t.Fatalf("premise: %s is not cooling down", routeID)
	}
}

// A refused switch changes nothing and records why — and the person's
// own Disconnect afterwards clears that record, however soon it comes.
//
// The engine used to KEEP the refusal through a ClearRoute that
// followed it within five seconds, for a host that tore everything
// down after a refused switch (the Android service on the first phone
// pass). No host does that any more: the service asks
// engine_route_precheck first and a refused switch touches nothing
// (vpn/StartSequence.kt). The only ClearRoute left in that window was
// the person tapping Disconnect, after which a disconnected app went on
// reporting "refused: cooldown" for a route it was not even trying.
func TestRefusedSwitch_LeavesTheRouteAloneAndADisconnectClearsTheReason(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	// r-two goes into a cooldown without disturbing what is running.
	c.mu.Lock()
	c.pm.Resume("r-two", "vless-reality")
	c.pm.Failed("r-two", "vless-reality", diagnostics.TCPConnectTimeout)
	c.pm.Resume("r-st", "vless-reality")
	c.pm.Connected()
	c.mu.Unlock()
	proofs := stub.ProofCount()

	if err := SetRoute("r-two"); err == nil {
		t.Fatal("a cooling route was attempted")
	}
	blob := diagBlob(t)
	for k, want := range map[string]any{
		"active_route":          "r-st",
		"route_check":           RouteCheckOK,
		"route_running":         true,
		"connect_refused":       ConnectRefusedCooldown,
		"connect_refused_route": "r-two",
	} {
		if blob[k] != want {
			t.Errorf("after a refused switch: %s = %v, want %v", k, blob[k], want)
		}
	}
	if !stub.Connected() || stub.ProofCount() != proofs {
		t.Fatalf("the refused switch disturbed the running route: connected=%v proofs %d→%d", stub.Connected(), proofs, stub.ProofCount())
	}

	// The person taps Disconnect at once (well inside the old window).
	if err := ClearRoute(); err != nil {
		t.Fatal(err)
	}
	blob = diagBlob(t)
	if blob["connect_refused"] != ConnectRefusedNone || blob["connect_refused_route"] != "" {
		t.Fatalf("a disconnected engine still reports a refusal: connect_refused=%v route=%v", blob["connect_refused"], blob["connect_refused_route"])
	}
	if blob["route_check"] != RouteCheckNone || blob["active_route"] != "" || blob["posture"] != string(pathmanager.PostureNoRoute) {
		t.Fatalf("the disconnect did not disconnect: route_check=%v active_route=%v posture=%v", blob["route_check"], blob["active_route"], blob["posture"])
	}
}

// engine_route_precheck: the same answer SetRoute would give, with
// nothing started and nothing stopped.
func TestRouteConnectPrecheck(t *testing.T) {
	c, stub := checkInit(t, "r-st")
	seedStableRoute(t, c, "r-two")
	seedStableRoute(t, c, "r-cool")
	if err := SetRoute("r-st"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.pm.Resume("r-cool", "vless-reality")
	c.pm.Failed("r-cool", "vless-reality", diagnostics.TCPConnectTimeout)
	c.pm.Resume("r-st", "vless-reality")
	c.pm.Connected()
	epoch := c.routeEpoch
	c.mu.Unlock()
	proofs := stub.ProofCount()

	check := func(id string) map[string]any {
		t.Helper()
		body, err := RouteConnectPrecheck(id)
		if err != nil {
			t.Fatalf("RouteConnectPrecheck(%s): %v", id, err)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// A route that would be attempted: says so, changes nothing.
	out := check("r-two")
	if out["refused"] != "" || out["route_id"] != "r-two" || out["active_route"] != "r-st" {
		t.Fatalf("precheck of a usable route = %v", out)
	}
	blob := diagBlob(t)
	if blob["connect_refused"] != ConnectRefusedNone || blob["active_route"] != "r-st" || blob["route_check"] != RouteCheckOK {
		t.Fatalf("a passing precheck changed state: %v / %v / %v", blob["connect_refused"], blob["active_route"], blob["route_check"])
	}

	// Refusals: the code, recorded exactly as SetRoute records it.
	if out := check("r-cool"); out["refused"] != ConnectRefusedCooldown {
		t.Fatalf("precheck of a cooling route = %v", out)
	}
	blob = diagBlob(t)
	if blob["connect_refused"] != ConnectRefusedCooldown || blob["connect_refused_route"] != "r-cool" {
		t.Fatalf("a refusing precheck did not record the reason: %v / %v", blob["connect_refused"], blob["connect_refused_route"])
	}
	if out := check("no-such-route"); out["refused"] != ConnectRefusedOther {
		t.Fatalf("precheck of an unknown route = %v", out)
	}
	if err := c.store.MarkRouteRevoked("r-two"); err != nil {
		t.Fatal(err)
	}
	if out := check("r-two"); out["refused"] != ConnectRefusedRevoked {
		t.Fatalf("precheck of a revoked route = %v", out)
	}

	// Through all of it the connected route was never touched.
	c.mu.Lock()
	sameEpoch := c.routeEpoch == epoch
	active := c.activeRoute
	c.mu.Unlock()
	if !sameEpoch || active != "r-st" || !stub.Connected() || stub.ProofCount() != proofs {
		t.Fatalf("precheck disturbed the running route: epoch same=%v active=%q connected=%v proofs %d→%d",
			sameEpoch, active, stub.Connected(), proofs, stub.ProofCount())
	}
	// And the precheck agrees with SetRoute.
	if err := SetRoute("r-cool"); !errors.Is(err, errRouteCooling) {
		t.Fatalf("SetRoute(r-cool) = %v, want the cooldown refusal the precheck predicted", err)
	}

	// A build that cannot tunnel says so and records nothing.
	dataPlaneLinked = false
	out = check("r-st")
	dataPlaneLinked = true
	if out["refused"] != "no_data_plane" {
		t.Fatalf("precheck without a data plane = %v", out)
	}
}

func TestRouteConnectPrecheck_NotInitialised(t *testing.T) {
	if loadedCore() != nil {
		t.Skip("an engine is up")
	}
	if _, err := RouteConnectPrecheck("r-st"); err == nil {
		t.Fatal("RouteConnectPrecheck before Init returned no error")
	}
}
