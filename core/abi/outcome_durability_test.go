package abi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/core/engine"
	"daal/core/internal/selection"
)

// Wave 5 (telemetry). Before this pass the connect path computed a
// classified outcome on every attempt and dropped it: `proven` was
// false and `health_pct` null on every route in every install, forever,
// because the five routestore history columns had no writer. These
// tests pin the write and — more importantly — pin that it SURVIVES A
// RESTART, which is the whole difference between a signal a selector
// can use and one that dies with the process.

func TestSetRoute_PersistsSuccessAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	seedStableRoute(t, mustCore(), "r-st")

	// The route is unproven before anything has been attempted.
	before := routeSummary(t, "r-st")
	if before.Proven {
		t.Fatal("route reported proven before any attempt")
	}
	if before.HealthPct != nil {
		t.Fatalf("health_pct = %v before any attempt; want null", *before.HealthPct)
	}

	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}

	// Restart on the same state dir. The pathmanager FSM is gone; only
	// the durable columns remain, and they are what must carry the
	// fact forward.
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	after := routeSummary(t, "r-st")
	if !after.Proven {
		t.Fatal("a route that connected is not proven after restart")
	}
	if after.HealthPct == nil {
		t.Fatal("health_pct is still null after a recorded success")
	}
	if *after.HealthPct != 100 {
		t.Fatalf("health_pct = %v after a clean success; want 100", *after.HealthPct)
	}
}

func TestSetRoute_PersistsClassifiedFailure(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	// Drive a deterministic failure through the stub driver. The
	// message is one diagnostics.Classify maps to a real category, so
	// the test asserts the CATEGORY reached the column rather than a
	// generic "unknown".
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skipf("driver is %T, not the stub; this test drives the stub", c.driver)
	}
	stub.InjectFailure(errFakeTLS{})

	if err := SetRoute("r-st"); err == nil {
		t.Fatal("SetRoute should have failed")
	}

	row, err := c.store.GetRoute("r-st")
	if err != nil {
		t.Fatal(err)
	}
	if row.LastFailureCategory != "tls_handshake_failed" {
		t.Fatalf("last_failure_category = %q, want tls_handshake_failed", row.LastFailureCategory)
	}
	if row.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive_failures = %d, want 1", row.ConsecutiveFailures)
	}
	if row.LastFailureBucket == "" {
		t.Fatal("last_failure_bucket not stamped")
	}
	// The durable cooldown must agree with the FSM's, not be
	// re-derived: perRouteCooldown(tls_handshake_failed) is 30 min and
	// the column has to name the same instant the FSM will honour.
	if row.CooldownUntil == "" {
		t.Fatal("cooldown_until not stamped for a cooling-down class")
	}
	if want := pmCooldownUntil(c, "r-st"); row.CooldownUntil != want.UTC().Format("2006-01-02T15:04:05Z07:00") {
		t.Fatalf("cooldown_until = %q, FSM says %v", row.CooldownUntil, want)
	}
	// A failure alone must NOT manufacture a health percentage: there
	// is no success rate to report, and 0 would read as "measured
	// terrible" rather than "never worked".
	sum := routeSummary(t, "r-st")
	if sum.Proven {
		t.Fatal("a route that only ever failed reports proven")
	}
	if sum.HealthPct != nil {
		t.Fatalf("health_pct = %v after failures only; want null", *sum.HealthPct)
	}
}

// errFakeTLS carries a message diagnostics.Classify maps onto
// TLSHandshakeFailed.
type errFakeTLS struct{}

func (errFakeTLS) Error() string { return "tls: handshake failure" }

func routeSummary(t *testing.T, routeID string) RouteSummaryDisplay {
	t.Helper()
	body, err := RouteSummary(routeID)
	if err != nil {
		t.Fatalf("RouteSummary: %v", err)
	}
	var out RouteSummaryDisplay
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if strings.TrimSpace(out.RouteID) == "" {
		t.Fatalf("empty summary: %s", body)
	}
	return out
}

// Input.NetworkSignals had no producer anywhere in the tree; every
// Decide call in production ran with an empty set. This pins the first
// one — and, as importantly, pins that it stays empty when there is
// nothing to say.

func TestActiveNetworkSignals_EmptyWithoutFailures(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	if got := activeNetworkSignals(c, time.Now().UTC()); len(got) != 0 {
		t.Fatalf("signals on a fresh install = %v, want none", got)
	}
}

func TestActiveNetworkSignals_DerivedFromRecordedFailures(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	now := time.Date(2026, 8, 18, 14, 30, 0, 0, time.UTC)
	if err := c.store.RecordFailure("r-st", "udp_collapsed", time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	got := activeNetworkSignals(c, now)
	if len(got) != 1 || got[0] != selection.SignalUDPCollapsed {
		t.Fatalf("signals = %v, want [udp_collapsed]", got)
	}

	// The previous bucket still counts (a failure at 13:59 is a live
	// signal at 14:01)...
	if got := activeNetworkSignals(c, now.Add(time.Hour)); len(got) != 1 {
		t.Fatalf("signals one hour later = %v, want the failure to still count", got)
	}
	// ...and a day later it does not. A stale signal fed to a live
	// decision is how a selector explains a confident wrong answer.
	if got := activeNetworkSignals(c, now.Add(24*time.Hour)); len(got) != 0 {
		t.Fatalf("signals a day later = %v, want none", got)
	}
}

// A route that failed and then CONNECTED has disproved its own signal.
// RecordSuccess deliberately leaves the failure columns in place so
// "flaky vs solid" stays readable, which means the raw columns keep
// asserting udp_collapsed about a network the route has since carried a
// tunnel on. Selection reads this set; leaving it uncorrected is the app
// demoting its working routes and explaining why.
func TestActiveNetworkSignals_SuppressedAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	failedAt := time.Date(2026, 8, 18, 14, 5, 0, 0, time.UTC)
	if err := c.store.RecordFailure("r-st", "udp_collapsed", time.Time{}, failedAt); err != nil {
		t.Fatal(err)
	}
	if got := activeNetworkSignals(c, failedAt); len(got) != 1 {
		t.Fatalf("precondition: signals right after the failure = %v, want one", got)
	}

	// Recovery INSIDE the same hour bucket — the case hour-bucket
	// comparison cannot decide and consecutive_failures can.
	if err := c.store.RecordSuccess("r-st", failedAt.Add(25*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := activeNetworkSignals(c, failedAt.Add(30*time.Minute)); len(got) != 0 {
		t.Fatalf("signals after a same-hour recovery = %v, want none", got)
	}

	// A LATER failure re-arms it — recovery suppresses the failure it
	// followed, not every failure forever. Same hour bucket again, so
	// this also pins that the re-arm does not depend on a bucket
	// rollover.
	if err := c.store.RecordFailure("r-st", "udp_collapsed", time.Time{}, failedAt.Add(40*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := activeNetworkSignals(c, failedAt.Add(45*time.Minute)); len(got) != 1 {
		t.Fatalf("signals after a fresh failure = %v, want it re-armed", got)
	}
}

func TestActiveNetworkSignals_NonMirroredCategoriesProduceNothing(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	now := time.Date(2026, 8, 18, 14, 30, 0, 0, time.UTC)
	// auth_failed is a real, recorded, recent failure that carries NO
	// network signal — it says something about credentials, not about
	// the network. Manufacturing a signal from it would be the exact
	// fabrication this lane exists to remove.
	if err := c.store.RecordFailure("r-st", "auth_failed", time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	if got := activeNetworkSignals(c, now); len(got) != 0 {
		t.Fatalf("signals from auth_failed = %v, want none", got)
	}
}

func TestDiagnosticsExplain_CarriesTheRealSignalSet(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	// Connect so the FSM has an active route (DiagnosticsExplain only
	// runs Decide when one exists), then record a live failure signal.
	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	if err := c.store.RecordFailure("r-st", "sni_rst", time.Time{}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	body, err := DiagnosticsExplain()
	if err != nil {
		t.Fatalf("DiagnosticsExplain: %v", err)
	}
	var payload struct {
		NetworkSignals []string `json:"network_signals"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.NetworkSignals) != 1 || payload.NetworkSignals[0] != "sni_rst" {
		t.Fatalf("network_signals = %v, want [sni_rst]; body=%s", payload.NetworkSignals, body)
	}
}

// Wave 6 (rotation ladder). Explanation.Failures had no producer:
// selection.Decide returns a race PLAN, so no candidate has failed at
// plan time and the field was `[]` in every blob this app has ever
// emitted. The publisher's rotation recommender reads exactly that
// field, so on real data it had nothing to reason from and answered its
// no-evidence default whatever was actually wrong.
func TestDiagnosticsExplain_CarriesTheRecordedFailures(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")

	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}

	// Before any failure the list is empty — and empty is the honest
	// answer, not a placeholder.
	body, err := DiagnosticsExplain()
	if err != nil {
		t.Fatalf("DiagnosticsExplain: %v", err)
	}
	if got := explainFailures(t, body); len(got) != 0 {
		t.Fatalf("failures before any recorded failure = %v, want none", got)
	}

	if err := c.store.RecordFailure("r-st", "tcp_reset", time.Time{}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body, err = DiagnosticsExplain()
	if err != nil {
		t.Fatalf("DiagnosticsExplain: %v", err)
	}
	got := explainFailures(t, body)
	if len(got) != 1 {
		t.Fatalf("failures = %v, want one; body=%s", got, body)
	}
	if got[0].RouteID != "r-st" || got[0].Classification != "tcp_reset" {
		t.Fatalf("failure = %+v, want {r-st tcp_reset}", got[0])
	}
	// Tag is the cooldown-PROPAGATION attribution, and nothing in the
	// tree produces one. A tag here would make the publisher's rule 6
	// fire and answer "destroy this server and rebuild it in another
	// datacenter" on the evidence of one reset.
	if got[0].Tag != "" {
		t.Fatalf("failure carried tag %q; an absent attribution must stay absent", got[0].Tag)
	}
}

// The recovery rule is shared with the signal set, so it must hold on
// this surface too: a route that failed and then connected is not
// currently failing, whatever its (deliberately retained) failure
// columns still say.
func TestDiagnosticsExplain_FailuresSuppressedAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	c := mustCore()
	seedStableRoute(t, c, "r-st")
	if err := SetRoute("r-st"); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}

	at := time.Now().UTC()
	if err := c.store.RecordFailure("r-st", "tcp_reset", time.Time{}, at); err != nil {
		t.Fatal(err)
	}
	body, err := DiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	if len(explainFailures(t, body)) != 1 {
		t.Fatalf("precondition: expected one failure; body=%s", body)
	}

	if err := c.store.RecordSuccess("r-st", at.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	body, err = DiagnosticsExplain()
	if err != nil {
		t.Fatal(err)
	}
	if got := explainFailures(t, body); len(got) != 0 {
		t.Fatalf("failures after recovery = %v, want none", got)
	}
}

func explainFailures(t *testing.T, body string) []selection.FailureRecord {
	t.Helper()
	var payload struct {
		Failures []selection.FailureRecord `json:"failures"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("unmarshal explain body: %v", err)
	}
	return payload.Failures
}
