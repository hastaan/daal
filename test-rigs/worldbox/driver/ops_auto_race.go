package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Racing and measurement — the second slice of the automatic connect, as
// op `auto` sees it (the engine's half: core/abi/connect_race.go,
// core/netmem/measure.go).
//
// The first slice tried the routes one after another, and several dead
// ones in a row cost the person the sum of their timeouts. The engine now
// checks TWO beside each other — never more, because every route a phone
// knows starting in the same second to one address is a burst a censor
// can recognise — and remembers, per network, how each route did.
//
// Every press of op `auto`, whatever else it is about, is asked the one
// question (twoAtATime): did the censor ever see this phone with more
// than two routes in flight? The phone `race` asks the rest:
//
//	connect   The censor drops the two routes a phone that remembers
//	          nothing checks first (learned from phone `first`: the pair
//	          is the engine's choice, not the ranking's first two). They
//	          are checked beside each other, both are named not_carrying
//	          with each other as `raced_with`, a third route carries, and
//	          the press takes clearly less than their two budgets one
//	          after the other. At the censor the second route's first
//	          packet follows the first's by the delay the engine promises.
//	          The route list then says how each did HERE: the two dropped
//	          ones "failing", the one that carried graded and timed.
//	again     Disconnect, Connect, the block still in place: the route
//	          that carried here is checked ALONE — the censor sees new
//	          connections to one endpoint and no other.

// The engine's stated numbers this op holds it to (core/abi/connect_race.go,
// core/abi/connect_auto.go). They are repeated here, not imported: the
// rig asserts what the engine SAYS it does.
const (
	// AutoMaxInFlight: raceMaxInFlight.
	AutoMaxInFlight = 2
	// AutoSilentBudget: what the engine SAYS one route to an address that
	// answers nothing costs a pass — one attempt, 4 s
	// (ProofConfig.StopAtUnreachedRelay; backlog AC-30).
	// AutoSilentCost: what it costs on this rig when the censor drops the
	// SYN — both attempts, 8 s: a timed-out connect does not say which
	// phase it died in, the check that settles it runs beside the second
	// attempt, and the stop is only looked at between attempts (FINDINGS
	// AUTO-2). The race is held to both: it must beat two routes one
	// after the other as they really cost (green), and it should be done
	// in one stated budget (red, known, until AUTO-2 is closed).
	AutoSilentBudget = 4 * time.Second
	AutoSilentCost   = 2 * AutoSilentBudget
	// AutoRaceDelayMin / Max: the second probe of a pair starts this long
	// after the first (raceDelayMin, raceDelayMax). At the censor the gap
	// between the two first packets also carries the difference between
	// two instance starts, so the floor asserted is a little under the
	// engine's and the ceiling well over.
	AutoRaceDelayMin   = 150 * time.Millisecond
	AutoRaceDelayMax   = 450 * time.Millisecond
	autoRaceGapFloor   = 100 * time.Millisecond
	autoRaceGapCeiling = 1500 * time.Millisecond
	// autoRaceRoom: the second probe's delay and the carrying route's
	// own connect, with room for a loaded machine.
	autoRaceRoom = AutoRaceDelayMax + 2500*time.Millisecond
	// AutoRaceWithin bounds a press whose first two routes are silent and
	// whose third carries, as a silent route really costs: one after the
	// other the two alone are 16 s before anything carries.
	// AutoRaceWithinStated is the same with the cost the engine states.
	AutoRaceWithin       = AutoSilentCost + autoRaceRoom
	AutoRaceWithinStated = AutoSilentBudget + autoRaceRoom
)

var autoGrades = map[string]bool{"unknown": true, "good": true, "ok": true, "slow": true, "failing": true}

// tap starts the censor's packet log for this world. Without it the
// two-at-a-time question is answered from the engine's own account only,
// and every answer says so.
func (a *autoOp) tap() {
	t0 := time.Now()
	err := StartFlowTap(a.rc.Ctx, a.rc.P)
	a.tapOK = err == nil
	a.rc.R.Add("", a.phase, "censor.flow_tap", Pass, got(err == nil, Pass, Fail), errStr(err), nil, t0)
}

func (x *autoAnswer) entry(routeID string) map[string]any {
	for _, t := range x.all {
		if t["route_id"] == routeID {
			return t
		}
	}
	return nil
}

// racingSeen: every distinct `auto.racing` the poll saw during the press.
func (x *autoAnswer) racingSeen() (pairs [][]string, most int) {
	rows, _ := x.ev["progress"].([]any)
	seen := map[string]bool{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		ids := anyStrings(m["racing"])
		if len(ids) == 0 {
			continue
		}
		if len(ids) > most {
			most = len(ids)
		}
		if k := strings.Join(ids, ","); !seen[k] {
			seen[k] = true
			pairs = append(pairs, ids)
		}
	}
	return pairs, most
}

// sawRacing: a page polling the diagnostics saw the two routes named as
// being checked together, `trying` the first of the pair.
func (x *autoAnswer) sawRacing(a, b string) (bool, string) {
	rows, _ := x.ev["progress"].([]any)
	for _, r := range rows {
		m, _ := r.(map[string]any)
		ids := anyStrings(m["racing"])
		if len(ids) != 2 || !(ids[0] == a && ids[1] == b || ids[0] == b && ids[1] == a) {
			continue
		}
		if m["state"] != "trying" || m["trying"] != ids[0] {
			return false, fmt.Sprintf("racing=%v with state=%v trying=%v: `trying` must stay the first of the pair, for a page that knows nothing of racing", ids, m["state"], m["trying"])
		}
		return true, ""
	}
	return false, fmt.Sprintf("the diagnostics never showed %s and %s being checked together (auto.racing)", a, b)
}

// twoAtATime is asked of every press: at the censor, the phone never had
// more than AutoMaxInFlight routes in flight (flowtap.go for what "in
// flight" means there and what it cannot see), and the engine's own
// `auto.racing` never named more.
func (p *autoPhone) twoAtATime(step string, x *autoAnswer, t0 time.Time) {
	pairs, most := x.racingSeen()
	ev := map[string]any{"engine_racing_seen": pairs, "tried": x.triedText()}
	var wrong []string
	if most > AutoMaxInFlight {
		wrong = append(wrong, fmt.Sprintf("auto.racing named %d routes at once", most))
	}
	detail := ""
	if !p.op.tapOK {
		detail = "the censor's packet log is not running: judged from the engine's own account only, which is weaker"
	} else if pkts, err := ReadFlowTap(p.op.rc.P); err != nil {
		wrong = append(wrong, "the censor's packet log could not be read: "+err.Error())
	} else {
		x.uses = flowUses(pkts, x.from, x.to)
		n, set := maxConcurrent(x.uses)
		ev["censor_saw"], ev["most_endpoints_at_once"] = flowText(x.uses, x.from), n
		if n > AutoMaxInFlight {
			wrong = append(wrong, fmt.Sprintf("the censor saw new connections to %d of the relay's endpoints at the same time (%s): %s",
				n, strings.Join(set, ", "), flowText(x.uses, x.from)))
		}
	}
	if len(wrong) > 0 {
		detail = strings.Join(wrong, "; ")
	}
	p.add(step, "", "at_most_two_routes_in_flight", Pass, got(len(wrong) == 0, Pass, Fail), detail, ev, t0)
}

// useOf is the censor's record of one family's endpoint in this press.
func (x *autoAnswer) useOf(f Family) (endpointUse, bool) {
	ep := fmt.Sprintf("%s/%d", f.Endpoint.Proto, f.Endpoint.Port)
	for _, u := range x.uses {
		if u.Endpoint == ep {
			return u, true
		}
	}
	return endpointUse{}, false
}

// ---- what the route list says of this network ---------------------------

// measuredRow is one route's `measured` block: how it did on the network
// the phone is on (engine_available_routes / engine_route_summary).
type measuredRow struct {
	Present                           bool
	Grade                             string
	SetupMs, Samples, Carried, Failed int
	Last                              int64
}

func (m measuredRow) text() string {
	if !m.Present {
		return "no `measured` block"
	}
	return fmt.Sprintf("grade=%s setup_ms=%d samples=%d carried=%d failed=%d last=%d", m.Grade, m.SetupMs, m.Samples, m.Carried, m.Failed, m.Last)
}

func parseMeasured(v any) measuredRow {
	m, ok := v.(map[string]any)
	if !ok {
		return measuredRow{}
	}
	n := func(k string) int { f, _ := m[k].(float64); return int(f) }
	last, _ := m["last"].(float64)
	return measuredRow{Present: true, Grade: str(m, "grade"), SetupMs: n("setup_ms"), Samples: n("samples"), Carried: n("carried"), Failed: n("failed"), Last: int64(last)}
}

// listing asks for what the Connections page reads. rows: every route's
// `measured`; summary: the connected route's, from its own summary (the
// main screen's line), nil when nothing is connected.
func (p *autoPhone) listing(step string, t0 time.Time) (rows map[string]measuredRow, summary *measuredRow, ok bool) {
	ev := p.ask(step, "listing", "listing", 20*time.Second, t0)
	if ev == nil {
		return nil, nil, false
	}
	rows = map[string]measuredRow{}
	doc, _ := ev["routes"].(map[string]any)
	list, _ := doc["routes"].([]any)
	for _, r := range list {
		m, _ := r.(map[string]any)
		rows[str(m, "route_id")] = parseMeasured(m["measured"])
	}
	if sum, isMap := ev["summary"].(map[string]any); isMap {
		m := parseMeasured(sum["measured"])
		summary = &m
	}
	if e := str(ev, "error"); e != "" || len(rows) == 0 {
		p.add(step, "", "listing", Pass, Fail, "engine_available_routes: "+e, nil, t0)
		return nil, nil, false
	}
	return rows, summary, true
}

func measuredText(rows map[string]measuredRow) string {
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var parts []string
	for _, id := range ids {
		parts = append(parts, id+": "+rows[id].text())
	}
	return strings.Join(parts, " | ")
}

// measuredAfterConnect: after a press that connected, the route list
// says how the routes did HERE — the row and the summary of the route
// that carried agree, it is graded and counted, and a route nothing was
// asked of says "unknown" and not a guess.
func (p *autoPhone) measuredAfterConnect(step string, x *autoAnswer, cands []autoRoute, t0 time.Time) {
	rows, summary, ok := p.listing(step, t0)
	if !ok {
		return
	}
	var wrong []string
	for id, m := range rows {
		if !m.Present {
			wrong = append(wrong, id+" has no `measured` block")
		} else if !autoGrades[m.Grade] {
			wrong = append(wrong, fmt.Sprintf("%s: grade %q is not one of unknown|good|ok|slow|failing", id, m.Grade))
		}
	}
	on := rows[x.routeID]
	attempt := 0
	if t := x.triedEntry(x.routeID); t != nil {
		ms, _ := t["setup_ms"].(float64)
		attempt = int(ms)
	}
	switch {
	case !on.Present:
	case on.Grade != "good" && on.Grade != "ok":
		wrong = append(wrong, "the route that just carried is graded "+on.Grade)
	case on.Samples < 1 || on.Carried < 1 || on.Last <= 0:
		wrong = append(wrong, "the route that just carried: "+on.text())
	case attempt <= 0:
		wrong = append(wrong, "the call gives no setup_ms for the route that carried")
	case attempt >= 5 && on.SetupMs <= 0:
		// (The remembered time is rounded to 10 ms; an attempt under 5 ms
		// may honestly read 0.)
		wrong = append(wrong, fmt.Sprintf("this attempt took %d ms and the remembered setup time is %d", attempt, on.SetupMs))
	}
	if summary == nil || !summary.Present {
		wrong = append(wrong, "engine_route_summary of the connected route has no `measured` block (the main screen's line reads it)")
	} else if *summary != on {
		wrong = append(wrong, "the summary says "+summary.text()+" and the list says "+on.text())
	}
	touched := map[string]bool{}
	for _, t := range x.tried {
		touched[str(t, "route_id")] = true
	}
	for _, r := range cands {
		if m := rows[r.ID]; !touched[r.ID] && m.Present && (m.Grade != "unknown" || m.Samples != 0 || m.Failed != 0) {
			wrong = append(wrong, fmt.Sprintf("%s was not tried (or its check was stopped) and is remembered as %s", r.ID, m.text()))
		}
	}
	p.add(step, x.family, "measured", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"measured": measuredText(rows), "attempt_setup_ms": attempt}, t0)
}

// ---- race: the first pair is dropped ------------------------------------

func (a *autoOp) race(first autoRoute, partnerID string) {
	rc := a.rc
	p := a.start("race", ClientOpts{})
	if p == nil {
		return
	}
	defer p.stop()
	cands := p.candidates()
	var partner *autoRoute
	for i := range cands {
		if cands[i].ID == partnerID {
			partner = &cands[i]
		}
	}
	if partner == nil || len(cands) < 3 {
		p.add("connect", "", "pair", Skipped, Skipped,
			"needs three candidates and a first pass that checked two of them together (phone `first`); the engine checked "+first.ID+" beside "+got(partnerID == "", "nothing", partnerID), nil, time.Now())
		return
	}
	fa, fb := rc.Fams[first.Family], rc.Fams[partner.Family]
	t0 := time.Now()
	block := func(f Family) string {
		return fmt.Sprintf("ip saddr %s ip daddr %s %s dport %d drop", ClientIP, RelayPublicAddrSet(), f.Endpoint.Proto, f.Endpoint.Port)
	}
	if err := censorRules(rc.Ctx, block(fa), block(fb)); err != nil {
		p.add("connect", "", "censor.block", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer censorRules(rc.Ctx)
	x := p.press("connect", "auto", t0)
	if x == nil {
		return
	}
	ea, eb := x.entry(first.ID), x.entry(partner.ID)
	var wrong []string
	for _, e := range []struct {
		id, other string
		t         map[string]any
	}{{first.ID, partner.ID, ea}, {partner.ID, first.ID, eb}} {
		switch {
		case e.t == nil:
			wrong = append(wrong, e.id+" is not in `tried`")
		case e.t["result"] != "not_carrying" || str(e.t, "category") == "":
			wrong = append(wrong, fmt.Sprintf("%s: result=%v category=%q, want not_carrying and a category", e.id, e.t["result"], e.t["category"]))
		case str(e.t, "raced_with") != e.other:
			wrong = append(wrong, fmt.Sprintf("%s: raced_with=%q, want %s", e.id, str(e.t, "raced_with"), e.other))
		}
	}
	if x.connected && (x.routeID == first.ID || x.routeID == partner.ID) {
		wrong = append(wrong, "the engine says it is connected on a route the censor drops")
	}
	p.add("connect", "", "both_dropped_routes_checked_together", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), x.evidence(), t0)
	seen, why := x.sawRacing(first.ID, partner.ID)
	p.add("connect", "", "progress_visible", Pass, got(seen, Pass, Fail), why, map[string]any{"progress": x.ev["progress"]}, t0)

	ms, _ := x.ev["auto_ms"].(float64)
	took := time.Duration(ms) * time.Millisecond
	timing := map[string]any{"auto_ms": ms, "one_after_another_ms": (2 * AutoSilentCost).Milliseconds(), "within_ms": AutoRaceWithin.Milliseconds(),
		"stated_budget_ms": AutoSilentBudget.Milliseconds(), "within_stated_ms": AutoRaceWithinStated.Milliseconds(), "tried": x.triedText()}
	fast := x.connected && took < AutoRaceWithin
	p.add("connect", x.family, "faster_than_one_after_another", Pass, got(fast, Pass, Fail),
		got(fast, "", fmt.Sprintf("connected=%v after %s; two silent routes one after the other cost %s before anything carries, and checked together they must be done within %s",
			x.connected, took.Round(10*time.Millisecond), 2*AutoSilentCost, AutoRaceWithin)), timing, t0)
	// The engine's stated budget for a silent address is one attempt.
	stated := x.connected && took < AutoRaceWithinStated
	p.add("connect", x.family, "a_silent_address_costs_one_attempt", Pass, got(stated, Pass, Fail),
		got(stated, "", fmt.Sprintf("connected=%v after %s; at the stated %s for an address that answers nothing, two checked together are done within %s",
			x.connected, took.Round(10*time.Millisecond), AutoSilentBudget, AutoRaceWithinStated)), timing, t0)
	p.add("connect", x.family, "verdict", "moved_on", x.verdict, "", x.evidence(), t0)

	// At the censor: the second route's first packet is not in the same
	// instant as the first's.
	if a.tapOK {
		ua, okA := x.useOf(fa)
		ub, okB := x.useOf(fb)
		gap := time.Duration(ub.First - ua.First)
		if gap < 0 {
			gap = -gap
		}
		okGap := okA && okB && gap >= autoRaceGapFloor && gap <= autoRaceGapCeiling
		p.add("connect", "", "second_route_starts_after_a_delay", Pass, got(okGap, Pass, Fail),
			got(okGap, "", fmt.Sprintf("seen by the censor: %s — the engine says the second starts %s–%s after the first", flowText(x.uses, x.from), AutoRaceDelayMin, AutoRaceDelayMax)),
			map[string]any{"gap_ms": gap.Milliseconds(), "censor_saw": flowText(x.uses, x.from)}, t0)
	}
	if !p.connectedOn("connect", x, t0) {
		return
	}
	// What this network's memory says now.
	if rows, _, ok := p.listing("connect", t0); ok {
		wrong = nil
		for _, id := range []string{first.ID, partner.ID} {
			if m := rows[id]; m.Grade != "failing" || m.Failed < 1 || m.Carried != 0 {
				wrong = append(wrong, id+" answered nothing here and is remembered as "+m.text())
			}
		}
		if m := rows[x.routeID]; m.Grade != "good" && m.Grade != "ok" || m.Carried < 1 {
			wrong = append(wrong, x.routeID+" carried here and is remembered as "+m.text())
		}
		p.add("connect", x.family, "measured", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), map[string]any{"measured": measuredText(rows)}, t0)
	}
	p.disconnect("disconnect", x.family, time.Now())

	// The same network, the same block. The route that carried here is
	// checked alone: one endpoint at the censor, nothing beside it.
	t0 = time.Now()
	y := p.press("again", "auto", t0)
	if y == nil {
		return
	}
	wrong, ev := p.aloneProblems(y, x.routeID)
	p.add("again", x.family, "remembered_route_alone", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), ev, t0)
	p.add("again", x.family, "verdict", "", y.verdict, "", y.evidence(), t0)
	p.connectedOn("again", y, t0)
}

// aloneProblems: what is wrong with a press that should have checked ONE
// route — the one that carried on this network — and nothing beside it:
// in the engine's account (one entry, `carried_here`, no `raced_with`, no
// stopped check, `auto.racing` never set) and at the censor (new
// connections to that route's endpoint and no other).
//
// Where it can fail for the right reason: a phone on which nothing was
// side-probed in the last minutes and whose remembered route CAN be
// probed beside another. (A route the engine never side-probes — naive —
// or one probed a moment ago is checked alone whatever the rule says;
// phones `memory`, `speed` and `metered` are built to avoid both.)
func (p *autoPhone) aloneProblems(y *autoAnswer, routeID string) (wrong []string, ev map[string]any) {
	rc := p.op.rc
	if len(y.tried) != 1 || y.tried[0]["route_id"] != routeID || y.tried[0]["why"] != "carried_here" || y.tried[0]["result"] != "carried" {
		wrong = append(wrong, "want only "+routeID+" tried, because it carried here")
	}
	if len(y.stopped) > 0 || str(y.entry(routeID), "raced_with") != "" {
		wrong = append(wrong, "another route was checked beside the remembered one")
	}
	if pairs, _ := y.racingSeen(); len(pairs) > 0 {
		wrong = append(wrong, fmt.Sprintf("auto.racing was %v during the press", pairs))
	}
	ev = y.evidence()
	if p.op.tapOK {
		fam := ""
		for _, r := range p.routes {
			if r.ID == routeID {
				fam = r.Family
			}
		}
		want := endpointOf(rc.Fams[fam])
		if len(y.uses) != 1 || y.uses[0].Endpoint != want {
			wrong = append(wrong, fmt.Sprintf("the censor saw new connections to: %s — want %s and no other", got(len(y.uses) == 0, "nothing", flowText(y.uses, y.from)), want))
		}
		ev["censor_saw"] = flowText(y.uses, y.from)
	}
	return wrong, ev
}
