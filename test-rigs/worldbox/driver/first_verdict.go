package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The first verdict — what the engine told the FIRST phone.
//
// Under a scenario that degrades the path instead of cutting it
// (Scenario.MustEstablish) a session is allowed to ask again with a fresh
// phone when the engine's connection proof fails, because the later
// checks (family/established, the wire) need a connected engine to say
// anything. A fresh phone has a fresh state directory: no cooldown, no
// failure record. Judging only the phone that finally connected therefore
// throws away the one answer a real person would have been given — "this
// route is dead", a cooldown, and a failure category sent on to the
// publisher. For a whole afternoon throttle-56k was green on two full
// runs in which two families had been told exactly that
// (connect_attempts=2 in the evidence, and nothing red).
//
// So every connect attempt of a session is recorded (ConnectAttempt, in
// the `tunnel` evidence), and where the scenario declares what the engine
// must say — a category other than "unasserted" — the FIRST one is judged
// on its own as `engine.first_verdict`: it must be "connected". A retry
// that works does not turn it green.

// ConnectAttempt is one phone's connect, as the engine reported it.
type ConnectAttempt struct {
	Phone      int    `json:"phone"` // 1 = the first phone
	ClientDir  string `json:"client_dir"`
	Connected  bool   `json:"connected"`
	SetRouteMs any    `json:"set_route_ms,omitempty"`
	// What a phone whose connect failed was told (empty when connected).
	Stage     string `json:"stage,omitempty"`
	Error     string `json:"error,omitempty"`
	Category  string `json:"category,omitempty"`
	Posture   string `json:"posture,omitempty"`
	Explained string `json:"explained,omitempty"` // the explanation's reason line: carries the cooldown
}

// connectAttempt reads one finished connect off the client: ev and err
// are what Client.Wait(…, "connected") returned.
func connectAttempt(n int, c *Client, ev map[string]any, err error) ConnectAttempt {
	a := ConnectAttempt{Phone: n, ClientDir: c.Dir, Connected: err == nil}
	if ev != nil {
		a.SetRouteMs = ev["set_route_ms"]
	}
	if err == nil {
		return a
	}
	a.Error = oneLine(err.Error(), 300)
	if ev == nil {
		return a
	}
	a.Stage, _ = ev["stage"].(string)
	if diag, ok := ev["diag"].(map[string]any); ok {
		a.Category, _ = diag["route_check_category"].(string)
		a.Posture, _ = diag["posture"].(string)
	}
	if exp, ok := ev["explain"].(map[string]any); ok {
		a.Explained, _ = exp["reason"].(string)
	}
	return a
}

// FirstConnected is what engine.first_verdict expects and, for a first
// phone that connected, records.
const FirstConnected = "connected"

// firstVerdict is the outcome of engine.first_verdict for a session's
// connect attempts: what the first phone was told, whatever happened to
// the phones after it.
func firstVerdict(attempts []ConnectAttempt) (outcome, detail string) {
	if len(attempts) == 0 {
		return "no-attempt", "the session made no connect attempt"
	}
	first := attempts[0]
	if first.Connected {
		return FirstConnected, ""
	}
	cat := first.Category
	if cat == "" {
		cat = "uncategorised"
	}
	outcome = "failed:" + cat
	after := "no later phone connected either"
	for _, a := range attempts[1:] {
		if a.Connected {
			after = fmt.Sprintf("phone %d of %d — a fresh install with no memory of the failure — then connected on the same route (set_route_ms=%v)", a.Phone, len(attempts), a.SetRouteMs)
			break
		}
	}
	detail = fmt.Sprintf("the scenario says this family connects, and the FIRST phone was told it does not: %q (category %s, posture %s, after %v ms; %q). %s. A real person has one phone: they see the failure and the cooldown, and the publisher is sent %s for a route that works",
		first.Error, cat, first.Posture, first.SetRouteMs, first.Explained, after, cat)
	return outcome, detail
}

// firstVerdictCheck records engine.first_verdict where it applies.
func (rc *RunCtx) firstVerdictCheck(f Family, phase, expect string, attempts []ConnectAttempt, t0 time.Time) {
	if phase != "family" || expect != Blocked || !rc.Scn.MustEstablish(f.Name) {
		return
	}
	// A scenario that asserts nothing about the engine's account
	// (heavy-loss: which step fails differs from run to run) asserts
	// nothing about the first one either. The attempts are still in the
	// `tunnel` evidence.
	if declared, err := rc.Scn.CategoryFor(f.Name); err != nil || declared == CategoryUnasserted {
		return
	}
	outcome, detail := firstVerdict(attempts)
	rc.R.Add(f.Name, phase, "engine.first_verdict", FirstConnected, outcome, detail,
		map[string]any{"connect_attempts": len(attempts), "attempts": attempts}, t0)
}

// ---- the slow-path category --------------------------------------------

// EngineSlowAfterMs is the engine's own "connected, but slow" threshold
// (engine.DefaultProofConfig().SlowAfter). The rig does not configure it:
// wb-client writes only the proof targets, so every lab phone runs the
// default — driver/first_verdict_test.go holds the two together.
const EngineSlowAfterMs = 2000

// connectOverheadMs is how much longer than the proof itself a whole
// engine_set_route may take here (starting the instance, the route-store
// writes): the band in which set_route_ms cannot say on which side of
// the threshold the PROOF was.
const connectOverheadMs = 150

// CategorySlow is the taxonomy's degraded outcome.
const CategorySlow = "path_too_slow"

// slowCategoryFor turns a declared `path_too_slow` into what the engine
// must have reported for ONE connect, given how long that connect took.
//
// The engine sees a slow path only through its own proof
// (specs/failure-taxonomy-v1.md, "What one route can see": "path_too_slow,
// when a handshake still finishes quickly → nothing"). So the answer is
// not free, it is decided by the time the engine itself spent:
//
//   - the connect took longer than the threshold (plus overhead): the
//     person waited, the engine measured it, and it must say
//     path_too_slow. "Connected" with nothing more is red.
//   - the connect finished within the threshold: the proof cannot have
//     been slow, and the engine must say nothing. path_too_slow is red.
//   - within the overhead band the proof may have been on either side,
//     and either is accepted.
//
// connectMs < 0 (not measured) leaves the declaration as it is.
func slowCategoryFor(declared string, connectMs int64) string {
	if declared != CategorySlow || connectMs < 0 {
		return declared
	}
	switch {
	case connectMs <= EngineSlowAfterMs:
		return CategoryNone
	case connectMs <= EngineSlowAfterMs+connectOverheadMs:
		return CategorySlow + "|" + CategoryNone
	}
	return CategorySlow
}

// rawFace is what the raw differential probe (censor/truth.category) can
// confirm of a declared category. It sees packets, not speed: a path that
// is only slow answers every probe, so its raw face is "none" — and the
// slowness itself is proven by the scenario's own `prove` entries
// (throttle-56k: bulk-is-slow).
func rawFace(declared string) string {
	parts := strings.Split(declared, "|")
	for i, p := range parts {
		if p == CategorySlow {
			parts[i] = CategoryNone
		}
	}
	return strings.Join(parts, "|")
}

func msOf(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return -1
}

// ---- a quiet link between phones ---------------------------------------

// QuietBudget bounds the wait for the censor's shaper to drain.
const QuietBudget = 60 * time.Second

// tc prints the byte count with a unit once it is large ("backlog 43Kb
// 22p"); the packet count is the plain number.
var qdiscBacklog = regexp.MustCompile(`backlog \S+ (\d+)p`)

// shaperBacklog is how many packets sit in the censor's qdiscs right now.
func shaperBacklog(ctx context.Context, devs []string) (int, error) {
	total := 0
	for _, dev := range devs {
		out, err := sh(ctx, inNS(NSCensor, "tc", "-s", "qdisc", "show", "dev", dev, "root")...)
		if err != nil {
			return 0, err
		}
		m := qdiscBacklog.FindStringSubmatch(out)
		if m == nil {
			return 0, fmt.Errorf("tc -s qdisc show dev %s: no backlog line in %q", dev, oneLine(out, 200))
		}
		n, _ := strconv.Atoi(m[1])
		total += n
	}
	return total, nil
}

// linkQuiet waits, before a session, until nothing of an EARLIER session
// is still queued in the censor's shaper.
//
// Every session is a separate phone on the censored network; the worlds'
// families merely take turns on one link. A scenario with a rate cap
// queues what it cannot forward (netem holds up to 1000 packets), and a
// QUIC family does not stop sending when its client goes away: hysteria2
// and tuic kept the 56 kbit/s queue full for seconds after their session
// ended, and the family that came next (naive after hysteria2,
// vless-reality after tuic, in every full run) spent its whole connection
// proof behind the previous phone's packets — its SYN was not answered
// for 4 s. That is one phone's traffic failing another phone's connect:
// cross-talk of the rig, not the scenario. The backlog found and the time
// waited are recorded on control.before; a shaper that never drains is
// red there.
func (rc *RunCtx) linkQuiet() (ev map[string]any, err error) {
	// WB_NO_QUIET=1: start on the link as the last phone left it, to
	// reproduce what the engine says behind seconds of queue (FINDINGS
	// CEN-O5).
	if len(rc.Scn.Censor.TC) == 0 || os.Getenv("WB_NO_QUIET") != "" {
		return nil, nil
	}
	vars := scenarioVars(rc.Rec.CoverSNI)
	var devs []string
	for _, t := range rc.Scn.Censor.TC {
		devs = append(devs, substVars(t.Dev, vars))
	}
	t0 := time.Now()
	first, err := shaperBacklog(rc.Ctx, devs)
	if err != nil {
		return nil, err
	}
	last := first
	quiet := waitFor(rc.Ctx, QuietBudget, func() bool {
		n, e := shaperBacklog(rc.Ctx, devs)
		last, err = n, e
		return e != nil || n == 0
	})
	ev = map[string]any{"shaper_backlog_packets": first, "waited_for_quiet_ms": time.Since(t0).Milliseconds()}
	if err == nil && !quiet {
		err = fmt.Errorf("the censor's shaper still holds %d packet(s) of an earlier session after %s (it held %d when this session began): this session would be measuring that backlog, not the scenario", last, QuietBudget, first)
	}
	return ev, err
}
