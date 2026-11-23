// relaypack_drill.go — the person's check of a file's backup update
// routes (the "drill": core/refresh/drill.go; build/ux/notes/
// wave3-engine-api.md).
//
// It is engine_relaypack_refresh with the JSON request
// {"drill":true,"route_id":"<any route of the file>"} (or
// "relay_pack_id"): no new export. The engine walks ONLY the update
// ladder of that route's pack — every class it may ask, the strike hold
// ignored, once per 10 minutes per pack — and answers, per class, one
// word. Like the button's walk it is registered (relaypack_recover.go),
// so a connect, a disconnect or Shutdown cuts it off and no second walk
// starts beside it; unlike the button it never runs while a route is
// active, even a dead one (the button would pause it; the drill is a
// check, not a recovery).

package abi

import (
	"encoding/json"
	"strings"
	"time"

	"daal/core/refresh"
)

// refreshRequest is the JSON form of engine_relaypack_refresh's argument.
type refreshRequest struct {
	RelayPackID string `json:"relay_pack_id"`
	RouteID     string `json:"route_id"`
	Drill       bool   `json:"drill"`
}

// parseRefreshRequest: ok when arg is a JSON request; bad when it starts
// like one and does not parse.
func parseRefreshRequest(arg string) (req refreshRequest, ok, bad bool) {
	s := strings.TrimSpace(arg)
	if !strings.HasPrefix(s, "{") {
		return req, false, false
	}
	if err := json.Unmarshal([]byte(s), &req); err != nil {
		return req, false, true
	}
	return req, true, false
}

func drillRouteUp() map[string]refresh.DrillClass {
	out := map[string]refresh.DrillClass{}
	for _, cl := range (&refresh.RelayPackRefresher{}).DrillClasses() {
		out[cl] = refresh.DrillClass{Result: refresh.DrillSkipped, Reason: refresh.DrillSkipRouteUp}
	}
	return out
}

// relayPackDrill runs one drill (see the file comment).
func relayPackDrill(c *Core, relayPackID, routeID string) RelayPackRefreshResult {
	c.mu.Lock()
	if c.shuttingDown {
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverCancelled}
	}
	if as, _ := c.auto.snapshot(); c.recover.done != nil || as == AutoStateTrying {
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverInProgress}
	}
	if c.activeRoute != "" || refresh.RouteActive() {
		// Never while a route is up: nothing is stopped or dialled.
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverTunnelRequired, Drill: drillRouteUp()}
	}
	packID, known := c.drillPackLocked(relayPackID, routeID)
	if !known {
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverUnknownPack}
	}
	probe := c.relayPackProbeLocked()
	if !probe.LadderHeld(packID) {
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverNotAvailable}
	}
	if due, wait := probe.DrillDue(packID); !due {
		c.mu.Unlock()
		return RelayPackRefreshResult{Outcome: RecoverRateLimited, RetryAfterS: int((wait + time.Second - 1) / time.Second)}
	}
	t := c.recoverRegisterLocked([]string{packID}, RecoverTriggerDrill, 0)
	c.mu.Unlock()

	var res refresh.RelayPackResult
	if rp, err := ensureRelayPackRefresh(); err == nil {
		res, _ = rp.RefreshDrill(t.ctx, packID)
	} else {
		res = refresh.RelayPackResult{RelayPackID: packID, Outcome: refresh.OutcomeFreshnessCancelled}
	}
	if res.RelayPackID == "" {
		res.RelayPackID = packID
	}
	results := []refresh.RelayPackResult{res}

	c.mu.Lock()
	stopped := c.recover.stops != t.stops
	if c.recover.seq == t.seq {
		if c.recover.cancel != nil {
			c.recover.cancel()
		}
		c.recover.cancel, c.recover.done = nil, nil
	}
	state, outcome, retry := recoverSummary(results)
	if res.Outcome == refresh.OutcomeDrillNotHeld {
		state, outcome = RecoverNotAvailable, res.Outcome
	}
	if !stopped && !c.shuttingDown {
		c.recover.setResult(state, outcome)
	}
	c.mu.Unlock()
	close(t.done)
	if stopped && state != RecoverUpdated {
		state = RecoverCancelled
	}
	return RelayPackRefreshResult{Outcome: state, RetryAfterS: retry, Packs: results, Drill: res.Drill}
}

// drillPackLocked resolves the pack a drill is for: relayPackID, or the
// pack of route routeID. known: some route of the device belongs to it.
// Called with Core.mu held; reads the store.
func (c *Core) drillPackLocked(relayPackID, routeID string) (string, bool) {
	if c.store == nil {
		return "", false
	}
	rows, err := c.store.ListRoutes()
	if err != nil {
		return "", false
	}
	if relayPackID == "" {
		for _, row := range rows {
			if routeID != "" && row.RouteID == routeID {
				relayPackID = row.RelayPackID
				break
			}
		}
	}
	if relayPackID == "" {
		return "", false
	}
	for _, row := range rows {
		if row.RelayPackID == relayPackID {
			return relayPackID, true
		}
	}
	return "", false
}
