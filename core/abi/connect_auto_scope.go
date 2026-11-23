package abi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"daal/core/engine"
)

// "Connect with this file" — the automatic connect, limited to one
// file's routes (engine_set_auto_scope; build/ux/notes/wave3-engine-api.md).
//
// THE FAULT IT FIXES. The app's file sheet picked the file's best route
// itself and connected it BY HAND (engine_set_route, or on Android
// vpn_start with that route id): the engine left automatic mode, and the
// app pinned the route ("your choice"). The person had asked for the
// file, not for one of its ways.
//
// WHAT IT IS. Not a second chooser. The host names the file's routes
// with engine_set_auto_scope, then starts the ordinary automatic connect
// (engine_connect_auto; on Android the VPN service's vpn_start with no
// route id). That pass — and everything the automatic connect does while
// it stays in charge: the race of two, the fall-over, the speed move,
// the move to the best route after the survey, the survey itself — lists
// its candidates through autoCandidatesLocked, which keeps only the
// routes in scope. Order, refusals, verdicts and memory are the ones of
// the unscoped connect.
//
// THE SCOPE'S LIFE.
//   - engine_set_auto_scope ARMS a scope for the next automatic connect
//     only, for autoScopeArmTTL (the Android VPN permission prompt sits
//     between the two calls). "[]" disarms it.
//   - engine_connect_auto takes the armed scope (and disarms it). A call
//     with none armed is the ordinary connect over every route: the
//     main button never inherits a file's scope.
//   - The scope then covers the connect the person asked for and the
//     fall-over while a route of the file still carries. It ENDS when a
//     scoped pass finds nothing in the file (no candidate, or none
//     carried, and no walk for a new address under way): the engine's
//     next pass — its own fall-over, or a host's re-ask such as Android's
//     DaalVpnService after the engine ran out of routes — is over every
//     route again. Resilience first: a file that has stopped working does
//     not keep the person offline while other files would carry. It
//     also ends with the automatic connect: a route picked by hand
//     (engine_set_route), a disconnect (engine_clear_route), Shutdown,
//     or the next engine_connect_auto. Both platforms follow this one
//     rule; the person's own "check all routes" survey is never scoped.
//   - Connected and carrying on a route of the file: the call names it
//     and takes charge, as the unscoped call does. Carrying on a route
//     of ANOTHER file: a pass over this file's routes runs (the person
//     asked for this file). When none of them carries, the route the
//     person had is put back (a candidate tried through the tunnel's
//     own instance stopped it), the automatic connect takes charge of
//     it with the pass's verdict in the `auto` block, and the scope
//     ends; the answer is the pass's, Connected false
//     (autoScopedElsewhereLocked).
//
// The ids are route ids the host already lists (available_routes); the
// scope never leaves memory and is never logged (only its size).

// autoScopeArmTTL: how long an armed scope waits for the connect.
const autoScopeArmTTL = 2 * time.Minute

// autoScopeMax bounds the ids one scope may name.
const autoScopeMax = 256

// SetAutoScope is engine_set_auto_scope: `["<route_id>", …]` arms the
// scope of the next automatic connect; "[]" or "" disarms it. Returns
// how many of the ids the store holds (0: the connect would find nothing
// to try), or an error for input that is not a JSON list of strings (or
// is too long).
func SetAutoScope(routeIDsJSON string) (int, error) {
	c := loadedCore()
	if c == nil {
		return 0, errors.New("abi: not initialized")
	}
	var ids []string
	if s := strings.TrimSpace(routeIDsJSON); s != "" {
		if err := json.Unmarshal([]byte(s), &ids); err != nil {
			return 0, fmt.Errorf("auto scope: %w", err)
		}
	}
	if len(ids) > autoScopeMax {
		return 0, errors.New("auto scope: too many routes")
	}
	scope := map[string]bool{}
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			scope[id] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(scope) == 0 {
		c.auto.pendingScope, c.auto.pendingAt = nil, time.Time{}
		return 0, nil
	}
	known := 0
	if c.store != nil {
		if rows, err := c.store.ListRoutes(); err == nil {
			for _, row := range rows {
				if scope[row.RouteID] {
					known++
				}
			}
		}
	}
	c.auto.pendingScope, c.auto.pendingAt = scope, nowUTC()
	engine.LogInfo(fmt.Sprintf("auto scope armed routes=%d known=%d", len(scope), known))
	return known, nil
}

// takeAutoScopeLocked: the scope of the automatic connect that starts
// now — the armed one if it is still fresh (it is disarmed either way),
// else nil (every route). Called with Core.mu held.
func (c *Core) takeAutoScopeLocked() map[string]bool {
	scope, at := c.auto.pendingScope, c.auto.pendingAt
	c.auto.pendingScope, c.auto.pendingAt = nil, time.Time{}
	if scope == nil {
		return nil
	}
	if el := nowUTC().Sub(at); el < 0 || el > autoScopeArmTTL {
		return nil
	}
	return scope
}

// setAutoScopeLocked makes scope the automatic connect's (nil: every
// route). Called with Core.mu held.
func (c *Core) setAutoScopeLocked(scope map[string]bool) {
	c.auto.scope = scope
	a := &c.auto
	a.mu.Lock()
	a.scoped = scope != nil
	a.mu.Unlock()
}

// inAutoScopeLocked: the automatic connect may use the route. Called
// with Core.mu held.
func (c *Core) inAutoScopeLocked(routeID string) bool {
	return c.auto.scope == nil || c.auto.scope[routeID]
}
