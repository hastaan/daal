package abi

import (
	"encoding/json"
	"errors"
	"sync"

	"daal/core/budget"
)

// budgetState is the lazy-init singleton for the route budget engine.
// Phase 2A. The engine binds to the same routestore the rest of the
// ABI uses; instantiation is idempotent.
type budgetState struct {
	mu     sync.Mutex
	engine *budget.Engine
}

var globalBudget = &budgetState{}

// pendingBudgetSessionBump is set by Init when the budget engine is
// not yet instantiated. The lazy ensureBudget consumes the flag on
// first instantiation, applying NewSession() exactly once.
//
// The flag is guarded by globalBudget.mu so the init/instantiate race
// across goroutines remains deterministic.
var pendingBudgetSessionBump bool

// resetBudgetForShutdown clears the cached budget engine so a
// subsequent Init in the same process picks up the new store. Also
// clears any queued session bump so a Shutdown without a paired
// ensureBudget does not leak a phantom bump into the next Init.
func resetBudgetForShutdown() {
	globalBudget.mu.Lock()
	defer globalBudget.mu.Unlock()
	globalBudget.engine = nil
	pendingBudgetSessionBump = false
}

// bumpBudgetSessionForInit is called from abi.Init at the end of a
// successful boot. If the engine singleton already exists, bump its
// epoch immediately. Otherwise queue the bump for the lazy
// ensureBudget to apply on first use.
//
// This hook is the canonical session boundary at the engine layer.
// engine_set_mode and engine_network_changed do NOT call it.
func bumpBudgetSessionForInit() {
	globalBudget.mu.Lock()
	defer globalBudget.mu.Unlock()
	if globalBudget.engine != nil {
		globalBudget.engine.NewSession()
		return
	}
	pendingBudgetSessionBump = true
}

// budgetEngineIfPresent returns the existing engine singleton without
// instantiating a new one. Used by mode-change paths that should not
// trigger lazy init from a non-byte-charging operation.
func budgetEngineIfPresent() *budget.Engine {
	globalBudget.mu.Lock()
	defer globalBudget.mu.Unlock()
	return globalBudget.engine
}

func ensureBudget() *budget.Engine {
	c := mustCore()
	globalBudget.mu.Lock()
	defer globalBudget.mu.Unlock()
	if globalBudget.engine == nil {
		globalBudget.engine = budget.New(&budget.RoutestoreStore{S: c.store}, nowUTC)
		if pendingBudgetSessionBump {
			globalBudget.engine.NewSession()
			pendingBudgetSessionBump = false
		}
	}
	return globalBudget.engine
}

// SetRouteBudget is engine_set_route_budget. Validates `tag` against
// the closed budget caps map; returns
// {"applied":true,"route_id":"...","budget_tag":"...","hourly_cap_bytes":N}.
func SetRouteBudget(routeID, tag string) (string, error) {
	if routeID == "" {
		return "", errors.New("abi: route_id required")
	}
	cap, err := budget.CapFor(tag)
	if err != nil {
		body, _ := json.Marshal(map[string]any{"error": "unknown_budget_tag", "tag": tag})
		return string(body), err
	}
	if err := ensureBudget().SetTag(routeID, tag); err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{
		"applied":          true,
		"route_id":         routeID,
		"budget_tag":       tag,
		"hourly_cap_bytes": cap,
	})
	return string(body), nil
}

// budgetEngine is exposed for tests + diagnostics; not part of the
// release ABI.
func budgetEngine() *budget.Engine { return ensureBudget() }
