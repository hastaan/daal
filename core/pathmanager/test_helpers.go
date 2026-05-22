package pathmanager

import "time"

// SetSkippedForTest is a test-only helper that injects a
// `(family, activeNetwork)` cooldown directly into the manager's
// internal maps. Used by Phase 2G's auto-promotion tests to drive
// the burn-pressure detector without going through the real
// failure pipeline.
//
// NOT a release ABI; the file lives outside `_test.go` so the
// `core/abi` package's tests can call it. The function name's
// `ForTest` suffix is the marker that this is internal test
// scaffolding — production code MUST NOT call it.
func (m *Manager) SetSkippedForTest(family string, until time.Time, ladderStep int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.familyCooldown == nil {
		m.familyCooldown = map[string]time.Time{}
	}
	if m.familyEscalation == nil {
		m.familyEscalation = map[string]int{}
	}
	key := familyEscKey(family, m.activeNetwork)
	m.familyCooldown[key] = until
	m.familyEscalation[key] = ladderStep
}
