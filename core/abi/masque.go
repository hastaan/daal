package abi

import (
	"errors"
	"time"

	"daal/core/transports/masque"
)

// Phase 3C. MASQUE sub-mode override + persistence helpers.
// The single new release ABI symbol is wired through
// `masque_export.go` (cshared) and `masque_gomobile.go`
// (gomobile facade) per the project's release-surface
// convention.
//
// Locked invariants (this phase):
//   - Override is per-engine, NOT per-network (cross-product
//     would be a fingerprint surface — same reasoning as 3A's
//     experimental gate and 3B's rendezvous priority override).
//   - Empty string CLEARS the override (engine returns to the
//     auto cascade).
//   - Unknown sub-mode IDs are rejected at the setter (-3) so
//     the user sees a clear error rather than silent fallback.
//   - The override survives session epochs by virtue of being
//     persisted in the secrets KV (it is a user preference,
//     not session state).
//   - The override is accepted in BOTH the keystore and vault
//     storage profiles. MASQUE has no FCM/APNS surface (cf. 3B
//     push opt-in) so there is no profile-based rejection.

const masqueSubmodeOverrideKey = "masque_submode_override"

// SetMasqueSubmodeOverride is the Go-typed setter for the
// per-engine MASQUE sub-mode override. Pass empty string to
// clear (engine returns to the auto cascade).
//
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-3 sub-mode is not in the v1 closed list
func SetMasqueSubmodeOverride(submode string) int {
	if loadedCore() == nil {
		return -1
	}
	if submode != "" && !masque.IsKnownSubmode(submode) {
		return -3
	}
	c := loadedCore()
	c.mu.Lock()
	c.masqueSubmodeOverride = submode
	c.mu.Unlock()
	if c.store != nil {
		_ = c.store.PutSecret(masqueSubmodeOverrideKey, []byte(submode))
	}
	return 0
}

// MasqueSubmodeOverride returns the current per-engine
// override. Empty string means "no override — use the auto
// cascade." Pure read.
func MasqueSubmodeOverride() string {
	if loadedCore() == nil {
		return ""
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.masqueSubmodeOverride
}

// LastChosenMasqueSubmode returns the sub-mode the masque
// handler most recently chose (across all routes / sessions
// in the lifetime of this process). Empty string means "no
// masque route activated yet this session." Pure read;
// snapshot, not cumulative.
func LastChosenMasqueSubmode() string {
	if loadedCore() == nil {
		return ""
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastChosenMasqueSubmode
}

// RecordChosenMasqueSubmode is the engine-side hook for the
// masque handler's per-route + per-network persistence
// callback. Updates the in-memory diagnostics field, the
// routestore (per-route), and the netmem store (per-network)
// in one shot. Mirrors 3B's `RecordRendezvousWinner`.
//
// `submode` MUST be in the v1 closed list; unknown values are
// rejected with an error (defence-in-depth — chooseSubmode
// also returns only known sub-modes).
func RecordChosenMasqueSubmode(routeID, submode, networkID string) error {
	if loadedCore() == nil {
		return errors.New("abi: not initialised")
	}
	if !masque.IsKnownSubmode(submode) {
		return errors.New("abi: unknown masque sub-mode " + submode)
	}
	c := loadedCore()
	c.mu.Lock()
	c.lastChosenMasqueSubmode = submode
	c.mu.Unlock()
	if c.store != nil {
		// Per-route persistence. The routestore stores the
		// last-chosen sub-mode under a per-route key; the
		// columnar form (a `last_used_masque_submode` column)
		// is held back to V4 — at 3C the per-route history is
		// surfaced via netmem (per-network) which is the
		// dimension chooseSubmode actually consults at step 3.
		_ = c.store.PutSecret("masque_submode:"+routeID, []byte(submode))
	}
	if ns := netmemStore(); ns != nil && networkID != "" {
		_ = ns.RecordLastUsedMasqueSubmode(networkID, submode, time.Now().UTC())
	}
	return nil
}

// loadMasqueState is the Init-time daaltor for the 3C
// per-engine state. Missing key defaults to "no override."
// An out-of-list persisted value is filtered (in-memory only;
// the persisted bytes are left untouched and a subsequent
// SetMasqueSubmodeOverride call rewrites them).
func loadMasqueState(c *Core) {
	if c == nil || c.store == nil {
		return
	}
	body, err := c.store.GetSecret(masqueSubmodeOverrideKey)
	if err != nil || len(body) == 0 {
		return
	}
	val := string(body)
	if !masque.IsKnownSubmode(val) {
		return
	}
	c.mu.Lock()
	c.masqueSubmodeOverride = val
	c.mu.Unlock()
}
