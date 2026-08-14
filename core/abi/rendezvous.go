package abi

import (
	"encoding/json"
	"errors"
	"time"

	"daal/core/rendezvous"
)

// Phase 3B. Rendezvous priority override + push opt-in setters
// + persistence helpers. The two ABI surfaces are wired through
// `rendezvous_export.go` (cshared release symbol) and
// `rendezvous_gomobile.go` (gomobile facade) per the project's
// release-surface convention. The push device-token plumbing is
// gomobile-only and lives in `push_token_gomobile.go`; release
// builds for Linux/Windows do NOT export it (cshared file is
// intentionally absent).
//
// Locked invariants:
//   - Rendezvous priority override is per-engine, NOT per-
//     network (cross-product would be a fingerprint).
//   - Push opt-in is rejected by SetPushRendezvousEnabled when
//     storage profile is "vault" (return -2). The vault profile
//     must never call FCM/APNS at all.
//   - Unknown channel IDs in the override are silently dropped
//     by the Selector at race time (defence-in-depth); the
//     setter validates and rejects (return -3) so the user
//     sees a clear error rather than silent fallback.

const (
	rendezvousPriorityKey = "rendezvous_priority_override"
	pushRendezvousKey     = "push_rendezvous_enabled"
	pushDeviceTokenKey    = "push_device_token"
	pushDevicePlatformKey = "push_device_token_platform"
)

// SetRendezvousPriority is the Go-typed setter for the per-engine
// rendezvous priority override. The supplied list MAY be empty
// (which means "no priority — fall back to the bundle's
// rendezvous_priority list and then to rendezvous.DefaultPriority");
// nil means "remove the override."
//
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-3 priority list contains an unknown channel ID
func SetRendezvousPriority(priority []string) int {
	if loadedCore() == nil {
		return -1
	}
	for _, ch := range priority {
		if !rendezvous.IsKnownChannel(ch) {
			return -3
		}
	}
	c := loadedCore()
	c.mu.Lock()
	c.rendezvousPriorityOverride = append([]string(nil), priority...)
	c.mu.Unlock()
	if c.store != nil {
		body, _ := json.Marshal(priority)
		_ = c.store.PutSecret(rendezvousPriorityKey, body)
	}
	return 0
}

// RendezvousPriority returns the current per-engine override
// (nil if not set). Pure read.
func RendezvousPriority() []string {
	if loadedCore() == nil {
		return nil
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rendezvousPriorityOverride == nil {
		return nil
	}
	return append([]string(nil), c.rendezvousPriorityOverride...)
}

// SetPushRendezvousEnabled is the Go-typed setter for the push
// opt-in. Returns:
//
//	 0 success
//	-1 engine not initialised
//	-2 storage profile is "vault" — push is forbidden
func SetPushRendezvousEnabled(enabled bool) int {
	if loadedCore() == nil {
		return -1
	}
	c := loadedCore()
	c.mu.Lock()
	if c.storageProfile == "vault" {
		c.mu.Unlock()
		return -2
	}
	c.pushRendezvousEnabled = enabled
	c.mu.Unlock()
	if c.store != nil {
		val := []byte("0")
		if enabled {
			val = []byte("1")
		}
		_ = c.store.PutSecret(pushRendezvousKey, val)
	}
	return 0
}

// PushRendezvousEnabled reports the current opt-in value.
func PushRendezvousEnabled() bool {
	if loadedCore() == nil {
		return false
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pushRendezvousEnabled
}

// SetPushDeviceToken stores the platform-supplied push token.
// gomobile-only. The release-cshared build deliberately does
// NOT export this function — desktop platforms do not have
// FCM/APNS tokens. Returns -1 if the engine is not initialised
// or -2 if the storage profile is "vault".
func SetPushDeviceToken(platform, token string) int {
	if loadedCore() == nil {
		return -1
	}
	c := loadedCore()
	c.mu.Lock()
	if c.storageProfile == "vault" {
		c.mu.Unlock()
		return -2
	}
	c.pushDeviceToken = token
	c.pushDeviceTokenPlatform = platform
	c.mu.Unlock()
	if c.store != nil {
		_ = c.store.PutSecret(pushDeviceTokenKey, []byte(token))
		_ = c.store.PutSecret(pushDevicePlatformKey, []byte(platform))
	}
	return 0
}

// PushDevice is the gomobile-friendly return shape for
// PushDeviceToken. gomobile bind rejects multi-value returns
// where the second value isn't `error`, so we return a struct.
type PushDevice struct {
	Platform string
	Token    string
}

// PushDeviceToken returns the stored push device token + its
// platform. Both fields are empty if no token is set.
func PushDeviceToken() PushDevice {
	if loadedCore() == nil {
		return PushDevice{}
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return PushDevice{Platform: c.pushDeviceTokenPlatform, Token: c.pushDeviceToken}
}

// RecordRendezvousWinner is the engine-side hook for the
// snowflake handler's per-route + per-network persistence
// callback. Updates routestore + netmem in one shot and stamps
// the in-memory diagnostics field.
//
// channelID MUST be in the v1 closed list; unknown values are
// rejected with an error (defence-in-depth — the Selector also
// returns only known channels).
func RecordRendezvousWinner(routeID, channelID, networkID string) error {
	if loadedCore() == nil {
		return errors.New("abi: not initialised")
	}
	if !rendezvous.IsKnownChannel(channelID) {
		return errors.New("abi: unknown rendezvous channel " + channelID)
	}
	c := loadedCore()
	c.mu.Lock()
	c.lastWinningRendezvousChannel = channelID
	c.mu.Unlock()
	if c.store != nil {
		if err := c.store.RecordRendezvousWinner(routeID, channelID); err != nil {
			return err
		}
	}
	if ns := netmemStore(); ns != nil && networkID != "" {
		_ = ns.RecordWinningRendezvousChannel(networkID, channelID, time.Now().UTC())
	}
	return nil
}

// pushQueueSingleton is the per-engine push payload queue. It
// is lazy-created on first use so unit tests that don't touch
// the push surface incur zero allocation. Capacity 16 — push
// is a hint, not guaranteed delivery.
var pushQueueSingleton *rendezvous.PushQueue
var pushQueueOnce = struct {
	create func() *rendezvous.PushQueue
}{
	create: func() *rendezvous.PushQueue { return rendezvous.NewPushQueue(16) },
}

// pushQueueGet returns the per-engine PushQueue, creating it on
// first call.
func pushQueueGet() *rendezvous.PushQueue {
	if pushQueueSingleton == nil {
		pushQueueSingleton = pushQueueOnce.create()
	}
	return pushQueueSingleton
}

// resetPushQueueForShutdown is called from Shutdown to drop the
// queue so a follow-up Init starts fresh.
func resetPushQueueForShutdown() {
	pushQueueSingleton = nil
}

// loadRendezvousState is the Init-time daaltor for the 3B
// per-engine state. Missing keys default to "no override" /
// "push disabled". Errors fall through to the defaults; the
// engine never refuses to start over a missing-or-corrupt 3B
// state value.
func loadRendezvousState(c *Core) {
	if c == nil || c.store == nil {
		return
	}
	if body, err := c.store.GetSecret(rendezvousPriorityKey); err == nil && len(body) > 0 {
		var pri []string
		if json.Unmarshal(body, &pri) == nil {
			// Filter unknown channels at daalte time so a
			// stale persisted override does not poison the
			// in-memory state. The persisted value is left
			// untouched on disk; a subsequent SetRendezvous
			// Priority call will rewrite it.
			out := pri[:0]
			for _, ch := range pri {
				if rendezvous.IsKnownChannel(ch) {
					out = append(out, ch)
				}
			}
			c.mu.Lock()
			c.rendezvousPriorityOverride = out
			c.mu.Unlock()
		}
	}
	if body, err := c.store.GetSecret(pushRendezvousKey); err == nil && len(body) > 0 {
		// Only honour the persisted value if the storage
		// profile permits it. The vault profile must never
		// have push enabled; if a corrupted state attempts
		// it, force false in-memory.
		c.mu.Lock()
		if c.storageProfile != "vault" && body[0] == '1' {
			c.pushRendezvousEnabled = true
		}
		c.mu.Unlock()
	}
	if body, err := c.store.GetSecret(pushDeviceTokenKey); err == nil {
		c.mu.Lock()
		if c.storageProfile != "vault" {
			c.pushDeviceToken = string(body)
		}
		c.mu.Unlock()
	}
	if body, err := c.store.GetSecret(pushDevicePlatformKey); err == nil {
		c.mu.Lock()
		if c.storageProfile != "vault" {
			c.pushDeviceTokenPlatform = string(body)
		}
		c.mu.Unlock()
	}
}
