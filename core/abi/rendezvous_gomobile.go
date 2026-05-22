//go:build !cshared

package abi

import (
	"encoding/json"
	"errors"
	"time"

	"daal/core/rendezvous"
)

// EngineSetRendezvousPriority is the gomobile facade. Phase 3B.
// The supplied JSON-encoded array of channel IDs becomes the
// per-engine override; pass "[]" to clear.
//
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-3 priority list contains an unknown channel ID
//	-4 priorityJSON is malformed
func EngineSetRendezvousPriority(priorityJSON string) int {
	if globalCore == nil {
		return -1
	}
	var list []string
	if err := json.Unmarshal([]byte(priorityJSON), &list); err != nil {
		return -4
	}
	return SetRendezvousPriority(list)
}

// EngineSetPushRendezvousEnabled is the gomobile facade for the
// `push` rendezvous opt-in. Returns:
//
//	 0 success
//	-1 engine not initialised
//	-2 storage profile is "vault" — push is rejected
func EngineSetPushRendezvousEnabled(enabled int) int {
	if globalCore == nil {
		return -1
	}
	return SetPushRendezvousEnabled(enabled != 0)
}

// EngineSetPushDeviceToken is the gomobile-only push token
// setter. Phase 3B. The release-cshared build does NOT export
// a corresponding C symbol; desktop platforms have no FCM/APNS
// tokens. The token + platform string are persisted in secrets
// KV and consumed by the push-rendezvous solicitor when the
// `push` channel is enabled.
//
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-2 storage profile is "vault"
func EngineSetPushDeviceToken(platform, token string) int {
	return SetPushDeviceToken(platform, token)
}

// EngineDeliverPushPayload is the gomobile-only inbound for
// FCM/APNS data-message delivery. The platform layer (Android
// FirebaseMessagingService / iOS NotificationServiceExtension)
// receives a remote message, extracts the `daal_push` data
// payload, and hands it to the engine through this facade. The
// engine verifies the publisher signature on the payload and,
// if valid, treats it as a `push` channel Solicit response.
//
// `payload` is the raw JSON bytes from the FCM/APNS data
// message; signature verification per
// specs/push-rendezvous-v1.md "Payload format".
//
// Returns:
//
//	 0 success (payload accepted; rendezvous Hint queued)
//	-1 engine not initialised
//	-2 storage profile is "vault" (push opted out)
//	-5 signature verification failed
//	-6 payload malformed or stale (timestamp drift > 5 min)
func EngineDeliverPushPayload(payload []byte) int {
	if globalCore == nil {
		return -1
	}
	c := globalCore
	c.mu.Lock()
	if c.storageProfile == "vault" {
		c.mu.Unlock()
		return -2
	}
	if !c.pushRendezvousEnabled {
		c.mu.Unlock()
		return -2
	}
	store := c.store
	c.mu.Unlock()

	// 3B push verifier resolver. The routestore persists
	// publisher fingerprints + rotation chains but does NOT
	// (yet) persist the raw ed25519 pubkey bytes by
	// fingerprint. Until that index lands at 3B-Soak, the
	// resolver consults a per-engine lookup populated by the
	// bundle importer; in this scaffolding it returns
	// (nil, false) for unknown fingerprints so the verifier
	// rejects with ErrPushNoPinnedPublisher. The platform
	// layer queues retries on -5; the 3B-Soak follow-up adds
	// the index and the eligible-publisher check.
	resolver := func(publisherKeyHex string) ([]byte, bool) {
		if store == nil {
			return nil, false
		}
		raw, err := store.GetSecret("publisher_pub:" + publisherKeyHex)
		if err != nil || len(raw) != 32 {
			return nil, false
		}
		return raw, true
	}

	pl, err := rendezvous.VerifyPushPayload(payload, resolver, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, rendezvous.ErrPushSignatureInvalid),
			errors.Is(err, rendezvous.ErrPushNoPinnedPublisher):
			return -5
		default:
			return -6
		}
	}
	pushQueueGet().Enqueue(pl)
	return 0
}
