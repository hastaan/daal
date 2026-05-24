package rendezvous

// Phase 3B push rendezvous protocol.
//
// Push is the only rendezvous channel that is not initiated by
// the client. The flow is:
//
//   1. Engine boot: gomobile bridge calls
//      EngineSetPushDeviceToken(platform, token).
//   2. Engine registers the token with the partner-operated
//      registry (NEVER project-operated; see
//      specs/push-rendezvous-v1.md "Registry posture") through
//      the active tunnel — i.e., when no working tunnel is up,
//      registration is queued and the registry SEES NO traffic.
//      The registration body carries publisher_key_hex + token
//      and the partner returns an ACK; the project never holds
//      the device-token database.
//   3. The partner's broker fronting layer receives a censorship
//      event (via an out-of-band signal — explicitly out of the
//      project's threat model) and triggers a publisher to send
//      a signed Hint payload via FCM/APNS to the registered
//      tokens.
//   4. The platform's push delivery surface (Android
//      FirebaseMessagingService / iOS NotificationService
//      Extension) wakes the app, extracts the `daal_push` data
//      payload, and hands it to the engine through
//      EngineDeliverPushPayload(payload).
//   5. The engine verifies the payload's publisher signature
//      against ALL pinned publisher keys (any pinned publisher
//      may legally push), discards stale payloads (timestamp
//      drift > 5 min), and queues the resulting Hint to be
//      consumed by the next push-channel Solicit call.
//
// The package implements steps 4 + 5 (the protocol surface);
// steps 1–3 are platform-side and are wired through
// `core/abi/push_token_gomobile.go`. All upstream FCM/APNS code
// (firebase.google.com/go/v4/messaging,
// github.com/sideshow/apns2) lives at the gomobile boundary and
// is NEVER imported by this package.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// MaxPushDrift is the maximum tolerated clock skew between the
// publisher's signing timestamp and the engine's local clock.
// Payloads outside the window are rejected as stale.
const MaxPushDrift = 5 * time.Minute

// Errors specific to push verification.
var (
	ErrPushPayloadMalformed  = errors.New("push: payload malformed")
	ErrPushSignatureInvalid  = errors.New("push: signature invalid")
	ErrPushPayloadStale      = errors.New("push: payload stale (timestamp drift > 5m)")
	ErrPushNoPinnedPublisher = errors.New("push: payload signed by an unpinned publisher")
)

// PushPayload is the signed-by-publisher push delivery
// envelope. The signature covers Marshal(payload) WITHOUT the
// `signature` field (i.e., a struct copy with Signature="" gets
// canonical-marshalled). The wire format is the same JSON
// shape as `bundle.RendezvousHint` so the offline-hint and push
// paths share verification semantics.
type PushPayload struct {
	Bridge         string `json:"bridge"`
	FingerprintHex string `json:"fp"`
	NotAfter       string `json:"not_after"`         // RFC3339Z
	IssuedAt       string `json:"issued_at"`         // RFC3339Z; engine enforces drift
	PublisherKey   string `json:"publisher_key_hex"` // hex-lowercased ed25519 pubkey
	HintVersion    int    `json:"hint_version"`      // 1
	Signature      string `json:"signature,omitempty"`
}

// PinnedKeyResolver returns the ed25519 public key bytes for
// the supplied publisher key fingerprint hex (lowercased).
// Returns nil + false if the publisher is not pinned.
type PinnedKeyResolver func(publisherKeyHex string) ([]byte, bool)

// PushQueue is the per-engine queue that accepts verified
// PushPayloads from the platform delivery surface and surfaces
// them to the next `push` channel Solicit call. It is a
// single-writer / single-reader bounded buffer; payloads beyond
// the cap are dropped (push-rendezvous is a hint, not a
// guaranteed-delivery channel).
type PushQueue struct {
	mu    sync.Mutex
	items []PushPayload
	cap   int
}

// NewPushQueue constructs a queue with the given soft cap. cap
// = 0 disables the cap.
func NewPushQueue(cap int) *PushQueue {
	if cap < 0 {
		cap = 0
	}
	return &PushQueue{cap: cap}
}

// Enqueue appends a verified payload. Returns the new queue
// length; older entries beyond cap are dropped.
func (q *PushQueue) Enqueue(p PushPayload) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, p)
	if q.cap > 0 && len(q.items) > q.cap {
		drop := len(q.items) - q.cap
		q.items = q.items[drop:]
	}
	return len(q.items)
}

// Dequeue removes and returns the oldest payload, or
// (PushPayload{}, false) if empty.
func (q *PushQueue) Dequeue() (PushPayload, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return PushPayload{}, false
	}
	p := q.items[0]
	q.items = q.items[1:]
	return p, true
}

// Len returns the number of queued payloads.
func (q *PushQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// VerifyPushPayload parses + verifies a wire-format push
// payload. Returns the verified PushPayload or an error.
//
//   - rawJSON: the raw bytes from the FCM/APNS data message's
//     `daal_push` field.
//   - resolver: returns the pinned ed25519 pubkey for a given
//     publisher key fingerprint hex. The engine wires this to
//     core/routestore.GetPublisher.
//   - now: the current time (test-injected).
func VerifyPushPayload(rawJSON []byte, resolver PinnedKeyResolver, now time.Time) (PushPayload, error) {
	if len(rawJSON) == 0 {
		return PushPayload{}, ErrPushPayloadMalformed
	}
	var p PushPayload
	if err := json.Unmarshal(rawJSON, &p); err != nil {
		return PushPayload{}, ErrPushPayloadMalformed
	}
	if p.Bridge == "" || p.FingerprintHex == "" || p.IssuedAt == "" ||
		p.PublisherKey == "" || p.Signature == "" || p.HintVersion != 1 {
		return PushPayload{}, ErrPushPayloadMalformed
	}

	// Resolve the publisher's pinned key. This is the only
	// trust anchor: a valid push payload MUST be signed by a
	// publisher whose key is already pinned in the routestore.
	pubKey, ok := resolver(p.PublisherKey)
	if !ok || len(pubKey) != ed25519.PublicKeySize {
		return PushPayload{}, ErrPushNoPinnedPublisher
	}

	// Verify the signature over the canonical-marshalled
	// payload with Signature field cleared.
	sig, err := base64.RawURLEncoding.DecodeString(p.Signature)
	if err != nil {
		return PushPayload{}, ErrPushPayloadMalformed
	}
	signed := p
	signed.Signature = ""
	body, err := json.Marshal(&signed)
	if err != nil {
		return PushPayload{}, ErrPushPayloadMalformed
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), body, sig) {
		return PushPayload{}, ErrPushSignatureInvalid
	}

	// Clock-skew check.
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return PushPayload{}, ErrPushPayloadMalformed
	}
	if drift := now.Sub(issued); drift > MaxPushDrift || drift < -MaxPushDrift {
		return PushPayload{}, ErrPushPayloadStale
	}

	return p, nil
}

// NewPushSolicitor builds a Solicitor wired to a per-engine
// PushQueue. The Solicitor:
//
//   - Returns the next queued Hint, if any.
//   - Otherwise, blocks until the context expires or a payload
//     arrives, then returns it.
//
// In hedged-selection scenarios, the surrounding Selector
// imposes a short context deadline (the hedge interval), so
// "blocks" is a bounded wait.
//
// The returned Solicitor is intentionally simple — push is a
// "wait for a piece of mail to arrive" channel; there is no
// outbound RPC the engine can make.
func NewPushSolicitor(q *PushQueue) Solicitor {
	return func(ctx context.Context, req Request) (Hint, error) {
		// First-shot drain.
		if p, ok := q.Dequeue(); ok {
			extra, _ := json.Marshal(map[string]string{
				"bridge":    p.Bridge,
				"not_after": p.NotAfter,
			})
			return Hint{
				ChannelID: ChannelPush,
				BridgeFP:  p.FingerprintHex,
				Extra:     extra,
			}, nil
		}
		// Wait until cancelled.
		<-ctx.Done()
		// Final attempt in case a payload arrived during cancel.
		if p, ok := q.Dequeue(); ok {
			extra, _ := json.Marshal(map[string]string{
				"bridge":    p.Bridge,
				"not_after": p.NotAfter,
			})
			return Hint{
				ChannelID: ChannelPush,
				BridgeFP:  p.FingerprintHex,
				Extra:     extra,
			}, nil
		}
		return Hint{}, ctx.Err()
	}
}
