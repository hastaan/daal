// Package trust manages publisher pin state and trust-state transitions
// (`unknown`, `tofu`, `trusted`, `expired`, `revoked`, `changed_key`) per
// specs/publisher-keys-v1.md. The store of record is routestore; this
// package is a thin policy layer.
package trust

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"daal/core/routestore"
)

// State is the publisher's current local trust state.
type State string

const (
	StateUnknown    State = "unknown"
	StateTOFU       State = "tofu"
	StateTrusted    State = "trusted"
	StateExpired    State = "expired"
	StateRevoked    State = "revoked"
	StateChangedKey State = "changed_key"
)

// Pin represents the durable pin information for a publisher.
type Pin struct {
	PublisherID string // hex fingerprint
	DisplayName string
	State       State
	KeyStatus   string // active|rotated|compromised|revoked
}

// LookupPin returns the pin for fingerprint, with sql.ErrNoRows if unknown.
func LookupPin(s *routestore.Store, fingerprint string) (Pin, error) {
	row, err := s.GetPublisher(fingerprint)
	if err != nil {
		return Pin{}, err
	}
	return Pin{
		PublisherID: row.PublisherID,
		DisplayName: row.DisplayName,
		State:       State(row.TrustLevel),
		KeyStatus:   row.KeyStatus,
	}, nil
}

// FirstSeen records a brand-new publisher whose key the user has just
// accepted (TOFU). Caller is responsible for prompting; this function
// performs the durable write.
func FirstSeen(s *routestore.Store, pub ed25519.PublicKey, displayName string,
	now time.Time, accepted bool) error {
	if !accepted {
		return errors.New("trust: first-seen not accepted")
	}
	id := fingerprintHex(pub)
	from := StateUnknown
	to := StateTOFU
	bucket := routestore.HourBucket(now)
	if err := s.UpsertPublisher(routestore.PublisherRow{
		PublisherID: id, DisplayName: displayName, TrustLevel: string(to),
		FirstSeen: bucket, LastSeenBundle: bucket, KeyStatus: "active",
		RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		return err
	}
	return s.AppendTrustAudit(id, string(from), string(to), "first-seen accepted", now)
}

// AcceptRotation records a successfully verified rotation chain. The new
// publisher is pinned with the same trust level as the old publisher; the
// old publisher's row is updated to key_status=rotated.
func AcceptRotation(s *routestore.Store, oldPub, newPub ed25519.PublicKey,
	displayName string, now time.Time) error {
	oldID := fingerprintHex(oldPub)
	newID := fingerprintHex(newPub)
	if oldID == newID {
		return errors.New("trust: rotation chain has identical keys")
	}
	old, err := s.GetPublisher(oldID)
	if err != nil {
		return fmt.Errorf("trust: old publisher unknown: %w", err)
	}
	old.KeyStatus = "rotated"
	if err := s.UpsertPublisher(old); err != nil {
		return err
	}
	bucket := routestore.HourBucket(now)
	rotation := append([]string{oldID}, old.RotationChain...)
	if err := s.UpsertPublisher(routestore.PublisherRow{
		PublisherID:       newID,
		DisplayName:       displayName,
		TrustLevel:        old.TrustLevel,
		FirstSeen:         bucket,
		LastSeenBundle:    bucket,
		KeyStatus:         "active",
		RotationChain:     rotation,
		RevocationSources: []string{},
	}); err != nil {
		return err
	}
	return s.AppendTrustAudit(newID, string(StateUnknown), State(old.TrustLevel).String(),
		"rotation accepted from "+oldID, now)
}

// MarkRevoked marks a publisher as revoked and revokes all of its routes.
func MarkRevoked(s *routestore.Store, fingerprint, reason, source string, now time.Time) error {
	row, err := s.GetPublisher(fingerprint)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// Allow revocation of an unknown key as a defensive pre-pin.
		row = routestore.PublisherRow{
			PublisherID: fingerprint, DisplayName: "(unknown)",
			TrustLevel:     string(StateRevoked),
			FirstSeen:      routestore.HourBucket(now),
			LastSeenBundle: routestore.HourBucket(now),
			KeyStatus:      "revoked",
		}
	} else {
		row.TrustLevel = string(StateRevoked)
		row.KeyStatus = "revoked"
	}
	row.RevocationSources = appendUnique(row.RevocationSources, source)
	if err := s.UpsertPublisher(row); err != nil {
		return err
	}
	if err := s.AppendTrustAudit(fingerprint, "*", string(StateRevoked), reason, now); err != nil {
		return err
	}
	return s.MarkPublisherRoutesRevoked(fingerprint)
}

// IsRevoked is a fast-path predicate.
func IsRevoked(s *routestore.Store, fingerprint string) bool {
	p, err := LookupPin(s, fingerprint)
	if err != nil {
		return false
	}
	return p.State == StateRevoked
}

func (s State) String() string { return string(s) }

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func fingerprintHex(pub ed25519.PublicKey) string {
	// Local copy of the bundle-go fingerprint to avoid an import cycle;
	// importer.go uses bundle.PublisherFingerprint and passes the hex into
	// MarkRevoked. This helper is for the rotation/first-seen paths where a
	// caller already has the public key but not the rendered hex.
	h := sha256First(pub)
	return h
}

// sha256First is implemented here to keep this package self-contained.
// It must produce identical output to bundle.PublisherFingerprint(pub).Hex.
func sha256First(pub []byte) string {
	return shaHex(pub)
}
