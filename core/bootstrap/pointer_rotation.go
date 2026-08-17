package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"daal/core/routestore"
)

// PointerRotation is the project-root-signed envelope shipped alongside
// (or inside) a Tier-3 directory bundle. It carries one or both of a
// fresh primary and fallback PointerSet. Phase 1.5A clients that observe
// a rotation with a later `valid_until` than what they currently have
// (embedded or persisted) overlay it for future boots.
//
// Format: a small JSON wrapper. Each PointerSet inside the wrapper is
// itself project-root-signed, exactly as the embedded ones are; the
// wrapper itself adds no signature — the inner sets carry their own.
type PointerRotation struct {
	V        int        `json:"v"`
	Kind     string     `json:"kind"` // "pointer_rotation"
	Primary  PointerSet `json:"primary,omitempty"`
	Fallback PointerSet `json:"fallback,omitempty"`
}

// PersistedPointers is the on-disk shape stored in secrets_kv under the
// key bootstrap-pointers:v1.
type PersistedPointers struct {
	V        int        `json:"v"`
	Primary  PointerSet `json:"primary"`
	Fallback PointerSet `json:"fallback"`
}

// PersistKey is the secrets_kv key under which persisted rotations live.
const PersistKey = "bootstrap-pointers:v1"

// VerifyPointerRotation validates each non-empty inner set against the
// project-root public key.
func VerifyPointerRotation(rot PointerRotation, rootPub ed25519.PublicKey, now time.Time) error {
	if rot.V != 1 {
		return fmt.Errorf("pointer_rotation: unsupported version %d", rot.V)
	}
	if rot.Kind != "pointer_rotation" {
		return fmt.Errorf("pointer_rotation: bad kind %q", rot.Kind)
	}
	if len(rot.Primary.Pointers) == 0 && len(rot.Fallback.Pointers) == 0 {
		return errors.New("pointer_rotation: empty rotation")
	}
	if len(rot.Primary.Pointers) > 0 {
		if err := VerifyPointerSet(rot.Primary, rootPub, now); err != nil {
			return fmt.Errorf("primary: %w", err)
		}
	}
	if len(rot.Fallback.Pointers) > 0 {
		if err := VerifyPointerSet(rot.Fallback, rootPub, now); err != nil {
			return fmt.Errorf("fallback: %w", err)
		}
	}
	return nil
}

// LoadPersistedPointers returns the on-disk persisted set, or
// (zero-value, nil) if none is stored.
func LoadPersistedPointers(store *routestore.Store) (PersistedPointers, error) {
	body, err := store.GetSecret(PersistKey)
	if err != nil || len(body) == 0 {
		return PersistedPointers{}, nil
	}
	var p PersistedPointers
	if err := json.Unmarshal(body, &p); err != nil {
		return PersistedPointers{}, nil
	}
	return p, nil
}

// PersistPointerRotation stores `rot` in secrets_kv if and only if its
// inner sets verify under rootPub AND each set's valid_until exceeds the
// currently persisted (or embedded fallback) valid_until.
//
// Tampered envelopes are silently dropped — the function returns nil and
// performs no write. This matches the Phase 1.5A spec: a runtime rotation
// is an opportunistic improvement, never a vector for downgrade.
func PersistPointerRotation(store *routestore.Store, rot PointerRotation,
	rootPub ed25519.PublicKey, embedded *Manifest, now time.Time) (bool, error) {

	if err := VerifyPointerRotation(rot, rootPub, now); err != nil {
		return false, nil // silent drop
	}
	current, _ := LoadPersistedPointers(store)
	merged := PersistedPointers{V: 1, Primary: current.Primary, Fallback: current.Fallback}

	rotationContributed := false
	consider := func(rotation PointerSet, persisted PointerSet, embedded PointerSet) (PointerSet, bool) {
		// Compare rotation against the higher of (persisted, embedded).
		baseline := embedded
		if before(baseline.ValidUntil, persisted.ValidUntil) {
			baseline = persisted
		}
		if len(rotation.Pointers) > 0 && before(baseline.ValidUntil, rotation.ValidUntil) {
			return rotation, true
		}
		return persisted, false
	}
	if next, won := consider(rot.Primary, current.Primary, embedded.PrimaryPointers); won {
		merged.Primary = next
		rotationContributed = true
	}
	if next, won := consider(rot.Fallback, current.Fallback, embedded.FallbackPointers); won {
		merged.Fallback = next
		rotationContributed = true
	}
	if !rotationContributed {
		return false, nil
	}

	body, err := json.Marshal(merged)
	if err != nil {
		return false, err
	}
	if curr, _ := store.GetSecret(PersistKey); equalBytes(curr, body) {
		return false, nil
	}
	if err := store.PutSecret(PersistKey, body); err != nil {
		return false, fmt.Errorf("pointer_rotation: persist: %w", err)
	}
	return true, nil
}

// EffectivePointerSets returns the pointer sets a fetch should actually
// use: the persisted (rotated) set when it outlives the embedded one,
// otherwise the embedded set.
//
// Read-only by design. Provider.Refresh calls this on every fetch
// rather than mutating the process-wide Manifest, because that Manifest
// is also read concurrently by engine_pointer_rotation_status — an
// in-place overlay there is a data race, and the race would be on the
// one structure that decides where the device looks for help.
func EffectivePointerSets(store *routestore.Store, m *Manifest) (primary, fallback PointerSet) {
	if m == nil {
		return PointerSet{}, PointerSet{}
	}
	primary, fallback = m.PrimaryPointers, m.FallbackPointers
	if store == nil {
		return primary, fallback
	}
	persisted, _ := LoadPersistedPointers(store)
	if before(primary.ValidUntil, persisted.Primary.ValidUntil) {
		primary = persisted.Primary
	}
	if before(fallback.ValidUntil, persisted.Fallback.ValidUntil) {
		fallback = persisted.Fallback
	}
	return primary, fallback
}

// OverlayPersistedOntoManifest mutates `m` so that any persisted pointer
// set with a later valid_until than the embedded one wins. Called during
// engine boot — after embedded.LoadManifest(), before PinTier1 — where
// nothing else holds a reference to `m` yet. Anything running after boot
// must use EffectivePointerSets instead.
func OverlayPersistedOntoManifest(store *routestore.Store, m *Manifest) {
	if store == nil || m == nil {
		return
	}
	m.PrimaryPointers, m.FallbackPointers = EffectivePointerSets(store, m)
}

// PointerRotationStatus is the JSON shape returned by the ABI.
type PointerRotationStatus struct {
	HavePersisted         bool   `json:"have_persisted"`
	PrimaryValidUntil     string `json:"primary_valid_until"`
	FallbackValidUntil    string `json:"fallback_valid_until"`
	PrimarySource         string `json:"primary_source"` // "embedded" | "persisted"
	FallbackSource        string `json:"fallback_source"`
	EmbeddedPrimaryUntil  string `json:"embedded_primary_until"`
	EmbeddedFallbackUntil string `json:"embedded_fallback_until"`
}

// Status describes which pointer set the next boot would use.
func (m *Manifest) StatusFromStore(store *routestore.Store) PointerRotationStatus {
	out := PointerRotationStatus{
		EmbeddedPrimaryUntil:  m.PrimaryPointers.ValidUntil,
		EmbeddedFallbackUntil: m.FallbackPointers.ValidUntil,
	}
	if store == nil {
		out.PrimaryValidUntil = m.PrimaryPointers.ValidUntil
		out.FallbackValidUntil = m.FallbackPointers.ValidUntil
		out.PrimarySource = "embedded"
		out.FallbackSource = "embedded"
		return out
	}
	persisted, _ := LoadPersistedPointers(store)
	out.HavePersisted = len(persisted.Primary.Pointers) > 0 || len(persisted.Fallback.Pointers) > 0
	if before(m.PrimaryPointers.ValidUntil, persisted.Primary.ValidUntil) {
		out.PrimaryValidUntil = persisted.Primary.ValidUntil
		out.PrimarySource = "persisted"
	} else {
		out.PrimaryValidUntil = m.PrimaryPointers.ValidUntil
		out.PrimarySource = "embedded"
	}
	if before(m.FallbackPointers.ValidUntil, persisted.Fallback.ValidUntil) {
		out.FallbackValidUntil = persisted.Fallback.ValidUntil
		out.FallbackSource = "persisted"
	} else {
		out.FallbackValidUntil = m.FallbackPointers.ValidUntil
		out.FallbackSource = "embedded"
	}
	return out
}

func before(a, b string) bool {
	if a == "" {
		return b != ""
	}
	if b == "" {
		return false
	}
	at, ae := time.Parse(time.RFC3339, a)
	bt, be := time.Parse(time.RFC3339, b)
	if ae != nil || be != nil {
		return false
	}
	return at.Before(bt)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
