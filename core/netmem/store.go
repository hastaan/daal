package netmem

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// SecretsKV is the minimal surface this package needs from the
// routestore secrets KV. It is satisfied by *routestore.Store at
// the abi layer; tests use an in-memory fake.
type SecretsKV interface {
	PutSecret(key string, plaintext []byte) error
	GetSecret(key string) ([]byte, error)
	DeleteSecret(key string) error
	ListSecretKeys(prefix string) ([]string, error)
}

// keyPrefix is the routestore secrets_kv key namespace this package
// owns. Stable across versions; bumping requires a migration.
const keyPrefix = "netmem:"

// TTL is how long a Snapshot is retained without being re-Put. The
// Sweep call deletes stale entries. 30 days matches the V2.4
// roadmap line.
const TTL = 30 * 24 * time.Hour

// ErrNotFound is returned by Get when no snapshot exists for the
// given network ID.
var ErrNotFound = errors.New("netmem: not found")

// Store is the per-network-memory persistence layer.
//
// Get and Put are each one operation of the underlying SecretsKV and as
// thread-safe as it is (routestore is, per its package contract). Every
// helper that READS a snapshot, changes it and WRITES it back holds mu
// for the whole of that: the host's network callback switches networks
// on its own thread while a connect or the liveness loop records route
// outcomes on another, and two such read-modify-writes interleaved
// dropped whichever was written first (a carried sample, a failure
// streak) or filed it under a record that was being moved away.
type Store struct {
	kv SecretsKV
	mu sync.Mutex
}

// New returns a Store that persists into the given SecretsKV.
func New(kv SecretsKV) *Store {
	return &Store{kv: kv}
}

// Put encodes the snapshot as canonical JSON and persists it
// encrypted under "netmem:<networkID>". LastSeen is overwritten
// with the supplied now timestamp so callers can't accidentally
// race Sweep by leaving it zero.
func (s *Store) Put(networkID string, snap Snapshot, now time.Time) error {
	if networkID == "" {
		return errors.New("netmem: empty networkID")
	}
	snap.LastSeen = now.UTC()
	body, err := snap.MarshalCanonical()
	if err != nil {
		return err
	}
	return s.kv.PutSecret(keyPrefix+networkID, body)
}

// Get returns the snapshot for networkID, or ErrNotFound. An empty
// snapshot is returned alongside the error sentinel; callers may
// ignore the snapshot value and rely solely on the error.
func (s *Store) Get(networkID string) (Snapshot, error) {
	if networkID == "" {
		return Snapshot{}, errors.New("netmem: empty networkID")
	}
	body, err := s.kv.GetSecret(keyPrefix + networkID)
	if err != nil {
		// Translate any underlying not-found into ErrNotFound.
		// routestore returns sql.ErrNoRows on miss; for
		// privacy/semantic reasons we collapse all read errors
		// here into the single sentinel — callers cannot
		// distinguish "missing" from "decrypt failed" anyway, and
		// either way the right behaviour is "treat as fresh".
		return Snapshot{}, ErrNotFound
	}
	return UnmarshalSnapshot(body)
}

// PutKeepingRouteMemory writes snap as the record of networkID, keeping
// what the record already holds about its ROUTES (RouteMemory and its
// sequence) — those are written when a route carries or fails, by
// RecordRouteOutcome, and a rewrite of everything else must not undo
// one that landed a moment ago. The read and the write are one step.
func (s *Store) PutKeepingRouteMemory(networkID string, snap Snapshot, now time.Time) error {
	if networkID == "" {
		return errors.New("netmem: empty networkID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, err := s.Get(networkID); err == nil {
		snap.RouteMemory, snap.RouteMemorySeq = prev.RouteMemory, prev.RouteMemorySeq
	}
	return s.Put(networkID, snap, now)
}

// PutIfAbsent writes snap as the record of networkID unless it already
// has one, as one step. Reports whether it wrote.
func (s *Store) PutIfAbsent(networkID string, snap Snapshot, now time.Time) (bool, error) {
	if networkID == "" {
		return false, errors.New("netmem: empty networkID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.Get(networkID); err == nil {
		return false, nil
	}
	return true, s.Put(networkID, snap, now)
}

// Forget deletes the snapshot for networkID. Idempotent: deleting
// an absent key returns nil.
func (s *Store) Forget(networkID string) error {
	if networkID == "" {
		return errors.New("netmem: empty networkID")
	}
	return s.kv.DeleteSecret(keyPrefix + networkID)
}

// All returns the network IDs currently persisted, sorted
// lexicographically. Used by diagnostics + Sweep. Does NOT decrypt
// any snapshot.
func (s *Store) All() ([]string, error) {
	keys, err := s.kv.ListSecretKeys(keyPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, keyPrefix))
	}
	sort.Strings(out)
	return out, nil
}

// RecordWinningRendezvousChannel updates the per-network
// `LastWinningRendezvousChannel` hint without rewriting the
// rest of the snapshot. Phase 3B; consumed by the rendezvous
// Selector via the engine layer's wired callback. If no
// snapshot exists yet for networkID, a fresh one is created
// carrying only this hint and the supplied LastSeen timestamp.
func (s *Store) RecordWinningRendezvousChannel(networkID, channelID string, now time.Time) error {
	if networkID == "" {
		return errors.New("netmem: empty networkID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.Get(networkID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	snap.LastWinningRendezvousChannel = channelID
	return s.Put(networkID, snap, now)
}

// LookupWinningRendezvousChannel returns the per-network hint
// for the supplied networkID, or "" if absent. Pure read.
func (s *Store) LookupWinningRendezvousChannel(networkID string) string {
	if networkID == "" {
		return ""
	}
	snap, err := s.Get(networkID)
	if err != nil {
		return ""
	}
	return snap.LastWinningRendezvousChannel
}

// RecordLastUsedMasqueSubmode updates the per-network
// `LastUsedMasqueSubmode` hint without rewriting the rest of
// the snapshot. Phase 3C; consumed by the masque handler's
// chooseSubmode cascade via the engine layer's wired callback.
// If no snapshot exists yet for networkID, a fresh one is
// created carrying only this hint and the supplied LastSeen
// timestamp.
//
// Caller is expected to validate `submode` against the v1
// closed list (`core/transports/masque.IsKnownSubmode`); this
// store accepts any value so old data round-trips even if the
// closed list evolves.
func (s *Store) RecordLastUsedMasqueSubmode(networkID, submode string, now time.Time) error {
	if networkID == "" {
		return errors.New("netmem: empty networkID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.Get(networkID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	snap.LastUsedMasqueSubmode = submode
	return s.Put(networkID, snap, now)
}

// LookupLastUsedMasqueSubmode returns the per-network MASQUE
// sub-mode hint for networkID, or "" if absent. Pure read.
func (s *Store) LookupLastUsedMasqueSubmode(networkID string) string {
	if networkID == "" {
		return ""
	}
	snap, err := s.Get(networkID)
	if err != nil {
		return ""
	}
	return snap.LastUsedMasqueSubmode
}

// RecordRouteCarried notes that routeID carried a round trip on
// networkID. The rest of the snapshot is kept as it is; a network seen
// for the first time gets a snapshot holding only this.
func (s *Store) RecordRouteCarried(networkID, routeID string, now time.Time) error {
	return s.RecordRouteOutcome(networkID, routeID, RouteOutcome{Carried: true}, now)
}

// RecordRouteFailed notes that routeID failed on networkID, and the
// taxonomy category it failed with.
func (s *Store) RecordRouteFailed(networkID, routeID, category string, now time.Time) error {
	return s.RecordRouteOutcome(networkID, routeID, RouteOutcome{Category: category}, now)
}

func (s *Store) recordRoute(networkID, routeID string, now time.Time, set func(*RouteMemory, uint64, int64)) error {
	if networkID == "" || routeID == "" {
		return errors.New("netmem: empty networkID or routeID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.Get(networkID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if snap.RouteMemory == nil {
		snap.RouteMemory = map[string]RouteMemory{}
	}
	snap.RouteMemorySeq++
	m := snap.RouteMemory[routeID]
	set(&m, snap.RouteMemorySeq, now.UTC().Truncate(time.Hour).Unix())
	snap.RouteMemory[routeID] = m
	return s.Put(networkID, snap, now)
}

// LookupRouteMemory returns what is remembered about every route on
// networkID; nil when nothing is. Pure read.
func (s *Store) LookupRouteMemory(networkID string) map[string]RouteMemory {
	if networkID == "" {
		return nil
	}
	snap, err := s.Get(networkID)
	if err != nil {
		return nil
	}
	return snap.RouteMemory
}

// ForgetRoute removes routeID from the memory of every network. For a
// route the person deleted.
func (s *Store) ForgetRoute(routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids, err := s.All()
	if err != nil {
		return err
	}
	for _, id := range ids {
		snap, err := s.Get(id)
		if err != nil {
			continue
		}
		if _, ok := snap.RouteMemory[routeID]; !ok {
			continue
		}
		delete(snap.RouteMemory, routeID)
		// LastSeen is kept: forgetting a route is not a visit to the
		// network and must not extend its retention.
		body, err := snap.MarshalCanonical()
		if err != nil {
			return err
		}
		if err := s.kv.PutSecret(keyPrefix+id, body); err != nil {
			return err
		}
	}
	return nil
}

// Sweep deletes snapshots older than TTL. Returns the IDs deleted
// in deterministic order. Callers are expected to call Sweep on
// the scheduler's hourly tick.
func (s *Store) Sweep(now time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids, err := s.All()
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-TTL)
	var deleted []string
	for _, id := range ids {
		snap, err := s.Get(id)
		if err != nil {
			// Corrupt/undecryptable: drop it. The privacy posture
			// is "stale wins over inscrutable".
			_ = s.Forget(id)
			deleted = append(deleted, id)
			continue
		}
		if snap.LastSeen.Before(cutoff) {
			if err := s.Forget(id); err == nil {
				deleted = append(deleted, id)
			}
		}
	}
	return deleted, nil
}
