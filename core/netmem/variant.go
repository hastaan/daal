package netmem

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

// Route VARIANTS — the connect ladder's per-network memory
// (core/abi connect_ladder.go; specs/network-memory-v1.md "Route
// variants").
//
// A variant is one route with its first flight changed: its hello cut
// by a desync preset, or its TLS name swapped for one of the route's
// signed cover names, or both. What a variant did on a network is kept
// in the SAME RouteMemory map as the routes themselves, under the key
//
//	<routeID>#d:<preset>          a desync preset (or "pack-<6 hex>": the pack's offer)
//	<routeID>#n:<id>              the cover name whose signed id is <id>
//	<routeID>#d:<preset>#n:<id>   both
//
// so it reuses the record's ordering counter, streaks, grade and the
// snapshot's 30-day retention, and the blob holds no name in plaintext —
// only the entry's signed id. ForgetRoute drops a route's variants with
// it; ForgetVariants drops them alone (the route's signed endpoint
// changed).
//
// Two ageing rules are the variant's own (a route's record has neither):
//
//   - Confidence halves for every VariantHalfLife since the variant last
//     carried here with nothing fresher: a winner is sticky, and decays
//     so the plain route is tested again in time.
//   - A "blocked" mark (the variant's last outcome here was a failure)
//     expires after VariantBlockedExpiry, so a name or a cut that was
//     stopped is retried once the block may have lifted. A variant that
//     has carried here before needs VariantBlockedStreak failures in a
//     row to be marked (VariantBlockedAt): one stopped hello right after
//     a flap is not enough to skip a proven winner for three days.

// VariantSep separates a route id from its variant suffix.
const VariantSep = "#"

const (
	// VariantHalfLife: confidence halves per this much time since the
	// variant last carried on the network.
	VariantHalfLife = 24 * time.Hour
	// VariantBlockedExpiry: a variant that failed here is not offered
	// again for this long; after it, it may be.
	VariantBlockedExpiry = 72 * time.Hour
	// VariantBlockedStreak: failures in a row that mark a variant which
	// has carried here before.
	VariantBlockedStreak = 2
	// shownPerRelayMax / shownRelaysMax bound CoverNamesShown.
	shownPerRelayMax = 16
	shownRelaysMax   = 64
)

// VariantKey is the RouteMemory key of a route's variant; the route id
// itself for the empty suffix.
func VariantKey(routeID, suffix string) string {
	if suffix == "" {
		return routeID
	}
	return routeID + VariantSep + suffix
}

// SplitVariantKey splits a RouteMemory key into the route id and the
// variant suffix ("" for a plain route).
func SplitVariantKey(key string) (routeID, suffix string) {
	if i := strings.Index(key, VariantSep); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// VariantsOf returns the variant records of routeID in mem, keyed by
// suffix. nil when there are none.
func VariantsOf(mem map[string]RouteMemory, routeID string) map[string]RouteMemory {
	var out map[string]RouteMemory
	prefix := routeID + VariantSep
	for k, m := range mem {
		if strings.HasPrefix(k, prefix) {
			if out == nil {
				out = map[string]RouteMemory{}
			}
			out[k[len(prefix):]] = m
		}
	}
	return out
}

// Confidence is how much a variant's last success here is still worth:
// 1 within VariantHalfLife of the hour it carried, halving per
// VariantHalfLife after that; 0 when its last outcome here was not a
// success. Hour buckets, as everything in the record.
func (m RouteMemory) Confidence(now time.Time) float64 {
	if !m.CarriedLast() || m.CarriedHour == 0 {
		return 0
	}
	age := now.UTC().Truncate(time.Hour).Sub(time.Unix(m.CarriedHour, 0).UTC())
	if age < 0 {
		age = 0
	}
	c := 1.0
	for n := age / VariantHalfLife; n > 0 && c > 1.0/1024; n-- {
		c /= 2
	}
	return c
}

// BlockedAt reports whether the record carries a "blocked" mark that has
// not expired: its last outcome here was a failure within
// VariantBlockedExpiry of now.
func (m RouteMemory) BlockedAt(now time.Time) bool {
	return m.FailedSince(now.Add(-VariantBlockedExpiry))
}

// VariantBlockedAt is BlockedAt for a variant: a failure within
// VariantBlockedExpiry, and — for one that has carried here before —
// VariantBlockedStreak of them in a row.
func (m RouteMemory) VariantBlockedAt(now time.Time) bool {
	if !m.BlockedAt(now) {
		return false
	}
	return m.Carried == 0 || m.FailStreak >= VariantBlockedStreak
}

// ShownKey is the opaque form CoverNamesShown keeps a relay address or a
// cover name in: the first 8 bytes of SHA-256 over a domain-separated
// input, hex. Never the string itself.
func ShownKey(networkID, s string) string {
	sum := sha256.Sum256([]byte("daal-netmem-shown|" + networkID + "|" + s))
	return hex.EncodeToString(sum[:8])
}

// RecordCoverNameShown notes on networkID that the cover name nameKey
// was presented to the relay relayKey (both ShownKey). Idempotent.
// Bounded: a relay keeps at most shownPerRelayMax names (more is never
// asked for: the engine stops far below), and the map at most
// shownRelaysMax relays, the lexically first one dropped to make room.
func (s *Store) RecordCoverNameShown(networkID, relayKey, nameKey string, now time.Time) error {
	if networkID == "" || relayKey == "" || nameKey == "" {
		return errors.New("netmem: empty networkID, relay or name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.Get(networkID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if snap.CoverNamesShown == nil {
		snap.CoverNamesShown = map[string][]string{}
	}
	names := snap.CoverNamesShown[relayKey]
	for _, n := range names {
		if n == nameKey {
			return nil
		}
	}
	if len(names) >= shownPerRelayMax {
		return nil
	}
	if _, ok := snap.CoverNamesShown[relayKey]; !ok && len(snap.CoverNamesShown) >= shownRelaysMax {
		keys := make([]string, 0, len(snap.CoverNamesShown))
		for k := range snap.CoverNamesShown {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		delete(snap.CoverNamesShown, keys[0])
	}
	snap.CoverNamesShown[relayKey] = append(names, nameKey)
	return s.Put(networkID, snap, now)
}

// CoverNamesShownTo returns the names (ShownKey) presented to relayKey
// on networkID; nil when none. Pure read.
func (s *Store) CoverNamesShownTo(networkID, relayKey string) []string {
	if networkID == "" || relayKey == "" {
		return nil
	}
	snap, err := s.Get(networkID)
	if err != nil {
		return nil
	}
	return append([]string(nil), snap.CoverNamesShown[relayKey]...)
}
