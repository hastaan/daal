package abi

// standby.go — the standby-address add-on, recipient side (optional
// add-ons item S7; docs/optional-addons-plan.md §1.5,
// specs/optional-addons-v1.md §3, specs/relaypack-v1.md "`_standby`
// key").
//
// A relay may have a second address, signed into its pack as
// `_standby`: open (the address itself) or sealed (only
// SHA-256("daal/standby-v1" ‖ salt ‖ ipv4)). The 16-byte standby key
// (salt ‖ ipv4) opens a sealed one. It needs no signature of its own —
// the pack already committed to it, so a forged or mistyped key matches
// nothing and is refused here. This file is where a key is ACCEPTED:
//
//   - typed by the person (engine_standby_key: StandbyKey below);
//   - the `standby_key` member of a `daal-refresh-v2` container fetched
//     by the refresh walk (core/refresh, lane L-fetch:
//     AcceptStandbyKeyBytes / StandbyKeySink).
//
// An accepted key is kept on every held route whose commitment it
// opens, as its 16 raw bytes under bundle.StandbyKeyStoreKey (encrypted
// secrets_kv). Nothing else is written: the set-route guard
// (endpoint_guard.go routeStandby) re-checks the match at every connect
// and the ladder's address variant (connect_ladder.go) reads the
// address from there. The key and the address are never logged,
// returned or reported — the answer is a closed word and a count.

import (
	"encoding/json"
	"errors"
	"fmt"

	"daal/bundle-go/bundle"
	"daal/core/engine"
	"daal/core/refresh"
)

// Outcomes of StandbyKey (the `outcome` member).
const (
	// StandbyKeyAccepted: the key opens the sealed standby of `routes`
	// held routes and is kept on each.
	StandbyKeyAccepted = "accepted"
	// StandbyKeyNoMatch: held routes have a sealed standby, and this key
	// opens none of them (a mistyped key, a key for another relay, or
	// one whose address could never be dialled).
	StandbyKeyNoMatch = "no_match"
	// StandbyKeyMalformed: not a standby key (bundle.ParseStandbyKeyText).
	StandbyKeyMalformed = "malformed"
	// StandbyKeyNoStandby: no held route (of that file) has a sealed
	// standby a key could open.
	StandbyKeyNoStandby = "no_standby"
)

// StandbyKeyResult is engine_standby_key's JSON body.
type StandbyKeyResult struct {
	Outcome string `json:"outcome"`
	Routes  int    `json:"routes"`
}

// StandbyKey is engine_standby_key(relay_pack_id, key): check the text
// form of a standby key against the sealed `_standby` of the held
// routes of one file ("" = every held file) and keep it on each route
// it opens. Error only when the engine is not initialised or the store
// cannot be written.
func StandbyKey(relayPackID, key string) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	res := StandbyKeyResult{Outcome: StandbyKeyMalformed}
	if k, err := bundle.ParseStandbyKeyText(key); err == nil {
		var serr error
		res, serr = c.acceptStandbyKey(relayPackID, k)
		if serr != nil {
			return "", serr
		}
	}
	body, _ := json.Marshal(res)
	return string(body), nil
}

// AcceptStandbyKeyBytes is the store hook for a standby key that did
// not come from a person: the 16 raw bytes, as the `standby_key` member
// of a `daal-refresh-v2` container carries them once decoded. Same
// checks and the same writes as StandbyKey; a key that is not 16 bytes
// is malformed.
func AcceptStandbyKeyBytes(relayPackID string, raw []byte) (StandbyKeyResult, error) {
	c := loadedCore()
	if c == nil {
		return StandbyKeyResult{}, errors.New("abi: not initialized")
	}
	k, err := bundle.StandbyKeyFromBytes(raw)
	if err != nil {
		return StandbyKeyResult{Outcome: StandbyKeyMalformed}, nil
	}
	return c.acceptStandbyKey(relayPackID, k)
}

// StandbyKeySink is AcceptStandbyKeyBytes as a value, for a package
// that cannot import this one (core/refresh is imported BY core/abi):
// the refresh walk is handed one through an interface of its own with
// this method set and calls it when a container carries a key.
// accepted = the number of routes the key opened (0: refused).
type StandbyKeySink struct{}

var _ refresh.StandbyKeySink = StandbyKeySink{}

// AcceptStandbyKey implements the refresh walk's standby-key hook.
func (StandbyKeySink) AcceptStandbyKey(relayPackID string, key []byte) (accepted int, err error) {
	res, err := AcceptStandbyKeyBytes(relayPackID, key)
	return res.Routes, err
}

// acceptStandbyKey keeps k on every held route (of relayPackID, or of
// every file when "") whose stored sealed `_standby` it opens. A key
// whose address is not a public IPv4 address is never kept, even when
// it matches (bundle.StandbyAddressOK). Shadowsocks routes have no
// standby (the store holds none for them; skipped anyway), nor do
// revoked or expired ones.
func (c *Core) acceptStandbyKey(relayPackID string, k bundle.StandbyKeyBytes) (StandbyKeyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.store == nil {
		return StandbyKeyResult{}, errors.New("abi: no store")
	}
	rows, err := c.store.ListRoutes()
	if err != nil {
		return StandbyKeyResult{}, fmt.Errorf("abi: list routes: %w", err)
	}
	usable := bundle.StandbyAddressOK(k.Address())
	sealed, n := 0, 0
	for _, row := range rows {
		if row.RelayPackID == "" || (relayPackID != "" && row.RelayPackID != relayPackID) {
			continue
		}
		if row.TransportFamily == string(bundle.TransportShadowsocks) || row.TrustState == "revoked" || row.TrustState == "expired" {
			continue
		}
		raw, err := c.store.GetSecret(bundle.StandbyStoreKey(row.RouteID))
		if err != nil || len(raw) == 0 {
			continue
		}
		sb, err := bundle.ParseStandbyJSON(raw)
		if err != nil || sb.Mode != bundle.StandbyModeSealed {
			continue
		}
		sealed++
		if !usable || !sb.Matches(k) {
			continue
		}
		kb := k // PutSecret wipes what it is handed
		if err := c.store.PutSecret(bundle.StandbyKeyStoreKey(row.RouteID), kb[:]); err != nil {
			return StandbyKeyResult{}, fmt.Errorf("abi: keep standby key: %w", err)
		}
		n++
	}
	res := StandbyKeyResult{Outcome: StandbyKeyNoStandby}
	switch {
	case n > 0:
		res = StandbyKeyResult{Outcome: StandbyKeyAccepted, Routes: n}
	case sealed > 0:
		res.Outcome = StandbyKeyNoMatch
	}
	engine.LogInfo(fmt.Sprintf("standby key outcome=%s routes=%d", res.Outcome, res.Routes))
	return res, nil
}
