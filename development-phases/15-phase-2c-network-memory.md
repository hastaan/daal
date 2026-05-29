# Phase 2C — Per-Network Memory

## Roadmap Coverage

V2.3 ("Per-network memory — the client remembers which routes
worked on which networks"). Closes 2B's carry-over ("FSM state can
now be persisted per-network").

## Goal

Make Daal remember, per-network, which routes succeeded, which
mode the user picked, and how much budget each route burned. When
the user roams from network A to network B, the engine restores B's
last-known good state instead of cold-starting.

The privacy bar: the network identifier is a **truncated
SHA-256 of (carrier + SSID)**, never the SSID or BSSID itself. Cell
networks are bucketed by carrier only. The whole memory blob is
encrypted at rest in `secrets_kv`.

## Scope

- New `core/netmem/` package — `Store{ Get(networkID) Snapshot;
  Put(networkID, Snapshot); Forget(networkID); All() []NetworkID }`.
  Backed by `secrets_kv` keyed `netmem:<networkID>`.
- New release ABI function `engine_network_changed(network_kind,
  carrier, ssid)`. Surface 36 → **37**. The engine computes the
  hashed network ID, swaps `Store` snapshots, and re-applies the
  remembered mode + per-route states atomically.
- `engine_export_diagnostics` gains `current_network_id` (the
  hashed ID, never the SSID).
- Pathmanager + budget integration — `Pipe` consults the active
  network ID; counters and FSM cooldowns are tagged with that ID;
  `network_changed` triggers a swap.
- TTL — a network's memory ages out 30 days after last contact. The
  scheduler's `RefreshBudgetReset` task also sweeps stale netmem
  entries.
- Desktop UI — `Home.tsx` shows a small "Network: <hashed ID
  prefix>" line under the mode picker. No SSID. The user can tap
  "Forget this network".
- Spec: new `specs/network-memory-v1.md`; amend
  `specs/engine-abi-v1.md` to surface 37.

## Out of scope (deferred)

- **Cross-device sync** of network memory. Roadmap V4.
- **Heuristic auto-mode** based on remembered network behaviour.
  V2.4 / 2D ships lifeline; auto-mode is post-V2.

## Implementation Details

### NetworkID

```go
package netmem

type Kind string
const (
    KindWiFi    Kind = "wifi"
    KindCell    Kind = "cell"
    KindEth     Kind = "eth"
    KindUnknown Kind = "unknown"
)

// HashID computes the stable network identifier the engine and the
// netmem store agree on. Output is the first 8 bytes of
// SHA-256(kind || "|" || carrier || "|" || ssid), hex-encoded.
// For cell networks, ssid is empty so the hash buckets by carrier.
// For ethernet, both carrier and ssid are empty; the hash is constant
// per kind.
func HashID(kind Kind, carrier, ssid string) string
```

The hash function is documented and stable across versions; this is
part of the v1 contract.

### Snapshot

```go
type Snapshot struct {
    // The user-selected mode last active on this network. One of
    // the four V2 modes:
    //   "lifeline"        — 2B budget mode (0.33× factor)
    //   "normal"          — 2B default
    //   "bulk"            — 2B explicit-opt-in (bulk-capable only)
    //   "lifeline-strict" — 2D local-only behavioural mode
    // Note the engine-side string `lifeline-strict` is distinct from
    // the budget tag `lifeline-only` (V2.1 scarcity_class).
    Mode          string

    LastSeen      time.Time

    // Per-route success/failure counts for THIS network. Drives the
    // V2.4 roadmap's per-network memory: the path manager reads this
    // to bias route selection on a network's first re-encounter.
    // The map is sparse — only routes that have actually been
    // exercised on this network appear.
    RouteFamilyStats map[string]FamilyStats // family → counts

    // Per-route current FSM (posture + cooldown-reason + budget) at
    // disconnect time. Persisted so a re-encounter restores the
    // user's last-known good state instead of cold-starting.
    RouteHealth   map[string]RouteHealthSlim // route_id → slim state

    // Per-route consumed bytes for THE LAST OBSERVED hour bucket.
    // Restored on reconnect IF the bucket is still current; if the
    // bucket has rolled, the entry is discarded (the budget engine
    // already enforces this on Add).
    BudgetUsage   map[string]uint64
    BudgetBucket  time.Time

    // Network-diagnosis indicators per V0.3 / V2.4 roadmap:
    UDPProbeOK    bool      // last UDP probe outcome on this network
    UDPProbeAt    time.Time // when the probe was last run
    DNSPoisoned   bool      // dns_poisoned indicator was raised on this network
}

type FamilyStats struct {
    Successes uint64
    Failures  uint64
}

type RouteHealthSlim struct {
    Posture        string // V2.3 posture
    CooldownReason string // V0.3 category, or empty
    CooldownUntil  time.Time
    BudgetExhausted bool
}
```

Snapshots serialise as canonical JSON (sorted keys) before being
encrypted and stored. Two snapshots with the same logical content
produce byte-identical ciphertext? No — the AEAD nonce is fresh
per write; stability is at the plaintext layer.

The roadmap V2.4 is explicit about the four pieces of per-network
state: route-family success/failure counts, UDP probe result,
DNS poisoning indicator, and the user's mode + per-route budget
state. All four are encoded above. Earlier draft schemas only
captured the mode + budget pair — the family stats and the two
diagnosis indicators were missing and are added in this rewrite.

### ABI

```c
int engine_network_changed(const char* network_kind,   // "wifi"|"cell"|"eth"|"unknown"
                           const char* carrier,
                           const char* ssid,
                           char* out, int out_len);
```

Returns:

```json
{ "network_id": "1a2b3c4d5e6f7080",
  "mode": "normal",
  "restored_routes": 12,
  "fresh": false }
```

`fresh: true` means this is the first time the engine has seen this
network ID; no state was restored.

The function is **the only place** that accepts `ssid`; it is hashed
on entry and the raw value is dropped before any other code path
sees it. Tests assert this with a recording wrapper: any code path
that receives the raw SSID is a regression.

Surface 36 → **37**.

### Encrypted at rest

`secrets_kv` already provides age-encrypted storage. The blob layout:

```
key:   netmem:<networkID>
value: AGE(canonical-JSON(Snapshot))
```

Old (>30 day) entries are swept by `core/netmem/Store.Sweep(now)`,
called by the scheduler at the top of every hour.

### Key derivation (roadmap V2.4)

The encryption key is derived per the roadmap V2.4's user-class
rule:

- **High-risk user class** — the AEAD key is derived from the
  device PIN via Argon2id. Without the PIN, the netmem blobs are
  unreadable. A wrong PIN at unlock yields a soft "no remembered
  networks yet" UX, which is consistent with the high-risk threat
  model (a seized device should not yield network history under
  even a partial-cooperation attack).
- **Other user classes** (Ordinary, Blackout, Activist) — the
  AEAD key is a device-bound key sourced from the platform
  keystore (Android Keystore, macOS Keychain, Windows DPAPI, Linux
  libsecret). Loss of the keystore = loss of netmem; this is
  acceptable because the data is purely a usability optimisation,
  never a security boundary.

### Panic-wipe (roadmap V2.4 last bullet)

`Settings → Panic-wipe` (already wired for the route-secrets
vault in 1.5A) extends in 2C to also delete every `netmem:*` key
in `secrets_kv`. The wipe is synchronous and irreversible.

### Ledger of trust (UI)

The desktop renders:

```
Network 1a2b3c4d…   (Wi-Fi)        [ Forget this network ]
  Last seen: 2026-04-26 18:00 UTC
  Mode:      normal
  Routes:    12 healthy, 1 quarantined
```

Never the SSID. Never the BSSID. The user can prove to themselves the
device is not phoning home anything that names their AP.

## Testing Requirements

- Unit tests for `HashID` — every kind/carrier/ssid combination is
  stable; SHA-256 collisions are not artificially worried about
  (8-byte truncation gives 2^32 buckets, sufficient).
- Unit tests for `Store` — round-trip Put/Get; Forget removes both
  blob and index; Sweep removes >30-day entries; All returns sorted IDs.
- Integration: drive `engine_network_changed("wifi", "", "Foo")`
  twice and assert the second call returns `fresh: false` with a
  matching mode and route states.
- **Privacy test**: a `regression_test.go` greps the engine's exported
  diagnostics for the literal SSID strings used in the test and
  asserts none appear. This is the canonical "no telemetry beam"
  guard.
- Desktop e2e: the Network line shows the hash prefix only.
- `nm` count = **37**.
- Soak: a new scenario `network-roam` connects on `Wi-Fi:Home`,
  exhausts a route's budget, switches to `Wi-Fi:Cafe`, and asserts
  the second network sees a fresh budget (not the exhausted state of
  the first).

## Exit criteria

1. `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` = **37**.
2. Engine version unchanged at `daal-core 0.5.0+survivability`.
3. `core/netmem` tests green; privacy regression test green.
4. Soak `network-roam` PASS in both modes.
5. Desktop renders network line correctly with no SSID leakage.
6. `specs/network-memory-v1.md` shipped; `engine-abi-v1.md` amended.

## Handover to Phase 2D

Phase 2D receives:
- A network ID it can attach lifeline-mode persistence to (a network
  the user has flagged as hostile remembers it across sessions).
- A 37-function release ABI ready for one more append in 2G if
  needed, or none.
- A Forget-this-network button users can use to recover from a
  poisoned-memory edge case.
