# Per-Network Memory v1

## Status

**Frozen at the end of Phase 2C.** The hashed network-ID derivation,
the `Snapshot` JSON shape, the encrypted-at-rest contract, the
30-day TTL, the engine_network_changed ABI shape, and the
SSID/carrier no-leak invariant are part of the V2 entry-criterion
contract and the V0.1 + CC.6 privacy posture.
**Phase 3B additively widens `Snapshot` with one field —
`last_winning_rendezvous_channel: string` — consumed by the
3B rendezvous Selector. The hash derivation, no-leak invariant,
and ABI shape are unchanged.**
**Phase 3C additively widens `Snapshot` with one field —
`last_used_masque_submode: string` — consumed by the 3C
chooseSubmode cascade as a soft hint biasing the start rung
of the next session on this network.**

## Roadmap coverage

V2.4 ("Per-network memory — a small SQLite store of coarse network
ID, route-family success/failure counts per network, UDP probe
result per network, DNS-poisoning indicator per network; encrypted
at rest with a key derived from the device PIN (high-risk class)
or a device-bound key (other classes); panic-wipe deletes it").

## Privacy invariants (load-bearing)

1. **Raw SSID, BSSID, and carrier strings NEVER cross the
   `engine_network_changed` argument frame.** They are hashed at
   the entry of `core/abi.NetworkChanged`; the raw inputs are
   discarded in the same function call before the hash propagates
   anywhere else.
2. **Persisted blob is encrypted at rest** via the routestore age
   identity (`secrets_kv` v1).
3. **The hashed network ID is not a secret** — the user is entitled
   to see it (rendered as an 8-character hex prefix in the desktop's
   `NetworkLine` component) so they can verify the engine is
   observing roams without ever seeing what the engine thinks
   their SSID is.
4. **Regression-tested.** `core/abi.TestSSIDDoesNotLeakIntoDiagnostics`
   drives `engine_network_changed` with distinctive SSID + carrier
   strings, then exports diagnostics, and asserts neither raw
   string appears anywhere in the output. The soak rig adds a
   day-level invariant (`no_ssid_leak_in_diagnostics`) keyed by
   each scenario's `engine_actions`.

## HashID derivation

```
networkID = firstNBytes(8, SHA-256(kind || "|" || carrier || "|" || ssid))
            → lowercase hex (16 chars)
```

- 8-byte truncation = 2^32 buckets — overkill for a single
  device's lifetime network history.
- `kind` ∈ {`wifi`, `cell`, `eth`, `unknown`}.
- For cell networks, `ssid` is empty; the hash buckets by carrier.
- For ethernet, both carrier and ssid are empty; hash is constant
  per kind.
- `SentinelUnset = "0000000000000000"` is the network ID the engine
  starts on after `engine_init`, before the first
  `engine_network_changed`. Treated as a real-but-empty network:
  writes are accepted, but Sweep prunes it on the first hour
  boundary if no real Put happens.

The hash function is **part of the v1 contract**; bumping the
truncation length, the separator, or the hash algorithm
invalidates every saved blob.

## Snapshot shape

```jsonc
{
  "mode": "lifeline" | "normal" | "bulk" | "lifeline-strict",
  "last_seen": "2026-04-27T12:00:00Z",
  "route_family_stats": { "vless-reality": { "successes": 12, "failures": 1 } },
  "route_health": { "r1": { "posture": "ImportedActive",
                            "cooldown_reason": "tcp_reset",
                            "cooldown_until": "...",
                            "budget_exhausted": false } },
  "budget_usage": { "r1": 5000000 },
  "budget_bucket": "2026-04-27T12:00:00Z",
  "udp_probe_ok": true,
  "udp_probe_at": "2026-04-27T11:30:00Z",
  "dns_poisoned": false,
  "last_winning_rendezvous_channel": "",
  "last_used_masque_submode": ""
}
```

Serialised as canonical JSON (sorted keys at every level), then
encrypted via `routestore.PutSecret` under the key
`netmem:<networkID>`.

The shape covers every V2.4 roadmap bullet:
- Mode + per-route budget state.
- Per-route-family success/failure counts.
- UDP probe result per network.
- DNS-poisoning indicator per network.

## ABI

`engine_network_changed` (Phase 2C release ABI, surface 36 → **37**):

```c
int engine_network_changed(const char* kind,
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

`fresh: true` iff this is the first time the engine has seen this
hashed ID.

`engine_export_diagnostics` widens additively with
`current_network_id` (string, the hashed ID, never the SSID).

## Network-roam flow

On every `engine_network_changed` invocation:

1. Hash the (kind, carrier, ssid) tuple. Discard the raw inputs.
2. Persist the OUTGOING network's snapshot (mode, per-route
   budget bucket usage, route health, posture) — best-effort; a
   write error is swallowed because the user's correctness bar is
   "incoming state takes effect", not "outgoing state perfectly
   preserved".
3. Read the INCOMING network's snapshot, if present.
4. Restore: mode goes through `SetMode` (so the posture axis
   follows); per-route hourly budget counters seed via
   `budget.Engine.RestoreNetwork`; per-route health is recorded
   for diagnostics (additive, not back-restored to the FSM).
5. Update active-network labels on every 2C-aware subsystem
   (`pathmanager.Manager.SetActiveNetwork`,
   `budget.Engine.SetActiveNetwork`, the abi-layer
   `globalNetmem.activeNetwork`).

## Family-escalation key (V2.3 + V2.4)

The pathmanager's family-escalation counter is keyed by
`(family, networkID)` at 2C. A roam to a different network resets
the V2.3 ladder for that family on the new network; the original
network's escalation state is intentionally untouched (the user's
V2.3 ladder for "MCI evening" survives a quick stop on a friendly
Wi-Fi).

Pre-2C callers that don't `SetActiveNetwork` observe the legacy
single-key behaviour (the empty `activeNetwork` collapses
`familyEscKey(family, "")` to just `family`). 2B's family tests
stay byte-stable.

## Encryption-key derivation (V2.4 verbatim)

| Storage profile | Key source |
|---|---|
| `vault` | Argon2id over user PIN — see `specs/key-vault-v1.md` (landed in **2D**). |
| `keystore` | Platform keystore (Android Keystore / Keychain / DPAPI / libsecret), via routestore age identity (landed in 2C). |

The labels are behavioural, never group-based — any string like
"high-risk" / "ordinary" is forbidden by
`core/opsec_test.go::TestNoGroupBasedLabels`.

At 2D, both paths are live. The `vault` profile is selected by
the empty marker file `state/.use_vault`; otherwise the engine
runs under `keystore`. Switching profile is a one-way decision
made at onboarding; mid-run profile changes are out of scope at
v1.

## TTL & sweep

`netmem.Store.Sweep(now)` deletes snapshots whose `last_seen` is
older than 30 days.

It is driven by the scheduler's own `KindNetmemSweep` action on a
24-hour cadence (`scheduler.DefaultCadence().NetmemSweep`), bound at
the ABI layer by `refreshExecutor.SweepNetworkMemory` and stamped
under the `scheduler:last-netmem-sweep` secret. The cadence is
deliberately loose relative to the 30-day TTL: a day of slack at the
boundary is immaterial, and a sweep re-reads every stored blob, which
is not free on a phone.

HISTORY, because it matters for how this section should be read. This
paragraph previously said the sweep was "wired into the scheduler's
hourly tick ... opportunistic via the hourly KindBudgetReset". No such
wiring ever existed: `Sweep` had tests and no production caller, and
`KindBudgetReset`'s executor only ever called `budget.Engine.HourRollover`.
For the whole period that text stood, the 30-day bound was documented
and unenforced, and per-network blobs accumulated for the life of the
install. The retention bound is a privacy control — the set of stored
networks is a coarse travel record recoverable from a seized device —
and a bound that nothing enforces is not a bound. Treat a retention
claim in this spec tree as a claim about code until you have found the
caller.

## Panic-wipe (V2.4 last bullet)

The existing `Settings → Panic-wipe` (Phase 1.5A) extends to
delete every `netmem:*` key in `secrets_kv`. Synchronous,
irreversible. The wipe primitive is the same routestore
`DeleteSecret` plus the new `ListSecretKeys` primitive (Phase
2C).

## Files

### Engine (Go)

- `core/netmem/{doc.go, hash.go, snapshot.go, store.go,
  hash_test.go, store_test.go}` — new package.
- `core/routestore/secrets.go` — `ListSecretKeys(prefix)`.
- `core/budget/engine.go` — `SetActiveNetwork`, `ActiveNetwork`,
  `CaptureNetwork`, `RestoreNetwork`.
- `core/budget/network_test.go` — capture/restore + session-epoch
  invariance tests.
- `core/pathmanager/fsm.go` — `(family, networkID)` keying for
  `familyEscalation`, `familyCooldown`, `failures`, `familyLastReason`;
  `SetActiveNetwork`, `ActiveNetwork`, `NextRoute(rs, mode)`.
- `core/pathmanager/network_test.go` — per-network escalation,
  roam-reset, `SkippedFamilies` projection, `NextRoute` wiring.
- `core/abi/network.go`, `core/abi/network_export.go`,
  `core/abi/network_gomobile.go`, `core/abi/network_test.go` — ABI
  surface for `engine_network_changed`.
- `core/abi/abi.go` — `Init` seeds `SentinelUnset`; `Shutdown`
  resets the netmem singleton; `ExportDiagnostics` widens with
  `current_network_id`.

### Soak rig

- `cmd/daal-soak-engine/main.go` — `set-mode` and
  `network-changed` commands.
- `test-rigs/distribution-failure/soak-driver/internal/{client,
  censor, soak, invariants}/*.go` — `EngineAction` schema;
  `runEngineActions` dispatcher; `ExportDiagnostics` capture +
  Input field; `no_ssid_leak_in_diagnostics` invariant.
- `test-rigs/distribution-failure/scenarios/{network-roam,
  mode-bulk-unlock, posture-recovery-cycle}.json` — the three
  engine-driven scenarios (folded 2B-Rig into 2C per spec
  approval).
- `test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go`
  — default whitelist now includes the three new scenario IDs.

### Desktop

- `client-desktop/daal-desktop-core/src/{engine.rs,
  commands.rs}` — `network_changed` Rust shim.
- `client-desktop/tauri/src-tauri/src/lib.rs` —
  `#[tauri::command] network_changed` registered.
- `client-desktop/tauri/src/lib/bridge.ts` — `NetworkKind`,
  `NetworkChangedResult`, `networkChanged()`,
  `DiagnosticsBlob.current_network_id`.
- `client-desktop/tauri/src/pages/components/NetworkLine.tsx` —
  hashed-prefix display.
- `client-desktop/tauri/src/pages/Home.tsx` — `NetworkLine` wired
  in above the mode picker.
- `client-desktop/tauri/src/i18n/{en,fa}.json` — `home.network`,
  `home.forget_network`.

## Stability

- The hash function (8-byte truncated SHA-256, separator "|",
  ordered fields) is locked at v1.
- The Snapshot JSON shape is locked at v1; new fields are
  additive only.
- `engine_network_changed` is an additive, append-only release ABI
  symbol (#37). Signature is locked.
- Diagnostics widening (`current_network_id`) is additive only.
- The SSID-leak no-leak invariant is the canonical V0.1 + CC.6
  privacy regression and applies to every future ABI addition.

## Phase 3B widening

`Snapshot` gains one optional field:

```jsonc
{
  ...,
  "last_winning_rendezvous_channel": "domain_fronted_broker"
}
```

The field is the ID of the rendezvous channel that most
recently completed a successful Solicit on this network. Set
by the engine on a successful 3B Selector race; cleared only
by the standard 30-day TTL eviction or panic-wipe. Empty
string means "no winner recorded on this network."

The 3B Selector consults the field as a soft hint: with a
recorded winner, the Selector fires that channel at t=0
regardless of the bundle-supplied or per-engine-overridden
priority list (the rest of the priority list still hedges at
t=4s). The hint is per-network and never leaves the device.

This widening is **additive**: a 3A snapshot decoded by a 3B
engine deserialises with the field empty; a 3B snapshot
decoded by a 3A engine round-trips the field as an unknown
key (Go's `encoding/json` ignores it on `Snapshot` because
the 3A struct does not declare it).

## Phase 3C widening

`Snapshot` gains one additional optional field:

```jsonc
{
  ...,
  "last_used_masque_submode": "masque_h3_quic"
}
```

The field is the MASQUE sub-mode that most recently completed
a successful Dial on this network. One of `masque_h3_quic`,
`masque_h2_connect`, `masque_lifeline`, or `""` (no record).
Set by the engine on a successful MASQUE Dial via
`core/abi.RecordChosenMasqueSubmode`; cleared only by the
standard 30-day TTL eviction or panic-wipe.

The 3C `chooseSubmode` cascade consults the field as a soft
hint at step 3: with a recorded value, the masque handler
biases the start rung to it (running BEFORE the per-session
2C UDP probe step). The hint is per-network and never leaves
the device.

The widening is again **additive** and follows the same
forward / backward-compatibility rule as 3B: a 3B snapshot
decoded by a 3C engine deserialises with the new field empty;
a 3C snapshot decoded by an older engine ignores the field.

The 3B and 3C hints coexist on the same network row;
`RecordWinningRendezvousChannel` and
`RecordLastUsedMasqueSubmode` each preserve the other field
(neither helper rewrites the full snapshot — they read,
update one field, and write).

## Cross-references

- `specs/rendezvous-channels-v1.md` — V3.2 channel taxonomy
  and selection algorithm. The netmem hint biases the
  Selector's t=0 fire.
- `specs/route-budgets-v1.md` — per-route hourly + session caps.
  At 2C, hourly counters are device-wide on the persisted axis;
  per-network restore rides on top via Capture/Restore.
- `specs/posture-fsm-v1.md` — V2.3 8-state posture axis. The
  family-escalation ladder is keyed `(family, networkID)` at 2C.
- `specs/engine-abi-v1.md` — ABI surface 36 → 37 at 2C.
- `specs/failure-taxonomy-v1.md` — V0.3 cooldown reasons.
- `specs/mode-budgets-v1.md` — V2.2 modes are persisted in
  `Snapshot.Mode` per network.
