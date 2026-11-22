# Engine ABI v1

## Status

**Frozen at the end of Phase 1B; extended additively in Phase 1C, 1D,
1.5A, 1.5B, 1.5C-Polish, 2F, 2A, 2C, 2D, 2G, 2E, 3A, and 3B.**
Surface MAY grow (new functions); existing function signatures and
semantics MAY NOT change. Per V0.4 / V1.1, ABI stability is a
contract.

Current surface count: **70 release symbols** (61 verified 2026-11-19
with `nm` against a library built from the tree; `engine_network_facts`
added the same day, `engine_relaypack_refresh`, the five
`engine_field_probe_*`, `engine_survey_routes` and `engine_standby_key`
on 2026-11-20, all counted from the source — see
the ABI ledger at the end of this document, which is the authoritative
count). The source
tree carries **73** `//export engine_*` declarations; the extra three
are `//go:build cshared && soak` and are never present in a release
build.

The `engine_version` string is **`daal-core 0.9.0+v3-share`**. The
version bump is informative; the surface change itself remains
append-only.

The historical per-phase breakdown that used to sit here (14 from
Phase 1B + 9 from 1C + …, totalling 44) stopped being maintained
after Phase 3B. Do not use it as a count; use the ledger.

Phase 2G additions:

- `engine_set_auto_promotion(int enabled) -> int` — flips the
  preference that lets the engine auto-promote to `lifeline-strict`
  when the burn-pressure detector fires. Default-on at
  `engine_init`; the flag survives session epochs (it is a user
  preference, not session state). Always returns 0. Manual
  `engine_set_mode` calls within the same hour-bucket suppress
  auto-promotion for that bucket — the user's choice always wins.

`engine_export_diagnostics` widens additively at 2G with:
`auto_promotion_enabled: bool` (always present) and
`auto_promotion_last_fired_at: RFC3339` (rendered only after the
detector has fired at least once this engine session). Canonical
regressions:

- `core/abi/auto_promotion_test.go::TestAutoPromotionDefaultsEnabled`
- `core/abi/auto_promotion_test.go::TestEvaluateAutoPromotionRespectsManualOverride`
- `core/abi/auto_promotion_test.go::TestEvaluateAutoPromotionDebouncesPerHour`

Phase 2E additions:

- `engine_lifecycle_event(const char* token) -> int` — surfaces
  iOS Network-Extension state transitions into the engine. Locked
  v1 token set: `will_sleep`, `did_wake`, `memory_pressure_warning`.
  Returns 0 on success, -1 on tokens outside the locked v1 set
  (the engine refuses to silently accept tokens introduced by a
  future Swift version without an ABI spec amendment). The
  function is side-effect-light by design: the engine records the
  event for diagnostics and nothing else. Real reactions
  (cooldown adjustment, refresh deferral) happen elsewhere when
  those code paths consult diagnostics state.

`engine_export_diagnostics` widens additively at 2E with:
`last_lifecycle_event` (the most recent token, or absent) and
`last_lifecycle_at` (RFC3339; absent if no event has fired in
this engine session). Both fields are absent on Linux / Android /
desktop builds — no caller invokes the symbol on those platforms.
Canonical regressions:

- `core/abi/lifecycle_test.go::TestLifecycleEventAcceptsLockedTokens`
- `core/abi/lifecycle_test.go::TestLifecycleEventDiagnosticsAbsentBeforeFirstFire`
- `core/abi/lifecycle_test.go::TestLifecycleEventDoesNotBumpSessionEpoch`

The iOS gomobile artifact (`Libbox.xcframework`) is built with:

```
gomobile bind -target=ios -iosversion=15.0 -tags ios \
  -ldflags='-s -w' -o client-ios/Libbox.xcframework ./core/abi
```

Documented in `specs/ios-build-v1.md`.

Phase 3A additions:

- `engine_set_experimental_families_enabled(int enabled) -> int`
  — flips the per-engine boolean that admits routes whose family
  is at Experimental maturity (see
  `specs/transport-families-v1.md`). Default-OFF at
  `engine_init`; the flag survives session epochs (it is a user
  preference, not session state). Returns 0 on success, -1 on
  engine-not-initialised. Persists in `secrets_kv` under key
  `experimental_families_enabled`. The pathmanager's rank
  pipeline gains a new filter step *before* trust / budget /
  network-memory that drops experimental-maturity routes when
  the flag is OFF; dropped routes appear in the 2A skip ledger
  with `reason: "experimental_family_disabled"` and the 2G
  burn-pressure detector ignores entries with that reason —
  experimental-only networks must NOT trigger auto-promotion.

`engine_export_diagnostics` widens additively at 3A with:
`experimental_families_enabled: bool` (always present) and
`experimental_routes_skipped: int` (per-rank-pass count of
routes filtered by the gate). Canonical regressions:

- `core/abi/experimental_test.go::TestExperimentalGateDefaultsOff`
- `core/abi/experimental_test.go::TestExperimentalGateSurvivesSessionEpoch`
- `core/abi/experimental_test.go::TestExperimentalGatePersistsAcrossModeChange`
- `core/pathmanager/family_filter_test.go::TestExperimentalFilterDropsAndLogs`
- `core/pathmanager/family_filter_test.go::TestBurnPressureIgnoresExperimentalSkips`

Phase 3B additions:

- `engine_set_rendezvous_priority(const char* json_array) -> int`
  — sets the per-engine override of the bundle-supplied
  rendezvous-channel priority list. The arg is a JSON-encoded
  array of channel IDs (each MUST be one of
  `domain_fronted_broker`, `sqs`, `amp_cache`, `push`,
  `offline_hint`). An empty array clears the override; the
  engine falls back to the bundle's
  `routes[].rendezvous_priority`. Returns 0 on success, -1 on
  malformed JSON or unknown channel ID, -2 on
  engine-not-initialised. Persists in secrets KV under
  `rendezvous_priority`. Survives session epochs.
- `engine_set_push_rendezvous_enabled(int enabled) -> int`
  — flips the per-engine opt-in for the FCM/APNS push
  rendezvous channel. Default-OFF at engine_init. The flag
  survives session epochs. Returns 0 on success, -1 on
  engine-not-initialised, -2 in the `vault` storage profile
  (high-risk users; hard rule per
  `specs/push-rendezvous-v1.md`). Persists in secrets KV
  under `push_rendezvous_enabled`. Push device-token setting
  is gomobile-only and NEVER round-trips through cshared.

`engine_export_diagnostics` widens additively at 3B with:
`rendezvous_priority: [string]` (always present; the active
priority — override OR bundle), `rendezvous_channel: string`
(winning channel for the active route, OR absent for
non-Snowflake routes), and `push_rendezvous_enabled: bool`
(always present). Canonical regressions:

- `core/abi/rendezvous_test.go::TestRendezvousPriorityDefaultsEmpty`
- `core/abi/rendezvous_test.go::TestRendezvousPrioritySurvivesSessionEpoch`
- `core/abi/rendezvous_test.go::TestPushRendezvousRejectedInVaultProfile`
- `core/rendezvous/selector_test.go::TestHedgedSelectionFiresAtFourSeconds`
- `core/rendezvous/selector_test.go::TestNetmemHintBiasesT0`

Phase 3C additions:

- `engine_set_masque_submode_override(const char* submode) -> int`
  — sets the per-engine pin for the MASQUE sub-mode chooser.
  The arg is a NUL-terminated UTF-8 string from the v1 closed
  list (`masque_h3_quic`, `masque_h2_connect`,
  `masque_lifeline`) OR the empty string to clear (engine
  returns to the auto cascade). NULL is treated as empty.
  Returns 0 on success, -1 on engine-not-initialised, -3 on
  unknown sub-mode. Persists in secrets KV under
  `masque_submode_override`. Survives session epochs.
  Accepted in BOTH the keystore and vault storage profiles
  (MASQUE has no FCM/APNS surface — there is no profile
  rejection at 3C).

`engine_export_diagnostics` widens additively at 3C with:
`masque_submode: string` (always present; the most recently
chosen sub-mode this session, OR empty if no MASQUE route has
been activated yet), and `masque_submode_override: string`
(always present; the engine-pinned override, OR empty if no
override). Both fields are enumerable (one of three values +
`""`); neither carries a URL or IP. Canonical regressions:

- `core/abi/masque_test.go::TestMasqueSubmodeOverride_DefaultsEmpty`
- `core/abi/masque_test.go::TestSetMasqueSubmodeOverride_RejectsUnknownSubmode`
- `core/abi/masque_test.go::TestMasqueOverrideSurvivesSessionEpoch`
- `core/abi/masque_test.go::TestMasqueOverride_AcceptedInVaultProfile`
- `core/abi/masque_test.go::TestRecordChosenMasqueSubmode_PersistsThroughLayers`
- `core/abi/masque_test.go::TestDiagnostics_AlwaysCarryMasqueFields`
- `core/transports/masque/masque_test.go::TestChooseSubmode_OverrideWins`
- `core/transports/masque/masque_test.go::TestChooseSubmode_LifelineStrictHintsLifeline`
- `core/transports/masque/masque_test.go::TestChooseSubmode_NetmemHintBiasesStart`
- `core/transports/masque/masque_test.go::TestChooseSubmode_H2BurnedDropsToLifelineInLifelineModes`

Release ABI surface bumps to **45** at 3C (3B: 44 → 3C: 45).
Engine version bumps to `daal-core 0.7.2+v3-transport`.

Phase 3D additions:

- **No new release-surface ABI symbols.** Locked at 3D: the
  refraction-family hooks (psiphon + conjure) are
  package-internal Go-level entry points
  (`abi.RecordPsiphonActiveRoute`,
  `abi.RecordConjureActivation`,
  `abi.PsiphonActiveRoute`, `abi.ConjureActiveRoute`,
  `abi.ConjurePhantomInUseHash`), invoked by the in-process
  transport handlers and by the soak-engine RPC dispatcher.
  The release surface stays at 45 (append-only invariant
  preserved).

`engine_export_diagnostics` widens additively at 3D with **five
new fields**, always present:

- `psiphon_compiled_in: bool` — **constant `false` since Wave 5.**
  Both this flag and the one below claimed a vendored tree was
  linked into the running binary; neither psiphon-tunnel-core nor
  gotapdance has ever been in `core/go.mod`, and no build script
  ever passed the `-tags no_psiphon` that nominally flipped this
  one. The build-tag pair is deleted; see
  `core/abi/refraction_compiled.go` and
  `docs/transport-family-inventory.md`.
- `conjure_compiled_in: bool` — **constant `false` since Wave 5**,
  for the same reason. Both families are `unsupported` and their
  recorders refuse a non-empty route ID, so
  `psiphon_active_route`, `conjure_active_route` and
  `conjure_phantom_in_use` are permanently `""`.
- `psiphon_active_route: string` — most recently activated
  psiphon route ID this session; `""` when no activation.
- `conjure_active_route: string` — most recently activated
  conjure route ID this session; `""` when no activation.
- `conjure_phantom_in_use: string` — 8-byte SHA-256
  truncation of the raw phantom IP, hex-encoded
  (16 hex chars). The raw IP NEVER appears in diagnostics.
  Mirrors the 2C `current_network_id` and 2D PIN no-leak
  redaction invariants.

Canonical regressions:

- `core/abi/refraction_test.go::TestDiagnostics_AlwaysCarryRefractionFields`
- `core/abi/refraction_test.go::TestRecordConjureActivation_HashesPhantomIP`
- `core/abi/refraction_test.go::TestRecordConjureActivation_DifferentIPsHashDifferently`
- `core/abi/refraction_test.go::TestPsiphonCompiledInFlag_TruePerDefault`
- `core/abi/refraction_test.go::TestVersionStringIs073`
- soak: `psiphon-blob-rotation` and `conjure-phantom-pool`
  scenarios, plus the
  `no_raw_phantom_ip_leak_in_diagnostics` invariant.

Engine version bumps to `daal-core 0.7.3+v3-transport` at 3D.
Release ABI surface stays at **45** (append-only invariant
preserved; no new symbols at 3D).

Phase 3E additions:

- **Two new release-surface ABI symbols** (release 46 + 47;
  append-only invariant preserved):
  - `engine_wasm_kill_switch_pubkey()` — buffer-style
    cshared. Returns the engine-immutable Ed25519 public key
    (32 bytes raw) for the WASM kill-switch surface. Allows
    host UIs to display the publisher fingerprint. See
    `specs/wasm-kill-switch-v1.md`.
  - `engine_loaded_wasm_modules()` — buffer-style cshared.
    Returns a JSON array
    `[{slug, sha256_prefix, loaded_at}, …]` matching the
    `loaded_wasm_modules` diagnostic field. See
    `specs/wasm-transport-v1.md`.

Both symbols are present under `-tags no_wasm` (they emit the
empty surface — pubkey is the embedded constant, modules
array is `[]`). Hosts MUST NOT branch on absence.

`engine_export_diagnostics` widens additively at 3E with
**four new fields**, always present:

- `wasm_compiled_in: bool` — `false` when the running binary
  was built with `-tags no_wasm`; otherwise `true`.
- `loaded_wasm_modules: array<object>` — list of
  `{slug, sha256_prefix, loaded_at}` for every WASM module
  currently loaded into the wazero runtime. `sha256_prefix`
  is the first 16 hex chars (8 bytes); the full hash is
  NEVER surfaced. Empty array under `-tags no_wasm` or when
  no modules are loaded.
- `wasm_kill_switched_count: int` — cardinality of the
  killed-sha256 set daalted from
  `secrets_kv:wasm_killed:*` plus deltas applied this
  session.
- `last_wasm_module_dial_outcome: string` — most recent
  closed-enum dial outcome, or `""` at boot. One of
  `{ok, fuel_exhausted, memory_cap, dial_timeout,
  host_callback_error}`.

Canonical regressions:

- `core/abi/wasm_test.go::TestDiagnostics_AlwaysCarryWasmFields`
- `core/abi/wasm_test.go::TestRecordWasmDialOutcome_RejectsUnknownOutcome`
- `core/abi/wasm_excluded_test.go::TestWasmCompiledInFlag_FalseUnderNoWasmTag`
- `core/wasm/killswitch_test.go::TestPublisherCanonicalPayload_RoundTrips`
- `core/abi/rendezvous_test.go::TestVersionStringIncludesV3Transport`
  (asserts `0.8.0+v3-wasm`)
- soak: `wasm-hello-transport` and `wasm-kill-switch`
  scenarios, plus the
  `no_unloaded_module_appears_in_diagnostics` invariant.

Engine version bumps to `daal-core 0.8.0+v3-wasm` at 3E.
Release ABI surface bumps to **47** (45 → 47; append-only).

Phase 2D additions:

- `engine_set_mode` widens its accepted mode set to include
  `lifeline-strict` (signature unchanged).
- `engine_unlock_secrets(const char* pin) -> int` — Argon2id PIN-vault
  unlock. Returns 0 on success, -1 on wrong/empty PIN, -2 if the
  engine is running under the keystore storage profile.
- `engine_set_allow_bulk_capable(int allow) -> int` — flips the
  per-session bulk-capable opt-in flag honoured by the
  lifeline-strict ranker. Always returns 0; cleared by NewSession.

`engine_export_diagnostics` widens its body additively at 2D with:
`secrets_unlocked: bool`, `storage_profile: "vault" | "keystore"`,
`session_allows_bulk_capable: bool`, and (only when
`mode == "lifeline-strict"`) `lifeline_strict_active_since`.
The `storage_profile` label is behavioural by construction; the
`TestNoGroupBasedLabels` opsec invariant rejects any user-class
label such as `"high-risk"` or `"ordinary"` from appearing in the
engine, the spec tree, the desktop, or the soak rig.

The 2D PIN never crosses any other ABI surface, never appears in
diagnostics, and is wiped from the derived-key buffer immediately
after Argon2id returns. Canonical regressions:

- `core/abi/secrets_test.go::TestPINDoesNotLeakIntoDiagnostics`
- `core/keyvault/vault_test.go::TestPINNotEmbeddedInBlob`
- `test-rigs/.../invariants.go::ruleNoPINLeakInDiagnostics`

## Surface (Phase 1B — 14 functions)

```c
/* Lifecycle */
int   engine_init(const char* state_dir, const char* log_level);
int   engine_shutdown(void);
const char* engine_version(void);

/* Routes */
int   engine_set_route(const char* route_id);
int   engine_clear_route(void);
int   engine_set_mode(const char* mode);             /* lifeline | normal | bulk */
int   engine_apply_cooldown(const char* route_id, int seconds);

/* Probes */
int   engine_probe_udp(int timeout_ms);              /* 0 ok, 1 fail */
int   engine_probe_dns(int timeout_ms);
int   engine_probe_tcp443(int timeout_ms);

/* Stats / diagnostics */
int   engine_stats_redacted(char* out, int out_len);
int   engine_export_diagnostics(char* out, int out_len);

/* Bundle import */
int   engine_import_sbp(const char* path, char* out, int out_len);
int   engine_resolve_trust_prompt(const char* publisher_fingerprint,
                                  int decision,
                                  char* out, int out_len);
```

`decision`: `0`=trust, `1`=just this one bundle, `2`=cancel.

`out` buffers receive UTF-8 JSON; the function returns the number of
bytes written (excluding the trailing NUL) or a negative value on
failure.

**Signed endpoints (no symbol added; behaviour of three existing ones).**
See `specs/relaypack-v1.md` "Endpoint commitment".

- `engine_import_sbp` / `engine_resolve_trust_prompt` reject a RelayPack
  whose outbound does not match its route's signed endpoint. The verdict's
  `Reason` is one of `endpoint_mismatch`, `endpoint_unauthenticated`,
  `endpoint_malformed`, `pack_has_no_credentials`, `pack_is_older`.
  A bundle of any kind that carries no signed endpoint for a route the
  device already holds with one is rejected the same way, with
  `endpoint_downgrade` (`relaypack-v1.md` "A commitment is sticky").
  `engine_import_sbp`
  returns the rejection directly — never a trust prompt — and leaves no
  pending prompt.
- The verdict gains two additive members: `Merged` (routes whose new
  signed endpoint was applied to credentials the device already held) and
  `Unavailable` (`[{RouteID, Family, Reason}]`, `Reason` ∈ `not_offered`,
  `no_credentials`, `needs_new_file`, `older_than_device`): the pack's
  routes that were NOT
  stored. `RouteCount` counts stored routes only, on the trust prompt as
  well. A route in `Unavailable` does not exist for any other call.
- `engine_set_route` refuses a route whose stored outbound no longer
  matches the endpoint its import stored, and a RelayPack route that has
  none. The refusal is returned before any attempt is recorded: it is not
  a route failure and feeds no health or cooldown state.

**Connection check (no symbol added; behaviour of four existing ones).**
The engine instance starting is not a connection: the data plane dials
the relay lazily, so a route to a blocked relay starts like any other.
A route is connected only once it has carried one real round trip
(`core/engine/proof.go`, `core/abi/route_check.go`).

- `engine_set_route` returns 0 only after that round trip. After the
  instance starts the route is *verifying*; the engine opens a connection
  through the route's own outbound to one of a small set of very common
  hosts (drawn at random; a second, different one is tried before the
  route is called dead) and reads a TLS ServerHello back. Nothing leaves
  the device outside the tunnel and no application data is sent. The call
  therefore blocks for up to `attempts × attempt_timeout_ms` (8 s by
  default; a `tor` route is given longer) on a route where nothing is
  seen moving, and longer in the two cases below. **A host MUST NOT call
  it on a thread that draws its interface or runs its event loop**
  ("Hosts" below). On failure the instance is
  torn down, the failure is classified by phase
  (`specs/failure-taxonomy-v1.md` "Classification by phase"), the route
  is cooled down and recorded as failed, the posture goes to `Recovery`,
  and the call fails — the path an instance that could not start has
  always taken. Success, `proven` and `health_pct` are recorded only on
  proof. A proof that succeeds slower than `slow_after_ms` connects the
  route and records it as *degraded* (`path_too_slow`), never as failed.
  "Slower" is the whole proof — every attempt, the failed ones included,
  whichever phase they had reached: the caller waited through all of it.
- *Slow is not silent.* When every ordinary attempt ran out of time and
  the engine saw the path MOVING while they did — bytes came back from
  the far side; or the relay answered a connection after
  `max(slow_after_ms / 2, 1 s)` or more; or the relay's address answered
  a bare SYN that late — one further attempt is made with a budget of
  `slow_budget_ms` (20 s by default). If it completes, the route is
  connected and *degraded* (`path_too_slow`). If it does not, the connect
  fails with category `path_too_slow`: the instance is torn down and
  `route_check` is `failed`, but the route is NOT cooled down, gets no
  failure record and no success record, and produces no network signal —
  the next `engine_set_route` for it is attempted at once. A path on
  which nothing was seen moving never gets the long attempt. (The
  evidence needs a TCP connection to the relay or an answer through it; a
  QUIC route whose own handshake does not finish within one attempt shows
  none and is still `udp_no_reply`.)
- *The carry-phase timeout is asked again on a fresh connection.* A
  timeout after the route's outbound handed over a connection says
  nothing about the relay when the outbound answered from a session it
  already held — which, on a route that has been connected for a while,
  is every dial of a multiplexed, pooled or QUIC family. So after the
  ordinary attempts end that way the engine opens ONE more outbound with
  the route's own options, makes one attempt through it (another target,
  `attempt_timeout_ms`), removes it, and classifies by what that attempt
  saw: a block that begins mid-session is classified exactly as a failed
  connect through the same block would be. Not done for `naive` and
  `tor`, nor for a route dialled through a detour. If the fresh
  connection carries a round trip, the route's own session was stale;
  the check still fails (as `unknown`) and the next re-check decides.
- *A relay with no way out.* If on that fresh connection the relay
  completes its own handshake (TLS to the relay, or QUIC and its
  authentication) and the far side then stays silent as well — the third
  host in a row, each run by a different operator — the failure is
  `relay_no_egress`: the relay answers and does not reach the internet.
  It is recorded on the route, never cooled down, and is not a
  censorship-class category. Families whose dial does not include the
  relay's answer (`shadowsocks`, `naive`) cannot make this statement and
  report `unknown`.
- `engine_clear_route`, and an `engine_set_route` for another route,
  abandon a check in flight instead of waiting for it; the abandoned call
  fails and records nothing about its route. `engine_clear_route` does
  not wait for dials that are still waiting on an unreachable relay.
- An `engine_set_route` that is refused before it starts anything — the
  route is unknown, revoked, expired, cooling down, fails the endpoint
  check, or its configuration cannot be built — changes nothing: a
  connected route stays connected and keeps being re-checked (below), and
  a check in flight for another call is not abandoned. This includes a
  call for the connected route itself while it is `failed` and cooling
  down: it fails, and the route still returns to `ok` by itself when a
  re-check succeeds.
- `engine_export_diagnostics` gains two always-present members:
  `route_check` ∈ `""` (no route), `"verifying"`, `"ok"`, `"degraded"`,
  `"failed"`, and `route_check_category` (the taxonomy category behind
  `failed` / `degraded`, else `""`). A consumer MUST NOT present
  `verifying` as connected. The event stream's `state` values are
  `Verifying`, `Connected`, `Degraded`, `Disconnected`.
- `engine_export_diagnostics` also carries the always-present boolean
  `route_running`: true exactly while an engine instance for a route is
  up. It is true for `verifying`, `ok` and `degraded`, false for `""`,
  and it is what tells the two `failed` apart: `false` after a connect
  that failed (the instance was torn down; the engine retries nothing and
  selects nothing), `true` for a connected route that failed a re-check
  (the instance is up and is re-checked, below). Both leave the posture
  at `Recovery`. A consumer MUST NOT present `failed` with
  `route_running: false` as connecting or retrying; it is a failed
  attempt that needs the user. `route_check` and `route_running` are read
  under one lock and always describe the same moment.
- The `failed` state a failed connect leaves behind ends when the
  cooldown that failure started (the route's, or its family's) has run
  out: from then on `route_check` is `""` and the posture `NoRoute`. The
  route's failure record is not touched. A failed connect that started no
  cooldown (`auth_failed`, `path_too_slow`, `relay_no_egress`, …) stays
  `failed` until the next `engine_set_route` that is not refused. A
  `failed` with `route_running: true` is never ended by time.
- `engine_clear_route` erases only what it stops. When it finds an
  instance running or a check in flight (`verifying`, `ok`, `degraded`,
  or `failed` with `route_running: true`) it stops it and resets
  `route_check`, `route_check_category`, `connect_refused` and the
  posture (`NoRoute`). When it finds nothing running (`route_check` `""`,
  or `failed` with `route_running: false`) it leaves all of them as they
  are: the verdict of the last connect is still true, and a host that
  tears its own plumbing down after a connect that did not come up calls
  `engine_clear_route` as part of that — on Android before the interface
  has read the diagnostics once. It is safe to call any number of times.
- `engine_export_diagnostics` carries the always-present
  `connect_refused` and `connect_refused_route`: why the last
  `engine_set_route` was refused before anything was started, as a closed
  code, and for which route. `""` (it was not), `"needs_new_file"` (a
  RelayPack route with no signed endpoint: it was imported from a file
  made before files carried one, and only a new file fixes it),
  `"cooldown"`, `"revoked"`, `"expired"`, `"family_unsupported"` (an
  `amneziawg` route: refused even when picked, since every attempt is a
  plain WireGuard handshake to a server that drops it), `"other"`. Cleared by the next
  `engine_set_route` that is not refused and by an `engine_clear_route`
  that stops something (above) — however soon after the refusal that
  call comes: a disconnected engine reports no refusal. (Between
  2026-11-19 and the repair pass of the same branch a clear within five
  seconds of the refusal kept it, for a host that tore down after a
  refused switch; no host does, see `engine_route_precheck`.) A refusing
  `engine_route_precheck` records the same two members. It
  exists because a host may have no way to hand the returned error to its
  interface (on Android the call is made by the VPN service, long after
  the command that asked for it has returned). A consumer maps the code
  to its own words and never displays engine text.
- `engine_route_precheck(route_id, out, out_len)` (added 2026-11-19)
  asks whether `engine_set_route(route_id)` would be refused right now,
  and starts and stops nothing. It writes
  `{"route_id":"…","refused":"<code>","active_route":"…"}` to `out`
  (caller-owned buffer, the `engine_export_diagnostics` convention) and
  returns the number of bytes written, or -1 only when the engine is not
  initialised. `refused` is `""` when the route would be attempted, else
  a `connect_refused` code, or `"no_data_plane"` for a build that cannot
  tunnel. A refusal is not an error; it is recorded in the diagnostics
  exactly as a refused `engine_set_route` records it (`no_data_plane`
  is not recorded). The answer can go stale, so `engine_set_route` still
  checks for itself. It exists for a host that must do something
  irreversible before it can call `engine_set_route` — the Android VPN
  service asks first, so that a switch to a route that would be refused
  touches nothing.
- **Automatic connect** — `engine_connect_auto(out, out_len)` (added
  2026-11-19; `core/abi/connect_auto.go`, `connect_auto_verdict.go`).
  Connects on the first route that carries a round trip, the engine
  choosing; no route id. Blocking, like `engine_set_route`, and it uses
  the TUN fd already set exactly as `engine_set_route` does. It writes

  ```
  {"connected":true|false,"route_id":"r2","family":"websocket-tls",
   "tried":[{"route_id":"r1","family":"vless-reality",
             "result":"carried|not_carrying|start_failed|refused|cancelled|stopped",
             "category":"<failure category or empty>",
             "refined":"","refused":"","why":"ranked","relay":1,
             "raced_with":"","setup_ms":0}],
   "verdict":"<code>","candidates":4,"already_connected":false}
  ```

  and returns the bytes written, or -1 only when the engine is not
  initialised. A pass in which nothing carried is not an error.
  - **Candidates**: every imported route that `engine_set_route` would
    not refuse right now (same function: not revoked, not expired, not
    needing a new file, not cooling down, endpoint guard), minus
    experimental families while that gate is off (`refused:
    "experimental_off"`), bulk-capable routes in `lifeline-strict`
    (`refused: "mode"`), and, gate open or closed, every family the
    path manager never selects (`routestore.IsSelectableFamily` false):
    `refused: "family_unsupported"` for one this build cannot dial
    (amneziawg, tor-bridge, ...), `refused: "manual_only"` for `other`
    or an unknown family (a pasted link to someone else's server,
    connected only when the person picks it). Routes left out are listed after the tried
    ones with `result: "refused"`; nothing is written to
    `connect_refused`. `candidates` counts the routes that could be
    tried.
  - **Order** (`why`): `carried_here` — the route's last outcome on this
    network was a round trip, most recent first; then `ranked` — the
    path manager's ranking for the current mode; then `mode_other` — a
    route the ranking leaves out for the mode alone, tried rather than
    not at all; then `failed_here` — failed on this network in the last
    24 h and has not carried here since. "This network" is the hashed
    id of the last `engine_network_changed`, or one shared bucket when
    the host has reported none. The memory is `route_memory` in the
    per-network snapshot (`specs/network-memory-v1.md`): hour buckets, a
    counter for exact order, a category; written on a connect outcome
    and on a change in the liveness of the connected route, never on a
    read.
  - **One at a time.** Each candidate is started and checked exactly as
    `engine_set_route` does it, with one difference in the check's
    budget: a relay whose address never answered is not asked a second
    time (the second attempt differs only in the far-side target).
    Worst case per dead candidate with the default configuration: 4 s
    (address silent), 8 s (first flight swallowed), 12 s (relay answers,
    carries nothing); a path seen moving can still take the slow budget.
  - **What a failed candidate is charged with** (revised 2026-11-19
    after review). Each failed candidate cools its own route down as a
    failed connect does, but does NOT feed the family's
    three-failures-in-an-hour count (a pass walks every route the
    person holds; counting it tripped every family at once and then
    climbed the 5 min … 24 h ladder for as long as an outage lasted).
    Its durable failure row and this network's memory of it are written
    when the pass ends — unless NOTHING AT ALL ANSWERED: no route
    carried and every failure was silence (`tcp_connect_timeout`,
    `udp_no_reply`, `dns_timeout`, `network_offline`). Such a pass saw
    a device with no usable network, not broken routes: the cooldowns
    are lifted again, nothing durable is written, and the next
    `engine_connect_auto` (or `engine_set_route`) may try every route
    at once. If the route a fall-over pass was moving away from had
    gone silent too, its cooldown is lifted with the rest.
  - **Already connected**: nothing is started; `already_connected: true`
    and the running route — and the engine TAKES CHARGE of that route
    (`auto.mode` true, `auto.state` "connected"), also when it was
    picked by hand. A route with a check in flight is replaced. If the
    call arrives while an engine-started pass is moving away from a
    route, it takes that pass over and inherits the route it was moving
    away from (put back if nothing carries).
  - **A route store that cannot be listed** is `verdict:
    "store_unreadable"`, never `no_routes`; nothing is started.
  - **Cancel**: `engine_clear_route`, an `engine_set_route` that gets
    past its refusals, or a newer `engine_connect_auto` abandons the
    pass, a check in flight included; the abandoned call returns
    `verdict: "cancelled"` with the last entry `result: "cancelled"`
    and records nothing about that route.
  - **`verdict`** (closed; a consumer shows its generic line for a code
    it does not know): `""` connected on the first route tried;
    `moved_on`; `no_routes`; `all_need_new_file`;
    `all_expired_or_revoked`; `all_cooling_down`; `network_down` (every
    route tried was told by the device that there is no network — the
    engine has no reachability probe, so silence alone is never called
    this); `relay_unreachable` (every TCP connect to the server's
    address unanswered, UDP routes to it silent — the address is dead or
    blocked, or the network has no way out, which silence cannot be told
    from); `udp_blocked_here` (every UDP route silent while a TCP route
    to the same address was answered); `name_blocked` / `address_blocked`
    (two different names to the same address AND port: one got through /
    both stopped at the same point); `all_failed`; and four beyond the
    first design: `none_usable`, `cancelled`, `no_data_plane`,
    `store_unreadable`; and `looking_for_address` (added 2026-11-20:
    nothing else carried and the engine has paused the dead route for
    one direct walk of its pack's freshness mirrors — see "Recovery for
    a route that is connected and carries nothing" below; `state` is
    `trying` while it says this, and the pass's own verdict comes back
    when the walk finds nothing). `udp_blocked_here` keeps the contract's name
    and says more than is proved: the two observations show that THIS
    route's UDP port was silent while the server's address was alive —
    a network dropping UDP, a stopped UDP service on the relay and a
    provider firewall on that port are indistinguishable. A consumer
    must not word it as "this network blocks UDP".
  - **`refined`** on a tried route is what a second route of the same
    pass adds to its `category` (which is never rewritten):
    `udp_blocked_here` (its UDP was silent and a TCP route to the same
    address was answered or carried), `relay_unreachable` (its UDP was
    silent and a TCP connect to the same address went unanswered),
    `name_blocked`, `address_blocked`, or `""`. `relay` numbers the
    server addresses of the pass (same number = same address; the
    address is never reported).
  - **Staying in charge** (`auto.mode`): true from a pass that starts
    anything until an explicit `engine_clear_route` or an
    `engine_set_route` that gets past its refusals. While it is true and
    the connected route fails a liveness check (the engine's own timer:
    `liveness_interval_s` ±25 %, `recheck_interval_s` while failed, and
    at once on `engine_network_changed` to a different network), the
    engine tries the other candidates by itself; the host does not
    replace the TUN. Precisely: one failed check does not move it —
    the route is checked again after 5 s (never later than
    `recheck_interval_s`), and a SECOND failure in a row starts the
    pass. It does not move at all for `path_too_slow`,
    `relay_no_egress` or `network_offline` (the instance may still be
    carrying, or no route would fare better); a route that fails with
    one of those and later gets no answer at all is recorded as a new
    failure and is then moved away from. If none carries, the instance
    of the route that was connected is put back unchecked
    (`route_check: "failed"`, `route_running: true`) and re-checked as
    before; the next pass the engine starts BY ITSELF in the same
    outage waits 5, 10, 20, 40, then 60 minutes (reset when a route
    carries again or the automatic connect is stopped). An explicit
    `engine_connect_auto` is not held to that wait.
  - **Tunnelled refresh follows the engine.** Every instance has its
    own inlet, so after any instance the engine starts — a candidate
    that carries, the instance put back after a pass, the way back from
    a failed switch — it re-points `engine_set_tunnel_refresh` itself
    when the host's last call was `enabled=1`. A host need not (and on
    a same-route restart cannot) notice.
  - **`engine_shutdown` during a pass** ends it: no further candidate
    is started (`verdict: "cancelled"`), and it returns only when every
    side instance (below) is closed.
  - **Two at a time, where the driver can** (added 2026-11-19;
    `core/abi/connect_race.go`, `core/engine/side_singbox.go`). The
    "one at a time" rule above is what a pass falls back to. Where the
    route can be proved in a SIDE instance — a second, short-lived
    sing-box built from the route's own config with every inbound
    removed: no TUN, no refresh inlet, sockets protected through the
    same registered protect callback, closed before the probe returns —
    the pass checks the next TWO candidates beside each other and starts
    the tunnel's instance on the first that proves (the same attempt as
    above, so the winner is proved a second time through the tunnel:
    that second round trip is the cost).
    - Side-probeable: outbound types `vless`, `vmess`, `trojan`,
      `shadowsocks`, `anytls`, `hysteria`, `hysteria2`, `tuic`, `http`,
      `socks`, not detoured — the families vless-reality,
      websocket-tls, hysteria2, tuic, shadowsocks, anytls. Never:
      naive (process-wide Cronet), tor, wireguard / amneziawg
      (endpoints), anything else. Those are tried alone, in order.
    - Never more than 2 probes in flight. Never two probes to the same
      relay address AND port number. Preferred partner: the other
      transport kind (stream / datagram), then another port; a route
      that failed here recently is not pulled ahead of one that did not.
      The second probe starts 150–450 ms (uniform) after the first.
    - The route whose last outcome on this network was a round trip
      (`why: "carried_here"`, grade not `failing`) is tried ALONE first.
      The last candidate left is tried alone.
    - At most 12 side probes per network per hour (in memory); a route
      side-probed in the last 3 minutes is not side-probed again. When
      either limit is hit the pass continues one at a time.
    - On a network the host reports as metered
      (`engine_network_facts`) a pass the ENGINE starts (fall-over) does
      not side-probe; a pass the person asked for may.
    - A probe stopped because the other proved first is reported as
      `result: "stopped"` — a NEW value of `result` — and records
      nothing. A side probe that failed is charged exactly as a failed
      candidate (route cooldown, never the family's three-in-an-hour
      count, settled with the pass). A fall-over pass leaves the
      instance of the route it is moving away from running until
      something else has proved.
    - `tried[]` entries gain `"raced_with":"<route id or empty>"` and
      `"setup_ms":<int>` (this attempt's time from starting the route to
      its first round trip; 0 for a route that did not carry). The
      `auto` block gains `"racing":["r1","r4"]` while two are in flight
      (`[]` otherwise); `trying` is the first of the pair.
  - **Measurement** (added 2026-11-19; `core/netmem/measure.go`). Per
    (network, route), inside `route_memory`: `setup_ms` (smoothed: each
    sample moves it three tenths of the way; rounded to 10 ms),
    `samples`, `carried`, `failed`, and the hour buckets already kept.
    Fed by every connect outcome (automatic, by hand, a side probe that
    ran to its end) and by the liveness check when its result CHANGES or
    is slow — never by a read. `engine_route_summary` and every row of
    `engine_available_routes` carry, for the network the device is on,
    `"measured":{"grade":"unknown|good|ok|slow|failing","setup_ms":N,
    "samples":N,"carried":N,"failed":N,"last":<unix s of the hour, 0 =
    never>}` — always an object. Grade: `unknown` nothing recorded;
    `failing` two failures in a row since it last carried, or failed
    and never carried here; `slow` two slow checks in a row, or two
    setup samples in a row over 4000 ms; `ok` two in a row within
    1501–4000 ms (or carried and never timed); `good` two in a row at or
    under 1500 ms. One sample never moves a settled grade (the first
    sample ever sets it); the one exception is that a route that
    carries stops being `failing` at once.
  - **Moving for speed** (added 2026-11-19; `core/abi/connect_speed.go`).
    Automatic mode only. When the connected route's check is `degraded`
    twice in a row and this network's memory holds another usable,
    side-probeable route graded `good` / `ok` here or never tried here
    (and not already timed at more than the limit below), that ONE
    route is proved in a side instance. The engine moves to it only if
    it proved, its own proof was not slow, and its setup time is at most
    50 % of the time the running route's last check took; the verdict on
    the connected `auto` block is then `moved_faster`. Otherwise it
    stays. No further speed probe for 15 minutes after one that did not
    lead to a move, and none for 30 minutes after a move. Never on a
    metered network; a candidate that fails is not cooled down.
  - **Network facts from the host** — `engine_network_facts(kind, id,
    validated, metered, out, out_len)` (added 2026-11-19;
    `core/abi/network_facts.go`):

    ```c
    int engine_network_facts(const char* kind, const char* id,
                             int validated, int metered,
                             void* out, int out_len);
    ```

    `kind` ∈ {wifi, cellular, ethernet, vpn, other, none} — the
    underlying (non-VPN) default network; `id` an opaque per-network
    string, hashed on entry with the hash `engine_network_changed` uses
    (`netmem.HashID(kind, "host-network", id)`) and never stored, logged
    or returned in clear; `validated` and `metered` 1 / 0 / -1
    (unknown). Writes `{"network_id":"<16hex>","kind":"…","validated":N,
    "metered":N,"changed":bool,"fresh":bool}`; returns the bytes
    written, or -1 for an unknown kind or an engine that is not
    initialised. It never waits for a connection check.
    - The hashed id is the key of the per-network memory. The first
      network of a kind a host names takes over the route memory of the
      old kind-only record (`engine_network_changed("wifi","","")`,
      then the "unset" record), which is then deleted.
    - Another network, a network after `none`, or `validated` becoming
      1 asks for a liveness check at once. `none` asks for nothing.
    - `kind: "none"` or `validated: 0` turns the verdict of a pass in
      which NOTHING AT ALL answered into `network_down`. `validated: 0`
      stops nothing from being tried. `kind: "none"` keeps the engine
      from starting a fall-over pass by itself.
    - `metered: 1` keeps the engine from starting side probes by itself.
    - Once it has been called, `engine_network_changed` is answered
      (`"superseded":true`) and changes nothing.
    - `engine_export_diagnostics` member `network` (always present):
      `{"from_host":bool,"kind":"…","validated":N,"metered":N}`.
  - `engine_export_diagnostics` member `auto` (always present, from
    memory): `{"state":"idle|trying|connected|failed","mode":bool,
    "trying":"r2","index":2,"total":4,"tried":[…],"verdict":"…",
    "route_id":"r2","family":"…"}`. While `state` is `trying`,
    `route_check` moves between `verifying` and `failed` per candidate:
    a consumer shows the pass, not each candidate's failure. A failed
    pass's block survives an `engine_clear_route` that finds nothing
    running, with `mode` false.
  - **Recovery for a route that is connected and carries nothing**
    (added 2026-11-20, blackout plan C0; `core/abi/relaypack_recover.go`,
    `core/refresh/relaypack_recover.go`). When the automatic connect is in
    charge of a route that is failed-but-running and nothing else
    carries — at the end of a fall-over pass, at the end of one with NO
    other candidate (a one-route file, or every other route cooling
    down), or on a later check of the dead route while the pass back-off
    holds — and the lost route's pack names a freshness endpoint whose
    failure-walk limit allows it, the engine: stops the dead instance and
    opens the RECOVERY WINDOW (no route is active, but every ordinary
    fetcher — subscription, revocation, bootstrap, the scheduled
    freshness poll — still sees the tunnel guard as up, because the
    person has not disconnected); walks THAT pack's freshness mirrors
    ONCE, directly from the device's own address (one pack, at most 45 s
    end to end, no pointer recovery on this kind); applies a newer signed
    pack only through the ordinary verified path; then puts the route's
    instance back and closes the window. When a pack was applied, the
    routes of the applied pack are forgiven their cooldowns, the outage's
    pass back-off is reset and the route is checked at once on its new
    endpoint. Not in `lifeline-strict` ("nothing unless I ask": only the
    button below walks there). During the walk `auto.state` is `trying`
    with `verdict: "looking_for_address"` (and `trying: ""`),
    `route_running` false and `active_route` `""`; the host keeps the TUN
    and does nothing. `engine_connect_auto` called during the walk
    returns AT ONCE with `verdict: "looking_for_address"`, `connected`
    false, and puts the automatic connect in charge; it does not wait
    for the walk and does not cut it off. Any stop
    (`engine_clear_route`, `engine_set_route`, a newer pass,
    `engine_shutdown`, any connect that starts an instance) cuts the walk
    off and nothing is put back; Shutdown waits up to 3 s for it to let
    go of the store.
    - Rate limits, per pack, persisted: per network (hashed tag; the
      last four networks kept) at most once per 10 min, doubling per
      walk on that network that found nothing new, capped at 1 h; a
      network not walked yet after 1 min since the last walk anywhere;
      and never more than 4 walks an hour or 12 a day whatever the
      networks. A walk that was cancelled, or that never reached the
      network, does not spend the floor and is not a miss (a cancelled
      one still counts toward the hourly/daily ceiling). A fall-over
      pass on another network (after 1 min there) is not held to the
      pass back-off unless that network had a pass of its own this
      outage whose back-off still holds. Neither unscheduled kind moves
      the scheduled poll's `last_failure_at` / `consecutive_failures`;
      a scheduled poll the guard refuses — or one that would ride the
      tunnel of a running route whose connection check has failed —
      keeps its stamp but does not escalate, dials nothing and does not
      try pointer recovery.
    - The walk's dialer re-checks on every dial whether a route is
      active: if one comes up mid-walk the rest of the walk is refused,
      not sent direct; and any connect cancels the walk before it raises
      the guard, so no connection from the real address stays open
      beside a live tunnel.
    - One attempt per pack at a time: a scheduled poll, a failure walk
      or a press that finds the pack being walked returns at once
      (`skipped_rate_limited`, `retry_after_s` 30), dials nothing and
      stamps nothing.
    - `engine_export_diagnostics` member `relay_recovery` (always
      present, from memory): `{"state":"idle|looking|updated|unchanged|
      unreachable|rejected|tunnel_required|rate_limited|cancelled",
      "trigger":"failure|user|","packs":N,"outcome":"<core/refresh
      outcome code>","bucket":"YYYY-MM-DDTHH:00:00Z|"}`. The refresh
      outcome `cancelled` is new with this kind (an unscheduled walk cut
      off from outside; never recorded as `freshness_unreachable`).
  - **The connect ladder** (added 2026-11-20, revised the same day;
    `core/abi/connect_ladder.go`; blackout plan T2/T5,
    `docs/adaptive-cover-names-plan.md` §1.3–§1.7). Inside the pass, no
    new call. When a TCP route's attempt is stopped AT ITS TLS HELLO, the
    pass tries the SAME route again at once, alone, with its first flight
    changed — a VARIANT: a hello desync preset (the pack's `_desync`
    offer first, then `sni-cut`, `tlsrec-sni`, `chain`; only where the
    outbound can be cut), a cover name from the route's signed
    `_cover_names` list (`specs/relaypack-v1.md`), or both. What it gets
    depends on what stopped the hello:
    - reset or closed at the hello (not measured as the relay's own: a
      stop that came back no sooner than one measured round trip is the
      relay refusing, and gets nothing), category
      `tls_sni_or_cert_block_suspected`, `tcp_reset` /
      `tls_handshake_failed` in the handshake phase, or `refined:
      name_blocked`: up to 2 variants, names included;
    - unanswered after the TCP connect (a timeout — what a default-deny
      address looks like as much as a name): one preset at most, no name;
    - `refined: address_blocked` (two names to the same address and port
      stopped alike), or any other failure: nothing more for the route in
      this pass. When two routes or more were tried and every TCP attempt
      timed out at its hello, the ladder is off for the rest of the pass.
    A fall-over pass whose connected route failed with a hello-shaped
    category tries that route's next variant (or, when a variant was what
    was running, the route as it is) first.
    - Cover names are offered only for a route with a stored signed
      endpoint, from a `trusted` or `tofu` publisher, whose outbound is
      proved by its key (REALITY on with its public key; or a certificate
      key pin with no `insecure`); vless-reality only takes `reality:
      true` entries; class `cdn` entries are not offered by this build;
      none on the shared bucket of a host that has reported no network.
    - Budget: at most 2 variants per route per pass (1 after a hello
      timeout) and at most 3 per pass; each counts against the
      12-per-hour side-probe allowance and none is tried once it is spent
      (a route's remembered first variant is its own attempt, not
      counted); at most 3 distinct cover names per (network, relay
      address) ever — a count kept in the network's snapshot, hashes
      only, which forgetting or re-minting a route does not reset — and
      none new to a relay while two names to it carry a blocked mark
      here. In `lifeline-strict`, and in every pass the engine starts by
      itself, only variants that carried on this network before are
      used. Always sequential.
    - A variant's failure at its hello is the variant's alone: no route
      cooldown, no family cooldown, no failure row, nothing remembered
      against the route (the path manager's attempt is closed without an
      outcome). A connected route whose variant fails a liveness check in
      any OTHER way is charged as a route. A variant that carries after
      the route's own hello was stopped in the same pass drops the route's
      charge, lifts its cooldown, and takes back the family step that
      charge took — unless another route of the family failed in the
      pass. Its outcome is kept per network under its own key
      (`specs/network-memory-v1.md` "Route variants"): only a reset or
      close at the hello marks a variant (a silent failure, a server-side
      stop or a later failure writes nothing; one that carried here
      before needs two in a row); one that cannot start is set aside in
      memory until the engine restarts. One that carried here within 48 h,
      more recently than the plain route, is the route's FIRST attempt
      there next time (and what a reconnect of the route starts while the
      device stays on that network); on another network nothing of it
      applies. When a route's signed endpoint changes, its variants are
      forgotten.
    - `tried[]` entries gain `"variant":"<word>"` (omitted for the route
      as it is): `d:<preset>` (`split1|sni-cut|chain|tlsrec-sni`, or
      `pack-<6 hex>` for a pack offer that is not one preset — the hex a
      digest of the offer), `n:<id>` (the entry's signed id — never the
      name), or both joined by `#`. A NEW `why` value `ladder` marks an
      attempt the ladder added. The result gains `"variant"` for the
      connected route, and the `auto` block gains `"variant"` (`""` for
      the route as it is). Log lines carry the same words only; the
      failure text of a name variant is not published.
- **Look for a new address now** — `engine_relaypack_refresh(relay_pack_id,
  out, out_len)` (added 2026-11-20):

  ```c
  int engine_relaypack_refresh(const char* relay_pack_id, void* out, int out_len);
  ```

  One freshness walk on request, for one pack or (`""`) for every held
  pack that names an endpoint (at most three). With a route that
  carries: through the tunnel dialer, or refused (`tunnel_required`) —
  the guard is unchanged. With nothing running: direct. With a route
  running that carries nothing: the recovery above, with
  `trigger: "user"`. Works in `lifeline-strict`. Per pack at most one
  walk a minute, then 2 min after two presses in a row that found
  nothing new and 5 min after three or more (the count starts again an
  hour after the last press); a press inside it dials and stops
  nothing, and a press the guard refuses or that is cut off does not
  use it. `in_progress` while a walk or an automatic pass is in flight
  (nothing is started). Every walk is registered with the engine: a
  disconnect or a connect cuts it off (`cancelled`). Blocking, bounded
  by the walk (≈ 55 s per pack at worst): call it off the UI thread.
  Writes `{"outcome":"updated|unchanged|unreachable|rejected|
  tunnel_required|rate_limited|no_endpoints|unknown_pack|in_progress|cancelled",
  "retry_after_s":N,"route_paused":bool,"rechecking":bool,
  "packs":[{"relay_pack_id":"…","outcome":"…","kind":"on_demand",
  "applied":bool,"changed":bool,"via_tunnel":bool,"endpoints_tried":N,
  "providers":N,…}]}`; returns the bytes written, or -1 only when the
  engine is not initialised. No URL, host or address is ever returned.
- **Network test** — `engine_field_probe_{start,status,cancel,seal,discard}`
  (added 2026-11-20, `core/abi/fieldprobe.go`; the test is
  `specs/field-probe-v2.md`):

  ```c
  int engine_field_probe_start(const char* opts_json, void* out, int out_len);
  int engine_field_probe_status(void* out, int out_len);
  int engine_field_probe_cancel(const char* reason);
  int engine_field_probe_seal(const char* opts_json, void* out, int out_len);
  int engine_field_probe_discard(void);
  ```

  - `start` returns AT ONCE; the run (≈ 3 min, hard stop 4) goes on in
    the engine. `opts_json`: `{"network_label":"home_internet|mci|
    irancell|rightel|other_mobile|work_or_public|not_said",
    "dns_servers":["<link DNS server>",…],"private_dns":"off|auto|strict|
    unknown","consent_version":1,"vpn_active":bool,"ipv6_global":bool,
    "blocked":bool}` (`blocked`: the host's
    `onBlockedStatusChanged`). `private_dns: "strict"` skips the
    link-resolver questions.
    `dns_servers` are used in memory for the run only (Go cannot ask
    Android's resolver for TXT/HTTPS); on a Linux desktop with none
    given, `/etc/resolv.conf`. Writes `{"started":true,"of":0}` or
    `{"started":false,"refused":"running|connected|vpn_active|
    no_network|local_blocked|consent_required|no_report_key|
    no_test_relay|test_relay_shared|rate_limited"}` (`consent_version` / `retry_after_min` added where
    they apply). -1 only for an engine not initialised or opts that
    are not JSON.
  - `status`: `{"state":"running","step":N,"of":M}`, or the most recent
    kept result `{"state":"done|aborted","net_kind":"wifi|cellular|
    ethernet|other|unknown","report":{…schema v2…},"summary":
    ["netTest.summary.…",…],"complete":bool,"abort_reason":"…"}`, or
    `{"state":"idle","plan":{"steps","max_connections",
    "max_relay_connections","minutes","consent_version",
    "targets_version","names":[…],"public_resolver":"1.1.1.1"}}`
    (`names`: every name the test may resolve or put in a hello, and
    `public_resolver` the one resolver it asks directly — the "what is
    tested" screen). `abort_reason` adds `local_blocked`, `vpn_active`,
    `connected` to v1's set. The idle and done/aborted answers also carry
    `"has_test_relay":bool` (a trusted held route carries a report
    address; the page offers the test only then) and `"publisher_id"`
    (that route's publisher, "" when none).
  - `cancel(reason)`: `""` (the person), `"backgrounded"`,
    `"network_changed"`, `"vpn_active"` (the Android shell's
    NetworkCallback on `TRANSPORT_VPN`), `"connecting"`; the partial
    result is kept. The engine also stops a run by itself when Daal
    connects, another VPN shows in the network facts, or the network
    changes. Returns 1 when a run
    was going, else 0.
  - `seal`: `opts_json` `{"notes":"≤500 chars","transient":bool,
    "out_path":"<dir or file>","net_kind":""}` — the kept result with
    the note, validated, padded to 16 KiB and sealed to the main Test
    route's own `_report_to` (`specs/sealed-report-v1.md`); file mode
    0600, neutral name `net-xxxxxxxx.dat`. `transient: true`: the
    engine writes it in `<state_dir>/fieldprobe-out/` and ignores
    `out_path`; such files are deleted by `discard`, at shutdown, by the
    next process's first network-test call, and after an hour.
    `out_path` (required when not transient) is chosen by the shell,
    never by the page. Writes `{"sealed":true,"path","file_name","bytes"}`
    or `{"sealed":false,"refused":"no_result|notes_too_long|running"}`.
  - `discard`: deletes every kept result and transient file (cancelling a
    run first); returns how many results, or -1.
  - Kept in the route store's encrypted secrets (`fieldprobe/result/
    <kind>`, `fieldprobe/history`), so `engine_panic_wipe` removes them;
    7-day expiry. `engine_shutdown` stops a run (waits up to 5 s).
    Every probe socket goes through the host's protect callback
    (`engine.ProtectFD`); a refusal with no TUN fd and no route is
    ignored (nothing to bypass). Logs: one start and one end line and
    refusal codes, closed words only.
- **A switch that fails goes back** (added 2026-11-19, the end-to-end
  rig's SW-1): `engine_set_route(B)` while route A is carrying, where B
  then carries nothing, still returns the error and records B's failure
  — and the engine starts and checks A again. Diagnostics member
  `switch_back` (always present): `{"failed_route":"B",
  "failed_family":"…","category":"…","restored_route":"A",
  "restored":true|false}`; `failed_route` is `""` when there is nothing
  to report. A host must read `active_route` / `route_running` after a
  failed `engine_set_route` before tearing anything down.
- `engine_export_diagnostics` carries four more always-present members
  (added 2026-11-19):
  - `active_route: string` and `active_route_family: string` — the
    route whose engine instance is running right now (being checked,
    connected, or connected and failing its re-check) and its transport
    family; `""` when nothing is running. Served from engine memory,
    never from the route store. A consumer MUST take the active route
    from here and not from a store-backed call: `engine_diagnostics_explain`
    carries the same `active_route` and fills its `pick` only when the
    store can be read.
  - `store_recovered: boolean` — the route store was found damaged at
    `engine_init`, was set aside on disk under a dated name (never
    deleted) and replaced by an empty one. True from that `engine_init`
    on, across restarts, until routes exist again. A consumer tells the
    person their saved connections were reset and to add their file
    again.
  - `recent_errors: array` — the last engine calls that failed, newest
    last, each `{time, call, text, count}`. In memory only. `text` is an
    error class passed through the log scrubber (no addresses,
    credentials or tokens); it is for a diagnostics export and a details
    area, never a sentence to display.
- While a route is connected the same proof is repeated every
  `liveness_interval_s` (±25 %), and at once when
  `engine_network_changed` reports a different network. A connected route
  that fails it becomes `failed` with a classified category, a cooldown
  and a failure record; its instance is left running (stopping it would
  leave the platform tunnel interface up with nothing behind it), it is
  re-checked every `recheck_interval_s`, and it returns to `ok` when a
  proof succeeds. One outage is one failure record. The engine does not
  select another route (that is the selection stage, which calls the same
  function: `abi.CheckActiveRoute`).

*Engine configuration file.* `<state_dir>/engine-config.json`, optional,
read once by `engine_init`. Absent means every default. A file that does
not parse, carries an unknown member, a negative value or a target that
is not `host:port` fails `engine_init`.

```json
{ "connection_check": {
    "targets": ["www.example.com:443"],
    "attempt_timeout_ms": 4000, "attempts": 2, "slow_after_ms": 2000,
    "slow_budget_ms": 20000,
    "liveness_interval_s": 180, "recheck_interval_s": 30 } }
```

Every member is optional; zero or absent means the default shown (the
default `targets` are the hosts in `engine.DefaultProofTargetSet`,
below). `targets` are TLS endpoints on the far side of the relay; the
target's certificate is deliberately not verified (nothing is
authenticated or sent, and a device with a wrong clock must not be told
its route is dead).

*The default targets.* `www.google.com`, `www.microsoft.com`,
`www.cloudflare.com`, `github.com`, `www.apple.com`, `www.amazon.com`,
all on port 443. The list is held to five rules
(`core/engine/proof.go`; `TestDefaultProofTargets_*`):

1. *What the relay's network already carries.* The connection leaves the
   relay, so the party that sees it is the relay's hosting network and
   whoever watches it. Each target is the front page of a service that
   datacentre machines and phones both open all day — and that the
   relay's own users open through it — so the check is one more TLS
   connection to a name that network sees constantly.
2. *Reachable from a rented server anywhere.* Each is answered from an
   anycast or multi-region edge that accepts TCP and completes TLS for
   any source address. Services that turn datacentre addresses away do it
   in HTTP (a challenge page); the check never gets that far.
3. *TLS only, and nothing after it.* Port 443, a full TLS handshake, a
   `close_notify`, and no byte of application data: no HTTP request, no
   header, no path, nothing that names Daal or the device. The handshake
   is Go's standard one, the same for every Daal client.
4. *No one company can fail a working route.* The attempts of one check
   go to neighbours in the list from a random starting point, and
   neighbours are run by different companies (GitHub is counted as
   Microsoft), so two failures in a row are never one operator's outage
   or one operator's refusal of a datacentre range. The fresh-connection
   attempt takes a third.
5. *Nobody's donated infrastructure.* A volunteer-funded site is not
   ours to use as a beacon. (`www.wikipedia.org` was in the first list
   and was removed for this, and because it is blocked in several
   jurisdictions where servers are rented.)

*Who learns what.* The censor between the device and the relay sees only
the tunnel: the check is inside it. The relay learns that a connected
client opened a connection to a common site — which it learns about all
of that client's traffic. The relay's upstream sees a TLS handshake from
the relay to one of six names, with no request after it, about once per
connect and once every three minutes (±25 %) per connected device, among
that device's own traffic to the same kind of name. The target learns the
relay's address and that something completed a handshake. No party is
shown anything that identifies the device, its user, or Daal by name;
what CAN be learned by a patient observer of the relay's upstream is that
a handshake with no data recurs — which is why the interval is jittered,
the target is random, and the list is configuration: a publisher who
knows their relay's neighbourhood can replace it. A relay that reaches
none of the targets is reported as `relay_no_egress` (above), not as a
failure of the route.

*Not verified.* The list was checked for reachability from one
residential network and reasoned about for datacentres; it has not been
run from a relay in every hosting region. `relay_no_egress` is what a
relay that cannot reach them looks like, and it is not a cooldown.

*Hosts.* Because `engine_set_route` blocks for the check, a host calls it
from a worker thread and treats `engine_clear_route` (safe from any
thread) as its cancel. The Android VPN service makes every engine call on
one dedicated thread and cancels from another
(`DaalVpnService.kt`, "THREADING"); the desktop shell's `connect` command
is async and runs the call on the blocking pool. While the call is in
flight the interface reads `route_check: "verifying"` and says "Checking
the connection…"; a tap in that state, and in `failed` with
`route_running: true`, stops the route.

Regressions: `core/abi/route_check_test.go`, `core/abi/route_check_tw_test.go`
(all), `core/engine/proof_test.go`, `core/engine/proof_singbox_test.go`,
`core/engine/proof_midsession_singbox_test.go` (`-tags singbox`),
`core/diagnostics/observe_test.go`, `core/pathmanager/fsm_test.go`;
`client-ui/src/lib/routeCheck.test.ts`, `connectThreading.test.ts`;
end-to-end rig scenarios `throttle-56k`, `deep-queue`.

## Surface (Phase 1C — 9 additional functions, append-only)

```c
/* Sharing — sender side */
int engine_share_begin(const char* route_ids_csv,
                       int include_lan,
                       const char* static_qr_uri,
                       char* out, int out_len);
int engine_share_end(const char* session_id);

/* Sharing — receiver side */
int engine_share_browse(int timeout_ms, char* out, int out_len);
int engine_share_pull(const char* host, int port,
                      const char* pin, const char* session_id,
                      const char* expected_spki,
                      char* out, int out_len);
int engine_share_pull_url(const char* share_uri,
                          const char* pin, const char* session_id,
                          char* out, int out_len);

/* Animated QR */
int engine_fountain_next_frame(const char* session_id, char* out, int out_len);
int engine_fountain_feed_frame(const char* session_id,
                               const char* frame_b64,
                               char* out, int out_len);

/* URI / clipboard ingest */
int engine_uri_detect(const char* text, char* out, int out_len);
int engine_uri_import(const char* uri, char* out, int out_len);
```

Function order MUST be preserved; new ABI functions added in later
phases will be appended at the end. The Phase 1C functions are documented
in `specs/share-bundle-v1.md`, `specs/lan-share-v1.md`,
`specs/qr-static-v1.md`, `specs/qr-fountain-v1.md`, and
`specs/uri-import-v1.md`.

**Amendment (Wave 4 Step 11) — `engine_share_pull` gained a parameter.**
`expected_spki` is the sender's published `spki=` TXT value; the engine
REFUSES the TLS handshake when it is empty, malformed, or does not match
the presented certificate (see `specs/lan-share-v1.md`). Append-only
applies to the function ORDER, which is unchanged; this is a signature
change, taken deliberately because the alternative was an ABI whose
default spelling connects to an unauthenticated peer. It was safe to make
because the function had no caller in any language at the time: it was
allowlisted out of `tools/check-plumbing.mjs`, never `dlsym`'d, and
absent from the Kotlin/Swift/JNI bridges. Any future host that resolves
this symbol must pass five arguments before the out-buffer pair.

`engine_share_pull_url`'s parameter is renamed `share_uri` (the shape
widened from a bare https URL to also accept `daalshare://lan?...`); its
signature is unchanged. The pin travels inside the URI, so this call has
no unpinned spelling either.

Both now return `-1` on failure. They previously had identical
`if err != nil` and success branches, which wrote an empty body and
returned `0` — making a refused pull indistinguishable from a successful
empty one to every host.

## Surface (Phase 1D — 3 additional functions, append-only)

```c
/* Bootstrap directory + Tier-2 seeds */
int engine_bootstrap_install_seeds(char* out, int out_len);
   /* Idempotent. Imports the embedded Tier-2 seed .sbps if not already
      represented in the route store. Returns:
        {"installed_count": N, "skipped_existing": M}
   */

int engine_bootstrap_refresh(int timeout_ms, char* out, int out_len);
   /* Tries primary pointers in order, then fallback. Verifies pointer-set
      signature against the embedded project root. Each fetch is raw TLS
      + HTTP/1.1 (no net/http inside core). Pin-checks the publisher
      fingerprint of the fetched .sbp against the pointer entry. On
      success, imports the directory bundle (which silent-imports because
      its publisher is a pre-pinned Tier-1 publisher) and demotes any
      existing Tier-2 seeds via UserNote. Returns:
        {"directory_fetched":bool, "pointer_used":"...",
         "expires_at":"...", "routes_added":N, "routes_updated":M,
         "reason":"..."}
   */

int engine_bootstrap_status(char* out, int out_len);
   /* Returns:
        {"have_seeds":bool, "have_directory":bool,
         "directory_expires_at":"...", "directory_age_hours":N,
         "tier2_remaining":N, "next_refresh_recommended":bool}
   */
```

Phase 1D functions are documented in `specs/bootstrap-pointer-v1.md`,
`specs/bootstrap-directory-v1.md`, `specs/bootstrap-tiers-v1.md`, and
`specs/embedded-material-v1.md`.

## Surface (Phase 1.5A — 6 added functions)

```c
/* Subscriptions */
int engine_subscription_add(const char* publisher_fingerprint_hex,
                            const char* url, const char* display_name,
                            char* out, int out_len);
int engine_subscription_refresh(const char* subscription_id, int timeout_ms,
                                char* out, int out_len);
int engine_subscription_remove(const char* subscription_id);

/* Revocation */
int engine_revocation_refresh_all(int timeout_ms, char* out, int out_len);

/* Pointer rotation (V1.5.5) */
int engine_pointer_rotation_status(char* out, int out_len);

/* Diagnostics */
int engine_diagnostics_explain(char* out, int out_len);
```

Subscription URLs are NEVER returned by any of these functions. The
caller passes the URL into `subscription_add` once; thereafter it lives
only in the age-encrypted secret KV under
`subscription-url:<subscription_id>`.

The "list" affordance is exposed via gomobile (`SubscriptionList()`) and
the CLI (`daal-core subscription-list`); it is not a part of the C ABI
surface — every host already iterates a list locally if it needs one.

## Surface (Phase 1.5B — 1 added function)

```c
/* TunnelDialer wiring */
int engine_set_tunnel_socks(const char* host, int port,
                            const char* username, const char* password,
                            char* out, int out_len);
```

## Surface (Phase 1.5C-Polish — 1 added function)

```c
/* Subscription enumeration. Returns the subscriptions snapshot the
   desktop Subscriptions screen renders on mount. The body shape is
   {"subscriptions":[{"subscription_id":"...","publisher_id":"...",
                       "display_name":"...", ... }]}.
   URLs are NEVER returned; the secret KV holds them. */
int engine_subscription_list(char* out, int out_len);
```

## Surface (Phase 2F — 1 added function)

```c
/* In-engine scheduler status. Returns the JSON snapshot documented
   in specs/scheduler-v1.md:
     { "cadence": {...}, "last_tick": "RFC3339", "ticks": N,
       "next_due": [ {"kind":"subscription|revocation|bootstrap|budget-reset",
                       "ref":"...","next_due":"RFC3339"}, ... ] } */
int engine_scheduler_status(char* out, int out_len);
```

## Surface (Phase 2A — 1 added function)

```c
/* Assigns or updates a route's budget tag (a.k.a. scarcity_class).
   Validates against the closed cap map in core/budget; rejection
   writes {"error":"unknown_budget_tag","tag":"..."} and returns -1.
   On success returns
   {"applied":true,"route_id":"...","budget_tag":"...","hourly_cap_bytes":N}.
   N == 0 means unlimited (bulk-capable). See specs/route-budgets-v1.md. */
int engine_set_route_budget(const char* route_id,
                            const char* budget_tag,
                            char* out, int out_len);
```

`engine_export_diagnostics` widens its body additively at 2A: a
`budgets` array is appended that mirrors `core/budget.Engine.Snapshot`.
Pre-2A callers that don't decode the new field continue to work
unchanged; the array is rendered only if the engine has been
instantiated.

**2A-Polish widening (still additive, surface still 36):** each
`budgets[]` row gains three fields — `session_cap_bytes`,
`session_consumed_bytes`, and `modes_allowed` (string array). The
canonical V2.1 cap table (hourly + session + allowed-modes) is
`specs/route-budgets-v1.md`. `engine_init` is the session boundary;
each successful init zeroes the per-session counters by bumping the
in-process session epoch.

**2B widening (still additive, surface still 36):**

- `engine_export_diagnostics` root gains `posture` (string),
  `route_health` (array), and `skipped_families` (array). The
  legacy `state` and `why` fields are unchanged.
- `route_health[]` row shape:
  `{route_id, in_cooldown, cooldown_reason, cooldown_until,
  budget_exhausted}`. `cooldown_reason` is a V0.3 category string
  (per `specs/failure-taxonomy-v1.md`).
- `skipped_families[]` row shape:
  `{family, until, ladder_step, reason?}`. `ladder_step` is the
  1-indexed V2.3 backoff-ladder step (5min/15min/1h/4h/24h).
- `budgets[]` row's `hourly_cap_bytes` and `session_cap_bytes` now
  reflect the *effective* (post-mode-multiplier) cap. Pre-2B
  consumers of these fields read the same shape; the value just
  scales by `ModeFactor(active_mode)`. The `modes_allowed` field
  is mode-independent and unchanged.
- `engine_set_mode` accepts `{lifeline, normal, bulk}` at 2B. The
  2D `lifeline-strict` mode is rejected by the engine until 2D
  widens the validation set.

## Surface (Phase 2C — 1 additional function, surface 36→37)

```c
/* Notifies the engine that the device's active network has
   changed. The (kind, carrier, ssid) tuple is hashed inside the
   engine on entry — the raw strings NEVER cross the FFI back to
   the host, are NEVER persisted unhashed, and are NEVER surfaced
   through any other ABI call. The 8-byte truncated SHA-256 hex
   identifies the network for the persisted snapshot store. See
   specs/network-memory-v1.md for the derivation contract.
   On success returns
     {"network_id":"<16hex>","mode":"<m>","restored_routes":N,
      "fresh":<bool>}
   where `fresh:true` means this hashed ID has never been seen
   before. `kind` ∈ {wifi,cell,eth,unknown}; carrier and ssid may
   be empty. */
int engine_network_changed(const char* kind,
                           const char* carrier,
                           const char* ssid,
                           char* out, int out_len);
```

**2C widening (additive):**

- `engine_export_diagnostics` root gains `current_network_id`
  (string, 16 hex chars). The sentinel value
  `"0000000000000000"` is rendered before any
  `engine_network_changed` call (i.e., immediately after
  `engine_init` and before the host has reported a network).
  The hashed network ID is NOT a secret; the user is entitled to
  see it (the desktop renders an 8-character hex prefix in the
  Home page's `NetworkLine`).
- The legacy fields are unchanged. The 2B `posture`,
  `route_health`, `skipped_families` blocks are unchanged.
- `engine_init` seeds the active network on the sentinel value;
  `engine_shutdown` resets the netmem singleton.
- The 2C `network-roam` soak scenario adds a regression invariant
  (`no_ssid_leak_in_diagnostics`) that asserts neither the raw
  SSID nor the raw carrier passed to any
  `engine_network_changed` action appears anywhere in
  `engine_export_diagnostics`. Required for V0.1 + CC.6.

Semantics:

- Sets the SOCKS5 endpoint that `core/refresh.Refresher.Dialer` (and
  `RevocationRefresher.Dialer`) use for subscription / revocation
  fetches. The endpoint is expected to be a loopback inlet on a local
  sing-box sidecar, but no such constraint is enforced — the function
  accepts any host/port pair.
- Empty `host` clears the override and reverts both refreshers to
  direct dialing.
- Idempotent. Calling it during an in-flight refresh is safe; the next
  fetch picks up the new endpoint.
- Returns `{"applied":true,"endpoint":"host:port"}`.
- The function NEVER accepts or returns a destination URL. It does not
  log username/password.

Spec details: `specs/tunnel-dialer-v1.md`.

## Artifacts

| Build target | How produced | Consumer |
|---|---|---|
| `libbox.aar` (gomobile) | `gomobile bind -target=android -tags gomobile ./abi` | `client-android` |
| `libdaalcore.{so,dll,dylib}` | `go build -buildmode=c-shared -tags cshared ./cmd/libdaalcore` | Tauri desktop (Phase 1.5B) |
| `daal-core` (CLI) | `go build ./cmd/daal-core` | developer testing on Linux/Windows |
| `daal-soak-engine` (test rig) | `go build -tags soak ./cmd/daal-soak-engine` | Phase 1.5C blackout soak driver |

## Soak-build-only surface (NOT counted in the 37-function release ABI)

When the engine library is built with `-tags soak`, **one** additional
function is exposed for use by the Phase 1.5C blackout-soak rig only.
Release builds do NOT compile this symbol.

*(Historical note: this paragraph used to cite a release-build CI step in
`.github/workflows/desktop.yml` asserting a count of 37. That workflow no
longer exists and the count is now 60.
The assertion survives as `EXPECTED_ABI` in `./daal release-check`, which
you must run yourself. See the ABI ledger at the end of this document.)*

```c
/* Soak-tag only — overrides time.Now() inside the engine. */
void engine_set_now_unix(long long unix_seconds);
```

Semantics: stores `unix_seconds` in a process-wide atomic. Every
subsequent ABI call routes time-of-day through `nowUTC()` which
consults that atomic; setting it to zero reverts to real wall-clock.
`engine_shutdown` clears it unconditionally. The function is documented
in `specs/blackout-soak-rig-v1.md`. It is NOT a release-ABI surface
addition — the release ABI count remains at **37**.

## Stability rules

- A function MUST keep its argument count and order.
- A function MAY widen output (e.g., a `stats` response gaining a new field) only if the new field is JSON-additive.
- New functions MUST be appended; never inserted between existing functions.
- The `engine_version` string is the source of truth for clients to know which functions are safe to call.

## Privacy invariants (CC.6)

- No function in this surface initiates an outbound network call to a project-controlled endpoint.
  - **Phase 1D exception:** `engine_bootstrap_refresh` is the first ABI function that DOES open an outbound TCP+TLS connection. The endpoints it may contact are exhaustively enumerated by the embedded, project-root-signed pointer set. There is no telemetry beam, no User-Agent, no cookies, no referrer; only the directory body is read.
- `engine_export_diagnostics` writes a redacted blob locally; the caller is responsible for any user-mediated sharing.
- All times in JSON outputs are hour-bucketed (`YYYY-MM-DDTHH:00:00Z`).
- No function accepts or emits a destination URL, IP, hostname, or port the user is browsing to.
  - The pointer URLs in `bootstrap_refresh` are bootstrap infrastructure URLs only, not user destinations. They are baked into the binary and rotate only with a project-root-signed pointer-set rotation (V1.5.5).

## Phase 3F additions

Release surface 47 → 48. One new symbol, `engine_redistribute_route(route_id, recipient_delegate_fp_hex)`:

- Returns a JSON envelope (success body or closed-enum error envelope).
- Empty body / `identity_unavailable` envelope under `-tags no_delegate_share`.
- Closed enum: `ok` / `policy_refuses` / `cap_exhausted` / `chain_depth_exceeded` / `route_unknown` / `identity_unavailable`.

Diagnostics widen with three always-present fields: `delegate_share_compiled_in` (bool), `delegate_share_counters` (object `{route_id: {shared_with_count, cap}}`), `last_delegate_share_outcome` (string).

Engine version bumps to `daal-core 0.9.0+v3-share`. ABI is append-only; the existing 47 release symbols are unchanged. See `delegate-keys-v1.md`.

---

## ABI ledger — reconciliation pass, 2026-08-17

This section exists because six documents in this repo carried six
different ABI counts and none matched the binary. **This ledger is the
authority.** Regenerate it, do not hand-edit it:

```sh
# release surface (what ships)
nm -D --defined-only build/libdaalcore.so | awk '{print $3}' | grep -c '^engine_'
# source surface (includes soak-only symbols)
grep -rh '^//export engine_' core/ | wc -l
```

**Release surface: 70.  Source surface: 73.** (2026-11-20, later:
`engine_standby_key` added (optional add-ons S7); counting the source
for it found `engine_survey_routes` already there and in neither count,
so the step is 68 / 71 → 70 / 73. Earlier on 2026-11-20: the five
`engine_field_probe_*` added, after `engine_relaypack_refresh` made it
63 / 66 the same day. 62 / 65 on 2026-11-19. It was 58 /
61 on 2026-08-17; `engine_set_tunnel_refresh`, `engine_route_precheck`,
`engine_connect_auto` and `engine_network_facts` were added since, the
first without this ledger being updated. 62 / 65 is counted from the
source: a library built before `engine_network_facts` exports 61.)

### Caveat on `./daal release-check`

`daal:425-427` counts symbols from `$BUILD_DIR/libdaalcore.so`, i.e.
`build/`, **not** from the copy tracked under
`client-shell/tauri/src-tauri/resources/`. On a fresh clone `build/` does
not exist, so the ABI check reports 0 or is skipped. `release-check`'s
ABI number is only meaningful after `./daal build` in the same tree.

### Symbols previously absent from every spec

These twelve were shipping but documented nowhere. Recorded here to
close the gap; all are append-only additions that changed no existing
signature.

| Symbol | Signature | Notes |
|---|---|---|
| `engine_route_summary` | `(const char *route_id, void *out, int out_len) -> int` | JSON body via `copyOut`; -1 on error |
| `engine_available_routes` | `(void *out, int out_len) -> int` | JSON body via `copyOut` |
| `engine_throughput_snapshot` | `(void *out, int out_len) -> int` | JSON body via `copyOut` |
| `engine_panic_wipe` | `(void) -> int` | 0 on success, -1 on error |
| `engine_route_delete` | `(const char *route_id) -> int` | 0 on success, -1 on error |
| `engine_publisher_delete` | `(const char *publisher_id) -> int` | returns routes removed (>= 0), -1 on error |
| `engine_scheduler_tick` | `(void) -> int` | forces one tick at `time.Now().UTC()` |
| `engine_set_tun_fd` | `(int fd, void *out, int out_len) -> int` | Android/desktop data plane |
| `engine_clear_tun_fd` | `(void *out, int out_len) -> int` | idempotent; safe without a prior set |
| `engine_register_protect_callback` | `(uintptr_t cb, void *out, int out_len) -> int` | `cb == 0` clears the binding |

Added after that pass (append-only, no existing signature changed):

| Symbol | Signature | Notes |
|---|---|---|
| `engine_set_tunnel_refresh` | `(int enabled, void *out, int out_len) -> int` | puts the engine's own scheduled fetches on its in-process loopback inlet, or takes them off; -1 when there is no live inlet (before `engine_set_route` has succeeded) — refresh then stays fail-closed, never direct |
| `engine_route_precheck` | `(const char *route_id, void *out, int out_len) -> int` | JSON body via `copyOut`; -1 only when the engine is not initialised; see "Connection check" above |
| `engine_connect_auto` | `(void *out, int out_len) -> int` | JSON body via `copyOut`; -1 only when the engine is not initialised; blocking; see "Automatic connect" above |
| `engine_network_facts` | `(const char *kind, const char *id, int validated, int metered, void *out, int out_len) -> int` | JSON body via `copyOut`; -1 for an unknown kind or an engine that is not initialised; never blocks on a connection check; see "Network facts from the host" above |
| `engine_relaypack_refresh` | `(const char *relay_pack_id, void *out, int out_len) -> int` | JSON body via `copyOut`; -1 only when the engine is not initialised; blocking, bounded by one freshness walk; see "Look for a new address now" above |
| `engine_field_probe_start` | `(const char *opts_json, void *out, int out_len) -> int` | JSON body via `copyOut`; returns at once; refusals are JSON, -1 only for an engine not initialised or bad JSON; see "Network test" above |
| `engine_field_probe_status` | `(void *out, int out_len) -> int` | JSON body via `copyOut`; -1 only when not initialised |
| `engine_field_probe_cancel` | `(const char *reason) -> int` | 1 a run was going, 0 not |
| `engine_field_probe_seal` | `(const char *opts_json, void *out, int out_len) -> int` | JSON body via `copyOut`; writes the sealed file; refusals are JSON |
| `engine_field_probe_discard` | `(void) -> int` | results deleted (>= 0), -1 on error |
| `engine_survey_routes` | `(int start, void *out, int out_len) -> int` | JSON body via `copyOut`; recorded here 2026-11-20, the comment above its export in `core/abi/survey_export.go` is its contract |
| `engine_standby_key` | `(const char *relay_pack_id, const char *key, void *out, int out_len) -> int` | JSON `{"outcome":"accepted\|no_match\|malformed\|no_standby","routes":<n>}` via `copyOut`; `relay_pack_id` `""` = every held file; keeps the 16 key bytes on each route whose sealed `_standby` it opens; never echoes the key or the address; -1 when the engine is not initialised or the store cannot be written. Optional for the desktop core (`Engine::standby_key`). `specs/optional-addons-v1.md` §3.4 |

The TUN triplet was specified only in
`development-phases/45-gap-dataplane-and-delivery.md` and never merged
here; `engine_route_delete` / `engine_publisher_delete` (commit
`05d0e30`) appeared in no spec at all.

### Soak-only symbols — NOT part of the release surface

Guarded by `//go:build cshared && soak`. They exist only in soak-rig
builds and must never be counted toward the 60, nor relied on by any
client.

| Symbol | Signature | File |
|---|---|---|
| `engine_set_now_unix` | `(long long t) -> void` | `core/abi/clock_soak_export.go` |
| `engine_soak_set_wg_memory_kib` | `(long long kib) -> void` | `core/abi/ios_handoff_soak_export.go` |
| `engine_soak_force_wg_handoff` | `(void) -> void` | `core/abi/ios_handoff_soak_export.go` |

### Downstream copies of the count

Every one of these was stale before the 2026-08-17 pass. If the surface
grows again, update the live ones together (the count was 60 in each as
of 2026-11-19; `engine_connect_auto` made it 61 and
`engine_network_facts` 62 the same day, and only
`daal` `EXPECTED_ABI` and this document were updated with them; the last three are dated history and keep the number
they were written with). On 2026-11-20 (70, after `engine_standby_key`) the live
ones were brought up together: `daal` `EXPECTED_ABI`, `specs/frp-track-v1.md`,
`development-phases/README.md`, `docs/build-and-release.md` and the unreleased
section of `CHANGELOG.md`:

- `daal` `EXPECTED_ABI`
- `specs/frp-track-v1.md`
- `development-phases/README.md` (states it as an invariant)
- `docs/build-and-release.md`
- `CHANGELOG.md`
- `development-phases/45-gap-dataplane-and-delivery.md`

### A note on the counts appearing earlier in this document

Statements such as "Release surface 47 → 48" and "the existing 47
release symbols are unchanged" in the Phase 3B / delegate-share section
are **accurate as history** — they describe the surface at that commit —
and have deliberately been left alone. Only the header count at the top
of this document was a live claim, and it has been corrected.
