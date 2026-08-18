# Engine ABI v1

## Status

**Frozen at the end of Phase 1B; extended additively in Phase 1C, 1D,
1.5A, 1.5B, 1.5C-Polish, 2F, 2A, 2C, 2D, 2G, 2E, 3A, and 3B.**
Surface MAY grow (new functions); existing function signatures and
semantics MAY NOT change. Per V0.4 / V1.1, ABI stability is a
contract.

Current surface count: **58 release symbols** (verified 2026-08-17 —
see the ABI ledger at the end of this document, which is the
authoritative count). The source tree carries **61** `//export
engine_*` declarations; the extra three are `//go:build cshared &&
soak` and are never present in a release build.

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

- `psiphon_compiled_in: bool` — `false` when the running binary
  was built with `-tags no_psiphon` (GPLv3 isolation); release
  builds for the unconstrained distribution path report `true`.
- `conjure_compiled_in: bool` — reserved for future build-tag
  conditioning; constant `true` at 3D.
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
longer exists — there is no `.github/` directory — and the count is now 58.
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

**Release surface: 58.  Source surface: 61.**

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

The TUN triplet was specified only in
`development-phases/45-gap-dataplane-and-delivery.md` and never merged
here; `engine_route_delete` / `engine_publisher_delete` (commit
`05d0e30`) appeared in no spec at all.

### Soak-only symbols — NOT part of the release surface

Guarded by `//go:build cshared && soak`. They exist only in soak-rig
builds and must never be counted toward the 58, nor relied on by any
client.

| Symbol | Signature | File |
|---|---|---|
| `engine_set_now_unix` | `(long long t) -> void` | `core/abi/clock_soak_export.go` |
| `engine_soak_set_wg_memory_kib` | `(long long kib) -> void` | `core/abi/ios_handoff_soak_export.go` |
| `engine_soak_force_wg_handoff` | `(void) -> void` | `core/abi/ios_handoff_soak_export.go` |

### Downstream copies of the count

Every one of these was stale before this pass and has been corrected to
58. If the surface grows again, update all of them together:

- `daal:50` `EXPECTED_ABI`
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
