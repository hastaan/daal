# Phase 3F — One-Tap Send Working Routes + Delegate-Signed Re-Shares

**Status:** Locked at the start of Phase 3F (post-3E). Ready for
implementation.
**Roadmap line:** V3.6 — "One-tap send working routes."
**Engine version (target):** `daal-core 0.9.0+v3-share`.
**ABI release surface:** **47 → 48** (+1 symbol; append-only invariant
preserved).
**Maturity:** Lands as a UX surface on top of stable 1C share
infrastructure. Not feature-flagged.

## Strategic frame (verbatim from the roadmap)

> "in the Routes screen, a 'Share working routes with a friend'
> affordance that ... turns 'the friend asked me for routes over
> WhatsApp' into a structured, signed, trust-preserving action."

3F is **not** a new transport. It is the structured-handshake UI
that converts an already-working 1C/3E route into a verifiable,
capped, policy-respecting `.sbp.share` artifact for offline
distribution. It builds on the device-local share identity already
shipped at 1C (`secrets_kv:share/identity:v1`); no new key custody
model is introduced.

If a publisher's bundle does not declare a redistribution policy,
the receiver-side default is `none` (locked, fail-closed).

## Locked decisions (12 invariants for 3F)

1. **ABI append-only.** +1 release symbol at 3F; surface 47 → 48.
2. **Delegate key = existing 1C share identity.** Reuse
   `secrets_kv:share/identity:v1` verbatim. **No new derivation,
   no BIP32, no per-recipient sub-keys at 3F.** A V4 follow-up
   MAY introduce per-recipient unlinkability; 3F deliberately
   keeps the surface flat to avoid a key-management overhang.
3. **Three redistribution_policy values, closed enum:** `none`,
   `delegated_n`, `transitive`.
4. **Default policy when absent = `none`.** Fail-closed on the
   receiver side; greyed-out share affordance on the sender side.
5. **Re-share counter custody = local + chain-signed.** The
   sender's local counter is advisory; the *authoritative* hop
   count lives inside the `.sbp.share` `redistribution_chain[]`,
   which any re-importer (and any further re-sharer) walks to
   enforce caps.
6. **Per-route cap is a uint8 (0–255).** `delegated_n` carries
   `n` in the same field. Locked at 3F; no semver waiver to
   widen.
7. **`transitive` chains capped at depth 5.** Hard limit at the
   parser; chains deeper than 5 are rejected per-bundle (soft-
   validation discipline preserved — other routes in the same
   bundle still parse).
8. **Re-share never strips trust.** The original publisher's
   signature is preserved verbatim; the delegate signature is
   *appended*, never replaces.
9. **No new V0 failure categories.** Re-share rejections map
   onto existing `bundle_signature_invalid` (broken chain),
   `publisher_revoked` (cap exceeded surfaces as policy-
   revocation), `bundle_corrupted` (malformed chain), and a new
   cosmetic surface `delegate_cap_exhausted` mapped onto
   `bundle_corrupted`.
10. **Soft-validation discipline preserved.** A `.sbp.share`
    whose chain has one bad hop rejects only that bundle; a
    parent `.sbp` shipping multiple `routes[]` with different
    policies does NOT reject the whole bundle on a single bad
    route.
11. **`UpsertRoute` non-clobber discipline preserved.** Local
    re-share counters live in
    `secrets_kv:delegate_share_counter:<route_id>`, NEVER
    overwritten by bundle re-import.
12. **Trust ladder unchanged.** Delegate signing does not
    promote trust; `tofu_friend` stays `tofu_friend`. The
    receiver's trust prompt (1C) still gates first-time
    imports.

## Sub-task breakdown (10 sub-tasks)

| #  | Task |
|----|------|
| 1  | `core/delegate/` package: chain walker, cap enforcer, `BuildSbpShare`, `VerifyChain`, `EnforceCap`; ~10 unit tests |
| 2  | Bundle parser: `routes[].redistribution_policy` (closed enum), `.sbp.share` shape (`redistribution_chain[]`, `delegate_caps[]`), 6 new errors, ~8 v3f tests |
| 3  | Routestore: 1 ALTER (`redistribution_policy` TEXT) + RouteRow widening + non-clobber test; new `secrets_kv:delegate_share_counter:*` namespace |
| 4  | ABI: 1 new release symbol (`engine_redistribute_route`), 3 new diagnostics fields, version 0.8.0 → 0.9.0; tests + `-tags no_delegate_share` excluder |
| 5  | Publisher CLI: extend `bundle` subcommand with `--redistribution-policy` and `--delegate-cap` flags; tests |
| 6  | Engine: `core/share/export.go` widening — call into `core/delegate/` to enforce policy + chain, sign re-share with existing 1C identity |
| 7  | UI specs (en + fa): "Share with a friend" affordance shape, counter display, greyed-out semantics, chain-disclosure modal copy |
| 8  | Soak: 3 scenarios (`delegate-share-cap`, `delegate-share-policy-respected`, `delegate-share-chain-depth-5`) + dispatch + invariants + v2-superset 23 → 26 |
| 9  | Specs: 1 NEW (`delegate-keys-v1.md`) + 7 AMENDED |
| 10 | Handover doc + final regression sweep (`nm` count = 48, all tag combinations) |

## ABI additions

```c
// Release symbol 48
const char* engine_redistribute_route(
    const char* route_id,
    const char* recipient_delegate_fp_hex
);
//   Builds a .sbp.share for the given route, signed by the
//   device's 1C share identity, addressed to
//   `recipient_delegate_fp_hex` (the recipient's share identity
//   fingerprint, exchanged offline before the share session).
//
//   Returns serialized bundle bytes (base64-encoded JSON envelope)
//   on success, or a JSON error envelope on failure:
//     {"error":"policy_refuses"|"cap_exhausted"|
//              "chain_depth_exceeded"|"route_unknown"|
//              "identity_unavailable", ...}
//
//   Empty string under -tags no_delegate_share. Always succeeds
//   in the sense of not panicking.
```

Diagnostics widen with **3 always-present fields**:

| Field                            | Type   | Default | Notes |
|----------------------------------|--------|---------|-------|
| `delegate_share_compiled_in`     | bool   | `true` (default build); `false` under `-tags no_delegate_share` | mirrors 3D / 3E shape |
| `delegate_share_counters`        | object | `{}`    | `{route_id: {shared_with_count, cap}}`; route_ids are local (never leak) |
| `last_delegate_share_outcome`    | string | `""`    | one of `ok` / `policy_refuses` / `cap_exhausted` / `chain_depth_exceeded` / `""` |

## Bundle-format widening (SBP-v1, additive)

`routes[]` widening (1 new optional field):

```jsonc
"routes": [{
  "id": "...",
  "transport_family": "...",
  "redistribution_policy": "none" | "delegated_n" | "transitive",
  "redistribution_cap": 0..255   // present iff policy == "delegated_n"
}]
```

`.sbp.share` shape (a `.sbp` variant; `bundle.type == "delegated_share"`):

```jsonc
"redistribution_chain": [
  {
    "delegate_fp_hex":  "...",
    "delegate_pub":     "<base64>",
    "signed_at":        "<RFC3339>",
    "recipient_fp_hex": "...",
    "signature":        "<base64-rawstd ed25519>"
  }
],
"delegate_caps": [
  {
    "route_id":                       "...",
    "shared_with_count_at_sign_time": 5,
    "cap_at_sign_time":               10
  }
]
```

**6 new parse errors:**

- `ErrRedistributionPolicyMalformed`
- `ErrRedistributionCapMalformed`
- `ErrRedistributionChainBroken`
- `ErrRedistributionChainTooDeep`
- `ErrRedistributionCapExceeded`
- `ErrRedistributionPolicyForbids`

## Build matrix at 3F exit

- `cd core && go build ./...` — green.
- `cd core && go build -tags no_delegate_share ./abi/...` — green; flag flips false.
- `cd core && go build -tags "no_psiphon no_wasm no_delegate_share" ./abi/...` — green.
- `cd core && go test ./...` — green.
- `cd bundle/go && go build ./... && go test ./...` — green.
- `cd cmd/daal-soak-engine && go build -tags soak ./...` — green.
- `cd test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...` — green.
- `nm libdaalcore.so | grep ' T engine_' | wc -l` = **48**.

## Spec deliverables

**1 NEW:**
- `specs/delegate-keys-v1.md`

**7 AMENDED:**
`specs/sbp-v1.md`, `specs/share-bundle-v1.md`,
`specs/route-object-v1.md`, `specs/engine-abi-v1.md`,
`specs/publisher-cli-v1.md`, `specs/routestore-v1.md`,
`specs/blackout-soak-rig-v1.md`.

## Soak coverage

**`delegate-share-cap`** (~14 days): driver re-shares route 11
times against a `delegated_n` policy with `n=10`; the 11th MUST
refuse (engine returns `cap_exhausted`); diagnostics surfaces
`last_delegate_share_outcome=cap_exhausted`. The local counter
MUST equal the chain's `shared_with_count_at_sign_time` at every
step.

**`delegate-share-policy-respected`** (~14 days): asserts
`none`-policy routes refuse re-share (`policy_refuses` outcome)
AND a `transitive` route validates correctly to depth 5 AND
rejects at depth 6.

**`delegate-share-chain-depth-5`** (~14 days): drives a 5-hop
chain through 5 simulated devices via the soak's existing
in-process import path; asserts the canonical regression
`chain_signature_walk_terminates_in_publisher`.

`--scenarios v2-superset` widens 23 → **26**.

## Out of scope (deferred to V4+ or later)

- BIP32-style per-recipient delegate sub-keys (V4
  unlinkability work; explicitly deferred per locked decision 2).
- Delegate-key revocation (V4).
- Online publisher policy push.
- Cross-device counter sync (V4 mesh).
- Receipt-side device-to-device sync (V4 mesh).
- Lifeline-relay per-session ephemeral keys (3G picks this up).

## Handover to 3G

3G (optional partner-operated lifeline relay, V3.7) receives:

- A stable delegate-signing surface.
- A precedent for **publisher-declared policy fields**.
- ABI release surface 48; append-only invariant intact.
- Engine version `daal-core 0.9.0+v3-share`.

If 3G's preconditions fail, V3 closes at 3F. The non-shipping
outcome is an EXPECTED outcome of the roadmap.
