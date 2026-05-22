# Delegate Keys v1 (Phase 3F)

**Status**: locked at Phase 3F. Append-only thereafter.
**Engine version**: `daal-core 0.9.0+v3-share`.
**ABI release symbol**: `engine_redistribute_route` (release surface 47 → 48).
**Build-tag excluder**: `-tags no_delegate_share` flips `delegate_share_compiled_in` to false; the engine returns `{"error":"identity_unavailable"}` for every redistribute call.

## 1 Goals

The 3F surface lets a user one-tap re-share an in-store route with a friend, without:

1. Coining a new key (the existing 1C share identity at `secrets_kv:share/identity:v1` IS the delegate key).
2. Loosening the trust ladder (publisher signature is always preserved verbatim; delegate signatures are only ever appended).
3. Introducing telemetry (Position B preserved; the device-local re-share counter is the only new persistent state and never leaves the device).

## 2 Closed enums (locked at v1)

### 2.1 `redistribution_policy` (per-route)

| Value | Meaning |
|----|----|
| `none` | Re-share refused (default for absent / empty). |
| `delegated_n` | Re-share permitted up to a per-route uint8 cap. |
| `transitive` | Re-share permitted unconditionally at the sender side; chain depth is enforced receiver-side. |

Empty / absent maps to `none` (fail-closed). Unknown values reject with `ErrRedistributionPolicyMalformed` at the bundle parser.

### 2.2 `Outcome` (engine_redistribute_route closed enum)

| Value | When |
|----|----|
| `ok` | Success. The wire envelope is the JSON body. |
| `policy_refuses` | Policy is `none` (or empty / unknown) for the route. |
| `cap_exhausted` | `delegated_n`: device-local counter ≥ publisher cap. |
| `chain_depth_exceeded` | Local chain already at `MaxChainDepth = 5`. |
| `route_unknown` | No such route in the routestore. |
| `identity_unavailable` | 1C share identity unavailable, or `-tags no_delegate_share` build. |

## 3 Wire format

### 3.1 Per-route fields (additive on `routes[]` in SBP-v1)

```jsonc
"routes": [{
  "id": "...",
  "transport_family": "...",
  "redistribution_policy": "none" | "delegated_n" | "transitive",
  "redistribution_cap": 0..255            // present iff policy == "delegated_n"
}]
```

Bundle parser rules:

- `redistribution_cap` MUST be in [1, 255] when `redistribution_policy = delegated_n`.
- `redistribution_cap` MUST be 0 / absent for `none` / `transitive`.
- An empty `redistribution_policy` with a non-zero cap rejects.

### 3.2 `.sbp.share` shape (top-level on Manifest)

A `.sbp.share` is a `.sbp` whose `bundle.type == "delegated_share"`. It MUST carry both:

```jsonc
"redistribution_chain": [
  {
    "delegate_fp_hex":  "...",                  // truncated SHA-256 of delegate_pub
    "delegate_pub":     "<base64-rawstd>",      // ed25519 32-byte pubkey
    "signed_at":        "<RFC3339>",
    "recipient_fp_hex": "...",                  // intended recipient's delegate fp
    "signature":        "<base64-rawstd>"       // ed25519 over canonicalChainState
  }
],
"delegate_caps": [
  {
    "route_id":                       "...",
    "shared_with_count_at_sign_time": 0..255,
    "cap_at_sign_time":               0..255
  }
]
```

A non-`delegated_share` bundle with either field rejects.

### 3.3 `canonicalChainState`

The bytes a hop signs over are:

```
JSON({"orig_sig":"<base64(orig_sig)>","prior_hops":[<prior_hops...>]})
```

`prior_hops` is an empty array (NEVER null) when no prior hops exist. The Go `encoding/json` package canonicalises field order via the struct definition; any deviation is a spec-version bump.

### 3.4 `engine_redistribute_route` envelope

Success body (returned verbatim as bytes by `engine_redistribute_route`):

```jsonc
{
  "type":                  "delegated_share",
  "route_id":              "...",
  "recipient_fp_hex":      "...",
  "redistribution_chain":  [<hops>],
  "delegate_caps":         [<caps>],
  "issued_at":             "<RFC3339>"
}
```

Error envelope:

```jsonc
{ "error": "<closed-enum>", "detail": "<human-readable>" }
```

Empty body or `identity_unavailable` envelope under `-tags no_delegate_share`.

## 4 Persistent state

| Key | Owner | Notes |
|----|----|----|
| `secrets_kv:share/identity:v1` | Phase 1C (reused at 3F) | Ed25519 keypair; the delegate key is a verbatim alias. NO new derivation. |
| `secrets_kv:delegate_share_counter:<route_id>` | Phase 3F | ASCII-decimal uint8. UpsertRoute MUST NOT clobber. |
| `routes.redistribution_policy` (TEXT) | Phase 3F | `<policy>` or `<policy>:<cap>` for `delegated_n`. One ALTER. |

## 5 Diagnostics widening

Three always-present fields:

| Field | Type | Notes |
|----|----|----|
| `delegate_share_compiled_in` | bool | `true` (default) / `false` under `-tags no_delegate_share`. |
| `delegate_share_counters` | object | `{route_id: {shared_with_count, cap}}`. Routes with empty / `none` policy are NOT surfaced. |
| `last_delegate_share_outcome` | string | One of the closed enum values; `""` until first call. |

## 6 Bundle errors (closed list at v1)

- `ErrRedistributionPolicyMalformed`
- `ErrRedistributionCapMalformed`
- `ErrRedistributionChainBroken`
- `ErrRedistributionChainTooDeep`
- `ErrRedistributionCapExceeded`
- `ErrRedistributionPolicyForbids`

## 7 Compile-in flag

The `core/delegate` package ships with two build-tag-conditional twins:

- `delegate.go` (`!no_delegate_share`): full surface; `Compiled = true`.
- `delegate_excluded.go` (`no_delegate_share`): every entry point returns `OutcomeIdentityUnavailable` / `ErrIdentityUnavailable`; `Compiled = false`.

The ABI side mirrors the same pattern with `delegate_compiled.go` / `delegate_compiled_excluded.go` flipping `delegateShareCompiledIn`.

## 8 Trust ladder (unchanged)

The 3F surface does not touch the existing trust ladder. A `.sbp.share` is consumed at import as a `.sbp` whose publisher-key fingerprint is the original publisher's; the chain is an *additional* signature trail that the importer surfaces in the chain-disclosure modal but does not promote to the publisher slot.

## 9 V2 cell-scope read (FRP-11 amendment)

V2 trusted cells (`specs/cell-v1.md`) reuse the 3F closed enums and per-route cap mechanics unchanged. A new V2 cell-scope sub-object on `family_specific_config._relaypack.cell_scope` adds three fields per route: `cell_id`, `cell_join_fp`, `cell_max_depth`. The 3F `redistribution_policy` and `redistribution_cap` STAY at the route level; `cell_max_depth` is bounded by `redistribution_cap` (recipient takes the min when projecting policy). See supplement §12.2.5 + §16.

End — locked at 3F (v1); §9 amendment locked at FRP-11.
