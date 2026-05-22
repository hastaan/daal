# Bootstrap Tiers v1

## Status

Locked at the end of Phase 1D.

## Threat model

A user installs the app on a network where:

- the app store is reachable but slow,
- DNS is partially poisoned (RFC1918 sinkholes for known anti-censorship
  hostnames),
- some TLS hosts are SNI-blocked,
- some endpoints are intermittently allowed during off-peak hours.

The app must connect, with a non-zero probability, on first launch and
every subsequent launch, **without** the user holding a working
subscription. It also must not become a beacon for the user — embedded
material must be disposable at fingerprint level, the fetcher must not
emit telemetry, and emergency capacity must be visibly labeled so the
user does not depend on it.

## The three tiers

| Tier | What it is | Lifecycle | Where it lives |
|---|---|---|---|
| **Tier 1 — Durable** | Project root pubkey + 3..5 publisher pubkeys + signed primary and fallback pointer sets. | Rotated only on a new app release; pointer-set rotation lands in V1.5.5. | `core/bootstrap/embedded` |
| **Tier 2 — Disposable** | 3..8 emergency seed `.sbp`s signed by Tier-1 publishers. `valid_until` ≤ 30d after `created_at`. | Replaced on every app release; demoted to fallback-only the moment a Tier-3 directory is successfully imported. | `core/bootstrap/embedded` |
| **Tier 3 — Refreshable** | A signed directory `.sbp`, fetched at runtime through whichever tunnel is up. | Refreshed at most daily; `bundle.expires_at` ≤ 72h after `created_at`. | Routestore (`source_type = "tier3_directory"`) |

## Boot flow

```
                       ┌──────────────────────┐
                       │ launch              │
                       └─────────┬────────────┘
                                 │
                                 ▼
                       ┌──────────────────────┐
                       │ user routes present? │
                       └────┬───────────┬─────┘
                          yes          no
                            │           │
                  ┌─────────▼──┐   ┌────▼─────────────────┐
                  │ use user   │   │ have valid Tier-3?   │
                  └────────────┘   └────┬───────────┬─────┘
                                       yes          no
                                        │           │
                                ┌───────▼───┐   ┌───▼──────────┐
                                │ use dir   │   │ install Tier-2│
                                └───────────┘   │ seeds + race  │
                                                └───┬───────────┘
                                                    │
                                              ┌─────▼──────────┐
                                              │ refresh Tier-3 │
                                              │ through tunnel │
                                              └────────────────┘
```

## Refresh policy

- Refresh runs opportunistically when a tunnel is up.
- If no tunnel is up, the client tries direct fetches against the primary
  pointers, then fallback pointers, before declaring "all bootstrap
  blocked".
- A successful refresh demotes every Tier-2 seed to fallback-only by
  setting `user_note = "tier2_demoted_at=<bucket>"`. The path manager
  treats demoted seeds as last-resort routes after all directory routes
  have failed.
- A failed refresh is recorded in diagnostics with category
  `subscription_unreachable`; the user is not nagged unless 7 days have
  passed without a successful refresh.

## Emergency-pool labeling (V1.5)

- Any route with `scarcity_class = "emergency"` is rendered with a
  persistent red "Limited capacity" pill in the home screen. The pill is
  **not dismissible** — it disappears when the active route is no longer
  emergency.
- The first-launch screen is the bootstrap-welcome screen, not the
  routes screen, until the user imports a real subscription.

## Real-budget enforcement (deferred)

V1.5 ships data-model + UI labeling only. Per-route `bytes_used_today`
caps (100 MB warn / 200 MB pause/day) land in V2's route-budget engine.
Until then, an emergency route is implicitly capped only by sing-box's
own connection limits and the user's voluntary off-peak behavior.

## V1.7 first-publisher pilot

The placeholder Tier-1 keys baked into Phase 1D are produced by
`daal-publish` against test fixtures. The V1.7 pilot replaces these
with operator-signed keys; the file shape under `core/bootstrap/embedded`
is identical, so the swap is a directory-level operation only.
