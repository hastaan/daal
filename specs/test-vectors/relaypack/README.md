# RelayPack Test Vectors (FRP-1 seed + FRP-2 expansion)

Sixteen canonical vectors covering the V1.5 / V1.6 / PostV2 phase
matrix. The first six were seeded at FRP-1; FRP-2 added ten more
covering importer-roundtrip, idempotent re-import, legacy
non-RelayPack passthrough, and explicit RP021 rejection. Each
vector is a pair:

- `<name>.sbp` — the sealed `.sbp` archive (ZIP with
  `manifest.json` + `manifest.sig` + `publisher.pub`). Generated
  by `publisher/cmd/relaypack-fixtures/main.go`. **Tracked in
  git.**
- `<name>.expected.json` — the per-phase expected validator
  outcome (pass/error_code/warnings), consumed by
  `TestCorpusReplay` in `bundle/go/relaypackvalidate/corpus_test.go`.
  **Tracked in git.**

To regenerate the `.sbp` files (e.g. after a schema edit):

```
cd publisher && go run ./cmd/relaypack-fixtures
```

The generator is deterministic: it uses a fixed test publisher key
(seed `sha256("daal-frp-1-fixture-seed")`) and fixed RFC3339
timestamps so the output bytes are stable across runs.

A pretty-printed `<name>.manifest.json` companion is **NOT**
tracked in git but can be emitted on demand for review:

```
cd publisher && go run ./cmd/relaypack-fixtures -emit-manifest-json
```

These companions duplicate data already inside the signed `.sbp`,
trigger spurious secret-scanner alerts on the test publisher key
fingerprint hex, and are not part of the FRP-1 spec contract. To
inspect a sealed bundle without regenerating, `unzip
<name>.sbp` will yield the manifest.

## Vector list

### FRP-1 seeds

| Vector | Purpose | V1.5 | V1.6 | PostV2 |
|--------|---------|------|------|--------|
| `direct-vps-minimal` | Two `direct_vps` `vps-native` candidates. | OK + RP019/RP020 warns | OK + RP019/RP020 | OK + RP019/RP020 |
| `direct-vps-with-sni` | `direct_vps` carrying `public_domain:`, `host:`, `sni:` tags. | OK | OK | OK |
| `cdn-fronted-minimal` | One `cdn_fronted` + one `direct_vps`, minimal cdn:* + origin_* tags. | reject RP004 | OK | OK |
| `cdn-fronted-with-origin` | `cdn_fronted` candidate with full `origin_risk_tags`. | reject RP004 | OK | OK |
| `modifier-rejected` | Candidate with non-empty `modifiers[]`. | reject RP013 | reject RP013 | OK iff kind in allow-list |
| `legacy-flat-tags-rejected` | Candidate with pre-v2.3.4 flat `shared_risk_tags`. | reject RP017 | reject RP017 | reject RP017 |

### FRP-2 expansion

| Vector | Purpose | V1.5 | V1.6 | PostV2 |
|--------|---------|------|------|--------|
| `legacy-non-relaypack` | `.sbp` with no `_relaypack` and no bundle slot. | OK (validator inert) | OK | OK |
| `mixed-relaypack-direct-only` | Three `direct_vps` siblings on one VPS. | OK + RP019 | OK + RP019 | OK + RP019 |
| `mixed-relaypack-direct-and-cdn` | One `cdn_fronted` + two `direct_vps`. | reject RP004 | OK | OK |
| `idempotent-reimport` | Same as `direct-vps-minimal`; importer-side proves re-import yields equal rows. | OK | OK | OK |
| `cdn-fronted-no-cdn-tag-rejected` | `cdn_fronted` candidate missing `cdn:*` tag. | reject RP004 | reject RP005 | reject RP005 |
| `cdn-fronted-no-origin-tag-rejected` | `cdn_fronted` candidate missing `origin_*` tag. | reject RP004 | reject RP006 | reject RP006 |
| `direct-vps-with-cdn-tag-rejected` | `direct_vps` candidate carrying a `cdn:*` tag. | reject RP009 | reject RP009 | reject RP009 |
| `direct-vps-with-origin-tag-rejected` | `direct_vps` candidate carrying an `origin_*` tag. | reject RP010 | reject RP010 | reject RP010 |
| `single-candidate-relaypack-rejected` | One `vps-native` candidate. | reject RP014 | reject RP014 | reject RP014 |
| `bundle-with-freshness-url-v15-rejected` | Non-empty `Manifest.relay_pack.freshness_url` at V1.5. | reject RP021 | OK (FRP-8 lifts) | OK |

## Importer-vs-validator split

The publisher-side **validator** at `bundle/go/relaypackvalidate/`
runs all 16 vectors against all three phases (`PhaseV15`,
`PhaseV16`, `PhasePostV2`) via `TestCorpusReplay`. Outcomes
match `<name>.expected.json`.

The on-device **importer** at `bundle/go/importer/` calls the
same validator with `Phase: PhaseV15` only. A vector that
expects a V1.5 reject (RP004 / RP013 / RP021 / etc.) yields
`VerdictRejected` with `Reason = "relaypack_<code>"`. A vector
that expects V1.5 OK is imported and the nine new
`RouteRow` columns round-trip through the routestore.

See `specs/relaypack-v1.md` for the schema, validator rule list,
and importer-behaviour contract.
