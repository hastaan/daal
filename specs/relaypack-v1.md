
## Status

Locked at FRP-1 (Phase 29 of `phases of development/`). **Bumps
`spec_version` from 2 to 3.**

The RelayPack profile is a constraining schema layered over the
existing `.sbp` format (`specs/sbp-v1.md`), not a separate file
format. A v3 bundle that does not carry RelayPack metadata is a
regular `.sbp`. A v3 bundle that does carry RelayPack metadata adds
two surfaces:

1. A new top-level `Manifest.relay_pack` slot.
2. A per-candidate `_relaypack` sub-object inside the existing
   `RouteManifestEntry.FamilySpecificConfig` opaque-JSON slot.

The schema is lifted verbatim from the diaspora-helper supplement
v2.3.7 §12.2 + §12.2.2 + §12.2.2.bis + §12.2.5. This document is the
on-disk contract; the supplement is the design rationale.

## Purpose

A RelayPack annotates an `.sbp` bundle with the metadata a
recipient needs to:

1. Race a public-risk-tag-diverse shortlist of candidates
   (supplement §13.1, §13.3).
2. Attribute failures to the correct surface and propagate
   cooldowns along **mode-specific** edges (§13.4).
3. Generalise per-network lessons across deployments via the
   `(family × exposure_mode × public_risk_tag_signature)` memory
   key (§13.4 / `network-memory-v1.md`).
4. Surface "why this route" explanations in plain language
   (§14.5 / `diagnostics-explain-v1.md`).

Without the mode-aware split, breadth becomes a liability: the
selector either treats two candidates' failures as two independent
signals when they are really one shared-IP failure
(under-correlation), or falsely demotes Cloudflare-fronted siblings
on an origin-IP failure that TIC never observed (over-correlation).
With it, breadth becomes a moat.

## Schema

### Bundle-level slot — `Manifest.relay_pack`

```jsonc
{
  "spec_version": 3,
  // ... unchanged sbp-v1 manifest fields ...
  "relay_pack": {
    "relay_pack_id":       "rp-moms-extended-family-may-2026-001",  // stable across rotations
    "shared_risk_graph": [
      { "tag": "public_ip:5.75.0.1",  "members": ["r1", "r2"] },
      { "tag": "public_asn:24940",    "members": ["r1", "r2", "r3"] }
    ],
    "cell_scope_default":  null,                                     // V2; nullable at V1.5 (FRP-11)
    "freshness_url":       ""                                        // V1.6 (FRP-8); empty at V1.5
  }
}
```

The slot is `omitempty` — bundles that do not carry RelayPack
metadata simply omit it. Setting `relay_pack` requires
`spec_version: 3`; the verifier rejects mismatched values with
`ErrUnsupportedSpec`.

`shared_risk_graph[].members` MUST reference candidate IDs that
exist in `Manifest.routes[]`. The graph is computed by the Helper
at sign time (supplement §12.3) and the recipient does not
recompute — verification confirms the publisher signed those
specific tag claims.

### Per-candidate sub-object — `_relaypack`

```jsonc
{
  "id": "r1",
  "transport_family": "vless-reality",
  // ... unchanged sbp-v1 RouteManifestEntry fields ...
  "family_specific_config": {
    // family-specific keys (REALITY dest, SNI, etc.) ...
    "_relaypack": {
      "exposure_mode":       "direct_vps",       // direct_vps | cdn_fronted | serverless_external
      "family_class":        "vps-native",       // vps-native | vps-possible | external-ecosystem
      "probing_risk_class":  "low",              // low | moderate | high
      "modifiers":           [],                  // §12.2.2.bis; empty at V1.5/V1.6
      "public_risk_tags":    [ /* what TIC sees */ ],
      "origin_risk_tags":    [ /* what only the operator sees */ ],
      "cell_scope":          null                 // V2 (FRP-11); null at V1.5
    }
  }
}
```

The bundle parser does not understand the inner shape — it carries
`family_specific_config` as a `json.RawMessage`. The shared validator
at `bundle/go/relaypackvalidate/validator.go` parses the
`_relaypack` key out at import time; the selector reads it at
selection time. **Old clients that do not understand the inner
schema still verify the bundle's signature** because the bytes
round-trip cleanly through canonicalisation regardless of whether
the parser understands the inner schema.

### `direct_vps` example

Direct-mode candidates carry the public IP, ASN, provider, DC,
port, and the SNI/cover-SNI string TIC observes — all directly
visible to the censor. The only forbidden tag in `public_risk_tags`
is `cdn:*` (CDN-mode-only). `public_domain:*`, `host:*`, `sni:*`
ARE allowed when the deployment legitimately uses a visible domain
on its own VPS without a CDN. `origin_risk_tags` MUST be empty (in
direct mode the origin IS the public surface).

```jsonc
"_relaypack": {
  "exposure_mode": "direct_vps",
  "family_class":  "vps-native",
  "probing_risk_class": "low",
  "public_risk_tags": [
    "public_ip:5.75.0.1",
    "public_asn:24940",
    "public_provider:hetzner",
    "public_dc:fsn1",
    "public_port:tcp443",
    "sni:www.microsoft.com"
  ],
  "origin_risk_tags": []
}
```

### `cdn_fronted` example

```jsonc
"_relaypack": {
  "exposure_mode": "cdn_fronted",
  "family_class":  "vps-native",
  "probing_risk_class": "low",
  "public_risk_tags": [
    "cdn:cloudflare",
    "public_domain:e.example.com",
    "sni:e.example.com",
    "host:e.example.com",
    "ws_path_fp:sha256:e3b0c4..."
  ],
  "origin_risk_tags": [
    "origin_ip:5.75.0.1",
    "origin_asn:24940",
    "origin_provider:hetzner",
    "origin_dc:fsn1",
    "origin_cert:cloudflare_origin_ca"
  ]
}
```

TIC sees only the `public_risk_tags`. The `origin_risk_tags` exist
for the FRP's own rotation logic and for correctly attributing a
CDN-origin error (522/525/526) to origin repair rather than
censorship recovery (§13.4).

### `modifiers[]` (reserved schema slot, §12.2.2.bis)

`modifiers[]` is a per-candidate optional array of client-side
packet-mutation modifiers the recipient applies before bytes leave
the machine. Distinct from `exposure_mode`: `exposure_mode` is
"what endpoint do I connect to"; `modifiers[]` is "what do I do to
the packets on the way out."

```jsonc
"modifiers": [
  {
    "kind":               "client_desync",
    "platform":           "linux_desktop_only",
    "probing_risk_class": "high"
  }
]
```

Reserved slot at V1.5 and V1.6: the validator rejects any non-empty
array (RP013). The currently reserved kinds are `client_desync` and
(placeholder) `tls_fragment`. **FRP-12 introduces the per-modifier
framework with per-kind feature flags (see "Modifier framework
(FRP-12)" section below).**

## Modifier framework (FRP-12 amendment)

FRP-12 ships the per-modifier validator framework that conditionally
lifts RP013. The framework is opt-in per modifier `kind`; **at FRP-12
ship zero kinds carry a PASS record**, so RP013 still hard-rejects
every non-empty `modifiers[]` array. The first concrete modifier
PASS record lives in a separate post-track phase.

**Catalogue.** Each reserved kind has a per-file spec at
`specs/modifiers/<kind>.md` carrying:

- `kind` — string identifier matching `_relaypack.modifiers[].kind`.
- `pass_record.status` — `PENDING | PASS | REJECTED | DEPRECATED`.
- `min_phase` — earliest validator phase at which the kind is
  accepted (when PASS). Mirrors `relaypackvalidate.Phase` exactly:
  `V1.5 | V1.6 | PostV2`.
- `platforms[]` — allowed platform strings. Permitted values:
  `linux-desktop, windows-desktop, macos-desktop, android, ios`.
- Free-form description, methodology, observed result, reviewer,
  and risk-notes sections.

The locked template lives at `specs/modifiers/_template.md`.

**Build-time registry.** A small Go binary at
`publisher/deploy/modifiers/cmd/genregistry` parses every
`specs/modifiers/<kind>.md` (excluding `_template.md` and
`README.md`) into a Go literal map at
`publisher/deploy/modifiers/registry_gen.go`. The generator refuses
to emit any record whose `validate()` fails (locked invariant 43)
and refuses any PASS-status record unless invoked with the
`--allow-pass` flag, which the FRP-12 release MUST NOT use (locked
invariant 37).

**Validator integration.** The relaypack validator was already
plumbed at FRP-1 with `Phase` enum + `ValidateOpts.AllowedModifierKinds`
map. FRP-12 wires the modifier registry into the deploy-side caller
(`publisher/deploy/relaypack/binder.go`): the binder now populates
`AllowedModifierKinds` from `modifiers.AllowedKindsAt(phase)`, which
returns the set of registered kinds whose `Status == PASS` and whose
`MinPhase` ordinal is ≤ the requested phase ordinal. Validator
package itself is **not modified at FRP-12** — RP013's existing
per-kind allow-list logic does the work.

**Engine importer platform gate.** `core/trust.StoreAdapter.SaveImport`
preflights modifier-bearing routes before persistence by calling
`core/internal/selection/candidate_platform.go` (`RejectByPlatform`).
For each modifier kind it consults a `PolicyFn` on the `StoreAdapter`.
Nil policy is fail-closed, which is the FRP-12 ship state because zero
modifier kinds are PASS. A kind whose policy says `Pass=false` is
rejected with error code `IMP_MODIFIER_PLATFORM` (locked invariant 40);
a kind whose policy says PASS but whose `Platforms` list does not
include the runtime platform is also rejected with the same code. Engine
MUST NOT import `daal/publisher` (asymmetric guard); a later concrete
PASS phase wires the generated modifier policy into the trust-layer
`ModifierPlatformPolicy` view without changing the RelayPack wire schema.

**Carry on the wire.** The schema is **unchanged**: `modifiers[]`
was already a reserved slot at FRP-1; FRP-12 adds no new field. The
`spec_version` stays at 4.

### `cell_scope` (V2 metadata, §12.2.5)

V2 redistribution metadata extending 3F's `redistribution_policy` +
`redistribution_cap`. The 3F fields stay where they are at the
route level; `cell_scope` adds new V2-cell-only metadata. Nil at
V1.5; FRP-11 lifts the validator. The `cell_scope.policy:
transitive` value is rejected at V1.5 (RP016).

```jsonc
"cell_scope": {
  "cell_id":        "moms-extended-family-may-2026",
  "cell_join_fp":   "9f3a...",
  "cell_max_depth": 1
}
```

## V1.6 CDN-fronted profile (FRP-8)

V1.6 adds the `cdn_fronted` exposure mode to the production
acceptance set. RP004 lifts at `Phase: V16`; the validator now
accepts cdn_fronted candidates if and only if they pass the
**§11.7 hardening template** structurally.

### §11.7 hardening template (mandatory at V1.6)

Every `cdn_fronted` candidate in a V1.6-signed RelayPack MUST be
provisioned with:

* Cloudflare Origin CA cert pinned to the origin (15-year default);
* Full Strict TLS verification on the zone;
* Authenticated Origin Pulls enabled, client cert deployed to origin;
* Provider-level firewall locked to Cloudflare edge ranges
  (refresh runs on Helper, never on origin);
* No DNS-only A or AAAA records on the chosen hostname;
* No SMTP / MX / SSH service exposed on the origin IP;
* Public random path → Worker / Page Rule rewrite → stable origin
  path indirection;
* HTTP / HTTPS only — UDP families never `cdn_fronted` (RP007).

### `_cdn_attestation` sub-field (additive, no `spec_version` bump)

The wizard provider records its §11.7 conformance as a signed
attestation blob inside the per-candidate `_relaypack` opaque
container under the reserved key `_cdn_attestation`. This is
additive within the slot already bumped at FRP-1; `spec_version`
does NOT bump at FRP-8.

```jsonc
"_cdn_attestation": {
  "origin_ca_fingerprint": "<hex sha256(cert.pub_pem)>",
  "aop_enabled":           true,
  "firewall_id":           "<provider-firewall-id>",
  "dns_only_present":      false
}
```

The validator's job is structural-attestation conformance
(RP022 / RP023). It does NOT call Cloudflare. **Live-posture
re-verification** is the wizard's "Settings → Routes → Verify
CDN posture" button (`publisher/deploy/cloudflare/posture.go`),
which re-fetches Origin CA fingerprint, AOP flag, firewall rule,
and the proxied-DNS state from Cloudflare and surfaces drift.

### Freshness JSON shape (sub-key-aware) — `daal/freshness-v2`

Per FRP-8 §6: a publisher's freshness document is **either** root-
signed (no active sub-key on the publisher) **or** sub-key-signed
with the FRP-7.5 cert embedded inline (active sub-key exists).
Recipients walk the same `pub → cert → sub` chain they already
walk for `.sbp` bundles.

**This section previously described `daal/freshness-v1` and called
the shape "locked". Wave 3 (Step 8) superseded it, and the change
is not additive: `core/refresh` REFUSES a v1 document with
`ErrFreshnessVersion` rather than reading it on a best-effort
basis (`relaypack.go` `FreshnessKindV1`, test
`TestVerifyFreshnessDocument_V1Refused`). The v1 shape below is
therefore recorded as history, not as an accepted alternative.**

```jsonc
{
  "kind":                  "daal/freshness-v2",
  "relay_pack_id":         "<deterministic from BindAndSign>",
  "supersedes":            ["<pack id this document ALSO governs>", "..."],
  "sequence":              1747219200,
  "current_bundle_sha256": "<hex>",
  "current_signed_url":    "https://<frp-static-host>/<bundle-name>.sbp",
  "last_modified":         "2026-05-14T12:34:56Z",
  "not_after":             "2026-05-17T12:34:56Z",
  "mirrors":               [{"url": "https://..."}, ...],
  "publisher_pub_hex":     "<root publisher pub, hex>",
  "pad":                   "<signed filler; key never omitted>",
  "subkey_cert":           {/* SubkeyCert JSON, omitted iff root-signed */},
  "signature_hex":         "<Ed25519 over canonical JSON above with signature_hex stripped>"
}
```

Every added field is inside the signed body. What each one is for,
because each closes a hole that made the v1 channel either inert or
attackable:

- **`supersedes[]`** — the pack-id rule. `DeriveRelayPackID` hashes
  `public_ip | server_id | region | provider | families`, and rungs
  L3–L6 exist to change exactly those, so a rotation RENAMES the
  pack. A recipient knows only the id stamped on its own route
  rows, so a post-rotation document naming the new id is rejected
  as `ErrFreshnessWrongPack` — every mirror, every device, while
  the publisher's screen reports a successful publish. A document
  satisfies `ExpectRelayPackID` by naming it as `relay_pack_id`
  **or** by listing it here. The id derivation was deliberately NOT
  changed to fix this: that id is already inside every distributed
  manifest and keys the route rows, so re-deriving it would rename
  every pack in the field at once.
  Recipients that apply a superseding pack MUST re-key their
  persisted freshness record onto the applied pack's id; without
  that the new id starts at high-water 0 and opens a one-document
  replay window.
- **`sequence`** — monotonic per pack, persisted by the recipient as
  a high-water mark (`MinSequence`). Rollback protection held only
  in memory protects a process, not a device. A document AT the
  high-water mark is accepted only while it names the bundle
  already installed (`CurrentBundleSHA256`), because the counter's
  granularity lets two same-second documents share a value.
- **`not_after`** — signed expiry, so a captured document cannot
  freeze a recipient indefinitely. Mirror documents are bounded by
  the enclosing bundle's expiry.
- **`mirrors[]`** — the endpoint set to poll on the NEXT cycle, so a
  publisher can retire a burned freshness host without
  re-delivering a pack. A degraded set (single provider, or
  duplicates) is refused rather than partially trusted.
- **`pad`** — signed filler quantising the document's size. The key
  is never `omitempty`: an absent key is itself a signal.

Signing rules + recipient verification chain locked verbatim in
`38-phase-frp-8-v1-6-cdn-fronted.md` §6 — the recipient code
lives at `core/refresh/relaypack.go` and consults
`core/internal/selection/freshness.go` for the pure-policy
"should we attempt a refresh now?" decision (no sockets in
selection). The publisher half is
`publisher/deploy/freshness/document.go`, whose struct this one
mirrors field for field.

### `Manifest.relay_pack.freshness_url` (lifted at V1.6)

The slot is reserved at FRP-1 and held empty at V1.5 by RP021.
At `Phase: V16` the gate inverts: a non-empty FRP-controlled
`https://` URL is allowed and recommended. The freshness URL is
FRP-controlled (NOT a Daal-project hostname); BYO domain is the
production-closure default per §22.2.

### `Manifest.bundle.recipient_fp_hex` (added at FRP-14)

FRP-14 binds each `.sbpx`-wrapped bundle to exactly one recipient
identity. The new manifest field `bundle.recipient_fp_hex` is the
SHA-256 of the recipient's 32-byte X25519 pubkey, hex-encoded
(64 lowercase hex chars).

Rules:

* **V1.5 (legacy):** field is omitted / empty. The validator treats
  empty as "no recipient binding" and skips the cross-check.
* **V1.6+:** the publisher app populates the field with the recipient
  fingerprint at sign time, before age-encryption wraps the bundle.
* **Recipient app `VerifyBundle`:** after age-decryption, recomputes
  `sha256(localIdentity.X25519Pub)` and compares hex-lowercase. A
  mismatch returns `ErrRecipientMismatch` (RP025); a missing field
  on a V1.5 import is permitted for backwards compat with old packs.
  (History: FRP-14 originally wrote RP024 here, colliding with the
  FRP-8 cdn-without-direct-sibling lint warning that already owned
  the number in `relaypackvalidate/codes.go`; renumbered to RP025 on
  2026-08-14 — see `docs/handovers/frp-14-handover.md` §2.5.)
* The field lives in the signed manifest payload, so a publisher
  cannot forge it without the publisher private key. Together with
  the age envelope (`specs/sbpx-envelope-v1.md` §4), this prevents a
  malicious publisher from re-wrapping recipient A's pack to
  recipient B.

| Code | Severity | Rule |
|------|----------|------|
| RP024 | error | `bundle.recipient_fp_hex` is non-empty AND does not match the local recipient identity. |

## Validator rule list (locked at FRP-1)

The validator at `bundle/go/relaypackvalidate/validator.go` enforces
the rules below. `ValidateOpts.Phase` selects the phase gate
(`V1.5` / `V1.6` / `PostV2`); the same validator binary is used
across all three phases — phase progression flips constants, not
validator code.

| Code | Severity | Rule |
|------|----------|------|
| RP001 | error | A candidate carries `_relaypack` but `Manifest.relay_pack` is nil. |
| RP002 | error | `exposure_mode` is not one of `direct_vps | cdn_fronted | serverless_external`, OR the `_relaypack` blob is malformed. |
| RP003 | error | `exposure_mode: serverless_external` is rejected at V1.5 and V1.6 (reserved post-V2). |
| RP004 | error | `exposure_mode: cdn_fronted` is rejected at V1.5. FRP-8 lifts at V1.6. |
| RP005 | error | A `cdn_fronted` candidate must carry ≥1 `cdn:*` tag in `public_risk_tags`. |
| RP006 | error | A `cdn_fronted` candidate must carry ≥1 `origin_*` tag in `origin_risk_tags`. |
| RP007 | error | A `cdn_fronted` candidate's `transport_family` must appear `yes` or `conditional` in supplement §11.1.1's `cdn_fronted` column. UDP-only families (`hysteria2`, `tuic`, `wireguard`, `amneziawg`) are rejected. |
| RP008 | error | A `direct_vps` candidate must carry ≥1 `public_ip:*` tag. |
| RP009 | error | A `direct_vps` candidate must NOT carry any `cdn:*` tag (CDN-mode-only). |
| RP010 | error | A `direct_vps` candidate must NOT carry any `origin_*` tag (in direct mode the origin IS the public surface). |
| RP011 | error | `family_class` is not one of `vps-native | vps-possible | external-ecosystem`. |
| RP012 | error | `probing_risk_class` is not one of `low | moderate | high`. |
| RP013 | error | A non-empty `modifiers[]` is rejected at V1.5 / V1.6. At PostV2, every modifier kind must appear in `ValidateOpts.AllowedModifierKinds`. |
| RP014 | error | The bundle must contain ≥2 `vps-native` candidates. One-candidate RelayPacks defeat the purpose. |
| RP015 | error | `family_class: external-ecosystem` is rejected for any candidate the FRP is self-hosting (these must come from partner-supplied bundles). |
| RP016 | error | A non-empty `cell_scope` is rejected at every pre-V2 phase — V1.5 **and V1.6** (cells require V2 / FRP-11; `cell_scope.policy: transitive` is rejected here). |
| RP017 | error | A legacy flat `shared_risk_tags` array on `RouteManifestEntry` (pre-v2.3.4 schema) is rejected with explicit pointer to v2.3.5 schema. |
| RP018 | error | `relay_pack.shared_risk_graph[].members` must reference candidate IDs that exist in `Manifest.routes[]`. |
| RP021 | error | `relay_pack.freshness_url` is populated at V1.5. The slot is reserved at FRP-1; FRP-8 lifts acceptance at V1.6 — where the blanket rejection is **replaced by a shape check**, not removed: absolute `https://`, a fully-qualified host that is not an IP literal / loopback, no embedded credentials, ≤2048 bytes. |
| RP022 | error | At `Phase: V16`, every `cdn_fronted` candidate's `_cdn_attestation` blob (additive sub-field inside the FRP-1 `_relaypack` opaque container — no `spec_version` bump) must carry `origin_ca_fingerprint`, `aop_enabled: true`, `firewall_id`. Validator does NOT call Cloudflare; live-posture re-verification is the wizard's "Verify CDN posture" job. |
| RP023 | error | `_cdn_attestation.dns_only_present` is `true` (the wizard's deploy-time check found a DNS-only A/AAAA record on the chosen subdomain — §11.7 hard rule). Distinguishes "attestation missing" (RP022) from "attestation present but reports posture failure" (RP023). |
| RP019 | warn  | All RelayPack candidates share every `public_risk_tag` (no diversity at all). UI nudge: add a CDN front, a second VPS, or a different provider. |
| RP020 | warn  | The bundle has no `udp_gated:true` AND no UDP-shaped families. Recipients on UDP-only paths will have no candidate. |
| RP024 | warn  | A `cdn_fronted` candidate without a `direct_vps` sibling in the same RelayPack — UI nudge: "consider adding a direct route as fallback". |

## Lint codebook (warnings, non-blocking)

`LintReport.Warnings` is returned alongside the `error` result. The
import path uses the warnings to surface UI nudges; warnings never
block the bundle import. FRPs may safely choose to ignore them.

| Code | Pointer | Trigger | UI nudge |
|------|---------|---------|----------|
| RP019 | `manifest` | All candidates share every public_risk_tag. | "Your bundle has no public-surface diversity. Consider adding a CDN front (Cloudflare wizard at V1.6), a second VPS, or a different provider." |
| RP020 | `manifest` | No UDP coverage. | "Recipients on UDP-only paths (rare but real) will have no candidate. Consider adding a `hysteria2` or `tuic` candidate." |
| RP024 | `manifest` | At `Phase: V16`, a `cdn_fronted` candidate exists with no `direct_vps` sibling. | "Your CDN front has no direct fallback. If Cloudflare itself is filtered, recipients have no path. Consider adding a `direct_vps` candidate alongside." |

## Tag vocabulary (open extension model)

Tags are arbitrary `category:value` strings that compare for
equality. Adding a new dimension is a vocabulary extension, not a
schema migration. The validator does not enforce a closed list of
categories; it only enforces presence/absence of certain prefixes
in mode-specific positions (per RP005..RP010).

Reserved categories at FRP-1:

**Public-surface (visible to TIC):**
- `public_ip:` — IPv4 / IPv6 of the publicly-resolved endpoint
- `public_asn:` — ASN of the public IP
- `public_provider:` — provider name (`hetzner`, `vultr`, `stark`, ...)
- `public_dc:` — provider datacentre code
- `public_port:` — `tcp443` / `udp443` / etc.
- `public_domain:` — visible domain (CDN-fronted or direct-with-domain)
- `host:` — `Host:` header value (CDN-fronted; usually equals public_domain)
- `sni:` — TLS ClientHello SNI (cover-SNI for REALITY; visible domain otherwise)
- `cdn:` — CDN identifier (`cloudflare`, `fastly`, `cloudfront`, ...). **CDN-mode only.**
- `ws_path_fp:` — sha256 fingerprint of WebSocket path (visible random path)

**Origin-only (only meaningful for `cdn_fronted`):**
- `origin_ip:` — origin's IP (TIC never sees this under §11.7 hardening)
- `origin_asn:` — origin's ASN
- `origin_provider:` — origin's provider
- `origin_dc:` — origin's datacentre
- `origin_cert:` — origin certificate issuer (e.g. `cloudflare_origin_ca`)

**Application/profile (orthogonal):**
- `udp_gated:` — `true` / `false` (also expressible as `RouteManifestEntry.UDPGated`)
- Future: `bgp_community:`, `domain_suffix:`, `ip_reputation:`...

The validator does not enforce a category allow-list — adding
`bgp_community:8075` to a candidate's `public_risk_tags` is
schema-valid as soon as the FRP signs the bundle. The selector
silently ignores unknown categories at selection time and the
diversity computation simply treats them as opaque `category:value`
strings.

## Compatibility contract

### Old clients (pre-FRP-1, `spec_version <= 2`)

A bundle carrying `Manifest.relay_pack != nil` is rejected at
signature verification because the new top-level slot is part of
the canonical signed payload. This is the intentional
update-required failure mode, identical to the 1.5A v1→v2
transition.

A `_relaypack` sub-object inside `FamilySpecificConfig` is invisible
to old parsers because `FamilySpecificConfig` is `json.RawMessage`
— the bytes round-trip through canonicalisation cleanly. So a v2
bundle that somehow accidentally carried `_relaypack` would still
verify, but the older client would fall back to plain-`.sbp`
selection without RelayPack-aware shortlisting.

### Newer clients (post-FRP-1, `spec_version >= 3`)

A v3 bundle without RelayPack metadata (no `Manifest.relay_pack`,
no `_relaypack` in any candidate) is a regular `.sbp` and verifies
cleanly. The validator is inert (returns empty `LintReport, nil
error`).

A v3 bundle with `_relaypack` on at least one candidate but no
`Manifest.relay_pack` is rejected with RP001.

A v2 bundle (`spec_version: 2`) with non-nil `Manifest.relay_pack`
is rejected with `ErrUnsupportedSpec` (defence-in-depth — producers
should set v3 when sealing RelayPack-bearing bundles).

### Forward compatibility

The schema is **additive only**:
- `Modifier` kinds added by FRP-12 land via the
  `AllowedModifierKinds` allow-list at PostV2; no `spec_version`
  bump.
- `CellScope` policy field added by FRP-11 lands as a new field on
  the existing struct; no `spec_version` bump.
- `freshness_url` is already part of the struct at FRP-1 but must be
  empty at V1.5 (`RP021` rejects non-empty values); FRP-8 lifts the
  validator to accept non-empty values; no `spec_version` bump.

The next `spec_version` bump after FRP-1 is **FRP-7.5** (sub-key
cert chain), which lifts `spec_version` from 3 to 4. FRP-7.5 is
orthogonal to RelayPack: a v4 bundle MAY or MAY NOT carry the
`Manifest.relay_pack` slot, and a RelayPack-bearing bundle MAY
or MAY NOT be sub-key-signed. The RelayPack validator rules in
this document are unchanged at FRP-7.5; the only sub-key-aware
verifier code lives in `bundle/go/bundle/sbp.go::VerifyBundle`
and walks `pub → cert → sub` before manifest verification. See
`specs/sbp-v1.md` §"Phase FRP-7.5 widening" for the locked
sub-key wire shape and the five new sentinel errors.

## Test vectors

`specs/test-vectors/relaypack/` ships 6 canonical seed vectors at
FRP-1. Each is a pair: `<name>.sbp` (the sealed ZIP archive) plus
`<name>.expected.json` (the per-phase validator outcome consumed
by `TestCorpusReplay`). A pretty-printed `<name>.manifest.json`
companion is regenerable on demand (`cd publisher && go run
./cmd/relaypack-fixtures -emit-manifest-json`) but is NOT tracked
in git — it duplicates data already inside the signed `.sbp` and
trips secret scanners on the deterministic test publisher key
fingerprint.

| Vector | Purpose | V1.5 | V1.6 | PostV2 |
|--------|---------|------|------|--------|
| `direct-vps-minimal` | Two `direct_vps` `vps-native` candidates, no diversity. | OK + RP019 + RP020 warnings | OK + RP019 + RP020 | OK + RP019 + RP020 |
| `direct-vps-with-sni` | `direct_vps` carrying `public_domain:`, `host:`, `sni:` tags. | OK | OK | OK |
| `cdn-fronted-minimal` | One `cdn_fronted` + one `direct_vps`, minimal cdn:* + origin_* tags. | reject RP004 | OK | OK |
| `cdn-fronted-with-origin` | `cdn_fronted` candidate with full `origin_risk_tags`. | reject RP004 | OK | OK |
| `modifier-rejected` | Candidate with non-empty `modifiers[]`. | reject RP013 | reject RP013 | OK iff kind in allow-list |
| `legacy-flat-tags-rejected` | Candidate with pre-v2.3.4 flat `shared_risk_tags`. | reject RP017 | reject RP017 | reject RP017 |

FRP-2 expands the corpus to **16 vectors** (10 new), adds
importer-roundtrip cases, idempotent re-import, legacy
non-RelayPack passthrough, and an explicit RP021 rejection
exercise.

## Importer behaviour (FRP-2)

The on-device importer at `bundle/go/importer/importer.go` calls
`bundle/go/relaypackvalidate.Validate(parsed,
ValidateOpts{Phase: PhaseV15})` **once per bundle, unconditionally,
immediately after `bundle.VerifyBundle` and before the first-seen trust
prompt can be shown**. The same helper is called again inside the
persistence path as a defensive guard for direct `AcceptTrustPrompt`
callers. The unconditional call is load-bearing: it catches `RP001` (a
route's `_relaypack` carried without the bundle-level
`Manifest.relay_pack` slot) — the case that would otherwise silently
bypass validation if the importer gated validation on slot presence.

On `*ValidationError`, the importer returns `VerdictRejected` with
`Reason = "relaypack_" + code` so the FRP-6 UI surface can render
the lint code verbatim. No row is written; no secret is persisted.

When the bundle passes validation AND `Manifest.relay_pack != nil`,
the importer per-route calls `bundle.ParseRelayPackEntry` on the
opaque `RouteManifestEntry.FamilySpecificConfig` blob and builds an
`importer.RelayPackMeta` carrying:

- per-candidate fields (`exposure_mode`, `family_class`,
  `probing_risk_class`, `public_risk_tags`, `origin_risk_tags`,
  modifiers as canonical JSON), plus
- bundle-level fields denormalised onto every route
  (`relay_pack_id`, `freshness_url`, `shared_risk_graph` as
  canonical JSON).

The meta flows through `importer.RouteInput.RelayPack` to
`core/trust/state.go::SaveImport`, which copies the nine fields
onto `routestore.RouteRow` and persists them via the existing
`UpsertRoute` path. Legacy non-RelayPack bundles produce
`RouteInput.RelayPack == nil`; the nine new `RouteRow` fields hold
sentinel-empty values (`''` / `'[]'`).

**Idempotence.** Re-importing the same `.sbp` produces equal row
sets — same row count, same column values for every RelayPack
field. `UpsertRoute` is the existing PRIMARY-KEY-conflict-update
path; the FRP-2 columns reuse the same upsert clause.

**Position B (importer never opens a network connection).**
`Manifest.relay_pack.freshness_url` is recorded as a string only;
the importer NEVER fetches it at import time. FRP-8 introduces the
freshness fetch via the existing tunneled-fetch path, gated by
the on-device cadence policy. Verified by
`core/routestore/import_opsec_test.go` (no `net.Dial` /
`http.Client` / `net/http` references in `bundle/go/importer/`,
`core/trust/`, or `core/routestore/` outside `_test.go`).

## Helper-side production (FRP-4a / FRP-4b)

The Helper produces RelayPacks in two phases that the wizard
treats as a single user-visible step.

**FRP-4a: deploy core (Helper machine).** The
`publisher/deploy/` package provisions the VPS, runs the locked
cloud-init template, polls the hardened health endpoint, and
emits an unsigned `*provider.OperatorRecord` — including the
per-candidate `[]CandidateMeta` slice — as JSON. Each
`CandidateMeta` carries the same fields the on-device
`_relaypack` per-candidate sub-object will eventually carry
(`family`, `exposure_mode`, `family_class`, `probing_risk_class`,
`port`, `params`, `public_risk_tags`, `origin_risk_tags`). At
V1.5 every `CandidateMeta` has `exposure_mode = "direct_vps"` and
`origin_risk_tags = []`. **No publisher key is generated and no
RelayPack is signed at FRP-4a.** The CLI surface is the
`daal-deploy` binary; the wizard shells out to it via Tauri.

**FRP-4b: live binder (Helper machine).** The
`publisher/deploy/relaypack/binder.BindAndSign(rec, privKey,
opts)` function — added at FRP-4b, not here — reads the
`OperatorRecord`, computes:

- `relay_pack_id`: SHA-256 over `(provider, server_id, region,
  public_ip, sorted-family-set)` truncated to 16 bytes hex
  (FRP-4b lifted the input from candidate_count to the
  sorted family set so the id is stable across single-candidate
  reorderings yet changes when the operator adds/removes a family).
- `freshness_url`: empty string at V1.5; FRP-8 sets it.
- `shared_risk_graph`: derived from each candidate's
  `public_risk_tags[]` per supplement §12.3.

…then runs `bundle/go/relaypackvalidate.Validate(b,
ValidateOpts{Phase: PhaseV15})` BEFORE signing, signs via the
existing `bundle/go/publisher.Bundle` deterministic builder, and
writes the signed `.sbp` to a staging directory the wizard's
QR-fountain renderer (FRP-6) consumes.

**Determinism boundary.** Same OperatorRecord + same publisher
private key + same `Now` ⇒ byte-identical `.sbp`. The Helper-side
production path is a pure function over locked inputs; the
non-determinism that would prevent this property is fenced in
the cloud-provider call (Hetzner assigns the public IP) — once
the OperatorRecord is committed, every downstream byte is
reproducible.

**Position B at the Helper.** The deploy core opens connections
ONLY to (a) the cloud-provider API (`hetznercloud/hcloud-go/v2`,
plus FRP-10's `govultr/v3` and Stark REST adapters), (b) the
Helper-bound box health endpoint over the IP-bound ufw rule for
the duration of the 60-second provisioning window, and (c) at
FRP-10 only — for V2 deploys — the in-box `daal-relay-mgmt`
service over the cloud-provider firewall during the 5-minute
ephemeral window per L1/L2 rotation. No telemetry, no project
endpoint, no DNS lookup outside the cloud-provider hostname.
Verified by `publisher/deploy/opsec_test.go`.

**FRP-10 amendment — V2 mgmt-plane fields on
`OperatorRecord`.** The Helper-side `OperatorRecord` gains two
optional fields at FRP-10 to support the V2 fast path:

- `MgmtPort` (int) — random port in `[10000, 65000]` chosen at
  provision time. Stamped into the V2 cloud-init template's
  `/etc/daal/mgmt/port`. A zero value marks a V1.5 record (the
  Helper's mgmt client refuses the V2 fast path on such records
  and routes through redeploy).
- `MgmtTLSFingerprint` (string) — lowercase hex SHA-256 of the
  on-box self-signed leaf cert DER. Captured from the
  bootstrap-window relay (`daal-relay-health`) during
  provisioning. Empty on V1.5 records. Pinned per-deploy by the
  Helper-side mgmt client; a TLS handshake whose leaf does not
  match returns `ErrFingerprintMismatch`.

Both fields are additive — they do not appear in the on-the-
wire `.sbp` shape and so do not affect the recipient-side
schema. They are persisted by the desktop wizard via the V007
schema migration (`mgmt_port` + `mgmt_tls_fingerprint`
columns on the `operators` table). The full V2 mgmt-plane
contract lives in `specs/daal-relay-mgmt-v1.md`.

## Cross-references

- `specs/sbp-v1.md` — base bundle format (`.sbp`); FRP-1 widening section.
- `specs/selection-v1.md` — the selector consumer (FRP-3). RelayPack `_relaypack`, `relay_pack_id`, and `shared_risk_graph` flow through `core/internal/selection/` and drive the diversity-shortlist + mode-aware cooldown-propagation rules.
- `daal-roadmap-v3-supplement-diaspora-helper.md` §12.2 — design rationale.
- `phases of development/29-phase-frp-1-relaypack-schema.md` — phase doc with 27 invariants.
- FRP-2 (`30-phase-frp-2-import-store-preservation.md`) — importer + store preservation.
- FRP-3 (`31-phase-frp-3-selection-brain.md`) — selector consumes the schema.
- FRP-4a (`32-phase-frp-4a-publisher-deploy-core.md`) — Helper-side deploy substrate that produces unsigned `OperatorRecord` + `[]CandidateMeta`.
- FRP-4b (`34-phase-frp-4b-direct-deploy-integration.md`) — Helper-side `BindAndSign` that turns the OperatorRecord into a signed `.sbp`.
- FRP-8 (`38-phase-frp-8-v1-6-cdn-fronted.md`) — lifts `cdn_fronted` and non-empty `freshness_url` to V1.6.
- FRP-11 (`41-phase-frp-11-trusted-cells.md`) — lifts `cell_scope`. See §"V2 cell aggregation" below.

## V2 cell aggregation (FRP-11 amendment)

A cell-aggregated `.sbp` reuses this schema verbatim. The bundle-signer key (admin-quorum-delegated per `specs/cell-v1.md`) signs the manifest; `manifest.publisher.key_fingerprint_hex` is the bundle-signer's fingerprint. Inner-publisher provenance flows through the FRP-7.5 sub-key cert chain (`trust/subkey-cert.json`) per route. Two new bundle files (`trust/cell-membership.json`, `trust/cell-delegation.json`) carry the admin-quorum chain; `bundle.VerifyBundle` is UNCHANGED. Spec version stays at 4. See `specs/cell-v1.md` for the full chain walk and admin-quorum rules.
- FRP-12 (`42-phase-frp-12-modifier-framework.md`) — per-modifier framework.
