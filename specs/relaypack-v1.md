
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

### `_report_to` key (additive, no `spec_version` bump)

A route's `family_specific_config` MAY carry `"_report_to": "daal1…"`:
the publisher's network-test report address (`specs/sealed-report-v1.md`,
`daal-deploy report-keygen`). It is signed with the manifest like every
other member; builds that predate it ignore it (no decoder of the
top-level object is strict). Routes that carry it are the **Test relay**
(`specs/field-probe-v2.md`): the engine offers the network test only when
a held route carries a valid address, and seals results only to it. An
invalid address is treated as absent. The validator does not require it
and does not reject it. The binder writes it on every route of the pack
when signed with `bind-and-sign --report-to daal1…`
(`relaypack.BindOpts.ReportTo`; a malformed address refuses to sign).

The Test relay MUST be its own address: no route the family uses every
day (one without `_report_to`) may point at the same server address. The
test sends plain hellos with three different names to that address in
about 20 s, which must never happen to a daily relay; the engine refuses
to start (`test_relay_shared`) when it sees the two share an address.
The report is sealed to the `_report_to` of the route the test proves
(the REALITY/443 route), and the test's alt-port and UDP routes come only
from that route's pack.

### `_cover_names` key (additive, no `spec_version` bump)

A route's `family_specific_config` MAY carry the signed list of OTHER
names its TLS first flight may present
(`docs/adaptive-cover-names-plan.md` §1.3, §1.7; parser
`bundle/go/bundle/cover_names.go`). It is a sibling of `_endpoint`,
`_relaypack` and `_desync` — never inside the endpoint commitment, whose
decoder is strict. Covered by the manifest signature; builds that predate
it ignore it.

```jsonc
"_cover_names": {
  "v": 1,
  "names": [
    {"id": 1, "name": "www.example.com",    "class": "foreign"},
    {"id": 2, "name": "static.example.net", "class": "cdn", "cdn": "fastly"},
    {"id": 4, "name": "mirror.example.org", "class": "mirror", "reality": true}
  ]
}
```

- `id` (required): the entry's stable identity, 1..9999, unique in the
  list. The engine refers to an entry ONLY by its id (memory and every
  report hold the id, never the name or its position). A publisher gives
  each new entry an id that list never used before and NEVER reuses one;
  entries may then be dropped (a name retired fleet-wide) or reordered
  without what a device remembers about one id describing another name.
- `class` ∈ `foreign | cdn | mirror`. `cdn`: which CDN or prefix the name
  lives on, `[a-z0-9-]{1,32}` — required on a `cdn` entry, absent on any
  other. `reality` (optional, default false): the route's relay's
  REALITY inbound answers for this name (it is in the inbound's server
  names). A vless-reality route offers ONLY such entries; websocket-tls
  and anytls (relay proved by its SPKI pin) offer any entry; no other
  family uses the list. This build offers NO `cdn` entry (a CDN-hosted
  name sent to a plain VPS address is the name/prefix mismatch a censor
  checks; that waits for a CDN-fronted family).
- At most 8 entries; names are full LDH DNS names in canonical form —
  lower case, no trailing dot, no spaces (a non-canonical name is
  refused, not normalised) — no address, no duplicates.
- **Refused at parse, the whole list** (fail closed): any domestic name —
  under `.ir` (or `.ایران`), or on the known-domestic list in the parser
  — or the class `domestic`; an unknown member; an unknown class; a bad
  or repeated id; a bad `cdn` word; a version other than 1.
- The engine never resolves a listed name: it is only a string in the
  hello. It offers the list only for a route with a signed `_endpoint`
  from a trusted or TOFU-pinned publisher whose outbound is proved by its
  key.
- **On the device.** The importer keeps the members of
  `family_specific_config` the engine reads at connect time —
  `_desync` and `_cover_names`, an allowlist
  (`bundle.EngineFamilyConfigKeys`) — on the route's row, and only for a
  route with a signed endpoint; `_endpoint` (an address and a key) and
  `_relaypack` are never copied there (the row is not the encrypted half
  of the store). Every import and refresh rewrites it.
- How it is used: `specs/engine-abi-v1.md` "The connect ladder". The
  publisher side that writes the list is not built yet.

### `_standby` key (additive, no `spec_version` bump) — optional add-ons

Reserved 2026-11-20 for the standby-address add-on
(`docs/optional-addons-plan.md` §1, `specs/optional-addons-v1.md` §3).
**Built:** parser, commitment and key functions
`bundle/go/bundle/standby.go` (S1); importer
(`bundle/go/importer/endpoint_plan.go`) and set-route guard
(`core/abi/endpoint_guard.go`) (S2); the signing check RP027
(`relaypackvalidate.ValidateForSigning`); the binder
`publisher/deploy/relaypack/endpoint.go` (S5); the store keeping it
(`core/trust` SaveImport; both secrets go with the route,
`routestore.perRouteSecretKeys`); the engine's address variant and
`engine_standby_key` (S7); a key carried by a `daal-refresh-v2`
container is offered to the same store by the refresh walk
(`abi.StandbyKeySink`). All built 2026-11-20.

**Compatibility.** Every build ignores a member of
`family_specific_config` it does not know: no decoder of that object is
strict, `_endpoint` is read by its own key, and the engine's row keeps
only `bundle.EngineFamilyConfigKeys`. So a phone on a build from before
this member imports a pack that carries it exactly as if it were
absent, the freshness merge included. Tested against a frozen copy of
the rules as they shipped (`bundle/go/importer/compat_old_test.go`,
`internal/oldrules`, frozen from 079ef96).

A route's `family_specific_config` MAY carry `_standby`: a second address
of the same relay, on the same ports with the same keys, that the route
may be dialled at. It is a sibling of `_endpoint` — never inside the
endpoint commitment, whose decoder is strict — and is covered by the
manifest signature. Two shapes:

```jsonc
// sealed (the default): only a commitment to the address
"_standby": { "v": 1, "mode": "sealed", "commit": "<base64, 32 bytes>" }
// open: the address itself
"_standby": { "v": 1, "mode": "open", "server": "203.0.113.20" }
```

- **Shape.** `v` is `1`. `mode` is `sealed` (exactly the members `v`,
  `mode`, `commit`) or `open` (exactly `v`, `mode`, `server`). `commit` is
  standard base64 with padding of 32 bytes. `server` is a canonical
  dotted-quad IPv4 address (no leading zeros) that is not unspecified,
  loopback, private, link-local, multicast or broadcast, and is not
  `_endpoint.server`. Anything else — an unknown member, another
  version, a missing member, a bad length — makes `_standby` malformed,
  and a malformed `_standby` is treated as **absent**: no standby is
  dialled for that route. The import is not refused for it and the
  route's `_endpoint` is unaffected. (`_standby` can only widen what a
  route may dial, so ignoring it is the closed reading; a malformed
  `_endpoint` still refuses the pack.)
- **The commitment.** `commit = SHA-256("daal/standby-v1" ‖ salt ‖ ipv4)`:
  the 15 ASCII bytes of the domain string with no terminator, a 12-byte
  random `salt`, and the 4 address bytes in network order. One relay has
  one standby, so every route of it carries the same `_standby`.
- **The standby key** is `salt ‖ ipv4`, 16 bytes. It needs no signature:
  the signed pack already committed to it, so a forged or mistyped key
  matches no commitment and is refused, and can steer nobody anywhere. It
  is not a secret once used; it is an address.
  - Text form (what a person reads aloud or types): the 128 bits, most
    significant first, followed by two zero bits, as 26 symbols of
    Crockford's base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), shown in
    five groups of 6-5-5-5-5 separated by one space. On input case is
    ignored, spaces and `-` are ignored, `O` reads as `0` and `I` and
    `L` as `1`; any other symbol, a count other than 26, or non-zero
    trailing bits is malformed.
  - DNS form: the 16 bytes as one AAAA record.
  - There is no checksum: the commitment is the check.
  - Test vector (`bundle/go/bundle/standby_test.go`, cross-checked with
    an independent implementation): salt `00 01 02 … 0b`, address
    `203.0.113.20` →
    key text `000G40 R40M3 0E209 185WP 03H2G`;
    commit `oLKATgHpOx6iddfCqnGCuDAi1XSE7ysXDZ1tUmE5HHY=`;
    DNS form `1:203:405:607:809:a0b:cb00:7114`.
    Sixteen `ff` bytes read `ZZZZZZ ZZZZZ ZZZZZ ZZZZZ ZZZZW` (the two
    trailing bits are zero).
  - A key whose address is not a public IPv4 address (the rules for
    `server` above) is never acted on, even when it matches.
- **Families.** Never on `shadowsocks` (no server authentication that is
  independent of the shared key, so a stale standby could hand a
  stranger the traffic): the binder does not write it there, and a
  `_standby` on a shadowsocks route is ignored. For every other family a
  stale standby fails closed — the handshake is to the committed key.
- **The endpoint rule, amended.** Where "Endpoint commitment" below
  requires an outbound's `server` to equal `_endpoint.server`, it may
  instead equal the open `_standby.server`, or the address inside a held
  standby key that matches `_standby.commit`. Nothing else moves: port,
  `server_name`, TLS pin, REALITY public key, shadowsocks method and
  digest are checked exactly as before, and the stored profile itself
  keeps the committed address (the standby is a dial-time variant,
  `specs/optional-addons-v1.md` §3.3).
- **Import.** The importer hands the store the `_standby` of every
  route that may use one, exactly as signed (`importer.RouteInput.Standby`;
  nil when absent, malformed, on shadowsocks, or on a route without a
  direct `_endpoint`). An outbound in a file may sit at the open standby
  address; a sealed standby needs a key, and none is held at import, so
  there the outbound must be at `_endpoint.server`. Publishers mint at
  `_endpoint.server` (older builds require it).
- **On the device.** Not in `bundle.EngineFamilyConfigKeys`: open mode
  holds an address, and the route row is not the encrypted half of the
  store. The engine keeps it beside the route's commitment, as signed,
  under `standby:<route_id>` (`bundle.StandbyStoreKey`), with an accepted
  key as its 16 raw bytes under `standby-key:<route_id>`
  (`bundle.StandbyKeyStoreKey`); every import and refresh rewrites the
  first, a newer commitment without `_standby` removes both, and a key
  that no longer matches the held commitment is never used (the guard
  checks the match at every connect). The set-route guard
  (`routeEndpointGuard`) accepts an outbound at the committed server,
  the open standby, or the address of a held key that matches.
- **Signing.** RP027 (signing only): a malformed `_standby`, one on
  shadowsocks or on a route without a direct `_endpoint`, an open one
  equal to the endpoint's server, or routes of one relay address that
  do not all carry the same one (shadowsocks excepted).
- **Where a key comes from.** A key the person types
  (`engine_standby_key`, `specs/optional-addons-v1.md` §3.4), the
  `standby_key` member of a `daal-refresh-v2` container (below), or a
  file. When the publisher switches to the standby, the next signed pack
  names it as `_endpoint.server` and needs no key at all.
- **Publisher rules.** Sealed is the default; open is offered only while
  no Everyone file exists for the relay (owner decision D-1). Removing a
  standby signs and publishes a pack without `_standby` **before** the
  address is released, so no current commitment names an address that
  may be handed to someone else.

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

### Mirror provider `appsscript` — optional add-ons

Reserved 2026-11-20 for the Google update-channel add-on
(`docs/optional-addons-plan.md` §3, `specs/optional-addons-v1.md` §5).
**Built 2026-11-20:** publisher backend G1/G2
(`publisher/deploy/freshness/backends/appsscript/`, one more backend of
`publish-freshness`), the recipient's front fetcher G4
(`core/bootstrap/{front.go,h2mini.go,hpack_tables.go}`: Chrome-shaped
uTLS hello, HTTP/2 framed by hand with no `net/http`, the one allowed
redirect, the bounded read) and its walk G5 (`core/refresh/frontmirror.go`:
which endpoints are Google mirrors, the container, the D-3 rule in
`refresh.ValidateMirrorSet`). Details the built walk fixes:

- An `appsscript` mirror is walked only by the two unscheduled walks
  (the engine's failure walk and the person's button), only when the
  walk dials direct (the C0 walk with the tunnel down), and **last**,
  after the ordinary mirrors in their random order. The scheduled poll
  and anything riding the tunnel skip it.
- The random delay before the first connection is bounded by what is
  left of the walk's own budget, not by the full 120 s (accepted by the
  lead, 2026-11-20).
- A standby key in the container is offered to the engine's store after
  the document (and the pack, if any) was applied; a walk whose key was
  kept counts as one that found a new address.

- **One script per Google account, one slot per relay** (amended
  2026-11-22, protocol `daal-refresh-v2`). The publisher adds one script
  to a Google account (Accounts → Google) and every relay that turns the
  channel on gets a *slot* in it: 8 random bytes, 11 base64url
  characters. The slot's read token is derived, never stored:
  `k = base64url(HMAC-SHA256(write_key, "daal-read-v2" ‖ 0x0A ‖ slot)[0:16])`,
  22 characters, so only the holder of the account's write key can make
  one and one relay's pack says nothing of another relay's slot. The
  connect check uses the reserved slot `connectTest`, which no relay is
  given. The single-relay shape of the first build (`?k=<token>` alone,
  `daal-refresh-v1`) was never deployed and is no longer accepted
  anywhere.
- **The entry.** One member of the signed mirror set
  (`trust/freshness-mirrors.json`, `daal/freshness-mirrors-v1`):
  `{"provider": "appsscript", "url": "https://script.google.com/macros/s/<id>/exec?s=<slot>&k=<token>"}`.
  The URL is exactly that shape: host `script.google.com`, path
  `/macros/s/<id>/exec` with `<id>` of 20–120 characters from
  `[A-Za-z0-9_-]`, and exactly two query parameters in this order: `s`,
  11 base64url characters, then `k`, 22 base64url characters, nothing
  else. It is a mirror like any other for the set's rules (https, no
  credentials, distinct host).
- **What it serves** is not a freshness document but the slot's
  `daal-refresh-v2` container (next section) holding one; for a wrong
  `k`, an unknown slot or a slot never written, the bland text
  `Nothing here.`.
- **How a recipient fetches it** (G4): through the Google front — SNI
  `www.google.com`, HTTP/2 `:authority script.google.com`, a Chrome-shaped
  hello — following exactly one redirect, and only to
  `script.googleusercontent.com` over the same front; a bounded read of
  64 KiB; if the fronted attempt fails, one plain attempt with SNI
  `script.google.com`. At most two connections to Google per walk, and
  0–120 s of random delay before the first (the script's quota is 30
  simultaneous executions). A recipient fetches it only after a route
  died and with no tunnel up, like every mirror. A mirror in a
  freshness document's `mirrors[]` (which carries URLs only) is treated
  as `appsscript` exactly when its URL has this shape.
- **The two-mirror rule, amended** (owner decision D-3): a mirror set
  whose only provider is `appsscript` is accepted with that one mirror.
  Every other set still needs at least two distinct providers. This
  applies where the rule is enforced today: the publisher's
  `NewMirrorSet` and the recipient's verification of the set
  (`core/refresh`). The card says that a Google suspension then stops
  updates.

### The `daal-refresh-v2` container — optional add-ons

The body the `appsscript` mirror serves for one slot (and the only
thing the script stores per slot): the freshness document, the signed
credential-less pack it names, and optionally a standby key, in one
small text object, so a recipient behind the Google front needs no
second fetch. (v2 is v1 with the slot; v1 was never deployed and is
read by nothing.)

```jsonc
{
  "kind":        "daal-refresh-v2",
  "slot":        "<the slot it was written for>",
  "freshness":   "<base64 of the freshness document, its exact bytes>",
  "pack":        "<base64 of the signed credential-less .sbp>",  // optional
  "standby_key": "<the 26-symbol standby key>"                  // optional
}
```

- UTF-8 JSON, at most 65 536 bytes in all; `freshness` at most 16 KiB
  decoded, `pack` at most 48 KiB decoded. `kind` must be exactly
  `daal-refresh-v2`, and `slot` must equal the `s` of the mirror URL it
  was fetched from; a recipient refuses anything else (a script that
  mixed two relays' texts up is "nothing here", never a document to
  weigh). Unknown members are ignored: every part authenticates itself,
  and nothing in the container is trusted because of where it came from.
  (The connect check's container carries a `check` nonce; recipients
  never fetch the test slot.)
- `freshness` is verified exactly as a document fetched from any mirror
  (signature chain, `relay_pack_id` / `supersedes`, `sequence` high-water
  mark, `not_after`). Nothing else in the container is used unless it
  verifies.
- `pack` is used only when its SHA-256 equals the document's
  `current_bundle_sha256`, and then goes through the same merge as a
  pack fetched from `current_signed_url` (rules 3–4 of "Recipient
  rules"); `current_signed_url` is not fetched.
- `standby_key` is accepted only when it matches a held route's
  `_standby.commit` (after the pack, if any, was applied). It is the 26
  symbols run together, upper case, the last symbol's two padding bits
  zero; the publisher's builder takes the key in any form
  `bundle.ParseStandbyKeyText` reads (the grouped form people are shown)
  and writes this one.
- `{"kind": "daal-refresh-v2", "slot": "<slot>"}` with no `freshness`
  is the empty container a relay that turned the channel off leaves in
  its slot: "nothing new", not an error.
- **The update** (publisher → script; recipients never see it) is one
  HTTPS POST of `{"slot": "<slot>", "seq": <integer>, "blob": "<the
  container JSON as a string>", "mac": "<64 lower-case hex>"}` with
  `mac = HMAC-SHA256(write_key, "daal-refresh-v2" ‖ 0x0A ‖ slot ‖ 0x0A ‖
  ASCII decimal seq ‖ 0x0A ‖ blob)` and `write_key` 32 random bytes the
  publisher's app generated for the account and embedded in the script.
  The script stores the blob in that slot only when the MAC holds and
  `seq` is greater than the slot's stored one (the same update again is
  answered ok); other slots are untouched. Answers: `{"ok":true,"seq":n}`
  or `{"ok":false,"error":"malformed"|"too_large"|"refused"|"stale"|"full"}`
  (`full`: the account's Script Properties store, about 500 KB in all,
  refused the write). The write key only prevents vandalism of the
  channel; recipients trust the publisher's signature, never the script.

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
| RP026 | error (signing only) | `relaypackvalidate.ValidateForSigning`: a `cdn_fronted` candidate's `_cdn_endpoint` is missing or unusable, sits beside an `_endpoint`, is on a family other than `websocket-tls`, or could never be dialled (no `ech_config`, `plain_fallback` off); or a candidate that is not `cdn_fronted` carries `_cdn_endpoint`. **Never run on a recipient** (`Validate` does not include it): a newer publisher's shape must cost a recipient one route, not the pack. |
| RP027 | error (signing only) | `ValidateForSigning`: a `_standby` is malformed, sits on shadowsocks or on a route without a direct `_endpoint`, is an open standby equal to `_endpoint.server`, or the routes of one relay address do not all carry the same one (shadowsocks excepted). Recipients treat every such `_standby` as absent. |
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
- New data for a route goes in a **sibling** member of
  `family_specific_config` that older builds ignore (`_report_to`,
  `_cover_names`, `_standby`, `_cdn_endpoint`), never inside
  `_endpoint`, whose decoder is strict and whose refusal costs the whole
  pack. A route whose outbound older builds must not see (they would
  refuse the pack for an outbound with no `_endpoint`) wraps it in its
  profile under a key of its own with no top-level `type`
  (`_daal_cdn_outbound`). Each such member is refused only at signing
  (`ValidateForSigning`); a recipient that cannot read one drops that
  member or that route, never the pack.

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

Every route of the corpus that carries `_relaypack` also carries a signed
`_endpoint` and a profile holding the outbound the real minter renders
for it (one profile per route, `profiles/<id>.json`), for one fixture
relay with made-up credentials and a throwaway certificate: the corpus is
an import corpus as well as a validator one, and a RelayPack outbound
with no commitment is refused at import. The `expected.json` validator
outcomes are unchanged by this.

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

After validation, and still before any trust prompt, the importer applies
the endpoint rules of "Endpoint commitment" below: an outbound that does
not match its route's signed endpoint refuses the import, a route with no
outbound is not stored, and a signed endpoint is merged into credentials
the device already holds.

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

## Endpoint commitment — "signed endpoint, local credential"

**Normative.** Implemented by `bundle/go/bundle/endpoint.go` (format,
check, merge; the CDN-fronted shape in `cdn_endpoint.go`, the standby
in `standby.go`), `bundle/go/importer/endpoint_plan.go` (import policy),
`publisher/deploy/relaypack/endpoint.go` (signing) and
`core/abi/endpoint_guard.go` (set-route).

### The problem

`manifest.sig` covers `manifest.json`. It does not cover
`profiles/<id>.json` — the sing-box outbound a route dials — because a
RelayPack's profiles are rewritten per recipient *after* signing
(`users-pack-sbp[x]`, without the publisher key). Until this section
existed, anyone who could touch a pack in transit could therefore point
every route at a server of their choosing, under the genuine publisher's
fingerprint words. An age envelope addressed to a recipient's public key
is confidentiality, not authentication, and the default shared `.sbp`
has no envelope at all.

### The commitment

At `bind-and-sign` time the relay exists, so everything about a route
that is **not** a per-recipient secret is known. Each route's
`family_specific_config` — an object inside the **signed** manifest —
carries it under the reserved key `_endpoint`:

```jsonc
"family_specific_config": {
  "port": 443,
  "_relaypack": { /* … */ },
  "_endpoint": {
    "v": 1,
    "server": "203.0.113.10",          // the address the route dials
    "port": 443,
    "server_name": "cover.example",    // see the table
    "tls_spki_sha256": "<base64>",     // SHA-256 of the relay's TLS leaf SubjectPublicKeyInfo
    "reality_public_key": "<base64url>",
    "ss_method": "2022-blake3-aes-128-gcm",
    "ss_server_key_sha256": "<hex>"    // SHA-256("daal/ss-server-key/v1\0" + iPSK)
  }
}
```

| family | fields | the outbound must… |
|---|---|---|
| `vless-reality` | `server port server_name reality_public_key` | be `vless`; TLS on; `tls.server_name` = `server_name`; REALITY on with that public key |
| `websocket-tls` `hysteria2` `tuic` `anytls` | `server port tls_spki_sha256 [server_name]` | be the family's type; TLS on; `tls.certificate_public_key_sha256` = the pin (every entry); no REALITY; no extra trusted certificate; `tls.server_name` = `server_name` when committed |
| `naive` | `server port tls_spki_sha256` | be `naive`; TLS on; install at least one trusted certificate, **every** one of which carries the pinned key; `tls.server_name` (absent = the address) equals `NaiveVerificationName(server, certificates)` |
| `shadowsocks` | `server port ss_method ss_server_key_sha256` | be `shadowsocks`; that method; the box-wide half of `"<iPSK>:<uPSK>"` hashes to the digest; no `tls`, no `plugin` |

For every family: `server` and `server_port` equal the commitment;
`tls.insecure` is absent or false; no `detour`, bind or routing-mark
knob; no `server_ports` (hysteria2's port-hopping list replaces
`server_port` when present); no trust anchor read from a path on the
device.

**Member names.** In the outbound object, its `tls` object and
`tls.reality`, every member name MUST be plain lower-case ASCII: one or
more of `a`–`z`, `0`–`9`, `_`. An outbound with any other member name in
those three objects — `Server`, `INSECURE`, `\u017ferver`, the empty
name — does not match (`endpoint_mismatch`), whatever its values, and
this is tested before any of the equalities above. The reason is that
the equalities are read by exact name while sing-box matches a member to
a field without regard to case, using Unicode simple case folding
(U+017F LATIN SMALL LETTER LONG S is an `s`, U+212A KELVIN SIGN is a
`k`), and lets the later of two members that fold onto one field win. A
profile could otherwise keep `"server"` exactly as signed, add
`"\u017ferver"`, and satisfy the check while the engine dialled the
second; `"Insecure": true` would be a `tls.insecure` the "absent or
false" rule never saw. Every sing-box field name is plain lower-case
ASCII, so nothing a pack legitimately says is excluded. Objects below
those three (`transport`, `multiplex`, …) are not constrained: nothing
in them is committed, and `transport.headers` carries HTTP header names.
Pinned by `TestCheckOutbound_RefusesFoldedKeySpellings`
(bundle/go/bundle) and, against the linked sing-box,
`TestFoldedProfileKeys_SingBoxReadsThem_TheEndpointCheckRefusesThem`
(core/engine, `-tags singbox`).

`_endpoint` is strict: an unknown member, a version other than `1`, or a
field that does not belong to the route's family makes the commitment
malformed (`endpoint_malformed`) — a commitment this build would not
fully enforce is not one it may partially enforce.

### The CDN-fronted endpoint — optional add-ons (additive)

Reserved 2026-11-20 for the Cloudflare add-on
(`docs/optional-addons-plan.md` §2, `specs/optional-addons-v1.md` §4).
**Built (B-4, endpoint part):** format, check and merge
`bundle/go/bundle/cdn_endpoint.go`; import
(`bundle/go/importer/endpoint_plan.go` `planCDNRoute`); set-route guard
(`core/abi/endpoint_guard.go`); the signing check RP026
(`relaypackvalidate.ValidateForSigning`). **Built 2026-11-20 (B-4
outbound part, B-6, B-6b, integration):** the binder writing it
(`relaypack.BindOpts.CDN`; `bind-and-sign` fills it from the operator
record's `cdn_front` member, seeds from the Cloudflare ranges the front
record holds, roots = the shipped set `relaypack.CDNShippedRootDigests`,
or `--cdn-*` flags), the minter (`relaypack/client_outbound.go`
`CDNClientOutbound`, wrapped by `client_pack.go`; the door's path from
the creds file's `cdn_ws_path` or `users-pack-sbp[x] --cdn-front`, the
roots shipped or `--cdn-roots-file`), the engine's edge pick
(`core/edgepick`) and hello order (`core/abi/connect_cdn.go`).

A `websocket-tls` route whose `_relaypack.exposure_mode` is `cdn_fronted`
commits to a host name and a root set instead of an address and a key
pin.

**Where it travels — and why not in `_endpoint`.** `_endpoint` is
decoded strictly (below), and every build since endpoint commitments
refuses the **whole** pack — every other route and the freshness merge
of the signed skeleton with it — for one unknown member there. Families
may stay on an older build for a long time, so the CDN commitment is a
sibling member of its own, and the route carries **no** `_endpoint`:

```jsonc
"family_specific_config": {
  "_relaypack": { "exposure_mode": "cdn_fronted", /* … RP005–RP007 */ },
  "_cdn_attestation": { /* RP022 / RP023, unchanged */ },
  "_cdn_endpoint": {
    "v": 1,
    "server": "<label>.<zone>",          // a host name, never resolved by a recipient
    "port": 443,
    "server_name": "<label>.<zone>",     // equals server
    "cdn": "cloudflare",
    "edge_seeds": ["104.16.0.0/13", "..."],
    "ech_config": "<base64 ECHConfigList>",               // optional
    "tls_roots_sha256": ["<base64 SHA-256 of a root's SubjectPublicKeyInfo>", "..."],
    "plain_fallback": false                               // optional, default false
  }
}
```

and the recipient's outbound for the route is **wrapped** in its
profile, beside the minter's `_daal_unavailable` marker, with no
top-level `type`:

```jsonc
// profiles/<id>.json of a CDN-fronted route in a recipient's file
{
  "_daal_unavailable": { "family": "websocket-tls", "reason": "…" },
  "_daal_cdn_outbound": { "type": "vless", "server": "104.16.1.2", /* … */ }
}
```

(`bundle.WrapCDNOutbound`; `bundle.CDNProfileOutbound` unwraps, and also
accepts an outbound at the top of the profile.) A build from before this
amendment therefore sees, for that one route, no commitment and no
outbound: it reports the route `not_offered` ("not included in this
file … nothing is wrong with your phone"), imports every other route,
and on the freshness path merges every other route and reports this one
`no_credentials`. Tested against a frozen copy of those rules, and
against the real code of 079ef96 on packs this build produced
(`bundle/go/importer/compat_old_test.go`; the same file shows the
earlier proposal — these members inside `_endpoint` — refused whole by
the old rules). A recipient's old build also runs the RelayPack
validator, which already accepts a `cdn_fronted` `websocket-tls`
candidate at V1.6 when RP005–RP007 and RP022/RP023 hold, so the minter
MUST write `_cdn_attestation` and the tags.

The member is covered by the manifest signature like every other
member of `family_specific_config` (canonicalisation re-parses the
object and sorts its keys); the wrapped outbound, like every outbound,
is not signed and is held to the commitment.

- **Shape.** Decoded strictly: an unknown member, a version other than
  `1`, or any rule below broken makes it unusable for this build. On a
  recipient that costs **that route only** — it is reported
  `needs_newer_app` and the rest of the pack is used: the member is
  signed, so a shape this build does not know is a newer publisher, not
  an altered file. A route carrying both `_endpoint` and `_cdn_endpoint`
  refuses the pack (`endpoint_malformed`). RP026 refuses all of these
  at signing.
  - `cdn`: `cloudflare` (the only value). Family: `websocket-tls` only.
  - `server`: a canonical LDH host name of at least two labels — lower
    case, no trailing dot, not an IP literal, not domestic (`.ir`, its
    IDN, or the known-domestic list of `_cover_names`).
  - `edge_seeds`: 1–8 canonical (host bits zero, as `netip` prints it)
    IPv4 or IPv6 CIDR prefixes of public unicast space, no repeats,
    taken by the publisher abroad from the CDN's published ranges at
    sign time. Recipients dial an address inside them and never
    download a range list or resolve the host name (domestic DNS would
    answer `10.10.34.x`).
  - `ech_config`: standard base64 (padded) of the ECHConfigList in the
    host name's HTTPS record (a 2-byte length then that many bytes),
    read over DoH from abroad at sign time and at every freshness
    publish; at most 512 bytes decoded. Absent means the zone serves no
    ECH ("Name hidden: no"). It is the same for every site on the CDN and
    identifies nobody; a stale one costs one round trip (the edge
    answers with retry configs).
  - `tls_roots_sha256`: 1–8 standard-base64 SHA-256 digests of root
    certificates' SubjectPublicKeyInfo, no repeats. The app ships the
    root set; the minter installs the listed roots in the outbound.
  - `plain_fallback`: the signed per-pack flag of owner decision D-2.
    A commitment with no `ech_config` and `plain_fallback` off could
    never be dialled; RP026 refuses to sign it.
- **The outbound must** (`bundle.CheckCDNOutbound`) be `vless` over a
  `ws` transport whose `Host` header is set exactly once (any spelling
  of the name), to one value, `server_name`; TLS on with
  `tls.server_name` = `server_name`; `server` an IP address inside one
  of `edge_seeds` (the engine's edge pick writes it; a host name there
  is refused) and `server_port` = `port`; no
  `certificate_public_key_sha256`; REALITY absent or off; no
  `tls.insecure`, no `disable_sni`; no `certificate_path` or
  `certificate_directory_path`; at least one root installed as
  `tls.certificate`, **every** one of which has a listed SPKI digest —
  sing-box then trusts those roots and nothing else, whatever the
  platform holds. ECH: `tls.ech.enabled` with `tls.ech.config` exactly
  the committed ECHConfigList (PEM `ECH CONFIGS`) and no `config_path`
  or `query_server_name` — never a configuration fetched by a DNS
  lookup (which would put the zone name in a query) or read from the
  device; ECH off is accepted **only** when `plain_fallback` is true.
  The general rules above (plain lower-case member names, no `detour`,
  bind knobs or `server_ports`) apply unchanged and extend to the
  `transport` and `tls.ech` objects. The ws path is a credential: it
  stays in the profile, the same for every recipient of the route.
- **Import.** As rules 1–4 of "Recipient rules" with this checker: an
  outbound in the file that does not match refuses the whole pack
  (`endpoint_mismatch`); the unwrapped outbound is what is stored, and
  the `_cdn_endpoint` object (as signed) is the route's stored
  commitment (`endpoint:<route_id>`; a reader tells the two shapes apart
  by the `cdn` member, `bundle.IsCDNCommitment`). The set-route guard
  holds the stored outbound to it.
- **Hello order** (engine, B-6b): ECH; then ECH with the outer hello
  split (`record_fragment` + `fragment`); then stop. A plain hello
  (which shows the zone name) only when `plain_fallback` is true. The
  route is tried after every direct route and after the open standby.
- **Merge** (`bundle.MergeCDNEndpoint`, freshness or a later file, into
  a device route whose stored commitment is a CDN one) moves the port,
  `tls.server_name`, the ws `Host`, the ECH configuration (removed when
  none is committed), and the edge address when it is no longer inside
  the seeds (to the first address of the first seed; the device
  re-picks). Installed roots that are no longer listed are dropped; if
  none is left the route is `needs_new_file` and left as it was.
  Credentials (uuid, ws path) stay.
- **Stated limit.** The CDN terminates TLS, so it can read the VLESS
  header — the recipient's UUID and each destination host and port —
  and sees every recipient's address. Payloads that are themselves TLS
  stay opaque. Weaker than a key pin in that one way, and the
  publisher's card says so before anything is bought.

No manifest struct changes, so the canonical bytes of every existing
field are unchanged and **`spec_version` does not move**:
`family_specific_config` was already an opaque, signed object.

`naive` has no committed name, and its name is still not free: the
client recomputes it and refuses an outbound that carries any other
(whether the certificates a naive outbound installs replace the
platform's roots or are added to them is the HTTP stack's business; a
name of somebody else's choosing is only harmless in the first case).
Its TLS verification name is a function
of the address and the certificate —
`NaiveVerificationName(server, certificates)`: the address when the
certificate names it; otherwise the certificate's first DNS name;
otherwise the address. Relays provisioned since this section carry one
stable DNS name in their certificate (cloud-init), which is what lets a
naive route follow the relay to a new address (L3) without the
certificate changing. A relay provisioned earlier has no such name and
loses naive on L3.

The certificate's **first** DNS name is the relay's current cover host:
when `rotate-tls` moves the cover host the relay re-issues the
certificate on the same key with the new host first and the earlier
names kept after it (`specs/daal-relay-mgmt-v1.md` §4.2 step 5). The key
pin — the only thing this commitment says about naive's certificate —
does not move, so no endpoint needs re-signing for it. A pack minted
after the rotation installs the new certificate and so verifies, and
presents, the current cover host; a device that keeps the certificate it
was handed keeps the name that certificate leads with, which the relay
still answers to. Carrying the name in the commitment, so that such a
device follows without a new file, is not specified.

A naive outbound may carry `udp_over_tcp` (packs minted since 2026-11-18
do: `{"enabled": true, "version": 2}`). It is not covered by the
commitment and does not need to be: it changes what the committed stream
carries, not where the stream goes or what proves who answered. A merge
keeps the device's value.

### Why the credentials may stay unsigned

The per-recipient credentials (uuid, passwords, REALITY short id, ws
path) stay in the unsigned profile. That is safe, and the argument is
the design:

> The client refuses to dial a route whose outbound disagrees with the
> commitment on server, port or server-authentication material. So the
> only thing left for an attacker to change is a credential. A changed
> credential is presented to the **committed** server over a channel
> authenticated by the **committed** key. The genuine relay refuses it;
> nobody else can complete the handshake to receive it. A tampered
> credential can only fail to connect. It can never be sent elsewhere.

Tested: `TestCheckOutbound_CredentialsAreFreeAndCannotMoveTheEndpoint`,
and on the wire by the rig (`op:tamper credential_rewrite.*`).

Stated limits:

- **shadowsocks** has no server authentication independent of the shared
  key. A stranger cannot substitute a key (the digest is committed);
  someone who is both a recipient of the same relay and on the network
  path can still impersonate it to another recipient. That is the
  protocol.
- **Bundles that are not RelayPacks** (`Manifest.relay_pack == nil`)
  carry no commitment: their profile bytes are covered by no signature
  and can be rewritten by whoever handles the file. They can therefore
  never replace a committed route (next section); the routes they add
  under new ids remain unauthenticated.

### A commitment is sticky

Once a route on the device is bound to a signed endpoint — it has a
stored commitment, or its row carries a `relay_pack_id` — nothing that
carries **no** commitment for that route id may replace it. An import
of a bundle with `Manifest.relay_pack == nil` that names such a route id
is **refused whole**, reason `endpoint_downgrade`, before any trust
prompt and again before persistence; no route, commitment or
`relay_pack_id` on the device changes. This holds whatever the route's
trust state (an expired or revoked committed route is not an opening),
and whoever signed the incoming bundle. The store enforces it
independently of the importer (`core/trust` `SaveImport` refuses the
write before writing anything).

The only way a committed route stops being one is the user removing it;
a commitment left in the store by a removed route binds nothing.

Tested: `TestImport_BundleWithoutCommitmentsDoesNotReplaceCommittedRoutes`
(bundle/go/importer), `TestStoreAdapter_CommitmentIsSticky` (core/trust),
rig `op:tamper uncommitted_replacement.*`.

### Recipient rules (import)

For a bundle with `Manifest.relay_pack != nil`, per usable route, before
any trust prompt and again before persistence (a route carrying
`_cdn_endpoint` follows the same rules with that commitment in place of
`_endpoint`, its outbound unwrapped from the profile; "The CDN-fronted
endpoint"):

1. **Outbound present** (the profile is a JSON object with a non-empty
   `type`): the route MUST carry a valid `_endpoint` and the outbound
   MUST match it. Otherwise the **whole import is refused** —
   `endpoint_unauthenticated` (no commitment) or `endpoint_mismatch`.
   It is a refusal, never a trust prompt: the file is provably not what
   its publisher signed.
2. **No outbound** (the signed skeleton's metadata-only profile, or the
   minter's `_daal_unavailable` marker): the route is **not stored**. It
   is not listed, not selectable, not activatable. It is reported in
   `Verdict.Unavailable` with a reason — `not_offered` (marker),
   `no_credentials`, `needs_new_file`, `older_than_device`, or
   `needs_newer_app` (a signed add-on member this build cannot read;
   "The CDN-fronted endpoint").
3. **Merge.** If the route has a commitment and the device already holds
   an outbound for the same route id, from the **same publisher**, of the
   **same family**, the new signed endpoint is applied to that outbound
   and its credentials are kept (`MergeEndpoint`: server, port, TLS
   name, pin, REALITY public key, shadowsocks method move; nothing else
   does). The result must itself match the commitment. If it cannot —
   the device's naive certificate does not carry the committed key, its
   shadowsocks server key is not the committed one — the route is
   reported `needs_new_file` and **left exactly as it was**. A profile
   that yields no outbound never replaces one that does.
   A merge additionally requires *continuity*: on the freshness path the
   publisher-signed document (which names the pack ids it supersedes)
   provides it; for a pack handed over as a file the `relay_pack_id`
   must equal the one on the device's route, **and the merge must move
   the route forward** (next rule).
4. **A file only moves a route forward.** The credential-less signed
   pack is public (it is what the freshness mirrors serve), and an
   in-place rotation — port, cover host, REALITY key, TLS key — keeps
   the `relay_pack_id`. So a merge that does not come from the freshness
   path (file, QR, share) additionally requires the incoming manifest's
   `bundle.created_at` to be **strictly later** than the `created_at` of
   the manifest the route's current commitment came from. The one
   exception is the manifest the route is already on (equal
   `created_at` **and** an identical `_endpoint`), which changes nothing
   and is accepted. Otherwise the route is reported `older_than_device`
   and **left exactly as it was**. If either date is missing or is not
   RFC 3339, nothing can be shown and the route is reported
   `needs_new_file`, untouched. The freshness path is ordered by its own
   signed sequence high-water mark and is not subject to this rule.
   Without it, whoever holds a relay key the publisher rotated away from
   could hand a recipient the old public file and return the phone,
   silently (the publisher is already trusted), to that key.
5. A pack that leaves no route to store is refused:
   `pack_is_older` if any of its routes was `older_than_device`,
   otherwise `pack_has_no_credentials`.

**A RelayPack with no commitments is refused**, not accepted with a
warning. Nothing is fielded, every fixture was migrated, and an
"unauthenticated endpoint" state a user may click through is the
original hole with a label on it.

The engine keeps each stored route's commitment beside its profile
(`endpoint:<route_id>`), together with the `bundle.created_at` of the
manifest it was signed in (`endpoint-signed-at:<route_id>`; written and
removed with the commitment, read by rule 4). `SetRoute` re-checks the outbound against it
before dialling; a RelayPack route with no stored commitment is not
dialled. A refusal there is not recorded as a failure of the route.

### Publisher rules

- `bind-and-sign` commits every candidate whose family is in the table.
  Material comes from three places, in this order of authority:
  1. `--relay-identity <file>` — the relay's own statement of who it is
     (`daal-deploy relay-identity`, mgmt `GET /identity`,
     `specs/daal-relay-mgmt-v1.md` §4.9). **This is the path**: it needs
     no recipient and no provider-specific SSH read, so a pack can be
     signed before the first recipient exists, on every provider. Where
     it speaks — REALITY public key, TLS pin, cover host, shadowsocks
     method and server-key digest — it outranks the record, and every
     disagreement is reported (`identity_warnings`). An identity older
     than 15 minutes does not outrank the record on the cover host
     (`rotate-tls` rewrites the record; an old identity cannot know).
  2. the OperatorRecord — always the source of the address and the
     ports; of the cover host, REALITY public key and TLS pin only where
     the relay's identity is silent.
  3. `--endpoint-creds <file>` — any `users-provision` /
     `rotate-credentials` reply, of which only the relay-wide fields are
     read; for a relay too old to state its identity. It fills what is
     still empty and never overrides the record: the record is what
     every rotation verb rewrites, while a saved reply is a snapshot.

  No recipient secret and no shadowsocks key (only its digest) is
  written to the pack. The summary's `committed_identity` is what the
  signed endpoints commit the relay to, read back out of the pack.
- A relay's shadowsocks key does not exist until its first recipient
  (`pending_families` in its identity). A pack signed before that has no
  shadowsocks commitment, and the publisher MUST sign again once the key
  exists — the publisher app does so as soon as a relay reply disagrees
  with the `committed_identity` it stored.
- A candidate whose material is missing is signed **without** a
  commitment, named on stderr and in `uncommitted_families` on stdout;
  no recipient can use it. If no committable candidate got one, nothing
  is signed.
- `users-pack-sbp[x]` checks each outbound it renders against the
  route's commitment. A route with no commitment is dropped and
  reported like any other unrenderable route. A mismatch — the relay
  moved since the pack was signed — fails the verb: sign again first.
- After any rotation that moves an endpoint (L2, L3) or replaces the
  relay (L4–L6) the publisher MUST run `bind-and-sign` again — from a
  fresh `relay-identity` after L2 and after a rebuild — before minting
  or announcing, and MUST republish freshness. The publisher app does
  all three itself and tells the operator who, if anyone, still needs a
  new file (the table below); it does not say "every recipient" after
  an L2.

### Freshness delivers the signed endpoint; what still needs a file

The file whose digest a freshness document names is `bind-and-sign`'s
output: the signed, credential-less pack. It is the only pack that may
be hosted publicly. Recipients merge it (rule 3). Consequently:

| rung | what changes | per-recipient credentials | a recipient that polls |
|---|---|---|---|
| L1 `rotate-credentials` | one recipient's credentials | changed for that recipient | **that recipient needs a new file** |
| L2 `rotate-tls` | cover host | unchanged | recovers, no new file. (If the shared ws path was moved as well, the websocket route alone needs a new file: the path travels with the credentials.) **A recipient that does not poll** (a pack with no freshness mirrors) keeps connecting on every route except vless-reality — the only one that puts the cover host on the wire — and needs a new file for that route alone. |
| L3 `assign-fip` | address | unchanged | recovers, no new file |
| L4–L6 rebuild | new box: new REALITY key, new TLS key, new credentials | changed for everyone | **every recipient needs a new file** |

L4–L6 cannot be made mergeable from the publisher alone: the relay mints
each recipient's credentials itself (`/users/provision` takes a name),
so a rebuilt relay answers with different secrets. The new keys do
travel in the signed endpoint; the credentials need a courier.

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
- per route, the signed `_endpoint` commitment (see "Endpoint
  commitment" above), from the relay's identity
  (`BindOpts.RelayIdentity` / `--relay-identity`), the record, and
  `BindOpts.Endpoint` / `--endpoint-creds`, in that order of authority. The profile the binder
  writes for each route still holds no outbound and no secret: its
  output is the signed, credential-less pack.

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
- `specs/optional-addons-v1.md` and `docs/optional-addons-plan.md` — the `_standby` key, the CDN-fronted endpoint, the `appsscript` mirror provider and the `daal-refresh-v2` container (reserved and built 2026-11-20; one script per Google account with a slot per relay since 2026-11-22).

## V2 cell aggregation (FRP-11 amendment)

A cell-aggregated `.sbp` reuses this schema verbatim. The bundle-signer key (admin-quorum-delegated per `specs/cell-v1.md`) signs the manifest; `manifest.publisher.key_fingerprint_hex` is the bundle-signer's fingerprint. Inner-publisher provenance flows through the FRP-7.5 sub-key cert chain (`trust/subkey-cert.json`) per route. Two new bundle files (`trust/cell-membership.json`, `trust/cell-delegation.json`) carry the admin-quorum chain; `bundle.VerifyBundle` is UNCHANGED. Spec version stays at 4. See `specs/cell-v1.md` for the full chain walk and admin-quorum rules.
- FRP-12 (`42-phase-frp-12-modifier-framework.md`) — per-modifier framework.
