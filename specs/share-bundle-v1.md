# Share Bundle v1

## Status

Phase 1C deliverable. The on-the-wire format is identical to a Phase 0B
`.sbp` bundle (`specs/bundle-format-v1.md`); this spec narrows what
`bundle.type = "friend_share"` means and which fields the share builder
sets.

## Producer

`bundle/go/share/export.go::BuildShareBundle`. Inputs:

- One or more `ExportInput` records (route id, transport family, scarcity,
  profile bytes, validity window, redistribute flag).
- A `PublisherIdentity` (the device's per-app sharing keypair; ed25519).

Output: a signed `.sbp` whose manifest carries:

| Field                              | Value                                           |
|------------------------------------|-------------------------------------------------|
| `publisher.name`                   | identity display name (e.g. "My Daal")         |
| `publisher.key_fingerprint_hex`    | sha256(pub) of identity                         |
| `publisher.trust_class`            | `tofu_friend`                                   |
| `bundle.type`                      | `friend_share`                                  |
| `bundle.created_at`                | RFC3339 (hour-bucketed by caller)               |
| `bundle.expires_at`                | created_at + 30 days                            |
| `routes[*].id`                     | the original route id (preserved)               |
| `routes[*].config_path`            | `profiles/<sanitized id>.json`                  |
| `routes[*].udp_gated`              | preserved from sender                           |

The signature covers the canonical manifest JSON (the same canonicalizer
used for all signed `.sbp` artifacts).

## Redistributability

Every `ExportInput` carries an explicit `AllowRedistribute` boolean.
`BuildShareBundle` MUST refuse to construct a bundle if any input has
`AllowRedistribute=false`. Phase 1C V1 ships with the default
`AllowRedistribute=true`; future phases will respect publisher policy
attached to each route at import time.

## Consumer

The receiver imports a friend-share `.sbp` through the **same** importer
path as any other bundle (`bundle-go/importer.ImportBytes`). That path:

1. Verifies the manifest signature against the embedded `publisher.pub`.
2. Computes the publisher fingerprint and looks it up in the local store.
3. Surfaces a `VerdictTrustPromptNeeded` if the publisher is unknown.

So a friend-share never silently joins the trust set. The receiver sees
the same modal trust prompt described in `specs/trust-ui-v1.md`, with the
sender's display name and 4-word fingerprints (EN + FA).

## Trust-class semantics on the receiver

| Outcome of trust prompt   | Receiver-side `trust_level`     |
|---------------------------|---------------------------------|
| "I trust this publisher"  | `tofu_friend`                   |
| "Just for this one bundle"| `unknown` (re-prompts next time)|
| "Cancel"                  | nothing persisted               |

The bundle's own `publisher.trust_class` field is informational only; the
receiver's policy decides the on-device label.

## Identity persistence

The sender's ed25519 sharing identity is stored in the secrets KV under
key `share/identity:v1` (age-encrypted by routestore like all other
secrets). The same identity is reused across sessions so the recipient who
already trusted Alice's phone does NOT see another trust prompt the next
time Alice shares a different route.

## Privacy invariants (CC.6)

- The sharing identity is per-device, not per-user; it carries no profile
  or contact information beyond the user-chosen display name.
- The bundle is built in memory; no `.sbp` file is written to disk during
  a session.
- On `share_end`, the in-memory bundle bytes are zeroed.

## Phase 3F: delegate-share variant (`.sbp.share`)

A `.sbp.share` is a `.sbp` whose `bundle.type ==
"delegated_share"`. The publisher signature (manifest.sig) is
preserved verbatim from the upstream `.sbp`; the delegate
identity (1C share identity at `secrets_kv:share/identity:v1`)
appends a `redistribution_chain[]` hop and a `delegate_caps[]`
entry instead of re-signing the manifest.

The share package widens `ExportInput` with two optional fields
(`RedistributionPolicy`, `RedistributionCap`) carried verbatim
onto the manifest, and adds `BuildShareBundleDelegated` that
splices a publisher-supplied chain + caps into the manifest
before signing. See `delegate-keys-v1.md` for the wire format.
