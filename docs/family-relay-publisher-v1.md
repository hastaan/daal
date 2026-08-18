# Family Relay Publisher — Operator Guide v1

## Status

Skeleton at FRP-4a (Phase 32). Deploy-core sections written here.

- FRP-5 will add wizard sections (token custody, screen-by-screen UX,
  multi-language EN/FA copy).
- FRP-4b will add the end-to-end signed-RelayPack flow + screen 4–6
  live-binding documentation.
- FRP-7 will add the rotation playbook (L1–L6).
- FRP-8 will add the `cdn_fronted` deploy template.

This file is the operator-facing manual for "Family Relay Publishers"
(FRPs) — the diaspora users who run the publisher Helper machine to
provision a small VPS, sign a RelayPack with their publisher key, and
hand it to recipients via QR / Signal / shared file.

## Audience

A diaspora user with a laptop, a credit card, and a willingness to
spend ~10 minutes once and ~5 EUR/month for a small VPS. The
operator does not need to be technical. The Helper handles all
choices that require infrastructure knowledge.

## Architectural overview

```
+---------------------------------------------+
| Helper machine (FRP's laptop)               |
|                                             |
|  +--------------+    +-------------------+  |
|  | Tauri wizard |--->| daal-deploy CLI  |  |
|  | (FRP-5)      |    | (FRP-4a)          |  |
|  +--------------+    +-------------------+  |
|         |                     |             |
|         v                     v             |
|  +----------------+   +------------------+  |
|  | OS keystore +  |   | hcloud-go/v2     |  |
|  | AES-GCM (PIN)  |   | Hetzner adapter  |  |
|  | (FRP-5)        |   |                  |  |
|  +----------------+   +------------------+  |
|                              |              |
|                              v (HTTPS)      |
+--------------------------|--+---------------+
                           |
                           v
                +---------------------+
                | Hetzner Cloud API   |
                +---------------------+
                           |
                           v provisions
                +---------------------+
                | VPS (origin box)    |
                |  - sing-box         |
                |  - daal-relay-     |
                |    health (60 s)    |
                +---------------------+
```

The wizard never talks to the VPS directly. Everything goes through
either (a) the Hetzner Cloud API, or (b) the box's health endpoint
during the 60-second provisioning window over an IP-bound ufw rule.
Post-provisioning the box exposes only sing-box on 443/TCP+UDP.

## Deploy core overview (FRP-4a)

This phase ships the operator-side deploy substrate. All work lives
in:

- `publisher/deploy/provider/` — the `Provider` interface and the
  Hetzner adapter.
- `publisher/deploy/cloudinit/` — the locked YAML template, the
  verifier shim, and the pinned-artefact manifest.
- `publisher/deploy/health/` — the Helper-side polling client and
  the box-side HTTP handler shape.
- `publisher/deploy/profiles/` — the `iran-default` toolbox
  profile (data, not code).
- `publisher/deploy/cli/` — the subcommand dispatcher consumed
  by the `daal-deploy` binary.
- `cmd/daal-deploy/` — the CLI binary.
- `cmd/daal-relay-health/` — the box-side health endpoint binary.

### `Provider` interface

```go
type Provider interface {
    Provision(ctx, opts) (*OperatorRecord, error)
    Reprovision(ctx, rec, opts) error
    Decommission(ctx, rec) error
    AssignFloatingIP(ctx, rec, fipID) error
    UnassignFloatingIP(ctx, rec) error
    Pricing(ctx, rec) (Pricing, error)
}
```

The Hetzner adapter is the first implementation. Vultr / Stark
adapters land at FRP-10. The wizard's deploy step is
provider-agnostic.

### CLI surface

This list is generated from the dispatch switch in
`publisher/deploy/cli/cli.go:69-129`, which is the only authority.
**29 verbs**, not the 7 this section listed until 2026-08-17:

```
# lifecycle
daal-deploy version
daal-deploy pricing            daal-deploy list-server-types
daal-deploy list-servers
daal-deploy provision          daal-deploy reprovision
daal-deploy decommission       daal-deploy verify
daal-deploy assign-fip         daal-deploy floating-ip {assign,unassign}

# packs + signing
daal-deploy bind-and-sign      daal-deploy qr-fountain
daal-deploy publish-freshness  daal-deploy rotate-recommend

# CDN fronting (FRP-8)
daal-deploy cdn-provision      daal-deploy cdn-rotate-path
daal-deploy cdn-rotate-hostname
daal-deploy cdn-rotate-origin

# trusted cells (FRP-11)
daal-deploy cell-create        daal-deploy cell-invite
daal-deploy cell-sign          daal-deploy cell-verify
daal-deploy cell-status

# per-recipient credentials + packs (FRP-14)
daal-deploy users-provision    daal-deploy users-revoke
daal-deploy users-list         daal-deploy users-pack-sbp
daal-deploy users-pack-sbpx    daal-deploy users-unpack-sbpx
```

Typical invocations (flags unchanged):

```
daal-deploy pricing      --provider hetzner --region fsn1 \
                          --server-type <type> --token-file <path>
daal-deploy provision    --provider hetzner --region fsn1 \
                          --server-type <type> \
                          --toolbox iran-default --helper-ip <ip> --pubkey <path> \
                          [--dry-run]
daal-deploy reprovision  --record-file <path> [--new-toolbox <name>] \
                          [--new-sni <host>] [--regen-credentials]
daal-deploy decommission --record-file <path>
daal-deploy floating-ip  assign --record-file <path> --fip-id <id>
daal-deploy floating-ip  unassign --record-file <path>
daal-deploy verify       --record-file <path>
```

**Do not hardcode a `--server-type` from this document.** The examples
above deliberately say `<type>`: they previously said `cx22`, and
Hetzner now rejects it with "server type 104 is deprecated"
(`client-ui/src/publisher/PublisherWizard.tsx:138,570`). Get the current
catalogue at runtime from `daal-deploy list-server-types`.

Record-producing subcommands emit structured JSON on stdout. The wizard
shells out via `std::process::Command` and parses JSON for the live
read-only pricing call at FRP-5; live provisioning is wired at FRP-4b.

### Cloud-init invariants

- Every relay artefact is fetched from a Daal-controlled mirror,
  signed with the Daal release key, and verified on the box BEFORE
  installation.
- The verifier shim uses ONLY base-image tools: `bash`, `python3`
  stdlib, and `openssl`. No bootstrap binary downloaded before
  signature verification (chicken-and-egg solved by §9.2.1).
- The ephemeral SSH key is removed and `sshd` disabled at +60 s.
- The health endpoint's ufw rule is deleted at +60 s; the binary
  itself self-terminates at 300 s.
- The `daal` system user is `nologin`, `lock_passwd: true`,
  `sudo: false`. It owns sing-box runtime files only.

### `iran-default` toolbox profile

The default candidate set for Iranian conditions, V1.5 direct-VPS:

Regenerated from `publisher/deploy/profiles/iran-default.json` in the
Wave-5 repair pass. The previous version of this table still listed
`wireguard` and `amnezia-wg`, which the profile no longer carries, and
omitted `shadowsocks` and `anytls`, which it gained.

| Family          | Default | Probing risk | UDP-gated | Port     |
|-----------------|---------|--------------|-----------|----------|
| vless-reality   | yes     | low          | no        | 443/tcp  |
| websocket-tls   | yes     | low          | no        | 8445/tcp |
| naive           | yes     | low          | no        | 8444/tcp |
| hysteria2       | yes     | low          | yes       | 443/udp  |
| shadowsocks     | no      | moderate     | no        | 8446/tcp |
| anytls          | no      | moderate     | no        | 8447/tcp |
| tuic            | no      | moderate     | yes       | 8443/udp |

**The three opt-in families all cost a port outside the target
country's whitelist.** 8443, 8446 and 8447 are not whitelisted egress
in Iran, exactly like naive on 8444 and websocket-tls on 8445
(`publisher/deploy/relayports/relayports.go` states this in its own
words). Enabling them buys transport diversity on OTHER networks — and
for shadowsocks specifically, independence from the nested-TLS
classifier that threatens the three TLS tiers at once. None of them is
a new way through the whitelist, and nothing operator- or user-facing
may imply otherwise.

**`amnezia-wg` must not be enabled, and is no longer a candidate in
either shipped profile.** sing-box 1.13.12 contains no AmneziaWG code
at all, so the Jc/S1/H1..H4 obfuscation parameters that ARE the family
have nowhere to go; a pasted AmneziaWG conf imports as a downgraded
plain-WireGuard route. It is `unsupported` in
`core/routestore/family.go`.

**`wireguard` is dialable but is not a relay family.** Wave 5 gave
`core/engine/config.go` the `endpoints[]` slot sing-box needs and made
`bundle/go/uri/wireguard.go` emit a real endpoint object with
`"type":"wireguard"`, so the label is now `experimental` rather than
`unsupported`. Daal still does not SERVE it — no relay inbound, no
per-recipient credential, no firewall rule — so it reaches a user only
by paste or import. And the copy constraint travels with it: plain
WireGuard is a named immediate-block target in Iran and must never
borrow AmneziaWG's track record.

Serving a family the recipient cannot dial produces a route the user
selects and loses, which is worse than not offering it. The full
serve-vs-dial reconciliation for every family is
`docs/transport-family-inventory.md`.

V1.6 will add `cdn_fronted` candidates to this profile via FRP-8.

### Position B at the Helper

The deploy CLI opens connections ONLY to:

1. The cloud-provider API (`hetznercloud/hcloud-go/v2`).
2. The box's health endpoint over the IP-bound ufw rule, for the
   60-second provisioning window only.

There is no telemetry, no project endpoint, no usage analytics.
This is verified by `publisher/deploy/opsec_test.go` which scans
every non-test `.go` file under `publisher/deploy/` for
forbidden tokens.

## Wizard sections

*(Was "(Pending FRP-5.)". FRP-5 shipped May 2026 — and the wizard has
since been rebuilt again. The publisher wizard is now **3 screens**, not
the 7 FRP-5 planned; see `d80c638` and
`client-ui/src/publisher/PublisherWizard.tsx`. This section was never
written and is not a reliable description of anything; treat the code
and `development-phases/33-phase-frp-5-desktop-wizard.md` as the
sources.)*

## End-to-end flow

*(Was "(Pending FRP-4b.)". FRP-4b shipped May 2026; see
`development-phases/34-phase-frp-4b-direct-deploy-integration.md` and
the handover at `docs/handovers/frp-4b-handover.md`. Never written
here.)*

## Rotation playbook

*(Was "(Pending FRP-7.)". FRP-7 shipped May 2026; see
`development-phases/36-phase-frp-7-direct-rotation-pilot-soak.md` and
`docs/handovers/frp-7-handover.md`. Never written here.)*

**This document is therefore partly historical.** Three of its sections
were placeholders for phases that shipped over a year ago and were never
filled in. Either write them or retire the file; do not read the empty
sections as "not done yet".

## CDN-fronted deployment (FRP-8, V1.6)

V1.6 lifts `cdn_fronted` candidates into production acceptance
via FRP-8. The backend command surface and CLI path are live for
FRP-9; the GUI can place the optional CDN-front step wherever pilot
testing shows the operator flow is clearest.

### Wizard flow (screen-by-screen)

1. **CDN-front step (optional, skippable).**
   The operator chooses BYO domain (recommended for V1.6
   closure-metric eligibility) or the project test-zone
   (closed-pilot pathway only, surfaced behind a warning
   checkbox + `domain_suffix:daal-relay-test.org` shared-risk
   tag). Cloudflare API token is pasted; the wizard seals it
   in the OS keystore under alias
   `daal.cloudflare.{operator_id}.token`.

2. **§11.7 hardening (mandatory at V1.6).** Provisioning runs
   `publisher/deploy/cloudflare`:
   - Issue Origin CA cert (15-year default), pin to operator;
   - Enable Authenticated Origin Pulls on the zone, deploy
     client cert to origin via cloud-init `write_files`
     extension at `/etc/daal/cdn/aop_client.pem` (mode 0600);
   - Lock provider firewall to Cloudflare edge ranges
     (refresh runs on Helper, never on origin);
   - Refuse if a DNS-only A or AAAA record already exists on
     the chosen subdomain;
   - Upload Worker rewrite script: `/<random-public-path>` →
     `/<stable-origin-path>`;
   - Bundle the §11.7 conformance evidence as a signed
     `_cdn_attestation` blob inside the per-candidate
     `_relaypack` opaque container (RP022 / RP023).

3. **Live-posture re-verification.** A "Settings → Routes →
   Verify CDN posture" button calls
   `publisher/deploy/cloudflare/posture.go::Verify` and
   surfaces drift between the recorded attestation and the
   current Cloudflare zone state. The validator does NOT call
   Cloudflare; structural-attestation conformance is its job
   (RP022 / RP023), live re-confirmation is the wizard's.

4. **Mode-aware rotation copy.** Four variants per
   `wizard.rotate.copy_*` keys:
   - `copy_direct` — direct VPS rotate (origin IP changes);
   - `copy_cdn_path` — public-path rotate (Cloudflare-API-only,
     no box redeploy);
   - `copy_cdn_origin` — origin behind CDN rotate (Origin CA
     cert + AOP client cert re-issued; public hostname
     unchanged);
   - `copy_freshness_only` — freshness JSON re-publish only
     (recipients pick up new manifest fingerprint without
     scanning a fresh QR).

### Freshness endpoint

Per-publisher signed freshness JSON document at an
FRP-controlled static URL (NOT a Daal-project hostname).
Hosted on the FRP's choice of: GitHub Pages, Cloudflare R2,
IPFS gateway. The freshness signing path is sub-key-aware
(FRP-7.5): root-signed if no active sub-key, sub-key-signed
with embedded `subkey_cert` if an active sub-key exists.

Recipient polling is opportunistic per supplement §14.4: on
every successful tunnel-establishment event + on
selector-classified `cdn_hostname_blocked` /
`path_pattern_blocked` events. NO scheduled poll. NO fixed
cadence. Atomic RelayPack swap on same-publisher hit; no
re-TOFU.

### Storage (V005 `cdn_fronts` table)

Public CDN metadata only (hostname, zone_id, public_path,
origin_path, worker_route_id, fingerprints, paths, booleans,
IDs). The Cloudflare API token stays in the OS keystore;
Origin CA private key + AOP client cert private bytes live on
disk under the wizard staging dir at mode 0600 and are
referenced by path only in the V005 row.

## Cross-references

- `specs/relaypack-v1.md` — RelayPack on-disk schema (V1.6 CDN-fronted profile + RP022..RP024).
- `specs/sbp-v1.md` — base bundle format (`freshness_url` slot).
- `daal-roadmap-v3-supplement-diaspora-helper.md` §9, §10, §11, §11.7, §14.4, §19.2.6, §22.2 — design rationale.
- `phases of development/32-phase-frp-4a-publisher-deploy-core.md` — FRP-4a phase doc.
- `phases of development/38-phase-frp-8-v1-6-cdn-fronted.md` — FRP-8 phase doc.
