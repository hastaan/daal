# Phase 32 (FRP-4a) — Publisher Deploy Core

**Status:** SHIPPED 2026-05-03. FRP-5 gate verdict: **PASS** after readiness correction. Commits: 2224208 (0/4 spec), 152b05c (1/4 provider+profile+opsec), 5b1b4ea (2/4 cloudinit+shim+manifest), fd28be7 (3/4 hetzner+health+daal-relay-health), 667e339 (4/4 cli+daal-deploy+handover). See `docs/handovers/frp-4a-handover.md`.
**Roadmap line:** *"`publisher/deploy/` Go package + `Provider` interface + Hetzner implementation. `publisher/deploy/cli/` CLI wrapper. Cloud-init template with pinned, signed artefacts (§9.2) and hardened health endpoint (§9.6)."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — Helper-side tooling).**
**ABI release surface target:** **48** **(UNCHANGED — all work is in the publisher tree, not the engine).**
**Maturity:** code phase. Lands the operator-side deploy substrate the wizard (FRP-5) will later drive.
**Predecessor:** Phase 31 (FRP-3) — selector substrate exists; FRP-4a needs it primarily for the `Explanation` shape that the deploy CLI's dry-run output references.
**Successor:** Phase 33 (FRP-5) — wizard generates publisher key + OperatorRecord; binds back at FRP-4b.

## 1. Strategic frame (verbatim from the supplement)

> **§9 Cloud-init: pinned, signed, no third-party relay-artifact fetches at boot.** All Daal relay artifacts are fetched as pinned, Ed25519-signed, hash-verified blobs from Daal-controlled signed mirrors. The verifier shim (~50 lines, `bash + python3 + openssl`) is the only boot-time code that runs before signature verification has been performed.
>
> **§9.6 Health endpoint.** Hardened: one-time-token + IP-bound + auto-close. The Helper polls the box once over the provisioning window via the `daal-relay-health` binary; box-side ufw rule limits the health port to the Helper IP for 60 s; auto-close at the end of the window via systemd timer; in-binary 300 s self-shutdown as belt-and-braces.
>
> **§11 Protocol toolbox — what one VPS can host, honestly.** First-class transport families with `family_class: vps-native`: VLESS-Reality, websocket-tls, naive, hysteria2, TUIC, WireGuard, AmneziaWG. Used by the `iran-default` toolbox profile.

FRP-4a's job is to land the deploy substrate end-to-end **without binding to the wizard's publisher key**. It ships: the `Provider` interface, the Hetzner implementation, the pinned cloud-init template (`§9.3` YAML), the verifier-shim embedded in the YAML, the hardened health endpoint and its 60 s auto-close, the SSH self-destruct (`§9.3` ssh_authorized_keys cleanup), and the CLI wrapper. **No publisher key is generated here**; that's FRP-5. **No RelayPack is signed here**; that's FRP-4b. FRP-4a is the foundation FRP-4b binds to once the wizard exists.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Go-module root for `publisher/` | **Reused, NOT created here.** `publisher/go.mod` (module `daal/publisher`) was created at FRP-1 and remains the single publisher tooling module even though the RelayPack validator moved to `bundle/go/relaypackvalidate/` at FRP-2. FRP-4a extends the same module with `publisher/deploy/{provider,cloudinit,health,cli}/` subpackages. No new `go.mod` files. The publisher module imports `daal/bundle-go` (signing, types) and MAY import `daal/core` only via its own narrow needs (e.g. `core/abi` constants for build-stamping); `daal/bundle-go` and `daal/core` MUST NOT import `daal/publisher` (asymmetric: publisher is downstream of both). CI-equivalent build command for the publisher module is `cd publisher && go build ./...` (NOT `go build ./publisher/...` from the repo root, which would not resolve). |
| Package layout | `publisher/deploy/` (top-level inside the new `publisher/` module), with subpackages `provider/`, `provider/hetzner/`, `cloudinit/`, `health/`, `cli/`. All net-new at FRP-4a. |
| Provider interface | `type Provider interface { Provision(ctx, opts) (*OperatorRecord, error); Reprovision(...) error; Decommission(...) error; AssignFloatingIP(...) error; Pricing() (...); }` (locked shape in §5 below). |
| First adapter | Hetzner (`provider/hetzner/`). Uses `hetznercloud/hcloud-go/v2`. Other providers are FRP-10. |
| Cloud-init template language | YAML with Go `text/template` placeholders. Verbatim shape from supplement §9.3. |
| Verifier shim | Embedded in YAML `write_files`. `bash + python3 + openssl`. Source bytes pinned in `cloudinit/shim.sh.tmpl`; YAML-embeds it via Go template. Round-trip-tested. |
| Pinned artefact manifest source | `publisher/deploy/cloudinit/artifacts.go` carries the V1.5 V1.5 artefact set as compile-time constants: release name, install_as, sha256, signature, mirrors. The artefact set is updated by hand on each release; verification at boot is signature-based. |
| Health endpoint shape | One-time token in URL path; IP-bound (firewall + binary check); 300 s in-binary auto-shutdown; ufw rule auto-close at 60 s post-service via systemd timer. Per supplement §9.6. |
| SSH self-destruct | Implemented in cloud-init `runcmd` block. Window: 60 s post-`systemctl enable --now`. Removes ephemeral `authorized_keys`, disables `sshd`, closes 22/tcp via `ufw --force delete`. Per supplement §9.3 v2.3.3 hardening. |
| `daal` system user | `nologin`, `lock_passwd: true`, `sudo: false`. Owns sing-box runtime files only. Per supplement §9.3 v2.3.3 hardening. |
| Toolbox profiles at V1.5 | `iran-default` only. Profile is data, not code: a JSON file at `publisher/deploy/profiles/iran-default.json` listing the candidate set the wizard offers. |
| OperatorRecord schema | Defined here as a Go struct (`type OperatorRecord struct { ... }`); the SQLite persistence layer lives at FRP-5 (it's wizard-side). FRP-4a's CLI emits OperatorRecords as JSON for FRP-5 to consume. |
| CLI command set | `daal-deploy version`, `daal-deploy provision`, `daal-deploy verify`, `daal-deploy decommission`, `daal-deploy floating-ip {assign,unassign}`, `daal-deploy assign-fip` (legacy alias), `daal-deploy pricing`. CLI is the dry-run / scripted surface; FRP-5 wraps it via Tauri commands. |
| RelayPack signing | NOT here. FRP-4b binds publisher key + signs the RelayPack. FRP-4a's CLI emits unsigned candidate metadata for FRP-4b to consume. |
| Telemetry | None. CLI never opens a connection to anything except the cloud provider's own API and the box's health endpoint. Verified by `opsec_test.go`. |
| Determinism | Provisioning is idempotent at the level of `Reprovision`: re-running on the same `OperatorRecord` recovers state without creating duplicates. Cloud-init template is deterministic in output for fixed inputs (signed YAML hash). |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **No engine release symbols added.** ABI count stays 48; `publisher/deploy/` is Helper-side tooling.
18. **Cloud-init artefact list is pinned.** No live `apt-get install sing-box` style step. Per supplement §9.1.
19. **Verifier shim uses only base-image tools.** `bash + python3 + openssl`. Per supplement §9.2.1. No bootstrap binary downloaded before signature verification.
20. **No standing SSH surface post-provisioning.** `sshd` disabled; 22/tcp closed; ephemeral key removed. Per supplement §9.5.1 (post-v2.3.3).
21. **Health endpoint auto-closes.** ufw rule deleted by systemd timer at +60 s post-service; in-binary 300 s self-shutdown is belt-and-braces. Per supplement §9.6.
22. **Position B preserved.** No telemetry, no project-controlled probes, no inference about the FRP. Verified by OPSEC test.
23. **Provider interface is the contract.** Vultr/Stark adapters at FRP-10 implement the same interface; the wizard's deploy step is provider-agnostic.
24. **No publisher key generation here.** FRP-4a's CLI accepts a publisher pubkey as input (for embedding in the artefact manifest if needed) but never creates one. FRP-5's job.
25. **OperatorRecord JSON is the wire shape.** FRP-5 consumes the same JSON FRP-4a emits; the SQLite schema at FRP-5 stores it as JSONB or column-by-column. Either is acceptable.
26. **No RelayPack signing.** FRP-4a writes the candidate metadata to a file; FRP-4b reads, signs with the publisher key, and emits the `.sbp`.
27. **Toolbox profiles are data.** `iran-default.json` and any future profile can be edited without recompiling Daal (profile loader is `publisher/deploy/profiles/loader.go`).
28. **`daal/publisher` module reused, NOT created here.** `publisher/go.mod` was created at FRP-1 and remains the single publisher tooling module after the RelayPack validator moved to `bundle/go/relaypackvalidate/` at FRP-2. FRP-4a extends the same module with `publisher/deploy/{provider,cloudinit,health,cli,profiles}/` subpackages; FRP-11 (`publisher/cell/`), FRP-12 (`publisher/deploy/modifiers/`), and FRP-13 (`publisher/directory/`) also reuse it. No nested `go.mod` files. The repo deliberately has no root `go.mod` and no `go.work`; each top-level module (`bundle/go/`, `core/`, `cmd/<binary>/`, `publisher/`) is built from its own root with `cd <root> && go build ./...`. Dependency direction: `publisher → bundle` and `publisher → core`; **`bundle/` and `core/` MUST NOT import `daal/publisher`** (asymmetric).

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-4a stub with this locked spec at `phases of development/32-phase-frp-4a-publisher-deploy-core.md`. |
| 1  | Read inputs end-to-end: supplement §9, §10, §11, §11.1, §11.4, §11.5, §11.7 (read-only — V1.6 implementation guidance only); FRP-0 handover §"Per-module matrix" entry for `publisher/deploy/`; existing `bundle/go/publisher/` for tonal reference; existing `bundle/go/go.mod` and `core/go.mod` for replace-directive pattern. |
| 1.5| **Confirm `publisher/go.mod` already exists** (created at FRP-1 sub-task 6.5; module path `daal/publisher`). `cd publisher && go mod tidy` after adding the new `publisher/deploy/` subpackages so the module's dep graph stays clean. NO new `go.mod` files. NO conversion to a workspace. |
| 2  | Author `publisher/deploy/provider/provider.go` with the `Provider` interface (§5 below). Author `publisher/deploy/provider/types.go` with `OperatorRecord`, `ProvisionOpts`, `Pricing` types. |
| 3  | Author `publisher/deploy/provider/hetzner/`: `provider.go` implementing the interface; `client.go` wrapping `hcloud-go/v2`. Use `client.Server.Create` + `client.SSHKey.Create` + `client.FloatingIP.Create` per supplement §9 timeline. |
| 4  | Author `publisher/deploy/cloudinit/`: `template.go` (Go `text/template` rendering of supplement §9.3 YAML); `shim.sh.tmpl` (verbatim from supplement §9.2.1, ~50 lines); `artifacts.go` (V1.5 pinned artefact manifest as compile-time constants per §2); `template_test.go` (golden-file tests against an expected YAML snapshot per locked input set). |
| 5  | Author `publisher/deploy/health/`: `health.go` (Helper-side polling logic — token, IP, port, deadline); `endpoint.go` (the `daal-relay-health` binary's HTTP handler shape, for tests). The actual `daal-relay-health` binary is built separately from the same repo; FRP-4a builds it under `cmd/daal-relay-health/` per supplement §9.2 artefact list. |
| 6  | Author `cmd/daal-relay-health/main.go`. Tiny HTTP server: serves `GET /healthz/<token>` for IPs matching the configured Helper IP; auto-shuts down at 300 s per supplement §9.6. |
| 7  | Author `publisher/deploy/profiles/`: `loader.go`; `iran-default.json` (the V1.5 toolbox profile — full set of `vps-native` candidates per supplement §11.5). |
| 8  | Author `cmd/daal-deploy/main.go` — CLI wrapper. Subcommands per §2 above. Each subcommand emits structured JSON (or `--quiet` plain output) so FRP-5's wizard can shell out and parse. |
| 9  | Author `publisher/deploy/opsec_test.go`: forbidden network call grep (only allowed: `hetznercloud/hcloud-go`, the box's own health endpoint, the pinned-artefact mirrors at runtime *on the box, not on the Helper*); never `http.Post` from the Helper to a project endpoint. |
| 10 | Idempotence test: provision twice with the same `OperatorRecord`; second call is a no-op. Decommission is idempotent. FloatingIP assign/unassign is idempotent. |
| 11 | Cloud-init smoke test: render the YAML against fixture inputs; verify the output round-trips through `yaml.Unmarshal` cleanly; verify each `write_files` entry has the expected hash; verify the verifier-shim source matches the pinned bytes. |
| 12 | Final regression sweep: `cd publisher && gofmt -l ./...`; `cd publisher && go build ./...`; `cd publisher && go test ./...`; `cd cmd/daal-deploy && go build ./...`; `cd cmd/daal-relay-health && go build ./...`; `nm` returns 48; FRP-5 gate verdict; handover. |

## 5. `Provider` interface (locked)

```go
package provider

type Provider interface {
    // Provision creates a new VPS, runs the cloud-init, polls health,
    // self-destructs SSH, and returns an OperatorRecord. The publisher
    // key is supplied by the caller (FRP-5's wizard); FRP-4a does not
    // generate it.
    Provision(ctx context.Context, opts ProvisionOpts) (*OperatorRecord, error)

    // Reprovision rebuilds the box according to the OperatorRecord's
    // toolbox profile, with new credentials. Used by direct-mode
    // rotation L1/L2/L4/L5/L6 at V1.5. Idempotent.
    Reprovision(ctx context.Context, rec *OperatorRecord, opts ReprovisionOpts) error

    // Decommission deletes the VPS and any associated cloud resources.
    // Idempotent (safe to retry).
    Decommission(ctx context.Context, rec *OperatorRecord) error

    // AssignFloatingIP attaches a floating IP to the OperatorRecord's
    // server, swapping a previous one out. Implements direct-mode L3
    // (~10 s wall-clock per supplement §14.1).
    AssignFloatingIP(ctx context.Context, rec *OperatorRecord, fipID string) error

    // Pricing returns the current per-hour cost in EUR for the
    // OperatorRecord's server type, fetched live from the provider.
    // Used by the wizard's cost-disclosure screen.
    Pricing(ctx context.Context, rec *OperatorRecord) (Pricing, error)
}

type ProvisionOpts struct {
    PublisherPubKey []byte             // Ed25519 pubkey from FRP-5's wizard
    Region          string             // e.g. "fsn1" (Hetzner Falkenstein)
    ServerType      string             // e.g. "cx22" (Hetzner cheapest)
    ToolboxProfile  string             // "iran-default"
    HelperIP        net.IP             // for the IP-bound health endpoint
    EphemeralSSHKey ed25519.PrivateKey // for the 60 s provisioning window
}

type ReprovisionOpts struct {
    NewToolboxProfile string  // for L6 protocol-mix change; "" = unchanged
    NewSNI            string  // for L2 SNI change; "" = unchanged
    NewWSPath         string  // for L2 path change; "" = unchanged
    RegenCredentials  bool    // for L1 credential regen
}

type OperatorRecord struct {
    Provider        string             `json:"provider"`         // "hetzner"
    ServerID        string             `json:"server_id"`
    ServerType      string             `json:"server_type"`
    Region          string             `json:"region"`
    PublicIP        net.IP             `json:"public_ip"`
    PublicIPv6      net.IP             `json:"public_ipv6,omitempty"`
    FloatingIPID    string             `json:"floating_ip_id,omitempty"`
    ToolboxProfile  string             `json:"toolbox_profile"`
    PublisherPubKey []byte             `json:"publisher_pub_key"` // Ed25519
    Candidates      []CandidateMeta    `json:"candidates"`        // unsigned; FRP-4b signs
    ProvisionedAt   time.Time          `json:"provisioned_at"`
    LastReprovisionedAt *time.Time     `json:"last_reprovisioned_at,omitempty"`
}

type CandidateMeta struct {
    Family            string   `json:"family"`             // vless-reality | websocket-tls | ...
    ExposureMode      string   `json:"exposure_mode"`      // V1.5: always "direct_vps"
    FamilyClass       string   `json:"family_class"`       // "vps-native"
    ProbingRiskClass  string   `json:"probing_risk_class"`
    Port              int      `json:"port"`
    Params            json.RawMessage `json:"params"`      // family-specific
    PublicRiskTags    []string `json:"public_risk_tags"`
    OriginRiskTags    []string `json:"origin_risk_tags"`   // empty for direct_vps
}
```

## 6. Cloud-init template (locked, derived from supplement §9.3)

The full YAML template lives at `publisher/deploy/cloudinit/template.yaml.tmpl`. Critical sections preserved verbatim:

- `packages:` — `curl, ca-certificates, openssl, python3, ufw` (per v2.3.2 fix)
- `users:` — `daal` system user with `nologin`, `lock_passwd: true`, `sudo: false`
- `ssh_authorized_keys:` — root-attached ephemeral key (per v2.3.3 hardening)
- `write_files:` — pinned artefact manifest, release pubkey, verifier shim (~50 lines from §9.2.1)
- `runcmd:` — verifier shim invocation, systemd unit enable, **60 s SSH self-destruct timer**, `ufw --force delete` of port 22 (per v2.3.3)

Helper renders the template against `ProvisionOpts`; the rendered YAML is uploaded as `UserData` to Hetzner; the box runs cloud-init at first boot; the Helper polls `/healthz/<token>` until success or deadline.

## 7. `iran-default` toolbox profile (locked at FRP-4a)

Per supplement §11.5. The profile is a JSON file the wizard renders into checkbox UI. V1.5 set:

```json
{
  "name": "iran-default",
  "description": "Default candidate mix for Iranian network conditions, V1.5 direct-VPS only.",
  "candidates": [
    {"family": "vless-reality",   "default_enabled": true,  "probing_risk_class": "low",      "udp_gated": false},
    {"family": "websocket-tls",   "default_enabled": true,  "probing_risk_class": "low",      "udp_gated": false},
    {"family": "naive",           "default_enabled": true,  "probing_risk_class": "low",      "udp_gated": false},
    {"family": "hysteria2",       "default_enabled": true,  "probing_risk_class": "low",      "udp_gated": true},
    {"family": "tuic",            "default_enabled": false, "probing_risk_class": "moderate", "udp_gated": true},
    {"family": "wireguard",       "default_enabled": false, "probing_risk_class": "moderate", "udp_gated": true},
    {"family": "amnezia-wg",      "default_enabled": false, "probing_risk_class": "moderate", "udp_gated": true}
  ]
}
```

V1.6 will add `cdn_fronted` candidates to this profile via a separate edit at FRP-8.

## 8. Build matrix at FRP-4a exit

```
$ ls publisher/go.mod                                            # exists; module path daal/publisher
$ cd publisher && gofmt -l ./...                                 # no output
$ cd publisher && go build ./...                                 # green (NOT `go build ./publisher/...` from repo root — there is no root go.mod)
$ cd publisher && go test ./...                                  # green
$ cd cmd/daal-deploy && go build ./...                          # green (its own module per existing cmd/<binary>/go.mod pattern)
$ cd cmd/daal-relay-health && go build ./...                    # green
$ /tmp/daal-deploy version                                      # exists; reports version
$ /tmp/daal-deploy pricing --provider hetzner --region fsn1 --server-type cx22 --token-file /tmp/hetzner.token
   # accepts FRP-5 cost-disclosure shape; live call requires token
$ /tmp/daal-deploy provision --dry-run --provider hetzner --region fsn1 --server-type cx22 --toolbox iran-default --helper-ip 1.2.3.4 --pubkey /tmp/test.pub
   # emits OperatorRecord JSON to stdout; no API call
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l           # 48 (UNCHANGED)
$ # OPSEC grep: no calls outside permitted set
$ git grep -nE 'http\.Post|http\.Get|net\.Dial' publisher/deploy/ | grep -v '_test.go' | grep -v hcloud
   # output limited to vetted matches
```

## 9. Spec deliverables

**1 NEW (skeleton; full content at FRP-5 + FRP-4b):**
- `docs/family-relay-publisher-v1.md` — operator-facing deploy docs. FRP-4a writes the deploy-core / CLI sections; FRP-5 adds the wizard sections; FRP-4b adds the end-to-end flow.

**1 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"Helper-side production" cross-reference describing how candidate metadata flows from `publisher/deploy/` to RelayPack signing.

## 10. Out of scope (deferred)

- Publisher key generation — **FRP-5.**
- OperatorRecord SQLite persistence — **FRP-5.**
- RelayPack signing — **FRP-4b.**
- Wizard UI — **FRP-5.**
- QR handoff — **FRP-5.**
- `cdn_fronted` deploy path (Cloudflare provisioning) — **FRP-8.**
- Vultr / Stark adapters — **FRP-10.**
- In-box mgmt API for L1/L2 fast path — **FRP-10 (V2 §9.5.2).**
- Freshness endpoint static-host upload — **FRP-8.**

## 11. Handover requirements

The FRP-4a handover must contain:

1. Status: SHIPPED. Date.
2. New file paths under `publisher/deploy/`.
3. CLI command list with `--help` output captured.
4. Cloud-init YAML template hash (so FRP-8 can prove it amended cleanly).
5. `iran-default.json` content hash.
6. Dry-run `provision` invocation with sample OperatorRecord output.
7. OPSEC grep result.
8. `nm` count = 48 unchanged.
9. FRP-5 gate verdict.
10. Open follow-ups: any wizard bridge surface FRP-5 will need that the CLI doesn't yet emit.

## 12. Track ordering rationale

FRP-4a before FRP-5 because the wizard is a thin UI on top of the deploy substrate. Building the wizard against a stub provider would let UI choices accidentally constrain the data model; building the deploy substrate first means the wizard binds to a stable contract. FRP-4a deliberately stops short of binding the publisher key — that's the cleanest split between "deploy-the-VPS" (4a) and "sign-the-RelayPack-with-the-key" (4b), and it lets FRP-5's wizard choose key custody (OS keystore + PIN-derived AES-GCM) without that decision leaking into the deploy core.

End — locked at FRP-track planning. Next: FRP-5 (desktop wizard).
