# Phase 34 (FRP-4b) — Direct-Mode Deploy Integration

**Status:** SHIPPED 2026-05-03 (commits 6f1f845, d61abd5, a801cdb, 4fab988, 70a6951, 0c0f299, plus post-ship readiness correction). Handover at [`docs/handovers/frp-4b-handover.md`](../docs/handovers/frp-4b-handover.md).
**Roadmap line:** *"V1.5 — FRP MVP (direct-VPS only). RelayPack profile shipped with `iran-default` toolbox profile, all candidates `exposure_mode: direct_vps`."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — Helper-side bind).**
**ABI release surface target:** **48** **(UNCHANGED).**
**Maturity:** integration phase. Glues FRP-5's keys to FRP-4a's deploy substrate; signs the direct-mode RelayPack end-to-end.
**Predecessor:** Phase 33 (FRP-5) — wizard shell ready; publisher keypair + pre-provision OperatorRecord written; screens 4–6 are disabled shells awaiting wire-up.
**Successor:** Phase 35 (FRP-6) — recipient UX consumes the signed RelayPack.

## 1. Strategic frame (verbatim from the supplement)

> **§3.2 Per-candidate metadata is carried inside the existing `RouteManifestEntry.FamilySpecificConfig` `json.RawMessage` slot as a `_relaypack` sub-object so the bytes round-trip through old parsers' canonicalisation cleanly.**
>
> **§21.1 V1.5 — FRP MVP (direct-VPS only).** All candidates `exposure_mode: direct_vps` at V1.5.
>
> **§22.1 V1.5 success metric.** A diaspora user in Berlin who has never used Hetzner before installs Daal desktop, opens the wizard, and has a working RelayPack provisioned within 10 minutes.

FRP-4b's job is the **live integration** step. It does three things FRP-5's shell deliberately did not:

1. **Wires screen 4 (Provisioning progress) live.** Reads FRP-5's pre-provision OperatorRecord; runs `daal-deploy provision` via the FRP-4a CLI; updates the OperatorRecord status to `provisioned`; surfaces progress to the screen 4 UI.
2. **Wires screen 5 (RelayPack signing) live.** Reads the unsigned candidate metadata FRP-4a's CLI emitted; signs each candidate's `_relaypack` sub-object with the publisher key (FRP-5 generated); builds the bundle-level `Manifest.relay_pack` slot (per FRP-1's schema); bakes the `.sbp` deterministically; runs FRP-1's validator with `Phase: V15`; emits the signed `.sbp` to the staging directory.
3. **Wires screen 6 (RelayPack handoff) live.** Renders the QR-fountain over the signed `.sbp` (per `specs/qr-fountain-v1.md`); shows the bundle's SHA-256 fingerprint + EN/FA wordlists below the QR; the "Rotate" button stays a disabled shell here (FRP-7 wires that).

This is the live path the FRP-5 shell screens were holding space for. The split (FRP-5 shell → FRP-4b live wire) preserves the `4a → 5 → 4b` track ordering and matches the user's blocker-2 correction.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Binder location | `publisher/deploy/relaypack/` (new subpackage). Sibling of `publisher/deploy/cloudinit/` (FRP-4a). |
| Binder API | `func BindAndSign(rec *provider.OperatorRecord, privKey ed25519.PrivateKey, opts BindOpts) (*bundle.Bundle, error)`. Pure function over locked inputs. |
| `relay_pack_id` derivation | SHA-256 over `(provider, server_id, region, public_ip, sorted candidate family set)` truncated to 16 bytes hex with `rp-` prefix. Deterministic; stable under candidate reordering; changes when the VPS or candidate family set changes. |
| `shared_risk_graph` derivation | Computed from candidates' `public_risk_tags[]` per supplement §12.3. Helper computes; signed inside the bundle. |
| `freshness_url` value | Empty string at V1.5. FRP-8 sets the actual URL. |
| Signing | Reuse `bundle.BuildSignedBundleDeterministic` from `bundle/go/bundle`; FRP-4b only adds the RelayPack-aware preprocessing step. `publisher/deploy/relaypack/` must not import `core/` or `bundle/go/publisher/`. |
| Determinism | Same OperatorRecord + same privkey + same `Now` ⇒ byte-identical `.sbp`. Verified by round-trip test. |
| Validator integration | FRP-4b calls FRP-1's validator with `Phase: V15` BEFORE signing. Any validator error stops the bind; the wizard surfaces the error to the FRP. |
| Lint warnings | FRP-1's `LintReport` is propagated up to the wizard for FRP-side display; not a hard reject. |
| RelayPack fingerprint disclosure | Screen 6 shows the bundle's SHA-256 fingerprint + EN/FA wordlists; FRP-4b includes those in its return value so the wizard doesn't recompute. |
| Where the `.sbp` is written | Staging directory (`~/.config/daal/staging/{relay_pack_id}.sbp`). FRP-4b writes; the live screen-6 renderer reads from here. |
| Wizard files updated at FRP-4b | `client-desktop/tauri/src-tauri/src/wizard/cli_bridge.rs` (extends with `provision` + `bind-and-sign` subcommand calls); `client-desktop/tauri/src/wizard/screen4.tsx` (provisioning live); `client-desktop/tauri/src/wizard/screen5.tsx` (signing live); `client-desktop/tauri/src/wizard/screen6.tsx` (QR-fountain live). The shell layouts FRP-5 produced are filled in, not replaced. |
| Telemetry | None. Verified by reuse of FRP-4a's OPSEC test. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **No engine release symbols added.** ABI count stays 48.
18. **`BindAndSign` is a pure function.** Inputs in, bytes out; no global state, no I/O outside the staging-directory write.
19. **FRP-1 validator runs before signing.** Bundle never gets signed if validation fails.
20. **`freshness_url` field is present in the bundle but empty at V1.5.** Round-trips canonically.
21. **`shared_risk_graph` is signed.** It's part of the canonical payload; FRPs cannot un-sign-and-edit.
22. **Determinism property tested.** Round-trip test verifies byte-identical output for fixed inputs (modulo the `Now` parameter which the test pins). |
23. **Wizard never sees the privkey.** The privkey is loaded from the keystore in a Tauri command, passed by-reference to FRP-4b's binder via the Rust-Go bridge, used transiently, zeroed on return. The Go binder receives a `[]byte` slice; the Rust caller zeroes it on the Rust side after the call.
24. **OperatorRecord cloud identity is preserved.** FRP-4b updates the local wizard DB from `pre-provision` to `provisioned` and records signed-SBP metadata, but it does not mutate the provisioned VPS identity or perform rotation. Rotation mutations are FRP-7's job.
25. **Position B preserved.** No telemetry; no signing service.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-4b stub with this locked spec at `phases of development/34-phase-frp-4b-direct-deploy-integration.md`. |
| 1  | Read inputs end-to-end: FRP-1 (`relay_pack.go` schema), FRP-4a (`OperatorRecord`, `CandidateMeta`), FRP-5 (wizard staging path); supplement §3.2, §12.2, §12.3. |
| 2  | Author `publisher/deploy/relaypack/binder.go` implementing `BindAndSign(rec, privKey, opts) (*bundle.Bundle, error)`. |
| 3  | Author `publisher/deploy/relaypack/risk_graph.go` computing the `shared_risk_graph` from `[]CandidateMeta`. Per supplement §12.3 — derives edges from each candidate's `public_risk_tags`. |
| 4  | Author `publisher/deploy/relaypack/relay_pack_id.go` deriving the deterministic ID per §2 above. |
| 5  | Wire FRP-1 validator: call `validator.Validate(b, ValidateOpts{Phase: V15})` before signing; on error, return the error wrapped with context; on success, propagate the `LintReport` in the binder return value. |
| 6  | Wire `bundle.BuildSignedBundleDeterministic` for the actual signature step. Confirm the deterministic builder from 1A still produces byte-identical output when the new `relay_pack` slot is present. |
| 7  | Author `publisher/deploy/relaypack/binder_test.go`. ≥10 tests: deterministic round-trip; validator-error halts bind; lint-warning propagated; `relay_pack_id` deterministic; `shared_risk_graph` correctly derived; empty `freshness_url` round-trips; multiple candidates produce single bundle; signature verifies. |
| 8  | Extend `client-desktop/tauri/src-tauri/src/wizard/cli_bridge.rs` to invoke `daal-deploy provision` and `daal-deploy bind-and-sign` subcommands. (FRP-5 left this stub with only `pricing` wired.) |
| 9  | Add `daal-deploy bind-and-sign --operator-record <path> --priv-key <fd> --output <path>` subcommand. Reads OperatorRecord JSON; reads privkey from a file descriptor (so the wizard can pipe without writing to disk); writes the signed `.sbp` to the output path. |
| 10a | Wire screen 4 (Provisioning progress) live: invokes `daal-deploy provision` via `cli_bridge`; updates SQLite `operators.status` from `pre-provision` to `provisioned`; surfaces real-time progress to UI. |
| 10b | Wire screen 5 (RelayPack signing) live: reads provisioned OperatorRecord; invokes `daal-deploy bind-and-sign`; surfaces lint warnings from FRP-1 in a small "FRP info" banner; hard-stop on validator error with a "Fix and retry" button. |
| 10c | Wire screen 6 (RelayPack handoff) live: reads the signed `.sbp` from the staging directory; renders QR-fountain via `specs/qr-fountain-v1.md` JS lib (existing); shows fingerprint EN/FA wordlists below the QR; the "Rotate" button stays a disabled shell (FRP-7 wires that). |
| 11 | End-to-end smoke test: run `daal-deploy provision --dry-run` (FRP-4a), pipe the resulting OperatorRecord into `daal-deploy bind-and-sign` with a test keypair, verify the resulting `.sbp` parses with `bundle.ParseSBP` (the actual symbol in `bundle/go/bundle/sbp.go`) and validates with `validator.Validate`. |
| 12 | Final regression sweep: `cd publisher && go build ./deploy/relaypack/... && go test ./deploy/relaypack/...`; `cd cmd/daal-deploy && go build ./...`; `nm` returns 48; FRP-6 gate verdict; handover. |

## 5. `BindAndSign` API (locked)

```go
package relaypack

type BindOpts struct {
    Now              time.Time     // for deterministic builds and bundle.created_at
    Expiry           time.Duration // bundle validity window
    Phase            string        // "V15" / "V16" — validator phase
    FreshnessURL     string        // empty at V1.5; populated at V1.6
}

type BindResult struct {
    Bundle           *bundle.Bundle
    BundleSHA256     string
    FingerprintHex   string
    FingerprintEN    string  // EN wordlist
    FingerprintFA    string  // FA wordlist
    LintReport       publisher.LintReport // from FRP-1 validator
    RelayPackID      string
    SharedRiskGraph  []bundle.SharedRiskEdge
}

// BindAndSign reads an OperatorRecord (FRP-5 produced), reads each candidate's
// metadata (FRP-4a populated), enriches each with the FRP-1 _relaypack sub-
// object, builds the bundle-level Manifest.relay_pack slot, runs the FRP-1
// validator with the supplied Phase, and signs the result with privKey.
//
// Returns a BindResult on success. On validator error, returns nil + error;
// LintReport is populated and propagated up.
//
// Deterministic: same inputs ⇒ byte-identical bundle output.
func BindAndSign(rec *provider.OperatorRecord, privKey ed25519.PrivateKey, opts BindOpts) (*BindResult, error)
```

## 6. `shared_risk_graph` derivation (locked)

```
For each candidate c in rec.Candidates:
  For each tag t in c.PublicRiskTags:
    edges[t] = edges[t] ∪ {c.id}

For each tag t with |edges[t]| ≥ 2:
  emit SharedRiskEdge{Tag: t, Members: sorted(edges[t])}

Output: list sorted by tag for canonical determinism.
```

The graph is the same data the selector at FRP-3 reads (per supplement §12.3); pre-computing it at sign time saves the recipient's selector from re-deriving it.

## 7. Build matrix at FRP-4b exit

```
$ cd publisher && gofmt -l ./deploy/relaypack/                  # no output
$ cd publisher && go build ./deploy/relaypack/...               # green (under daal/publisher module)
$ cd publisher && go test ./deploy/relaypack/...                # ≥10 tests
$ cd cmd/daal-deploy && go build ./...                          # green (its own module)
$ /tmp/daal-deploy bind-and-sign --help                          # subcommand exists
$ # E2E smoke
$ /tmp/daal-deploy provision --dry-run --provider hetzner --region fsn1 --server-type cx22 --toolbox iran-default --helper-ip 1.2.3.4 --pubkey /tmp/test.pub > /tmp/op.json
$ /tmp/daal-deploy bind-and-sign --operator-record /tmp/op.json --priv-key /tmp/test.priv --output /tmp/test.sbp
$ /tmp/daal-publish verify /tmp/test.sbp                         # green
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l            # 48 (UNCHANGED)
$ # Determinism
$ /tmp/daal-deploy bind-and-sign --operator-record /tmp/op.json --priv-key /tmp/test.priv --output /tmp/test1.sbp --now-unix 1746230000
$ /tmp/daal-deploy bind-and-sign --operator-record /tmp/op.json --priv-key /tmp/test.priv --output /tmp/test2.sbp --now-unix 1746230000
$ sha256sum /tmp/test1.sbp /tmp/test2.sbp                         # identical
```

## 8. Spec deliverables

**1 AMENDED:**
- `docs/family-relay-publisher-v1.md` — gains an end-to-end deploy + bind + sign flow section.
- `specs/relaypack-v1.md` — gains a §"Helper-side bind path" cross-reference describing how `BindAndSign` enriches candidates and computes the risk graph.

## 9. Out of scope (deferred)

- Rotation logic (`Reprovision`, floating-IP swap UI) — **FRP-7.**
- `cdn_fronted` candidate enrichment — **FRP-8.**
- Cell-aware bind — **FRP-11.**
- Modifier carry-through — **FRP-12.**
- Mobile binder (FRP wizard on Android) — V2.

## 10. Handover requirements

The FRP-4b handover must contain:

1. Status: SHIPPED. Date.
2. New file paths under `publisher/deploy/relaypack/`.
3. CLI subcommand `bind-and-sign` `--help` output.
4. Determinism test result.
5. End-to-end smoke output.
6. Validator integration verified (test where validator error halts bind).
7. `nm` count = 48 unchanged.
8. FRP-6 gate verdict.

## 11. Track ordering rationale

FRP-4b is short and integration-shaped because the heavy lifting was already done in FRP-1 (validator), FRP-4a (deploy substrate), and FRP-5 (wizard + key custody). Putting the bind step in its own phase (rather than rolling it into FRP-4a or FRP-5) means the binder is a pure function with a locked test surface, and any future bind variants (V1.6 CDN-aware bind at FRP-8, cell-aware bind at FRP-11) can extend the same surface without disturbing FRP-4a or FRP-5.

End — locked at FRP-track planning. Next: FRP-6 (recipient UX).
