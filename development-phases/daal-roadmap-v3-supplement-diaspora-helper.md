# Daal — Roadmap Supplement: The Family Relay Publisher

*A roadmap supplement to `daal-roadmap-v3.md` describing Daal's bottom-up route-supply architecture, in which trusted diaspora Iranians become **Family Relay Publishers** (FRPs) producing signed multi-candidate **RelayPacks** for their relatives in Iran. Daal remains the configurator and the local selection brain; it never becomes a merchant, never holds money or credentials on its own server, and never claims to know in advance which protocol will work on which Iranian network.*

**Supplement version:** 2.3.12 · **Drafted:** May 2026 · **Supersedes:** v1, v2, v2.1, v2.2, v2.3, v2.3.1, v2.3.2, v2.3.3, v2.3.4, v2.3.5, v2.3.6, v2.3.7, v2.3.8, v2.3.9, v2.3.10, v2.3.11 · **Targets:** V1.5 (FRP MVP, direct-VPS only), **V1.6 (CDN milestone)**, V2 (trusted cells + federation primitives + multi-provider + cloud-provider-firewall mgmt API + per-modifier framework), V3 (gated public directory — gate-evaluation framework SHIPPED at FRP-13; implementation post-track and gated)

> **v2.3.11 → v2.3.12 patch notes (FRP-13 gate-evaluation lock; one new subsection, no architecture change).** FRP-13 ships **only the gate-evaluation framework**, not the public-directory implementation. Eight commits land: the canonical contract `specs/public-directory-v1.md` Status: GATED (commit 1); the closure-record template `specs/public-directory-closure-v1.md` HOLD (commit 2); the machine-readable gate spec `specs/public-directory-gate-v1.md` carrying the six §17.2 conditions + five §22.4 thresholds verbatim, all status HOLD at ship (commit 3); the `cmd/daal-gate-eval` CLI consuming the gate spec + cell-closure status, with a hardened test suite (commit 4); the per-quarter audit-trail directory `specs/public-directory-gate-history/` with first entry `2026-Q2.md` recording the FRP-13-ship HOLD evaluation (commit 5); the operational process at `docs/public-directory-gate-evaluation.md` (commit 6); the phase-doc + frp-track-v1.md flips + this supplement bump + new §17.6 (commit 7); the FRP-track-terminator handover (commit 8). v2.3.12 adds **§17.6 — FRP-13 gate-evaluation lock** documenting the ten locked answers (gate-evaluation-framework-only scope; cell-closure HOLD preserved; no `publisher/directory/` package at FRP-13; recipient-fallback architectural-only; verbatim re-statement of §17.2 conditions; CLI both text + JSON output; quarterly history at `gate-history/`; status flip wording 'SHIPPED — gate-evaluation only'; FRP-track terminates at FRP-13; cell-closure cross-reference) plus eight new locked invariants (48–55). No `spec_version` bump (stays at 4); no engine ABI change (stays at 48); no `engine_*` C-shared symbols added; no `core/` change; no `bundle/go/` change; no validator code change.

> **v2.3.10 → v2.3.11 patch notes (FRP-12 modifier-framework implementation lock; one new subsection, no architecture change).** FRP-12 ships the per-modifier validator framework that conditionally lifts FRP-1's RP013 hard-reject for `_relaypack.modifiers[]`. **Zero PASS records ship at FRP-12** — the framework lands; the validator continues to hard-reject every PENDING / unknown modifier kind. Eleven commits land: the locked per-modifier `specs/modifiers/_template.md` (commit 1); two PENDING reserved-slot docs `specs/modifiers/{client_desync,tls_fragment}.md` (commit 2); the new `publisher/deploy/modifiers/` subpackage with frontmatter parser (commit 3) + build-time `cmd/genregistry` codegen + `registry_gen.go` (commit 4) + public registry API `Lookup / AllKinds / AllowedKindsAt / HasPassAt` (commit 5) + per-platform helper (commit 6); the engine importer platform gate helper at `core/internal/selection/candidate_platform.go` returning `IMP_MODIFIER_PLATFORM` (commit 7); the relaypack binder wired to populate `relaypackvalidate.ValidateOpts.AllowedModifierKinds` from the registry (commit 8); the desktop wizard modifier-surface line on Screen6Handoff + 11 EN/FA i18n keys + Rust-side build-time guard tests (commit 9, wizard tests 98→100); the Android `ModifierGuardTest` source-grep guard (commit 10); the relaypack-v1.md amendment + `docs/modifier-review-process.md` + this supplement bump + handover (commit 11). A readiness hardening pass wires the helper into `core/trust.StoreAdapter.SaveImport`, so modifier-bearing routes are rejected with `IMP_MODIFIER_PLATFORM` before persistence unless a future PASS policy allows them. v2.3.11 adds **§17.5 — FRP-12 implementation lock for the modifier framework** documenting eight locked answers (build-time codegen vs runtime parse; no PASS in `specs/`; subpackage layout; engine-side importer gate; validator wiring; min_phase enum mirrored; module location; UI strings count) plus eleven new locked invariants (37–47). No `spec_version` bump (stays at 4); no engine ABI change (stays at 48); no `engine_*` C-shared symbols added.

> **v2.3.9 → v2.3.10 patch notes (FRP-11 trusted-cells implementation lock; two new subsections, no architecture change).** FRP-11 ships the bundle-side cell types + cellcanon (commit 1) + the `ParseCellDocs` accessor (commit 2); the publisher-side `publisher/cell/` admin keypair generation, `MembershipBuilder`, `DelegationBuilder`, and `Aggregate` (commits 3–4); the per-cell `CellPublisher` interface + R2 + GH-Pages adapters reusing FRP-9 backends (commit 5); the recipient-side `core/trust/cell_verify.go` chain walk + AES-GCM `LabelStore` (commit 6); five `cmd/daal-deploy cell-*` subcommands (commit 7); the desktop wizard V008 migration + `CellRow` API + ~50 EN/FA i18n keys (commit 8, wizard tests 89→98); the Android cell-join receive surface — **cell-join only**, no admin signing — plus the `CellGuardTest` source-grep guard (commit 9, Android tests 34→47); the abuse-ticket + cell-internal revocation primitives + recipient-side `core/trust/cell_revocation.go` (commit 10); and the specs (commit 11). v2.3.10 adds **§16.6 — FRP-11 implementation lock for trusted cells** and **§17.4 — FRP-11 federation-primitives implementation lock** documenting the four locked-answers (admin keypair fresh per-admin; Android cell-join-only; CellPublisher interface + reuse FRP-9 R2/GH-Pages; trust labels in `core/trust/`) plus the six new locked invariants (31–36). No `spec_version` bump beyond V1.5's high-water at 4; no engine ABI change (count stays 48); no `engine_*` C-shared symbols added.
>
> **v2.3.8 → v2.3.9 patch notes (FRP-10 V2 mgmt-plane implementation lock; one new subsection, no architecture change).** FRP-10 implements §9.5.2's V2 cloud-provider-firewall mgmt architecture across three new provider adapters (Hetzner extension + Vultr + Stark), the in-box `cmd/daal-relay-mgmt` service (P-256 self-signed cert, exactly three routes, Ed25519 op-bound tokens), the V2 cloud-init template, the Helper-side TLS-pinned mgmt client, the V007 desktop-wizard schema migration adding `mgmt_port` + `mgmt_tls_fingerprint` to the operators table, and an Android publisher wizard at FRP-5 parity (provision + bind + QR only — no rotation surface on the phone). v2.3.9 adds **§9.5.5 — FRP-10 implementation lock for the V2 mgmt-plane** documenting the five concrete locks (TLS posture, port discipline, three-route API, Ed25519 token shape, cloud-firewall-as-gate) plus the Android-no-rotate boundary. Five new locked invariants (26–30) are exercised by the FRP-10 test surface. No `spec_version` bump beyond V1.5's; no schema bump beyond V1.6's `freshness_url` slot and V007's two new operator columns; no engine ABI change.

> **v2.3.7 → v2.3.8 patch notes (FRP-9 §14.4 closure; one new subsection, no architecture change).** FRP-9 implements the §14.4 cdn_fronted rotation table at the operator level. v2.3.8 adds **§14.6 — Operator rotation levels for cdn_fronted** documenting the L7 (`cdn_path`), L8 (`cdn_hostname`), L9 (`cdn_origin`) commands the wizard surfaces; the §14.4 origin-only-vs-public-surface invariants are restated as five locked invariants exercised by FRP-9's tests. No schema bump beyond V1.6's `freshness_url` slot; no `spec_version` bump beyond V1.5's. The L7/L8/L9 numbering is purely for the wizard's audit log + i18n; the §14.4 rotation table itself remains the canonical reference keyed on what the censor observed.

> **v2.3.6 → v2.3.7 patch notes (cell admin-scheme reconciliation with FRP-track lock; one architecture correction, otherwise prose-only).** During the FRP-track correction pass the cell admin scheme moved from "2-of-N threshold Ed25519" (with FROST / Shamir / MPC implementation hint) to "M-of-N independent Ed25519 signatures over the canonical membership document" plus an admin-quorum-signed delegation document granting bundle-signer authority. The 2-of-N → M-of-N independent-signature change is auditable, uses primitives Daal already depends on, removes the threshold-cryptosystem implementation choice the supplement was leaving open, and matches what `specs/cell-v1.md` will land at FRP-11. v2.3.7 reconciles the supplement prose with that lock in five places (§16.1 cell key bullet, §16.2 cell components paragraph, §16.3 revocation bullet, §17 abuse-mitigation prose, glossary "Cell" entry, plus the §0 ninth-pass reference list). No other architecture change.

> **v2.3.5 → v2.3.6 patch notes (ninth-pass review; lock-readiness wording cleanup — four corrections, no architecture change).** v2.3.5 closed the design gaps. v2.3.6 closes the four remaining stale-wording inconsistencies an upstream lock-readiness review surfaced. After this revision the supplement is text-lock-ready.
>
> 1. **§12.2.2 prose example reconciled with v2.3.5 validator rules.** The §12.2.2 prose introducing the `direct_vps` example still said *"the only tags absent from a direct-mode candidate's `public_risk_tags` are `cdn:` and `public_domain:`"*, contradicting v2.3.5's validator rule (which forbids only `cdn:*` on direct candidates and explicitly allows `public_domain:*`, `host:*`, `sni:*`). Reworded to: direct mode forbids `cdn:*` and any `origin_*` tag, but **may** carry `public_domain:*`, `host:*`, and `sni:*` when the deployment legitimately uses a visible domain on its own VPS without a CDN.
> 2. **§13.4 cooldown-table commentary on shared-`public_ip:` siblings corrected.** Said *"siblings sharing the same `public_ip:` (rare; usually only one direct candidate per IP)"*. In V1.5 — the dominant case — multiple direct candidates from one VPS share `public_ip:` by construction. Reworded to *"common in single-VPS RelayPacks (V1.5 default); treat as one correlated IP-burn event, not N independent failures"*.
> 3. **Stale "v2.3.4 schema" live-doc references flipped to v2.3.5.** Three places named the schema as "v2.3.4" in live prose even though v2.3.5 added `modifiers[]` and `freshness_url`: §3.2 per-candidate metadata bullet, §12.1 schema-work scope, §21.1 V1.5 spec deliverable, and the §12.2.2 validator-rules header. All four corrected to "v2.3.5". (Historical "added in v2.3.4" attribution markers in §§11.1.1, 11.6, 11.7, 13.4, 14.4, 14.5, 19.2.6, 20.4.1, 21.2, etc. are kept intact — they correctly record when each section was introduced.)
> 4. **§22.2 V1.6 success metric: "origin-side rotation" → "public-surface rotation".** The V1.6 success metric described a hostname/public-path change as an "origin-side rotation". Both are by definition **public-surface** changes (TIC-visible tags), and v2.3.5's §14.4 is explicit about this distinction. Reworded to: at least one **public-surface rotation** (hostname or public-path change) delivered via the V1.6 freshness endpoint with no QR re-scan; separately, at least one **origin-only rotation** (origin IP swap, cert refresh, DC move with hostname unchanged) with zero family-visible event and zero RelayPack republish.
>
> v2.3.6 is wording-only over v2.3.5; no architectural or schema change. All v2.3.5 invariants preserved.

> **v2.3.4 → v2.3.5 patch notes (eighth-pass review; mode-aware exposure model consistency cleanup — six corrections, no architecture change).** v2.3.4 landed the mode-aware exposure model but left six self-consistency holes that an upstream lock-readiness review found. v2.3.5 closes them.
>
> 1. **§13.1 shortlist rule softened to be V1.5-compatible.** v2.3.4's *"never include two candidates that share `public_ip:` or `cdn:` or `public_domain:` tags in the same shortlist"* was too strict for V1.5: every candidate from one VPS shares `public_ip:`, so the rule reduced the shortlist to one candidate and defeated the wide-toolbox goal. v2.3.5 makes the rule **soft, not hard**: the selector prefers public-risk diversity when available; when all candidates share `public_ip:*` (the dominant V1.5 case), it falls back to **secondary diversity axes** (protocol family, SNI, `probing_risk_class`, port) and treats a `public_ip:*` failure as one correlated event under §13.4. The hard prohibition is reduced to `cdn:*` only.
> 2. **V1.6 freshness mechanism specified.** v2.3.4 implied recipients receive cdn_fronted public-surface updates "in the background" without specifying the mechanism — the cell-directory machinery that would deliver this lands in V2 (§17.1). v2.3.5 adds a narrow **publisher freshness endpoint** as a V1.6 deliverable: a small per-publisher signed JSON document at an FRP-controlled static URL (NOT a Daal-project endpoint), polled opportunistically by recipients on every successful tunnel-establishment. Same publisher key → atomic RelayPack swap, no re-TOFU. Boundary clearly stated: works only when the recipient still has at least one working route or the URL is reachable through generic connectivity; fully-burned cases still require an out-of-band QR. §14.4 gains a new "V1.6 freshness model" subsection; §14.5 wizard copy distinguishes origin-only vs public-surface changes; §21.2 lists the freshness endpoint as a V1.6 deliverable.
> 3. **§12.2.2 validator: `direct_vps` may carry `public_domain:*`, `host:*`, `sni:*`.** v2.3.4 forbade these tags on direct candidates, which would have rejected legitimate direct `websocket-tls`, `naive`, or HTTPS-shaped candidates that legitimately use a visible domain on their own VPS without a CDN. v2.3.5 narrows the prohibition to **`cdn:*` only** (CDN-mode-only), and additionally forbids `origin_*` tags on direct_vps candidates (in direct mode the origin IS the public surface; the `origin_*` array is only meaningful when the origin is distinct from the public surface).
> 4. **`client_desync` removed from `exposure_mode` enum; new `modifiers[]` array (§12.2.2.bis).** v2.3.4 conflated *what endpoint the recipient connects to* (`exposure_mode`) with *how the recipient mutates outgoing packets* (FakeSNI / TCP desync). v2.3.5 corrects: `exposure_mode := direct_vps | cdn_fronted | serverless_external` (endpoint types only). Packet-mutation behaviours like `client_desync` and `tls_fragment` live in a new per-candidate `modifiers[]` array, validator-rejected at V1.5 / V1.6, post-V2 enableable. §11.6 field-techniques table updated to reflect the corrected schema; glossary updated.
> 5. **Stale V1.5/V1.6/V2 phase contradictions cleaned up.** v2.3.4 left three: (a) the §9.4 V1.5 provisioning timeline still listed *"Helper polls Cloudflare to set DNS"* even though V1.5 is direct-only — removed, replaced with a V1.6 implementation note; (b) the §14.1 L6 row used `iran-cdn-front` as a V1.5 redeploy example — replaced with a direct-only example (UDP/TCP profile rotation, REALITY-`dest` set rotation) and an explicit note that adding cdn_fronted candidates is V1.6, not V1.5 L6; (c) §21.3 V2 deliverables claimed "wires one-click L3 floating-IP rotation" — corrected to "extends one-click L3 to the new V2 provider adapters (Vultr, Stark)" since Hetzner's L3 fast path already ships at V1.5 (§14.1).
> 6. **§11.7 Cloudflare edge-range refresh execution owner clarified.** v2.3.4 said "daily edge-range refresh" without specifying where it runs. v2.3.5 makes explicit: the refresh runs **on the FRP Helper machine** (which holds the cloud-provider token), NOT on the origin box (which holds no token, by §10's trust-boundary property). Three trigger moments on the Helper: every deploy, every rotate, every explicit "Settings → Routes → Verify CDN posture" check, plus an optional local OS-scheduled-task opt-in for FRPs who want daily automatic refresh. Worst-case stale-firewall behavior explicitly traced through §13.4: it manifests as `origin_unhealthy` and triggers the origin-repair path, not as a censorship event. §21.2 deliverables list updated.
>
> v2.3.5 has no architectural change beyond the freshness endpoint (which is the smallest possible mechanism that closes the cdn_fronted public-surface rotation gap at V1.6 without requiring V2 cell primitives). All v2.3.4 invariants preserved.

> **v2.3.3 → v2.3.4 patch notes (seventh-pass review; mode-aware exposure model — model correction, not architecture reset).** This patch lands the **mode-aware exposure abstraction** that earlier versions of this document silently conflated. Two questions from upstream review forced the correction: (a) "when a route is fronted by Cloudflare, what does IP rotation even mean? — TIC never sees the origin IP"; (b) "what does §14's L3 floating-IP swap recover from on a CDN-fronted candidate?" The answers are: nothing, and nothing — the surfaces TIC observes on a CDN-fronted candidate are the **hostname**, **SNI/Host**, **WS path**, **Worker rule**, and the **CDN itself**, not the origin IP. This patch makes the schema, validator, selector, and rotation taxonomy honest about that distinction. Eight changes:
>
> 1. **§11 toolbox — exposure-mode compatibility column added.** Each first-class transport family now declares whether it can be deployed `direct_vps`, `cdn_fronted`, both, or conditionally. UDP-based families (Hysteria2, TUIC, WireGuard, AmneziaWG) are direct-only; HTTPS/WS-shaped families (`websocket-tls`, `webtunnel`) are CDN-frontable; REALITY is direct-only because Cloudflare cannot proxy it as intended. A healthy RelayPack is a **mix** of modes, not "everything fronted."
> 2. **§12.2.2 — schema replaces flat `shared_risk_tags` with the mode-aware split.** The `_relaypack` sub-object now carries `exposure_mode`, `family_class`, `probing_risk_class`, `public_risk_tags[]`, `origin_risk_tags[]`. **Critical correction**: `direct_vps` candidates still carry non-empty `public_risk_tags` (`public_ip:`, `public_asn:`, `public_provider:`, `public_dc:`, `public_port:`, `sni:`). *(v2.3.5 partially supersedes:* the v2.3.4 statement that "only `cdn:` and `public_domain:` tags are CDN-mode-specific" was too strict — `public_domain:`, `host:`, and `sni:` are allowed on direct_vps candidates that legitimately use a visible domain on their own VPS without a CDN; only `cdn:*` and `origin_*` are forbidden on direct_vps. See v2.3.5 patch note #3 above.) The `exposure_mode` enum was widened in v2.3.4 to `direct_vps | cdn_fronted | serverless_external | client_desync`. *(v2.3.5 supersedes:* `client_desync` was misplaced — it is a packet-mutation modifier, not an endpoint type, and v2.3.5 moves it to a separate `modifiers[]` array. The corrected enum is `direct_vps | cdn_fronted | serverless_external`. See v2.3.5 patch note #4 above.)
> 3. **§13 — selector cooldown rules become mode-aware (new §13.4).** `origin_*` failures on `cdn_fronted` candidates do **NOT** propagate to `public_risk_tags` of sibling fronted candidates sharing the same origin (TIC never observed the origin); `cdn:` failures **DO** propagate across every fronted candidate carrying that tag. CDN-origin 522/525/526 responses trigger an **origin-repair path**, not a censorship-recovery path. Nine new network-condition signals added (`dns_bogon_detected`, `protocol_whitelist_mode`, `udp_collapsed`, `quic_collapsed`, `sni_rst`, `cdn_hostname_blocked`, `cdn_wide_failure`, `origin_unhealthy`, `stateful_reassembly_present`).
> 4. **§14 — rotation ladder split.** L1–L6 ladder retained for `direct_vps`. New §14.4 **CDN-fronted rotation table** keyed on failure category (the L-numbering does not carry over cleanly to fronted mode); new §14.5 **wizard rotate-button copy** adapts to mode: fronted-mode burns are usually invisible to the family ("Daal updated your family's hostname in the background. They don't need to re-scan."); direct-mode burns prompt a new QR scan as today.
> 5. **§11.7 (new) — V1.6 Cloudflare deployment template specified.** Origin CA cert + Full Strict + Authenticated Origin Pulls + provider-firewall-locked-to-Cloudflare-edge-IP-ranges + no DNS-only A record + no SMTP/SSH on origin IP + public-random-path → Worker/Page-Rule rewrite → stable origin path indirection. **HTTP/HTTPS only**; no Spectrum dependency; UDP-based families are never `cdn_fronted`. The template is implemented at V1.6, not V1.5.
> 6. **§11.6 (new) — Field-observed tactical modifiers.** Compact gated table covering five intel-note techniques (FakeSNI/TCP desync, TLS fragmentation, MITM domain fronting, serverless HTTP relay, clean-CDN-IP scanning discipline). Every row marked `Default? no` and gated post-V2; this is **vocabulary reservation**, not a ship commitment. Tor/Snowflake/WebTunnel/Psiphon/Conjure remain governed by their existing route-family specs and are NOT in this table.
> 7. **§21 — phase plan inserts V1.6 CDN milestone.** Sequence becomes V1.5 → **V1.6 (NEW)** → V2 → V3. V1.5 ships the full mode-aware schema + selector vocabulary + validator, but produces only `direct_vps` candidates (no domain/Cloudflare UX in V1.5). V1.6 ships `publisher/deploy/cloudflare/`, the Cloudflare wizard path, the §11.7 hardening template, and the mode-aware rotation UI. V2 unchanged in shape (cells, federation primitives, multi-provider, mobile) but now operates over both exposure modes.
> 8. **§19.2.6 (new) — Origin-IP leak attack** named with CT-log scanning + DNS history + SMTP/MX leak + SSH banner attack vectors and the Origin CA + Authenticated Origin Pulls + Cloudflare-IP-only firewall mitigation. **§20.4 — project-subdomain pool caveat tightened**: BYO-domain is the V1.6 production default; a Daal-project test-zone exists only for closed pilot, behind a strong warning, with `project_subdomain_pool:daal` and `domain_suffix:daal-relay-test.org` shared-risk tags so the selector can demote the entire pool if it starts failing. **Delegated subzone model preferred** so Daal never holds origin IPs.
>
> **Invariants preserved across this patch.** Engine ABI = 48 (unchanged). Engine `Version` = `daal-core 0.9.0+v3-share` through V1.5 (unchanged). CC.6 Position B (no telemetry, ever) preserved. No new transport-family enum values. `udp_gated` field reuse unchanged. RelayPack stays an `.sbp` profile, not a new format. Per-candidate metadata stays in `FamilySpecificConfig._relaypack` (backward-compatible bytes round-trip via `json.RawMessage`). V1.5 wizard produces only `direct_vps` candidates; the schema is mode-aware but the wizard at V1.5 is mode-singular. v2-superset stays at 26; v3-superset stays at 31; 3-Soak unaffected.

> **v2.3.2 → v2.3.3 patch notes (sixth-pass review; SSH/cloud-init hardening — no architecture change).** Four corrections:
>
> 1. **§9.3 cloud-init — SSH is no longer a standing surface.** v2.3.2 left `ufw allow 22/tcp` open permanently and gave the `daal` system user `sudo: ALL=(ALL) NOPASSWD:ALL`, contradicting §9.5.1's "no standing SSH surface" claim. v2.3.3 fixes both: 22/tcp is now opened **IP-bound to the Helper for the 60-second provisioning window only** and explicitly closed in cleanup; `sshd` is `systemctl disable --now`-d at the end of the window; the `daal` user is reconfigured to `shell: /usr/sbin/nologin`, `sudo: false`, `lock_passwd: true`, with the ephemeral provisioning key attached to root (not to `daal`) and removed in cleanup. Post-provisioning the box exposes only sing-box on 443/TCP+UDP. §9.5.1 SSH-posture prose rewritten to match.
> 2. **§9.3 cloud-init — `ufw delete` made non-interactive.** `ufw delete ...` can prompt for confirmation and would hang cloud-init. Changed to `ufw --force delete ...` for both the SSH and health-port cleanup rules.
> 3. **§12.2.5 + §16.1 + §16.2 — remaining stale `max_depth` references fixed.** Two prose mentions (cell-scope rule-set and "what 3F gives for free") still used `max_depth`; both now use `cell_max_depth` (new V2 cell metadata) and `redistribution_cap` (existing 3F field) correctly.
> 4. **§9.2.1 + §9.3 + §9.4 + §24 — verifier-shim tool list and package-list inconsistencies fixed.** v2.3.2 said the shim used `curl + sha256sum` but the actual code uses Python `urllib.request.urlopen` and `hashlib.sha256`. The shim's true tool dependency is `bash + python3 + openssl`; updated. The §9.4 timeline row that still said "(curl, ca-certs)" and the §24 decision-table entry that still said "(curl, ca-certificates, openssl)" both updated to the full audited list `curl, ca-certificates, openssl, python3, ufw`.

> **v2.3.1 → v2.3.2 patch notes (fifth-pass review; mechanical doc/spec correctness — no architecture change).** Six blocking fixes plus two cleanups:
>
> 1. **§9.1 + §9.3 — `packages:` list completed.** Added `ufw` (required by §9.3 firewall rules) and `python3` (required by the §9.2.1 verifier shim). §9.1's distro-mirror trust-list updated to match.
> 2. **§9.3 — `/etc/daal-health/config.json` ownership fixed.** Added `owner: daal:daal` so the service running as `User=daal` can read its own config (previously defaulted to `root:root` and would have failed at startup).
> 3. **§9.2 + §9.3 — artefact install name vs release name disambiguated.** Introduced explicit `install_as` field (e.g. `sing-box`) distinct from versioned release name (e.g. `sing-box-<version>-linux-amd64`). The verifier shim now `os.replace`-s to the `install_as` path; systemd's `ExecStart` paths are now correct.
> 4. **§9.3 — portable sshd restart.** `systemctl restart sshd` replaced with `systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service` to handle Debian/Ubuntu's `ssh.service` naming.
> 5. **§9.3 + §9.6 — health-cleanup timing aligned.** Removed the misleading "after first health poll" comment; cleanup is the **end of the 60-second post-service provisioning window**, runs unconditionally (not gated on Helper success), with the in-binary 300 s auto-close as belt-and-braces. §9.6 prose rewritten to match.
> 6. **§12.2.5 — `cell_scope` 3F field name corrected.** v2.3.1 said `max_depth` was an existing 3F field. Actual 3F field is `redistribution_cap` (`bundle/go/bundle/types.go:296`). Reworked: `redistribution_policy` and `redistribution_cap` stay at the route level (3F existing); cell-scope's `cell_max_depth` is renamed and explicitly marked as new V2 cell metadata, bounded by the route's `redistribution_cap`.
> 7. **§3.2 + §12.1 — fictional `core/sign` path corrected.** Replaced with the real Go path `bundle/go/bundle/sign.go` + `bundle/go/bundle/canonical.go`.
> 8. **§13.3 — selector rule wording corrected.** `udp-required candidates` → `` `udp_gated:true` candidates `` to match the existing `.sbp` field name used everywhere else in the doc.

> **v2.3 → v2.3.1 patch notes (fourth-pass review; doc cleanup only — no architecture change).** Three wording fixes:
>
> 1. **§9.2 — "only third party trusted at boot" claim corrected.** Reworded to say "the only third-party *relay artifacts* trusted are Daal-signed blobs" and explicitly cite §9.1's enumeration of distro-mirror trust as the other accepted dependency. Removes the lingering contradiction between §9.1 and §9.2.
> 2. **§14.1 — wall-clock language corrected for the V1.5/V2 split.** Earlier prose said "L1 is 5 seconds" without phase-qualifying it, which would mislead a V1.5 reader. Reworded to make clear L1's 5 s target is the V2 path; V1.5 is ~90 s; the trust-and-impact distinction between L1 and L4 holds in both phases even when wall-clock collapses.
> 3. **Historical patch-note blocks marked as SUPERSEDED where they describe rejected designs.** Added a header note explaining that v2.1's three-tier in-box-mgmt plane was rejected by v2.3, and tagged the relevant entries explicitly so a reader cannot mistake them for the live architecture.

> **v2.2 → v2.3 patch notes (third-pass code review).** Two implementation blockers and three wording inconsistencies fixed:
>
> 1. **§9.5 + §14 — V1.5 management-plane bootstrap deadlock fixed.** v2.2's `daal-relay-mgmt` design had the Helper open a per-operation box-side `ufw` rule before each L1/L2 call. With SSH self-destructed at first boot and no `client.Server.Exec(...)` on any cloud-provider API, **the Helper had no channel to open that rule.** The design was unimplementable. v2.3 picks a clean two-stage architecture: **V1.5 = redeploy-only for L1/L2** (no in-box mgmt service; L1/L2 fold into the same redeploy code path as L4/L5/L6, raising L1 wall-clock from 5 s to 90 s — acceptable at V1.5 scale and operationally complete); **V2 = cloud-provider firewall + persistent narrow-API mgmt service** via a new `Provider.SetEphemeralFirewallRule` interface method (Hetzner Cloud Firewalls, Vultr Firewall, Stark REST). V2 restores the original 5 s / 20 s targets for L1 / L2.
> 2. **§9.3 cloud-init — missing `daal-health.service` unit added.** The runcmd block called `systemctl enable --now daal-health` but `write_files` only contained `sing-box.service`. The unit file is now written explicitly. v1.5 has exactly two units (`sing-box`, `daal-health`); the V2 `daal-relay-mgmt` unit is added when V2 ships.
> 3. **§1 (TOC) — title corrected.** "no third-party fetches at boot" → "no third-party relay-artifact fetches at boot" (v2.2 fixed the §9 section heading and prose but missed the TOC entry).
> 4. **§24 (decision table) — wording aligned with §9.1.** "Removes third-party fetch from the boot trust boundary" → "Removes third-party *relay-artefact* fetch from the boot trust boundary; distro-mirror trust on a small package list is accepted as shape-equivalent to base-image security update path."
> 5. **§24 (decision table) — new row for the L1/L2 management plane** documenting the V1.5/V2 split and citing the v2.2 deadlock that motivated it.

> **Reading the historical patch-note blocks below.** The blocks that follow this v2.3 entry are kept as an audit trail of the design's evolution. **They describe intermediate designs that are NO LONGER part of the current architecture.** In particular, v2.1 introduced a "short-lived in-box `daal-relay-mgmt` API gated by box-side `ufw`" management plane that v2.3 has since rejected as unimplementable (no Helper bootstrap channel after SSH self-destructs). The current architecture is the v2.3 model documented in §9.5 (V1.5 redeploy-only; V2 cloud-provider firewall + persistent narrow-API mgmt service). When historical entries below describe a model that contradicts the live document, the live document wins. Each historical block is preserved verbatim for traceability and is **superseded** by the patch block(s) above it.
>
> ---
>
> **v2.1 → v2.2 patch notes (second-pass code review; SUPERSEDED in part by v2.3 §9.5 rewrite).** Six concrete corrections after re-reading against `bundle/go/bundle/sbp.go`, `bundle/go/bundle/canonical.go`, and the cloud-init YAML in §9.3:
>
> 1. **§3.2 + §12.1 + §12.2.2 — RelayPack forward-compat claim corrected.** v2.1 said the new top-level `Manifest` slot was "JSON-additive and forward-compatible." This is **false** for Daal's verifier: it round-trips `bytes → typed Manifest → CanonicalManifestJSON → verify`, and unknown JSON fields are dropped at unmarshal — old parsers canonicalise without the new fields and signature verification fails. Fixed by (a) carrying per-candidate metadata inside the existing `RouteManifestEntry.FamilySpecificConfig` `json.RawMessage` slot under a `_relaypack` sub-object, where bytes round-trip cleanly through canonicalisation; and (b) admitting that the bundle-level new top-level slot is genuinely **update-required for old clients** (same compatibility contract as 3A/3B/3E/3F), with a `spec_version` bump at V1.5 making the gate explicit.
> 2. **§16 — stale "no new engine work" sentence at line 1039 fixed.** Replaced with the corrected wording from §16.2 that names the new specs/import/UI work while keeping the engine release ABI unchanged.
> 3. **§9.3 cloud-init — `daal-fetch-verify` flag/positional mismatch fixed.** The shim takes `$1 $2 $3` positional args; `runcmd` was calling it with `--manifest --pubkey --target` flags. Now uses positional args matching the shim's contract.
> 4. **§9.1 — "no third-party fetches at boot" claim retitled and clarified.** v2.1's title was imprecise: the YAML legitimately fetches `curl`, `ca-certificates`, `openssl` from the distro mirror. The accurate scope is "no third-party *relay-artifact* fetches at boot" — distro-mirror trust on a small package list is unavoidable and shape-equivalent to the base image's existing security update path; we accept it. We reject only the load-bearing relay-binary fetch.
> 5. **§9.3 cloud-init — `ufw delete` rule mismatch fixed.** The `ufw allow from <ip> to any port 9876 proto tcp` rule has a different ufw-internal form than `ufw allow 9876/tcp`. The cleanup now deletes the exact IP-bound rule that was added.
> 6. **§9.2 — artifact install flow disambiguated.** Removed the `relay-pack-<version>.tar.gz` from the artefact list and added an explicit "binaries only; configuration via `write_files`; activation via `systemctl enable --now`" statement so the shim's job is unambiguous.

> **v2 → v2.1 patch notes (post-code-review; entry #5 SUPERSEDED by v2.3 §9.5 rewrite).** Eight concrete corrections after re-reading the supplement against `bundle/go/bundle/types.go`, `bundle/go/importer/importer.go`, `core/trust/state.go`, and `specs/delegate-keys-v1.md`:
> 1. **§3.2 + §12.1 — RelayPack schema honesty.** Reworded "no engine ABI change, no `nm` count change" to keep the true claim (release-symbol count stays at 48; engine `Version` unchanged) but explicitly name the **real schema, parser, importer, and store widening** the profile requires at V1.5. The "free" framing was misleading; the work is real but additive.
> 2. **§11.1 + §11.2 + §11.4 — `trojan-tls` and `shadowtls` are not Daal transport families.** Removed them from the `vps-native` enumeration (10 → 8 first-class families). ShadowTLS-wrapped Shadowsocks is expressed as `transport_family: "shadowsocks"` with ShadowTLS keys carried inside `family_specific_config`.
> 3. **§11.3 + §13.1 — `udp_required` → existing `udp_gated`.** Reused the existing `.sbp` field (`bundle/go/bundle/types.go:201`) instead of inventing a new one.
> 4. **§16.2 + §16.3 — Trusted cells are not "no engine work".** Cells reuse 3F's `delegated_n` wire shape and cap mechanics but require new `specs/cell-v1.md`, new M-of-N independent-Ed25519 admin-quorum scheme over a membership doc plus an admin-quorum-signed delegation grant of bundle-signer authority, new aggregated-RelayPack inner-provenance, new import-side cell-signature verification chain (admin-quorum → membership → delegation → bundle-signer → inner-publisher), and new cell-management UI. Engine release ABI still stays unchanged.
> 5. **§9.5 + §14 — SSH/rotation contradiction resolved.** *(SUPERSEDED by v2.3.)* This entry described a "three-tier management plane" with a short-lived in-box `daal-relay-mgmt` API gated by box-side `ufw`. The v2.3 third-pass code review rejected this design as unimplementable: with SSH self-destructed at first boot and no `client.Server.Exec` on any cloud-provider API, the Helper had no channel to open the per-operation `ufw` hole. The current model (V1.5 redeploy-only; V2 cloud-provider firewall + persistent narrow-API mgmt service) is documented in §9.5 and §14. Read this historical entry as evidence of the design's evolution, not as a description of the live architecture.
> 6. **§9.2.1 + §9.3 — verifier-shim chicken-and-egg.** Replaced the call to `daal-fetch-verify` (a binary that needed verification before it existed) with an inlined ~50-line `bash + python3 + openssl` shim embedded directly in cloud-init `write_files`. Trust root is the cloud provider's base image only.
> 7. **§5.5 + §7 + §18.1 + §20.1 — hard-coded euros stripped.** All concrete prices replaced with "live via `Provider.Pricing()`" and qualitative descriptions. Hetzner pricing changes (most recently April 2026) make pinned euros stale within months.
> 8. **§8.1–§8.11 — minor-version pins removed.** Concrete `v2.21.x` etc. replaced with "track latest stable major.x; concrete minor pin in `go.mod`". Added work-in-progress caveat for `golang.org/x/net/quic` with a stdlib-`net` fallback path.

> **What this document is.** The base roadmap (`daal-roadmap-v3.md`) describes Daal's protocol stack, trust system, and ship-criteria through V3. It correctly identifies that "**Daal does not run refraction infrastructure; it consumes it**" and that "**a new Iran client is not a language or framework problem; it is a distribution, packaging, and bootstrap problem on top of a solved protocol stack**." This supplement makes those statements operationally concrete by describing **the dominant route-supply mechanism for the Iranian context: trusted diaspora Iranians becoming small publishers that emit signed multi-protocol RelayPacks, distributed through trusted cells before any public federation**.
>
> **What changed from v1.** v1 framed this as a "Diaspora Helper" wizard producing a single VPS configuration. Two rounds of critique converged on a sharper architecture: the wizard is only the UX; the **product** is a publisher pipeline (FRP) emitting a multi-candidate **RelayPack** artefact (a profile of `.sbp`, not a new format) annotated with **shared-infrastructure-risk** metadata so the **client-side selection brain** can race a small diverse shortlist, classify failures, propagate cooldowns along shared-risk edges, and remember per-network winners — without telemetry, without central servers, and without merchant-of-record obligations on the project. Trust scales in three deliberate stages: family-only by default, **trusted cells** (mapped onto 3F's `delegated_n` policy) as the practical bridge, **federation primitives** in V2 with a **public directory gated on observed abuse-handling maturity** — not on calendar.
>
> **Why this matters now.** The protocol engine is shipped (3F + 3-Soak; ABI=48; engine `daal-core 0.9.0+v3-share`). The remaining gap between "Daal is technically capable" and "an Iranian family is online tonight despite TIC" is **route supply**. NGOs do not appear at small-project scale; commercial providers cap project growth at provider growth; five million diaspora Iranians do exist, are technically capable enough to follow a wizard, and are intrinsically motivated to keep their relatives connected. The FRP architecture turns that latent capacity into Daal's primary route-supply mechanism, with each helper-operated VPS surviving longer than commercial multi-tenant relays because the traffic pattern of one family is statistically indistinguishable from a small home VPN or a remote-developer SSH endpoint — flying under TIC's capacity-aware blocklist heuristics.
>
> **Telemetry posture preserved.** Everything in this supplement is consistent with **Position B (no telemetry, ever)** as locked in CC.6 of the base roadmap. The FRP architecture introduces zero phone-home, zero centrally-held user state, zero account system on the project side, and zero merchant-of-record surface.

---

## North Star

> Daal turns trusted diaspora members into Family Relay Publishers. Each FRP provisions a dense multi-transport **RelayPack** on ordinary VPS infrastructure. Recipients import one signed `.sbp` bundle conforming to the RelayPack profile; Daal locally probes, ranks, races a small diverse shortlist, classifies failures, propagates cooldowns along the shared-infrastructure-risk graph, remembers per-network winners, and switches without telemetry. The design **exploits breadth as a property, not a liability**. Trust scales in three deliberate stages: family-only by default, **trusted cells** as the practical bridge, **federation primitives** in V2 with a **public directory gated on observed abuse-handling maturity** — not on calendar.

---

## Table of contents

1. [North Star — what the FRP architecture is for](#1-north-star)
2. [Why this exists — the route-supply gap V1–V3 leaves open](#2-why-this-exists)
3. [Core conceptual stack — FRP, RelayPack, Selection, Cells](#3-core-stack)
4. [The configurator pattern — Daal is a screwdriver, not a furniture store](#4-configurator-pattern)
5. [User-facing flow — the wizard](#5-user-flow)
6. [System architecture — what runs where](#6-architecture)
7. [Provider strategy — adapters, not vendor lock-in](#7-provider-strategy)
8. [Library and package selection — what we use, line by line](#8-libraries)
9. [Cloud-init: pinned, signed, no third-party relay-artifact fetches at boot](#9-cloud-init)
10. [Token storage and trust boundary](#10-tokens)
11. [Protocol toolbox — what one VPS can host, honestly](#11-toolbox)
12. [The RelayPack profile — `.sbp` with portfolio intelligence](#12-relaypack)
13. [Client Selection Policy — the local brain](#13-selection)
14. [Rotation Ladder — one button, mode-aware escalation](#14-rotation)
15. [Anti-burn race policy](#15-anti-burn)
16. [Trusted Cells — the bridge between family and federation](#16-trusted-cells)
17. [Federation Primitives vs Public Directory — sequencing](#17-federation)
18. [Funding architecture — affiliates, donations, grants, never merchant](#18-funding)
19. [Threat model and abuse-resistance](#19-threat-model)
20. [Diaspora user acquisition — the actual unsolved supply problem](#20-acquisition)
21. [Phase placement — V1.5, V1.6, V2, V3 mapping](#21-phase-placement)
22. [Success metrics](#22-success-metrics)
23. [What this supplement deliberately omits](#23-omits)
24. [Decision points (chronological)](#24-decisions)
25. [Appendix A — Cross-references](#appendix-a)
26. [Appendix B — Glossary](#appendix-b)

---

<a name="1-north-star"></a>
## 1. North Star

The FRP architecture exists so that **a non-technical Iranian living in Europe, North America, Turkey, the Gulf, or Australia can click through five screens in Daal desktop and end up with a per-family VPS in Frankfurt, signed and bundled for a parent or sibling in Tehran to scan as a QR code, in approximately five minutes — without Daal ever holding the user's payment, the user's identity, or the user's cloud credentials on a Daal-controlled server**.

A successful run produces:

* A real, paid, KYC-verified VPS at a real cloud provider (Hetzner, Vultr, Stark Industries, Linode, etc.), owned by **the diaspora user** under **the user's own cloud account** with **the user's own credit card**.
* A complete sing-box server-side configuration on that VPS, exposing a **dense, network-fit multi-transport toolbox** (see §11) on a single IP/port stack via SNI/protocol multiplexing.
* An Ed25519 publisher keypair generated and stored **locally on the diaspora user's device only**, never transmitted.
* A signed `.sbp` bundle conforming to the **RelayPack profile** (§12) — a portfolio of candidates from one publisher, annotated with **shared-infrastructure-risk** metadata so the client selector can reason about correlated failure.
* A locally-stored encrypted **OperatorRecord** so the FRP can later rotate, snapshot, decommission, or migrate the deployment without re-doing the wizard.

The diaspora user becomes a **Tier-2 (community) Publisher** in Daal's vocabulary, with the same cryptographic identity properties as any other publisher in the trust system. The Daal project itself is **never the merchant of record, never the cloud reseller, never the abuse-complaint inbox, never the holder of payment data, never the holder of API tokens at rest**.

**Two design properties drive everything in the rest of the document:**

1. **Breadth is a property to be exploited, not a liability to be minimised.** Daal cannot know in advance which protocol will work on which Iranian network on which day. The toolbox must therefore be wide. Reliability comes from **the local selection brain**, not from picking "the right protocol" at deployment time.

2. **Correlated failure must be modelled explicitly.** Two candidates on the same VPS that both fail are not two independent protocol failures; they are likely one shared-IP / shared-ASN / shared-domain failure. RelayPack annotates shared risk; the selector attributes failure up that graph and propagates cooldowns along its edges. Without this, breadth becomes a trap. With it, breadth becomes a moat.

---

<a name="2-why-this-exists"></a>
## 2. Why this exists — the route-supply gap V1–V3 leaves open

The base roadmap excellently designs **the consumer side** of route supply: how a client receives bundles, verifies signatures, ranks routes, rotates burned endpoints, surfaces trust state, shares offline. It does not meaningfully address **how routes appear in the directory in the first place** beyond gestures at "publishers" as institutional actors.

In the Iranian context, the institutional-actor model is structurally weak.

### 2.1. NGOs are slow, picky, and few

The base roadmap's V1.7 (first publishers and pilot) suggests partner organizations. This is correct architecturally but operationally optimistic. NGO partnerships take 3–12 months of relationship-building per partner. Most NGOs in the press-freedom space (Article 19, Access Now, RSF, EFF) do not currently run VPN infrastructure. The few that do (Tor's WebTunnel operators, Psiphon-the-org) already serve their own funnels. **The gap between "engine ready" and "first 100 users in Tehran connected" cannot be bridged on NGO timelines for a small project.** This is also why the base roadmap's **3G partner-operated lifeline relay did not ship**: all five hard pre-conditions (partner / MOU / audit / threat-model / kill-switch test) were unmet, and the work was filed as a locked spec rather than executed.

### 2.2. Commercial Iranian providers cap project growth at provider growth

Existing Iranian Telegram-channel V2Ray providers can be onboarded as Tier-2 publishers and should be — but each commercial provider has their own pricing, support burden, IP-rotation cadence, and incentives to keep users on their proprietary subscription rather than migrating to a Daal-distributed bundle. **Project scale becomes provider scale.**

### 2.3. The diaspora is the largest under-utilised resource

Conservatively **5–6 million** Iranians abroad; concentrated in LA, Toronto, London, Berlin, Stockholm, Sydney, Istanbul, Dubai. A material fraction have a working credit card, a laptop, a worry about a parent in Iran, willingness to pay a small monthly cloud-provider fee indefinitely, and full capability to follow a wizard but not to set up sing-box manually. **A self-service "set up a private VPS for my family in 5 minutes" tool does not exist for this audience.** Outline Manager is the closest analogue but is single-protocol (Shadowsocks), single-provider (DigitalOcean, ill-suited to Iran), unsigned (no publisher trust), and non-portfolio. The FRP architecture closes this gap.

### 2.4. Why this is the dominant supply mechanism, not a side feature

| Dimension | NGO publishers | Commercial providers | FRP architecture |
|---|---|---|---|
| Time to first user | 3–12 months | 1–2 months/provider | Days |
| Cost to project | Partnership labour | Onboarding labour | Marginal: zero per user |
| Trust isolation | Many users / publisher | Many users / publisher | One family / publisher |
| IP burn blast radius | All users on that publisher | All users on that publisher | One family |
| Capacity scaling | Bound by partner budget | Bound by provider capacity | Bound only by diaspora willingness |
| Abuse blast radius | Partner's whole infra | Provider's whole IP pool | One family's VPS |
| Resistance to deplatforming | Single point of failure | Single point of failure | Massively distributed |
| Resistance to TIC blocklisting | Many users / IP | Many users / IP | One IP / family — minimal heat |

The last row is operationally critical. **A VPS serving 3–7 family members generates a traffic pattern statistically indistinguishable from a small home VPN or a remote-developer SSH endpoint.** TIC's heuristics burn IPs that look "VPN-like" (sustained encrypted traffic to many endpoints from many sources). One-family VPSes do not look like that and **survive much longer** than commercial multi-tenant relays. This is the fundamental advantage of the FRP model: route supply is naturally resistant to the censor's capacity-aware blocklisting because each route serves a small enough population to fly under the heuristic radar.

---

<a name="3-core-stack"></a>
## 3. Core conceptual stack — FRP, RelayPack, Selection, Cells

The whole architecture is four named concepts. Pinning them is the most important thing this v2 does.

### 3.1. Family Relay Publisher (FRP)

The trusted diaspora *role*. An FRP is a Daal Tier-2 publisher with these identity properties:

* Owns an Ed25519 publisher keypair generated locally on their device.
* Owns at least one helper-provisioned VPS under their own cloud-provider account.
* Emits signed `.sbp` bundles conforming to the **RelayPack profile**.
* Is the abuse-mediation contact for their own deployment with their own cloud provider.
* May (opt-in) participate in a **trusted cell** with other FRPs.

The FRP is the *publisher pipeline*, not the wizard. The wizard is only one front-end onto the FRP role. Power users can run the same role through `daal-deploy-cli`. Future bots, scripts, and automation can run the same role through the same Go package.

### 3.2. RelayPack

The *artefact*. A RelayPack is **an `.sbp` bundle conforming to a tighter profile** (§12) — multiple candidates from one publisher representing one logical relay deployment, annotated with shared-infrastructure-risk metadata.

Critically, **RelayPack is a profile of `.sbp`, not a replacement format**. It inherits Daal's existing trust machinery (publisher keys, signing, TOFU, revocation, redistribution-policy caps, experimental-gate flags) for free and adds *only* the metadata the selector needs to reason about portfolio-level reliability.

Honest scope of the schema work this requires (revised after code review): **no exported engine ABI change** — `nm libdaalcore.so | grep ' T engine_' | wc -l` stays at 48; engine `Version` stays `daal-core 0.9.0+v3-share`. **But RelayPack metadata is signature-bearing and is therefore NOT silently forward-compatible with older parsers.** Daal's verifier round-trips `bytes → typed Manifest → CanonicalManifestJSON → verify` (`bundle/go/bundle/sbp.go:73`, `bundle/go/bundle/canonical.go:11`); unknown JSON fields are dropped at unmarshal, so an older parser canonicalises *without* the new fields while the publisher signed *with* them and signature verification fails.

Two compatibility-aware design choices follow:

* **Per-candidate metadata** (`exposure_mode`, `family_class`, `probing_risk_class`, `modifiers[]`, `public_risk_tags[]`, `origin_risk_tags[]` — the full v2.3.5 mode-aware schema; see §12.2.2 and §12.2.2.bis) is carried **inside the existing `RouteManifestEntry.FamilySpecificConfig` opaque-JSON slot** (`bundle/go/bundle/types.go:209`), which is typed as `json.RawMessage` and **does** round-trip cleanly through canonicalisation as raw bytes. **No parser change required for backward-compatibility on these fields.** The validator at `publisher/deploy/relaypack/validator.go` parses them out of the opaque blob at import time; the selector reads them at selection time.

* **Bundle-level metadata** (`relay_pack_id`, the bundle-wide shared-risk graph derived from per-candidate `public_risk_tags`, cell-scope defaults, and the V1.6 `freshness_url` slot per §14.4) is genuinely **new typed first-class fields on `Manifest`**, landing as a new optional top-level slot in the same shape as 3A's `kill_switches`, 3B's `rendezvous_hints`, 3E's `transport_modules`, and 3F's `redistribution_chain` / `delegate_caps` (the established widening pattern). **This means RelayPack-aware bundles are update-required for old clients**: a pre-V1.5 client's verifier rejects the signature; the user is prompted to update Daal. Same compatibility contract that 3A/3B/3E/3F already imposed. The `spec_version` integer is bumped at V1.5 (3-Soak completed at v3-share without bumping; the RelayPack profile is the trigger). `freshness_url` is additive within the same already-bumped slot at V1.6 — no further `spec_version` bump.

The importer (`bundle/go/importer/importer.go`), import boundary (`core/trust/state.go`), and route-store row (`core/routestore/store.go`, `RouteRow` at line 127) widen to land the new fields. Signature canonicalisation rules in `bundle/go/bundle/sign.go` + `bundle/go/bundle/canonical.go` extend to cover the new top-level slot. Validator `publisher/deploy/relaypack/validator.go` enforces the profile at import time. Old `.sbp` bundles (without the new top-level slot) verify unchanged.

### 3.3. Client Selection Policy

The *brain*. A deterministic local policy (no ML) that turns a RelayPack's breadth into actual reliability on a specific network. Probes the network, filters by trust/expiry/revocation/UDP-availability/budget, builds a **shared-risk-diverse shortlist**, races a small number of candidates, classifies failures using the existing taxonomy (`classify.go`), propagates cooldowns along shared-risk edges, remembers per-network winners, and explains its choice in plain language. §13.

### 3.4. Trusted Cells

The *trust scaling layer*. A cell is a bounded group of FRPs (family + close friends + a diaspora student org + a local mosque circle) that mutually share spare RelayPack capacity using the existing 3F `delegated_n` redistribution policy. Cells are the bridge between "private family only" (too small) and "global public directory" (too risky). §16.

These four concepts and their relationships are what the rest of the document elaborates.

---

<a name="4-configurator-pattern"></a>
## 4. The configurator pattern — Daal is a screwdriver, not a furniture store

The decisive architectural choice: **Daal never holds money, never holds cloud credentials on a server, never owns the VPSes it configures**.

Two designs were considered:

### 4.1. Design A (rejected): Daal-as-merchant

User pays Daal; Daal owns a master cloud account; Daal spins up VPSes on its master and bills the user.

**Why rejected.** Daal would be a payment-services business (Stripe/Mollie/Adyen, KYC, OFAC, EU VAT in every member state), a cloud reseller (TOS violation absent reseller agreements), the abuse-complaint inbox for every VPS in the fleet (one bad user → entire master account suspended), and the custodian of Iranian-related transaction data (sanctions screening, processor flagging, account holds). Worst, **a single deplatforming event takes down the whole fleet at once** — a censor needs only to compromise one bank, one processor, or one cloud account to dark every diaspora-served Iranian.

### 4.2. Design B (adopted): Daal-as-configurator

User signs up with a cloud provider directly (own name, own card, own KYC). User generates an API token in the provider's console. User pastes the token into Daal. From that moment, **Daal automates everything** — provisioning, configuration, key generation, RelayPack signing, IP rotation, decommissioning — using the user's credentials, locally, on the user's device.

**Why adopted.** Outline Manager (Jigsaw/Google), Algo VPN (Trail of Bits), Streisand (historically). The configurator pattern cleanly avoids every regulatory surface area. The user's relationship is with Hetzner; Daal is a configurator the user runs locally. **A deplatforming event affects exactly one user.**

### 4.3. The unavoidable browser excursion

Three things must happen in the cloud provider's console that Daal cannot automate:

1. **Sign up for a Hetzner account.** No cloud provider exposes account creation as third-party API.
2. **Add a payment method.** German banking law (and analogous law in every EU member state) requires the provider to obtain payment credentials directly from the cardholder.
3. **Generate an API token.** Hetzner Cloud has no OAuth (only the legacy Robot console does); token generation is a button click.

Total ~3 minutes for a non-technical user. The wizard makes those minutes feel **guided** rather than abandoned.

### 4.4. Defence-in-depth: dedicated cloud project/account

The wizard recommends (and the docs require for cells) that the FRP creates **a dedicated cloud-provider project / sub-account scoped to Daal**. Even though tokens are local-only, scoping limits blast radius if the FRP's token is later compromised: an attacker confined to the Daal-scoped project cannot touch the user's other cloud workloads.

---

<a name="5-user-flow"></a>
## 5. User-facing flow — the wizard

Invoked from Daal desktop (Tauri) by clicking **Routes → Help my family in Iran**. Five wizard screens plus two progress modals.

### 5.1. Screen 0 — Welcome and informed consent

Persian + English (more locales added later). Three things made unambiguous:

* **Daal never sees your money or your family's traffic.** You pay the cloud provider directly. Daal cannot see what the family does over the route.
* **Cost: a small monthly fee paid directly to the cloud provider.** The wizard shows the live price on the next screen via `Provider.Pricing()`. Order of magnitude: small-team-coffee per month, not subscription-VPN per month.
* **New customers typically receive a referral credit covering the first ~2 months** (Hetzner offers this; amount and conditions are provider-controlled). Disclosed transparently along with "Daal earns a referral fee from your provider; you pay nothing extra."

### 5.2. Screen 1 — Provider choice

Default: **Hetzner Frankfurt** for Iran-targeted deployments (`research/intel-and-some-working-methods.md`: graylisted, Frankfurt = principal European peering hub for Iranian transit, RTT 80–120 ms). Other providers exposed as advanced options (Vultr, Stark Industries, Linode). The default is fine for 95% of users.

### 5.3. Screen 2 — Account connection

Two radio options: existing account → skip to Screen 3; or **I need to create one (free, ~3 minutes)** → Daal opens default browser to a pre-referraled signup URL and shows a passive modal that the user dismisses with `I'm done — continue` when they have a token in hand.

### 5.4. Screen 3 — Token paste and validation

Token pastes into a `type=password` input. Daal silently calls `client.Server.All(ctx)` for instant green-checkmark validation; 401 surfaces as red-X "This token isn't valid — try generating a new one." Token is immediately written to OS-native keystore + PIN-derived AES-GCM defence-in-depth (§10) and overwritten in the input field.

### 5.5. Screen 4 — Server sizing and region

```
Step 4 of 5: Choose server size

How many family members will use this server?

◯ Small  (1–3 people)    [live price]   — entry tier
● Medium (3–7 people)    [live price]   — recommended
◯ Large  (7–15 people)   [live price]   — heavy use

Server location:
● Frankfurt, Germany  — best for Iran (~80–120 ms)
◯ Helsinki, Finland   — backup
◯ Falkenstein, Germany — Hetzner alternate

[ Provision RelayPack ]
```

Prices are **fetched live** via `Provider.Pricing()` at wizard render time. Hard-coded euro figures are deliberately omitted from this roadmap — Hetzner has revised pricing more than once (most recently the April 2026 price-adjustment cycle), and roadmap prose that pins specific euros becomes stale within months. The medium tier corresponds to a CPX21-class instance (3 vCPU, 4 GB RAM, 20 TB egress) which is calibrated for the typical Iranian-family use case (~3–7 active users, 50–150 GB egress per family per month). Multiple DC options exist because Hetzner occasionally rotates abuse-prefix lists per location; later rotation can move the box across DCs.

### 5.6. Screen 5 — Provisioning progress (modal)

```
Setting up your family's RelayPack...

✓ Generating publisher key for your family
✓ Creating server in Frankfurt
✓ Installing pinned, signed Daal relay artifacts
⋯ Configuring protocol toolbox (this takes ~60 seconds)
○ Annotating shared-infrastructure-risk graph
○ Generating QR code for your family

████████████████░░░░░░░░░░░  62%
```

Wall-clock ~90 seconds end-to-end (§9.4 timeline).

### 5.7. Screen 6 — RelayPack handoff

```
Done! Your family's RelayPack is ready.

         ┌────────────────────────┐
         │      [ QR CODE ]       │
         └────────────────────────┘

Your family can scan this QR code with their copy of Daal
to receive 5 candidate routes from this RelayPack. They will
see your name as:

     river-village-strong-promise

[ Save QR as image ]   [ Send via Telegram ]
[ Copy share link ]    [ Print QR ]
[ Receive via LAN now ] (if family is on same Wi-Fi)
```

The four-word fingerprint is the BIP-39-rendered first 44 bits of the publisher key per `specs/publisher-keys-v1.md`. The Telegram option uses the OS share sheet; nothing in Daal contacts Telegram itself.

### 5.8. Subsequent flows (no wizard)

After the wizard the FRP has a stored, encrypted OperatorRecord plus the publisher private key. Subsequent operations are single-button and described in §14 (Rotation Ladder).

---

<a name="6-architecture"></a>
## 6. System architecture — what runs where

Four named components.

### 6.1. `daal-deploy` — the Go provisioning library

New internal Go package at `publisher/deploy/`. Engine of the wizard; also exposable as CLI for power users.

```go
package deploy

type DeployRequest struct {
    Provider        ProviderTag      // "hetzner" | "vultr" | "linode" | "stark"
    APIToken        string
    Region          string           // "fsn1" / "hel1" / "fra"
    ServerSize      ServerSize
    FamilyTag       string           // "moms-route", arbitrary local label
    PublisherKey    publisher.Key
    Cloudflare      *CloudflareOpts  // optional CDN front
    Toolbox         ToolboxProfile   // §11 — which transports to install
    DryRun          bool
}

type DeployResult struct {
    ServerID        string
    ServerIPv4      net.IP
    ServerIPv6      net.IP
    FloatingIPv4    net.IP
    RelayPack       *bundle.Signed   // §12
    OperatorRecord  OperatorRecord
}

func Deploy(ctx context.Context, req DeployRequest) (*DeployResult, error)
func Rotate(ctx context.Context, op OperatorRecord, level RotationLevel, token string) (*DeployResult, error) // §14
func Decommission(ctx context.Context, op OperatorRecord, token string) error
func Snapshot(ctx context.Context, op OperatorRecord, token string) (snapshotID string, err error)
func RestoreFromSnapshot(ctx context.Context, snapshotID string, req DeployRequest) (*DeployResult, error)
```

`Deploy` is a state machine with explicit checkpoints to resume from partial failures. All cloud calls go through a `Provider` interface (§7). Calls use exponential backoff for transient errors. Permanent errors surface verbatim. **No data leaves the user's machine** except API calls to the cloud provider, signed-artefact fetches (§9.2), and the optional Cloudflare API — all direct from the user's machine, never via a Daal server.

### 6.2. `daal-deploy-cli`

Power users invoke `deploy` from CLI:

```sh
daal-deploy provision --provider hetzner --token-file /tmp/tk \
    --region fsn1 --size cpx21 --family-tag moms-route \
    --toolbox iran-default --output /tmp/moms-relaypack.sbp
```

Thin `cobra` wrapper around the package.

### 6.3. The Tauri front-end

React+TypeScript single-page app in Tauri's WebView. Calls `tauri::command` handlers in the Rust backend, which spawn `daal-deploy` as either a Go shared library (`-buildmode=c-shared`) or a sidecar process. The wizard holds **no logic** beyond input validation and progress display.

### 6.4. Mobile front-end (V2 add-on)

Future Android (Compose) and iOS (SwiftUI) wizards using the same Go package via `gomobile bind`. iOS wizard lives in the main app, not the NE extension (50 MB ceiling). Post-V1 to avoid blocking the desktop MVP.

---

<a name="7-provider-strategy"></a>
## 7. Provider strategy — adapters, not vendor lock-in

The `Provider` interface:

```go
type Provider interface {
    Validate(ctx context.Context, token string) error
    Provision(ctx context.Context, spec ProvisionSpec) (*ProvisionResult, error)
    AllocateFloatingIP(ctx context.Context, token, region string) (*FloatingIP, error)
    AssignFloatingIP(ctx context.Context, token, ipID, serverID string) error
    UnassignFloatingIP(ctx context.Context, token, ipID string) error
    Snapshot(ctx context.Context, token, serverID, label string) (snapshotID string, err error)
    Delete(ctx context.Context, token, serverID string) error
    Pricing(ctx context.Context, region string) (PricingTable, error)
}
```

**The strategic asset is the repeatable provisioning flow, not Hetzner.** Provider choice is a per-deployment adapter; provider availability changes; the FRP architecture must outlive any single vendor relationship.

V1 ships **only Hetzner** (cheapest mainstream EU cloud at the relevant tier; small-team-coffee monthly cost; Floating IPs cheaply rotatable without rebuilding the box; generous egress allowance included; graylisted per `intel-and-some-working-methods.md`; excellent `hcloud-go/v2` SDK; 3,600 API/hour rate limit). All concrete prices are pulled live via `Provider.Pricing()` rather than hard-coded in roadmap prose. V2 adds **Vultr** (wider regional coverage; per-hour billing; `govultr/v3`) and **Stark Industries** (popular in the Iran community; off TIC's most aggressive blocklists per `research/Protocols.md`; Lithuanian jurisdiction; no SDK so we wrap their REST in ~150 lines). V3 considers **Linode** only on user demand.

**Excluded providers:** AWS/GCP/Azure (egress 30–100× Hetzner; enumerable IP ranges; AWS has banned anti-censorship accounts), OVH and DigitalOcean (per `intel-and-some-working-methods.md`, ranges blanket-blocked when triggered), Iranian hosts (cooperate with TIC).

---

<a name="8-libraries"></a>
## 8. Library and package selection — what we use, line by line

### 8.1. Cloud provider SDKs

#### `github.com/hetznercloud/hcloud-go/v2`

Official Hetzner SDK. v2 is the current major version; v1 is deprecated (2024). ~10kLOC of audited resource handling, identical shape to Terraform's Hetzner provider. **Why this and not hand-rolled HTTP:** zero maintenance burden, security audits are upstream's concern, no scenario where hand-rolling is right. Surface used: `Server.Create/GetByID/Delete`, `FloatingIP.Create/Assign/Unassign`, `Image.CreateFromServer` (snapshots), `SSHKey.Create`, `Location.All`, `ServerType.All`, `Action.WatchProgress`. **Pin discipline:** track the latest stable `v2.x` (the upstream is API-stable on minor versions); concrete minor pin lives in `go.mod`, not in this roadmap, because pkg.go.dev advances faster than roadmap revisions.

#### `github.com/vultr/govultr/v3` (V2)

Official Vultr SDK. Surface: `Instance.Create/Get/Delete`, `ReservedIP.Create`, `Snapshot.CreateFromInstance`. **Pin discipline:** track the latest stable `v3.x`; concrete minor pin lives in `go.mod`.

#### Stark Industries (V2)

No SDK; ~150-line REST wrapper at `publisher/deploy/providers/stark/` using `net/http` + `encoding/json`.

#### `github.com/linode/linodego` (V3, conditional)

Official Linode SDK. Lands only on demand.

### 8.2. DNS and CDN

#### `github.com/cloudflare/cloudflare-go/v4`

Cloudflare's codegen-driven SDK mirroring their official spec. v0/v1 (hand-written) being phased out. **Why v4:** API-stable, actively maintained, upstream-recommended. Used to manage A/AAAA records pointing CDN-fronted subdomains at the box, optional proxy mode, Workers / Page Rules for fallback transports. The Cloudflare token is local-only and never sent to a Daal-controlled server. **Pin discipline:** track the latest stable `v4.x`; concrete minor pin lives in `go.mod`.

### 8.3. Cryptographic primitives

* **`crypto/ed25519`** (stdlib) — publisher signing keypairs. Already used in `bundle-go` and `core/`.
* **`crypto/ecdh`** (stdlib) — X25519 pairs for sing-box Reality `private_key`/`public_key`. Regenerated per box.
* **`golang.org/x/crypto/argon2`** — Argon2id derivation of AES-GCM keys from the user's Daal device PIN. Desktop params: `time=2, memory=64*1024, threads=1`. Mobile params tighter. **Pin discipline:** track upstream `golang.org/x/crypto` head; concrete pin in `go.mod`.
* **`crypto/aes` + `crypto/cipher`** (stdlib) — AES-256-GCM at-rest encryption of API tokens, OperatorRecords, and publisher private keys. **Stdlib only; no third-party crypto.**

### 8.4. QR generation

`github.com/skip2/go-qrcode` (static) and the existing `bundle/`-resident fountain-QR module (per V1.4 spec). No new dependency.

### 8.5. Cloud-init YAML

`gopkg.in/yaml.v3`. **No templating libraries** (`text/template` etc.). The cloud-init script is a structured Go value (`type CloudInit struct {...}`) serialised to YAML. This avoids template-injection bugs and keeps the script auditable.

### 8.6. RelayPack / bundle signing

Re-uses Daal's existing `bundle/go` package as a Go module dependency. The RelayPack profile is enforced by `publisher/deploy/relaypack/validator.go`, not by a new bundle format.

### 8.7. Local key/value storage

#### `github.com/zalando/go-keyring`

OS-native keystore wrapper (macOS Keychain, Windows Credential Manager, Linux libsecret). Per-provider tokens stored under `daal.deploy.hetzner.<account-id>`. **Why not a custom encrypted file:** keystores integrate with OS lock-screen auth. **Why both:** the keystore-stored token is itself AES-GCM-encrypted with a Daal-PIN-derived key as defence-in-depth (§10).

### 8.8. Database for OperatorRecords

#### `modernc.org/sqlite`

Pure-Go SQLite (avoids CGo at the Tauri boundary). Schema:

```sql
CREATE TABLE operator_records (
    record_id          TEXT PRIMARY KEY,
    family_tag         TEXT NOT NULL,
    provider           TEXT NOT NULL,
    provider_account   TEXT NOT NULL,
    provider_server_id TEXT NOT NULL,
    provider_region    TEXT NOT NULL,
    public_key_fp      TEXT NOT NULL,
    cell_membership    TEXT,                   -- §16, nullable
    encrypted_state    BLOB NOT NULL,          -- AES-GCM blob
    created_at         INTEGER NOT NULL,
    last_used_at       INTEGER NOT NULL,
    UNIQUE(provider, provider_server_id)
);
```

`encrypted_state` holds publisher private key, sing-box server keys, RelayPack candidate fingerprints, Cloudflare DNS record IDs, the **shared-risk graph** for the deployment, and (if cell-joined) the cell credentials. AES-GCM key derived from the Daal PIN via Argon2id.

### 8.9. CLI

`github.com/spf13/cobra` for `daal-deploy-cli`. Consistency with `kubectl`, `gh`, `hugo` ecosystem.

### 8.10. Logging, metrics

The Helper does **no telemetry** (CC.6). All logging is `log/slog` to a local file in the user's Daal app data directory. Stdlib only.

### 8.11. Network probing (selection brain)

* **`github.com/miekg/dns`** for explicit DNS probe queries (the selector tests DNS poisoning behaviour, §13).
* **`golang.org/x/net/quic`** for QUIC reachability probes — **caveat:** upstream documents this package as work-in-progress / not yet production-ready. V1.5 selection therefore uses raw UDP reachability via stdlib `net` for the UDP-availability probe and consults `golang.org/x/net/quic` only opportunistically for QUIC-shape detection where it is known to work. If the package is still pre-stable at V2 ship time, the selector falls back to a hand-rolled QUIC-version-negotiation probe (~80 lines) using stdlib `net`.
* **`net`** stdlib for TCP/UDP reachability — the load-bearing probe, always available.

These run on the **client side** (Iran-side Daal) as part of selection, not on the FRP side.

**Pin discipline:** all third-party probing libraries are tracked at major-version + latest-stable; concrete minor pins live in `go.mod`. Stdlib `net` has no version-pin concern.

---

<a name="9-cloud-init"></a>
## 9. Cloud-init: pinned, signed, no third-party *relay-artifact* fetches at boot

Cloud-init is the de-facto first-boot configuration mechanism. Every major provider supports it; Hetzner injects YAML into the VM's metadata service via `ServerCreateOpts.UserData`.

### 9.1. Boot-time trust dependencies — what we accept and what we reject

At first boot, the box has two distinct trust dependencies:

1. **The cloud provider's base image and its distro mirror.** The base image (Debian/Ubuntu) ships `bash` and a small set of base utilities. The distro mirror is fetched for `apt-get update` and the install of a short, audited package list — `curl`, `ca-certificates`, `openssl`, `python3`, `ufw` — declared in the YAML's `packages:` block. (`python3` and `openssl` ship pre-installed on most cloud images but are listed explicitly so the YAML works against any base; `ufw` is required by the §9.3 firewall rules and is not always pre-installed.) **This is unavoidable**: every cloud Linux image trusts its own distro mirror, and rebuilding a custom image from scratch to remove this dependency is not a useful exercise — the threat surface is the same shape as the base image's existing security update path.
2. **A third-party Daal-relay-artifact source.** v1 of this supplement specified fetching sing-box from sagernet's apt repo at first boot. **This is what v2 rejects.** It introduces a live, time-of-provision trust dependency on a project-external artifact source for the load-bearing relay binary. If sagernet's apt repo is poisoned, hijacked, deplatformed, or blocked at the moment of provisioning, every FRP provisioning at that moment is at risk.

The §9 design therefore accepts (1) — distro-mirror trust on a small package list — and rejects (2) — third-party-relay-artifact trust. **All Daal relay artifacts (sing-box, daal-relay-health in V1.5; sing-box, daal-relay-health, daal-relay-mgmt in V2) are fetched as pinned, Ed25519-signed, hash-verified blobs from Daal-controlled signed mirrors.** The previous section title "no third-party fetches at boot" was imprecise; the accurate scope is *no third-party relay-artifact fetches at boot*.

### 9.2. The pinned-artefact pattern

The Helper carries (at Daal release time) **pinned, checksum-verified, Daal-signed** server artefacts. The V1.5 artefact set is a small list of **executable binaries only**, each with two distinct names:

* a **release name** carrying version + arch (e.g. `sing-box-<version>-linux-amd64`) used as the mirror path and the signed-bundle entry name,
* an **install_as** name that is the final binary basename systemd invokes (e.g. `sing-box`).

V1.5 artefacts:

| Release name (mirror path) | `install_as` (filesystem location) |
|---|---|
| `sing-box-<version>-linux-amd64` | `/usr/local/bin/sing-box` |
| `daal-relay-health-<version>-linux-amd64` | `/usr/local/bin/daal-relay-health` |

The artefact manifest (`/etc/daal/artifacts.json`) lists each entry with `{name, install_as, sha256, sig_hex, mirrors[]}`; the verifier shim (§9.2.1) downloads to a temp file, verifies hash + Ed25519 signature, then `os.replace`-s to the `install_as` path with mode `0o755`. This replaces an earlier draft that conflated the versioned release name with the install path and would have left systemd looking for `/usr/local/bin/sing-box-<version>-linux-amd64` instead of `/usr/local/bin/sing-box`.

V2 adds `daal-relay-mgmt-<version>-linux-amd64` → `/usr/local/bin/daal-relay-mgmt` (the persistent management API per §9.5.2). V1.5 does **not** ship this binary — V1.5 management is redeploy-only (§9.5.1), and putting an in-box mgmt service onto V1.5 boxes without the V2 cloud-provider firewall integration would create dead code with no working bootstrap path.

**No tarball.** The verifier shim (§9.2.1) only fetches and verifies these binaries; everything else (systemd units, sing-box config, health-endpoint config, mgmt-endpoint config, firewall rules) is **written directly into the box's filesystem from the cloud-init `write_files` block** (§9.3). This eliminates the "what does the tarball contain and where does it unpack" ambiguity from the v2 draft. The shim's job is binary verification + placement. Configuration is `write_files`. Service activation is `runcmd → systemctl enable --now`.

Each artefact has:

* A **content hash** (SHA-256) embedded in the Daal release.
* An **Ed25519 signature** by the project's release key (separate from any directory key).
* **At least three signed mirrors**: the Daal GitHub Releases page, IPFS via web3.storage, and a Cloudflare R2 backup. The cloud-init script tries them in order; verification (hash + signature) happens locally on the box before installation. **Any mirror that fails verification is silently skipped.** A poisoning of one mirror is detected, not propagated.

This means **the only third-party *relay artifacts* the box trusts at first boot are Daal-signed blobs delivered through Daal-controlled signed mirrors.** The other boot-time trust dependencies are exactly the two enumerated in §9.1 — the cloud provider's base image and its distro mirror — both of which are accepted as shape-equivalent to the base image's existing security update path. No additional third-party software supply chain is introduced for the load-bearing relay binaries.

### 9.2.1. The verifier-shim chicken-and-egg

A naïve "fetch+verify all artefacts via `daal-fetch-verify`" plan needs a verifier binary that has itself not yet been verified. v2 closes this by **inlining a small verifier shim directly into the cloud-init `write_files`** (see §9.3 YAML), implemented in `bash + python3 + openssl`, all of which are present on the Debian/Ubuntu base images Hetzner ships.

The shim depends on:

* `bash` to drive the shim entrypoint and pass arguments through.
* `python3` (stdlib) for JSON parsing, SHA-256 hashing, and HTTPS mirror fetches via `urllib.request.urlopen`. **No `curl` is invoked from inside the shim** — `curl` is in `packages:` for other cloud-init purposes but the shim itself uses Python's stdlib HTTP client to keep the verification path self-contained.
* `openssl pkeyutl -verify -rawin` for Ed25519 signature verification (available in OpenSSL ≥ 3.0; both Debian 12 and Ubuntu 22.04+ ship this).

This trio is the **trust root on the box**: the cloud provider's base image. If that is compromised, no scheme involving a downloaded verifier binary would help either; the threat is identical. The shim avoids escalating that base-image trust into a second downloadable trust dependency.

The shim is ~50 lines, embedded in the YAML, and verifiable at every provisioning by reading the cloud-init log on the box. It is the *only* boot-time code that runs before signature verification has been performed. After it runs, the verified Daal-signed artefacts (`sing-box`, `daal-relay-health` in V1.5; plus `daal-relay-mgmt` from V2 onward) take over.

### 9.3. The cloud-init YAML, annotated

```yaml
#cloud-config
hostname: daal-relay
manage_etc_hosts: true
package_update: true
package_upgrade: false

packages:
  - curl
  - ca-certificates
  - openssl                          # §9.2.1 — verifier shim signature check
  - python3                          # §9.2.1 — verifier shim json/sha256/control flow
  - ufw                              # §9.3 — host firewall management

users:
  # The daal system user runs sing-box and daal-health only.
  # No interactive shell, no sudo. The provisioning ephemeral SSH
  # key is the *only* way in during the 60s window; it lives in a
  # separate root-owned authorized_keys (see ssh_authorized_keys
  # at the cloud-config root level below) and is removed in runcmd
  # together with closing 22/tcp in ufw (§9.5 — no standing SSH
  # surface).
  - name: daal
    sudo: false
    shell: /usr/sbin/nologin
    lock_passwd: true

# The ephemeral provisioning key is attached to root for cloud-init's
# default behaviour, NOT to the daal service user. After the 60s
# provisioning window runcmd removes it AND closes 22/tcp on the
# host firewall, so SSH is not a standing surface on the box.
ssh_authorized_keys:
  - ${EPHEMERAL_SSH_PUBLIC_KEY}        # §9.5 — burned ~60s in; 22/tcp closed

write_files:
  # Pinned artefact manifest
  - path: /etc/daal/artifacts.json
    permissions: '0644'
    content: |
      ${PINNED_ARTIFACT_MANIFEST}      # sha256s, signatures, mirror URLs

  # Release-key trust anchor (Ed25519 public key, PEM)
  - path: /etc/daal/release.pub
    permissions: '0644'
    content: |
      ${DAAL_RELEASE_PUBKEY}

  # Inlined verifier shim — uses only base-image tools: bash drives
  # the entrypoint, python3 (stdlib) handles JSON parsing, SHA-256
  # hashing, and HTTPS mirror fetches via urllib, and `openssl
  # pkeyutl -verify` does the Ed25519 signature check. Solves the
  # chicken-and-egg of needing a verifier binary that itself has
  # not yet been verified. See §9.2.1.
  - path: /usr/local/bin/daal-fetch-verify
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      MANIFEST=$1                  # /etc/daal/artifacts.json
      PUBKEY=$2                    # /etc/daal/release.pub
      TARGET=$3                    # /usr/local/bin/
      # For each artefact in the manifest:
      #   try each mirror URL in order
      #   download to /tmp
      #   verify sha256 matches manifest's expected hash
      #   verify Ed25519 signature with `openssl pkeyutl -verify`
      #   first artefact passing both checks wins
      #   move to TARGET and chmod +x
      # On any failure, skip mirror; on all-mirrors-fail, exit 1.
      python3 -c "$(cat <<'PY'
      import json, hashlib, subprocess, sys, urllib.request, os, tempfile
      m = json.load(open(sys.argv[1]))
      pub = sys.argv[2]; target = sys.argv[3]
      for art in m["artefacts"]:
          ok = False
          for url in art["mirrors"]:
              try:
                  with tempfile.NamedTemporaryFile(delete=False) as f:
                      data = urllib.request.urlopen(url, timeout=30).read()
                      f.write(data); f.flush()
                  if hashlib.sha256(data).hexdigest() != art["sha256"]:
                      continue
                  sig_path = f.name + ".sig"
                  open(sig_path, "wb").write(bytes.fromhex(art["sig_hex"]))
                  r = subprocess.run(
                      ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
                       "-rawin", "-in", f.name, "-sigfile", sig_path],
                      capture_output=True)
                  if r.returncode != 0:
                      continue
                  # install_as is the final binary basename (e.g. "sing-box");
                  # art["name"] is the versioned release name used only for
                  # the mirror path / log messages.
                  dst = os.path.join(target, art["install_as"])
                  os.replace(f.name, dst); os.chmod(dst, 0o755)
                  ok = True; break
              except Exception:
                  continue
          if not ok:
              print(f"FAIL: no mirror passed verification for {art['name']}", file=sys.stderr)
              sys.exit(1)
      PY
      )" "$MANIFEST" "$PUBKEY" "$TARGET"

  # The sing-box server-side config
  - path: /etc/sing-box/config.json
    permissions: '0600'
    owner: root:root
    content: |
      ${SING_BOX_CONFIG_JSON}

  # Health endpoint config — one-time token + IP-bound (§9.6).
  # Owner is daal:daal because the daal-health.service runs as
  # User=daal Group=daal; if this stayed root:root the service
  # would be unable to read its own config at startup.
  - path: /etc/daal-health/config.json
    owner: daal:daal
    permissions: '0600'
    content: |
      {
        "one_time_token": "${HEALTH_TOKEN}",
        "allowed_client_ip": "${PROVISIONING_CLIENT_IP}",
        "auto_close_after_seconds": 300
      }

  # systemd units — V1.5 has exactly two units: sing-box and daal-health.
  # No daal-relay-mgmt unit in V1.5 (per §9.5.1, V1.5 management plane is
  # redeploy-only; the persistent mgmt service is V2 work).
  - path: /etc/systemd/system/sing-box.service
    permissions: '0644'
    content: |
      [Unit]
      Description=sing-box (Daal relay)
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=simple
      ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
      Restart=on-failure
      RestartSec=5
      LimitNOFILE=1048576
      AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
      CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
      NoNewPrivileges=true
      [Install]
      WantedBy=multi-user.target

  - path: /etc/systemd/system/daal-health.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Daal relay health endpoint (provisioning-window only, §9.6)
      After=sing-box.service
      Wants=sing-box.service
      [Service]
      Type=simple
      ExecStart=/usr/local/bin/daal-relay-health -config /etc/daal-health/config.json
      Restart=no
      # The endpoint self-terminates after auto_close_after_seconds (§9.6 / 300s
      # default) regardless of whether the Helper polled. systemd then leaves
      # it stopped; runcmd explicitly disables it ~60s in.
      User=daal
      Group=daal
      NoNewPrivileges=true
      [Install]
      WantedBy=multi-user.target

runcmd:
  # Fetch + verify pinned artefacts (mirror-tried in order; first verified wins).
  # The shim takes positional args matching its $1 $2 $3 contract.
  - /usr/local/bin/daal-fetch-verify /etc/daal/artifacts.json /etc/daal/release.pub /usr/local/bin/

  # Enable services
  - systemctl daemon-reload
  - systemctl enable --now sing-box
  - systemctl enable --now daal-health

  # Firewall: allow only required inbound. Note that 22/tcp is opened
  # ONLY for the 60s provisioning window, IP-bound to the Helper, and
  # is closed unconditionally in the cleanup block below — same shape
  # as the health-port rule. There is NO standing SSH surface on a
  # post-provisioning box.
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 443/tcp
  - ufw allow 443/udp
  - ufw allow from ${PROVISIONING_CLIENT_IP} to any port 22 proto tcp     # SSH, IP-bound, provisioning-only
  - ufw allow from ${PROVISIONING_CLIENT_IP} to any port 9876 proto tcp   # health, IP-bound, provisioning-only
  - ufw --force enable

  # Hardening — restart whichever sshd unit name this distro ships
  # (Debian 12+ ships ssh.service; Ubuntu 22.04+ ships ssh.service;
  # Hetzner's Ubuntu 24.04 image ships ssh.service; some older images
  # use sshd.service. Try both, succeed if either works.)
  - sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  - sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  - systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service

  # End of the 60-second post-service provisioning window.
  # The Helper's polling and DNS work happens inside this window
  # (typical end-to-end is ~30s after sing-box comes up); after 60s,
  # cloud-init unconditionally tears down everything provisioning-only:
  #   - the ephemeral SSH authorized_keys for root (the only key on
  #     the box),
  #   - the standing sshd service (no in-box SSH surface remains),
  #   - the IP-bound ufw rules for both 22/tcp and 9876/tcp (deleted
  #     by exact match against the rules that were added above —
  #     IP-bound and generic rules have different ufw-internal forms
  #     and do not match each other; `ufw --force delete` is required
  #     to skip the interactive confirmation),
  #   - the daal-health.service (which would self-terminate at its
  #     own auto_close_after_seconds=300 anyway, but we stop it
  #     explicitly so it cannot linger if the box was suspended/
  #     resumed during provisioning).
  # The 300-second auto-close inside the health binary itself is
  # belt-and-braces against the unlikely case that cloud-init's 60s
  # sleep gets skipped (e.g. early termination on error).
  - sleep 60
  - rm -f /root/.ssh/authorized_keys
  - systemctl disable --now ssh.service 2>/dev/null || systemctl disable --now sshd.service
  - ufw --force delete allow from ${PROVISIONING_CLIENT_IP} to any port 22 proto tcp
  - ufw --force delete allow from ${PROVISIONING_CLIENT_IP} to any port 9876 proto tcp
  - systemctl stop daal-health
  - systemctl disable daal-health

final_message: "Daal relay ready in $UPTIME seconds"
```

The YAML is built as a structured Go value (no string templates) and serialised via `gopkg.in/yaml.v3`.

### 9.4. The provisioning timeline

| Step | Elapsed | Notes |
|---|---|---|
| `client.Server.Create()` returns | 1–2 s | Hetzner queues |
| Server `Status: initializing` | ~10 s | KVM start, image clone |
| Server `Status: running`, cloud-init begins | ~25 s | OS booted |
| `apt-get update` + install of `packages:` block | ~40 s | small audited list: curl, ca-certificates, openssl, python3, ufw |
| Pinned-artefact fetch + signature verify | ~55 s | local verify against Daal release key |
| sing-box service starts | ~70 s | systemctl up |
| Health endpoint responds | ~75 s | first successful Helper poll (one-time-token, IP-bound) |
| Helper signs RelayPack | ~80 s | Ed25519; per-candidate mode-aware risk-tag arrays (§12.2.2) annotated from deployment context. **No DNS / Cloudflare step at V1.5** — V1.5 produces only `direct_vps` candidates so the bundle works immediately via the public IP and no DNS provisioning is needed. The Cloudflare provisioning step lands at V1.6 (§11.7, §21.2) and adds ~5–15 s for DNS record + Origin CA cert + AOP + Worker rule + provider-firewall lock. |
| Helper renders QR | ~85 s | local image generation |
| Wizard shows "Done!" | ~90 s | end-to-end |

### 9.5. Management plane — V1.5 model and the V2 upgrade

**The bootstrap problem.** A previous draft of this supplement specified an `daal-relay-mgmt` API on the box, off-by-default with no listening port, that the Helper would activate per-operation by opening a box-side `ufw` rule. **This design is unimplementable.** With SSH deleted at first boot, the Helper has no channel to open a box-side `ufw` rule or start a stopped service: cloud-provider APIs (`hcloud-go`, `govultr/v3`, etc.) operate on the cloud abstraction layer (server lifecycle, network attachments, snapshots, floating IPs) and do not run commands inside a running guest OS. There is no `client.Server.Exec(...)`. The earlier "short-lived management API gated by box-side `ufw`" had no working bootstrap path.

v2.3 picks a clean two-stage architecture: **redeploy-only for V1.5, cloud-provider firewall for V2**.

#### 9.5.1. V1.5 management plane — redeploy-only

In V1.5, **L1 and L2 rotation are implemented as redeploy**, the same way L4/L5/L6 are. There is no in-box management service. The full rotation ladder collapses to:

| Level | V1.5 implementation | Wall-clock |
|---|---|---|
| **L1 — regenerate credentials** | Redeploy on the same DC + same provider; re-sign RelayPack with same publisher key but fresh UUIDs / X25519 / passwords; old box deleted | ~90 s |
| **L2 — change TLS / route params** | Redeploy on the same DC + same provider with new params (REALITY `dest`, WS path, SNI, ports) | ~90 s |
| **L3 — move floating IP** | Cloud-provider API only — `hcloud-go.FloatingIP.Assign/Unassign`; no box-side change at all | ~10 s + family scan |
| **L4 — move datacenter** | Redeploy at a different DC | ~3 min |
| **L5 — move provider** | Redeploy at a different provider | ~2 min |
| **L6 — change protocol mix** | Redeploy with a different toolbox profile | ~3 min |

The wall-clock cost of L1/L2 rises from the (unreachable) ~5–20 s in earlier drafts to ~90 s. **This is acceptable for V1.5** because:

* L3 (floating-IP swap) is the **most common** rotation. L1/L2 are credential-hygiene operations that happen rarely.
* The redeploy code path has to exist anyway for L4–L6; reusing it costs zero implementation effort.
* The architecture stays simple: one publisher key, one OperatorRecord, deterministic redeploys. **No standing in-box service surface beyond sing-box itself plus the provisioning-window-only health endpoint.**
* It is the cleanest answer to "what is the trust surface inside the box?" — *only* sing-box runs persistently. The health endpoint is torn down inside the 60-second provisioning window (§9.6) and never restarts; the 300 s in-process auto-close is belt-and-braces.

**SSH posture.** SSH is treated as a provisioning-only surface, not a standing one. The cloud-init `runcmd` block, at the end of the 60-second provisioning window, deletes the ephemeral authorized_keys, runs `systemctl disable --now ssh.service` to stop the sshd daemon entirely, and `ufw --force delete`-s the IP-bound 22/tcp rule. The `daal` system user is configured with `shell: /usr/sbin/nologin`, `lock_passwd: true`, and `sudo: false` — it exists solely to run sing-box and daal-health under reduced privilege; it carries no interactive shell, no password, and no sudo. **The post-provisioning box exposes only sing-box on 443/TCP and 443/UDP**; nothing else listens, nothing else has firewall ingress, and nothing else has a credential the Helper or any other actor can present. An attacker who later compromises the Helper can issue redeploy commands against the FRP's cloud account (same authority the legitimate Helper has — necessary for any rotation), but cannot SSH into running boxes (no listener; no key; no firewall hole), cannot install arbitrary code, cannot reach any in-box management surface (none exists).

#### 9.5.2. V2 management plane — cloud-provider firewall + persistent narrow-API mgmt service

V2 unlocks faster L1/L2 rotation by adding a **persistent in-box management service guarded by the cloud-provider firewall** — not by box-side `ufw`. Hetzner Cloud Firewalls (`hcloud-go.Firewall.SetRules`), Vultr's `Firewall` resource, and Stark's REST equivalent all expose IP-allowlist mutation as a first-class API operation **the Helper can drive directly from its own machine**. This eliminates the V1.5 deadlock cleanly.

V2 architecture:

* **Persistent `daal-relay-mgmt` service** running on the box on a non-default port, bound to localhost-equivalent semantics: it accepts connections only from IPs the cloud-provider firewall currently allowlists. Default firewall state: no IP allowlisted → service is unreachable from anywhere.
* **`Provider.SetEphemeralFirewallRule(ctx, serverID, callerIP, durationSec)`** is added to the `Provider` interface. Implementations exist for Hetzner (Cloud Firewalls API), Vultr (Firewall API), Stark (REST). The Helper calls this to allowlist its own outbound IP for a 5-minute window before each L1/L2 operation. The provider auto-removes the rule at expiry; the Helper also explicitly removes it on completion.
* **API surface:** narrow command allowlist exactly as in earlier drafts — `regenerate-credentials`, `change-tls-params`, `swap-port`, `reload-singbox`. One-time bearer token per request, embedded by the Helper, accepted exactly once.
* **Wall-clock for L1:** ~5 s. **L2:** ~20 s. (Original ladder targets restored.)

**Why this is the correct V2 architecture but wrong for V1.5.** It requires per-provider firewall-mutation work in the `Provider` interface (~80 lines × 3 providers + tests), a persistent in-box service that has to be hardened separately, and a documented threat model for the cloud-firewall-as-bootstrap mechanism. That is V2 work, not V1.5. V1.5 ships with the redeploy-only model and is operationally complete.

#### 9.5.3. Why not retain a hardened forced-command SSH key

SSH with `command="..."` and `restrict` options can be made narrow, and it would solve the bootstrap problem without a per-provider firewall API. We rejected it because:

* SSH key compromise gives general remote-execution capability *if* the forced-command escape is ever broken (historical sshd bugs include forced-command bypasses).
* The `Provider` interface is provider-by-provider work either way; having it own firewall mutation is a more honest fit for the configurator pattern than having it own SSH key rotation.
* The V1.5 redeploy-only path lets us ship without picking either, and the V2 cloud-firewall path is cleaner than forced-command SSH on every dimension that matters (auditable rule expiry, no SSH attack surface at all, narrow API rather than narrow shell).

#### 9.5.4. Why not provider-API-only for everything, forever

Cloud-provider APIs do not let us regenerate sing-box keys, rewrite TLS parameters, or swap a SNI host without rebuilding the box. V1.5's redeploy-only approach pays the full ~90 s rebuild cost on every credential-hygiene operation. V2's mgmt service brings that down to ~5 s. The 18× speed-up matters at scale (many FRPs each rotating credentials weekly) but is not blocking at V1.5 scale (≤50 FRPs in pilot).

#### 9.5.5. FRP-10 implementation lock for the V2 mgmt-plane (added in v2.3.9)

The §9.5.2 architecture lands at FRP-10 with five concrete locks the test surface pins. These are the implementation choices the architecture left underspecified in v2.3.8:

1. **Mgmt-plane TLS posture: self-signed leaf cert, fingerprint-pinned per deploy.** The box generates a P-256 ECDSA self-signed leaf at first boot inside `daal-relay-mgmt`. Cert lifetime is 10 years; there is no in-place management-cert rotation surface in V2. The bootstrap-window relay (§9.6) publishes the SHA-256 fingerprint to the Helper, which pins it into `OperatorRecord.MgmtTLSFingerprint`. The Helper-side mgmt client (`publisher/deploy/mgmt`) verifies the box's TLS leaf against this fingerprint on every call; mismatch is `ErrFingerprintMismatch` (no fallback to system trust store, and no unpinned accept; the client may bypass CA verification only to apply its own `VerifyPeerCertificate` pin). Empty fingerprint fails closed — the wizard falls back to the FRP-7 redeploy path.

2. **Mgmt-plane port: random per deploy in [10000, 65000].** The wizard picks the port at provision time and stamps it into both `OperatorRecord.MgmtPort` and the cloud-init template's `/etc/daal/mgmt/port`. There is **no fixed constant in any call site** — the Helper's mgmt client constructs the URL from `rec.PublicIP:rec.MgmtPort`, and the on-box service reads the port from `/etc/daal/mgmt/port` at boot. A `MgmtPort==0` record is the explicit V1.5 marker; the wizard refuses the V2 fast path on such records and routes to redeploy.

3. **Mgmt API surface: exactly three routes.** `POST /rotate-credentials` (L1, ~5 s), `POST /rotate-tls` (L2, ~20 s), `GET /health` (no auth). Adding a fourth route requires a supplement amendment. `cmd/daal-relay-mgmt/main_test.go::TestExactlyThreeRoutes` pins this at the implementation level.

4. **Mgmt auth: Ed25519-signed token, op-bound, 5-minute window.** Authorization header body is `<nonce>:<ts>:<op>:<base64-sig>`. Signature covers `<nonce>:<ts>:<op>`; `op` is bound to one of `{rotate-credentials, rotate-tls}` and the on-box service rejects token replay across endpoints. Timestamp window is `[-300 s, +60 s]` from server clock. The publisher key whose private half mints these tokens is the same Ed25519 key that signs the RelayPack — it lives in the Helper's keystore and **never on the box**; only the public half is written to `/etc/daal/mgmt/pubkey` by cloud-init.

5. **Cloud-firewall as gate, box-side ufw closed for mgmt.** Box-side `ufw` opens 443/tcp + 443/udp for sing-box and the provisioning-window 22/tcp + 9876/tcp; **box-side `ufw` does NOT open the mgmt port.** The cloud-provider firewall is the only gate. Per-call flow: Helper opens `(callerIP, mgmtPort)` for 300 s via `Provider.SetEphemeralFirewallRule(serverID, callerIP, port, 300)`, drives the mgmt call, removes the rule via `RemoveEphemeralFirewallRule(rule)` in a `defer` (cleanup runs even on call error). The provider auto-expires the rule at 300 s as belt-and-braces.

**FRP-10 also locks the Android boundary (§9.5.5.bis).** The Android publisher wizard is provision + bind + QR only — no rotate, no V2 mgmt-plane signing key on the phone. Rotations always happen on a desktop wizard. Rationale: the V2 mgmt token is a long-lived credential (the per-deploy publisher pubkey is baked into cloud-init); putting it on a phone whose loss model is "drop in a taxi" is a worse posture than requiring a second device for rotations. The Android `DeployBridge` interface deliberately exposes only `provision`, `bind`, and `renderQr`; reflection + source-grep tests in `client-android/app/src/test` enforce this at the file level.

**Three carry-overs the FRP-10 test surface defers** (live-pilot work):

* The Vultr adapter compiles + tests against an injected `vultrClient` interface; the live `govultr/v3` SDK wiring is gated on the V2 alpha pilot.
* The Stark adapter compiles + tests against the same interface shape; live API testing is gated on a Stark account with credentials.
* The Android `AndroidKeystorePublisherKey` (KeyGenParameterSpec for Ed25519 with `setUserAuthenticationRequired(true)`) and the gomobile-bound `mobile/deploy/Deploy.aar` are gated on the cross-compile toolchain landing.

The §14.4 / §14.6 rotation invariants are preserved unchanged. The V2 fast path replaces the redeploy step inside L1 / L2 only; L3 (`Provider.AssignFloatingIP`), L4–L6 (full redeploy), and L7–L9 (cdn_fronted operations on the Cloudflare API, not the box) all keep their V1.5 implementations.

### 9.6. The health endpoint hardening

The `daal-relay-health` endpoint exposes one route (`GET /healthz`) for the Helper to confirm sing-box is up. v1 left it open on port 9876 for ~5 minutes. v2 hardens it three ways:

1. **One-time bearer token.** Generated by the Helper and embedded in the cloud-init YAML; the endpoint requires `Authorization: Bearer <token>` and accepts the token at most once.
2. **IP-bound `ufw` rule.** Port 9876 is opened only to the Helper's outbound public IP (captured via `ipify` or equivalent at provisioning time), not to the world.
3. **Provisioning-window-only lifetime.** The cloud-init `runcmd` block tears down the IP-bound rule, stops the service, and disables the unit at the end of the **60-second post-service provisioning window** (the typical end-to-end Helper poll completes in ~30 s; the 60-second window gives slack for slow networks). The health binary itself **also** carries an internal `auto_close_after_seconds=300` self-terminate as belt-and-braces against the unlikely case that cloud-init's 60-second sleep is skipped (e.g. early termination on error). The cleanup is **not** gated on confirmed Helper success — a successful Helper poll happens to fall inside the same window, but the cleanup runs unconditionally so the endpoint cannot linger if the Helper crashed mid-provision.

These three defences are independent. Any one alone would be sufficient for normal operation; together they make the health endpoint a non-issue for an attacker who is not already in the same network path as the Helper at the moment of provisioning.

### 9.7. Hardening pre-baked

Cloud-init disables SSH password auth, disables root SSH, sets a strict UFW firewall, and uses systemd capabilities to drop sing-box's privilege envelope to `CAP_NET_ADMIN + CAP_NET_BIND_SERVICE` only. Identical across all deployments — the FRP does not get a "configure security" choice because they cannot reasonably make it.

---

<a name="10-tokens"></a>
## 10. Token storage and trust boundary

The FRP's API tokens (Hetzner, Cloudflare, etc.) are the most sensitive material the Helper handles.

### 10.1. What never happens

* Never transmitted to any Daal-controlled server.
* Never written to disk in plaintext.
* Never logged.
* Never copied to system clipboard automatically.
* Never sent in error reports (per CC.6, no error reports leave the device anyway).

### 10.2. What does happen

* On step 3, user pastes into a `type=password` input.
* Helper validates by calling `client.Server.All(ctx)` directly to Hetzner.
* On success, token is **immediately encrypted** with Argon2id-derived key from the user's Daal device PIN.
* Encrypted token stored in the OS-native keystore (`daal.deploy.hetzner.<account-id>`).
* Plaintext overwritten in memory; input field cleared.
* Subsequent operations: retrieve, decrypt with PIN-derived key, use for API call, re-zero.

### 10.3. Defence-in-depth

* **Layer 1 (OS keystore):** unlocked by OS-level credentials; locked device cannot extract content.
* **Layer 2 (Daal PIN):** keystore content is itself AES-GCM-encrypted with Argon2id key derived from a Daal-internal PIN distinct from the OS PIN.

Same model Daal applies to subscription URLs and other sensitive at-rest data per V1.3.

### 10.4. Token revocation

User revokes from Hetzner's console at any time, independent of Daal. Helper detects revocation on next API call (401) and surfaces "Your Hetzner token was revoked. Generate a new one and re-paste it here." OperatorRecords preserved; usable again on fresh token. **The user retains complete control over their cloud credentials at all times.**

### 10.5. Dedicated cloud project recommendation

The wizard recommends and the cell-membership UX requires that the FRP create **a dedicated cloud project / sub-account scoped to Daal**. Hetzner's Project model, Vultr's Sub-Accounts, and Linode's Linode Apps all support this for free. Scoping bounds blast radius if the token is later compromised: the attacker cannot reach the FRP's other cloud workloads.

---

<a name="11-toolbox"></a>
## 11. Protocol toolbox — what one VPS can host, honestly

Daal's parser-accepted transport family enum is fixed in `bundle/go/bundle/types.go` (lines 27–48). The 16 named families plus `other` (intentionally unhandled). **Trojan-TLS and ShadowTLS are not first-class families today**; they are ShadowTLS-wrapped Shadowsocks deployments expressed as `transport_family: "shadowsocks"` with ShadowTLS-specific keys carried inside the existing per-route `family_specific_config` opaque-JSON slot. Adding `trojan-tls` or `shadowtls` as their own family values is a `specs/transport-families-v1.md` extension and is **not** a V1.5 deliverable.

Not all of the existing families can be hosted on a normal VPS. The supplement says so explicitly to avoid overclaiming.

### 11.1. Three honesty classes

| Class | Definition | First-class families |
|---|---|---|
| **`vps-native`** | A normal helper-controlled VPS can host this directly with sing-box and a few systemd units. | `vless-reality`, `naive`, `websocket-tls`, `hysteria2`, `tuic`, `shadowsocks` (incl. ShadowTLS-wrapped via `family_specific_config`), `wireguard`, `amneziawg` (8 families) |
| **`vps-possible`** | The VPS can host this but with extra engineering — domain ownership, CDN account, special server-side build. | `webtunnel`, `masque` (H3/QUIC↔H2/TCP fallback ladder modelled in `masque.go`) |
| **`external-ecosystem`** | This family fundamentally requires infrastructure beyond a single VPS. Reachable through partner deployments and `transport_module`, not direct provisioning. | `psiphon` (upstream's own bundle network), `conjure` (refraction stations), `snowflake` (rendezvous + proxy ecosystem), `tor-bridge` (PT bridge ecosystem partially), `lifeline_relay` (kill-switch + audit + MOU per 3G), `transport_module` (the future-proof slot) |

The RelayPack profile **annotates each candidate with its honesty class**. Selectors use this for UI explanation: "This network is hard to reach. Try a `transport_module` route?" is a different prompt than "Try the WebSocket-TLS candidate from this RelayPack."

#### 11.1.1. Exposure-mode compatibility (added in v2.3.4)

The honesty class above is orthogonal to the **exposure mode** of a candidate. A `vps-native` family may be deployed `direct_vps` (the family's Daal connects to the origin VPS IP), `cdn_fronted` (the family's Daal connects to a CDN edge that proxies to the origin), or both. The two distinct surfaces TIC observes are different in each mode (see §12.2.2 schema and §13.4 cooldown rules), so the validator at `publisher/deploy/relaypack/validator.go` enforces compatibility at import time:

| Family | `direct_vps` | `cdn_fronted` | Notes |
|---|:---:|:---:|---|
| `vless-reality` | yes | **no** | Direct TCP/443. Cloudflare cannot proxy REALITY as intended (REALITY's design point requires the origin to terminate the outer TLS handshake itself; CDN-termination defeats the indistinguishability). |
| `websocket-tls` | yes | yes | Best CDN-frontable candidate; native HTTPS shape. |
| `webtunnel` | possible | yes | HTTPS/WS-shaped; `vps-possible` direct without CDN. |
| `naive` | yes | conditional | `cdn_fronted` only if the deployed shape is Cloudflare-compatible HTTPS behavior. Do not assume; the validator requires the FRP to opt in explicitly. |
| `masque` | partial | conditional | H2/TCP-like lifeline may fit ordinary CDN proxying; H3/CONNECT-UDP does **not** fit ordinary Cloudflare HTTP-proxy and would require Cloudflare Spectrum (Enterprise). |
| `hysteria2` | yes | **no** | UDP. Cloudflare's standard HTTP/HTTPS proxy does not carry arbitrary UDP. |
| `tuic` | yes | **no** | UDP/QUIC. Same reason. |
| `wireguard` | yes | **no** | UDP, not HTTP-shaped. |
| `amneziawg` | yes | **no** | UDP, not HTTP-shaped. |
| `shadowsocks` (incl. ShadowTLS-wrapped) | yes | **no** | Unless separately wrapped as a WebSocket/HTTPS candidate, which should be modelled as a distinct candidate of family `websocket-tls` rather than `shadowsocks`. |
| `psiphon` / `conjure` / `snowflake` / `tor-bridge` / `lifeline_relay` / `transport_module` | **n/a** | **n/a** | External ecosystems; not provisionable on a helper VPS in either mode. |

A healthy RelayPack is therefore a **mix of `direct_vps` and `cdn_fronted` candidates from the same publisher**, not "everything fronted" or "everything direct." The selector treats the two modes as different shared-risk-cohort siblings: a Cloudflare-wide block silently demotes `cdn_fronted` candidates while leaving `direct_vps` siblings unaffected; a TIC IP-burn on the origin's prefix demotes `direct_vps` candidates while leaving `cdn_fronted` siblings unaffected. This is the breadth-as-property argument from §1, applied at exposure-mode granularity.

V1.5 ships the schema, validator, and selector vocabulary above, but the V1.5 wizard produces only `direct_vps` candidates. **`cdn_fronted` candidate provisioning ships at V1.6** (§11.7, §21.2). FRPs running the V1.5 wizard see a "CDN-fronted candidates: coming in V1.6" line in the toolbox screen, not a broken option.

### 11.2. The "Reliable for Iran" toolbox profile

Not a protocol; a **named deployment profile** combining `vps-native` candidates known to fit the Iranian threat model. The wizard's default is `iran-default`:

| Required | Family | Rationale |
|---|---|---|
| Always | `vless-reality` (TCP/443) | Strongest HTTPS-shaped TCP candidate; blends with real TLS to popular hosts |
| Always | `websocket-tls` (TCP/443, SNI-multiplexed) | HTTPS-shaped fallback when REALITY is fingerprinted |
| Always | `naive` (TCP/443, SNI-multiplexed) | Different outer-TLS posture from REALITY; diversifies TLS-fingerprint risk |
| If UDP works | `hysteria2` (UDP/443) | High-performance UDP with strong obfuscation |
| Optional | `shadowsocks` (Shadowsocks-2022 wrapped in ShadowTLS-v3, expressed via `family_specific_config`) on TCP/443 | Compatibility fallback; popular in Iran community |
| Optional | `amneziawg` (UDP/51820) | WireGuard with Iran-specific Jc/Jmin/Jmax/H1..H4 params |

The profile is **declarative**: the wizard reads a `iran-default.toml`, builds the sing-box config, sets the RelayPack candidates, annotates the per-candidate mode-aware risk-tag arrays (§12.2.2 — `public_risk_tags` and `origin_risk_tags` per `exposure_mode`). Other profiles (`china-default`, `russia-default`, `general-purpose`) are added later. **Profiles are data, not code** — adding one is a config + test, not a release.

### 11.3. UDP-availability gating

Iran's UDP/QUIC posture changes with the network and the day. The RelayPack flags UDP-required candidates with the **existing** `.sbp` field `udp_gated: true` (per `bundle/go/bundle/types.go:201`); the client selector skips them entirely when its UDP probe fails (§13). No round-trip wasted on a guaranteed-failing protocol. **No new field is introduced** — `udp_gated` is reused with its existing semantics.

### 11.4. Active-probing-risk class

Each candidate carries a `probing_risk_class` (`low` / `moderate` / `high`):

* `low` — REALITY, ShadowTLS-v3-wrapped Shadowsocks (resistant to active probing).
* `moderate` — Hysteria2, TUIC, AmneziaWG.
* `high` — Plain (non-wrapped) Shadowsocks, raw WireGuard, plain TLS-only proxies (fingerprintable under sustained scrutiny).

The selector's race policy (§15) prefers `low` candidates for the leader race and demotes `high` candidates if the network shows recent active-probe-shaped resets.

### 11.5. One VPS provides what, exactly

A single helper VPS can host a **dense first layer of protocol diversity** (8 of 16 first-class families as `vps-native`, plus 2 more as `vps-possible` with extra engineering). It cannot provide **independent infrastructure diversity**: if the IP, ASN, provider, or domain is blocked, every candidate sharing that risk-tag fails together. This is precisely why the RelayPack's shared-risk graph (§12) and the selector's shared-risk-edge cooldowns (§13) exist. A second helper VPS at a different provider in a different ASN, or a trusted-cell peer's RelayPack (§16), is the way to obtain real infrastructure diversity. The supplement does not pretend one VPS solves this; the architecture is honest about staged diversity:

* **Stage 1 (V1.5):** one VPS, multiple transports — protocol diversity, correlated failure made visible.
* **Stage 2 (V2):** same FRP, multiple VPSes at different providers — adds infrastructure diversity.
* **Stage 3 (V2):** trusted cells + federation primitives — adds peer-FRP diversity (federation primitives ship at FRP-11 alongside `specs/cell-v1.md`; per §21.3 V2 deliverable list).
* **Stage 4 (V3):** gated public directory — adds community diversity once abuse handling is proven (only if §17.2's gate flips; otherwise V3 never ships and trusted cells are the architectural endpoint).
* **Stage 5 (post-V3):** partner transports (Psiphon, Conjure, Lifeline) — adds external-ecosystem diversity.

### 11.6. Field-observed tactical modifiers (added in v2.3.4)

A community of operators outside Daal ships ad-hoc circumvention tools whose tactics are sometimes more aggressive, more brittle, and more legally complicated than what Daal is willing to make a default. The intel notes at `research/intel-and-some-working-methods.md` document the strongest of these. v2.3.4 records them here as **schema-reservation slots and selector-discipline rules** so Daal can later *opt in* to them as gated modifiers without retrofitting the schema each time. **Every row below is `Default? no` and gated post-V2.** This section is **vocabulary reservation, not a ship commitment.**

This table is **not** the full external-ecosystem roadmap; Tor bridges, Snowflake, WebTunnel, Psiphon, and Conjure remain governed by their existing route-family specs and phase plans (3A/3B/3D + the `external-ecosystem` honesty class). They do not appear here.

| Technique | Daal treatment | Default? | Phase |
|---|---|:---:|---|
| **FakeSNI / TCP desync** | A `{kind: "client_desync"}` entry in the per-candidate `modifiers[]` array (§12.2.2.bis); client-side packet manipulation prepended to the connect; **Linux desktop only** (raw-socket capability); bumps the candidate's effective `probing_risk_class` to `high`. Does **not** change `exposure_mode` — a desync-modified `direct_vps` candidate is still a `direct_vps` candidate for cooldown attribution. | no | reserved schema slot via `modifiers[]`; implementation post-V2 after censor-lab validation |
| **TLS fragmentation / packet mutation** | A future per-candidate `{kind: "tls_fragment"}` entry in `modifiers[]`. Censor-lab tested before ship to confirm the mutation does not itself fingerprint Daal. Reserved schema slot via `modifiers[]`; no separate `exposure_mode` value. | no | post-V2 |
| **MITM domain fronting** | Browser-only emergency lifeline; requires **explicit local-CA install warning** (the user is asked to trust a local root CA generated on their device, with the security implication documented). Out of scope for Daal desktop's normal flow; reserved as a future `lifeline-strict` modifier. | no | post-V2 |
| **Serverless HTTP relay** (Cloudflare Workers, Google Apps Script-style) | Modelled as `exposure_mode: serverless_external`; HTTP-only; carries `scarcity_class: emergency`; ineligible for bulk-mode use; the validator at V1.5 and V1.6 rejects this enum value, V2+ may enable it under explicit feature-flag. **This is a real new endpoint type, not a packet-mutation modifier**, so it lives in the `exposure_mode` enum, not in `modifiers[]`. | no | reserved schema slot in `exposure_mode`; post-V2 |
| **Clean-CDN-IP scanning** | **Discipline rule, not a candidate type.** Iran-side clients **must not** perform active mass scanning to discover working CDN edge IPs. The selector relies on **publisher/cell intelligence + passive per-network memory** instead. Active scanning from a censored client would generate Daal-attributable traffic patterns, accelerate burn, and risk legal exposure for the recipient. The selector rules in §13.3 enforce this by never widening probe sets beyond the candidates explicitly listed in the active RelayPack. | no | discipline rule active immediately at V1.5 (selector-side) |

The schema correction (v2.3.5): the **`exposure_mode` enum** is `direct_vps | cdn_fronted | serverless_external` — these are **endpoint types** (what the recipient connects to). **Packet-mutation modifiers** like `client_desync` and `tls_fragment` live in a separate per-candidate `modifiers[]` array (§12.2.2.bis) because they describe **what the recipient does to its outgoing packets**, not what endpoint it connects to. Earlier v2.3.4 drafts conflated the two and listed `client_desync` as an `exposure_mode` value; that was wrong and is corrected here.

The validator at `publisher/deploy/relaypack/validator.go` rejects `serverless_external` (in `exposure_mode`) and any non-empty `modifiers[]` array at V1.5 and V1.6. They exist as reserved schema slots so a future RelayPack carrying them parses cleanly into typed structs; the rejection is a runtime gate, not a parse error. This means a future enabling change does **not** require a new `spec_version` bump.

### 11.7. V1.6 Cloudflare-fronted deployment template (added in v2.3.4; specified now, implemented in V1.6)

`cdn_fronted` candidates require a deployment shape that prevents the **origin-IP leak attack** (§19.2.6). v2.3.4 specifies the full template now so V1.6 has a stable spec target; **V1.5 does not implement this template** because V1.5 does not produce `cdn_fronted` candidates. The template is mandatory at V1.6 for any candidate carrying `exposure_mode: cdn_fronted`; the validator at `publisher/deploy/relaypack/validator.go` enforces structural conformance and the `publisher/deploy/cloudflare/` package implements the operations.

**Required deployment posture** for every `cdn_fronted` candidate in V1.6:

* **Cloudflare Origin CA cert on the origin** (not a public Let's Encrypt cert that would land in CT logs and be discoverable via cert-transparency scanning). The Origin CA cert is presented by the origin only to Cloudflare's edge and is not in any public CT log.
* **Cloudflare Full Strict TLS verification mode** (`ssl_mode: full_strict`). The edge validates the origin cert against Cloudflare's Origin CA root before forwarding any request.
* **Authenticated Origin Pulls enabled** (`authenticated_origin_pulls: true`). The origin only accepts inbound connections that present a Cloudflare-signed client cert. A bare scan to the origin IP — even from someone who learned the IP — fails the TLS handshake.
* **Provider-level firewall** (Hetzner Cloud Firewall, Vultr Firewall API, Stark REST) allowing inbound port `443/tcp` only from Cloudflare's published edge IP ranges (`https://www.cloudflare.com/ips-v4` + `ips-v6`).
  * **Where the refresh runs.** The edge-range fetch and the cloud-provider firewall update are performed **by the FRP Helper machine** (the diaspora user's desktop, where the Daal wizard / `daal-deploy-cli` runs) — not by the origin box. The Helper has the cloud-provider token; the origin box does not, and §11.7 explicitly forbids the origin holding any cloud-provider credential.
  * **When the refresh runs.** At three moments on the Helper: (a) immediately at every deploy and every rotate operation (synchronous; mandatory); (b) on an explicit "check" command exposed in the desktop UI under "Settings → Routes → Verify CDN posture"; (c) optionally as a local OS scheduled task on the Helper machine (Tauri-managed `cron`/`launchd`/`Task Scheduler` job, off by default; opt-in checkbox in the wizard for FRPs who want daily automatic refresh without launching the Helper UI). The Helper makes a normal HTTPS GET to `https://www.cloudflare.com/ips-v4` + `ips-v6`, parses the result, and applies it via the cloud-provider's firewall API using the Helper-resident token.
  * **Why not the origin box.** Putting the refresh job on the origin would require the origin to hold a cloud-provider API token, which violates §10's "Daal never holds cloud credentials on a Daal-controlled server" property, expands the origin's blast radius from "one family's tunnel" to "FRP's whole cloud account", and creates a latent compromise vector if the origin is ever taken over. The Helper-side refresh is strictly safer; the worst case if the Helper is offline for weeks and Cloudflare publishes new ranges in that interval is that the firewall rule lags real edge IPs — which would manifest as `origin_unhealthy` (522/525/526) errors at the recipient and trigger the §13.4 origin-repair path, not as a censorship event. The FRP can then run a "check" operation manually to re-sync. The trade-off is acceptable.
  * **Box-side `ufw` is not the gate** for this rule — the cloud-provider firewall is, because it operates upstream of the box, survives sing-box restarts, and (most importantly) is reachable by the Helper without the origin holding any token.
* **No DNS-only A or AAAA record** on any zone owned by the FRP that resolves to the origin IP. The wizard refuses to deploy if such a record exists for the chosen domain.
* **No SMTP / MX / SSH / extra services** on the origin IP. The §9.3 cloud-init posture (sing-box on 443/TCP+UDP only; sshd disabled; ufw closed by default) plus the provider-firewall rule above means the origin IP is unresponsive to any direct probe except a Cloudflare-edge-sourced TLS handshake bearing the right client cert.
* **Public random path → Cloudflare Worker / Page Rule rewrite → stable origin path indirection.** Each `cdn_fronted` candidate's `family_specific_config._relaypack` carries a `public_path_fp` (the visible random path) and a Worker/Page Rule on the FRP's Cloudflare zone rewrites it to a stable origin path that the sing-box config expects. This means **public-path rotation is Cloudflare-API-only** and does not require a box redeploy. Without this indirection, "rotate path from Cloudflare alone" is false (the box config would also have to change), which is why the indirection is mandatory at V1.6.
* **HTTP/HTTPS only**; no Spectrum dependency. UDP-based families are never `cdn_fronted` (§11.1.1). Cloudflare's free-tier proxy carries HTTP/HTTPS on standard ports; arbitrary TCP/UDP requires Cloudflare Spectrum (Enterprise) which is out of scope.

**Rotation paths under this template** are split per failure category in §14.4 (the CDN-fronted rotation table). Briefly: most `cdn_fronted` rotations are Cloudflare-API-only (hostname change, public-path change) and complete in seconds without a box change; origin-IP rotation is operator hygiene against future leaks (TIC never observed the origin); CDN-wide failure demotes the whole `cdn:cloudflare` cohort and the selector falls back to `direct_vps` siblings in the same RelayPack.

**Implementation handoff to V1.6** (§21.2): `publisher/deploy/cloudflare/` using `cloudflare-go/v4`; cert provisioning via the Origin CA API; firewall rule provisioning via the chosen cloud provider's SDK; Worker/Page Rule template; daily edge-range refresh job. The wizard's CDN screen surfaces the BYO-domain default (§20.4); the project test-zone is available only behind a strong warning for closed-pilot use.

---

<a name="12-relaypack"></a>
## 12. The RelayPack profile — `.sbp` with portfolio intelligence

A RelayPack is **an `.sbp` bundle conforming to a tighter profile**. It is *not* a new format. The supplement commits to writing `specs/relaypack-v1.md` to lock the profile precisely.

### 12.1. Why a profile, not a new format

`.sbp` already carries `transport_family`, `udp_gated`, `redistribution_policy`, experimental-gate flags, multi-route manifests, publisher signatures. A new bundle format would force a full engine ABI cycle (release-symbol additions, parser/verifier rebuilds, route-row schema migration, v2-superset and v3-superset regression rewrites, full soak re-runs). The profile approach reuses the existing format. **It is not, however, silently forward-compatible with older clients:** Daal's verifier round-trips `bytes → typed Manifest → CanonicalManifestJSON → verify` (`bundle/go/bundle/sbp.go:73`, `bundle/go/bundle/canonical.go:11`), so unknown JSON fields are dropped at unmarshal and a publisher's signature over those fields will not verify on an old parser. The profile therefore uses two distinct landing strategies depending on whether the field can survive in an opaque slot.

**Honest scope of the schema work this requires:** No exported engine ABI change — release-symbol count stays at 48; engine `Version` stays unchanged. **But this is real schema, parser, importer, and store widening at V1.5**, not zero work, and it is **update-required for older clients on the bundle-level fields** (same compatibility contract as 3A/3B/3E/3F):

* **Per-candidate metadata** (the v2.3.5 mode-aware schema: `exposure_mode`, `family_class`, `probing_risk_class`, `modifiers[]`, `public_risk_tags[]`, `origin_risk_tags[]`; full schema in §12.2.2 + §12.2.2.bis) is carried **inside** `RouteManifestEntry.FamilySpecificConfig` (the existing `json.RawMessage` opaque-JSON slot at `bundle/go/bundle/types.go:209`) under a `_relaypack` sub-object. Because that slot is `json.RawMessage`, the *bytes* round-trip cleanly through canonicalisation regardless of whether the parser understands the inner schema. **Genuinely backward-compatible on these fields.** The validator at `publisher/deploy/relaypack/validator.go` parses them out of the opaque blob at import time; the selector reads them at selection time. (Earlier drafts of this section placed a flat `shared_risk_tags` array as a new first-class field on `RouteManifestEntry`; the v2.3.5 design keeps the mode-aware schema inside the opaque blob and splits the tag list into `public_risk_tags` and `origin_risk_tags` so cooldown propagation is correct in CDN-fronted mode, and separates packet-mutation behaviours into the orthogonal `modifiers[]` array.)
* **Bundle-level metadata** (`relay_pack_id`, `shared_risk_graph`, cell-scope defaults, and the V1.6-additive `freshness_url` per §14.4) lands as a new optional top-level slot on `Manifest`, in the same shape as 3A's `kill_switches`, 3B's `rendezvous_hints`, 3E's `transport_modules`, and 3F's `redistribution_chain` / `delegate_caps`. **This is genuinely update-required for old clients**: a pre-V1.5 verifier rejects the signature on a RelayPack-bearing bundle and prompts the user to update Daal. The `spec_version` integer is bumped at V1.5 to make this gate explicit; V1.6's `freshness_url` is additive inside the same already-bumped slot and does not require a further bump.
* The signed canonical-payload rules in `bundle/go/bundle/sign.go` + `bundle/go/bundle/canonical.go` are extended to cover the new top-level slot. Existing `.sbp` files (without it) verify unchanged on both old and new clients.
* The importer (`bundle/go/importer/importer.go`), the import boundary (`core/trust/state.go`), and the route-store row (`core/routestore/store.go`, `RouteRow` at `core/routestore/store.go:127`) widen to land the new fields. **Today's importer drops several advanced V3 fields**; closing that gap is part of V1.5's import-path work and is one of the three V1.5 code-side gaps named in §13.6.
* `publisher/deploy/relaypack/validator.go` enforces the profile rules at import time.

The profile inherits Daal's existing trust machinery — publisher keys, signing, TOFU, revocation, redistribution-policy caps, experimental-gate flags — for free. The profile is enforced at import time and consumed by selection.

### 12.2. What the profile adds beyond plain `.sbp`

#### 12.2.1. `relay_pack_id`

A bundle-level identifier grouping candidates that share infrastructure risk. All candidates from one helper-provisioned VPS share one `relay_pack_id`. A trusted-cell-aggregated directory may carry many `relay_pack_id`s.

#### 12.2.2. The mode-aware risk-tag split (`exposure_mode`, `public_risk_tags`, `origin_risk_tags`)

> **v2.3.4 model correction.** Earlier versions of this section carried a flat `shared_risk_tags` array. That conflated **what TIC observes and can blocklist** with **what only the operator sees**, which produced wrong cooldown propagation for `cdn_fronted` candidates: a CDN-fronted candidate's origin IP failure would have falsely demoted every sibling sharing that origin even though TIC never observed the origin. v2.3.4 replaces the flat list with a four-key structure: `exposure_mode`, `family_class`, `probing_risk_class`, `public_risk_tags[]`, `origin_risk_tags[]`.

Per-candidate metadata is **carried inside the existing `RouteManifestEntry.FamilySpecificConfig` `json.RawMessage` slot** as a `_relaypack` sub-object so the bytes round-trip through old parsers' canonicalisation cleanly:

```jsonc
route.family_specific_config = {
  ...                           // family-specific keys (REALITY dest, SNI, etc.)
  "_relaypack": {
    "exposure_mode":       "direct_vps",      // direct_vps | cdn_fronted | serverless_external (V2+)
    "family_class":        "vps-native",      // vps-native | vps-possible | external-ecosystem
    "probing_risk_class":  "low",             // low | moderate | high
    "modifiers":           [],                // optional client-side packet-mutation modifiers; see §12.2.2.bis. Empty at V1.5 / V1.6.
    "public_risk_tags":    [ /* what TIC sees */ ],
    "origin_risk_tags":    [ /* what only the operator sees */ ]
  }
}
```

**Why `exposure_mode` and `modifiers[]` are separate.** `exposure_mode` describes **what endpoint the recipient connects to** (direct origin, CDN edge, serverless function). `modifiers[]` describes **how the recipient mutates outgoing packets before they hit the network** (FakeSNI prepend, TLS fragmentation, segment reordering). The two are orthogonal: a `direct_vps` candidate may or may not carry a `client_desync` modifier; a `cdn_fronted` candidate may or may not carry a TLS-fragmentation modifier. Conflating them would make the schema lie about what the censor observes versus what the client does. Earlier drafts of v2.3.4 placed `client_desync` as an `exposure_mode` value; v2.3.5 (this revision) corrects that.

**The two tag arrays are not symmetric.** `public_risk_tags` describe surfaces that the censor can directly observe and blocklist; `origin_risk_tags` describe surfaces that exist only in the operator's deployment topology and are never exposed to TIC under a correctly hardened `cdn_fronted` deployment (§11.7). Cooldown propagation rules (§13.4) treat them differently:

* A failure attributed to a `public_risk_tag` → the cooldown propagates across **every other candidate carrying that tag** (the censor blocked the surface; siblings sharing it are also burned).
* A failure attributed to an `origin_risk_tag` on a `cdn_fronted` candidate → the cooldown is **operator hygiene only** and does **NOT** propagate to `public_risk_tags` of sibling fronted candidates that happen to share the same origin (TIC never saw the origin; sibling public surfaces remain healthy).

##### `direct_vps` example (note: non-empty `public_risk_tags`)

Direct-mode candidates **still carry public risk tags** — the public IP, ASN, provider, DC, port, and the SNI/cover-SNI string TIC observes are all directly visible to the censor. The only tag a direct-mode candidate is **forbidden** to carry in `public_risk_tags` is `cdn:*` (CDN-mode-only). It **may** carry `public_domain:*`, `host:*`, and `sni:*` when the deployment legitimately uses a visible domain on its own VPS without a CDN in front (a direct `websocket-tls`, `naive`, or HTTPS-shaped candidate is a normal example). It is also forbidden to carry any `origin_*` tag (in direct mode the origin IS the public surface; the `origin_*` array is meaningful only when the origin is distinct, i.e. `cdn_fronted`).

```jsonc
"_relaypack": {
  "exposure_mode": "direct_vps",
  "family_class":  "vps-native",
  "probing_risk_class": "low",
  "public_risk_tags": [
    "public_ip:5.75.x.x",
    "public_asn:24940",          // Hetzner
    "public_provider:hetzner",
    "public_dc:fsn1",            // Hetzner Falkenstein
    "public_port:tcp443",
    "sni:www.microsoft.com"      // REALITY cover-SNI; visible in ClientHello
  ],
  "origin_risk_tags": []
}
```

In `direct_vps` mode the origin IS the public surface, so `origin_risk_tags` is empty by convention. (An alternative would be to duplicate the tags into both arrays; the chosen convention is that `origin_risk_tags` is meaningful only when the origin is **distinct from** the public surface, i.e. `cdn_fronted`.)

##### `cdn_fronted` example

```jsonc
"_relaypack": {
  "exposure_mode": "cdn_fronted",
  "family_class":  "vps-native",
  "probing_risk_class": "low",
  "public_risk_tags": [
    "cdn:cloudflare",
    "public_domain:momsroute.example.com",
    "sni:momsroute.example.com",
    "host:momsroute.example.com",
    "ws_path_fp:sha256:e3b0c4..."   // visible random path, fingerprinted not literal
  ],
  "origin_risk_tags": [
    "origin_ip:5.75.x.x",
    "origin_asn:24940",
    "origin_provider:hetzner",
    "origin_dc:fsn1",
    "origin_cert:cloudflare_origin_ca"
  ]
}
```

Here TIC sees only the entries in `public_risk_tags` (Cloudflare's anycast IP is shared with millions of unrelated sites and is not a useful blocklist target except at very high collateral cost). The `origin_risk_tags` exist for the FRP's own rotation logic and for correctly attributing a CDN-origin error (522/525/526) to origin repair rather than to censorship recovery (§13.4).

##### Validator rules at `publisher/deploy/relaypack/validator.go` (v2.3.5)

The validator enforces structural rules at import time:

* `exposure_mode` must be one of `direct_vps | cdn_fronted | serverless_external` (and the per-candidate `modifiers[]` array, §12.2.2.bis, may contain `client_desync` post-V2). V1.5 and V1.6 reject `serverless_external` (reserved schema slot; see §11.6) and reject any non-empty `modifiers[]` array (reserved post-V2).
* `cdn_fronted` requires the family to appear as `yes` or `conditional` in §11.1.1's `cdn_fronted` column. UDP-based families with `exposure_mode: cdn_fronted` are a parse-time reject.
* `cdn_fronted` candidates must carry **at least one `cdn:*` tag** in `public_risk_tags` AND **at least one `origin_*` tag** in `origin_risk_tags`. A `cdn_fronted` candidate with empty `origin_risk_tags` is malformed.
* `direct_vps` candidates must carry **at least one `public_ip:*` tag** in `public_risk_tags`. They **MAY** carry `public_domain:*`, `host:*`, and `sni:*` tags (a direct-mode `websocket-tls`, `naive`, or HTTPS-shaped candidate may use a visible domain on its own VPS without a CDN); they **MUST NOT** carry `cdn:*` tags (those are CDN-mode-only). They **MUST NOT** carry any `origin_*` tags (in `direct_vps` mode the origin is the public surface; the `origin_*` array is meaningful only when origin is distinct from public surface, i.e. `cdn_fronted`).
* The legacy flat `shared_risk_tags` array (pre-v2.3.4) is rejected with a clear error message pointing FRPs at the v2.3.4 schema.

##### Tag vocabulary

The tag scheme is open: tags are arbitrary `category:value` strings that compare for equality. Adding a new dimension (e.g. `bgp_community:...` or `domain_suffix:...` for project-test-zone candidates per §20.4) is a tag-vocabulary extension, not a schema migration. The `_relaypack` sub-object is parsed by the V1.5+ validator at import time; older clients who do not understand the inner schema still verify the bundle's signature (because the bytes round-trip via `json.RawMessage`) and simply fall back to plain-`.sbp` selection without RelayPack-aware shortlisting.

#### 12.2.2.bis. `modifiers[]` (added in v2.3.5; reserved schema slot, post-V2 implementation)

Per-candidate optional array of **client-side packet-mutation modifiers** the recipient applies before bytes leave their machine. Distinct from `exposure_mode` (§12.2.2): `exposure_mode` is "what endpoint do I connect to"; `modifiers[]` is "what do I do to the packets on the way out." Reserved slot at V1.5 and V1.6; the validator rejects any non-empty array. Post-V2 may enable specific modifiers under explicit feature-flag.

```jsonc
"_relaypack": {
  "exposure_mode": "direct_vps",
  "modifiers": [
    {
      "kind":               "client_desync",       // FakeSNI / TCP desync (§11.6)
      "platform":           "linux_desktop_only",  // raw-socket capability required
      "probing_risk_class": "high"
    }
  ],
  ...
}
```

The currently reserved modifier kinds are `client_desync` and (placeholder) `tls_fragment`. Both are off by default; both bump the candidate's effective `probing_risk_class` upward; both are platform-gated (Linux desktop only for raw-socket modifiers; mobile platforms reject them at the importer). The `exposure_mode` of a candidate carrying a modifier is unchanged — a `direct_vps` + `client_desync` candidate is still attributed by §13.4 cooldown rules as a `direct_vps` candidate, with the modifier influencing only the racing/preference decisions in §15.

#### 12.2.3. `probing_risk_class`

Per-candidate `low` / `moderate` / `high` annotation (§11.4). Drives anti-burn race policy (§15). Carried in the same `family_specific_config._relaypack` sub-object as the mode-aware risk-tag arrays.

#### 12.2.4. `family_class`

Per-candidate `vps-native` / `vps-possible` / `external-ecosystem` annotation (§11.1). Drives UI explanation and rotation-ladder pivot decisions (§14). Carried in the same `family_specific_config._relaypack` sub-object.

#### 12.2.5. `cell_scope`

Per-candidate redistribution metadata extending 3F's `redistribution_policy` + `redistribution_cap`. The 3F fields stay where they are at the route level (`bundle/go/bundle/types.go:296`); `cell_scope` adds **new V2-cell-only metadata** alongside them. Carried in the same `family_specific_config._relaypack` sub-object:

```
// 3F existing route-level fields (unchanged):
route.redistribution_policy = "delegated_n"
route.redistribution_cap    = 1     // 3F closed enum's per-route cap

// V2 cell-scope metadata (new; only meaningful when policy=delegated_n
// AND the route is part of a cell-aggregated RelayPack):
route.family_specific_config._relaypack.cell_scope = {
  "cell_id":        "moms-extended-family-may-2026",   // new V2 cell field
  "cell_join_fp":   "9f3a...",                          // new — fingerprint of cell-membership signing key
  "cell_max_depth": 1                                   // new — depth within the cell-aggregated chain; bounded by route.redistribution_cap
}
```

`cell_id` and `cell_join_fp` are nullable for plain family-only RelayPacks (V1.5). They become meaningful in V2 trusted cells (§16).

#### 12.2.6. Validator rules

The validator at `publisher/deploy/relaypack/validator.go` rejects RelayPacks that:

* Have fewer than 2 `vps-native` candidates (a one-candidate RelayPack defeats the purpose).
* Have any candidate missing `exposure_mode`, `family_class`, `probing_risk_class`, or both risk-tag arrays (per §12.2.2 schema).
* Have any candidate violating the per-mode tag-presence rules (§12.2.2: `cdn_fronted` must carry both a `cdn:*` public tag and at least one `origin_*` tag; `direct_vps` must carry a `public_ip:*` tag, must not carry `cdn:*` tags, and must not carry any `origin_*` tags. Direct-mode `public_domain:*`, `host:*`, and `sni:*` tags are explicitly allowed for non-CDN HTTPS-shaped deployments).
* Have any candidate using a `family × exposure_mode` combination disallowed by §11.1.1 (e.g. `hysteria2` with `cdn_fronted`).
* Have all candidates sharing every public tag (no diversity at all — flag for the FRP's UI to nudge them to add a Cloudflare front, a second VPS, or a different provider).
* Use `family_class: external-ecosystem` for any candidate the FRP is trying to self-host (these must come from partner-supplied bundles, not FRP provisioning).
* Carry `exposure_mode: serverless_external` at V1.5 or V1.6 (reserved schema slot; see §11.6).
* Carry a non-empty `modifiers[]` array at V1.5 or V1.6 (the `client_desync` modifier and other future modifiers are reserved post-V2; see §11.6 and §12.2.2.bis).
* Carry a `cell_scope.policy: transitive` from V1.5 deployments (cells require V2).
* Carry the legacy flat `shared_risk_tags` array (pre-v2.3.4 schema). The error message points FRPs at §12.2.2 of v2.3.4.

### 12.3. The shared-risk-graph annotation

The Helper computes the shared-risk graph from the deployment context — for `direct_vps` candidates: IP, ASN (looked up locally or via the cloud SDK metadata), DC, provider, port, cover-SNI; for `cdn_fronted` candidates: CDN, public domain, host, SNI, public-path fingerprint **as `public_risk_tags`** plus origin IP, origin ASN, origin provider, origin DC, origin cert as `origin_risk_tags`. The Helper embeds both arrays in the RelayPack at sign time (per §12.2.2). The recipient does not need to recompute; verification confirms the publisher signed those specific tag claims.

This is the design's load-bearing piece. **Without the mode-aware risk-tag split, breadth is genuinely a liability:** the selector either counts two candidates' failures as two independent signals when they are really one shared-IP failure (under-correlation), or falsely demotes Cloudflare-fronted siblings on an origin-IP failure that TIC never observed (over-correlation). **With it, breadth becomes a moat:** the selector races diverse-risk candidates, attributes failure correctly along **mode-specific** propagation rules (§13.4), and remembers per-network winners as `(family × exposure_mode × public_risk_tag_signature)` pairs that generalise across deployments.

### 12.4. The spec deliverable

`specs/relaypack-v1.md` lands alongside the V1.5 ship and is referenced from `specs/sbp-v1.md` as a constraining profile. It is short (~6 pages) because it adds metadata, not machinery. The validator implementation is ~200 lines of Go.

---

<a name="13-selection"></a>
## 13. Client Selection Policy — the local brain

The selector is what turns RelayPack breadth into actual reliability. Deterministic local policy. No ML. No phone-home. Aligned with the existing `family.go`, `fsm.go`, `network.go`, `auto_promotion.go`, and `classify.go` machinery.

### 13.1. The selection pipeline

**On every network change** (carrier change, SSID change, captive-portal exit), the selector runs:

1. **Probe.** Five small probes in parallel:
   * DNS A/AAAA for a known-popular host (CloudFront, Microsoft) — detects DNS poisoning behaviour.
   * TCP connect to `1.1.1.1:443` — detects gross TCP/443 reachability.
   * TCP connect to a real TLS host on 443 + ClientHello + first Application Data byte — detects TLS-handshake-pass behaviour.
   * UDP send + receive to `8.8.8.8:443` (a real QUIC listener) — detects UDP/QUIC availability.
   * MTR-style traceroute to detect path-level interference (optional, slower).
2. **Filter.** Drop candidates that fail any of: trust class, expiry, revocation, engine support, current Daal mode (lifeline-strict / normal / bulk), budget, experimental-gate, **UDP availability** if `udp_gated: true`, **active-probing class** if recent path-level resets indicate active probing.
3. **Diversity-shortlist.** Build a shortlist of ≤4 candidates **preferring** maximum `public_risk_tags` distance between them (the tag set TIC observes; per §12.2.2). Greedy: pick the highest-ranked candidate, then the highest-ranked candidate sharing the fewest `public_risk_tags` with the first, and so on. The diversity calculus is **soft, not hard**:
    * **When public-risk-diverse candidates are available**, never include two candidates that share a `cdn:*` tag, and prefer not to include two candidates that share `public_ip:*` or `public_domain:*` tags in the same shortlist.
    * **When all available candidates share the same `public_ip:*`** — the dominant V1.5 case, where one VPS hosts the whole RelayPack — the selector falls back to **secondary diversity axes**: protocol family (`vless-reality` vs `websocket-tls` vs `naive` vs UDP siblings), inner SNI (`sni:`), `probing_risk_class`, and port (`public_port:tcp443` vs `public_port:udp443`). The shortlist still races the toolbox; an `public_ip:*` failure is then attributed as a single correlated event by §13.4 (cooling all siblings sharing the IP for the configured short window) rather than as N independent failures. **The "wide toolbox" goal is preserved** — a single-VPS V1.5 RelayPack still races a diverse-protocol shortlist, just with the understanding that TIC-observed IP-burn invalidates the whole shortlist atomically.
    * **Mode mixing**: when both `direct_vps` and `cdn_fronted` candidates exist (V1.6+), the shortlist always mixes exposure modes so a CDN-wide block does not knock out the whole shortlist, and an origin-IP burn does not knock out the fronted siblings.
    * **`origin_risk_tags` are deliberately ignored at this step** for `cdn_fronted` candidates — TIC does not see the origin, so the diversity calculus is over public surfaces only.
4. **Race the shortlist** with the anti-burn policy (§15): start the leader, start the runner-up after a 400 ms head-start delay, start the third only if the first two both fail.
5. **Classify** failures using `classify.go`'s taxonomy: TLS reset, SNI block, UDP loss, QUIC drop, DNS poison, TCP reset, plus the v2.3.4 mode-aware classifications (`cdn_hostname_blocked`, `cdn_wide_failure`, `origin_unhealthy`; see §13.3 / §13.4).
6. **Cool down** the failed candidate. Then **propagate the cooldown along risk-tag edges per the §13.4 mode-aware rules**: a `public_risk_tag` failure propagates to every other candidate carrying that tag; an `origin_*` failure on a `cdn_fronted` candidate is operator hygiene only and does **not** propagate to siblings sharing the same origin (TIC didn't see the origin). Cooldown durations are differential by tag class — `public_ip:` cooldowns are short (the IP may rotate); `public_asn:`, `public_provider:`, and `cdn:*` cooldowns are longer.
7. **Remember.** Persist `(family × exposure_mode × public_risk_tag_signature × outcome)` per hashed-network in the existing `network.go` per-network-memory store. The memory key is the **(mode, public-risk-tag) signature**, not the route-ID — lessons generalise across deployments. "REALITY-direct-on-Hetzner-Frankfurt fails on Irancell tonight" is reusable across every FRP's RelayPack that shares those tags; "WebSocket-TLS-cdn_fronted-on-cloudflare with hostname-suffix `frp.example.org` works on Irancell tonight" is a separate signature.
8. **Explain.** Surface the selector's choice in plain language: *"Used REALITY because UDP is blocked on this network."* *"Switched to WebSocket-TLS after QUIC failed."* *"Cooled down everything on Hetzner Frankfurt for 30 minutes — try a peer's RelayPack from your cell."*

### 13.2. Why deterministic, not ML

* **Auditable.** Every decision is explainable in plain language. Every cooldown has a named cause.
* **Testable.** The selector is a pure function of `(network probe results, RelayPack, network memory)` → `(shortlist, race plan)`. Unit-testable. Soak-testable. No model drift.
* **Telemetry-free.** No central training data. No call-home for parameter updates.
* **Robust to adversarial inputs.** A poisoned probe can degrade a single decision but cannot retrain the selector against the user.
* **Extensible.** New rules are new `if` branches; no retraining cycle.

### 13.3. Rules library

A representative set of selector rules. **Mode-aware variants are tagged `(direct only)` or `(fronted only)` where applicable; the v2.3.4-introduced rules (lines tagged ★) reference the mode-aware schema in §12.2.2 and the propagation discipline in §13.4.**

```
# Probe-derived rules
If UDP probe fails:
    skip all candidates with udp_gated:true
    cool down `udp_gated:true` candidates for 30 minutes
    set network signal: udp_collapsed                                          ★

If QUIC version-negotiation fails but UDP itself works:
    set network signal: quic_collapsed                                         ★
    demote QUIC-only candidates (TUIC, MASQUE/H3); prefer TCP-shaped

If DNS lookup for known-popular host returns RFC-1918 / loopback / 0.0.0.0:
    set network signal: dns_bogon_detected                                     ★
    demote candidates that depend on a recursive resolver path (warn only)

If TCP/443 to control IPs succeeds but TCP/non-443 ports all fail:
    set network signal: protocol_whitelist_mode                                ★
    prefer HTTPS-shaped TCP candidates (websocket-tls, naive, vless-reality)
    demote UDP candidates regardless of UDP probe outcome

If TCP/443 reachable but TLS handshake RSTs immediately on ClientHello:
    set network signal: sni_rst                                                ★
    prefer probing_risk_class:low candidates
    demote probing_risk_class:high candidates

# Mode-aware burn rules (added v2.3.4)
If a public_risk_tag has 3+ recent failures:                                   ★
    cool down the whole tag; prefer candidates without that tag in
    public_risk_tags
    propagate cooldown ONLY to siblings sharing the same public_risk_tag

If a candidate fails with cdn_hostname_blocked AND exposure_mode==cdn_fronted: ★
    cool the public_domain:* and host:* and sni:* tags (NOT cdn:* alone)
    do not propagate cooldown to candidates that share only the cdn:* tag
    surface to FRP: "rotate hostname" recommendation

If a candidate fails with origin_unhealthy (522/525/526) AND
   exposure_mode==cdn_fronted:                                                 ★
    DO NOT cool ANY public_risk_tags
    cool ONLY the origin_*:tags involved
    surface to FRP: "origin repair" recommendation (NOT "censorship rotation")

If 2+ cdn_fronted candidates fail with cdn:cloudflare across 3+ separate
   recent network changes:                                                     ★
    set network signal: cdn_wide_failure
    cool cdn:cloudflare for 60 minutes
    prefer direct_vps siblings from the same RelayPack
    surface to user: "Cloudflare appears blocked on this network; using direct
                      routes from <publisher>"

If a direct_vps candidate fails with TCP RST on connect to public_ip:
    cool public_ip:* (short, ~5 min — IPs may rotate)
    cool public_asn:* and public_provider:* (longer, ~30 min)
    surface to FRP: "L3 floating-IP swap recommended"

# Per-network memory rules
If REALITY worked on this hashed-network within last 24h:
    prefer REALITY in shortlist unless cooldown applies

If all candidates in the RelayPack share a public_risk_tag that failed:        ★
    surface "rotate" prompt to FRP via cell-side notification (V2)
    or surface "ask FRP to rotate" prompt to recipient

If recent TLS resets show active-probe shape (RST timing, cert mismatch):
    set network signal: stateful_reassembly_present                            ★
    cool down probing_risk_class:high for 60 minutes

If lifeline-strict mode AND high-risk-class user:
    racemate count = 1 (no race; sequential)
    skip experimental-gated candidates entirely
```

The full network-signal vocabulary introduced at v2.3.4 is: `dns_bogon_detected`, `protocol_whitelist_mode`, `udp_collapsed`, `quic_collapsed`, `sni_rst`, `cdn_hostname_blocked`, `cdn_wide_failure`, `origin_unhealthy`, `stateful_reassembly_present`. Signals are local-only state, never transmitted; they are inputs to the selector's deterministic rules and are surfaced in the explanation strings shown to the user.

### 13.4. Mode-aware cooldown propagation (added in v2.3.4)

The cooldown propagation rules differ by `exposure_mode` because TIC sees different surfaces in each mode. The selector consults the mode-aware schema (§12.2.2) and applies the following attribution table after each classified failure:

| Network signal observed | Candidate's `exposure_mode` | Cool down (this candidate) | Propagate cooldown to siblings sharing... | Recommend (UI) |
|---|---|---|---|---|
| TCP RST on connect / IP-block | `direct_vps` | `public_ip:*` (short, ~5 min) + `public_asn:*` (~30 min) + `public_provider:*` (~30 min) | siblings sharing the same `public_ip:` (**common in single-VPS RelayPacks** — V1.5 default; treat as one correlated IP-burn event, not N independent failures) and siblings sharing the same `public_asn:` / `public_provider:` (also common) | L3 floating-IP swap (§14) |
| TLS reset on ClientHello (`sni_rst`) | `direct_vps` | `sni:*` (~30 min); demote `probing_risk_class:high` | siblings sharing the exact `sni:*` tag | L2 change SNI/dest (§14) |
| TLS reset on ClientHello (`sni_rst`) | `cdn_fronted` | `sni:*`, `host:*`, `public_domain:*` (~30 min) — but **NOT** `cdn:*` and **NOT** any `origin_*` | siblings sharing the same `public_domain:*` tag (rare; usually one fronted candidate per hostname) | Hostname rotation via Cloudflare DNS API (§14.4) |
| Path / pattern reset mid-stream | `cdn_fronted` | `ws_path_fp:*` (~30 min) | siblings sharing the exact `ws_path_fp:*` | Public-path rotation via Worker rule (§14.4) |
| 522/525/526-class CDN response (`origin_unhealthy`) | `cdn_fronted` | **NOTHING in `public_risk_tags`**. Only the `origin_*` tags involved are marked; the candidate is held until the FRP confirms origin repair. | **No siblings cooled.** This is operator hygiene, not censorship recovery. | Origin repair to the FRP; no user-side rotation needed |
| Sustained CDN-wide block (`cdn_wide_failure`) | `cdn_fronted` | `cdn:cloudflare` (~60 min) | **every** sibling carrying `cdn:cloudflare` | Demote all `cdn_fronted` siblings; selector switches to `direct_vps` siblings in the same RelayPack |
| UDP probe fails (`udp_collapsed`) | any | all `udp_gated:true` candidates (~30 min) | every `udp_gated:true` candidate (whole class) | Skip Hysteria2/TUIC/WG/AmneziaWG until network changes |
| QUIC version-negotiation fails (`quic_collapsed`) | any | demote QUIC-only candidates | n/a (preference shift, not propagated cooldown) | Prefer TCP-based siblings |
| `protocol_whitelist_mode` detected | any | demote UDP candidates regardless of UDP probe | n/a | Prefer HTTPS-shaped TCP siblings |

**The critical asymmetry** introduced by this section: an `origin_*` failure on a `cdn_fronted` candidate is **operator hygiene**, not censorship recovery. It does **NOT** propagate to `public_risk_tags` of sibling fronted candidates that happen to share the same origin, because TIC never observed the origin. Conversely, a `cdn:cloudflare` failure **DOES** propagate across every `cdn_fronted` candidate carrying that tag, because the censor's surface for blocking Cloudflare is the same anycast IP space for every candidate sitting behind it.

This asymmetry is the main reason the flat `shared_risk_tags` model from pre-v2.3.4 was wrong: it would have falsely demoted every `cdn_fronted` sibling sharing an origin on an `origin_*` failure, and would have under-propagated `cdn:*` failures by treating them as just one tag among many.

### 13.5. Code-side implementation hooks

* **Filter** uses existing `family.go` family-cooldown predicates.
* **Shortlist diversity** is a new ~80-line function in `internal/selection/shortlist.go`.
* **Race + classify** uses existing `fsm.go` race machinery, with anti-burn race rules added.
* **Cooldown propagation** is a new ~50-line function in `internal/selection/cooldown.go`.
* **Per-network memory** uses existing `network.go` with a key-shape change (`risk_tag_signature` instead of `route_id`).
* **Explanation** is a new UI surface that consumes a structured `SelectionDecision` value.

### 13.6. Code gaps to close

The current code has the foundation but not the full pipeline. The supplement commits to closing three specific gaps in V1.5:

1. **Generic import path drops V3 metadata.** `RouteRow` has fields for MASQUE, Psiphon, Conjure, WASM, rendezvous, redistribution; the import path may not preserve the v2.3.4 mode-aware tag arrays (`exposure_mode`, `public_risk_tags`, `origin_risk_tags`, `probing_risk_class`, `family_class`) into `RouteRow`. The RelayPack import lands these fields in the store. The selector's mode-aware rules (§13.4) are wired up at V1.5 even though only `direct_vps` candidates exist; the `cdn_fronted` rules are present and tested as no-ops at V1.5 and become live at V1.6.
2. **Direct `trojan://` and `vmess://` imports become `other`.** Acceptable for FRP-emitted RelayPacks (which use first-class transport families), but flagged for V2 generic-subscription work.
3. **Normal mode does not yet weigh per-network success memory.** Lifeline-strict does. V1.5 brings normal mode in line so per-network winners (now keyed on `family × exposure_mode × public_risk_tag_signature`) influence the shortlist in ordinary use.

---

<a name="14-rotation"></a>
## 14. Rotation Ladder — one button, mode-aware escalation

The wizard surfaces one **Rotate** button. Internally it picks the cheapest rotation level matching the failure category. The recipient family scans a new QR (for `direct_vps` rotations and for some `cdn_fronted` rotations) or auto-receives the change in the background (for most `cdn_fronted` rotations, V1.6+).

> **v2.3.4 model correction.** The L1–L6 ladder below remains correct for `direct_vps` candidates. For `cdn_fronted` candidates the L-numbering does not carry over cleanly — for example, "L3 floating-IP swap" recovers from nothing the censor observed, because TIC never sees the origin IP behind a correctly-configured Cloudflare front. v2.3.4 keeps the L1–L6 ladder as the **direct-mode** ladder unchanged, and adds **§14.4 CDN-fronted rotation table** keyed on failure category. The selector consults the mode-aware schema (§12.2.2) and the cooldown propagation rules (§13.4) to pick the cheapest matching rotation in the candidate's mode.

### 14.1. Direct-mode rotation ladder (`exposure_mode: direct_vps`)

| Level | What changes | V1.5 implementation | V1.5 wall-clock | V2 implementation | V2 wall-clock | When the selector calls for this |
|---|---|---|---|---|---|---|
| **L1: Regenerate credentials** | UUIDs, passwords, X25519 keys; re-sign RelayPack with same publisher key | Redeploy on same DC + provider with fresh credentials | ~90 s | In-box mgmt API: `POST /mgmt/regenerate-credentials` + cloud-provider firewall allowlist | ~5 s | Suspected credential compromise; family-side compromise; routine hygiene |
| **L2: Change TLS / route parameters** | New REALITY `dest`, new WS path, new SNI, new ports; same IP family | Redeploy on same DC + provider with new params | ~90 s | In-box mgmt API: `POST /mgmt/change-tls-params` | ~20 s | TLS-fingerprint blocked; SNI block; path-pattern detected |
| **L3: Move floating IP** | New Floating IP attached to same server; old IP unassigned | Cloud-provider API only — `hcloud-go.FloatingIP.Assign/Unassign`. No box-side change. | ~10 s + family scan | Same as V1.5 | ~10 s | Single IP burned; everything else fine; **most common rotation** |
| **L4: Move datacenter** | Redeploy on a fresh box in a different DC; old box deleted | Redeploy-on-rotation — full provisioning run; old `client.Server.Delete()` after new box healthy | ~3 min | Same as V1.5 | ~3 min | Whole DC's prefix is in a rotation; ASN-level burn within one provider |
| **L5: Move provider** | Redeploy on Vultr / Stark; old box deleted | Redeploy-on-rotation at the new provider | ~2 min | Same as V1.5 | ~2 min | Provider-level burn; cloud-account suspension; ToS issue |
| **L6: Change protocol mix** | Provision a different toolbox profile (e.g. UDP-only / TCP-only / different REALITY-`dest` set / different cover-SNI rotation) | Redeploy-on-rotation with new profile | ~3 min | Same as V1.5 | ~3 min | All `vps-native` candidates of one shape are burned; the FRP needs a different protocol mix on the same VPS. **At V1.5 this is direct-mode only.** Adding `cdn_fronted` candidates as a recovery path is a V1.6 operation (§11.7), not V1.5 L6. |

**V1.5 ships with the redeploy-only column on the left.** L1 and L2 collapse into the same redeploy code path that L4/L5/L6 already use; the rotation ladder is operationally complete in V1.5 with one fast path (L3, ~10 s) and five identical-shape redeploy paths (~90 s – 3 min). The selector's recommendation logic still picks the cheapest level matching the failure category (so the UI distinction between L1 and L4 is preserved); only the wall-clock equalises across the redeploy levels.

**V2 unlocks the in-box mgmt API for L1/L2** via the new `Provider.SetEphemeralFirewallRule` interface method (§9.5.2), bringing L1 down to ~5 s and L2 to ~20 s. Everything else stays the same.

### 14.2. Why a ladder, not a flat button

A burned Hetzner Frankfurt IP may be an **IP problem, a prefix problem, an ASN problem, or a protocol-shape problem**. Each has a different cheapest fix. Auto-escalating from L1 → L6 in order would be wasteful (L3 is a ~10 s floating-IP swap; L4 is a ~3 min DC redeploy). Auto-jumping to L6 on any failure would be panicky and burn the operator's spare capacity. The selector's classification of the failure (§13.4 mode-aware cooldown rules + §13.6 implementation hooks) selects the rotation level, surfaces it to the FRP, and lets the FRP confirm or override. The UI shows: *"This looks like a single-IP burn. Recommend L3 (~10 s, Floating IP swap). Override?"*

The cheapness ranking matters most at L3 (always ~10 s, both V1.5 and V2). L1 and L2 are credential-hygiene operations that are cheap in V2 (~5 s / ~20 s, in-box mgmt API) and acceptable but slower in V1.5 (~90 s, via the same redeploy path used for L4–L6); the selector's preference for the lowest matching level still holds in both phases — the wall-clock distinction between L1/L2 and L4/L5/L6 collapses in V1.5 (all ~90 s – 3 min) but the *trust-and-impact* distinction does not (L1 changes only credentials; L4 changes the IP and DC). The UI surfaces the level distinction to the FRP regardless of whether the implementation paths happen to share wall-clock cost in the current phase.

### 14.3. Ladder + cell membership

In V2 trusted cells (§16), L4 and L5 may be partially handled by **the cell**: a peer's RelayPack candidate from a different ASN auto-becomes a fallback, and the FRP can defer their own L4/L5 rotation while the family is served by a cell peer. This is the operational benefit of cells — rotation cost amortised across a small group.

### 14.4. CDN-fronted rotation table (added in v2.3.4; implemented at V1.6)

For `exposure_mode: cdn_fronted` candidates the L1–L6 ladder above does not apply unchanged. The cheapest fix is keyed on **what the censor observed**, which (per §13.4) differs from what the operator can rotate. The table below is the canonical reference; the selector picks the row that matches the classified failure and surfaces the recommendation through the same one-button **Rotate** UI.

**This table is implemented at V1.6** as part of the Cloudflare wizard milestone (§11.7, §21.2). At V1.5, no `cdn_fronted` candidates exist; the table is documented for forward compatibility and for tests that assert the rules are inert when no fronted candidate is present.

##### Origin-vs-public-surface change classification

The cdn_fronted fix column distinguishes **origin-only changes** (operator-side hygiene; the recipient's connection target is unchanged) from **public-surface changes** (a tag visible to TIC has been rotated; the recipient's connection target has changed and the RelayPack candidate must be republished). This distinction governs whether the family experiences any UX event at all:

* **Origin-only changes** (origin cert refresh, origin IP swap, origin DC/provider move with hostname unchanged): the public surface that TIC sees is identical before and after. The recipient continues connecting to the same `public_domain:` over Cloudflare, which now proxies to the new origin. No RelayPack republish, no signed-update event, no QR re-scan.
* **Public-surface changes** (hostname rotation, public-path rotation, full-CDN switch): a `public_risk_tag` value has changed. The recipient's RelayPack candidate must be re-emitted and re-signed so the recipient knows the new target. **Whether the recipient receives this update without a QR re-scan depends on the freshness mechanism in scope at the current phase** (see "V1.6 freshness model" below).

| Failure | `direct_vps` fix | `cdn_fronted` fix | Origin-only or public-surface? |
|---|---|---|---|
| Credential / key leak | Regen + redeploy (V1.5: ~90 s) / regen via mgmt API (V2: ~5 s) | Regen origin credentials + refresh Cloudflare Origin CA cert | Origin-only |
| **Origin IP burned** (TIC blocking the IP) | L3 floating-IP swap (~10 s) + family re-scan | **Usually irrelevant** (TIC sees Cloudflare's anycast edge, not the origin). If the origin IP is independently leaked per §19.2.6: rotate origin IP via cloud-provider API + update Cloudflare origin pointer + re-lock origin firewall to current edge ranges | Origin-only |
| **SNI / Host blocked** on the public surface | L2 change REALITY `dest` / SNI; redeploy (V1.5: ~90 s) / mgmt API (V2: ~20 s) | Rotate hostname via Cloudflare DNS API (~10 s); update RelayPack candidate to point at the new hostname | **Public-surface** |
| **WS path / pattern burned** | Change server path; redeploy with new params (V1.5: ~90 s) | Rotate **public** path at Cloudflare Worker / Page Rule (~10 s); the **stable origin path** behind the rewrite is unchanged; box config unchanged | **Public-surface** |
| **CDN-wide failure** (TIC blanket-blocking Cloudflare) | n/a | Cool `cdn:cloudflare` for the affected network; selector switches to `direct_vps` siblings from the same RelayPack; FRP may add a candidate behind a different CDN at V2 | Selector-only (no operator action required) |
| **Origin IP leaked** (CT scan, DNS history, abuse complaint) | L3 floating-IP swap (~10 s) | Rotate origin IP via cloud-provider API + update Cloudflare origin pointer + re-lock origin firewall to Cloudflare edge ranges | Origin-only |
| **Origin unhealthy** (522/525/526) | Fix VPS / service | **Origin repair path, not censorship-recovery path.** No `public_risk_tags` are cooled; the FRP receives an "origin repair" notification; the family's selector temporarily prefers `direct_vps` siblings until the origin is healthy. | Origin-only |
| **Provider / DC issue** (account suspended, DC outage) | L4/L5 redeploy (~2–3 min) | Move origin to a different provider/DC; **public hostname can stay** (the FRP repoints Cloudflare's origin record at the new IP) | Origin-only |

**V1.6 freshness model — the narrow signed publisher freshness endpoint.** V1.6 ships a minimal per-publisher freshness mechanism (well below cell-directory scope, which lands in V2 §17.1) so that **public-surface changes** can reach the family without a fresh QR scan. Concretely:

* **Publisher freshness URL.** Each FRP's RelayPack carries an optional `freshness_url` field at the bundle level (`Manifest`-level slot, additive in the same shape as v2.3.4's `relay_pack_id` and `shared_risk_graph` — no new `spec_version` bump beyond V1.5's). The URL is a static-hosting endpoint (GitHub Pages, R2, IPFS gateway) under the FRP's own control, NOT a Daal-project endpoint. The URL points at a small JSON document signed by the FRP's publisher key listing `{relay_pack_id, current_bundle_sha256, current_signed_url, last_modified}`.
* **Recipient polling.** The recipient client polls the `freshness_url` opportunistically: on every successful tunnel-establishment event (cheap, no extra connection — runs through whichever route is currently working), and on selector-classified `cdn_hostname_blocked` / `path_pattern_blocked` events. If the freshness document advertises a newer `current_bundle_sha256` than the recipient currently holds and is signed by the same publisher key the recipient already trusts, the recipient downloads the new bundle from `current_signed_url`, verifies the publisher signature, and atomically swaps the RelayPack. **No re-TOFU prompt** — same publisher key, just a fresh bundle.
* **Boundary of what this can do.** The freshness endpoint can deliver a new RelayPack only when **the recipient still has at least one working route through the publisher** (to fetch the freshness document) **or** when the freshness URL is reachable through whatever generic route the recipient has. For **fully-burned public-surface changes** where every cdn_fronted candidate is dead and no direct_vps sibling is available, the recipient cannot reach the freshness URL through Daal and must receive a fresh QR through an out-of-band channel (Signal call, in-person, printed). This is the same operational property as V1.5 today; the V1.6 freshness mechanism is an optimization, not a guarantee.
* **What freshness endpoint does NOT cover at V1.6.** Cross-publisher updates (you cannot get a new RelayPack from a different publisher via this mechanism — that's V2 cell-aggregation). Project-level pushes (Daal-the-project never pushes to FRPs through this channel — there is no such channel by design). Identity changes (a new publisher key always requires explicit TOFU consent on the recipient side).
* **Implementation.** ~150 lines: a small static-document upload step in `publisher/deploy/cloudflare/freshness.go` (or whatever provider the FRP chose for static hosting), a polling task in `internal/selection/freshness.go`, and a verification step in `bundle/go/importer/importer.go` that ensures the freshness document is signed by the same publisher key the recipient already trusts.

**Wall-clock observation.** The fastest `direct_vps` fix (L3 floating-IP swap, ~10 s) and the typical `cdn_fronted` fix (hostname or path rotation via Cloudflare API, ~10 s) are similar at the operator. **At the family**, however, they diverge:

* `direct_vps` rotations are always public-surface changes (the IP is by definition the public surface), so they always require a fresh RelayPack delivery — either through the freshness endpoint if the recipient still has any working route, or via a new QR otherwise.
* `cdn_fronted` **origin-only** rotations (most of the table above) are invisible to the family — TIC didn't see the change, and the recipient's RelayPack candidate is unchanged. No freshness-endpoint event, no QR, nothing.
* `cdn_fronted` **public-surface** rotations (hostname change, public-path change) are visible — they need a fresh RelayPack — but at V1.6 the freshness endpoint usually delivers it without a QR, because at least one direct_vps sibling or a still-working cdn_fronted sibling is normally available to fetch the freshness document.

**V1.6 also unlocks a partial answer to "all my candidates are `direct_vps` and they all share an ASN".** A V1.6 FRP can add a `cdn_fronted` candidate alongside their existing `direct_vps` candidates without changing their cloud provider — the same Hetzner box becomes the origin for a `websocket-tls` `cdn_fronted` candidate while continuing to serve `vless-reality` directly. This adds exposure-mode diversity to a single-VPS RelayPack without requiring a second VPS.

### 14.5. Wizard rotate-button copy adapts to mode (added in v2.3.4)

The wizard surfaces one **Rotate** button regardless of mode, but the on-screen explanation differs based on which mode's rotation the selector picked **and** whether the change is origin-only or public-surface (per §14.4):

* **`direct_vps` rotation chosen** (ladder L1–L6, always public-surface): *"Send your family the new QR code so they can update. Daal will also push the update via the freshness endpoint, but if their network is offline they'll need the QR. Estimated downtime: 10 seconds (L3) to 3 minutes (L4–L6)."* The wizard generates a fresh QR and surfaces a "Send via Signal / show on screen / print" panel; in parallel it uploads a freshness document so any recipient with a working route receives the update without rescanning.
* **`cdn_fronted` rotation chosen, origin-only change** (cert refresh, origin IP swap, origin DC/provider move, origin repair): *"This change does not affect what your family sees — TIC never saw your origin. No QR or notification needed."* No family-side action; freshness endpoint not even updated (the RelayPack candidate is byte-identical).
* **`cdn_fronted` rotation chosen, public-surface change** (hostname rotation, public-path rotation): *"Daal published an updated RelayPack. Your family's client will receive it via the publisher freshness endpoint within ~5 minutes if any of their routes is currently working. If their network is fully offline, they'll need the new QR."* The wizard shows a small QR fallback panel for the case where freshness cannot reach.
* **`cdn_fronted` rotation chosen, CDN-wide block** (selector-only): *"Cloudflare appears blocked on your family's network right now. Daal has switched them to your direct routes from the same RelayPack. No action needed."* No QR; no freshness update.

The mode-aware copy shipping at V1.6 directly maps to the §13.4 cooldown classifications and the §14.4 origin-only-vs-public-surface column, so a user-facing explanation is always paired with the same internal failure category that drove the rotation choice. **The freshness mechanism is a real V1.6 deliverable** (§14.4 "V1.6 freshness model" + §21.2 deliverables list), not a deferred V2 cell primitive.

### 14.6. Operator rotation levels for cdn_fronted (added in FRP-9)

The §14.4 rotation table is keyed on **what the censor observed**. The wizard, however, drives the rotation through three discrete operator-level commands so the audit log, the rotation-history table (V006 `signed_sbps.rotation_kind`), and the i18n copy can distinguish them programmatically:

* **L7 — `cdn_path` rotation.** Visible `/r/<random>` path moves; hostname, origin VPS, certs, AOP, edge-range firewall all stay. Cloudflare-API-only. The Worker rewrite script is re-uploaded with the new public path; the Worker route is delete-and-rebound; the stable origin path is unchanged. Public-surface change → **wizard MUST re-sign the RelayPack and re-publish the freshness document** so recipients can re-walk the sub-key chain on the new bundle.
* **L8 — `cdn_hostname` rotation.** Hostname moves (apex may move to a different Cloudflare zone); public path is preserved; origin IP attaches to the new hostname. Cloudflare-API-only on the new zone (LookupZoneID + EnsureProxiedRecords + UploadWorkerScript + BindWorkerRoute). Public-surface change → **wizard MUST re-sign the RelayPack and re-publish the freshness document.**
* **L9 — `cdn_origin` rotation.** Proxied A/AAAA records move to a new origin IP; hostname, public path, origin path, worker route binding, Origin CA fingerprint, AOP state are byte-identical before and after. **Censor sees nothing.** Origin-only change → **wizard MUST NOT re-sign the RelayPack and MUST NOT re-publish the freshness document.** The candidate is byte-identical because no `public_risk_tag` changed; an L9 history row is written with `rotation_kind='cdn_origin'` and `active=0` for audit purposes only.

The operator-level numbering carries over from the §14 direct-mode L1–L6 ladder (so an audit reader sees a single monotonic sequence), but the cdn_fronted modes are NOT a continuation of the L1–L6 semantics — they are mode-specific operations. The wizard's mode-aware copy (§14.5) renders L7/L8 as "your family will see a new fingerprint" and L9 as "your family sees no change, do not send anyone a new QR".

**Locked invariants exercised by FRP-9:**

1. The validator (`bundle/go/relaypackvalidate`) NEVER calls Cloudflare. RP022 enforces a signed CDN attestation on every cdn_fronted candidate at V1.6+; the attestation is produced once during provisioning and re-verified offline thereafter.
2. The Cloudflare API token NEVER leaves the Helper. The wizard hands it to `daal-deploy cdn-rotate-{path,hostname,origin}` via a mode-0600 tempfile; the subprocess zeroizes it on exit.
3. L9 origin-only rotations MUST NOT mutate any field of the V005 `cdn_fronts` row that contributes to a `public_risk_tag` (hostname, zone_id, public_path, origin_path, worker_route_id, origin_ca_fingerprint, aop_enabled). The wizard's `update_cdn_front_rotation` is deliberately not called on L9.
4. L9 origin-only rotations MUST NOT call `record_rotated_sbp`. The audit row is written via `record_origin_only_rotation` with `active=0` so the recipient's currently-active SBP slot stays untouched.
5. `freshness_signed_sbp_url` is a required L7/L8 input. L9 rejects it (a wizard bug supplying it on L9 would cause the family to see a "new fingerprint" event for an invisible rotation; we surface that at the input boundary).

---

<a name="15-anti-burn"></a>
## 15. Anti-burn race policy

In Iran, **bad retry behaviour can burn routes faster than censorship does.** The selector must use breadth carefully.

### 15.1. The four anti-burn rules

1. **Never race the entire shortlist in parallel.** Race the leader, start runner-up after 400 ms, start third only if first two fail. This is *staggered* race, not *parallel*.
2. **Never repeatedly retry a blocked family.** Cool down the family for at least 5 minutes after 2 consecutive classification-confirmed failures; longer for clearer signals.
3. **Never use high-scarcity paths for bulk traffic** unless the user's mode allows it. The mode → scarcity-class matrix already exists in V2; the supplement reuses it.
4. **Never expose all candidates as equal.** Rank by scarcity, stability, network fit, and mode. The shortlist is a *small ranked* list, not a *menu*.

### 15.2. The race-shortlist size rule

Default shortlist size: **3** candidates. Drops to **1** in lifeline-strict mode (sequential, never parallel). Drops to **2** when the network shows recent active-probe-shape resets (any race wastes more than it gains).

### 15.3. Probing-class escalation

`probing_risk_class:high` candidates are racemates only when:

* Recent active-probe signals are absent.
* The leader is `low` and at least one runner-up is also `low` or `moderate`.
* The network's per-network memory shows no recent `high`-class burn.

This means a careless deployment with all-`high`-class candidates self-limits to sequential trying, not parallel racing — so the FRP cannot accidentally burn the family's RelayPack by overstuffing it with fingerprintable protocols.

---

<a name="16-trusted-cells"></a>
## 16. Trusted Cells — the bridge between family and federation

The trusted cell is the V2 trust-scaling layer. It **builds on 3F's existing `redistribution_policy` wire shape and cap mechanics**, but requires new specs (`specs/cell-v1.md`), new import-side cell-signature verification, and new cell-management UI. The engine release ABI stays unchanged (count = 48); the work is at the bundle-format / importer / UI layer, exactly as detailed in §16.2.

### 16.1. What a cell is

A cell is a bounded group of FRPs (3–25 helpers) who mutually share spare RelayPack capacity. Examples:

* An extended family across LA, Toronto, and Berlin sharing 3 Hetzner Frankfurt boxes plus 1 Vultr Tokyo box.
* A diaspora student org at Imperial College with 8 helpers across UK / EU.
* A close-friends circle of journalists / activists with mutual operational trust.

Cells have:

* A **cell ID** (opaque string, not human-readable) and a **cell admin scheme**: M-of-N independent Ed25519 signatures by the cell admins over the canonical membership document. NOT a threshold cryptosystem (no key aggregation, no MPC, no BLS, no FROST). Each admin holds their own independent Ed25519 keypair; the membership doc embeds the admin pubkey array + quorum requirement; verification accepts the doc if at least M of the N admins have produced a valid signature over the canonical bytes.
* A **member list** (FRP publisher fingerprints) carried inside the membership document (which is admin-quorum-signed as above).
* A **bundle-signer key** (per-cell Ed25519) authorised by an admin-quorum-signed **delegation document**. Aggregated RelayPacks are signed by this bundle-signer key, not by the admin keys directly. This lets cells rotate the bundle-signer without an admin-quorum re-sign for every aggregate.
* A **cell-scope rule set** governing redistribution depth (`cell_max_depth: 1` typical, bounded by the route-level 3F `redistribution_cap`), bandwidth caps, abuse-report routing.
* An **opt-in flag per FRP**: a helper joins a cell explicitly; cell membership is revocable at any time.

### 16.2. How a cell builds on 3F — and what it adds

3F's `redistribution_policy: delegated_n` is **a per-route re-share cap** using the device-delegate identity from `specs/delegate-keys-v1.md`. It allows a recipient device to re-emit a route under a delegate signing key, capped at N onward shares. **It is not by itself a multi-publisher aggregation primitive.**

The cell layer is therefore **built on top of 3F**, not subsumed by it. What 3F gives for free:

* The signed-share wire shape (`bundle/go/bundle/types.go` `RedistributionChainHop`, `DelegateCapEntry`).
* The recipient-side cap-enforcement code (`core/delegate.EnforceCap`).
* The `redistribution_policy` enum and the `delegated_n` / `redistribution_cap` per-route mechanics (`bundle/go/bundle/types.go:296`). Cells stack a new `cell_max_depth` (V2 cell metadata, bounded by `redistribution_cap`) on top of these, but do not modify the 3F fields themselves.

What V2 cells add (real new work):

* A **cell admin-quorum identity** — N independent Ed25519 keypairs, one per cell admin, with a quorum requirement M (default M = ⌈(N+1)/2⌉; admins MAY pick stricter at cell-creation). NO threshold cryptosystem. Distinct from individual FRP publisher keys and from 3F's per-device delegate keys.
* A **cell-membership document** — embeds `(cell_id, admin_pubkeys[], quorum_M, members[], rule_set, valid_until)`; verifiable iff ≥M valid independent admin signatures cover the canonical bytes. Lands as `specs/cell-v1.md`.
* A **cell-delegation document** — admin-quorum-signed grant of bundle-signer authority to a per-cell Ed25519 bundle-signer key (`trust/cell-delegation.json`). Lets the bundle-signer be rotated without admin-quorum re-sign of every aggregate.
* A **cell-aggregated RelayPack** — a `.sbp` profile variant carrying cell-member-publisher signatures as inner provenance and a bundle-signer signature on the aggregate. Lands as a sub-section of `specs/relaypack-v1.md` plus an extension to the manifest's `redistribution_chain` shape.
* **Import-side cell verification chain** — recipient parser walks: admin-quorum-over-membership → membership-pubkey-set → delegation-grant → bundle-signer-on-aggregate → inner-publisher signatures. New code at `core/trust/cell_verify.go` (owns the chain walk; calls into `bundle.VerifyBundle` and reads bundle-side accessors) and per-package primitives at `publisher/cell/`. Bundle-local cell-aggregate parse + canonicalisation + bundle-signer-signature verification live at `bundle/go/bundle/sbp.go` + `bundle/go/bundle/cellcanon.go`. **`bundle/go/bundle/` MUST NOT import `core/` — the existing module-boundary invariant `core → bundle` (never the reverse) is preserved.**
* **Cell-management UI** — join-code paste, member review, abuse-ticket flow, revocation propagation.

The recipient sees: *"This RelayPack is signed by your cell `moms-extended-family-may-2026`, which contains routes from FRPs `river-village-strong-promise`, `cedar-canyon-bright-river`, `meadow-vault-noble-storm`."* TOFU happens at cell-join, not per-route. Revocation of any one FRP propagates through the cell key.

### 16.3. Why cells, not direct public federation

* **Family-only is too small.** A single FRP rotating L4–L6 leaves the family offline for minutes. Two cell peers can cover during rotation.
* **Public federation is too risky early.** Sybil spam, poisoned RelayPacks, takedown-as-a-service, social engineering, fake-helper malware, metadata leakage. Cells trade *scale* for *known-trust* and absorb most of these risks at the join boundary.
* **Cells reuse 3F's wire shape and cap mechanics, but require new specs (`specs/cell-v1.md`), new import-side cell-signature verification, and new cell-management UI.** The engine release ABI stays unchanged (count = 48); the work is at the bundle-format / importer / UI layer.

### 16.4. Operational shape

The wizard's V2 cell-join flow is:

```
Settings → Cells → Join cell

A friend or family helper has shared a cell-join code with you.
Paste it below:

[ moms-extended-family-may-2026.cell-join ]

You will share spare bandwidth with 4 other helpers in this cell.
Your family's routes always have priority. The cell will not touch
your tokens, your provider account, or your private publisher key.

[ Review what is shared ]   [ Join cell ]   [ Cancel ]
```

The cell-join code is itself a small signed file (~1 KB). It carries the cell ID, cell public key, current member list (fingerprint-only), and the rule set. Joining is a one-click operation that adds the cell credentials to the FRP's encrypted OperatorRecord.

### 16.6. FRP-11 implementation lock for trusted cells (added in v2.3.10)

§16.1–§16.5's architecture lands at FRP-11 with four concrete locks the test surface pins. These are the implementation choices the architecture left underspecified in v2.3.7+:

1. **Admin keypair**: FRESH per-admin Ed25519 keypair, generated at cell creation, NEVER reused as the admin's FRP publisher key. Persisted into the wizard's encrypted keystore via `secrets_kv` aliased by `cells.admin_priv_alias`. `publisher/cell.NewAdminKeypair` is the producer; `core/trust/cell_verify.go::VerifyCellChain` walks the chain `admin-quorum → membership → delegation → bundle-signer`.

2. **Android cell-management surface**: cell-JOIN ONLY. The phone NEVER signs membership, delegation, revocation, or abuse-ticket documents. The Android publisher package + the new Android cell-join package MUST NOT contain cell-admin signing call sites. Forbidden tokens (`SignMembership`, `SignDelegation`, `SignRevocation`, `SignAbuseTicket`, `MintAdminToken`, `core/trust/cell_admin`, `publisher/cell/admin`) are pinned absent by `client-android/app/src/test/java/.../publisher/CellGuardTest.kt` (mirrors FRP-10 invariant 30 source-grep test).

3. **Cell publication channel**: abstract `CellPublisher` interface + reuse FRP-9 R2 + GH-Pages adapters. NO new IPFS / plain-HTTPS adapter at FRP-11. `publisher/cell/freshness.New(backend, cellID)` produces a per-cell publisher over any FRP-9 `deployFresh.Backend`; live SDK wiring (govultr/v3 R2 client, git push to gh-pages) is a V2 alpha pilot carry-over.

4. **Trust-label storage**: engine-side `core/trust/labels.go::MemoryLabelStore`. AES-GCM (32-byte key) encrypted at rest, AEAD additional-data = cellIDFPHex (so labels keyed to one cell cannot be replayed against another). Never serialised into bundles, diagnostics, or cell-side directory documents. The wizard's V008 schema carries an advisory hint (`cells.trust_label`) so the per-cell row in the wizard UI renders a name even if the engine label store is briefly unavailable; the engine store is authoritative.

Six new locked invariants (31–36) numbered in `specs/cell-v1.md`:

| # | Invariant |
|---|---|
| 31 | Cell admin scheme is M-of-N independent Ed25519. NO threshold cryptosystem. N ∈ [1, 25]; M ≤ N. Default M = ⌈(N+1)/2⌉. |
| 32 | `spec_version` UNCHANGED at 4. Cell aggregation reuses the FRP-7.5 manifest contract via two new bundle files. |
| 33 | `bundle/go/bundle/` MUST NOT import `daal/core`. Recipient-side chain walk lives at `core/trust/cell_verify.go`. |
| 34 | No public directory. Per-cell directories only; FRP-13 gate. |
| 35 | No new `engine_*` C-shared symbols. ABI count stays 48. |
| 36 | Android cell-admin signing absent. Source-grep guard. |

### 16.5. Cell abuse handling

Cells inherit the existing publisher revocation surface (V1.5.2). If a cell peer's RelayPack is implicated in abuse:

* The reporting FRP signs an **abuse ticket** referencing the offending publisher fingerprint.
* The cell-admin FRPs (admin-quorum M-of-N independent Ed25519) review and may sign a **cell-internal revocation** that propagates through the membership-doc + delegation-doc chain.
* The offending FRP is removed from the cell membership list; their RelayPack is dropped from cell aggregation.
* The recipient family sees TOFU re-prompt: *"Cell `moms-extended-family-may-2026` revoked one of its members."*

This handles the abuse surface at *cell scale* (3–25 known peers), which is qualitatively easier than at *public scale* (thousands of unknown helpers).

---

<a name="17-federation"></a>
## 17. Federation Primitives vs Public Directory — sequencing

The v1 supplement mistakenly proposed federation in V3. The corrected sequencing is:

* **V2 ships federation primitives.** Signed publisher exchange, delegated cells, opt-in cell directories, RelayPack freshness/revocation surface, abuse-reporting hooks, local trust labels.
* **V2 default: trusted cells only. No public directory by default.**
* **Public directory: gated on observed abuse-handling maturity, not on calendar.**

### 17.1. The federation primitives (V2)

* **Signed publisher exchange.** A signed file format (`.pubex`) for one FRP to invite another to a cell, with cell-rule-set introspection.
* **Cell directory** at a well-known URL **per cell** (not project-wide). Each cell self-publishes its current membership + aggregated RelayPack via the cell's chosen distribution channel (GitHub Pages, IPFS, R2, plain HTTPS).
* **Freshness and revocation hooks.** RelayPacks carry expiry timestamps; freshness checks happen against the cell directory; revocations are cell-key-signed and pushed to all cell members on next directory poll.
* **Abuse-reporting surface.** A signed abuse-ticket format, routed within a cell. Tickets do not propagate beyond the cell unless that cell's rule set permits onward notification.
* **Local trust labels.** The recipient client tracks per-cell trust labels (e.g. `family`, `friends`, `org-X-cell`) for UI purposes; labels are local-only and never transmitted.

### 17.2. The public-directory gate

A **public directory** would aggregate cells that opt in, exposing community-tier RelayPacks to Iran-side clients with no helper of their own. v1 proposed this as a V3 feature. v2 corrects: **the public directory is gated on empirically demonstrated abuse-handling maturity**, defined as:

* Sybil spam absent or trivially recoverable across at least 90 days of cell-only operation.
* Poisoned-RelayPack incidents detected and revoked in <24 hours mean-time-to-revocation across at least 5 simulated incidents.
* Cloud-provider takedowns survived without user-side outage in at least 2 real incidents.
* Social-engineering attempts on cell admins caught in at least 2 simulated red-team exercises.
* Fake-helper malware vector closed via reproducible-build + signature-verification UX confirmed in audit.
* Metadata-leakage audit shows no per-recipient identifiable data carried in cell directories or RelayPacks.

These six conditions are evaluated against real V2 cell deployments. **The gate flips when the conditions are met, not on a date.** If they are never met, the public directory never ships — and that is an acceptable outcome. Trusted cells are sufficient for the architecture's strategic goal.

### 17.3. Why this sequencing is not timid

It maps directly onto Daal's existing discipline: **3G partner-lifeline-relay did not ship because pre-conditions were unmet**. The same discipline applied to a project-emergent federation (rather than a partner-emergent one) is the only consistent choice. The architecture is not pretending federation is "just a feature toggle." It is treating federation as a deliverable with hard pre-conditions, observable, testable, falsifiable.

### 17.4. FRP-11 federation-primitives implementation lock (added in v2.3.10)

§17.1's five primitives land at FRP-11 with the following status closed list (`specs/federation-primitives-v1.md`):

1. **Per-cell directory contract** — SHIPPED. `<PublicURL>/cell/<cell_id>/{membership,delegation,directory,revocations}.json` over any FRP-9 `Backend.PublicURL()`.
2. **Freshness + revocation hooks** — SHIPPED. `publisher/cell/freshness.CellPublisher`; recipient walks the cell trust chain at every poll; tampered/expired delegations land at `ErrCellChainDelegationOutOfWindow` and the recipient falls back to its previously-trusted directory bytes.
3. **Abuse-ticket format** — SHIPPED. Reporter publisher key signs the ticket; cell admins decide whether to escalate into a cell-internal revocation. Cross-cell ticket forwarding is deliberately NOT shipped.
4. **Local trust labels** — SHIPPED. Engine-side AES-GCM ciphertext store; never serialised.
5. **Signed publisher exchange (`.pubex`)** — RESERVED. Format is reserved as a future primitive for cell-to-cell publisher key exchange; FRP-11 does not ship the wire shape, and adding it requires a separate roadmap-level decision.

A sixth primitive in this category requires a roadmap-level decision and a `specs/federation-primitives-v2.md` widening.

### 17.5. FRP-12 implementation lock for the modifier framework (added in v2.3.11)

FRP-12 ships the per-modifier validator framework that conditionally lifts FRP-1's RP013 hard-reject for `_relaypack.modifiers[]`. The framework is opt-in per modifier `kind`; **at FRP-12 ship zero kinds carry a PASS record**, so RP013 still hard-rejects every non-empty `modifiers[]` array. The first concrete modifier PASS record lives in a separate post-track follow-on phase. Eight locked answers (closed list at FRP-12 ship):

1. **Build-time codegen, not runtime parse.** The modifier registry is generated by `publisher/deploy/modifiers/cmd/genregistry` reading every `specs/modifiers/<kind>.md` (excluding `_template.md` and `README.md`) and emitting `publisher/deploy/modifiers/registry_gen.go` as a deterministic Go literal map. Runtime parsing of `.md` files from a release-tarball binary was rejected as fragile; codegen keeps the registry deterministic and reviewable in PRs.
2. **No PASS records in `specs/`.** The verification grep `rg "status.*PASS" specs/modifiers/*.md | grep -v _template.md` MUST return empty at every commit through 11/11. A test-only synthetic PASS fixture lives at `publisher/deploy/modifiers/testdata/synthetic_pass.md` and feeds in-test loaders only; it is excluded from genregistry input.
3. **Subpackage layout.** `publisher/deploy/modifiers/{doc.go, registry.go, registry_gen.go, frontmatter.go, frontmatter_test.go, registry_test.go, platforms.go, platforms_test.go, testdata/, cmd/genregistry/}`. All within the `daal/publisher` Go module; no new go.mod.
4. **Engine importer platform gate at `core/trust.StoreAdapter.SaveImport` + `core/internal/selection/candidate_platform.go`.** `RejectByPlatform(modifiersJSON, runtimeGOOS, desktopHint, policy)` returns `ErrModifierPlatform` (wire label `IMP_MODIFIER_PLATFORM`) when any modifier kind is not PASS at the requested phase, OR when the runtime platform is not in the kind's `platforms[]` list. `StoreAdapter.SaveImport` calls it before persisting modifier-bearing routes. Nil policy is fail-closed at FRP-12 (zero PASS records); a later concrete PASS phase wires a generated policy into the trust-layer `ModifierPlatformPolicy` view. Engine MUST NOT import `daal/publisher` (asymmetric guard preserved).
5. **Validator wiring lives in `publisher/deploy/relaypack/binder.go`.** The validator package itself (`bundle/go/relaypackvalidate`) is **not modified at FRP-12** — RP013's existing `AllowedModifierKinds` plumbing (already shipped at FRP-1) does the work. The binder populates the map via the new `allowedModifierKindsForPhase(phase)` helper, which returns `modifiers.AllowedKindsAt(phase)` — empty at FRP-12 ship.
6. **`min_phase` enum mirrors `relaypackvalidate.Phase` exactly.** Permitted values: `V1.5`, `V1.6`, `PostV2`. The phase-doc text mentioning "V2 / V3" collapses to `PostV2` for consistency with the existing validator enum; V3 phase enum is a future extension, not at FRP-12.
7. **Module location: `daal/publisher` for the registry; `daal/core` for the engine gate.** No new go.mod. Asymmetric guard verified: `rg '^\s*"daal/publisher' core/` returns empty.
8. **Wizard + recipient UI strings: 11 EN + 11 FA keys at `tauri/src/wizard/i18n/wizard.{en,fa}.json`.** Surface lives on Screen6Handoff (`data-testid='modifier-surface'`); always renders "Modifiers: none active" at FRP-12 ship because the registry has zero PASS records. FA strings are placeholder-tagged English; native Persian translation per the FRP-12 carry-over (post-track FA review). Android has NO modifier UI at FRP-12 — phone is recipient-only, enforced by `ModifierGuardTest` source-grep.

Eleven new locked invariants (37–47) are exercised by the FRP-12 test surface (≥21 publisher-side modifier tests + 9 engine-side platform-gate tests + 2 wizard-side i18n guard tests + 2 binder-wiring tests + 1 Android source-grep guard). The locked invariants:

- **37.** Zero PASS records ship at FRP-12. Build-time + runtime guard.
- **38.** Unknown / PENDING / REJECTED / DEPRECATED kinds stay hard-rejected.
- **39.** `min_phase` enforced at the AllowedKindsAt filter.
- **40.** `platforms[]` enforced at the engine importer/store boundary with `IMP_MODIFIER_PLATFORM` before route persistence.
- **41.** Modifier carry is per-candidate (not bundle-wide).
- **42.** Recipient UI default OFF.
- **43.** Pass record reviewable; codegen rejects malformed front-matter.
- **44.** No engine release symbols added; ABI=48.
- **45.** Position B preserved (no telemetry).
- **46.** `exposure_mode: serverless_external` NOT in scope at FRP-12.
- **47.** Android source-grep guard for modifier admin / opt-in surfaces.

Carry-overs to the post-track follow-on phase: drafting the first concrete `client_desync` PASS record after Linux-desktop censor-lab review; finalising the `tls_fragment` library + semantics; recipient UI toggle wiring (rendered but inert at FRP-12); FA copy native review for the 11 new desktop strings.

### 17.6. FRP-13 gate-evaluation lock for the public directory (added in v2.3.12)

FRP-13 ships **only the gate-evaluation framework** for the V3 public directory; the directory implementation itself is **not** in scope and remains GATED behind the §17.2 + §22.4 verdict of `cmd/daal-gate-eval`. Eight commits land. **Ten locked answers (closed list at FRP-13 ship):**

1. **Gate-evaluation framework only.** No `publisher/directory/` subpackage is created at FRP-13. No directory probe, builder, signer, distributor, or recipient-side fetcher ships. The grep `rg "publisher/directory" --type=go` MUST return empty at FRP-13 ship. The framework is: three specs + one CLI + one quarterly-history dir + one process doc.
2. **Cell-closure HOLD preserved.** `specs/cell-closure-v1.md` remains HOLD at FRP-13 ship — V2 trusted-cell pilot has not run. The CLI's prerequisite check downgrades any all-PASS gate verdict to HOLD when cell-closure is HOLD; this is the explicit ordering enforcement of locked invariant 48 (cells-before-directory).
3. **Three specs, not one.** `specs/public-directory-v1.md` (the protocol contract; Status: GATED; ships at FRP-13 so the contract is reviewable, not so the protocol is implemented). `specs/public-directory-closure-v1.md` (the closure-record template; HOLD; mirrors `specs/cell-closure-v1.md`'s shape; flips to SHIPPED only when the gate flips). `specs/public-directory-gate-v1.md` (the machine-readable gate spec; SHIPPED at FRP-13 — the **spec** ships; the **gate verdict** is HOLD).
4. **Six §17.2 conditions + five §22.4 thresholds, verbatim.** The gate spec re-states the §17.2 abuse-handling-maturity conditions and the §22.4 V3 success metric verbatim from the supplement so the CLI is self-contained. If the two diverge, the supplement wins and the gate spec MUST be updated. All six conditions and all five thresholds carry status: HOLD at FRP-13 ship.
5. **CLI emits both text and JSON.** `cmd/daal-gate-eval` defaults to a text status table (FRP-13 ship style: 6 condition rows + 5 threshold rows + verdict). `--json` emits a structured `Report` value for programmatic consumers (e.g. a future CI check that warns on stale gate history). Exit codes: 0=PASS, 1=HOLD, 2=FAIL. The CLI validates the closed 6+5 row set and status enum. **PASS records with empty / TBD / null `evidence` are downgraded to FAIL, and PASS thresholds whose observed value does not meet the declared threshold are downgraded to FAIL** — the anti-vibe trap that prevents a maintainer from flipping a row with no underlying audit report or insufficient observed value.
6. **Quarterly history at `specs/public-directory-gate-history/<YYYY-QN>.md`.** Append-only audit trail. First entry `2026-Q2.md` records the FRP-13-ship HOLD evaluation. Re-evaluation cadence is operational (quarterly, first business day); skipped quarters are recorded explicitly in the next quarter's file.
7. **Status flip wording: "SHIPPED — gate-evaluation framework only".** The phase-doc and frp-track-v1.md status row use this exact phrasing to make it unambiguous in a code-review skim that FRP-13 did NOT ship a public directory. Anyone reading a future bug report MUST be able to tell at a glance that the directory is not running.
8. **FRP track terminates at FRP-13.** No `phases of development/44-…` file is ever created. Post-track phases live outside the FRP-NN naming scheme — at, e.g., `phases of development/post-track/01-public-directory-impl.md` if and when the gate flips. The `frp-track-v1.md` document gains a "FRP-track terminator" paragraph stating this explicitly.
9. **Acceptable outcome: never ship.** Per §17.5's design constraint and the project's anti-saviour-complex stance, a perpetual HOLD verdict is itself an acceptable architecture state. If the §17.2 gate never flips, V2 trusted cells become the project's permanent endpoint, the public directory never runs, and the FRP track terminates cleanly at FRP-12 + FRP-11 + FRP-13's framework.
10. **Closure record is immutable post-flip.** When (if ever) `specs/public-directory-closure-v1.md` flips from HOLD to SHIPPED, the record becomes immutable for audit purposes. Subsequent operational changes (cell quarantine, directory-key compromise) are recorded in separate documents (`specs/public-directory-gate-history/` for routine ops; a hypothetical `specs/public-directory-revocation-v1.md` for key compromise — created if and when needed, NOT at FRP-13).

**Eight new locked invariants (48–55) are added at v2.3.12:**

- **48. GATED start preserved.** The public-directory implementation phase (post-track) MUST NOT start until both: (a) `specs/cell-closure-v1.md` Status flips to SHIPPED, AND (b) `cmd/daal-gate-eval` verdict flips from HOLD to PASS. Source-of-truth: `cmd/daal-gate-eval` exit 0.
- **49. Acceptable outcome: never ship.** A perpetual HOLD verdict is an acceptable architecture endpoint. The project does NOT add features or relax conditions to force a flip.
- **50. No silent flips.** A condition's status MUST NOT be flipped from HOLD to PASS without recorded evidence, and a threshold's status MUST NOT be flipped to PASS unless the observed value meets the declared threshold. The CLI enforces this by downgrading PASS-without-evidence and unmet-threshold PASS rows to FAIL.
- **51. Engine line UNCHANGED at FRP-13.** No `core/` source change. No `bundle/go/` source change. No new C-shared symbol. ABI=48 unchanged. `spec_version=4` unchanged. Asymmetric guard `core → bundle, never reverse` clean.
- **52. No `publisher/directory/` package at FRP-13.** Source-grep guard: `rg "publisher/directory" --type=go` returns empty at FRP-13 ship.
- **53. FRP-track terminator.** `specs/frp-track-v1.md` gains a "FRP-track terminator" paragraph at FRP-13. No further FRP-NN phases are added; post-track work uses a different naming scheme.
- **54. Quarterly audit-trail append-only.** Files in `specs/public-directory-gate-history/` are not edited after the quarterly evaluation; corrections live in the next quarter's file.
- **55. Position B preserved.** No telemetry collection, ingestion, or aggregation infrastructure is built into the gate-evaluation framework. The §22.4 threshold counts are operator-supplied (project-lead's quarterly count from operational, aggregate-only data); per-recipient identifiers MUST NOT enter the gate spec.

Carry-overs to the post-track public-directory implementation phase (only if the gate flips): `publisher/directory/` package design; signed-directory format spec amendment; recipient-side directory fetcher with cell-closure cross-check; transparency-log integration for the directory key; first-quarter post-flip soak; `--quarterly` flag on `cmd/daal-gate-eval` for auto-regeneration of the next history file.

---

<a name="18-funding"></a>
## 18. Funding architecture — affiliates, donations, grants, never merchant

### 18.1. Affiliate referrals

The wizard's "Open Hetzner signup" uses a referral URL `https://accounts.hetzner.com/signUp?ref=<DAAL-PROJECT-CODE>`. Hetzner's referral program offers a credit-on-signup to the new user and a project commission once the user crosses a small spend threshold; specific amounts are provider-controlled, change over time, and are read from a per-provider configuration loaded at wizard render time rather than hard-coded in this roadmap.

Each provider implementation carries its own referral configuration:

```go
type ProviderReferral struct {
    ProviderTag       string
    SignupURL         string
    DisplayName       string
    NewUserCredit     string
    ProjectCommission string
}
```

Transparently disclosed in the wizard. A "Use plain provider URL" link surfaces the non-referraled option for purists.

### 18.2. Donations

* **GitHub Sponsors** — 0% platform fee.
* **Open Collective** — fiscal-host; ~10% fee.
* **Liberapay** — non-profit; minimal fees.
* **Crypto (BTC, XMR, USDT-TRC20)** — for diaspora users where bank transfers are inconvenient. Surfaced cautiously to avoid disproportionate regulatory attention.

Surfaced only on a Settings → About page. We do not nag.

### 18.3. Grants

Once the FRP architecture has produced **real users with measurable outcomes** (e.g. "150 FRPs → ~600 Iranians connected during the May 2026 Tehran blackout"):

* **Open Tech Fund (OTF)** — $30k–$300k, multi-year.
* **NLnet** — €5k–€50k, EU-funded, low paperwork.
* **Mozilla MOSS** — $50k–$250k.
* **Reset.tech** — UK press-freedom grants.
* **Internet Freedom Festival fellowships**.

Diversification across funders; multi-year horizons; avoid single-funder-disappears failure modes.

### 18.4. What we explicitly never do

* No payment-processor integration. No `pay` button.
* No subscription accounts on the project side.
* No "premium" tier on the Iran end-user side.
* No paid trust-class promotion (the project's directory key alone governs trust class per `specs/publisher-keys-v1.md`).
* No advertising.

### 18.5. Honest revenue model

| Source | Year 1 | Year 2 | Year 3 |
|---|---|---|---|
| Provider affiliate | €500–1500 | €2k–6k | €5k–12k |
| GitHub Sponsors / donations | €0–500 | €500–3k | €2k–8k |
| First OTF / NLnet grant | €0 | €20k–60k | €30k–80k (renewal) |
| **Total** | **€500–2k** | **€22k–69k** | **€37k–100k** |

Pays for: domain registrations, GitHub Pro, security audit ($30k–$50k cycles), and — by year 2 — half-time engineering. By year 3, plausibly a one-engineer salary plus a part-time contractor.

---

<a name="19-threat-model"></a>
## 19. Threat model and abuse-resistance

### 19.1. Compromise assumption

**The architecture must assume that at least one FRP machine in any meaningful cohort will be compromised by adversary tooling (IRGC implants, OS-level malware, supply-chain attack on a dependency, social engineering of the FRP).** The mitigation is not pretending compromise will not happen; it is **scoped publisher keys, revocation, rotation, cell limits, and not letting one helper poison global trust.**

### 19.2. Adversarial scenarios

#### 19.2.1. Iranian state actor compromises an FRP machine

**Impact.** Attacker obtains publisher private key, Hetzner token, OperatorRecord, cell credentials. May sign new RelayPacks under the FRP identity, provision additional servers under the FRP's Hetzner account, modify existing servers.

**Mitigation.** Publisher key encrypted with PIN-derived Argon2id key (locked device → not extractable). Family clients TOFU per V1.5; new RelayPack from same publisher with *new* candidates surfaces a diff prompt. V1.5.2 revocation lets the legitimate user (after recovery) sign a `revocation.json` that propagates over any working tunnel and refuses subsequent bundles. **Cell membership bounds blast radius:** a compromised FRP in a cell affects that cell only; the cell-admin M-of-N independent-Ed25519 quorum gates cross-cell trust escalation.

#### 19.2.2. Iranian state actor sets up a fake Helper

**Mitigation.** Reproducible builds (CC.2), signed releases (CC.4), well-known signing key, public security audit before pilot >100. Diaspora users (skewing technical) can build from source. The Helper does no exotic operations — sing-box, cloud-init, hcloud-go are all inspectable. **No central authentication service exists for the attacker to compromise.**

#### 19.2.3. Cloud provider account suspended

**Mitigation.** No shared infrastructure: each FRP's account is independent. **A suspension affects exactly one family.** The L5 rotation level (§14) supports redeploy on a different provider in ~2 minutes.

#### 19.2.4. Cloud provider deplatforms Daal-the-project

**Mitigation.** Affiliate revenue replaced by another provider's program. No user is affected; only project revenue dips.

#### 19.2.5. State pressures the Daal project itself

**Mitigation.** Project holds **no user data**: no accounts, no logs, no telemetry, no merchant records, no payment data, no API tokens, no IP addresses, no usage statistics. Compelling Daal to disclose user data is compelling it to disclose data it does not have. Directory key (counter-signing community submissions) is in HSM custody (CC.4); a compelled signature is technically possible but operationally noisy: HSM access requires two maintainers' physical presence; the resulting object is publicly observable.

#### 19.2.6. Origin-IP leak attack against `cdn_fronted` candidates (added in v2.3.4)

**Attack.** TIC, a third-party scanner, or an opportunistic adversary obtains the **origin IP** behind a Cloudflare-fronted candidate, even though the family's Daal never connects directly to the origin. Concrete vectors observed in the wild against Cloudflare-fronted services:

* **Certificate-Transparency log scanning.** If the origin presents a public Let's Encrypt cert (or any CA-issued cert that lands in CT logs), an adversary can scan the IPv4 address space for matching certs and de-anonymise the origin. Public databases of de-anonymised Cloudflare origins exist.
* **DNS history.** If the FRP ever published a non-proxied A or AAAA record for the same domain (even briefly during setup), DNS-history aggregators retain the original origin IP for years.
* **SMTP / MX leak.** If the origin runs an SMTP service (or its hostname appears in the MX record of any domain the FRP owns), the origin IP is published in mail headers and DNS.
* **SSH banner / service banner leak.** If port 22 or any non-Cloudflare-proxied service is reachable on the origin, internet-wide scanners (Censys, Shodan) record the IP and can be queried for hosts presenting Daal-relay-shaped fingerprints.
* **Abuse-complaint disclosure.** Cloudflare's abuse-handling process forwards complaints to the origin's hosting provider, which may publish or leak the origin IP back to the complainant.
* **Application-level bugs.** Error pages, redirects to absolute URLs, server-Date headers, or any application response that includes the origin's hostname or IP.

**Impact.** Once the origin IP is known, two attacks become possible: (a) TIC can blocklist the origin IP directly, bypassing Cloudflare entirely (this is a less-collateral fix than blanket-blocking Cloudflare anycast, so a determined censor will prefer it); (b) the origin can be probed, fingerprinted, and correlated with future deployments by the same FRP.

**Mitigation (locked at V1.6 deployment template; §11.7).**

* **Cloudflare Origin CA cert on the origin** — issued by a private Cloudflare CA, never lands in public CT logs, accepted only by Cloudflare's edge under Full Strict mode. Eliminates the CT-scan attack vector by construction.
* **Authenticated Origin Pulls enabled** — the origin only accepts inbound connections that present a Cloudflare-signed client certificate. A bare scan to a known origin IP gets a TLS handshake failure. Even if the IP is enumerated, the origin is unresponsive to anyone other than Cloudflare's edge.
* **Cloud-provider firewall locked to Cloudflare edge IP ranges** — refreshed daily from `https://www.cloudflare.com/ips-v4` and `ips-v6`. The provider firewall rejects any inbound 443/tcp not sourced from a current Cloudflare edge range, regardless of whether the connection presents a valid client cert. Defence-in-depth against a bug in the AOP layer.
* **No DNS-only A/AAAA record** — the wizard refuses to deploy if the FRP's chosen domain has any non-proxied record. The wizard's deploy step verifies the proxied state via the Cloudflare API immediately before signing the RelayPack.
* **No other public services on the origin IP** — `sshd` disabled (§9.3), no SMTP, no MX record pointing at the origin, no Daal-attributable service banner. The §9.3 cloud-init posture and §11.7 hardening checklist together ensure the origin presents nothing scannable beyond a Cloudflare-edge-only TLS endpoint.

**Selector behaviour after a confirmed origin-IP leak (§13.4 propagation rules):** rotate the origin IP via the cloud-provider API, re-lock the firewall to the new edge ranges, update Cloudflare's origin pointer, and **do NOT cool any `public_risk_tags`** (TIC didn't see the origin; the public surface is unaffected by the leak). The family experiences no rotation event at all.

**What remains residual.** Cloudflare itself can be compromised, mis-configured by the FRP (proxy mode accidentally toggled off), or politically pressured into disclosing origin IPs. The mitigation against the first two is the §11.7 deploy-time validation and the daily edge-range refresh; the mitigation against the third is keeping `direct_vps` siblings in every RelayPack so a CDN-wide compromise of any kind triggers selector failover (§13.4 `cdn_wide_failure` rule).

### 19.3. Federation-tier-specific failure modes (the model's enumeration)

Each must be addressed before the public-directory gate flips (§17.2):

* **Sybil spam.** Mitigation: rate-limited submissions per source IP; cell-key counter-signing; per-cell reputation scores in the directory; abuse-detection heuristics on submission rate.
* **Poisoned RelayPacks.** Mitigation: directory only accepts cell-key-signed RelayPacks (not raw publisher signatures); per-RelayPack abuse signals (excessive cooldowns, signed user-revocation tickets) demote in the next rotation.
* **Cloud-provider takedowns.** Mitigation: directory hosting itself is multi-mirror (GitHub Pages + IPFS + R2 + cell-side mirrors); takedown of any one mirror does not break propagation.
* **Social engineering of cell admins.** Mitigation: M-of-N independent-Ed25519 admin-quorum signatures required for cell-rule changes and cell-revocation events; cell-admin keys held on hardware tokens where possible.
* **Fake-helper malware.** Mitigation: reproducible builds, well-known signature, install-flow nudge to verify signatures; recipient-side anti-malware UX (§20.4).
* **Metadata leakage.** Mitigation: directories carry only fingerprints and aggregated RelayPacks; no per-recipient identifiable data; cell directory access is via a generic CDN endpoint (no per-cell auth that would reveal who polls).

### 19.4. Anti-burn race policy as security mitigation

The anti-burn race policy (§15) is itself a security mitigation: it bounds the rate at which the selector can be tricked into burning the FRP's RelayPack. An adversary network that returns aggressive resets can trigger at most one race-shortlist's worth of route exposure per network-change event — not a hammer on the whole portfolio.

---

<a name="20-acquisition"></a>
## 20. Diaspora user acquisition — the actual unsolved supply problem

Architecture creates capability. Distribution creates actual supply.

The supplement is incomplete without engaging with the **first-50 helpers** problem. This section is the public-doc half. The private launch plan (named intermediaries, named communities, rollout order) lives in the project's secret store, not here.

### 20.1. The first-50 target profile (public)

* Diaspora Iranian, primarily in Berlin, Stockholm, Toronto, London, LA.
* Has at least one close relative (parent, sibling, partner) in Iran, especially in Tehran / Mashhad / Isfahan / Shiraz.
* Already follows at least one of: technical-circumvention Telegram channels, diaspora-engineer Slack-equivalents, diaspora university CS departments.
* Has a working credit card on a non-Iranian bank.
* Owns a desktop or laptop on macOS / Windows / Linux.
* Willing to pay a small monthly cloud-provider fee indefinitely if it keeps a relative connected (order of magnitude: small-team-coffee per month).
* Willing to verify a release signature before installing (a meaningful filter — not bug-free user, but security-conscious).

### 20.2. Trust signals the project must ship before pilot

* **Reproducible builds** (CC.2). A verifier-side reproducible-build doc that any technically literate diaspora user can follow to verify a release matches the published source.
* **Signed releases** (CC.4). Well-known release key. Documentation explaining how to verify signatures on each platform.
* **Public security audit** before pilot >100. The audit must cover: publisher-key handling, OS keystore integration, cloud-init pinned-artefact verification, RelayPack profile validation, selector cooldown logic. Auditor selection is in the private appendix.
* **Open issue tracker, open RFC process** for spec changes. Spec versions locked (`relaypack-v1.md`, `selection-v1.md`) and never silently mutated.

### 20.3. Recipient anti-malware UX

The Iranian recipient must be able to install the Daal recipient app **on a device whose Play Store / App Store is largely inaccessible** without being phished into installing a fake.

* **Android**: distribution via **Bazaar / Myket** (the Iranian Android stores) with **signature-pin verification** in the recipient UI ("This app is signed by the Daal release key. The first four words of the signature are: cedar canyon bright river"). The four-word fingerprint matches the project's well-known fingerprint, available on multiple authoritative sources (project's website, Wikipedia entry, OTF program page, etc.).
* **iOS**: TestFlight or AltStore (post-V3, when iOS support lands).
* **Desktop**: signed installers with notarized Mac builds, EV-signed Windows installers, signed Linux packages (deb/rpm + checksums).

The recipient flow always shows the four-word fingerprint of the running build before any sensitive operation, so a fake build with a different signature is immediately visible.

### 20.4. The "I can help my family" moment

The moment we are designing for is concretely: **a 32-year-old engineer in Berlin reads a comment on an Iranian-tech Telegram channel from someone they trust, follows a link to Daal's website, verifies the signature on the desktop installer, runs the wizard, hands their parent in Tehran a printed QR code on their next visit (or sends it via a verified-Telegram-account voice message), and three weeks later their parent uses Daal without thinking about it.**

Every UX decision in the supplement maps backwards from that moment.

#### 20.4.1. BYO-domain vs project test-zone for V1.6 CDN-fronted candidates (added in v2.3.4)

V1.6 CDN-fronted candidates require a domain. The supplement makes a deliberate choice here: **BYO-domain is the production default; the Daal-project test-zone is a closed-pilot pathway only, behind a strong warning, never the default architecture.**

**Wizard behaviour at V1.6.** When a user reaches the V1.6 CDN screen, three options are surfaced:

| Option | Default? | Result |
|---|:---:|---|
| **Use my own domain** | yes (recommended) | Full `cdn_fronted` candidates with the §11.7 hardening template; the FRP's own Cloudflare account holds the Origin CA cert and DNS records; Daal never touches the FRP's domain or origin IP. **Production path.** |
| **Skip CDN for now** | yes (fallback) | Direct-only RelayPack as in V1.5; the FRP can add CDN later by re-running the wizard once they own a domain. |
| **Use Daal test subdomain** | hidden / pilot only | Closed-pilot pathway. Surfaced behind a strong warning. Generates a `cdn_fronted` candidate using a project-owned test zone. Not recommended for sensitive production use. |

**Why the project test-zone is not the production default.**

Many relays sharing a visible suffix like `*.daal-relay-test.org` would be a single block target for TIC: blocking the suffix takes out every test-zone deployment in one rule. The same suffix is also a single deplatform target for any cloud DNS provider, abuse complainant, or hostile actor. Worse, if Daal-the-project provisions DNS records on behalf of FRPs, the project necessarily learns the origin IPs and at least the relay identifiers — which directly contradicts the supplement's "no user data" property (§19.2.5). BYO-domain keeps these surfaces with the FRP.

**Architectural choice for the project test-zone (when used at all): delegated subzone, not project-managed origin records.**

If the test-zone is provided to a closed-pilot FRP, the preferred shape is:

* Daal-the-project owns the parent zone (e.g. `daal-relay-test.org`).
* A pilot FRP receives a delegated subzone (e.g. `r4nd0m123.daal-relay-test.org` with NS records pointing at the FRP's own Cloudflare account).
* The FRP's Cloudflare account controls DNS, Workers, origin pointer, and TLS settings within their subzone.
* **Daal-the-project never holds the origin IP** because origin records exist only inside the FRP-controlled subzone.

This is still centralised at the parent-zone level (a single TLD takedown affects every test-zone subdomain) and still blockable at the suffix level, but it removes the metadata-pressure failure mode where the project would otherwise learn each FRP's origin IP.

**RelayPack tagging for project-test-zone candidates** (per §12.2.2):

```jsonc
"_relaypack": {
  "exposure_mode": "cdn_fronted",
  "family_class":  "vps-native",
  "probing_risk_class": "low",
  "public_risk_tags": [
    "cdn:cloudflare",
    "domain_suffix:daal-relay-test.org",
    "project_subdomain_pool:daal",
    "public_domain:r4nd0m123.daal-relay-test.org",
    "sni:r4nd0m123.daal-relay-test.org",
    "host:r4nd0m123.daal-relay-test.org"
  ],
  "origin_risk_tags": [
    "origin_ip:5.75.x.x",
    "origin_provider:hetzner"
  ]
}
```

The selector treats `project_subdomain_pool:daal` and `domain_suffix:daal-relay-test.org` as ordinary `public_risk_tags` under §13.4 propagation rules. If the parent zone starts failing across multiple networks, the selector demotes **every** candidate carrying those tags — across all FRPs in the pilot — and the selector's `cdn_wide_failure` analogue at the suffix level demotes the entire pool. Pilot candidates also carry `scarcity_class: pilot` and `redistribution_allowed: false` to prevent test-zone candidates from leaking into ordinary cell aggregation.

**The phrasing the supplement adopts:**

> V1.6 CDN mode is production-supported for BYO domains. FRPs without a domain can ship direct-only RelayPacks at V1.5 / V1.6 and add CDN later. A Daal-project subdomain pool may exist only for closed pilots, feature-flagged builds, or test cohorts, with explicit warnings and shared-risk tags. **It is not a default production route-supply mechanism.**

### 20.5. Compromise-assumption acknowledgment

Even with the trust signals above, **one of the first 50 helpers will have a compromised machine**. The architecture's mitigations (publisher revocation, scoped tokens, cell limits, ladder rotation, anti-burn race policy, no global-trust contamination from one helper) are *the* answer; pretending it will not happen is not. The launch plan budgets for one early publicly-noted compromise-and-revocation event as a *demonstration* of the trust system working — not as a failure of the architecture.

### 20.6. What lives in the private appendix

* Named intermediaries (5–10 trusted people in the diaspora technical community).
* Named communities (specific Telegram channels, specific Slack-equivalents, specific diaspora orgs).
* Rollout order (who is approached first, who second, who third).
* Auditor selection (specific firms, specific contacts, specific audit windows).

**Publicly listing seed surfaces makes infiltration cheaper.** This is the same operational discipline that keeps affiliate codes out of public roadmaps.

---

<a name="21-phase-placement"></a>
## 21. Phase placement — V1.5, V1.6, V2, V3 mapping

### 21.1. V1.5 — FRP MVP (direct-VPS only)

**Scope.** Hetzner-only. Desktop only (Tauri). One-family-at-a-time. No cells. No federation. **Direct VPS only — `cdn_fronted` candidates ship at V1.6 (§21.2).** RelayPack profile shipped with `iran-default` toolbox profile, **all candidates `exposure_mode: direct_vps`**.

**Deliverables:**

* `publisher/deploy/` Go package + `Provider` interface + Hetzner implementation.
* `publisher/deploy/cli/` CLI wrapper.
* `publisher/deploy/relaypack/validator.go` enforcing the **full v2.3.5 mode-aware RelayPack profile**, including the per-mode tag-presence rules in §12.2.2 and the orthogonal `modifiers[]` array (§12.2.2.bis). The validator at V1.5 rejects any candidate with `exposure_mode: cdn_fronted` (V1.6) or `exposure_mode: serverless_external` (post-V2), and rejects any non-empty `modifiers[]` array (post-V2 — `client_desync`, `tls_fragment`); the schema is mode-aware so V1.6 lands without further schema churn.
* Tauri wizard screens 0–6, with a "CDN-fronted candidates: coming in V1.6" line on the toolbox screen instead of a broken option.
* OS-keystore + PIN-derived AES-GCM defence-in-depth.
* SQLite OperatorRecord schema.
* Cloud-init template with **pinned, signed artefacts** (§9.2) and hardened health endpoint (§9.6).
* Selection brain enhancements: **mode-aware** shortlist + cooldown propagation per §13.4 + per-network-memory key change (`family × exposure_mode × public_risk_tag_signature`). Mode-aware rules referencing `cdn_fronted` are present and tested as no-ops at V1.5; they become live at V1.6.
* `specs/relaypack-v1.md` (locks the full v2.3.5 mode-aware schema; §12.2.2 + §12.2.2.bis).
* `specs/selection-v1.md` (formal selector spec, including §13.3 rules and §13.4 cooldown propagation).
* `docs/family-relay-publisher-v1.md` + a 30-second screen-recorded demo.

**Gate to V1.6.** Five real FRPs in a closed pilot have provisioned VPSes; their families' Daal clients have stayed online for at least 7 consecutive days; at least one rotation event (any direct-mode ladder level) has been observed to recover under 60 seconds; the mode-aware schema has been exercised end-to-end (validator → importer → store → selector → UI) with `direct_vps` candidates.

### 21.2. V1.6 — CDN milestone (added in v2.3.4)

**Scope.** **`cdn_fronted` candidates ship**, with the §11.7 hardening template enforced. Cloudflare wizard path. Origin CA + Authenticated Origin Pulls + provider-firewall-locked-to-CF-edge-ranges + public-path-rewrite indirection. Mode-aware rotation UI (§14.4). Still Hetzner-only; still desktop-only; still no cells; still no federation. The new feature is **exposure-mode diversity**, not new providers or new trust scaling.

**Deliverables:**

* `publisher/deploy/cloudflare/` package using `cloudflare-go/v4`. Implements:
  * Cloudflare Origin CA cert provisioning.
  * Authenticated Origin Pulls enable + client-cert deployment to origin.
  * Worker / Page Rule template (public random path → stable origin path).
  * DNS record provisioning (proxied A + AAAA only; no DNS-only records).
  * Edge-IP-range refresh client (`edge_ranges.go`) consumed by the cloud-provider firewall rule. **Refresh runs from the FRP Helper machine** at deploy, rotate, and explicit-check events; optionally as a local OS scheduled task on the FRP machine. **Never runs on the origin box** (the origin holds no cloud-provider tokens; §11.7 explicitly forbids it).
* **Publisher freshness endpoint** (`publisher/deploy/cloudflare/freshness.go` + `internal/selection/freshness.go` + bundle-level `freshness_url` slot on `Manifest`): a small per-publisher signed JSON document at an FRP-controlled static URL listing the current bundle's hash and signed-bundle URL. Recipient clients poll opportunistically and atomically swap the RelayPack on a same-publisher freshness hit (no re-TOFU). See §14.4 "V1.6 freshness model" for boundary conditions.
* `publisher/deploy/providers/hetzner/firewall_cf.go` provisioning the Hetzner Cloud Firewall rule that allows inbound 443/tcp only from the daily-refreshed Cloudflare edge ranges.
* Wizard CDN screen with **BYO-domain default** (§20.4); the project test-zone path is available behind a strong warning for closed pilot only.
* Mode-aware **Rotate** UX (§14.4): the button copy adapts to whether the selector picked a direct-mode or fronted-mode rotation.
* Validator update: `exposure_mode: cdn_fronted` accepted; structural conformance to §11.7 enforced at deploy time (no DNS-only records, no SMTP/SSH on origin, AOP enabled, etc.).
* Selector rules from §13.4 become live (they were inert at V1.5).
* `docs/family-relay-publisher-v1.6.md` documenting the CDN flow + Cloudflare hardening checklist.

**Gate to V2.** 20+ FRPs running `cdn_fronted` candidates in production. At least one observed CDN-wide failure event (real or simulated) recovered from by the selector falling back to `direct_vps` siblings without operator intervention. At least one observed origin-IP-leak event (real or simulated, e.g. a deliberate misconfiguration) handled by the V1.6 origin-repair path without exposing the family. No direct-mode regressions vs the V1.5 gate.

### 21.3. V2 — Trusted cells + federation primitives + multi-provider + mobile

**Scope.** Add Vultr and Stark Industries providers. Mobile (Android Compose) wizard. **Trusted cells** (§16). **Federation primitives** (§17.1). **Default: cells only; no public directory.** Cells operate over **both** `direct_vps` and `cdn_fronted` candidates from V1.6.

**Deliverables:**

* `publisher/deploy/providers/vultr/` and `publisher/deploy/providers/stark/`.
* Floating-IP rotation across the new V2 providers (Vultr, Stark) — Hetzner's L3 floating-IP fast path already ships at V1.5 (§14.1). V2 extends the one-click L3 surface to the new provider adapters, not to Hetzner.
* Mobile wizard via `gomobile bind`.
* `publisher/cell/` package implementing cell-membership, cell-key handling, cell-aggregated RelayPacks (carrying both modes).
* `specs/cell-v1.md`.
* `specs/federation-primitives-v1.md`.
* In-box management plane (`daal-relay-mgmt`) gated by the cloud-provider-firewall ephemeral rule (`Provider.SetEphemeralFirewallRule`); restores L1/L2 rotation to ~5 s / ~20 s wall-clock.
* Documentation: `specs/family-relay-publisher-v2.md` covering multi-provider, multi-VPS-per-FRP, cell-join, mode mixing within a single RelayPack.

**Gate to V3.** 100+ active FRPs across at least two providers; at least 30% of FRPs have joined a cell; a documented rotation cycle has been recovered through cell-peer fallback without family-side outage; the six abuse-handling-maturity conditions (§17.2) have been measured and reported.

### 21.4. V3 — Public directory (gated)

**Scope.** Public directory aggregating opted-in cells. Inbound abuse-mitigation pipeline. Rate-limited submission. Multi-mirror hosting.

**Deliverables:** only if §17.2 gate flipped.

* `specs/public-directory-v1.md`.
* GitHub Actions workflow publishing the directory.
* Iran-side fallback: when no Tier-1/Tier-2/cell routes are reachable, query the public directory.
* Per-route abuse-signal tracking and demotion.

**Gate to V4.** 1,000+ active FRPs; at least 30% in cells; at least 10% of cells opted into the public directory; documented evidence of carrying users through a multi-day blackout.

### 21.5. iOS (post-V3)

Same rationale as base roadmap iOS deferral: TestFlight + entitlement constraints make it the least time-effective place to invest until the rest of the architecture is proven.

---

<a name="22-success-metrics"></a>
## 22. Success metrics

### 22.1. V1.5 FRP MVP success metric

> A diaspora user in Berlin who has never used Hetzner before installs Daal desktop, opens the wizard, and has a working RelayPack provisioned within 10 minutes. Their parent in Tehran scans the resulting QR code on their Daal Android client and is online within 60 seconds. Both sides remain operational without project intervention for at least 7 consecutive days. The selector demonstrably switches candidates at least once during the 7 days, and explains the switch in plain language to the recipient. **All candidates `exposure_mode: direct_vps` at V1.5.**

### 22.2. V1.6 CDN milestone success metric (added in v2.3.4; refined in v2.3.5)

> A diaspora user with their own domain runs the V1.6 CDN-mode wizard and produces a RelayPack mixing **`direct_vps` and `cdn_fronted` candidates** from the same Hetzner box, fully conforming to the §11.7 hardening template (Origin CA, Authenticated Origin Pulls, provider-firewall locked to Cloudflare edge ranges, no DNS-only A record, public-path → Worker-rewrite indirection). At least one TIC-observed event during a 30-day soak triggers the §13.4 mode-aware fallback (CDN-wide block demotes `cdn:cloudflare`; selector falls back to `direct_vps` siblings) **without family-side outage greater than 60 seconds and without family-side QR re-scan**. At least one **public-surface rotation** (hostname change or public-path change — both visible-to-TIC tags requiring a fresh RelayPack candidate, per §14.4) completes in under 30 seconds via Cloudflare API alone, with no box redeploy, and the updated RelayPack is delivered to the family via the V1.6 publisher freshness endpoint (§14.4) with no family-side QR re-scan. Separately, at least one **origin-only rotation** (origin IP swap, origin cert refresh, origin DC move with hostname unchanged) completes with zero family-visible event and zero RelayPack republish (the candidate is byte-identical because no `public_risk_tag` changed).

### 22.3. V2 trusted-cell success metric

> Across a soak deployment of 100 FRPs distributed across at least 3 providers and at least 2 EU regions, organised into at least 5 trusted cells of 5–25 members each: a TIC-driven burn cycle that blocks one entire provider's Frankfurt range is recovered from in under 15 minutes wall-clock time, by a combination of automated rotation and cell-peer fallback, with no more than 10% of family connections experiencing a lost-traffic event greater than 30 seconds.

### 22.4. V3 public-directory success metric (only if §17.2 gate flipped)

> During a documented Iranian internet blackout (defined by OONI or Censored Planet), the public directory carries Daal clients with no project-operated infrastructure on either end. At least 30% of FRPs are in cells; at least 10% of cells are in the public directory; the directory's average per-RelayPack burn lifetime is at least 7 days; project directory-key signing operations are auditable in a public log.

---

<a name="23-omits"></a>
## 23. What this supplement deliberately omits

* **Specific affiliate codes.** Operational secrets per provider; rotate; live in the project's secret store.
* **Persian translation copy.** Pilot territory; iterated with native-speaker review.
* **Specific Cloudflare Workers configuration for WebSocket-TLS.** Owned by `specs/route-object-v1.md` and sing-box upstream.
* **Detailed pricing breakdowns per region.** Pricing changes; the wizard pulls live pricing via `Provider.Pricing()`.
* **Marketing copy.** Downstream of having a shippable Helper; lives in the launch playbook.
* **Named diaspora-acquisition intermediaries.** Operational secret; lives in the private appendix per §20.6.
* **Specific auditor selection.** Same.

---

<a name="24-decisions"></a>
## 24. Decision points (chronological)

| Decision | Latest possible | Default | Notes |
|---|---|---|---|
| Helper-as-merchant vs Helper-as-configurator | Start of V1.5 | **Configurator** (locked) | Reversing requires a payment-services compliance plan; functionally a different project |
| Hetzner-only V1.5 vs multi-provider V1.5 | Start of V1.5 | **Hetzner-only** | Multi-provider is V2 |
| Cloud-init: live `apt-get` of relay artefacts vs pinned signed artefacts | Start of V1.5 | **Pinned signed relay artefacts; small distro-mirror package fetch accepted** (revised from v1) | Removes third-party *relay-artefact* fetch from the boot trust boundary; distro-mirror trust on a small audited package list (`curl`, `ca-certificates`, `openssl`, `python3`, `ufw`) is accepted as shape-equivalent to base-image security update path |
| Health endpoint: open vs one-time-token + IP-bound | Start of V1.5 | **One-time-token + IP-bound + auto-close** (revised from v1) | Real defence-in-depth |
| RelayPack: new format vs `.sbp` profile | Start of V1.5 | **`.sbp` profile** (revised from v1) | Inherits trust machinery; no engine ABI change; bundle-level new top-level slot is update-required for old clients (`spec_version` bump) |
| L1/L2 management plane | Start of V1.5 | **V1.5: redeploy-only; V2: cloud-provider firewall + persistent narrow-API mgmt service** (revised from v2.2) | v2.2's box-side `ufw` mgmt design had no working bootstrap path after SSH self-destructs; V1.5 ships redeploy-only, V2 unlocks fast L1/L2 via `Provider.SetEphemeralFirewallRule` |
| Selector: ML vs deterministic local policy | Start of V1.5 | **Deterministic** | Auditable, testable, telemetry-free |
| Cells in V2 vs V3 | Start of V2 | **V2** | Builds on `delegated_n` wire shape; new spec / import / UI; engine release ABI unchanged |
| Federation primitives in V2 vs V3 | Start of V2 | **V2** | Cell-side; not the same as a public directory |
| Public directory: V2 calendar-gate vs empirically-gated | Start of V2 | **Empirically gated** (revised from v1) | Ships only when §17.2 conditions met |
| **RelayPack risk-tag schema: flat vs mode-aware** | Start of V1.5 | **Mode-aware: `exposure_mode` + `public_risk_tags[]` + `origin_risk_tags[]`** (added v2.3.4) | Flat `shared_risk_tags` would have produced wrong cooldown propagation for `cdn_fronted` candidates (false demotion of siblings sharing an origin TIC never observed). Mode-aware schema lands at V1.5 even though only `direct_vps` candidates exist; `cdn_fronted` rules are tested no-ops at V1.5 and live at V1.6 |
| **CDN-fronted candidate phase placement** | Start of V1.5 | **V1.6 dedicated CDN milestone** (added v2.3.4) | Avoids burying CDN work inside V2 (which already carries cells, multi-provider, mobile); avoids "CLI-only opt-in inside V1.5" which would be the highest-risk-of-origin-leak path; gives a clean learning loop |
| **CDN-mode domain: BYO vs project-pool default** | Start of V1.6 | **BYO-domain production default; project test-zone closed-pilot only** (added v2.3.4) | Project-pool default would create a centralised block target, project liability, and metadata pressure (the project would learn origin IPs); delegated subzone preferred so Daal never holds origin records |
| **Field-technique reserved slots: `exposure_mode: serverless_external` + `modifiers[]: [client_desync, tls_fragment]`** | Start of V1.5 | **Reserved schema slots; rejected by V1.5 + V1.6 validators; enabled post-V2** (slots added v2.3.4; `modifiers[]` separation added v2.3.5) | Vocabulary reservation to avoid future schema churn; not a ship commitment. `serverless_external` is an endpoint type (lives in `exposure_mode`); `client_desync` and `tls_fragment` are packet-mutation modifiers (live in `modifiers[]`) — the two are orthogonal per v2.3.5. Tor/Snowflake/WebTunnel/Psiphon/Conjure stay in their existing route-family specs, NOT in §11.6 |
| Diaspora-acquisition surface: public listing vs private appendix | Pre-pilot | **Private appendix** (revised from v1) | Public listing makes infiltration cheaper |
| iOS support for the Helper | Post-V3 | Deferred | Same rationale as base roadmap iOS deferral |

---

<a name="appendix-a"></a>
## Appendix A — Cross-references

| Concept in this supplement | Base roadmap | Existing spec |
|---|---|---|
| Configurator pattern | V1.6 (Publisher CLI) — extended | `specs/publisher-keys-v1.md` |
| Publisher key generation | V0.2 spec B | `specs/publisher-keys-v1.md` |
| `.sbp` bundle signing | V0.2 spec A | `specs/sbp-v1.md` |
| **RelayPack profile** | V1.5 (this supplement) | `specs/relaypack-v1.md` (lands V1.5) |
| **Client Selection Policy** | V1.5 (this supplement) | `specs/selection-v1.md` (lands V1.5) |
| Bundle handoff via QR | V1.4 | `specs/qr-fountain-v1.md`, `specs/qr-static-v1.md` |
| Trust class (Tier-2 community) | V0.2 spec E | `specs/publisher-keys-v1.md` |
| 3F redistribution policy (basis for cells) | 3F shipped | `phases of development/25-phase-3f-one-tap-share.handover.md` |
| **Mode-aware exposure model** | V1.5 schema, V1.6 implementation (this supplement, v2.3.4) | `specs/relaypack-v1.md` §exposure-mode + §11.7 deployment template |
| **CDN-fronted candidates (V1.6 milestone)** | V1.6 (this supplement, v2.3.4) | `specs/relaypack-v1.md` §cdn_fronted + `publisher/deploy/cloudflare/` README |
| **Trusted cells** | V2 (this supplement) | `specs/cell-v1.md` (lands V2) |
| **Federation primitives** | V2 (this supplement) | `specs/federation-primitives-v1.md` (lands V2) |
| **Public directory (gated)** | V3 (this supplement, if gate flipped) | `specs/public-directory-v1.md` (post-gate) |
| Lifeline relay | V3.7 (3G filed not shipping) | `phases of development/26-phase-3g-lifeline-relay.md` |
| TOFU + revocation | V1.5.2 | `specs/revocation-v1.md` |
| Engine ABI stability (=48) | V0.4 / 3-Soak | `specs/engine-abi-v1.md` |
| Telemetry posture | CC.6 | (constitutional) |
| Reproducible builds | CC.2, CC.4 | (operational) |

---

<a name="appendix-b"></a>
## Appendix B — Glossary

* **Anti-burn race policy.** The selector discipline that bounds how aggressively candidates are tried, so Daal's own retry behaviour does not burn routes faster than censorship does.
* **Cell.** A bounded group of FRPs (3–25) mutually sharing spare RelayPack capacity using 3F's `delegated_n` redistribution policy. Authority gate: an admin-quorum-signed (M-of-N independent Ed25519) membership document plus an admin-quorum-signed delegation grant that authorises a per-cell bundle-signer key.
* **Cell scope.** The RelayPack profile's per-candidate annotation describing which cell can redistribute the candidate and to what depth.
* **Configurator pattern.** Daal automates cloud-provider operations using user-supplied credentials, locally, on the user's machine — never holding money, identity, or credentials on a Daal-controlled server.
* **Correlated failure.** Two or more candidates failing for one underlying reason (shared IP, shared ASN, shared domain, shared cert). The RelayPack's shared-risk graph makes it explicit; the selector attributes failure correctly along its edges.
* **Family Relay Publisher (FRP).** A trusted diaspora Iranian operating one or more helper-provisioned VPSes for their family in Iran, identified by an Ed25519 publisher key and Daal's `community` trust class.
* **Federation primitives.** The V2 mechanisms (signed publisher exchange, cell directories, abuse-reporting hooks, etc.) that enable cell-scoped trust scaling without yet exposing a public directory.
* **Floating IP.** A cloud-provider feature that lets an IP be reattached to a different server without rebuilding it. Critical for L3 of the rotation ladder.
* **Honesty class.** Per-candidate `vps-native` / `vps-possible` / `external-ecosystem` annotation, expressing what one VPS can and cannot host.
* **OperatorRecord.** The locally-stored, encrypted record of a helper-deployed VPS plus cell credentials, holding everything needed for later rotate, snapshot, decommission, or migrate.
* **Probing-risk class.** Per-candidate `low` / `moderate` / `high` annotation describing resistance to active probing; drives anti-burn race policy.
* **Public directory.** The V3 (gated) aggregator of opted-in cells. Ships only when §17.2's six abuse-handling-maturity conditions are met.
* **RelayPack.** An `.sbp` bundle conforming to the RelayPack profile: multi-candidate, single-publisher, shared-infrastructure-risk-annotated.
* **Rotation ladder.** Six escalation levels from L1 (regenerate credentials) to L6 (change protocol mix); the selector recommends the cheapest level matching the failure category.
* **Selector / Selection brain.** The deterministic local policy that turns RelayPack breadth into reliability via probe → filter → diversity-shortlist → race → classify → cool-down-propagate → remember → explain.
* **Shared-risk graph.** The per-RelayPack annotation linking candidates by mode-aware risk tags. Since v2.3.4 the tags are split into **`public_risk_tags`** (what TIC observes — `public_ip:`, `public_asn:`, `public_dc:`, `public_provider:`, `public_domain:`, `cdn:`, `sni:`, `host:`, `ws_path_fp:`, `public_port:`) and **`origin_risk_tags`** (operator-only — `origin_ip:`, `origin_asn:`, `origin_dc:`, `origin_provider:`, `origin_cert:`). Cooldown propagation differs by mode: a `public_risk_tag` failure propagates to every sibling carrying that tag; an `origin_*` failure on a `cdn_fronted` candidate is operator hygiene and does not propagate to siblings' public surfaces.
* **Exposure mode.** Per-candidate `direct_vps | cdn_fronted | serverless_external` annotation describing **what endpoint** the family's Daal connects to. Drives the mode-aware rotation table (§14.4) and the mode-aware cooldown rules (§13.4). V1.5 produces only `direct_vps`; V1.6 adds `cdn_fronted`; `serverless_external` is a reserved schema slot for post-V2 work. Packet-mutation behaviours (FakeSNI, TLS fragmentation) are NOT `exposure_mode` values — they live in `modifiers[]` (§12.2.2.bis).
* **Modifiers.** Per-candidate optional array of client-side packet-mutation modifiers (e.g. `client_desync`, `tls_fragment`) the recipient applies before bytes leave their machine. Reserved schema slot at V1.5 and V1.6 (validator rejects non-empty arrays); post-V2 may enable specific modifiers under explicit feature-flag. Distinct from `exposure_mode`: `exposure_mode` is "what endpoint do I connect to"; `modifiers[]` is "what do I do to the packets on the way out."
* **Public risk tag.** A risk-tag entry describing a surface that the censor (TIC) directly observes and can blocklist. Cooldown failures on these tags propagate to every sibling sharing the same tag. Examples: `public_ip:`, `cdn:`, `public_domain:`, `sni:`.
* **Origin risk tag.** A risk-tag entry describing a surface visible only to the operator under a correctly hardened deployment (§11.7). On `cdn_fronted` candidates, origin-tag failures are operator hygiene and do not propagate to public surfaces. Examples: `origin_ip:`, `origin_provider:`, `origin_cert:`.
* **Tier-1 / Tier-2 / Tier-3 publisher.** Project-operated / community-FRP / federation-aggregated publishers; trust class governs UI badges and selector priority.
* **TOFU.** Trust On First Use — explicit acceptance of a publisher's identity once, remembered locally.
* **Toolbox profile.** A named declarative deployment template (`iran-default`, `china-default`, etc.) combining `vps-native` candidates appropriate to a threat model. Profiles are data, not code.
