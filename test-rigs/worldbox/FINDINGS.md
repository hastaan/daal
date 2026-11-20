# Findings

Every defect and observation about **Daal itself** that the rig exposed —
fixed or open — with severity, exact reproduction, and what now pins it.
The rig does not work around any of them.

**How an open finding shows up in a run.** A check that does not match its
expectation is red (`ok:false` in `results.jsonl`) and stays red until the
product changes. If — and only if — it is listed in `known-findings.json`
against an entry of this file, the report prints it as `KNOWN [id]` and it
does not fail the run; any other red check does. When a known finding's
checks run and are all green, the run **fails** with "did not reproduce":
delete the entry there and mark the finding fixed here. So a fix is noticed
the day it lands, and nothing in that file can become a blanket excuse
(`driver/known_test.go` holds both files to that).

Repo state: the release-ready wave (branch `release-ready-wave`) with the
pin moved to relay-v1.5.1, published 2026-11-19 (GitHub releases
`relay-v1.5.1` and `relay-v1.5.1-mirror`, byte-identical to the candidate
the rig proved). Last gate 2026-11-19: `./daal e2e full` →
`PASS — 5388 checks`, 18 worlds, the three pinned worlds (`release`,
`release.lifecycle`, `release.all-families`) green; the only known
finding is CEN-4. **Not yet run on a phone or on a rented relay** — that
is `docs/release-runbook.md`, Part 2 onwards. **Since the first phone pass
(2026-11-19, branch `phone-pass-fixes`)** the rig also switches routes on a
live session (ops `switch`, `switch-all`): SW-0 and SW-2 are fixed, SW-1
is open and in `known-findings.json`. Gate on that branch, 2026-11-19:
`./daal e2e full` → `PASS — 5901 checks`, 20 worlds, known findings
reproduced: CEN-4 and SW-1 only. **Since the second phone pass
(2026-11-19, branch `auto-connect`)** the rig presses the one button (op
`auto`: engine_connect_auto on a real TUN — sections AUTO-0, AUTO-1,
AUTO-O1): SW-1 is fixed and its entry deleted, CEN-4 is narrowed, AUTO-1
is new and open. Gate on that branch, 2026-11-19: `./daal e2e quick` →
`PASS — 1960 checks` (17 worlds, 79 s; known: CEN-4), `./daal e2e full` →
`PASS — 6195 checks` (21 worlds, 225 s; known findings reproduced: CEN-4
×15, AUTO-1 ×1). **Since the measure-and-probe wave (2026-11-19, branch
`measure-and-probe`)** the rig checks what the censor sees while the
engine probes two routes at a time, the per-network measurements, the
move for speed and the network facts from the host (ops `auto` and
`auto-deep`, the flow tap — sections AUTO-3, AUTO-2, SW-3, AUTO-O3…O6):
AUTO-1 is fixed only for a host that reports NO network (kind `none`);
for a link that is up and not validated it is open and its entry is
back (the repair pass: an unvalidated network is not proof of no
internet); AUTO-2 and SW-3 are new and open. Gate on that branch,
2026-11-19: `./daal e2e quick` → `PASS — 2004 checks` (17 worlds, 128 s;
known: CEN-4 ×7, AUTO-2 ×1), `./daal e2e full` → `PASS — 6521 checks`
(22 worlds, 267 s; known findings reproduced: CEN-4 ×15, AUTO-2 ×1,
SW-3 ×1); after the repair pass `./daal e2e full` → `PASS — 6530 checks`
(267 s; known: CEN-4 ×15, AUTO-1 ×1, AUTO-2 ×1, SW-3 ×1; quick not
re-run). None of it has been run on a phone. Below, "the pinned release"
/ "the pinned box" in text written before 2026-11-19 means relay-v1.5.0.
Reproductions are run from `test-rigs/worldbox/`. "quick"/"full" are the
modes of `./daal e2e` (`./e2e.sh`); a world name is a row of its report.

### Fixed in this tree (26)

| id | severity | one line | status | reproduce (before the fix) | pinned by |
|---|---|---|---|---|---|
| BOOT-1 | **high** (security) | The management-TLS fingerprint the publisher pins — and then believes every relay reply on, including the keys it signs into a pack — was read from a plain-HTTP health reply: a machine on the path during provisioning swapped one JSON field and the publisher signed the attacker's REALITY key and TLS pin | **fixed** in `publisher/deploy/health` (`bootstrap.go`, `poll.go`, `handler.go`): the fingerprint is accepted only with a MAC under the health token, which reaches the box in cloud-init user-data and is no longer sent (the URL carries a derived value); no unauthenticated fallback. Second line in the wizard (`relay_identity.rs`): a relay that was not rebuilt and states a different REALITY key or TLS pin than the signed one is refused, not re-signed. Spec `daal-relay-mgmt-v1.md` §2.1. **Released as relay-v1.5.1 (2026-11-19)**: the pinned `daal-relay-health` authenticates, and the three pinned worlds provision through it. A relay built from relay-v1.5.0 fails at `provision` (closed); none is in service | unit, at `062f809`: a proxy that rewrites `mgmt_tls_fingerprint` in the health reply → `Poller.WaitForMgmtFingerprint` returns the attacker's value, no error | unit `TestPoller_RefusesAFingerprintRewrittenOnThePath`, `TestPoller_NeverSendsTheHealthToken`, `TestFingerprintMAC` (wire vector), `TestHandler_MakesTheMACItself`, `TestWaitForMgmtFingerprint_StopsOnAStandingRefusal` (publisher/deploy/health); wizard `a_relay_that_states_new_keys_without_a_rebuild_is_refused_not_signed`, `a_rebuilt_relay_is_signed_with_its_new_keys`, `only_a_committed_key_stated_differently_is_a_key_changed_in_place`; rig: every world, tree and pinned, provisions through the authenticated bootstrap (`--mgmt=tree` also runs the tree's `daal-relay-health`). **No rig check plays the on-path attacker** (the censor sits between client and relay, not between publisher and relay) |
| FAM-1 | **high** (user-visible) | On naive, an app's name lookups (plain UDP/53) get no answer: "connected", nothing loads | **fixed** in `core/engine/config.go` — **names only** — and since FAM-6's fix the naive pack carries UDP itself, so on naive this path no longer runs (lookups ride the tunnel); it still covers every TCP-only outbound (naive, http, tor, ssh, shadowtls, `network:tcp`), but the rig exercises naive only; needs one phone retest (Private DNS off, naive route and tor route, open a site by name) | revert the `hijack-dns` hunk, `./run.sh clean naive` → `family/naive dns` blocked | unit `TestBuildSingBoxConfigHijacksDNSForUDPLessOutbounds`, `TestTCPOnlyOutboundTypesMatchSingBox` (core/engine), and under `-tags singbox` (now run by `./daal test`) `TestHijackedDNSConfigIsAcceptedBySingBox` — the linked sing-box parses and starts the rule together with the legacy-format dns block; rig check `family/naive dns` in quick and full |
| LC-1 | low-to-medium (security, defence in depth) | A mgmt token already used once could be replayed with a different body (`users-revoke` against another recipient, etc.) | **fixed** twice over in `cmd/daal-relay-mgmt/main.go` + `publisher/deploy/mgmt/token.go` + spec §3: every mutating token is single-use (in memory), and — token format v2 — the signature now covers the method, the path and the SHA-256 of the body, so a token is good for ONE request whatever the daemon remembers (the restart residual is closed; what is left is stated in the section). The v1 format is refused. **Released as relay-v1.5.1 (2026-11-19)**; no relay older than relay-v1.5.1 is in service | `./run.sh --ops mgmtauth clean @default` (pinned release, at `062f809`) → `replay.users-revoke` honoured | unit `TestTokenIsBoundToTheRequest` (a signed token with another body is refused, never-used and after a restart), `TestV1TokenIsRefused`, `TestMutatingTokensAreSingleUse`, `TestAddressTokenIsSingleUse`, `TestTokenV2Vector_BoxAcceptsWhatThePublisherSigns` (cmd/daal-relay-mgmt); `TestToken_SignsTheRequestNotJustTheOp`, `TestTokenV2Vector_PublisherProducesTheFixture` (publisher/deploy/mgmt); rig `op:mgmtauth replay.users-revoke`, `signed_for_another_body`, `signed_for_no_body`, `v1_token` green on the tree build in quick and full, and on the pinned box in world release.lifecycle (full) since the pin moved — the `LC-1` entry is gone from known-findings.json |
| FAM-5 | low (latent) | Off Android the engine could never load Cronet from beside its own binary (a failed first try is cached for the process) | **fixed** in `core/engine/cronet_state.go`, `cronet_loader_naive.go` | revert, `./run.sh clean naive` → `tunnel` refused, "cronet: failed to load library" | unit `TestCronetLibraryArg` + `TestLoadCronetUsesCronetLibraryArg` (core/engine); rig: every `family/naive tunnel`. Android unchanged by construction, not device-tested |
| FAM-6 | medium (user-visible) | naive carried **no app UDP except DNS**: QUIC without a TCP fallback, calls, games got nothing while the route was "Connected" | **fixed** in `publisher/deploy/relaypack/client_outbound.go`: the minted naive outbound asks for `udp_over_tcp` (version 2); the relay's naive inbound accepts it with no change (sing-box 1.13.12 `protocol/naive/inbound.go`), the signed-endpoint check and the freshness merge keep it. **Packs already minted do not change: re-mint.** Not verified: a phone (datagrams over one TCP stream through Cronet — throughput, battery), and no soak | at `062f809`: `./run.sh clean naive` → `family/naive udp expect=blocked got=blocked` | `family/naive udp` = pass in every world and under every censor scenario (`families/naive.json`); unit `TestClientOutbound_NaiveCarriesUDP` (relaypack: minted, accepted by `bundle.CheckOutbound`, kept by `MergeEndpoint`), `TestClientOutboundMatrixIsCurrent` + the core/engine matrix test (the linked sing-box parses it) |
| INT-2 | medium (intermittent; on the relay) | naive: sing-box 1.13.12 decides the naive inbound's ALPN with a start-up race; about 1 start in 1000 leaves naive/TCP answering every ClientHello with alert 120 (`no_application_protocol`; Cronet `net_error -107`) for the whole life of that sing-box process. Nothing is logged; the engine says Connected | **fixed** in `cmd/daal-relay-mgmt/singbox_users.go` (the daemon now writes `alpn` into `naive-in`, so nothing is left to race; an older inbound is healed on the next recipient add); **released as relay-v1.5.1 (2026-11-19)**. Root cause is upstream sing-box, worth reporting there | `repro/int2-naive-alpn-race.sh` (no Daal involved: 3 dead instances in 3000 starts; `… pinned` → 0 in 3000) | unit `TestAppendNaiveUserCreatesInbound`, `TestNaiveALPNHealsAnOlderInbound` (cmd/daal-relay-mgmt); the `INT-2` entry (box=pinned, signature `net_error -107`, budget 4) is gone from known-findings.json since the pin moved: on any box the same face is an unexpected red |
| F-004 | **high** (security, design) | A pack's outbound profiles were not authenticated: anyone could rewrite the server address under the publisher's fingerprint | **fixed** — "signed endpoint, local credential": every route's server, port and server-authentication material is committed in the signed manifest (`_endpoint`), the importer refuses an outbound that disagrees (`endpoint_mismatch`, before any trust prompt), `SetRoute` re-checks. `bundle/go/bundle/endpoint.go`, `bundle/go/importer/endpoint_plan.go`, `publisher/deploy/relaypack/endpoint.go`, `core/abi/endpoint_guard.go`; spec `relaypack-v1.md` §"Endpoint commitment". **Not covered:** bundles that are not RelayPacks (section below) | at `257238a`: `./run.sh --ops tamper clean vless-reality` → `import_of_tampered_pack got=pass` | `op:tamper import_of_tampered_pack` and `.port` / `.tls_pin` / `.reality_public_key` / `.trusted_certificate` / `.tls_insecure` / `.folded_key` / `.shadowsocks_server_key`, `commitment_stripped.import`, `credential_rewrite.*` (quick + full); `tampered_pack.connect` (a phone told to connect with the tampered pack stops at import: no route listed, engine never started); `TestSetRoute_EndpointRefusalComesBeforeAnyConnectionAttempt` (core/abi: a refused route starts no engine, runs no connection check, records no attempt); `TestCheckOutbound_RefusesEveryEndpointRewrite`, `TestCheckOutbound_RefusesFoldedKeySpellings` (a second, case-folded spelling of a checked member name), `TestImport_TamperedEndpointIsRefusedNotPrompted`, `TestImportSBP_RefusesAPackWhoseEndpointWasRewritten` |
| F-006 | medium (security) | A bundle with no `relay_pack` slot — same publisher, same route ids, profiles rewritten with no key — silently replaced committed routes and deleted their commitments | **fixed** — a commitment is sticky: an import that carries no signed endpoint for a route the device already holds with one (stored commitment or `relay_pack_id`, in any trust state) is refused whole, `endpoint_downgrade`, before any trust prompt; the store refuses the same write itself, before writing anything. `bundle/go/importer/endpoint_plan.go` (rule 5), `core/trust/state.go` (`RouteCommitted`, `SaveImport`); specs `relaypack-v1.md` §"A commitment is sticky", `sbp-v1.md` §"What the signature covers". **Not covered:** a plain bundle's routes under NEW ids are still unauthenticated (section below) | with both guards switched off: `./run.sh --mgmt=tree --ops tamper clean vless-reality` → `uncommitted_replacement.import expect=refused got=pass` | `TestImport_BundleWithoutCommitmentsDoesNotReplaceCommittedRoutes` (bundle/go/importer); `TestStoreAdapter_CommitmentIsSticky`, `TestStoreAdapter_KeepsWhenARouteEndpointWasSigned` (core/trust); `op:tamper uncommitted_replacement.{control.new_routes.import,import,routes_kept}` |
| LC-2 | **high** | The freshness channel could only deliver the credential-less signed skeleton, which REPLACED a polling recipient's working pack with one that could not connect | **fixed** — a signed pack with no credentials is MERGED: the device keeps its credentials and takes the new signed endpoint; a profile with no outbound never replaces one that has one; the same file imported on a phone that holds nothing is refused (`pack_has_no_credentials`). After L2 and L3 a polling phone recovers with **no new file**. **Still needs a new file:** L1 (that one recipient) and L4–L6 (everyone) — section below | at `257238a`: `./run.sh --mgmt=tree --ops freshness clean vless-reality` → `unchanged.signed-pack-hosted.tunnel got=refused` | `op:freshness unchanged.signed-pack-hosted.{tunnel,routes_kept}`, `signed-pack-alone.import`, `published.*.holds_no_credentials`, `rotated.polled.tunnel`; `op:l2 no-new-file.cover-host-moved.*` (7 families); `op:l3 no-new-file.address-blocked.*` — including `.route_checked`: the merged route passed the engine's own connection check (`route_check=ok`) before it was Connected; `TestSetRoute_MergedRouteIsConnectedOnlyAfterTheConnectionCheck`, `TestSetRoute_MergedRouteThatCarriesNothingIsNotConnected` (core/abi); `TestApplyVerifiedRefresh_MergesSignedEndpointIntoDeviceCredentials`, `TestRotationHealsAnImportedPackOverTheNetwork` |
| LC-4 | medium (security) | A signed, credential-less pack from BEFORE a rotation, handed over as a file, was merged into a phone that had already moved on: its routes went back to the old cover host / port / relay key, silently (the publisher is already trusted) | **fixed** — a file only moves a route forward: outside the freshness path a merge needs the incoming manifest's `bundle.created_at` to be strictly later than the one the route's commitment came from (kept by the store beside the commitment); the manifest the route is already on is a no-op. An older one is reported `older_than_device` (`pack_is_older` when nothing else is in the file) and the route is untouched. Section below | importer: import v1, merge v2's skeleton (same pack id, REALITY key rotated), import v1's skeleton → `Imported, Merged=2`, both routes back on the old key. Rig, with the rule switched off: `./run.sh --mgmt=tree --ops freshness clean vless-reality` → `rotated.stale-signed-pack-by-file.tunnel got=blocked` (`reality verification failed`) | `TestImport_AnOlderSkeletonDoesNotRollARouteBack`, `TestImport_AnOlderSkeletonRouteIsReportedAndLeftAlone`, `TestImport_SkeletonDoesNotMergeIntoARouteOfUnknownAge` (bundle/go/importer); `TestStoreAdapter_KeepsWhenARouteEndpointWasSigned` (core/trust); `op:freshness rotated.stale-signed-pack-by-file.{not_merged,routes_kept,tunnel}` |
| LC-3 | medium | After an L3 address move naive could not connect to the new address (the box certificate named only the first-boot address) | **fixed for relays provisioned from this tree** — cloud-init adds one stable DNS name to the certificate; naive verifies against it when (and only when) the address it dials is not in the certificate (`bundle.NaiveVerificationName`). **And the name now follows the cover host**: `rotate-tls` re-issues the certificate on the same key with the new cover host first and the old names kept (`cmd/daal-relay-mgmt/tlscert.go`; released as relay-v1.5.1, 2026-11-19), so after L2 → L3 a re-minted file presents the CURRENT cover host and files from before both rotations keep connecting. The stable name is written by cloud-init, so only a relay provisioned FRESH from this release has it (a relay provisioned before this wave would lose naive on L3 until rebuilt; none is in service); a phone handed nothing keeps presenting the old name (section below). The "engine says Connected" half was CEN-1 | at `257238a`: `./run.sh --mgmt=tree --ops l3 clean naive hysteria2` → naive `new-file.address-blocked got=blocked` | `op:l3/naive new-file.address-blocked.{tunnel,wire}` and `no-new-file.address-blocked.tunnel` (full); `op:l2 box.certificate_follows_cover_host`; `op:l3/naive after-l2.new-file.presents_current_cover_host` and `op:l3/* no-new-file.after-l2.address-blocked.*` (world clean.rotation runs l2 THEN l3); `TestNaiveVerificationName`, `TestClientOutbound_NaiveVerificationNameFollowsTheCertificate`; `TestRotateTLS_ReissuesTheCertificateForTheNewCoverHost`, `_FailedReloadPutsTheOldCertificateBack`, `_CertificateTroubleDoesNotStopTheRotation`, `_WSPathOnlyLeavesTheCertificateAlone` (cmd/daal-relay-mgmt) |
| F-003 | medium | Routes the minter "dropped" still imported, listed and could be activated on the client | **fixed** — a RelayPack route whose profile holds no outbound is not stored: it is not listed, not selectable, not activatable; the import verdict names it (`Unavailable`, reason `not_offered` / `no_credentials` / `needs_new_file`) and the app has copy for each | at `257238a`: `./run.sh clean anytls` (pinned): `routes` lists r5–r7, `error` carries a parse error | `family/* import.unconnectable_not_listed` in every session of every world (red only where a pack has a dropped route: world release.all-families); `TestImport_RoutesTheMinterDroppedAreNotStored`, `TestDroppedRouteIsNeitherListedNorActivatable` |
| INT-1 | **high** (intermittent) | naive: the whole engine process died with SIGSEGV inside Cronet when a connection was closed at the moment its stream terminated — a use-after-free race in the pinned `cronet-go` (`Close`→`Cancel` against `terminate`→`Destroy`). Seen in the rig only; never observed on a device | **fixed** by bumping `cronet-go` (and `cronet-go/all`, `lib/*`) in `core/go.mod` to `v0.0.0-20260912104727-0d28acc44093`, the first module build with upstream `172bb4ede18c` "Fix bidirectional stream cancel racing with destroy" (it is what sing-box 1.14.1 ships; it builds against the pinned sing-box 1.13.12). **Linux proven here; Android NOT verified, and the phone needs a rebuilt `libcronet.so`** — the bump changes the library's C ABI (see the section) | `for i in 1 2 3 4; do WB_RESTART_CYCLES=25 ./run.sh --mgmt=tree --ops restarts clean naive & done; wait` → before: 3 engine deaths in 520 naive sessions; after: 0 in 1040 | unit `TestCronetGoCarriesTheCancelDestroyFix`, `TestCronetLibModulesMoveTogether`, `TestCronetGoCloseCancelsUnderTheLock` (`core/engine/cronet_pin_test.go`); rig: `*/naive engine.survived` is no longer excused by anything — one engine death fails the run; `tools/cronet/check-libcronet-stamp.sh` refuses a mismatched Android library |
| FAM-2 | medium | The app could not enable shadowsocks, anytls or tuic at all: the wizard hard-coded an empty family list | **fixed** in `client-ui/src/publisher/` — a collapsed, default-off "More ways to connect" section on the plan screen (`MoreWaysToConnect.tsx`, `extraFamilies.ts`), en+fa. The switches were locked, with the reason, until F-002's release; **unlocked since relay-v1.5.1 (2026-11-19)** — `cloudinit.PinnedMgmtServesOptInFamilies` and its UI mirror are true (section below). *Basis: unit-tested and type-checked; the app itself was not run* | `grep -n enabledFamilies client-ui/src/publisher/PublisherWizard.tsx` (was a constant `[]`) | vitest `src/publisher/extraFamilies.test.tsx` (26 tests); not pinned by the rig (above the ABI) |
| FAM-3 | medium | `provision --families` was a silent filter: a typo dropped the family, a short list dropped the defaults, exit 0 either way | **fixed** in `publisher/deploy/cli/cli_families.go`: a name the profile does not offer is exit 2 before any cloud call, naming the value and the valid set; what the list drops is stated (stderr, or a `provision_families` progress event) — as "will be asked to serve", naming the family, whenever the pinned release cannot serve one (none since relay-v1.5.1, 2026-11-19: the line is "will serve"). L6 keeps working: `reprovision` narrows the record it hands on | `daal-deploy provision … --dry-run --families vless-reality,tiuc` (section below) | unit `publisher/deploy/cli/cli_families_test.go`; not pinned by the rig |
| FAM-4 | low | De-selecting a default family did not take it off the box: 4 open, listening ports the pack never mentions | **fixed** (cloud-init + `daal-relay-mgmt` + both firewalls; backlog W5-1 with it); the daemon half is **released as relay-v1.5.1 (2026-11-19)**. The family set and the firewall are cloud-init: only a relay provisioned FRESH from this release has them | `./run.sh --mgmt=tree --relay-families shadowsocks,anytls clean shadowsocks anytls` | rig world narrow-relay (full): `mint/* not_served` green with `listener_on_box: false`, and `censor/prove.relay-tls-answers` asserted CLOSED on a relay without a 443/tcp family; unit `TestProvision_NarrowRelayBindsOnlyItsFamilies` and neighbours (`cmd/daal-relay-mgmt/families_test.go`), `TestFirewallPortsForFollowsTheFamilySet`, `TestSingBoxConfig_EveryInboundFollowsTheFamilySet`, `TestProvision_NarrowFamilySetLeavesNothingElseOpen` (hetzner, vultr), `TestRender_UFWOpensExactlyTheDataPlanePorts` |
| F-001 | low (latent) | `daal-fetch-verify` failed with a misleading message when `/tmp` and `/usr/local/bin` are different mounts | **fixed** in `publisher/deploy/cloudinit/shim.sh.tmpl` (stages beside the destination, prints the per-mirror reason); shim hash and cloud-init golden re-pinned; reaches a relay with the next provision | mount a tmpfs on the box's `/tmp` in `box/init.py` (section below) | unit `TestVerifierShim_InstallsAcrossMounts`, `_SaysWhyAMirrorFailed`, `_RefusesBadSignature`, `_FallsBackToSecondMirror` (`shim_exec_test.go` — they run the embedded shim) |
| CEN-1 | **high** | A route that carried nothing was "Connected", recorded as a success, and came out `proven: true`, `health_pct: 100`; the engine never classified a data-plane failure | **fixed** — a route is Connected only after one real round trip through its own outbound (`core/engine/proof.go`, `core/abi/route_check.go`): `verifying` → `ok` / `degraded` / `failed`; a failed proof is torn down, classified, cooled down and recorded, and `SetRoute` returns the error; a connected route is re-proved every ~3 min (jittered) and on a network change. Spec `engine-abi-v1.md`. **Not verified:** the phone (SetRoute now blocks for the proof, up to 8 s on a dead route, 90 s per attempt on tor) and the default public targets, which the lab cannot reach | at `257238a`: `./run.sh --mgmt=tree relay-ip-block vless-reality hysteria2` → `engine.category got=none`, posture `ImportedActive`, `proven_after=true` | `family/* engine.category` in every blocking scenario (40 sessions in full: 26 named exactly, 14 named as the coarser thing one route can see — CEN-4); unit `TestSetRoute_StartedButCarriesNothingIsNotConnected`, `TestSetRoute_IsVerifyingUntilProved`, `TestCheckActiveRoute_ConnectedToFailedAndBack`, `TestLiveness_TimerAndNetworkChange`, `TestSetRoute_RefusedLeavesTheConnectedRouteWatched`, `TestSetRoute_RefusedForCooldownKeepsTheRecoveryLoop` (a refused `SetRoute` used to stop the liveness loop of the route that stayed up — review finding, fixed), `TestSetRoute_RefusedLeavesTheCheckInFlightRunning` (a refused `SetRoute` used to cancel the connection check of another `SetRoute` still in flight and strand its instance in `verifying`, unproven and unwatched — review finding, fixed) (core/abi), `TestProveInstance_*` (core/engine, `-tags singbox`); vitest `src/lib/routeCheck.test.ts` |
| CEN-2 | medium | `diagnostics.Classify` could not tell a reset after the ClientHello from a reset of the address, and filed a TLS-phase timeout under `tcp_connect_timeout` | **fixed as far as one route can see** — the engine classifies a failed proof from an observation (phase reach / handshake / carry, UDP or TCP, TLS first flight or not: `core/diagnostics/observe.go`, `ClassifyObservation`); the locked string table is unchanged and still decides where the observation settles nothing. Name-keyed vs address-keyed reset is CEN-4 | at `257238a`: `echo 'read tcp4 1.2.3.4:5->6.7.8.9:443: i/o timeout' \| bin/wb-client --classify` → `tcp_connect_timeout` | `family/* engine.category` under sni-rst, sni-rst-stateless, sni-drop (the engine's category equals the raw probe's); unit `TestClassifyObservation_PhaseSeparatesWhatTheStringCannot`, `_FallsBackToTheLockedTable`, `TestSetRoute_FailedProofIsClassifiedByPhase`, `TestProveInstance_SwallowedHelloIsNotADeadAddress` |
| CEN-3 | medium (spec) | The failure taxonomy had no word for three things a censor does: UDP dropped toward ONE address, UDP dropped on ONE port, and "connects but too slow to use" | **fixed** — `specs/failure-taxonomy-v1.md` revision 2 adds `udp_address_blocked`, `udp_port_blocked`, `path_too_slow` (a degraded outcome, never a failure or a cooldown) and `udp_no_reply` (what one silent UDP route can honestly say). The engine produces `udp_no_reply` and `path_too_slow`; the two narrower UDP words need a second observation (CEN-4) | at `257238a`: scenarios relay-ip-block, port-whitelist, throttle-56k declared the nearest category (`unknown`, `udp_unavailable`, `none`) | `censor/* truth.category` now declares and raw-proves the new words; `family/* engine.category` under throttle-56k (`path_too_slow` where the proof sees it); unit `TestSetRoute_SlowProofIsDegradedNotFailed`, `TestPathTooSlowIsNotACooldownClass`, `TestClassifyObservation_SilentUDPIsNeverANetworkClaim`; `driver/censor_test.go` |
| CEN-5 | **high** (user-visible) | After a connect that failed the app said "Connecting…" for good while nothing was running — on Android with no error at all (the connect call resolves before the engine has tried the route). Same words as a connected route the engine really is retrying | **fixed** — the diagnostics blob says `route_running` (true exactly while an engine instance for a route is up); the app shows a failed connect as an error, "Could not connect on this route. Try another one.", and a lost connection as "Connection lost. Trying again…" (en + fa). Spec `engine-abi-v1.md`. **Not verified:** on a phone; the rig does not render the app, it checks the engine field the app reads. **Still open:** while a lost connection is being retried the main button does not disconnect (section below) | at `257238a` + CEN-1: any blocked session, e.g. `./run.sh --mgmt=tree relay-ip-block vless-reality` → the error event's `diag` has `posture: Recovery`, `route_check: failed` and nothing that says the engine stopped; `connStateWithCheck('connecting','failed')` → `connecting` → headline "Connecting…" / «در حال اتصال…» | `family/* engine.failed_connect_not_running` in every blocked session; unit `TestRouteRunning_TellsAFailedConnectFromALostConnection`, `TestRouteRunning_LostConnectionKeepsRunning` (core/abi); vitest `src/lib/routeCheck.test.ts` |
| CEN-6 | **high** (the rig hid it; one product defect under it) | throttle-56k could not go red: a first phone whose connect FAILED ("the route started but carried no traffic", `tls_handshake_failed` / `unknown`, a 5–30 min cooldown) was replaced by a fresh phone and only that one was judged; the cell accepted `path_too_slow|none`; and a connect that took 4.7–5.5 s read plain "Connected" | **fixed** — engine: a proof is slow when the WHOLE proof took longer than `slow_after_ms`, failed attempts included (`core/engine/proof.go` `proofWasSlow`; specs `engine-abi-v1.md`, `failure-taxonomy-v1.md`). Rig: every connect attempt is recorded and the first is judged alone (`engine.first_verdict`); the scenario declares `path_too_slow` and the cell is decided per connect by its time; a session waits for the censor's shaper to drain the session before it (the first-phone failures were the previous QUIC family's queue — rig cross-talk, measured). **Left as it is:** what the engine says on a link that already has seconds of queue (CEN-O5) | before: `./run.sh --mgmt=tree throttle-56k` → exit 0 with `connect_attempts: 2` on naive and vless-reality and `route_check: ok` after `set_route_ms` ≈ 5000. Now, the same failure made visible: `WB_NO_QUIET=1 ./run.sh --mgmt=tree throttle-56k` → `engine.first_verdict` red | `family/* engine.first_verdict`, `family/* engine.category` under throttle-56k; unit `TestRunProofTimedOutCarryAttemptThenSuccessIsSlow`, `TestProofWasSlowJudgesTheWholeProof` (core/engine); `driver/first_verdict_test.go` |
| F-002 | **high** | A relay provisioned from `main` could not serve shadowsocks, anytls or tuic: the then-pinned `daal-relay-mgmt` (relay-v1.5.0) predated them | **fixed — released as relay-v1.5.1, 2026-11-19**: the code was right and the fix was the release. The pinned `daal-relay-mgmt` serves all three; `PinnedMgmtServesOptInFamilies` and `RELEASED_RELAY_SERVES_EXTRA_FAMILIES` are true, which unlocks the wizard's switches and `provision --families` (FAM-2, FAM-3). Not run on a rented relay or a phone | at relay-v1.5.0: `./run.sh clean` (pinned) vs `./run.sh --mgmt=tree clean` | world release.all-families (full) all green on the pinned box, 7 families — it downloads through the real verifier, so a wrong hash or signature fails it too; unit `TestPinnedMgmtOptInGateMatchesThePin` (publisher/deploy/cloudinit) |
| F-005 | **high** (the app; code-reading) | The app signed a relay BEFORE it had the relay's connection material: `bind-and-sign` could commit a route only to what the OperatorRecord carries, and the wizard passed nothing else | **fixed — released as relay-v1.5.1, 2026-11-19**: the relay states its public identity over the management plane (`GET /identity`, read-only, authenticated); the wizard asks before every signature (`daal-deploy relay-identity` → `bind-and-sign --relay-identity`) on every provider, remembers what the pack commits to, and signs again when a later reply disagrees (the first recipient on a relay that serves shadowsocks; a disguise change; a rebuild). The pinned daemon serves `/identity`; the fallback is left for a relay too old to answer, and none is in service. *The desktop app itself was still not run: the wizard is proven against its fake relay in cargo tests, and the order of operations against a real daemon by the rig through the CLI* | at `062f809`: `daal-deploy bind-and-sign` on a record with no `reality_public_key`/`tls_cert_sha256` → exit 1 | `mint verb.relay-identity.before-first-recipient`, `verb.bind-and-sign.before-first-recipient`, `bind-and-sign.before-first-recipient.only_pending_families_uncommitted`, `resign.after-first-recipient`, then every `family/*` session of the world (the pack that connects was signed that way) — on tree worlds and, since the pin moved, on the three pinned worlds; `a_relay_whose_record_has_no_keys_is_signed_from_what_the_relay_says`, `the_first_recipient_makes_the_wizard_sign_again_so_shadowsocks_is_committed`, `an_older_relay_with_an_empty_record_is_learned_from_its_first_reply` (daal-wizard); `TestBindAndSign_RelayIdentity_SignsARecordThatKnowsNothing` (publisher/deploy/cli); `TestIdentity_BeforeAnyRecipient` (cmd/daal-relay-mgmt) |
| REL-1 | **high** (was release-blocking) | This tree could not manage a relay built from the then-PINNED release, relay-v1.5.0: the publisher mints token format v2 (the request is signed — LC-1's full fix) and that `daal-relay-mgmt` only understands v1, so every authenticated verb was 401; since BOOT-1's fix such a relay stopped one phase sooner, at `provision` (its health binary cannot authenticate the management fingerprint) | **fixed — released as relay-v1.5.1, 2026-11-19**: the pin moved to a daemon and a health binary built from this tree, byte-identical to the candidate the rig proved (`tools/release/relay-v1.5.1.sh`). The one release also carries F-002, LC-1, INT-2, INT-O1, FAM-4 and TW-11. There is still, deliberately, no compatibility path: a publisher from this tree cannot manage a relay-v1.5.0 box (a publisher that would sign less for an older relay is the downgrade); none is in service | at relay-v1.5.0: `./run.sh clean @default` (pinned) → `mint verb.users-provision.r1 got=fail` — `401: unauthorized: malformed token (need nonce:ts:op:sig)` | the three pinned worlds are green — quick: `release`; full: also `release.lifecycle`, `release.all-families` (`./daal e2e full` → `PASS — 5388 checks`, 18 worlds). It was never excused: a pinned world that stops before a client session is an unexpected red and `./daal e2e` exits 1 |
| SW-0 | **high** (user-visible; found on a phone, not by the rig) | After one route switch the tunnel carried traffic while the app said "No route selected" and every store-backed screen failed: the engine closed the old TUN's fd twice (once on `engine_set_tun_fd`, again when the old sing-box instance was torn down), and the second close hit whatever file had been given the freed number in between. Same pair of closes on every disconnect | **fixed** in `core/engine/platform.go`, `platform_singbox.go`, `core/abi/tun_fd.go`: one owner per copy, every instance reads a duplicate of its own | build `wb-client` with those two files as they were at `8d47a82` (section below), `./run.sh --mgmt=tree --ops switch clean vless-reality hysteria2` → `rotate.*.fds_intact` and `*.disconnect.fds_intact` fail: "closed underneath them and the number reused" | rig: ops `switch` (quick) and `switch-all` (full) — `fds_intact`, `store_survives`, `active_route`, `session.fd_trap_armed`; unit: `core/engine/tunfd_singbox_test.go` |

### Found in review, not by the rig — repaired 2026-11-19 (9, and BOOT-1 above)

No rig check went red for any of these: they were found by reading the
change, reproduced with a unit test first, then fixed. Each test named
here fails without its fix. None has a `known-findings.json` entry.

| id | severity | one line | status | reproduce (before the fix) | pinned by |
|---|---|---|---|---|---|
| REV-1 | **high** (user-visible, Android) | The VPN service calls `engine_clear_route` right after a start that did not come up and again from `onDestroy`; that call reset `route_check`, `connect_refused` and the posture before the page's first poll, so every failed or refused connect on a phone ended on a silent "Press to connect." | **fixed** in `core/abi/abi.go`: `ClearRoute` erases only what it stops — with nothing running and no check in flight the last connect's verdict stays (spec `engine-abi-v1.md`). Not seen on a phone | replay the service's call sequence against `core/abi`: `route_check = ""` after the teardown | unit `TestClearRoute_KeepsTheVerdictOfAConnectThatAlreadyFailed`, `TestClearRoute_KeepsARefusalWhenNothingWasRunning`, `TestClearRoute_StillClearsWhatItStops` (core/abi) |
| REV-2 | medium (the app; silent) | One transient failure of the automatic re-sign latched for good: the relay's reply was marked handled before the signature existed, so later files were built from a pack known to disagree with the relay | **fixed** in `client-shell/tauri/daal-wizard/src/relay_identity.rs` (`heal_after_reply`): marked handled only after `resign_and_republish` returns Ok. Not run in a window | one identity-ask timeout, then a clean `produce_shared_sbp`: 1 signature where 2 were expected | `a_failed_automatic_resign_is_tried_again_on_the_next_reply` (daal-wizard, `cargo test`) |
| REV-3 | medium (privacy; on the relay) | The certificate `rotate-tls` re-issues listed EVERY global address the box held, including one bound after first boot: an unauthenticated TLS handshake to the old address disclosed the new one | **fixed** in `cmd/daal-relay-mgmt/tlscert.go`: the re-issued certificate names the addresses the old one named and no others (spec `daal-relay-mgmt-v1.md` §4.2). Released as relay-v1.5.1 (2026-11-19) | handshake with no credentials, read the IP SANs: `[203.0.113.10 203.0.113.77]` | unit `TestRotateTLS_ReissuedCertificateDoesNotNameALaterBoundAddress`; rig `op:l2 box.certificate_follows_cover_host`, `op:l3/naive no-new-file.after-l2.address-blocked.*` still green |
| REV-4 | medium (user-visible; regression) | Network page: a connect refused while ANOTHER route was connected showed nothing at all (the banner needed "nothing active") | **fixed** in `client-ui/src/d2pages/NetworkPage.tsx` + `lib/routeCheck.ts` (`refusedToShow`): a tap on this page always gets its sentence. Traced, not driven | code reading; the helper's old condition | vitest `refusedToShow` (3 cases) in `lib/routeCheck.test.ts` |
| REV-5 | medium (user-visible) | Network page: a failed connection check was reported as the shell's raw `engine call returned -1` | **fixed** — `connectFailedKey`: the Connection page's sentence by the same category rule, or "Could not connect. Try again, or try another route." (en+fa) | code reading (`daal-desktop-core/src/errors.rs:11` is the text) | vitest `connectFailedKey` (4 cases, one reads the page source for the raw error) |
| REV-6 | medium (user-visible) | "Try again in a moment" had no button that tries again: in the error state the main button said Connect and opened the recovery sheet, which has no retry, and neither `path_too_slow` nor `relay_no_egress` ever clears | **fixed** in `lib/routeCheck.ts` (`tapAction`, `retryableFailure`): for those two categories the main button connects the same route again | the new test against the old `tapAction`: `expected 'recovery' to be 'connect'` | vitest "a failed connect the engine does not rest can be retried" |
| REV-7 | low (security, defence in depth; on the relay) | A management token was not bound to the relay it was minted for: two relays under one publisher key both honoured the same token and body | **fixed** — signing input line 2 is the SHA-256 of that relay's management certificate (still format v2; the wire token is unchanged). Released as relay-v1.5.1 (2026-11-19) | two daemons, one publisher key, one `users-revoke` token: 200 from both | unit `TestTokenIsBoundToTheRelay`, `TestTokenAudienceIsTheServedCertificate` (daemon), the shared fixture under `publisher/deploy/mgmt/testdata/`; rig `op:mgmtauth` |
| REV-8 | low (fingerprint) | The bare TCP reach check ran on every timed-out attempt, not only when the timeout hides its phase: one payload-less connect-and-close to the relay's port per failed proof, every 30 s on a failed route | **fixed** in `core/engine/proof_singbox.go` (`timeoutPhaseIsUnknown` gates it) | counting hop in front of an in-process relay: "2 of 4 connections to the relay's port carried nothing" | unit `TestProveSubject_CarryTimeoutMakesNoBareConnectToTheRelay` (`-tags singbox`) |
| REV-9 | low (security, defence in depth; on the relay) | Request binding ignored the query string (`/users/list?name=…` rode a token for `/users/list`; `POST /users/revoke?name=r2` changed the config), and three token field checks were held by no test | **fixed** in `cmd/daal-relay-mgmt/main.go` (`requireAuth`): any query string, even a bare `?`, is 400 before the token is read. Released as relay-v1.5.1 (2026-11-19) | the requests above: 200 | unit `TestQueryStringIsRefused`, `TestTokenFieldChecksHold` (each check proven by mutation in a scratch copy) |

### Open — need a decision, a release or a dependency fix (7 rows; open: CEN-4, AUTO-1, AUTO-2, SW-3, ADD-1)

| id | severity | one line | status | reproduce | pinned by |
|---|---|---|---|---|---|
| CEN-4 | medium | One route cannot tell apart what needs two observations: a route connected BY HAND that is silent on UDP is `udp_no_reply` (network-wide UDP loss, a QUIC-only filter, a dead address, a dead port), and a reset after the ClientHello is `tls_sni_or_cert_block_suspected` whether the filter is keyed on the name or on the address. **Narrowed 2026-11-19 by the automatic connect:** a pass that tries a second route to the same address now says `refined: relay_unreachable` (the address does not answer TCP either) or `refined: udp_blocked_here` (it does) — dead address vs UDP stopped is decided. Still one answer: all UDP dropped, a QUIC-only filter and one dead UDP port (all `udp_blocked_here`); name-keyed vs address-keyed reset (needs two names on one address AND port; today's packs have none) | open — narrowed. What is left needs an observation outside the routes (a non-QUIC datagram to the same endpoint; a second name), which is the prober's job. What the engine says is true and cools down only the one route | `./run.sh --mgmt=tree relay-ip-block hysteria2` → `engine.category expect=udp_address_blocked got=udp_no_reply`; `./run.sh --mgmt=tree tcp-reset-mid-handshake vless-reality` → `expect=tcp_reset got=tls_sni_or_cert_block_suspected`; `./run.sh --mgmt=tree --ops auto clean vless-reality hysteria2` → `quic-only.connect.refined expect=quic_blocked_here got=udp_blocked_here` (and, green: `memory.udp.refined`, `all-blocked.connect.refined`) | known-findings.json `CEN-4` (family phase: 11 UDP + 3 reset in full; `op:auto quic-only.connect.refined`); the report's ENGINE CATEGORY line lists each truth → reported pair |
| SW-2 | **high** (user-visible on a TUN kept across a switch; a leak otherwise) | The engine never stops the packet reader of a sing-box instance it closes. On a TUN that is REPLACED at a switch that reader sleeps for ever, holding the old interface open. On a TUN that is KEPT across a switch (what the Android service does since the phone pass) it wakes for every packet and takes about half of them away from the new instance: most new connections are reset or refused, for good, while the engine says Connected | **fixed 2026-11-19** — a dependency defect (sing-tun 0.8.9, `LinkEndpointFilter.Attach` never passed the "detach" on). The engine now builds against `third_party/sing-tun` (0.8.9 + that one line, via `replace` in every module that links it; `third_party/DAAL-PATCH.md`); pinned by `core/engine/singtun_detach_singbox_test.go` | `./run.sh --mgmt=tree --ops switch clean vless-reality hysteria2` → `keep.vless-reality>hysteria2.tunnel expect=pass got=blocked` and `rotate.session.old_tuns_released got=held` | `keep.*.tunnel` and `*.session.old_tuns_released` are ordinary green checks now: a regression is an unexpected red |
| SW-1 | low-to-medium | A switch to a route that turns out to carry nothing ended with NOTHING connected: `engine_set_route(B)` stops the connected route A before it has learned whether B works | **fixed 2026-11-19** (engine) — when B carries nothing the engine reconnects A, re-proves it, returns the error for B and records `switch_back` in the diagnostics. There is still a gap of B's check plus A's reconnect; nothing is left disconnected | `./run.sh --mgmt=tree --ops switch clean vless-reality hysteria2` → `check-rotate.unreachable.vless-reality>hysteria2.old_route_still_connected`, `.switch_back_recorded`, `.tunnel`, `.wire` green with the host doing nothing after the failed call | those four checks (quick and full); unit `TestSetRoute_FailedSwitchGoesBackToTheRouteThatWasCarrying` (core/abi). known-findings.json entry deleted |
| AUTO-1 | low | A border that forwards nothing at all read as ONE relay not answering: the automatic connect sees only its own routes, all to one address, so under `total-blackout` its verdict was `relay_unreachable` and never `network_down` | **narrowed 2026-11-19, open** — fixed for a host that reports NO network (`engine_network_facts` kind `none` turns a pass in which nothing answered into `network_down`; no traffic is added). A link that is up and merely not validated (what Android says under `total-blackout`), and a host that says nothing, still get `relay_unreachable`: validated 0 is also what a network that filters the platform's own check gives, and is not taken for "no internet" — section AUTO-1 | before: `./run.sh --mgmt=tree --ops auto total-blackout vless-reality hysteria2` → `scenario.connect.verdict expect=network_down got=relay_unreachable` | known-findings.json `AUTO-1` (1 check, full): `op:auto scenario.connect.verdict` under `total-blackout` (red, known: `relay_unreachable`) beside `scenario-untold.connect.verdict`; `op:auto-deep networks.down.verdict` (kind `none`: `network_down`) beside `networks.unvalidated.verdict` and `networks.dead-relay.verdict` (`relay_unreachable`); engine `TestNetworkFacts_NothingAnswered…` |
| AUTO-2 | low | A route whose address answers nothing costs a pass TWO attempt budgets (8 s), not the one (4 s) the automatic connect is meant to stop at (`StopAtUnreachedRelay`, backlog AC-30): a timed-out connect does not say which phase it died in, the reach check that settles it runs beside the second attempt, and the stop is only looked at between attempts. Two silent routes checked together are done in 8.3 s — half of the 16 s they cost one after the other, and twice the 4.5 s the stated budget gives | open — the engine's (core/engine/proof.go, proof_singbox.go); needs the first attempt's phase settled before the second is started | `./run.sh --mgmt=tree --ops auto clean vless-reality hysteria2` → `race.connect.a_silent_address_costs_one_attempt expect=pass got=fail` (`auto_ms` ≈ 8300; the censor's log shows two connections to each dropped endpoint, 4 s apart) | known-findings.json `AUTO-2` (1 check, quick and full); `race.connect.faster_than_one_after_another` (green) holds the half that works |
| ADD-1 | medium (add-ons: standby key through the Google channel) | The Google update channel refuses the standby key in the form the publisher holds it: `standby promote` prints it grouped with spaces (`bundle.StandbyKeyBytes.Text()`, the form shown to people), and `appsscript.Build` (`appsscript-check --standby-key-file`, `publish-freshness --appsscript-standby-key-file`) accepts only the 26 symbols run together: "standby key must be 26 Crockford base32 symbols" | open — `publisher/deploy/freshness/backends/appsscript/container.go` should read the key with `bundle.ParseStandbyKeyText` (spaces and '-' ignored, as the engine's own `StandbyKey` does) and carry the canonical form; no wave-2 lane owns that file | `./run.sh --mgmt=tree --ops standby-google clean vless-reality` → `google.standby_key_as_printed_accepted expect=pass got=fail`; with the key's spaces removed the same channel carries it and the phone reconnects on the standby (`found_the_new_address_through_google` green) | known-findings.json `ADD-1` (1 check, addons and full) |
| SW-3 | low | Every connect that had the TUN leaves one open file behind for the life of the process: the stop eventfd of gVisor's fd endpoint (`pkg/tcpip/link/stopfd`), which nothing closes when the instance is closed. One per connect, per switch, per move the engine makes by itself | open — a dependency's (gVisor as sing-tun uses it); the engine could close it where it closes the instance. Not a side instance's: those hold no TUN and leave nothing | `./e2e.sh full --only auto-deep` → `leak-stopped.cycle.a_connect_and_a_disconnect_leave_nothing expect=pass got=fail` (`[eventfd]` 5 → 6 across one connect by hand and disconnect) | known-findings.json `SW-3` (1 check, full) |

### Observations (no verdict; recorded so the day they change is visible)

| id | one line | where to see it |
|---|---|---|
| AUTO-O1 | The move from a route that stopped carrying is driven by the engine's own clock and by nothing on the host: one liveness check every 180 s ±25 % (30 s while failed). The rig sets 3 s for the fall-over phone and so proves THAT the engine moves by itself in the same TUN, not how soon a phone would | `op:auto fall-over.moved.*` (`waited_ms`, `liveness_interval_s` in the evidence); section AUTO-0 |
| AUTO-O2 | `udp_blocked_here` means "UDP to this relay was silent while TCP to the same address was answered" — it is also what a QUIC-only filter and a dead UDP port give (CEN-4). The sentence a person reads for it must not promise more than that | `op:auto quic-only.connect.refined` (red, known) beside `memory.udp.refined` (green) |
| AUTO-O3 | What "two routes in flight" means at the censor: the number of relay endpoints with a new connection between its first and its LAST packet. A dropped attempt's end is its last retransmission, up to a second before the engine gives up, so a third route started in that last second would not be seen; three started together would. The engine's own `auto.racing` (never more than two ids) is asserted beside it | `at_most_two_routes_in_flight` on every press of ops `auto` and `auto-deep` (`censor_saw`, `engine_racing_seen` in the evidence); `driver/flowtap.go` |
| AUTO-O4 | After a move for speed the engine has TWO reasons not to move again — the hold (30 min) and the back-off after any speed probe (15 min) — and the rig, which watches for 30 s with a third route free, cannot tell which one held. That it stays, and opens no connection to any other endpoint, is what is proved | `op:auto-deep speed.hold.stays_after_a_move_for_speed`; the two timers one by one: engine `TestSpeed_*` |
| AUTO-O5 | `network_down` is given on the host's word alone when nothing answered — and only on the word "no network at all" (kind `none`). Validated 0 was enough when this was first built; the repair pass took it out: a network whose filter also stops the platform's own connectivity check is never validated, and on it a dead relay read "this phone has no internet". The price is AUTO-1 staying open for a blackout with the link up | `op:auto-deep networks.unvalidated.verdict` (validated 0, the relay null-routed, the internet in fact there: `relay_unreachable`) beside `networks.down.verdict` (kind `none`) |
| AUTO-O6 | A route side-probed in the last 3 minutes is not side-probed again, so a second press soon after a first goes one route at a time: after a cancelled pair, or a pass in which everything was silent, the next press costs the full sum (29 s for four dead routes, where the first cost 21 s) | `op:auto all-blocked.connect` (`auto_ms`, after `all-blocked.cancel`) beside `relay-ip-block` `scenario.connect` |
| O-1 | The protect callback the phone registers is never called; only the uid exclusion keeps the engine out of its own TUN | `engine_protect_calls` in every `control.after` |
| O-2 | **Fixed in the tree.** Disconnect blocked ~5 s when the relay was blackholed (vless-reality, websocket-tls): closing sing-box waited out a dial already in flight. The instance's context is now cancelled before it is closed, and a connection check in flight is abandoned, not waited for | unit `TestCloseInstance_DoesNotWaitForADialToADeadRelay` (core/engine, `-tags singbox`), `TestClearRoute_DoesNotWaitForAConnectionCheck` (core/abi). The rig no longer reaches the old state: a blackholed route never becomes connected |
| O-3 | Backlog W5-1, **fixed with FAM-4, released as relay-v1.5.1 (2026-11-19)**: a default relay no longer binds `ss-in`/`anytls-in`. Only on a relay provisioned fresh from this release (the family set is written by cloud-init); none older is in service | `listener_on_box` in `mint/* not_served` — `false` on `--mgmt=tree` worlds; the pinned daemon is now the same code |
| O-4 | The three opt-in families connect with the experimental-families gate OFF | every session of anytls, shadowsocks, tuic |
| LC-O1 | `rotate-tls` said every recipient needs a new pack; only vless-reality stops working — **fixed**: the verb, the wizard and the screen now say who, if anyone, needs a new file | `op:l2 old-pack.tunnel` per family; `op:l2 rotate-tls.does_not_claim_everyone_needs_a_file` |
| LC-O2 | **Fixed** (publisher side; the v2 token it signs is what relay-v1.5.1, released 2026-11-19, accepts). `/whoami` had a handler and no caller that could authenticate to it (`MintToken` refused the op). The op is now in the minter's route table and `mgmt.Client.WhoAmI` calls it; nothing above the client uses it yet | unit `TestClient_WhoAmI_AuthenticatesAndReadsTheAddress`, `_OlderBoxIsNotAFailureOfAnythingElse`, `TestToken_EveryOpHasOneRoute` (publisher/deploy/mgmt); `TestTokenIsBoundToTheRequest` (the GET it is signed for) |
| LC-O3 | The first freshness poll after an import always downloads the whole pack | `op:freshness` evidence |
| LC-O4 | L1, L2, L3, revoke and multi-recipient all work end to end on the pinned release artefacts (default families; relay-v1.5.0 when first recorded, relay-v1.5.1 since 2026-11-19) | world release.lifecycle (full) |
| INT-O1 | **Fixed; released as relay-v1.5.1 (2026-11-19).** The kick wrapper's `SIGUSR2` ("graceful inbound drop") was a no-op — sing-box 1.13.12 registers handlers for INT, TERM and HUP only — so every kick was `sleep 2` + a full restart, and `users-revoke` / `rotate-credentials` kicked twice (~4.7 s, two restarts). Now one in-process reload (SIGHUP via `ExecReload`, verified in `cmd/sing-box/cmd_run.go`): the verbs take ~0.1 s and the relay's sing-box pid does not change. The `ExecReload` line is in the unit cloud-init writes, so only a relay provisioned fresh from this release reloads this way; none older is in service | relay `sing-box.service.lifecycle.log` (one `start`, no restarts); `ms` of the verbs in `publisher-verbs.jsonl`; unit `TestUsersRevoke_RemovesAndReloadsExactlyOnce`, `TestRotateCreds_ReloadsExactlyOnce`, `TestRenderV2_ApplyWrapperIsOneReloadAndNoSleep` |
| CEN-O1 | The relay's shadowsocks and anytls ports answer a few opaque bytes with a TCP reset within a millisecond; naive and websocket-tls wait, REALITY forwards — an active-probing tell. **Root-caused in sing-box 1.13.12's source: no configuration changes it** (it needs upstream code; recorded, not forked). Both families stay `probing_risk_class: moderate`, and `docs/transport-family-inventory.md` carries the tell for the recommender | section below |
| CEN-O2 | Only vless-reality puts a name on the wire; its ClientHello is 600 bytes in one TCP segment, so even a first-packet-only SNI filter reads it | scenarios sni-rst, sni-rst-stateless |
| CEN-O3 | Under 30% random loss the QUIC families still complete the fetch (7–11 s) and every TCP family fails it | scenario heavy-loss |
| CEN-O4 | naive's first request can end in `EOF` after ~0.5 s on a lossy or slow path, where the other families retry and get through — not root-caused | section below |
| CEN-O5 | **fixed (TCP families; see the section).** On a link that already has seconds of queue the connection proof (2 × 4 s) finished nothing, and the engine said what it says for a swallowed handshake: "could not connect", `tls_handshake_failed` or `unknown`, a cooldown. The engine now tells a path it saw moving from one that is silent and gives it one long attempt: connected and slow, or failed as `path_too_slow` with no cooldown. Scenario `deep-queue` | section below (under CEN-6) |

---

## BOOT-1 — the pin every relay reply is believed on was learned over plain HTTP (fixed; released 2026-11-19 as relay-v1.5.1)

**Released 2026-11-19.** The `daal-relay-health` half is in relay-v1.5.1
(`407581d6…d055`), which `publisher/deploy/cloudinit/artifacts.go` now
pins. Proof: the three pinned worlds (`release`, `release.lifecycle`,
`release.all-families`) provision through the authenticated bootstrap and
are green — `./daal e2e full` → `PASS — 5388 checks`, 18 worlds. Not yet
done against a rented relay.

**What.** `mgmt.Client` believes a relay's replies because the TLS session
is pinned to `OperatorRecord.MgmtTLSFingerprint`. All three provider
adapters learned that fingerprint from `daal-relay-health` —
`GET http://<box>:9876/healthz/<token>`, no integrity, the token in the
URL. A machine between the publisher and the new VPS during the
provisioning window (which is where a censor is) rewrote one field. From
then on it terminated the "pinned" session itself, forwarded the
publisher's request-bound token to the real box unchanged (the token
protects requests, not replies) and edited what came back: `GET /identity`
returned the attacker's REALITY key with no error, the publisher signed
it, and — because the wizard re-signs and republishes by itself when a
relay's stated keys differ from the signed ones — it could do that at any
later time too. `users-provision` replies (recipient credentials) were
readable the same way. Found in review, not by the rig; reproduced with
the production `Poller`.

**The fix.** The health token already travels where the path cannot see
it: in cloud-init user-data, over the cloud provider's HTTPS API. It is no
longer sent anywhere. The URL carries `HMAC(token, "daal-health-path-v1")`;
the box returns the fingerprint with
`HMAC(HMAC(token, "daal-mgmt-fpr-v1"), fingerprint)`; the poller refuses a
fingerprint whose MAC does not verify, inside `Poller.poll`, so no adapter
can be handed one (spec `daal-relay-mgmt-v1.md` §2.1). And independently,
the wizard no longer signs on a relay's say-so alone: a relay that has not
been rebuilt (same management certificate) and states a different REALITY
key or TLS pin than the active pack commits to is refused with
`E_RELAY_KEYS_CHANGED` — nothing signed, no note published.

**No fallback, so it rode the release.** The `daal-relay-health` of
relay-v1.5.0 answers the derived path with 404 and has no MAC to give.
Against such a box — the pinned one until 2026-11-19 — the publisher
stops ten seconds after the box comes up:

```
./run.sh clean vless-reality       (pinned = relay-v1.5.0, before the pin moved)
  FAIL provision  verb.provision  expect=pass got=fail
       hetzner: health: the relay's health endpoint does not recognise this provisioning secret (status 404) — its software may predate the authenticated bootstrap
```

So until the pin moved every pinned world stopped at `provision` instead
of at REL-1's `mint`; same exit status, same reason it was not excused
(see REL-1). The release was built after this fix (the candidate staged
before it was re-staged with `tools/release/relay-v1.5.1.sh`), and the
pinned worlds now provision. `--mgmt=tree` runs the tree's
`daal-relay-health` as well as its `daal-relay-mgmt`, so the tree worlds
exercise both halves too.

**Not closed here.** (1) The Hetzner adapter still reads `reality.pub` and
the TLS pin into the record over SSH with `InsecureIgnoreHostKey`; with a
relay that serves `GET /identity` those record values are outranked by
what the relay states over the (now authenticated) pin, but a record-only
signature — a relay too old for `/identity` — still rests on them. (2) On
the rebuild path that same SSH session authenticates with the root
password Hetzner returned, to a host key nobody checks. (3) No rig world
puts an attacker between the publisher and the relay.

## REL-1 — this tree could not manage a relay built from the then-pinned release, relay-v1.5.0 (released 2026-11-19 as relay-v1.5.1)

**Fixed 2026-11-19: the release happened and the pin moved.** GitHub
releases `relay-v1.5.1` and `relay-v1.5.1-mirror` carry sing-box 1.13.12
(`989e8486…06ea2`), `daal-relay-health` (`407581d6…d055`) and
`daal-relay-mgmt` (`4f13e453…f9de`), byte-identical to the candidate the
rig proved; `publisher/deploy/cloudinit/artifacts.go` pins them. Proof:
`./daal e2e full` → `PASS — 5388 checks`, 18 worlds, with `release`,
`release.lifecycle` and `release.all-families` — the pinned worlds — all
green. Not yet run on a rented relay or a phone. What is left of the
finding is deliberate: a publisher from this tree cannot manage a
relay-v1.5.0 box, and no such relay is in service. The rest of this
section is the finding as it stood before the release; "pinned" in it
means relay-v1.5.0.

**What.** LC-1's full fix changed the management token on both ends
(format v2: the signature covers the method, the path and the body's
digest; spec `daal-relay-mgmt-v1.md` §3). The publisher in this tree mints
v2 and nothing else. The `daal-relay-mgmt` then pinned in
`publisher/deploy/cloudinit/artifacts.go` (relay-v1.5.0, `e8cb16e8…`) was
built before that and accepts v1 only. So a relay provisioned from this
tree with that pin booted, passed health — and refused every
authenticated call:

```
./run.sh clean @default            (pinned)
  FAIL mint  verb.users-provision.r1  expect=pass got=fail
       users/provision: mgmt: users/provision 401: unauthorized: malformed token (need nonce:ts:op:sig)
```

**Why there is no compatibility path.** A publisher that signs less when
the relay says it is old is a downgrade waiting for somebody to ask for
it, and nothing is fielded that would need it. The daemon side is the
same: the tree daemon refuses v1 from anybody (`TestV1TokenIsRefused`,
rig `op:mgmtauth v1_token`).

**Severity: high, and it was release-blocking — nothing built from this
tree could ship before the relay re-release.** It was the same release
F-002, LC-1, INT-2, INT-O1, FAM-4 and TW-11 waited for; this made it
mandatory rather than merely overdue.

**What the rig said until the pin moved.** Every world on the pinned
box (`release` in quick; `release.lifecycle`, `release.all-families` in
full) stopped early — at `mint` for this reason, and since BOOT-1's fix
one phase sooner, at `provision` — reported `STOPPED EARLY` with that one
check UNEXPECTED — so `./daal e2e` exited 1, and the pre-push hook failed,
until the pin bump. That was on purpose and was never excused in
known-findings.json: an entry there was tried and the matrix answered
`BROKEN — the world never reached a client session` (exit 2, no verdict),
which is the rig refusing to let one excuse stand in for a whole world.
The red check was the true state: this tree and relay-v1.5.0 do not work
together. The tree worlds (`--mgmt=tree`: 14 of quick's 15, 15 of full's
18) were unaffected.

**The candidate was built and proven before anything was uploaded.**
`tools/release/relay-v1.5.1.sh`
(no `--upload`) stages it under `dist-release/relay-v1.5.1/`; the build is
reproducible (same hashes and signatures from a copy of the tree at
another path, same toolchain — go1.26.8; the toolchain is recorded in
`toolchain.txt` because the hash depends on it). With the pin bump applied
to a scratch copy of the tree (every edit the script prints), the box
verified the candidate against the real pins and signature and
`./run.sh clean` — world `release.all-families` — was all green, 7
families × every column (2026-11-18; again on 2026-11-19 after the
candidate was re-staged for BOOT-1 — `PASS — 5388 checks`, twice).
Nothing had been uploaded at that point; the same bytes were published on
2026-11-19. The tag moved to `relay-v1.5.1` because the artefact file names do not change:
new bytes under an already-pinned URL would break the builds that pin the
old hash and let a cache answer the new pin with the old bytes.

**What fixed it:** the pin bump (`tools/release/README.md`, "The pin
bump"; `tools/release/pin-bump.py` does the mechanical part), done
2026-11-19. It closed F-002, LC-1, INT-2 and F-005 on released relays
with it, and their known-findings entries are deleted.

---

## F-002 — the pinned mgmt artefact predated Wave 5; three families were unprovisionable from main (released 2026-11-19 as relay-v1.5.1)

**Fixed 2026-11-19 by the release.** relay-v1.5.1 is published and
pinned; its `daal-relay-mgmt` (`4f13e453…f9de`) is built from this tree
and serves shadowsocks, anytls and tuic. `PinnedMgmtServesOptInFamilies`
and `RELEASED_RELAY_SERVES_EXTRA_FAMILIES` are true. Proof: world
`release.all-families` — `./run.sh clean` with no `--mgmt=tree`, through
the real verifier — is green on all seven families (`./daal e2e full` →
`PASS — 5388 checks`, 18 worlds), and the `F-002` entry is deleted from
`known-findings.json`. Not yet run on a rented relay or a phone. What
follows is the finding as it stood before the release; "pinned" in it
means relay-v1.5.0.

**What.** `publisher/deploy/cloudinit/artifacts.go` pinned
`daal-relay-mgmt-0.1.0-linux-amd64` at SHA-256 `e8cb16e8…65df66b` (the file
was last changed 2026-08-18 09:14). The mgmt-side support for shadowsocks,
anytls and tuic users landed in `a656a27` ("Wave 5: every family a
self-hosted relay can actually serve", 2026-08-18 15:30) and the pin was not
moved. A build of today's tree with the release flags hashes to
`f11cf36a…38bc5dcc`.

So every relay provisioned from `main` downloaded a mgmt daemon that:

* never creates `ss-in` / `anytls-in` (nothing listens on 8446/tcp, 8447/tcp
  even though both firewalls open them),
* returns no `ss_password` / `anytls_password` / `tuic_uuid` from
  `/users/provision` (tuic's inbound exists — cloud-init renders it — but
  has no users).

`users-provision` and `users-pack-sbp` both **exit 0** and print warnings;
the pack is minted with those three routes replaced by an unavailable
marker (see F-003). The product's own warning text names the cause exactly
("the relay's daal-relay-mgmt binary predates the family: rebuild, re-sign,
re-upload, bump the hash pin … and provision a FRESH relay"). This is the
"binary pin" staleness layer; Wave 5's three families have never been
deployable.

**The code is right.** With the tree's mgmt daemon on the same box all six
dialable families carry verified TCP and UDP, survive revocation of another
recipient, refuse a revoked one and refuse forged credentials — the first
bytes shadowsocks-2022, anytls and tuic have carried in this project.

**Reproduce.**

```
./run.sh clean                 # pinned (relay-v1.5.0): 3 families red
./run.sh --mgmt=tree clean     # tree build of cmd/daal-relay-mgmt: all green
```

Pinned run, relevant lines:

```
FAIL mint   users-provision.r1.no_warnings  — warning: this relay offers "shadowsocks" but reported no credential for it …
FAIL mint   pack.r1.no_dropped_routes       — warning: route r5 (shadowsocks) is NOT connectable in this pack and was dropped …
FAIL mint/anytls       relay.listens        — nothing listening on 8447/tcp in the relay namespace
FAIL mint/shadowsocks  relay.listens        — nothing listening on 8446/tcp in the relay namespace
FAIL family/anytls|shadowsocks|tuic tunnel  expect=pass got=refused — engine: option parse: outbounds[0]: unknown outbound type:
```

**The fix was a release, not a code change** (done 2026-11-19): rebuilt
with `tools/release/relay-v1.5.1.sh` (the tag moved: see REL-1), signed with the release
key, uploaded, `Sha256` + `SigHex` bumped in `artifacts.go` **and, with the
same change, `PinnedMgmtServesOptInFamilies` (same file) and its mirror
`RELEASED_RELAY_SERVES_EXTRA_FAMILIES` (`client-ui/src/publisher/
extraFamilies.ts`) set to `true`** — that is what unlocked the wizard's
"More ways to connect" switches and turned `provision --families`' "will
be asked to serve" back into "will serve" (FAM-2, FAM-3). `go test
./deploy/cloudinit/` fails on a bump without the flip and on a flip
without a bump.
`./run.sh clean` (no flag) is the acceptance test: it downloads through the
real verifier, so a wrong hash or signature fails it too.

`./daal e2e full` before a tag is in the release runbook
(`docs/release-runbook.md`). Its world `release.all-families` is exactly
`./run.sh clean` without `--mgmt=tree`; it is green since the release,
and the `F-002` entry is deleted from `known-findings.json`.

---

## F-004 — pack profiles were outside the signature; the server address could be rewritten by anyone (fixed)

**What.** `VerifyBundle` authenticates `manifest.json` (via `manifest.sig`)
and, per route, only that `config_path` exists in the archive.
`profiles/<id>.json` — the sing-box outbound: **server address, port,
credentials, TLS pins, REALITY public key** — is covered by nothing. That is
how `users-pack-sbp` / `users-pack-sbpx` rewrite profiles after signing
without the publisher key (`publisher/deploy/relaypack/client_pack.go`
states this as the design, and says "the per-recipient .sbpx age envelope
provides the in-transit integrity").

Two problems with that:

1. The default artefact, the shared plain `.sbp`, has no envelope at all.
2. An age envelope addressed to a recipient's public key is confidentiality,
   not authentication: anyone who knows the recipient key can produce one.

**Why it matters.** Whoever can touch a pack in transit — and the channel it
is shared over is assumed hostile; that is the product's premise — can point
every route at a relay of their own choosing. The app shows the genuine
publisher's fingerprint words, the trust prompt is answered against the
genuine key, and the recipient's entire traffic goes to the attacker's
server. A rewritten `server` with otherwise-untouched credentials also hands
those credentials to that server on first connect.

**Reproduce.**

```
./run.sh --ops tamper clean vless-reality
```

`op:tamper` first proves the signature IS checked: it pushes
`bundle.expires_at` in `manifest.json` a thousand years out (a zip rewrite,
no key) and the importer must reject that (`bundle_signature_invalid`).
Then it rewrites `server` in every profile of r1's pack the same way and
imports the result into a fresh engine:

```
ok   op:tamper  manifest_rewrite_refused expect=refused got=refused  evidence: import=rejected, reason=bundle_signature_invalid
ok   op:tamper  rewrite                  expect=pass    got=pass     evidence: profiles_rewritten=4, keys_used=none
FAIL op:tamper  import_of_tampered_pack  expect=refused got=pass   — the engine imported a pack whose outbound servers were rewritten …
```

The import verdict is the ordinary first-seen trust prompt, with the
publisher's own fingerprint; the routes are listed and activatable.

**Fixed: "signed endpoint, local credential".** At bind-and-sign time the
relay exists, so everything about a route that is not a per-recipient
secret is known. `bind-and-sign` now writes, per route, an `_endpoint`
object into the route's `family_specific_config` — part of the signed
manifest: server address, port, the TLS name where it matters, the TLS key
pin (SPKI SHA-256), the REALITY public key, and for shadowsocks the method
and a digest of the box-wide key. The client refuses an outbound that
disagrees with it:

* at import (`bundle/go/importer/endpoint_plan.go`), for every path —
  file, trust prompt, freshness — with its own reason, `endpoint_mismatch`,
  **before** the trust prompt. A RelayPack outbound with no commitment at
  all is `endpoint_unauthenticated`;
* again at `SetRoute` (`core/abi/endpoint_guard.go`), against the
  commitment the import stored, so no other writer of a profile can make
  the engine dial an address nobody signed.

Credentials (uuid, passwords, short id, ws path) stay per-recipient and
unsigned. That is sound because the server and its key are pinned: a
rewritten credential is presented to the committed relay over a channel
authenticated by the committed key, so it can only be refused. It cannot
be sent anywhere else. `op:tamper credential_rewrite.*` shows exactly that
on the wire.

```
ok   op:tamper  manifest_rewrite_refused                        refused   bundle_signature_invalid
ok   op:tamper  import_of_tampered_pack                         refused   endpoint_mismatch (server)
ok   op:tamper  import_of_tampered_pack.port                    refused
ok   op:tamper  import_of_tampered_pack.tls_pin                 refused
ok   op:tamper  import_of_tampered_pack.reality_public_key      refused
ok   op:tamper  import_of_tampered_pack.trusted_certificate     refused   (naive's root)
ok   op:tamper  import_of_tampered_pack.tls_insecure            refused
ok   op:tamper  import_of_tampered_pack.folded_key              refused   (a second spelling of `server`)
ok   op:tamper  commitment_stripped.import                      refused   bundle_signature_invalid
ok   op:tamper  credential_rewrite.import                       pass      (not signed, by design)
ok   op:tamper  credential_rewrite.carries_nothing              blocked
ok   op:tamper  credential_rewrite.went_to_the_genuine_relay    pass
```

**A way round it, found in review and closed: a second spelling of a
member name.** The check read the outbound by exact member name; sing-box
matches a member to a field without regard to case, with Unicode simple
case folding (U+017F "ſ" is an `s`, U+212A "K" is a `k`), and the later of
two members that fold onto one field wins. The engine re-marshals a profile
with its keys in byte order, so a non-ASCII spelling always comes after the
genuine one. A pack that kept `"server"` exactly as signed and added
`"ſerver": "198.51.100.66"` (and `"public_Key"` in `tls.reality`, or
`"certificate_public_key_ſha256"` for the pinned families) passed both
gates — import and `SetRoute` — and the linked sing-box dialled the
attacker's address, authenticated by the attacker's key. Plain ASCII did
the same for members that must be absent: `"Insecure": true`,
`"Server_Ports"`, `"Detour"`. No key material needed; that is F-004 again.

Fixed at the cause, in `bundle.CheckOutbound` (so both gates and
`MergeEndpoint`'s result check): before any equality, every member name in
the outbound, its `tls` object and `tls.reality` must be plain lower-case
ASCII (`[a-z0-9_]+`), or the outbound does not match (`endpoint_mismatch`).
Nothing can then fold onto a checked field except the field's own name.
Spec: `relaypack-v1.md` §"Endpoint commitment", "Member names". Tests:
`TestCheckOutbound_RefusesFoldedKeySpellings` (bundle/go/bundle),
`TestImport_TamperedEndpointIsRefusedNotPrompted` (importer, four folded
cases), `TestFoldedProfileKeys_SingBoxReadsThem_TheEndpointCheckRefusesThem`
(core/engine, `-tags singbox`: shows the linked sing-box really reads the
second spelling, and that the check refuses it), and the rig row
`import_of_tampered_pack.folded_key`. Before the fix:
`./run.sh --mgmt=tree --ops tamper clean vless-reality` →
`import_of_tampered_pack.folded_key got=pass`.

**A pack with no commitments is refused, not flagged.** Nothing is fielded,
every fixture and test was migrated (`specs/test-vectors/relaypack/`
regenerated; `core/abi/testdata/` re-minted by
`mint-freshness-fixtures.sh`), and an "unauthenticated endpoint" state the
user may click through is the hole with a warning on it.

**What the publisher has to do differently.** `bind-and-sign` needs the
relay's connection material. The OperatorRecord carries the REALITY key
and the TLS pin when provisioning read them over SSH; otherwise — and
always for shadowsocks — pass any `users-provision` reply with
`--endpoint-creds` (only its relay-wide fields are read). A route whose
material is missing is signed WITHOUT an endpoint, reported on stderr and
in `uncommitted_families`, and can never be used; a pack in which no route
could be committed is not signed. `users-pack-sbp[x]` checks its own
output against the commitment and refuses to mint from a signed pack that
no longer describes the relay ("run bind-and-sign again"). **The app does
not pass `--endpoint-creds` yet** (`cli_bridge.rs`): a relay whose record
has the SSH-read fields is fine; one serving shadowsocks loses that route
until the bridge passes the flag.

**Residual, stated.**

* *Bundles that are not RelayPacks* (`daal-publish`, the bootstrap
  directory, a `.sbp` with no `relay_pack` slot) still carry profiles that
  nothing signs, and anybody handling the file can rewrite them (they are
  NOT "fixed at signing", as this section used to say). Such a bundle can
  no longer replace a committed route (F-006, below); the routes it adds
  under new ids are still unauthenticated. Closing that is a signed
  digest per route — a change to the base manifest and its
  cross-language fixtures — and was not made here.
* *shadowsocks* has no server authentication independent of the shared
  key. The commitment pins the address, port, method and a digest of the
  box-wide key, so a stranger cannot substitute one; somebody who is both a
  recipient of the same relay and on the path still can. That is the
  protocol.
* The stored commitment is as trustworthy as the device's own store.

---

## F-006 — a bundle with no commitments replaced committed routes (fixed)

**What.** `planRoutes` passed every profile of a bundle with no
`relay_pack` slot through unchecked; `SaveImport` then deleted the
route's stored commitment (the incoming route had none) and `UpsertRoute`
overwrote `relay_pack_id` with `''` — after which `routeEndpointGuard`
had nothing to hold the route to. Since `manifest.sig` does not cover
profile bytes, the attacker needs no key: one genuine, unexpired plain
bundle of the publisher naming the same route ids, profiles rewritten to
`{server: 198.51.100.66, tls.insecure: true}`. The publisher is already
trusted, so there was no prompt: `Imported`.

**Fixed.** A commitment is sticky (`endpoint_plan.go` rule 5). The
importer asks the store (`importer.CommittedRoutes`, implemented by
`trust.StoreAdapter.RouteCommitted`) whether the device holds a route
under that id that has a stored commitment or a `relay_pack_id` — in any
trust state, so an expired or revoked committed route is not an opening
— and refuses the whole import with `endpoint_downgrade`, before the
trust prompt and again before persistence. `SaveImport` makes the same
check itself, before its first write, so no other caller can do it
either. The app has copy for the new reason (en + fa).

```
ok   op:tamper  uncommitted_replacement.control.new_routes.import  expect=pass     got=pass
ok   op:tamper  uncommitted_replacement.import                     expect=refused  got=refused
ok   op:tamper  uncommitted_replacement.routes_kept                expect=pass     got=pass
```

**Residual, stated.**

* A plain bundle whose route ids are NEW to the device is still stored
  with unauthenticated profiles under the publisher's name (the control
  row above is exactly that). Only a signed per-route digest in the base
  manifest closes it.
* The only way out of a commitment is the user removing the route. A
  publisher who really wants to re-issue a route id as a plain route
  cannot.
* `routes_kept` compares the engine's route list, which does not show a
  route's pack id or profile; with the fix switched off it stayed green
  while `.import` went red. The unit tests are what pin "nothing changed".

---

## F-003 — "dropped" routes were still routes on the client (fixed)

**What.** When a credential is missing (F-002 is one way to get there),
`RewriteProfilesForRecipient` cannot remove the route — the manifest is
signed — so it replaces the profile with
`{"_daal_unavailable": {"family": …, "reason": …}}` and reports the route as
"NOT connectable … and was dropped". The comment says the missing `type`
"makes the route fail closed at set-route on the client".

It does fail closed. But `_daal_unavailable` is read by **nothing** outside
`client_pack.go` (no reference in any other `.go`, `.ts`, `.tsx`, `.rs` or
`.kt` file). On the client the route:

* is counted (`RouteCount: 7`) and listed by `AvailableRoutes()` with an
  ordinary `family_maturity`, indistinguishable from a working one;
* on `SetRoute` fails with `engine: option parse: outbounds[0]: unknown
  outbound type:` — which `SetRoute` then classifies and persists as a route
  *failure* (`pm.Failed` + `RecordFailure`), i.e. as if the network had
  blocked a working route.

So the recipient is offered tiers that can never work, and their failure
feeds the same health/cooldown bookkeeping real blocking does. The reason
string the publisher wrote for a human is never shown to one.

**Reproduce.** `./run.sh clean anytls` (pinned artefacts). Then
`out/latest/clients/*/events.jsonl`: the `routes` event lists r5–r7; the
`error` event carries the parse error. `unzip -p
out/latest/publisher/pack-r1.sbp profiles/r5.json` shows the marker.

**Fixed.** A RelayPack route whose profile holds no outbound — the
minter's `_daal_unavailable` marker, or the signed skeleton's metadata-only
profile — is not stored by the importer
(`bundle/go/importer/endpoint_plan.go`, rule 2). It is not in
`AvailableRoutes()`, it has no row for `SetRoute` to find, and it feeds no
health or cooldown bookkeeping. The import verdict lists it under
`Unavailable` with a closed reason (`not_offered`, `no_credentials`,
`needs_new_file`), and the app has plain-language copy for each
(`add.unavailable.*`, en + fa). The trust prompt's route count is the
number of routes that will actually be stored.

Pinned by `family/* import.unconnectable_not_listed`, which compares the
engine's route list with the pack in every session of every world (it can
only go red where a pack has a dropped route — today world
release.all-families, through F-002), and by
`TestImport_RoutesTheMinterDroppedAreNotStored` /
`TestDroppedRouteIsNeitherListedNorActivatable`.

*Not done:* the desktop/Android import screens do not yet render the
`Unavailable` list; the strings and the verdict field are there for them.

---

## F-005 — the app signs before it has what a signed endpoint needs (released 2026-11-19 as relay-v1.5.1)

**FIXED (truth wave, lane A).** Both halves of "What it takes" below were
built, because either alone leaves an ordering trap:

* **The relay says who it is.** `GET /identity` on the management plane
  (`specs/daal-relay-mgmt-v1.md` §4.9): REALITY public key, TLS key pin,
  cover host, the *digest* of the shadowsocks server key, served families
  and ports, and `pending_families` — the families whose key does not
  exist yet. Read-only, behind an `identity` token, on the pinned TLS
  session. `daal-deploy relay-identity` fetches it; `bind-and-sign
  --relay-identity` signs from it, and where the relay speaks it outranks
  the record. No SSH read and no recipient is needed, so it is the same
  on every provider.
* **The app signs again when the relay has moved.** The signer reports
  what the pack commits to (`committed_identity`); the wizard stores it
  and compares the relay-wide fields of every later reply against it. A
  difference — the shadowsocks key that appears with the first recipient,
  a moved cover host, a rebuilt relay — signs again and republishes the
  refresh note, *before* the file for that reply is built.

**Released 2026-11-19 (TW-1).** The pinned `daal-relay-mgmt`
(relay-v1.5.1) serves `/identity`. The rig expects every relay to state
its identity, and on the pinned box `verb.relay-identity.*` is now green
in all three pinned worlds (`./daal e2e full` → `PASS — 5388 checks`);
the `F-005` entry (box=pinned) is deleted from known-findings.json.
Before the pin moved the pinned daemon (relay-v1.5.0) had no `/identity`,
`relay-identity` answered "cannot say" (exit 3) and the app would have
been on its fallback there. Not yet run against a rented relay.

A relay too old to answer (`404` → exit 3) falls back to the same
machinery fed from a `users-provision` reply; with a record that carries
no key at all the wizard adds the shared `r0` to get one. A relay that
cannot be *reached* is an error, never a fallback.

**What the rig now does.** Its record never had the SSH-read material (no
sshd), so it was already the record the Vultr adapter writes — but it
provisioned a recipient *first* and passed `--endpoint-creds`, which is
not the app's order. `mint` now runs the app's order through the CLI:
`relay-identity` → `bind-and-sign` with nobody on the relay → the first
recipient → `bind-and-sign` again iff the reply disagrees with what was
signed (it must, exactly when a family was pending) → the pack every
`family/*` session then connects with. On relay-v1.5.0, the pinned
release artefact until 2026-11-19, which predates the route,
`relay-identity` had to answer exit 3 and the old order was used.

**Found on the way** (and fixed): an identity saved before an L2 and
reused after it outranked the record and signed the *old* cover host —
every phone that took the refreshed pack failed REALITY verification
(`op:l2 no-new-file.cover-host-moved.*` went red). The wizard never
reuses an identity across a disguise change; the CLI now also refuses to
let an identity older than 15 minutes outrank the record on the cover
host (`TestBindAndSign_AnOldIdentityDoesNotOutrankTheRecordOnTheCoverHost`).

**Not verified.** The desktop app was not run, on any provider; no real
cloud API was called. The *released* `daal-relay-mgmt` serves
`/identity` since relay-v1.5.1 (TW-1, 2026-11-19), but no real relay has
been provisioned from it yet.

What follows is the finding as it was written.


**Evidence basis: reading the wizard source; the CLI stands in for the
app.** Nothing here was seen in the desktop app or on a phone.

**What.** Since F-004 was fixed, `bind-and-sign` commits every route to a
signed endpoint, and a route it cannot commit is unusable. The material
comes from two places: the OperatorRecord, and a relay reply passed with
`--endpoint-creds`. The app (`commands.rs sign_relaypack` →
`cli_bridge.rs run_bind_and_sign`) passes the record only, and runs the
Sign step before any recipient exists, so it has no reply to pass.

What the record carries depends on the provider adapter:

* **Hetzner**: `reality_public_key` and `tls_cert_sha256` are read over
  the provisioning SSH session (`providers/hetzner/provider.go`). The pin
  file it reads, `/etc/daal/tls-spki-sha256.b64`, was written by nothing
  until this change (cloud-init now writes it). So a relay provisioned
  from this tree with the SSH read working signs all four default
  families, plus tuic and anytls. **shadowsocks is never committed** from
  the record alone (its server key is in no record), so that route is
  signed without an endpoint and dropped at mint.
* **Vultr**: the adapter reads neither (its own comment: the material "is
  read from the box's own /users/provision response at pack time"). The
  record has no material, `bind-and-sign` exits 1 with
  `no route could be given a signed endpoint`, and the Sign step fails.
* **Any provider, SSH read failed**: the same as Vultr, or REALITY only.

**Why it matters.** On Vultr the app cannot produce a pack at all until
this is wired. That is a regression introduced by closing F-004, accepted
because the alternative — signing packs whose endpoints nobody
authenticated — is F-004.

**What it takes.** One of:

1. the app provisions its first recipient (it already has a shared `r0`:
   `recipient_book.rs produce_shared_sbp`) before signing, stages that
   reply at mode 0600 and passes `--endpoint-creds`; and re-signs with the
   newest reply after each rotation; or
2. the relay publishes its public identity (REALITY public key, TLS key
   pin — neither is secret) through the bootstrap health endpoint that
   already relays the mgmt TLS fingerprint, so every adapter records it at
   provision time. That needs `daal-relay-health`, a pinned artefact.

(1) is self-contained in the app and also covers shadowsocks.

---

## F-001 — the artefact verifier needs `/tmp` and `/usr/local/bin` on one mount, and hides it when they are not (fixed)

**What.** `publisher/deploy/cloudinit/shim.sh.tmpl` downloads each artefact
to a `tempfile.NamedTemporaryFile` (default directory, `/tmp`) and installs
it with `os.replace(tmp, /usr/local/bin/<name>)`. `rename(2)` across mounts
fails with `EXDEV`. The whole per-mirror body is inside `except Exception:
continue`, so the error is discarded and the script reports

```
FAIL: no mirror passed verification for sing-box-1.13.12-linux-amd64
```

— after the download succeeded, the SHA-256 matched and the signature
verified. Provisioning then dies with "artifact verification failed".

**Why it matters.** Not today: the pinned image is `ubuntu-24.04`, whose
`/tmp` is on the root disk. It becomes a dead provision, with a message
that sends the operator looking at mirrors and signatures, the day the image
is one where `/tmp` is a tmpfs (systemd's upstream default; Debian 13 ships
it) or `/usr/local` is its own mount. The first boots of this rig failed
exactly this way (the laptop's `/tmp` is a tmpfs, and the box's `/usr/local`
was a separate bind mount); the box root filesystem was then rebuilt so that
both sit on one mount, like the VPS.

**Reproduce.** In `box/init.py`, mount a tmpfs on the box's `/tmp`
(`sh("mount", "-t", "tmpfs", "tmpfs", root + "/tmp")` before the chroot) and
run `./run.sh clean vless-reality`: `verb.provision` fails and
`out/latest/boxes/*/rootfs/var/log/cloud-init-output.log` ends with the
message above.

**Fixed.** The shim now creates its temp file in the install directory
(`tempfile.NamedTemporaryFile(dir=target, …)`), fsyncs it, verifies it
there and renames it into place — one mount by construction — removes its
temp files on every path, and prints, per mirror, why it was not accepted
(`<url>: sha256 mismatch`, `signature did not verify`, or the exception).
The gate is unchanged: SHA-256, then the Ed25519 signature through
`openssl`, before anything is installed. `VerifierShimSource`'s SHA-256
and the V1.5 cloud-init golden are re-pinned in `template_test.go`, with
the reason next to each. `shim_exec_test.go` runs the embedded shim bytes
against a local mirror with `TMPDIR` on a different filesystem
(`TestVerifierShim_InstallsAcrossMounts` — fails on the old shim with
exactly the message above), a missing artefact, a wrongly-signed one, and
a dead first mirror.

**Not verified in the rig**: the reproduction above needs a modified box
(`box/init.py`), which was not done; the unit test exercises the same
`EXDEV`. Reaches a relay only through a fresh provision.

---

## O-1 — the protect callback is registered and never used

`DaalVpnService` registers a protect callback before establishing the TUN;
the rig does the same and counts invocations: **0**, on every family, every
run (`engine_protect_calls` in each `control.after` check).
`androidPlatform.UsePlatformAutoDetectInterfaceControl()` returns true when
a callback is registered, but nothing in the config `BuildSingBoxConfig`
produces makes sing-box consult it (no `auto_detect_interface`). The
engine's sockets stay out of the tunnel solely because of
`addDisallowedApplication(self)` (here: uid exclusion). That matches the
comment in `DaalVpnService.kt`; it is recorded because the callback, its
JNI hop and `invokeProtect` read as a second line of defence and are not
one. Without uid exclusion the engine's dial loops into its own TUN
(observed while building the rig: a socket owned by the engine stuck in
`SYN-SENT 10.20.30.40 → 203.0.113.10:443`).

## O-2 — disconnect took ~5 s when the relay was unreachable (fixed)

**Fixed.** `box.Close()` does not interrupt a dial that is already waiting
on a dead address: sing-box lets it run out its 5 s connect timeout and
Close waits for it. The engine now builds each instance on a context of
its own and cancels it before closing (`closeInstance`,
`core/engine/engine_singbox.go`), so those dials return at once; and
`ClearRoute` abandons a connection check in flight instead of waiting for
it (`core/abi/abi.go`). Pinned by `TestCloseInstance_DoesNotWaitForADialToADeadRelay`
(an instance with a dial in flight to a blackholed address must close in
well under the connect timeout) and
`TestClearRoute_DoesNotWaitForAConnectionCheck`. The rig cannot show the
old number any more — with CEN-1 fixed a blackholed route never reaches
"connected", so there is no such session to disconnect — which is why the
pin is a unit test. As found:

Under `relay-ip-block`, stopping a vless-reality or websocket-tls session
(`ClearRoute`) blocks for ~5.0 s (`control.after` 5036 ms vs ~40 ms on a
healthy path); the other families return immediately. On the phone this is
the "Disconnect" tap appearing hung exactly when the user is most likely to
tap it. `./run.sh --mgmt=tree relay-ip-block`, compare the `ms` of
`control.after` per family in `results.jsonl`.

---

## FAM-1 — naive: connected, and no name resolves

**What.** `DaalVpnService.kt` gives Android two resolvers
(`.addDnsServer("1.1.1.1")`, `"9.9.9.9"`). The platform resolver queries
them over plain UDP/53. Inside the engine that datagram is routed to
`route.final` like any other packet; the naive outbound is HTTP/2 CONNECT
and cannot carry UDP, so the netstack answers the app with ICMP
port-unreachable. Every lookup fails at once.

`engine_singbox.go` has, since the naive tier landed, added a `dns` block
with a DNS-over-TCP server detoured through the active outbound, with the
comment "DNS must resolve THROUGH the tunnel … TCP DNS works over every
transport". A `dns` block only answers queries the router hands to it, and
no route rule did (`route` was `{"final": "active"}` and nothing else). It
was dead configuration.

**Why it matters.** The route reports Connected and carries TCP perfectly —
the tunnel check passes — and the user sees a browser that loads nothing.
It depends on the phone: Android's "Private DNS: Automatic" upgrades those
two resolvers to DNS-over-TLS (TCP/853), which naive carries, so the same
pack works on one phone and is dead on the next (Private DNS off, a
provider hostname that is itself unreachable, or Android < 9). That is
consistent with naive being "field-proven on device".

**Reproduce** (before the fix: `git stash` the two `core/engine/config*.go`
hunks).

```
./run.sh clean naive
  ok   family/naive  tunnel  expect=pass got=pass
  FAIL family/naive  dns     expect=pass got=blocked — UDP/53 lookup got no answer:
       udp 9.9.9.9/53: read udp 10.20.30.40:38288->9.9.9.9:53: read: connection refused
       (the same lookup over TCP/53 succeeded)
```

**Fixed.** `BuildSingBoxConfig` adds one route rule, `{"network":"udp",
"port":53,"action":"hijack-dns"}`, when — and only when — the active
outbound cannot carry UDP. The engine then answers the query itself through
the DNS-over-TCP server it always had. Outbounds that carry UDP are
untouched: their queries still go to the resolver the app asked. Test:
`TestBuildSingBoxConfigHijacksDNSForUDPLessOutbounds` (default build).

"Cannot carry UDP" is decided by `outboundCarriesUDP`, which mirrors the
network list each sing-box 1.13.12 outbound registers with: `http`, `tor`,
`ssh` and `shadowtls` are TCP-only always; `naive` is TCP-only unless
`udp_over_tcp` is enabled; any other type is TCP-only when its profile pins
`"network":"tcp"`. The first cut of this fix listed only `naive` and
`http`, which left **tor with the identical defect** (review finding; every
tor route is TCP-only). `TestTCPOnlyOutboundTypesMatchSingBox` reads the
always-TCP list back out of the pinned sing-box source, so a version bump
that changes it fails a test.

**What the rig proves and what it does not.** Only naive is exercised end
to end (`family/naive dns`). No rig family dials tor, ssh, shadowtls or a
`network:tcp` profile: for those the fix is covered by the unit tests
alone, and tor additionally needs the phone retest below. After the fix the rig's resolver log shows the lookup
arriving over TCP from the relay's egress address and `dns` is green.

**Still to do on the phone** (the rig cannot be Android's resolver): with
Private DNS set to *Off*, connect over a naive route and open a site by
name. Repeat once over a tor route: same symptom before the fix, never
observed by the rig.

---

## FAM-6 — naive carried no app UDP except DNS (fixed)

**What it was.** FAM-1's fix made names resolve on naive by answering
UDP/53 inside the engine. It did nothing for any other datagram. The naive
outbound the publisher minted was HTTP/2 CONNECT with no `udp_over_tcp`,
so sing-box built it with `networks = [tcp]`
(`protocol/naive/outbound.go`) and every app datagram that was not port 53
was refused inside the engine: voice/video calls, most games, QUIC-only
clients got nothing while the engine reported Connected. The rig held the
limitation still as an expectation (`families/naive.json` `"udp":
"blocked"`), which printed as a green cell.

**Fixed** (decided 2026-11-18: do it). One member in the minted naive
outbound, `"udp_over_tcp": {"enabled": true, "version": 2}`
(`publisher/deploy/relaypack/client_outbound.go`). Checked against the
source of the released sing-box 1.13.12, not assumed:

* **relay**: `protocol/naive/inbound.go`, `NewInbound` wraps its router in
  `uot.NewRouter(router, logger)` unconditionally — the same line the
  shadowsocks inbound has, whose client half Daal already mints with
  `udp_over_tcp`. No box change, no option, nothing in the release;
* **client**: `protocol/naive/outbound.go` registers `[tcp, udp]` when the
  option is enabled and tunnels datagrams in a CONNECT stream to sing's
  UoT address;
* **engine**: `outboundCarriesUDP` (`core/engine/config.go`) already read
  the option, so the DNS hijack steps aside for this route and lookups
  ride the tunnel like any other datagram. The hijack stays for the
  TCP-only outbounds that remain (http, tor, ssh, shadowtls,
  `network: tcp`);
* **signed endpoint**: `bundle.CheckOutbound` is a refusal list around
  server / port / key equalities; `udp_over_tcp` changes what the stream
  carries, not where it goes or what proves who answered, and is
  accepted. `MergeEndpoint` keeps it, so a phone that follows the relay
  without a new file keeps its UDP.

```
./run.sh clean naive            (same on the pinned sing-box with --mgmt=tree)
  ok   family/naive  udp  expect=pass  got=pass
relay sing-box log:  inbound/naive[naive-in]: inbound UoT connection to 192.0.2.80:7
```

`families/naive.json` now declares `"udp": "pass"`, so naive's `udp` is
asserted under every censor scenario for the first time.

**What it is not, and what was not verified.**

* It is not UDP: datagrams share one TCP stream, so a lost segment delays
  every datagram behind it. A call works; it cannot be better than the TCP
  path under it.
* **Packs already minted do not change**: recipients get UDP on naive with
  a re-minted file.
* Not run on a phone: throughput and battery of QUIC-inside-TCP through
  Cronet are unknown, and INT-1's close race gets a new kind of long-lived
  stream to hit (its fix is in the tree; Android is TW-3). No soak.
* An engine that does not know `udp_over_tcp` on the naive outbound would
  reject the whole outbound. Nothing is fielded; the engine in this tree
  (sing-box 1.13.12) knows it.

---

## FAM-2 — the app has no way to turn on shadowsocks, anytls or tuic (fixed)

**Evidence basis: established by reading the wizard source; the CLI stands
in for the app.** Nothing here was observed in a running app. The rig does
not compile or run the Tauri shell, the Rust bridge or the TS UI; the claim
is what `PublisherWizard.tsx:342`, `cli_bridge.rs` and `rebuildPlan.ts`
say. What the rig observed is the other half only: that the CLI flag is the
mechanism, and that with it the three families carry bytes. If a control
that sets the list exists somewhere this reading missed, the finding is
wrong and no run of the rig would show it.

**What.** The three Wave-5 families are `default_enabled: false` in
`iran-default.json`; the mechanism that enables them is
`daal-deploy provision --families …`. The Rust bridge forwards the flag
(`cli_bridge.rs`: `if !args.families.is_empty() { cmd.arg("--families") … }`),
but the only caller is

```ts
// client-ui/src/publisher/PublisherWizard.tsx:342
const enabledFamilies = useMemo<string[]>(() => [], []);
```

— a constant. There is no control that changes it, and the rebuild path
(`rebuildPlan.ts`) only ever intersects, so it can remove families and
never add one. An operator using the app gets the four default families,
always. The three families that "have never carried a byte" could not have:
outside a terminal there is no way to ask for them.

**Reproduce.** `grep -n enabledFamilies client-ui/src/publisher/*.tsx`. In
the rig the families are enabled the only way that exists — `./run.sh clean
tuic` passes `--families vless-reality,websocket-tls,naive,hysteria2,tuic`
to the real verb (see `verb.provision` evidence `families_flag`) — and with
that, plus a mgmt daemon that knows the families (`--mgmt=tree`, see F-002),
all three carry verified bytes.

**Fixed.** The plan screen of the build wizard has a collapsed section,
"More ways to connect" (`MoreWaysToConnect.tsx`). Opened, it lists the
profile's opt-in families — read from the `TOOLBOX_PROFILES` mirror that
`tools/check-toolbox-profiles.mjs` holds to the Go profiles — each off by
default, each with a plain-language name and one sentence on what it is
and what it costs (one more open port; nothing that gets through a
web-only network). anytls says, and repeats in a warning once ticked,
that the connection file is then made in a newer format that an older app
cannot open **at all**. The list the wizard sends
(`extraFamilies.ts: enabledFamiliesFor`) is `[]` when nothing is ticked —
exactly what it sent before — and otherwise every default family plus the
ticked ones, because `--families` replaces the defaults (FAM-3). The
choice is remembered per relay across a relaunch (best effort,
`localStorage`), so a resumed build does not silently fall back to the
defaults. Strings are in `d2-extra.{en,fa}.json` (both copies).

**Evidence basis, unchanged in kind: unit tests and the type checker.**
`extraFamilies.test.tsx` renders the section to markup, and checks the
list composition, the default-off/collapsed state, the wording rules and
— at source level — that the wizard's constant is gone. **The app was not
run**: nobody has clicked this in a Tauri window or on a phone, and the
Rust bridge's handling of a non-empty `enabled_families` on a FIRST
provision (it was only ever exercised by rebuilds) is established by
reading `cli_bridge.rs`, not by running it.

**Review finding on this fix (high): the switches offered what the
released relay cannot serve — fixed by locking them until F-002's
release.** With F-002 open, the only `daal-relay-mgmt` an app-provisioned
relay downloaded (relay-v1.5.0) served none of the three. Reproduced on
the box pinned then:

```
./run.sh clean anytls vless-reality      # pinned
KNWN mint/anytls   relay.listens  [F-002]   (nothing on 8447/tcp)
KNWN mint/anytls   pack.route     [F-002]   — the minter dropped this route: anytls needs anytls_password …
KNWN family/anytls tunnel  got=refused [F-002] — pick: pack has no route of family "anytls"
```

So a publisher who ticked anytls got one more open door, no anytls route,
and (the signed manifest names anytls) a connection file older apps
refuse — the cost the warning describes with none of the benefit, behind
copy that said only "newer and used far less".

Whether the pinned artefact serves these families is now one build
constant beside the pin, `PinnedMgmtServesOptInFamilies` in
`publisher/deploy/cloudinit/artifacts.go` (false when this was written;
**true since the pin moved to relay-v1.5.1, 2026-11-19**), mirrored for the
UI as `RELEASED_RELAY_SERVES_EXTRA_FAMILIES` in `extraFamilies.ts`. While
it is false the section is still there and still explains each option,
but every switch is disabled and unticked, one line says why ("You cannot
turn these on yet. The software that a new server installs does not
include them…", en+fa), the collapsed line reads "Not available yet", and
`enabledFamiliesFor` returns `[]` whatever was ticked or remembered in
`localStorage` — the wizard cannot ask a server for them. The feature is
not removed: flipping the two constants with the pin bump — done
2026-11-19 — restores exactly the behaviour described above, and the
locked state keeps its tests.

Held by: `TestPinnedMgmtOptInGateMatchesThePin` (stale hash ⇔ gate shut;
a bump that forgets the flip, or a flip without a bump, fails),
`TestOptInFamiliesOfMgmtAreTheProfilesOptInFamilies`,
`tools/check-toolbox-profiles.mjs` §5 and the vitest suite "while the
released relay software cannot serve them" (which also reads the Go
constant). **Not pinned by the rig** (above the ABI), and, as before,
**the app was not run**. The rig evidence for the underlying fact:
F-002 is closed by relay-v1.5.1 and `release.all-families` is green on
the pinned box (2026-11-19). Nobody has turned a switch on in a real
window yet.

---

## FAM-3 — `--families` filters silently (fixed)

**What.** `relayconf.CandidatesForProfile` keeps a profile candidate only if
the list names it. So:

* a misspelt family is dropped without a word, as long as one other name
  matches;
* the list REPLACES the defaults — `--families tuic` is a tuic-only relay,
  not "the defaults plus tuic".

Both exit 0 and both rent a server.

**Reproduce** (offline; `--dry-run` calls nothing):

```
daal-deploy provision --provider hetzner --region fsn1 --server-type cx22 \
  --toolbox-profile iran-default --pubkey-file pk.pub --token-file tok \
  --helper-ip 198.18.0.2 --dry-run --families vless-reality,tiuc -o rec.json
# rc=0; rec.json candidates: ["vless-reality"]
… --families tuic …
# rc=0; rec.json candidates: ["tuic"]
```

**Fixed, at the operator-input boundary** (`publisher/deploy/cli/
cli_families.go`). `provision` resolves `--families` against the toolbox
profile before it generates a key or builds a provider:

```
… --dry-run --families vless-reality,tiuc
# rc=2, no record:
# provision: --families: "tiuc" — not a transport family toolbox profile "iran-default" offers.
#   Valid: vless-reality, websocket-tls, naive, hysteria2, shadowsocks, anytls, tuic. Nothing was created
… --families tuic
# rc=0; rec.json candidates: ["tuic"], and on stderr:
# provision: --families REPLACES the defaults of toolbox profile "iran-default": this relay will serve tuic
#   and will NOT serve vless-reality, websocket-tls, naive, hysteria2, which the profile enables by default (…)
```

A real family of a different profile (`tuic` on `iran-tcp443`) is refused
the same way, with the profile that does offer it named. With
`--progress-json` the statement is one `provision_families` event.

`relayconf.CandidatesForProfile` is untouched — the intersection L6 needs
is still there. What changed for L6 is where it becomes visible:
`reprovision --new-toolbox-profile` (after the provider's unchanged
pre-delete refusal of an empty intersection) narrows the record's
candidates to what the new profile offers and says what the rebuild
drops, so the `provision --families <the record's families>` the app runs
next passes the new check (`TestReprovision_NarrowsTheRecordSoTheL6Rebuild
StillProvisions`). Both halves are the same binary.

**Review finding (with F-002 open): the line promised what the release
cannot serve.** `--families …,anytls` printed "this relay will serve …,
anytls" while the pinned `daal-relay-mgmt` serves no anytls. The plan now
carries `UnservedByRelease` (from `cloudinit.NotServedByPinnedMgmt`), and
when it is not empty the statement is a request, with the consequence:

```
… --dry-run --families vless-reality,websocket-tls,naive,hysteria2,anytls
# rc=0, stderr:
# provision: --families REPLACES the defaults of toolbox profile "iran-default": this relay will be asked to serve
#   vless-reality, websocket-tls, naive, hysteria2, anytls (anytls: off by default, turned on by this list). …
#   NOT SERVED YET: the released relay software this build installs (daal-relay-mgmt, pinned in
#   publisher/deploy/cloudinit/artifacts.go) predates anytls. Unless this relay runs a newer daal-relay-mgmt than
#   that release, the firewall port is opened for nothing: no recipient gets a credential for it and no connection
#   file will carry a route for anytls; and because anytls is named, every connection file is still made in the
#   newer format that older Daal apps cannot open at all
```

It is deliberately a statement and not a refusal: the same verb
provisions a relay whose daemon is newer than the pin (`--mgmt=tree` in
this rig, a release being tested), where the families do carry traffic.
The `provision_families` event gains `unserved_by_release`. Unit:
`TestFamilySummary_DoesNotPromiseWhatTheReleaseCannotServe`,
`TestResolveFamilies_UnservedComesFromThePin`. Since the pin moved to
relay-v1.5.1 (2026-11-19) `NotServedByPinnedMgmt` returns nothing, so the
line is "will serve" again; the request wording stays for the next time
the pin is behind a family.

**Not verified**: an L6 run through the app, or against a cloud — the
rig has no L6 op. `--provider stark` is exempt from the check: that
placeholder adapter has its own family table and its own silent filter.

---

## FAM-4 — a default family you did not ask for is still on the box (fixed)

**What.** With `--families shadowsocks,anytls` the record, both pack and
firewall *additions* follow the list — but the base firewall set
(443/tcp, 443/udp, 8444/tcp, 8445/tcp) is unconditional, `vless-in` and
`hy2-in` are unconditional in the rendered sing-box config, and the mgmt
daemon creates `naive-in`/`ws-in` and credentials for all four on the first
recipient. The relay ends up with four reachable listeners that no pack
mentions.

**Reproduce.**

```
./run.sh --mgmt=tree --relay-families shadowsocks,anytls clean shadowsocks anytls
  FAIL mint/vless-reality not_served expect=blocked got=pass — a firewall admits 443/tcp (box ufw=true, cloud=true)
  FAIL mint/hysteria2     not_served …443/udp…   FAIL mint/naive …8444/tcp…   FAIL mint/websocket-tls …8445/tcp…
```

(`listener_on_box: true` for all four in the check's evidence.)

**Fixed** (the daemon half released as relay-v1.5.1, 2026-11-19) — the
box now learns its own family set, and everything follows it:

* `relayports.FirewallPortsFor(families)` is the complete port set of a
  relay; there is no unconditional 443 any more, in the cloud firewall
  (hetzner, vultr) or in the ufw rules both cloud-init templates render.
* `relayconf.SingBoxConfigForFamilies` bakes `vless-in` only with
  vless-reality and `hy2-in` only with hysteria2 (`tuic-in` as before).
  A relay serving only on-first-use families boots with no inbound; the
  first-boot REALITY keying no longer fails when there is no REALITY
  inbound, and then writes no `reality.pub` / `cover-sni`.
* cloud-init writes the set to `/etc/daal/families`; `daal-relay-mgmt`
  creates inbounds, user rows and credentials for those families only,
  keeps its user registry as the union over all managed inbounds (it was
  `vless-in` alone), and returns a credential only for a row that exists.
  A box with no such file behaves as before; a file it cannot read is a
  `500`, not "everything".

```
./run.sh --mgmt=tree --relay-families shadowsocks,anytls clean shadowsocks anytls
  ok mint/vless-reality not_served expect=blocked got=blocked   (box_ufw_open false, cloud_firewall_open false, listener_on_box false)
  … hysteria2, naive, websocket-tls, tuic the same
  ok censor prove.relay-tls-answers expect=blocked got=blocked  — this relay serves nothing on 443/tcp …
RESULT: PASS — 55 checks
```

The last line is a rig change that came with the fix: `clean`'s
`relay-tls-answers` proof dials the relay on 443/tcp, which a relay
without vless-reality no longer has. A TCP proof aimed at a relay port
no served family listens on is now run with its expectation inverted
(`driver/prove_unserved.go`): it must NOT connect.

Contract: `specs/per-recipient-credentials-v1.md` §2.3. The cloud-init
golden moved and is re-pinned (`template_test.go`).

**What it does not reach.** Relays are built from pinned artefacts and
cloud-init has no upgrade path: this needed the relay re-release (new
`daal-relay-mgmt` — relay-v1.5.1, 2026-11-19) AND needs a fresh
provision: the family file and both firewalls are written at first boot,
so only a relay provisioned from this release has them. No older relay is
in service. For the record, new cloud-init with the relay-v1.5.0 daemon
served the default set correctly but still created `ss-in`/`anytls-in`,
and could not be provisioned at all without vless-reality (that daemon
requires `vless-in`: `/users/provision` answers 500, nothing is minted).
`rotate-credentials` on a relay without vless-reality makes the CLI warn
that the relay "did not echo its cover host / REALITY public key" — true,
and not a fault there; the warning's wording was left alone.

---

## FAM-5 — Cronet beside the binary was unloadable off Android

**What.** `loadCronet` pre-loads `libcronet.so` by soname, which is right on
Android (the app linker namespace) and nowhere else: `dlopen` does not
search the executable's directory. cronet-go's `LoadLibrary` is a
`sync.Once`, so that failed attempt was the cached answer for sing-box's
own later `LoadLibrary("")` — the one call that searches beside the binary.
The file's comment said the opposite ("on desktop/linux the .so ships
beside the binary so LoadLibrary("") already works").

**Why it matters.** Latent: only the Android build ships naive today. It is
what kept naive "not dialable headless" — the library was on this machine
all along (sing-box's dependency `cronet-go` ships a linux/amd64
`libcronet.so` as a Go module).

**Reproduce** (before the fix): `./run.sh clean naive` with `libcronet.so`
staged in `bin/` → `tunnel got=refused — cronet: failed to load library
libcronet.so: cannot open shared object file`.

**Fixed.** `cronetLibraryArg(goos)`: the soname on Android (unchanged),
`""` (cronet-go's own search, executable directory first) elsewhere. Tests:
`TestCronetLibraryArg` (the helper) and `TestLoadCronetUsesCronetLibraryArg`
(the wiring: `loadCronet` sits behind `with_naive_outbound`, which the
default test build never compiles, so the test parses the package source
and fails if any cronet `LoadLibrary` call passes anything but
`cronetLibraryArg(runtime.GOOS)`, or if the call disappears). naive now
carries verified bytes in the rig, with the real Chromium network stack on
the client.

**Not verified on a device.** Android behaviour is unchanged *by
construction* — `cronetLibraryArg("android")` returns the same soname the
old literal was, and the unit test pins that — not by a run on the phone.
The rig only ever exercises the linux branch.

---

## O-3 — W5-1, observed (fixed with FAM-4; released 2026-11-19 as relay-v1.5.1)

**Now:** on a `--mgmt=tree` world the same checks record
`listener_on_box: false` — the daemon creates inbounds only for the
families in `/etc/daal/families` (FAM-4). That daemon is the pinned one
since relay-v1.5.1 (2026-11-19); the file is written by cloud-init, so it
holds for a relay provisioned fresh from this release. As found:

`./run.sh --mgmt=tree clean vless-reality`: the `not_served` checks for
shadowsocks and anytls pass (both firewalls shut, no route in the pack) and
record `listener_on_box: true` — the tree's mgmt daemon binds `ss-in` and
`anytls-in` on a relay that serves neither. Exactly backlog W5-1; recorded
so the day it is fixed the evidence flips.

## O-4 — the experimental gate gates nothing

shadowsocks, anytls and tuic are `MaturityExperimental`. Every session in
the rig activates them with the experimental-families flag at its default
(off) and they connect. That matches the "AS BUILT it does not" note on
`Core.experimentalFamiliesEnabled`; it is recorded because a recipient can
be connected over an experimental family without ever having opted in.

---

# Lifecycle findings (LC-*) — what happens after first contact

Found by the lifecycle ops (`./run.sh --mgmt=tree --ops lifecycle clean`;
README "Lifecycle ops"). Same rules as above: a check that a defect turns
red stays red.

## LC-2 — the freshness channel replaced a working pack with one that could not connect (fixed)

**Evidence basis: two halves, of different strength.**
*Observed in the rig* (real engine, real `publish-freshness`, real
signatures): given a document that names the signed skeleton's digest, a
polling phone swaps its working pack for one that cannot connect; given a
document that names a connectable pack, the channel works.
*Established by reading the wizard source; the CLI stands in for the app*:
that the app publishes the former. `freshness.rs:565` takes the digest from
`row.signed_sbp_sha256`, which `record_signed_sbp` stamps from
`bind-and-sign`'s output. That Rust code is not compiled or run here — the
op drives `daal-deploy publish-freshness` with the digest that reading says
the app would pass. "As the app drives it" is therefore an inference: it
has not been seen on a phone or in the desktop wizard, and should be
confirmed once in the real app (publish with two mirrors, let a second
device tick with the VPN off) before the design work is scheduled on it.

**What.** A freshness document says "the pack is now `<sha256>`, fetch it at
`<url>`". The app publishes it from `freshness::publish`
(`client-shell/tauri/daal-wizard/src/freshness.rs`), and the digest it
passes is `row.signed_sbp_sha256` — stamped by `record_signed_sbp` from
`bind-and-sign`'s own output. That file is the signed **skeleton**: its
per-route profiles are `{"_relaypack":{…},"port":443}`, with no server and
no credentials. Recipients never hold that file; they hold the output of
`users-pack-sbp[x]`, which rewrites every profile into a real outbound and
therefore has a different digest.

The only file whose digest can match the published document is the
skeleton. So, whatever the operator puts at the pack URL ("Where the
rebuilt file will be downloadable"):

* **the signed pack** → every recipient that polls downloads it, the digest
  matches, the importer swaps it in atomically, and **all of that
  recipient's routes become unconnectable** —
  `set_route: engine: option parse: outbounds[0]: unknown outbound type:`.
  The engine files it as `classification: unknown`, cooldown 5 m. This
  happens **with no rotation at all**: the first poll after an import always
  fetches and applies the pack (LC-O3).
* **the recipient's (or the shared) connectable pack** → the digest does not
  match the document, the engine refuses it (correctly), and nothing is ever
  delivered. The channel is inert.

Either way the path that exists so that "nobody has to touch a phone" after
a rotation cannot deliver a pack a phone can connect with.

**The mechanism itself works.** When the document names the digest of a
*connectable* pack (which `daal-deploy publish-freshness` will happily
sign — the flags are free-form — but the app never does), a phone holding
the pre-rotation pack polls the mirrors directly, verifies, downloads,
swaps and connects with no new file; a document signed by another key is
refused and no pack is downloaded. That is `rotated.*` below, all green.

**Why it matters.** This is the recovery channel for L2…L6, and it is
advertised to operators as such. An operator who configures two mirrors and
a pack URL and follows the UI turns every polling recipient's working relay
into a dead one, silently, the first time their phone ticks with the VPN
off.

**Reproduce.** `./run.sh --mgmt=tree --ops freshness clean vless-reality`
(≈30 s; identical with the pinned artefacts):

```
ok   unchanged.polled_mirrors_directly                 pass     document fetches=1 pack fetches=1, all from the phone's own address
FAIL unchanged.signed-pack-hosted.tunnel               expect=pass got=refused  set_route: engine: option parse: outbounds[0]: unknown outbound type:
ok   unchanged.recipient-pack-hosted.tunnel            pass     (digest mismatch → refused → phone untouched)
ok   unchanged.recipient-pack-hosted.digest_mismatch_refused
ok   rotated.no-poll.tunnel                            blocked  (control: old pack, no poll, after rotate-tls)
ok   rotated.forged-document.tunnel                    blocked  (document signed by a stranger's key)
ok   rotated.forged-document.pack_not_fetched          pass     document fetches=2 pack fetches=0
ok   rotated.polled.fetched_new_pack                   pass
ok   rotated.polled.tunnel                             pass     ← no new file was handed to this phone
```

`out/<run>/storage-requests.jsonl` has every fetch (source address, host,
path); `clients/NN-fresh-*/events.jsonl` has the tick's scheduler status
and the engine's own explanation of the failure.

**Fixed: the signed skeleton is merged, not swapped.** With the endpoint
commitments of F-004 the skeleton is exactly the public half of a pack:
where the relay is and what proves it is the relay. So for every route in
a fetched (or handed-over) signed pack whose profile holds no outbound,
the importer looks at what the device already has for that route — same
publisher, same family — and applies the NEW signed endpoint to the
credentials ALREADY there (`bundle.MergeEndpoint`). Then:

* a route the device holds credentials for comes out connectable, on the
  new address / cover host / key;
* a route the device holds nothing for is not stored (F-003);
* a route whose credentials cannot belong to the relay any more (its key
  changed) is left exactly as it was and reported `needs_new_file`;
* **a profile with no outbound never replaces one that has one**;
* the same file on a phone that holds nothing is refused
  (`pack_has_no_credentials`), not imported as dead routes.

On the freshness path the publisher-signed document (which names the pack
ids it supersedes) is what says "this pack replaces yours"; a skeleton
handed over as a file is merged only into routes of the same pack id.

**What needs a new file, by rung** (also in `specs/relaypack-v1.md` and in
the app's copy, `freshness.rs`):

| rung | what changes | per-recipient credentials | a polling phone |
|---|---|---|---|
| L1 `rotate-credentials` | one recipient's credentials | **changed, for that recipient** | that recipient needs a new file; nobody else is affected |
| L2 `rotate-tls` | cover host (and, if asked, the shared ws path) | unchanged | **recovers with no new file** (`op:l2 no-new-file.*`, 7 families). If the ws path was moved too, the websocket route alone needs a new file: the path travels with the credentials |
| L3 `assign-fip` | address | unchanged | **recovers with no new file** (`op:l3 no-new-file.*`) |
| L4–L6 rebuild | a new box: new REALITY key, new TLS key, new credentials | **changed, for everyone** | every recipient needs a new file |

L4–L6 cannot be made mergeable from the publisher side alone. The relay
mints each recipient's credentials itself: `/users/provision` takes a name
and nothing else, and the publisher's database stores what the box
answered. A rebuilt box therefore answers with different secrets. Having
it accept the old ones is a change to the mgmt wire (a pinned, released
artefact) — and when the reason for the rebuild is that the box was
compromised or seized, re-installing the credentials it held is the wrong
thing to do. The new keys DO travel in the signed endpoint; it is only the
credentials that need a courier.

```
ok   op:freshness  unchanged.signed-pack-hosted.tunnel        pass
ok   op:freshness  unchanged.signed-pack-hosted.routes_kept   pass
ok   op:freshness  signed-pack-alone.import                   refused   pack_has_no_credentials
ok   op:freshness  published.fresh2.holds_no_credentials      pass
ok   op:freshness  rotated.polled.tunnel                      pass      ← nothing was minted for this phone
```

LC-O3 (the first poll after an import always downloads the pack) is now
harmless — the merge is idempotent — and still true.

**What stands in.** The storage (`wb storage`) and the upload to it: the
rig copies `publish-freshness --out-file`'s signed document and the pack
onto a static HTTPS host the phone reaches through the censor.
`publish-freshness`'s R2 and GitHub uploaders are not exercised.

## LC-3 — after an L3 address move, naive could not connect to the new address (fixed for newly provisioned relays)

**What.** The box's TLS certificate is generated once, at first boot, with
`subjectAltName=IP:<primary address>` (`v2.yaml.tmpl:313`). Every family but
naive authenticates the relay by the pinned certificate hash, so the
address in the SAN never matters. naive rides Cronet, which does real name
verification against the address it dialled. After `assign-fip` the
re-minted pack dials the floating IP, the certificate still says only the
primary address, and the handshake dies:

```
ERROR:net/socket/ssl_client_socket_impl.cc:924] handshake failed; returned -1, SSL error code 1, net_error -200
```

(`-200` is `ERR_CERT_COMMON_NAME_INVALID`.) The censor's wire tap saw 7
packets to 8444/tcp and 2217 bytes back — a TLS handshake and nothing else.

Nothing says so. `users-pack-sbp` mints the route without a warning,
`assign-fip` exits 0, and the engine reports `state: Connected`, `"Tunnel
up on r3"`, `failures: []` while no byte passes.

**Why it matters.** L3 is the rung for "the address is burned". After it,
one of the four default families is dead for every recipient, on the only
address that is not blocked, and the app's own diagnostics call it healthy.

**Reproduce.** `./run.sh --mgmt=tree --ops l3 clean naive hysteria2`
(also red with the pinned artefacts):

```
family     old-file.grace  old-file.address-blocked  new-file.address-blocked  released-address-file  original-file
hysteria2  pass            blocked                   pass                      blocked                pass
naive      pass            blocked                   !blocked(want pass)       blocked                pass
```

**Fixed, for relays provisioned from this tree.** The certificate now
carries one stable DNS name beside the address (cloud-init,
`v2.yaml.tmpl`: the cover host the relay was provisioned with). The naive
outbound verifies against the ADDRESS when the certificate names the
address it dials — so a relay that never moved puts nothing new on the
wire — and against that DNS name otherwise (`bundle.NaiveVerificationName`,
used by the minter, the importer's merge and nothing else). Cronet resolves
the name to the dialled address itself (cronet-go's server-redirect
resolver); no lookup leaves the device. No pin moves, so old files keep
working on the old address through the grace period, and a phone that
polls needs no new file at all:

```
family     old-file.grace  old-file.address-blocked  new-file.address-blocked  no-new-file.address-blocked  released-address-file  original-file
hysteria2  pass            blocked                   pass                      pass                         blocked                pass
naive      pass            blocked                   pass                      pass                         blocked                pass
```

**What this does not do.**

* A relay provisioned BEFORE this change has a certificate with no DNS
  name; nothing can add one without re-issuing it. Its naive route still
  dies on L3 (the minter emits the route as before, and it fails the name
  check). Rebuild the relay to get it.
* ~~After an L3, naive presents the cover host the relay was provisioned
  with, even if a later L2 moved it.~~ **Fixed in the daemon
  (2026-11-18; released as relay-v1.5.1, 2026-11-19).** `rotate-tls` now re-issues the
  certificate when the cover host moves (`cmd/daal-relay-mgmt/tlscert.go`,
  spec `daal-relay-mgmt-v1.md` §4.2 step 5): the SAME key, so no pin and
  no signed endpoint moves; the new cover host as the FIRST DNS name;
  every name the certificate had before kept after it; the addresses the
  certificate already named and no others (never one bound since first
  boot: any prober of the old address can read this certificate); 90 days
  from now. `/users/provision` and
  `/rotate-credentials` hand out the new certificate from then on.
  Observed, `./run.sh --mgmt=tree --ops l2,l3 clean naive vless-reality
  hysteria2`:

  ```
  op:l2  box.certificate_follows_cover_host                       pass   DNS: mirror.xtom.de, mirror.init7.net  (new, old) — same key
  op:l2/naive  old-pack.tunnel                                    pass   a file that trusts the OLD certificate accepts the new one
  op:l3/naive  after-l2.new-file.presents_current_cover_host      pass   the re-minted file verifies/presents the new cover host
  op:l3/naive  no-new-file.after-l2.address-blocked.tunnel        pass   a phone holding a file from before BOTH rotations, handed nothing
  ```

  A client that installed the old certificate as its root accepts the
  re-issued one (same subject, same key: the old certificate is a valid
  issuer for it) — that is Chromium's behaviour as the rig observed it
  through Cronet on linux, and `TestRotateTLS_Reissues…` holds the same
  for Go's verifier. **Not verified on Android's Cronet build.**

  **What is still true:** a phone that holds a naive file from before the
  L2 and is handed nothing connects after the L3 (the old name is still in
  the certificate) but keeps VERIFYING AND PRESENTING THE OLD NAME — the
  name it uses is derived from the certificate it holds
  (`NaiveVerificationName`), and the signed endpoint deliberately carries
  no name for naive. Moving that phone without a file means committing the
  name in the signed endpoint: `Endpoint.server_name` allowed for naive,
  the minter and `MergeEndpoint` following it instead of deriving, and the
  signer knowing the certificate's first name at sign time (the relay's
  `/identity` reply states the pin, not the certificate). Not done: it is
  a pack-format change across `bundle`, `relaypack` and the identity read.
  Until then such a phone shows the stale name until it gets a new file.
  The certificate also now LISTS the relay's past cover hosts to anyone
  who completes a TLS handshake with the naive port; it already said
  `CN=daal-relay` to the same observer.
* "The engine reports Connected while no byte passes" was CEN-1, not this.

## LC-4 — an old signed pack, handed over as a file, rolled a phone back (fixed)

Found in review of the LC-2 fix, not by the rig. The signed skeleton is
public by design: it is the file the freshness mirrors serve, so anybody
who ever fetched one can keep it. LC-2 made the importer MERGE such a file
into the credentials a phone already holds, on two paths: the freshness
path, which is ordered by the signed document's sequence high-water mark,
and the file path (file, QR, share), which asked only for the same
publisher, family and `relay_pack_id`. An in-place rotation — port, cover
host, REALITY key, TLS key — keeps the pack id. So the file path had no
notion of older and newer.

The scenario: the operator rotates a relay key or a port because the old
one is burned or seized. Whoever holds the old key hands a recipient the
old public file. The publisher is already trusted, so there is no prompt;
the phone goes back to the burned endpoint and to a key the adversary
holds, until the old pack's `expires_at`.

**Fixed: a file only moves a route forward.** The store keeps, beside each
route's signed commitment, the `bundle.created_at` of the manifest it came
from (`endpoint-signed-at:<route_id>`). Outside the freshness path a merge
now also requires the incoming manifest to be strictly later than that.
The manifest the route is already on (same date, identical commitment) is
a no-op and still accepted, which is what keeps LC-O3 harmless. Otherwise
the route is reported `older_than_device` and left exactly as it was; a
file with nothing else in it is refused as `pack_is_older`. A route whose
date is not known is not merged into by file at all (`needs_new_file`).
The freshness path is unchanged. Spec: `specs/relaypack-v1.md`, importer
rule 4.

```
ok   op:freshness/vless-reality rotated.stale-signed-pack-by-file.not_merged   pass
ok   op:freshness/vless-reality rotated.stale-signed-pack-by-file.routes_kept  pass
ok   op:freshness/vless-reality rotated.stale-signed-pack-by-file.tunnel       pass
```

With the rule switched off the same world is red on `.not_merged` and on
`.tunnel` (`reality verification failed`: the phone was back on the cover
host the relay had left).

**What this does not cover.** `created_at` has one-second resolution. Two
signings in the same second are not ordered, so the second one cannot be
delivered by FILE as a skeleton (it is refused as not newer; the
freshness path still delivers it). That is the rig's own situation — it
re-signs within a second of the first signing — and never an operator's.
And the rule is about the credential-less merge only: a recipient's own
OLDER full file (one that carries their credentials) still imports and
replaces what the phone holds, as any re-import does. That file is not
public, so it is a different threat; it is left as it was.

## LC-1 — a mgmt token already used once could be replayed with a different body (fixed; released 2026-11-19 as relay-v1.5.1)

**Released 2026-11-19.** The daemon with single-use tokens and token
format v2 is the pinned `daal-relay-mgmt` of relay-v1.5.1. Proof: world
`release.lifecycle` (pinned box) runs `op:mgmtauth` green in
`./daal e2e full` → `PASS — 5388 checks`, and the `LC-1` entry
(box=pinned) is deleted from known-findings.json. No relay older than
relay-v1.5.1 is in service. The reproduction below is against
relay-v1.5.0.

**What.** A `Daal-Mgmt-Token` signs `nonce:ts:op` and not the request body.
`daal-relay-mgmt` made the two address verbs single-use in Wave 3c for
exactly that reason, and left the other mutating verbs replayable for 300 s.
So a token the publisher used to revoke one recipient could be presented
again naming another:

```
FAIL op:mgmtauth replay.users-revoke expect=refused got=pass — a token already used to revoke r43
     was honoured a second time and revoked r42, whom the publisher never named: {"revoked_at_unix":…}
```

The same holds for `/rotate-credentials` (rotate somebody else),
`/users/provision` (mint another user) and `/rotate-tls` (move the cover
host again, killing every vless-reality pack again).

**Severity: low-to-medium.** The attacker needs a token (it travels inside
the pinned TLS session) and a path to the port (two firewalls, open to the
helper's address for one verb). It is defence in depth — the same depth the
address verbs already had.

**Fixed.** `cmd/daal-relay-mgmt/main.go`: every mutating op is now
single-use (`singleUseOp`); `users-list` and `whoami` stay replayable
because a GET may be re-sent by the HTTP transport with the same token and
neither changes anything. No wire change: the publisher has always minted a
fresh nonce per request, and a POST with a body is never replayed by the
transport once a byte reached the server. Test:
`TestMutatingTokensAreSingleUse` (fails without the fix). Spec updated:
`specs/daal-relay-mgmt-v1.md` §3 and §4.8.

**The residual, and its fix (token format v2, 2026-11-18).** The nonce
set is in memory, so single use held for the life of the mgmt process
only: restart `daal-relay-mgmt` (or reboot the box) inside the accept
window and a captured token was presentable once more — e.g. a used
`users-revoke` token replayed against another recipient. Six verbs relied
on it.

The token now signs the request, not just the op. Wire format
`v2:<nonce>:<ts>:<op>:<sig>`; the signature covers eight lines —
`daal-mgmt-token-v2`, relay, nonce, ts, op, METHOD, path, hex SHA-256 of the body
(spec §3; `tokenSigningInput` on the box, `signingInput` in the
publisher, pinned to each other by
`publisher/deploy/mgmt/testdata/token_v2_vector.json`). A token is good
for one request, byte for byte, whatever the daemon remembers. The box
refuses the v1 shape outright; the publisher cannot mint it. Every
authenticated client call goes through one function
(`mgmt.Client.signedRequest`) that takes the op and the body, so what is
signed and what is sent cannot come apart. The body is read (at most
64 KiB) before the token is verified and the handler is given exactly the
bytes whose digest was signed. Unit: `TestTokenIsBoundToTheRequest` clears
the nonce set (what a restart does) and replays with another body → 401,
config untouched.

**The relay is named too (review finding, 2026-11-19).** As first written
the v2 input named no relay, so a token was good on every relay that
trusts the same publisher key (an imported key; the old and the new box
around a rebuild): two daemons holding one key both answered 200 to the
same `users-revoke` token and body, and the second one's nonce set had
never seen it. Line 2 of the signing input is now the lower-case hex
SHA-256 of the management TLS certificate of the relay the token is for —
the publisher signs the fingerprint it pins the session on, the box
verifies with the fingerprint of the certificate it serves and refuses
everything if it has none. Done inside v2 (no v2 verifier had been released then).
Unit: `TestTokenIsBoundToTheRelay`, `TestTokenAudienceIsTheServedCertificate`
(cmd/daal-relay-mgmt), `TestToken_NamesTheRelay`,
`TestClient_SignsForTheRelayItPinned` (publisher/deploy/mgmt), and the
shared vector, which the box must also refuse as a sibling. Rig:
`op:mgmtauth signed_for_another_relay` = refused (`--mgmt=tree`; the rig
has one relay, so the probe signs for another relay's name rather than
carrying a token between two).

**What is left after v2.** The nonce set stays, as defence in depth: it
stops the SAME request being applied twice. After a restart inside the
window a captured token can repeat the identical request once. Per verb:
`users-revoke`, `bind-address`, `unbind-address` are idempotent;
`rotate-tls` with the same body changes nothing (400); `users-provision`
of an existing name is 409; **`rotate-credentials` re-mints the same
recipient again**, cutting that one recipient off until re-delivered —
reachable only by somebody who holds a token (inside the pinned TLS
session), has a path to the port (two firewalls) and can restart the
daemon or the box within 300 s. Closing it means persisting the nonce set
or refusing tokens older than the process (which fails publishers with a
slow clock right after a boot); neither was done. A token is still spent
when it verifies, even if the handler then rejects the body. Not
exercised by the rig: `mgmtauth` does not restart the daemon mid-op (the
unit test does the equivalent); it does present a never-used token signed
for another body, and a correctly signed v1 token — both refused.

**Until relay-v1.5.1** this stayed true of any relay provisioned from the
old pin: `./run.sh --ops mgmtauth clean vless-reality` against
relay-v1.5.0 was red on `replay.users-revoke` while `--mgmt=tree` was
green. Since the pin moved (2026-11-19) both are green.

**Everything else the op tried was refused** on both binaries: no
`Authorization`, a valid token under `Bearer`, garbage, an empty signature,
a stranger's key, the publisher's signature for another endpoint
(`users-list` → `/users/revoke`, `rotate-credentials` → `/users/revoke`),
a token 400 s old, a token 400 s in the future, unsigned `/rotate-tls` and
`/bind-address`, and a replayed `/bind-address` token aimed at a second
address. After all of it the box's sing-box config was byte-identical and
the targeted recipient still connected.

## LC-O1 — `rotate-tls` says every recipient needs a new pack; six of seven families keep working

**FIXED (truth wave, lane A).** `daal-deploy rotate-tls` no longer has a
standing warning: `warnings` is empty after a clean rotation and
`next_step` says what is true (which route is affected; sign again and
publish). The wizard's `rotate_tls` now signs the pack again from the
relay's new identity and republishes the refresh note itself, and its
summary carries a verdict decided from four facts — did the cover host
move, does the relay have the route that carries it, does it have any
other route, can the files people hold learn about the change:
*nobody* / *nobody, apps heal by themselves* / *nobody, but offline
until their app checks* / *nobody is cut off, one route waits for a new
file* / *everyone*. "Everyone" is true in exactly one cell
(`who_needs_a_file_after_a_disguise_change`). The screen leads with that
sentence (en + fa) instead of "every file you have handed out is dead".
One step stays the operator's and the copy says so: Daal publishes the
note, never the file, so the newly signed file has to be put at the
download address. Rig: `op:l2 rotate-tls.does_not_claim_everyone_needs_a_file`.

What follows is the observation as it was written.


After L2 the verb prints *"every recipient needs a re-minted pack before it
will connect again"* and the app counts every live recipient as needing a
file by hand. Observed (`--ops l2`, all families): an old pack is dead on
**vless-reality only**; websocket-tls, naive, hysteria2, anytls,
shadowsocks and tuic connect exactly as before, because none of them puts
the cover host on the wire (their `tls.server_name` is the relay address)
and L2 touches no credential. The warning errs on the safe side; the cost
is an operator hand-delivering files during a blackout to people whose
phones would have connected on another route anyway. Not changed: what the
screen should say depends on which route a recipient's phone picks, which
is route selection.

## LC-O2 — `/whoami` could not be called by the publisher (fixed; released 2026-11-19 as relay-v1.5.1)

The box serves `/whoami` behind a token whose op must be `whoami`
(`opFromPath`). `mgmt.MintToken` refused to mint that op, and nothing
under `publisher/` or the wizard called the endpoint: a route the spec
counts, with a handler, a counter and a response type — and no caller
that could authenticate to it.

**Fixed (auth only; semantics untouched).** `whoami` is in the minter's
op → route table (`publisher/deploy/mgmt/token.go`, `GET /whoami`) and
`mgmt.Client.WhoAmI` calls it: it returns the parsed source address, and
tells "older box / unusable answer" (`ErrWhoAmIUnsupported`: 404, 405, a
body that is not an address — spec §4.7 says these must never fail a
publisher action) apart from a relay that refuses the token. Since token
v2 the method is under the signature, so the publisher's `GET` token is
refused on a `POST`. The fix itself is on the publisher's side; the v2
token it signs is accepted by the released daemon since relay-v1.5.1
(2026-11-19). **Nothing above the client calls it yet** — no CLI
verb, and the wizard's "verified helper address" slot is still filled by
the echo services. That wiring is app work.

## LC-O3 — the first freshness poll after an import always downloads the whole pack

`relaypack_refresh.go` describes "digest equal → done, no bundle fetch" as
the common case. The persisted record starts with an empty
`CurrentBundleSHA256`, so on the first poll after any import `Changed` is
true whatever the document says, and the pack is fetched and applied. That
is one extra download in the clear from the recipient's real address — and
it is what turns LC-2 from "breaks after a rotation" into "breaks on the
first poll". Recording the imported pack's digest at import time would
close both.

## LC-O4 — L1, L2 and L3 work end to end on the release artefacts

Not a defect; recorded because none of it had run outside unit tests. With
the then-**pinned** `daal-relay-mgmt` (relay-v1.5.0; world release.lifecycle
is green on relay-v1.5.1 since 2026-11-19),
`./run.sh --ops lifecycle clean vless-reality websocket-tls naive hysteria2`:
four recipients with distinct credentials all connect; a revoked one is cut
off and the others are not; `rotate-credentials` on one recipient kills
exactly that recipient's old pack on every family; `rotate-tls` moves the
cover host in both places on the box and the rebuilt pack connects;
`assign-fip` drives the real `/bind-address`, the relay answers on the new
address, the old pack dies when the censor blocks the old address and the
re-minted one connects; `floating-ip release` drives `/unbind-address` and
leaves the record, the box and the account clean. `/health` advertises
exactly what was observed to work. The reds in that run are LC-1, LC-2 and
LC-3.

## CEN-1 — a blocked route was "Connected", a success, and proven; the engine never classified a data-plane failure (fixed)

**Fixed — what "this route works" now means.** One real round trip through
the route's own outbound: a connection opened through the active outbound
to a host on the far side of the relay, and a TLS ServerHello read back
(`core/engine/proof.go`, `proof_singbox.go`). Nothing leaves the device
except through the tunnel. The far-side host is drawn at random from a
small set of very common sites and a second, different one is tried before
a route is called dead; the set is an ordinary engine configuration field
(`<state_dir>/engine-config.json`, `connection_check.targets`) with a
production default — the rig points it at its own "internet" hosts through
that file (`wb-client --proof-targets`), no lab seam. The target's
certificate is deliberately not verified: nothing is authenticated or sent,
and a phone with a wrong clock must not be told its route is dead.

* `SetRoute`: Start → **verifying** (`route_check: "verifying"` in the
  diagnostics blob, FSM state `Verifying`, event `Verifying`) → proof. Only
  a proof gives `pm.Connected()`, `RecordSuccess`, posture
  `ImportedActive`. A failed proof tears the instance down, classifies the
  failure by phase (CEN-2), `pm.Failed`, `RecordFailure` with the FSM's
  cooldown, posture → Recovery, and `SetRoute` returns an error wrapping
  `abi.ErrRouteNotCarrying`. Default bound: 2 attempts × 4 s.
* Core.mu is not held across the proof; `ClearRoute` or another `SetRoute`
  cancels it and nothing is recorded (`ErrConnectCancelled`).
* While connected, `abi.CheckActiveRoute` re-proves the route every ~3 min
  (±25 %), and at once on `NetworkChanged` to a different network. A route
  that stops carrying goes to `route_check: "failed"` with a category, a
  cooldown and a failure row; the instance is left running (stopping it
  would leave the phone's VPN interface up with nothing behind it), it is
  rechecked every 30 s and goes back to `ok` when it carries again. It is
  the function the prober of the next stage calls; it selects nothing.
* The app shows "Checking the connection…" while verifying and "Connected,
  but slow" for a degraded route (`client-ui/src/lib/routeCheck.ts`, en+fa).

**Measured.** Full run, 40 blocked sessions that assert a category: the
engine names the failure exactly in 26 and as the coarser thing one route
can see in 14 (CEN-4); none reports `none`, none is `proven`. Clean path:
`SetRoute` including the proof takes 7–13 ms per family in the lab (the
`set_route_ms` of each `connected` event) — one round trip.

**Not verified.** The phone: `engine_set_route` now blocks for the proof
(up to 8 s on a dead route; a tor route is given 90 s per attempt), and
the Kotlin/Rust callers were not run. The default public targets: the lab
has no internet, so only the configured-target path is exercised. A relay
whose own egress cannot reach any default target would fail the proof as
`unknown` (carry phase) although the relay is reachable.

*Since:* the Android VPN service made that blocking call on the main
thread (an ANR on a dead route); every engine call is now on a control
thread and a stop cancels the check (`DaalVpnService.kt` "THREADING";
compiled, still not run on a phone). The default targets were reviewed
and are argued in `specs/engine-abi-v1.md` "The default targets". A relay
that answers and reaches none of them is `relay_no_egress`, not
`unknown`, on the families whose dial includes the relay's answer.

As found:

**What.** `abi.SetRoute` treats `driver.Start` returning nil as "the tunnel
is up": it calls `pm.Connected()`, `store.RecordSuccess()`, moves the
posture to `ImportedActive` and publishes `state: Connected`
(`core/abi/abi.go`, `core/engine/engine_singbox.go`). But `Start` returns
as soon as the sing-box instance has started — sing-box dials the relay
lazily, on the first connection an app opens. Nothing after that point
looks at whether a single handshake succeeded:

* sing-box's log is the only place the dial error appears, and with a
  `PlatformInterface` in the context sing-box sets its default log writer
  to `io.Discard` (`sing-box@v1.13.12/box.go:145`); the engine registers no
  `PlatformLogWriter`. The error text never reaches `diagnostics.Classify`.
* `Classify` has exactly one production caller that sees an engine error:
  the `Start` failure path. A config error can be classified; a censor
  cannot.
* `ProbeUDP` / `ProbeDNS` / `ProbeTCP443` return `ProbeUnimplemented`.
* I found nothing above the ABI that checks connectivity either (a grep
  of the Kotlin, TS and Rust sources for a post-connect probe finds none);
  the phone was not used to confirm that.

So under every blocking censor in the library the engine's own account of
the session is: posture `ImportedActive`, why `"tunnel up on r1"`,
`failures: []`, `network_signals: []` — and after disconnecting,
`AvailableRoutes` lists the route with **`proven: true`, `health_pct: 100`,
`in_cooldown: false`**. Measured for 37 of 37 blocked (scenario, family)
cells across the 10 scenarios that block something and assert a category (the `engine.category` column); the same
for a relay that is null-routed, a border that forwards nothing at all, and
an SNI reset one millisecond after the ClientHello.

**Why it matters.** This is the input side of everything the failure
taxonomy is for. `specs/failure-taxonomy-v1.md` assigns each category a
path-manager behaviour (cool the route down, cool the family down, disable
UDP families for two hours, try another family); `activeNetworkSignals`
and `activeRouteFailures` project the stored category into route selection
and into the diagnostics blob the publisher's rotation recommender reads.
All of it is fed by `RecordFailure`, which a censor can never trigger. In
the other direction, `RecordSuccess` on a blackholed route is what puts the
"proven" badge and a full health bar on a route that has never carried a
byte, and resets `consecutive_failures` — the counter the recovery rule
uses to decide a stored failure is history. To the user: Connect goes
green, nothing loads, and the app's explanation is that the tunnel is up.
LC-3 and FAM-1 are two instances of the same thing found from other
directions.

**Reproduce.**

```
./run.sh --mgmt=tree relay-ip-block vless-reality hysteria2
#   family/vless-reality tunnel           expect=blocked              got=blocked
#   censor/vless-reality truth.category   expect=tcp_connect_timeout  got=tcp_connect_timeout   (raw probe)
#   family/vless-reality engine.category  expect=tcp_connect_timeout  got=none
#     … the engine reported none — posture=ImportedActive why="tunnel up on r1" proven_after=true
./e2e.sh full                               # the same for every blocking scenario × family
```

Evidence per session: `out/<run>/clients/NN-<family>/events.jsonl`, the
`disconnected` event — `explain` (`abi.DiagnosticsExplain()` taken while
the route was active), `diag`, `routes_after`.

**Why it was not fixed when found.** Not small and not obviously one thing. The engine
needs a definition of "this route works" that is true: a handshake through
the active outbound, or the first bytes back through the TUN, or sing-box's
dial errors (a `PlatformLogWriter`, or a wrapping dialer) fed to the
classifier — and each has a cost: a canary connection on every connect is
itself a fingerprint and needs a destination; byte accounting is declared
and unwritten (`HasByteAccounting = false`); and what is then done with the
classification is route selection, which this work was told not to touch.
The rig's `engine.category` check is the acceptance test for whichever is
chosen: it goes green, cell by cell, when the engine's report equals what
the raw probe saw.

## CEN-5 — after a failed connect the app said "Connecting…" for good, with nothing running (fixed)

**What happened.** CEN-1 made a failed connect honest inside the engine:
the instance is torn down, the route cooled down, `SetRoute` returns the
error, posture → `Recovery`, `route_check: "failed"`. The app maps
`Recovery` to "connecting" and had no words for `failed`, so the headline
read "Connecting…" / «در حال اتصال…» — indefinitely, because the engine
never selects another route. On desktop the connect call rejects after
about 8 s and a generic recovery sheet opens over that headline. On
Android `vpnStart` resolves as soon as the service is started and the
service stops itself when `setRoute` fails: no error at all, a permanent
"Connecting…", and a second tap meets the cooldown refusal.

A connected route that stops carrying (the liveness check) reads exactly
the same — `Recovery`, `failed` — and there the engine really is
re-checking every ~30 s. The app could not tell the two apart.

**The review's suggested discriminator does not exist.** It proposed
"`explain.active_route` is empty" for the failed connect. It is not: the
path manager keeps the route as current after a failure
(`routeDownLocked` → `pm.Resume`), so `DiagnosticsExplain` returns
`active_route` and `pick` for the torn-down route too (measured). Nothing
in either blob said whether an instance was running.

**Fix.**

* Engine: `engine_export_diagnostics` gains the always-present boolean
  `route_running` — true exactly while an engine instance for a route is
  up (`verifying`, `ok`, `degraded`, and `failed` after a liveness
  failure); false with no route and after a failed connect. Kept in the
  connection-check state and read under the same lock as `route_check`
  (`core/abi/route_check.go`).
* App (`client-ui/src/lib/routeCheck.ts`): `failed` + `route_running:
  false` is the **error** state — "Could not connect on this route. Try
  another one."; tapping the button opens the recovery sheet ("Try
  another route" …). `failed` + `route_running: true` stays "connecting"
  with its own words — "Connection lost. Trying again…". An engine that
  does not emit the field changes nothing.

**Pinned by.** `engine.failed_connect_not_running` (every blocked
session: the diagnostics captured right after the failed `set_route`
must say `route_running: false`); `TestRouteRunning_*` (core/abi);
`src/lib/routeCheck.test.ts`.

**Not verified.** The rig drives the engine, not the app: nothing renders
the page, and nothing was run on a phone. The wiring from the blob to
the page (`backends/tauri.ts`) is covered by the type checker only.

**Was still open, now fixed.** While a lost connection is being retried
the page is in the "connecting" state, where a tap meant *connect*: it
called `connect` for the same route, which the cooldown refuses, and the
recovery sheet opened — no way to disconnect from that state. A tap now
stops whatever the engine has running (`lib/routeCheck.ts` `tapAction`:
"Cancel" while a connect is being checked, "Disconnect" for a lost
connection; the Network page offers Disconnect for a running route too).
And the error a failed connect leaves ends when the cooldown that
failure started runs out: the engine reports `route_check: ""`, posture
`NoRoute` (`core/abi/route_check.go` `expireFailedConnect`;
`TestFailedConnectErrorClearsWhenTheCooldownEnds`,
`TestLostConnectionIsNotClearedByTime`). Not verified on a phone.

## CEN-2 — the classifier could not say what the taxonomy asks of it (fixed as far as one route can see)

**Fixed.** The string table stays locked and unchanged. Beside it, the
engine classifies a failed proof from an *observation* — the phase the
failure happened in (reach / handshake / carry), whether the transport is
UDP, whether the family's first flight is a TLS ClientHello, and the kind
of failure read from the error chain (`core/diagnostics/observe.go`,
`ClassifyObservation`; spec "Classification by phase"). So a swallowed
ClientHello is `tls_handshake_failed` and not `tcp_connect_timeout`, and a
reset right after a ClientHello is `tls_sni_or_cert_block_suspected` and
not `tcp_reset`. Where the error cannot be trusted to give a timeout's
phase (a multiplexed outbound re-dials on the expired context and reports
a connect timeout for a connection whose SYN was answered; naive reports
everything from inside Cronet) the engine makes one bare TCP connect to
the route's own address and port, after the attempt has failed, and takes
the phase from that. What is left — a name-keyed reset vs an address-keyed
one — needs a second name to the same address and is CEN-4.

As found:

**What.** Suppose CEN-1 were fixed by handing the dial error to
`diagnostics.Classify`. For each blocked cell the rig records, as evidence
on `truth.category` (`product_classify_of_that_error`), what the product's
classifier makes of the plain Go error a raw socket gets for that failure
(run through the real function, linked into `wb-client --classify`):

| the censor does | taxonomy category (raw differential probe) | the error a socket sees | `Classify` says |
|---|---|---|---|
| null-routes the relay | `tcp_connect_timeout` | `dial tcp4 …:443: i/o timeout` | `tcp_connect_timeout` ✓ |
| RSTs every flow to the relay on first data | `tcp_reset` | `read tcp4 …: read: connection reset by peer` | `tcp_reset` ✓ |
| RSTs only a ClientHello with the cover SNI | `tls_sni_or_cert_block_suspected` | the same string | `tcp_reset` ✗ |
| swallows a ClientHello with the cover SNI | `tls_handshake_failed` | `read tcp4 …:443: i/o timeout` | `tcp_connect_timeout` ✗ |

The two ✗ are not typos in a table. A string cannot carry what
distinguishes the cases: *where* in the handshake the failure happened (the
rule `"i/o timeout" && "tcp"` matches a TLS read timeout on a TCP socket as
readily as a SYN timeout), and *whether another name to the same address
survives* (which is the whole difference between "this address is burned"
and "this cover name is blocked"). The spec's behaviours differ sharply:
`tcp_reset` cools the route 30 min and the family 5 min;
`tls_sni_or_cert_block_suspected` cools the **family for an hour on this
network** — and for REALITY the right reaction to a blocked cover name is
neither (it is a new cover name: L2), while the right reaction to a
reset-by-address is a new address (L3).

These strings are the Go standard library's, as seen by a plain socket;
sing-box wraps them, it does not rewrite them, but the engine's actual
strings could not be captured (CEN-1: they are discarded). Treat the table
as the best case.

**Reproduce.** `./run.sh --mgmt=tree sni-rst vless-reality`, then
`grep truth.category out/latest/results.jsonl` — `first_flight_result_error`
and `product_classify_of_that_error`. Or directly:
`echo 'read tcp4 1.2.3.4:5->6.7.8.9:443: i/o timeout' | bin/wb-client --classify`.

**Why no string rule could fix it.** The mapping table is declared locked;
the classification had to be made where the stage is known (the
dialer) and, for SNI-vs-address, by a second probe (CEN-4).

## CEN-3 — three things a censor does that the taxonomy could not name (fixed)

**Fixed.** `specs/failure-taxonomy-v1.md` revision 2 names them:
`udp_address_blocked`, `udp_port_blocked`, and `path_too_slow` — a
*degraded* outcome: never `RecordFailure`, never a cooldown, its own
`degraded[]` list in the explanation and `last_degraded_*` columns in the
route store. It adds a fourth, `udp_no_reply`, for what one silent UDP
route can honestly say, and a rule that a network-wide category is never
derived from one route's silence. The scenarios now declare the new words
and the raw differential probe proves them (`truth.category`: another
host on the same port, then another port). Wired in the engine:
`udp_no_reply` (every silent UDP route) and `path_too_slow` (the whole
proof took longer than `slow_after_ms`, 2 s by default — see CEN-6, which
replaced the first rule: "the round trip that succeeded, or an earlier
attempt that timed out before the relay answered"). Under throttle-56k
the proof takes 0.8–6 s depending on the family and the run; a path fast
enough for the proof and too slow for a page is not detected until the
engine counts bytes. The scenario declares `path_too_slow`, and which of
"slow" and "nothing" the engine must have said is decided per connect by
the time it took (CEN-6). The two narrower UDP words are produced by
no engine path yet (CEN-4).

As found:

Found by writing down, per scenario and family, which category describes
reality (`"category"` in `scenarios/*.json`) and having a raw probe check it.

1. **UDP dropped toward one address** (`relay-ip-block`, hysteria2/tuic).
   UDP works to every other host. `udp_unavailable` is defined as "UDP probe
   to known echo target failed" and its behaviour is "disable UDP-based
   families on this network for 2 h" — wrong network-wide conclusion from
   one burned address; `tcp_connect_timeout` is TCP by name. The scenario
   declares `unknown`, which is what the raw ladder returns when the control
   host still gets the datagram. A QUIC family has no equivalent of
   `tcp_connect_timeout`.
2. **UDP dropped on one port** (`port-whitelist`: UDP/443 passes, UDP/8443
   does not). tuic is `udp_unavailable` by the letter of the spec; acting on
   it disables hysteria2, which is carrying traffic on UDP/443 in the same
   run. The category has no port.
3. **Connects, and is too slow to use** (`throttle-56k`: every handshake
   completes, no family moves 256 KiB each way in 10 s). There is no
   failure to classify and no category for "throttled"; the scenario
   declares `none`. With CEN-1 fixed by a handshake check, this stays
   invisible.

Also noted while declaring: `network_offline` ("no network at all") is not
observable from a route's seat in `total-blackout` — the link is up, the
gateway answers, every SYN times out; per route it is
`tcp_connect_timeout` / `udp_unavailable`, and only the aggregate says
"nothing works".

## CEN-6 — throttle-56k could not go red: a wrong "route is dead" behind a fresh-phone retry, an either-way cell, and a 5 s connect that read "Connected" (fixed)

**As found** (review of the tree, then six full `throttle-56k` worlds, then
two more while fixing it — the same in all of them). The scenario says
every handshake completes and every family connects. In every full run:

- the first naive phone and the first vless-reality phone FAILED their
  connect after 8 s: `abi: the route started but carried no traffic`,
  category `tls_handshake_failed` (naive; "cooldown 30m0s") or `unknown`
  (vless-reality; "cooldown 5m0s"), posture `Recovery`. The session's
  MustEstablish loop stopped that phone, started another with an empty
  state directory, and every check after that — `engine.category` among
  them — was about the second phone. Evidence: `connect_attempts: 2`,
  exit 0.
- the cell was declared `path_too_slow|none`, so "slow" and "nothing to
  report" were both green, on any family, in any run.
- websocket-tls, shadowsocks, hysteria2 and tuic came back plain
  "Connected" (`route_check: ok`) with `set_route_ms` between 4.7 and
  5.6 s: the first proof attempt had run out its 4 s AFTER the relay
  answered (phase carry), the second succeeded in about a second, and
  `runProof` counted a carry-phase timeout as "a dead target, says nothing
  about the route".

So on this scenario the engine could say dead, connected or slow and the
row stayed green.

**What the first-phone failures were.** Not the scenario: the phone
before. They happened to naive and to vless-reality and to nobody else —
the two families that come after hysteria2 and after tuic. A QUIC family
keeps sending for seconds after its client is gone, and a 56 kbit/s netem
queues what it cannot forward: measured at the start of each session,
the censor's qdisc toward the client still held 23–32 packets (≈ 43 kB,
nine seconds at that rate) after a QUIC session and 3–18 after the
others. The next phone's SYN sat behind them: `attempt 1 (reach): dial
tcp 203.0.113.10:443: i/o timeout | attempt 2 (carry): context deadline
exceeded`. A family run alone, or first, connected on its first phone
every time. One phone's traffic failing another phone's connect is
cross-talk of the rig.

**Fix.**

- Engine (`core/engine/proof.go`, `proofWasSlow`): a proof that succeeded
  is slow when the whole proof — failed attempts included — took longer
  than `slow_after_ms`. The person who tapped Connect waited through all
  of it, and the phase an earlier attempt died in cannot tell a dead
  target from a capped path. A 5 s connect is now "Connected, but very
  slow" (`path_too_slow`, degraded, no cooldown). Cost, accepted: one
  proof target that is silent from the relay's side makes the connects
  that draw it first read "slow"; they were.
- Rig, the retry: every connect attempt is recorded (`connects` in the
  `tunnel` evidence — what each phone was told, its category, posture and
  the cooldown line), and `engine.first_verdict` judges the FIRST one
  alone: it must be `connected`. The retry is kept, because
  `family/established` and the wire check need a connected engine, but it
  can no longer make anything green.
- Rig, the cell: the scenario declares `path_too_slow`. For one connect
  exactly one answer is right, and the time the connect took decides it
  (`slowCategoryFor`): over 2 s the engine must have said
  `path_too_slow`; within 2 s it must have said nothing (the taxonomy's
  "What one route can see"); either is accepted only in a 150 ms band in
  which `set_route_ms` cannot say which side the proof was on. A failure
  category is red in every case. A unit test refuses any scenario that
  declares an alternation.
- Rig, the cross-talk: before a session on a shaped link the driver
  waits until the censor's qdiscs are empty (`shaper_backlog_packets`,
  `waited_for_quiet_ms` on `control.before`; a shaper that does not drain
  in 60 s is a red `link.quiet`).

**After** (three full worlds): every first phone connected
(`connect_attempts: 1` everywhere), waits of 0.3–9.3 s for the queue,
connects of 0.8–3.0 s; `none` on the four connects under 2 s and
`path_too_slow` on the other three, each as its time requires. Heavy-loss,
lossy-throttle and clean are unchanged and green.

**Reproduce.** Before the fix: `./run.sh --mgmt=tree throttle-56k`, exit
0, and in `results.jsonl` `connect_attempts: 2` on naive and
vless-reality. The failure itself, now visible instead of retried away:
`WB_NO_QUIET=1 ./run.sh --mgmt=tree throttle-56k` → `engine.first_verdict`
red with the first phone's error, category and cooldown.

**Not verified:** on a phone or a real throttled network; the rig's
throttle is a symmetric netem cap.

### CEN-O5 — what the engine says behind seconds of queue

With `WB_NO_QUIET=1` (above) the first phone starts on a link that has
about nine seconds of somebody else's packets queued toward it. Its
connection proof is two attempts of 4 s; neither finishes; the engine
reports a failed connect — truthfully, nothing was carried — with the
category of a handshake that was swallowed (`tls_handshake_failed`, after
the reach check finds the address alive) or `unknown` (the relay answered,
then nothing), and the route is cooled down for 5 to 30 minutes. Ten
seconds later the same route connects in two.

**Fixed for what the engine can see moving.** From the error alone a
handshake still crawling when the budget ends is the same silence as one
a filter dropped. What tells them apart is a measurement, and the engine
now makes it (`core/engine/proof.go` "SLOW IS NOT SILENT",
`proof_singbox.go`): bytes that came back from the far side before the
attempt timed out; a connection to the relay that completed a second or
more after it was asked for; the relay's address answering the reach
check's bare SYN that late (seconds behind a queue, milliseconds under
an SNI filter). With any of those, and only then, the proof makes one
more attempt with a 20 s budget (`slow_budget_ms`). A route that
completes it is connected and `path_too_slow`; one that does not fails
as `path_too_slow` — no cooldown, no failure row, no network signal
(`specs/failure-taxonomy-v1.md` revision 3). A route on which nothing
was seen moving fails in 8 s as before.

* `./run.sh --mgmt=tree deep-queue` — a new scenario: 1.2 s of delay each
  way, nothing dropped, 2.4 s per round trip. All seven families connect
  on the first phone and report `path_too_slow`; the connects took 7–15 s
  (vless-reality 15.3 s, shadowsocks 12.8 s, naive 10.4 s — each past the
  old 8 s bound, where it was "could not connect" and a cooldown).
* `WB_NO_QUIET=1 ./run.sh --mgmt=tree throttle-56k` — the run that showed
  the observation: `engine.first_verdict` is now `connected` on every
  family, all `path_too_slow` or `none` as their time requires.
* Unit: `TestRunProof_SlowPath*`, `TestRunProof_SilentPathGetsNoExtraTime`
  (core/engine), `TestProveSubject_SlowPathConnectsSlowInsteadOfFailing`,
  `TestProveSubject_SwallowedHelloGetsNoLongAttempt` (`-tags singbox`),
  `TestSetRoute_SlowPathFailureIsNotCooledDown` (core/abi),
  `TestClassifyObservation_TimeoutWithProgressIsNeverABlock`.

**Still open.** A QUIC route has no TCP to the relay and hands over no
connection until its own handshake is done, so one whose handshake needs
longer than a 4 s attempt shows nothing moving and is still
`udp_no_reply` with a cooldown. hysteria2 and tuic connect at 2.4 s per
round trip; no scenario goes far enough to show the failure, and fixing
it needs the engine to count datagrams. The rig's session wait for
`connected` was 20 s, shorter than a check that takes the long attempt:
it is now `EngineConnectWait` (40 s), and a raw probe's own timeouts can
be lengthened by a scenario that delays (`probe_patience_ms`).

**A mid-session block was `unknown`** on the families that hold a
session to the relay (multiplexed, pooled, QUIC): the liveness check's
dial was answered from that session, so all it saw was "a connection,
then nothing" — the carry phase. After such a timeout the proof now
opens one more outbound with the route's own options and classifies by
what an attempt through THAT sees (`proofSubject.diagnose`): the block is
named as a failed connect through it would be. No scenario blocks
mid-session; pinned by
`TestProveSubject_MidSessionBlockIsClassifiedLikeAFailedConnect`, which
first shows the same block reading carry/`unknown` without the fresh
connection.

## CEN-4 — one route cannot tell apart what needs two observations

**What.** The connection proof (CEN-1) makes one observation per route.
Several taxonomy categories are statements about the network and need
two. The engine reports the category that is true of what it saw and
never guesses the narrower one:

| the censor does (raw differential probe) | the engine reports | to tell apart it would need |
|---|---|---|
| `udp_unavailable` (all UDP dropped) | `udp_no_reply` | a datagram to another host and port |
| `quic_unavailable` (QUIC-shaped datagrams dropped) | `udp_no_reply` | a non-QUIC datagram to the same endpoint |
| `udp_address_blocked` | `udp_no_reply` | UDP to another host on the same port |
| `udp_port_blocked` | `udp_no_reply` | UDP on another port |
| `tcp_reset` keyed on the address, TLS family | `tls_sni_or_cert_block_suspected` | a ClientHello with another name to the same address |

Full run: 14 of the 40 blocked sessions (11 UDP, 3 reset —
tcp-reset-mid-handshake × vless-reality, websocket-tls, anytls). The
report's ENGINE CATEGORY line lists every truth → reported pair.

**Why it matters, and why it is not worse.** `udp_no_reply` cools down the
one route for 5 minutes and nothing else; the wrong answers it replaces
(`udp_unavailable`, `quic_unavailable`) would disable every UDP family on
the network for two hours on the evidence of one dead address. But
selection cannot yet learn "UDP is gone here, skip hysteria2 and tuic"
from the engine — it will try each. `tls_sni_or_cert_block_suspected`
cools the family for an hour where `tcp_reset` would cool it for five
minutes: on an address-keyed reset that is the harsher of the two.

**Reproduce.**

```
./run.sh --mgmt=tree relay-ip-block hysteria2            # expect=udp_address_blocked got=udp_no_reply
./run.sh --mgmt=tree tcp-reset-mid-handshake vless-reality   # expect=tcp_reset got=tls_sni_or_cert_block_suspected
```

**Narrowed by the automatic connect (2026-11-19).** `engine_connect_auto`
tries route after route, and two routes of one pack to one address are
two observations. What one route reports is unchanged (`category` in
`tried[]`, `route_check_category`, the table above — a route connected by
hand still has only itself); the pass adds `refined` beside it
(core/abi/connect_auto_verdict.go `deriveAuto`):

| the censor does | the QUIC route alone | another route of the pass saw | `refined` | rig check (`op:auto`) |
|---|---|---|---|---|
| every UDP datagram dropped, to anyone | `udp_no_reply` | TCP to the same address carried | `udp_blocked_here` | `memory.udp.refined` — green |
| the relay's address null-routed | `udp_no_reply` | TCP SYNs to the same address unanswered | `relay_unreachable` | `all-blocked.connect.refined` — green; scenario relay-ip-block: `scenario.connect.verdict` |
| QUIC Initials dropped, plain UDP delivered | `udp_no_reply` | TCP to the same address carried | `udp_blocked_here` | `quic-only.connect.refined` expects `quic_blocked_here` — **red, known** |

So "is it the address or is it UDP" is decided, which is the question
that sends a person for a new file or not. What is still one answer:

* **all UDP dropped / a QUIC-only filter / one dead UDP port** — all
  `udp_blocked_here`. No route of a pack sends a non-QUIC datagram to the
  relay, so no pass can separate them (AUTO-O2: the wording for the code
  must say "the fast ways did not get through", not "UDP is blocked").
* **name-keyed vs address-keyed reset** — `name_blocked` /
  `address_blocked` need two routes with different TLS names to the same
  address AND port. Today's packs put every family on its own port, so
  the rig has no world in which the engine could say either, and
  `tcp-reset-mid-handshake` stays as it was.
* **a route connected by hand** — one observation, as before.

The second observation exists only when the QUIC route is actually
tried, and a fresh phone tries the TCP routes first and connects: the
three rows above are staged by first connecting the QUIC route (so the
phone remembers it carried here and tries it first).

**Not done.** The second observation is a probe the device sends outside
any route (another host, another port, another name) — what it sends and
to whom is a fingerprinting decision and belongs to the prober of the
selection stage, which this change was told not to build.
`abi.CheckActiveRoute` and `diagnostics.ClassifyObservation` are where its
result plugs in; the categories and their behaviours are already in the
spec. Acceptance: the known-findings entry goes stale cell by cell.

## CEN-O1 — shadowsocks and anytls answer opaque bytes with an instant reset

In a clean world, 8 opaque bytes (first byte 0xb7) to each relay port, from
a plain socket:

| port | family | reaction |
|---|---|---|
| 443 | vless-reality | forwarded to the cover site; orderly close in ~1 ms |
| 8444 | naive | silence (still waiting after 2.5 s) |
| 8445 | websocket-tls | silence |
| 8446 | shadowsocks | **TCP RST in < 1 ms** (`shadowsocks: serve TCP …: bad header` in the relay's log); a TLS ClientHello gets the same |
| 8447 | anytls | **TCP RST in < 1 ms** |

An immediate, input-dependent reset is the kind of reaction the active
probing literature used to tell Shadowsocks servers apart (Alice et al.,
IMC 2020; `research/protocol-level-anatomy.md`). It also shaped the rig:
an opaque-first-flight family's "reset after data" is attributed to the
censor only when the censor's own DPI log shows a rule fired on that flow.

Reproduce: `./run.sh --mgmt=tree --shell clean`, then
`ip netns exec client bin/wb rawprobe --kind bytes --addr 203.0.113.10 --port 8446`.

**Where the reset comes from (read in the Go module cache, sing-box
v1.13.12 — what the relay runs; 2026-11-18).** One function, in the
shared library, for both families:

* `github.com/sagernet/sing@v0.8.10/common/network/handshake.go`,
  `CloseOnHandshakeFailure` (lines 36–61): when the handshake failed and
  the connection is not one that can write a protocol-level failure
  itself, it calls `SetLinger(0)` and then `Close()`. Linger 0 makes the
  kernel send **RST instead of FIN**, at once, whatever is or is not in
  the receive buffer.
* **shadowsocks** — `sing-box/protocol/shadowsocks/inbound_multi.go:141-143`
  (`MultiInbound.NewConnectionEx`): `err := h.service.NewConnection(…)`
  then `N.CloseOnHandshakeFailure(conn, onClose, err)`. The service is
  `sing-shadowsocks@v0.2.8/shadowaead_2022/service_multi.go`,
  `NewConnection0`: ONE `Read` of the fixed request header (salt + 16-byte
  identity header + the AEAD-sealed fixed chunk); fewer bytes than that is
  `ErrBadHeader` immediately, and a full-length header that does not
  decrypt, repeats a salt or carries a timestamp more than 30 s off is an
  error just the same. Every one of them ends in the linger-0 close. So:
  **any first flight that is not a valid, fresh request from a known user
  is reset at once.** This is the "consistently send RST" branch the
  Shadowsocks 2022 specification allows precisely so that the reaction
  does not reveal how many bytes the server consumed — the reset is
  consistent, it is not the old length-dependent tell. What it remains is
  a port that resets everything that is not its own protocol, instantly,
  where a web server would answer or wait.
* **anytls** — `sing-box/protocol/anytls/inbound.go:101-114`
  (`Inbound.NewConnectionEx`): TLS first (`tls.ServerHandshake`); bytes
  that are not a TLS record fail the handshake and go to
  `N.CloseOnHandshakeFailure` → **RST, where an ordinary TLS server sends
  an alert and/or FIN.** A correct ClientHello completes TLS (the leaf is
  self-signed) and reaches
  `github.com/anytls/sing-anytls@v0.0.11/service.go`, `NewConnection`:
  one read, the first 32 bytes are compared with the users' password
  hashes, and anything else goes to `s.fallback(…)` — which, with no
  fallback handler configured, returns `"fallback disabled"`, and the
  inbound again closes with linger 0. (Read from source; the rig measured
  the pre-TLS case only.)

**No configuration gives a drain or a timeout.** Checked field by field in
`sing-box@v1.13.12/option`: `ShadowsocksInboundOptions` is listen options
+ `network`, `method`, `password`, `users`, `destinations`, `multiplex`,
`managed`; `AnyTLSInboundOptions` is listen options + TLS + `users`,
`padding_scheme`; `ListenOptions` has no handshake-timeout or
reject-behaviour member (`listen`, `listen_port`, `bind_interface`,
`routing_mark`, `reuse_addr`, `netns`, the keep-alive trio,
`tcp_fast_open`, `tcp_multi_path`, `udp_fragment`, `udp_timeout`,
`detour`, `proxy_protocol*`); `InboundTLSOptions` has none either. The
`fallback` / `fallback_for_alpn` option that hands unauthenticated
connections to a real web server exists on the **trojan** (and vless
vision) inbounds only. So nothing in `daal-relay-mgmt`'s config generation
can change this, and nothing was changed.

**What it would take upstream (not forked, not patched — recorded).**

1. anytls, after TLS: expose a `fallback` option on the anytls inbound
   and pass it as `anytls.ServiceConfig.FallbackHandler` —
   `sing-anytls` already has the hook (`service.go:27,35,47,127`);
   sing-box 1.13.12 simply never sets it. A probe that speaks TLS and
   then HTTP would then get a real web server's answer.
2. anytls, before TLS, and shadowsocks: an inbound option (or a change of
   default in `CloseOnHandshakeFailure`) to **not** set linger 0 — close
   the write side and drain until the peer closes or a timeout, which is
   what an idle TCP service looks like and is the other behaviour the
   Shadowsocks 2022 specification permits. That is in `sagernet/sing`
   (shared by every inbound) plus one option per inbound in sing-box.
3. Either is an upstream feature request / PR against sing-box ≥ 1.14;
   picking it up means a new sing-box pin on the relay (a relay release)
   and nothing on the phone.

**What Daal does with it today.** Both families are opt-in, off by
default, and carry `probing_risk_class: moderate` in every shipped
profile (`publisher/deploy/profiles/*.json`) where the four default
families carry `low`; that field is what the recommender reads.
`docs/transport-family-inventory.md` ("How each relay port answers a
stranger") states the tell per family, so the selection work can
deprioritise these two where active probing is seen. shadowsocks is also
the one family with no TLS at all, which is why it exists (it survives a
TLS-fingerprint classifier) and why this is its cost.

## CEN-O2 — what each family shows an SNI filter

From `out/<run>/dpi-events.jsonl` and the packs: vless-reality sends its
cover host as `server_name`, in a 600-byte ClientHello that fits one TCP
segment — so `sni-rst-stateless`, which reads only the first data packet
and is beaten by any hello split in two, still catches it. Every other
family's profile names the relay by IP literal (`server_name:
"203.0.113.10"`), which Go and uTLS do not send as SNI: websocket-tls,
naive, anytls, hysteria2 and tuic put **no** name on the wire. They are
untouched by all three SNI scenarios for that reason alone — and a TLS
ClientHello with no SNI to a bare VPS address, presenting a self-signed
certificate, is its own kind of visible. Not modelled; noted.

## CEN-O3 — heavy loss separates the QUIC families from the TCP ones

With 30% independent loss in each direction on everything, hysteria2 and
tuic completed the 256 KiB-each-way fetch in 8 of 8 sessions (7–11 s
against ~40 ms clean; an app's single UDP datagrams through them were then
lost about as often as arithmetic says), and all five TCP families failed
it in 20 of 20 (a fraction of the payload after 10 s). `scenarios/heavy-loss.json`
asserts the robust half — TCP-only loss, TCP families blocked, QUIC
families pass — because a pass that depends on finishing inside a budget
by a second is not an assertion.

## CEN-O4 — naive gives up with `EOF` where the others get through

Seen while tuning the degraded-path scenarios, not root-caused. With 60 ms
delay, 3% loss and 2 Mbit/s each way (what `lossy-throttle` was before it
was relaxed to 1% / 4 Mbit/s), one naive session in three ended on its very
first request after 501 ms with `Get "http://192.0.2.80/whoami…": EOF`,
while all six other families completed the same fetch in the same world in
4.5–8.6 s. Under `throttle-56k` naive fails the same way (`EOF` at ~5 s)
where the others run out the 10 s budget still transferring. An `EOF` on a
first request is not a timeout: something on the naive path closed the
connection early. Six runs at 1% / 4 Mbit/s were clean.

Reproduce (repeat a few times): temporarily set both `tc` lines of
`scenarios/lossy-throttle.json` to `netem delay 60ms loss 3% rate 2mbit`,
then `./run.sh --mgmt=tree lossy-throttle naive`; or
`./run.sh --mgmt=tree throttle-56k naive` and read the `tunnel` detail.

---

# Integration findings (INT-*) — found by running the whole matrix repeatedly

## INT-1 — naive: the engine process dies with SIGSEGV in Cronet when a connection closes as its stream terminates (fixed)

**What.** During the third consecutive run of the full matrix, one naive
session's engine process (`wb-client`, i.e. `daal/core/abi` with the
phone's build tags `with_naive_outbound,with_purego`) died:

```
SIGSEGV: segmentation violation
PC=0x7ea491759089 m=10 sigcode=1 addr=0x8
signal arrived during cgo execution

github.com/ebitengine/purego.RegisterFunc.func4(...)
github.com/sagernet/cronet-go/internal/cronet.BidirectionalStreamCancel(...)      api_purego.go:1032
github.com/sagernet/cronet-go.BidirectionalStream.Cancel(...)                     bidirectional_stream_purego.go:107
github.com/sagernet/cronet-go.(*BidirectionalConn).Close(0x249e38b1000)           bidirectional_conn.go:272
github.com/sagernet/cronet-go.(*trackedNaiveConn).Close(0x249e383e9c0)            naive_client.go:550
github.com/sagernet/sing-box/route.(*ConnectionManager).connectionCopy(...)       route/conn.go:271
```

The head of that stderr is kept as `driver/testdata/cronet-cancel-crash.stderr`.

**Why.** A check-then-act race in `cronet-go` (the version `core/go.mod`
resolves, `v0.0.0-20260513071958-2faf34666c2c`), `bidirectional_conn.go`:

```go
func (c *BidirectionalConn) Close() error {
	c.access.Lock()
	… // not done yet
	close(c.close)
	c.access.Unlock()
	if c.cancelled.CompareAndSwap(false, true) {
		c.stream.Cancel()          // (2) …on a stream that (1) may just have freed
	}
```
```go
func (c *BidirectionalConn) terminate(err error) {   // Cronet's network thread: OnSucceeded / OnFailed / OnCanceled
	c.access.Lock()
	onTerminate, marked := c.markTerminatedLocked(err)   // sets cancelled = true — too late if Close already won the CAS
	c.access.Unlock()
	…
	if marked {
		c.stream.Destroy()         // (1)
```

`cancelled` stops a second `Cancel`; it does not stop `Destroy` from
running between `Close`'s CAS and its `Cancel`. When the far end finishes a
stream at the instant sing-box closes the same connection, `Cancel` is
called on a destroyed native object (`addr=0x8`: a field of a null
pointer). The same pattern is at lines 161 and 215 (the read/write
deadline paths).

**Why it matters.** It is not an error return; the process is gone. In the
rig the insider's routing was left pointing at a dead TUN. naive is a
default family and the one described as field-proven.

**What is observed and what is inferred.** Observed: the crash, on this
laptop, in the rig (linux/amd64, glibc, the desktop `libcronet`), and the
race in the source, which is plain Go in `cronet-go` and not specific to a
platform. The phone build compiles the same file with the same tags
(`tools/build-engine-android.sh:76`). **Inferred, never observed on a
device:** that it fires there, and what follows. The engine is loaded into
the VPN service's process (`libdaalcore.so`), so a SIGSEGV would kill the
service: the tunnel drops, and whatever Android does next (restart, or
traffic outside the tunnel if "block connections without VPN" is off)
happens with no diagnostics, because the engine never got to record
anything. But the window is a few instructions wide and depends on
scheduling; the phone has different cores, a different Go/cgo thread mix
and the bionic build of `libcronet.so`, so the rate there may be far lower
than here, or higher — the rig's 3-in-104 was under four worlds of
back-to-back naive sessions, which is not how a phone is used. "Field-proven"
does not settle it either way: an occasional VPN drop that reconnects is
exactly what nobody reports.

**Phone confirmation (to do; decides the priority).** Use a naive route
for a normal day, or force churn (open and close many pages, toggle
airplane mode a few times), then:

```
adb logcat -b crash -d | grep -B2 -A30 -E 'SIGSEGV|Fatal signal 11'
adb logcat -d | grep -E 'BidirectionalStreamCancel|libcronet\.so|libdaalcore\.so'
```

A hit is a native crash of the app's VPN process (`Fatal signal 11
(SIGSEGV)` or Go's own `SIGSEGV: segmentation violation` /
`signal arrived during cgo execution`) with `BidirectionalStreamCancel` or
frames in `libcronet.so` / `libdaalcore.so` in the backtrace; unexplained
VPN drops on naive with such a tombstone confirm it. No hit after sustained
naive use does not prove absence, but it does put this below findings that
are certain on the phone (CEN-1, for one). Until then read the "high" in
the table as "high if it fires on the phone": the consequence is severe,
its frequency on a device is unknown.

**How often.** Load-dependent. Once in the several hundred naive sessions
of four consecutive full matrices; then 3 times in 104 sessions (three of
four worlds, one each) with four worlds doing nothing but naive sessions
side by side. Every one has the identical stack.

**Reproduce.** Not deterministic, but quick:

```
for i in 1 2 3 4; do WB_RESTART_CYCLES=25 ./run.sh --mgmt=tree --ops restarts clean naive & done; wait
```

and look for a red `engine.survived` in the output (while the finding was
open it printed as `KNWN … engine.survived … [INT-1]`; it is now an
unexpected red that fails the run); each hit keeps its stderr under
`out/<run>/clients/NN-naive/stderr.log`.

**What the rig does.** A session whose engine process dies records a
red `engine.survived` with the crash signature, removes the dead VPN's
routing the way Android would, and repeats the session once — so a crash
is one red check with a name, not (as on first sight) "DNS blocked on
naive" plus "ip rule: File exists" on the next family. While this finding
was open that check was excused, pinned to the signature
(`BidirectionalStreamCancel`, family naive) with a per-run budget. It is
not excused any more: any engine death, on any family, fails the run.

**Fixed by a dependency bump — proven on Linux, NOT on Android.**

*Upstream.* `cronet-go` fixed exactly this on 2026-09-12: commit
`172bb4ede18c`, "Fix bidirectional stream cancel racing with destroy" —
`cancelled` becomes a plain bool guarded by `c.access`, `Close` and the
two deadline paths call `cancelLocked()` under the lock, and `terminate`
calls `Destroy` under the same lock. No tagged release contains it (the
newest Go-importable tag, `v0.0.1-143.0.7499.109-1`, is from December
2025 and older than what was pinned); it ships as the module-branch build
`v0.0.0-20260912104727-0d28acc44093`, which is what **sing-box 1.14.1
and later** pin. sing-box 1.13.x never picked it up (1.13.21 pins
`20260807…`).

*What was done.* `cronet-go` and `cronet-go/all` are bumped to that build
— and `cronet-go/lib/*` to the matching `20260912104006-c10c03c318db` —
in `core/go.mod`, `cmd/daal-core`, `cmd/daal-soak-engine` and the rig's
`labclient`. sing-box stays at 1.13.12; its naive outbound compiles
against the newer cronet-go unchanged. No fork, no `replace`.

*Proof.* The reproduction above, on this laptop, on an isolated copy of
`main` plus this change:

| cronet-go | worlds | naive sessions | engine deaths |
|---|---|---|---|
| `20260513…` (was pinned) | 20 | 520 | 3 — two with the `BidirectionalStreamCancel` stack above, one glibc abort `double free or corruption (!prev)` with no Go stack |
| `20260912…` (now pinned) | 40 | 1040 | 0 |

The rate before is lower than the 3-in-104 first recorded, because the
relay no longer restarts twice per revoke (INT-O1). The glibc abort is a
second way the same use-after-free can end; it was not in
`known-findings.json` and would have failed a run on its own. With the
old rate (~0.6 %), 1040 clean sessions happen by chance about one time in
400. The entry is deleted from `known-findings.json`: an engine death on
naive is an unexcused red check again.

*What is NOT verified — read this before shipping an APK.* Only
linux/amd64 was run, with the `libcronet.so` that ships inside the
`lib/linux_amd64` module at the matching version. On Android the library
is not taken from a module: it is relinked by hand from
`lib/android_*/libcronet.a` (`tools/cronet/build-libcronet-android.sh`,
a multi-GB Chromium toolchain) and reused across engine builds. **The
bump changes that library's C ABI** — `Cronet_Engine_SetUdpDialer` gained
an argument between the two versions, for one — so an APK that packages
the old `libcronet.so` beside the new Go wrapper is undefined behaviour,
not a fixed crash. Two guards were added because of that, neither of
which was run against a real NDK here:

* `build-libcronet-android.sh` now relinks the `libcronet.a` of the
  version `core/go.mod` pins (it took whichever sorted first in the
  module cache — after a bump, the old one) and writes a version stamp
  beside the `.so`;
* `build-engine-android.sh` refuses to package a `libcronet.so` whose
  stamp is missing or does not match (`tools/cronet/check-libcronet-
  stamp.sh`; `DAAL_NAIVE=0` builds without naive). Every existing
  `libcronet.so` is unstamped and will be refused until rebuilt.

So: **the Android `libcronet.so` must be rebuilt for all shipped ABIs
before the next APK**, and naive must be exercised on a phone afterwards.
Nothing here shows the race ever fired on a device, and nothing here
shows the new pair works on one.

*Update, same day (TW-3) — rebuilt, and both guards run against NDK r27.*
Three things in the paragraph above turned out wrong or incomplete when
the build was actually run:

* The relink does **not** need the multi-GB Chromium toolchain. Only the
  arm64 archive defeats the NDK's linker (R_AARCH64_GOTPCREL32,
  "relocation 315", unknown to LLVM 18's lld); any lld from LLVM 20
  links it, and the one bundled with the Rust toolchain — already a hard
  requirement of the Android app — is picked automatically. armeabi-v7a
  and x86_64 link with the NDK's own.
* The relink as written **could not have produced a library from the new
  archive**: the 2026-09 `libcronet.a` carries the real pre-freeze memory
  trimmer, which `cronet_stubs.cc` also defined — six duplicate-symbol
  errors. The stubs are weak now (used only where the archive has
  nothing), and the link runs with `-z defs`.
* The stamp could be forged by accident: it was a file holding a version,
  so a May library with that file copied beside it passed. Old and new
  libraries export **exactly the same 246 `Cronet_*` names**, so nothing
  at load time tells them apart either. The library now carries its
  origin in its own bytes (module, version, sha256 of the archive), the
  stamp adds the sha256 of the `.so`, and the engine binary's own build
  info is the third record; `tools/check-android-so-manifest.sh` (run by
  both `.so` manifest gates) refuses a set where they disagree.
  `tools/cronet/selftest-check-libcronet-stamp.sh` holds the cases.

`build-engine-android.sh` builds the library for all three ABIs when the
staged one is missing or stale and fails otherwise; both build scripts
now link for 16 KB pages (everything Go-built was 4 KB-aligned).

**Still not verified: anything on a device.** The checks are static —
identity, exported symbols against what the wrapper looks up, every
undefined symbol present in the API-24 system libraries, no ELF TLS, no
text relocations, 16 KB alignment. Nobody has `dlopen()`ed these three
files. Naive on a phone is TW-4 (c)/(d).

*Also not verified*: iOS/darwin/windows builds; `cmd/daal-soak-engine`
beyond `go build`.

*Upstream report*: none to file — upstream found and fixed it. If a
reference is wanted for a sing-box 1.13.x backport request: "naive
outbound: process SIGSEGV in `cronet-go` `BidirectionalConn.Close` →
`BidirectionalStream.Cancel` racing `terminate` → `Destroy` (fixed in
cronet-go 172bb4ede18c, shipped in 1.14.1); 1.13.21 still pins
cronet-go ec9a39c5ba3b, which has the race."

## INT-2 — naive: a relay whose naive inbound refuses every TLS handshake until sing-box restarts (root-caused: sing-box start-up race; fixed in the daemon, released 2026-11-19 as relay-v1.5.1)

**Released 2026-11-19.** The daemon that writes the `alpn` key is the
pinned `daal-relay-mgmt` of relay-v1.5.1; the `INT-2` entry (box=pinned,
intermittent, budget 4) is deleted from known-findings.json, so a naive
session with this face is an unexpected red on any box. Last full run:
`PASS — 5388 checks`, 18 worlds. The upstream race itself is not fixed.

**Classification: product, on the relay — an upstream sing-box defect that
Daal's box config exposes.** It was filed as "unclassified: product or
lab" because the rig's systemctl shim performs the restarts; the second
sighting came with the shim's lifecycle journal and exonerated it, and the
defect was then reproduced with no Daal code and no shim at all.

**Root cause.** sing-box 1.13.12, `protocol/naive/inbound.go` `Start`.
The inbound has a TCP half (HTTP/2) and a UDP half (HTTP/3) sharing ONE
tls config, and each half fills in ALPN if nobody configured it:

```
TCP goroutine:  if len(NextProtos) == 0 { Set([h2 http/1.1]) } else if !has(h2) { prepend h2 }
caller (UDP):   sing-quic ConfigureHTTP3: if len(NextProtos) == 0 { Set([h3]) }
```

Check-then-set from two goroutines. Almost always the caller runs first
and the result is `[h2 h3]`. When both read "empty" and the caller writes
last, the result is `[h3]`: for the whole life of that process the TCP
listener rejects every ClientHello that offers `h2` — every Daal naive
client — with the fatal alert `no_application_protocol` (120). That is the
7-byte record the wire tap saw; Cronet reports it as `net_error -107`.
sing-box logs nothing, the other inbounds are unaffected, and the next
restart of sing-box (any provision, revoke or rotation; a reboot) rolls
the dice again. Daal's mgmt daemon wrote `naive-in` with no `alpn` key, so
every start of every relay ran this race.

**Reproduction without Daal.** `repro/int2-naive-alpn-race.sh` starts the
released sing-box binary with one naive inbound on loopback, offers ALPN
h2 with `openssl s_client`, stops it, and repeats (12 workers × 250):

```
./repro/int2-naive-alpn-race.sh          starts=3000  served_h2=2997  dead(alert 120)=3
./repro/int2-naive-alpn-race.sh pinned   starts=3000  served_h2=3000  dead(alert 120)=0
```

The rate depends on parallelism and load; 1 in 1000 was measured with 12
busy workers on this laptop. On a small idle VPS it is probably lower, on
a single-vCPU box it may be unreachable — not measured.

**What it means on a real relay.** Each sing-box start has a small chance
of leaving naive dead until the next start, silently. A publisher who
provisions a recipient and stops there may have handed out a relay on
which naive never works; the recipient sees "Connected" and nothing
loads (CEN-1), and nothing on the box says why.

**Fix (released as relay-v1.5.1).** `appendNaiveUser` now writes
`"alpn": ["h2", "h3"]` into `naive-in`'s tls block — exactly the value the
usual interleaving produces, so a good start behaves as before — and with
the key present neither branch writes, so there is no race. It is applied
on every user add, so an inbound created by an older daemon is healed by
the next provision; an explicit alpn is left alone. Pinned by
`TestAppendNaiveUserCreatesInbound` and `TestNaiveALPNHealsAnOlderInbound`.
3000 starts with the key: 0 dead (3000 without: 3). That count alone would
be thin; the argument is the source — with the key set there is no write.

**What is still open.**

- ~~**Released relays.**~~ Closed 2026-11-19: the pinned
  `daal-relay-mgmt` (relay-v1.5.1) writes the key. A relay built from
  relay-v1.5.0 would run the race on every start; no such relay is in
  service.
- **Upstream.** The race is sing-box's; it should be reported there. A
  sing-box bump does not need Daal's key removed.
- **Not checked:** whether other sing-box inbounds that serve both TCP and
  QUIC from one tls config have the same pattern. Daal's other inbounds
  are single-transport (tuic already carries an explicit alpn).

**The two sightings, for the record.**

First: in one quick-mode run (no censor, tree daemon), op `revoke`:

```
15:10:13.18  verb.users-revoke.r2                 pass   (4766 ms; the relay's sing-box restarted twice)
15:10:14.42  anytls     bystander.tunnel          pass
15:10:15.72  hysteria2  bystander.tunnel          pass
15:10:16.70  naive      revoked.tunnel            blocked   ← expected, but see below
15:10:17.68  naive      bystander.tunnel          blocked   ← r1, never revoked; expected pass
             whoami: Get "http://192.0.2.80/whoami?…": EOF      (after 3 ms)
```

The engine's stderr for BOTH naive sessions (Cronet logs nowhere else):

```
ERROR:net/socket/ssl_client_socket_impl.cc:924] handshake failed; returned -1, SSL error code 1, net_error -107
ERROR:net/socket/ssl_client_socket_impl.cc:924] handshake failed; returned -1, SSL error code 1, net_error -107
```

`-107` is `ERR_SSL_PROTOCOL_ERROR`. The wire tap saw 12 packets go to
8444/tcp and 8 packets / 446 bytes come back for the two connections —
SYN-ACK, ACK, a 7-byte record and a FIN each: the relay's naive inbound
answered each ClientHello with a TLS alert and closed. The other inbounds
of the same sing-box process were serving normally a second earlier, and
naive itself worked before the verb and again after the next one. The
"revoked" session one second earlier failed the same way — so it was
`blocked` for the wrong reason, and its green cell proved nothing that
time. The engine reported Connected throughout (CEN-1).


Second (`./e2e.sh full`, world release.lifecycle, pinned box, op `l1`):
one naive session, `before.tunnel` blocked with the same stderr, 0.5 s
after a restart. The shim's journal for that instance:

```
16:56:12.791 stop pid=352: TERM in 0.111s; it held 5 listener(s) […]; none left listening
16:56:12.792 restart: new pid=380
16:56:13.297 (client) handshake failed … net_error -107        ← on pid 380
16:56:15.757 stop pid=380: TERM in 0.111s; … none left listening
```

No `CONTENDED`, no `KILL`, no listener left behind: by the classification
rule written after the first sighting, the shim is exonerated.

**Side effect the rig keeps.** The revoked-recipient negative control on
naive can be satisfied by this failure — it was, in the first sighting.
`op:revoke` therefore judges the pair: if the never-revoked bystander does
not get through on the same family right after, it records a red
`revoked.attributable` that no known-findings entry matches. A failed
session's red checks carry the tail of the engine's stderr, and the shim
journals every stop/start of every unit to
`boxes/<id>/rootfs/var/log/wb-units/<unit>.lifecycle.log`.

## SW-0 — one route switch closed somebody else's file (fixed)

**Found on a phone, not here** (first real-phone pass, 2026-11-19): connect
on one route, tap Connect on another. The tunnel went on carrying traffic;
the Connection page said "No route selected", the Network page showed
"unknown" and loaded for ever. The rig had never switched a route on a
live session — every session was connect → fetch → disconnect on a fresh
phone — so it could not have seen it.

**What.** The TUN fd had two owners. `engine_set_tun_fd(new)` closed the
previous fd while the old sing-box instance was still running on it;
tearing that instance down inside `engine_set_route(B)` closed the same
NUMBER again. In between the number was free, the process's next `open()`
got it (on the phone: the route store's database), and the second close
shut that. The same two closes ran on every disconnect (`engine_clear_route`
through the instance, then `engine_clear_tun_fd`).

**Fix** (core, lane A of the phone-pass wave): one owner per copy. The
host's fd is closed once, by `core/engine/platform.go`; every instance is
handed a duplicate, which it alone closes.

**Pinned by.** Ops `switch` and `switch-all` (`driver/ops_switch.go`,
`labclient/switch.go`): after every switch and after the disconnect,
`fds_intact` (sentinel files the "app" opened before the switch, between
the TUN rotate and the switch, and between clear_route and clear_tun_fd
are still open, still the same file, still writable), `store_survives`
(the four store-backed calls the pages make, afterwards and polled every
25 ms during the switch) and `active_route`. `session.fd_trap_armed`
fails if no sentinel ever landed on the old TUN's number.

**Proved red without the fix** (2026-11-19): `wb-client` built with
`go build -overlay` replacing `core/abi/tun_fd.go` and
`core/engine/platform_singbox.go` by their content at `8d47a82`, same
command as below. `rotate.vless-reality>hysteria2.fds_intact`,
`rotate.hysteria2>vless-reality.fds_intact` and every
`*.disconnect.fds_intact` failed ("fd 6 (opened between the TUN rotate
and the switch) is no longer the file its owner opened"), 11 red checks
in all. **What did not reproduce:** `store_survives` stayed green in that
build — here the freed number went to a sentinel, not to SQLite, so the
store itself was never the victim. The rig proves the double close, not
the particular file it hit on the phone.

```
./run.sh --mgmt=tree --ops switch clean vless-reality hysteria2
```

## SW-2 — a closed instance's packet reader is never stopped; on a kept TUN it eats the new instance's packets

**What.** Closing a sing-box instance does not stop the goroutine that
reads packets from its TUN. sing-tun 0.8.9 closes its gVisor stack with
`t.endpoint.Attach(nil)` — "detach, stop the readers" — but the endpoint
is wrapped in `LinkEndpointFilter`, whose `Attach` wraps whatever it is
given, `nil` included, in a non-nil filter (`stack_gvisor_filter.go`). The
fd endpoint underneath sees "already attached" and does nothing. The
reader stays in `ppoll` on the TUN's fd NUMBER.

What that costs depends on what the host does at a switch:

| the host | the old reader | seen in the rig |
|---|---|---|
| builds a new TUN for the next instance (rotate, check-rotate; every reconnect) | sleeps for ever on the old interface and keeps it open | `session.old_tuns_released got=held`: every replaced interface still exists after its instance was closed (42 of 42 in `switch-all`) |
| keeps the TUN and calls `engine_set_route(B)` (keep — `vpn/StartSequence.kt` since the phone pass) | the new instance's duplicate gets the number the old one just freed, on the same TUN: the old reader wakes for every packet and wins about half of them, feeding a stack that has been closed | `keep.vless-reality>hysteria2.tunnel got=blocked`: "connection refused" / "connection reset by peer" on 15–20 of 20 new connections, measured unchanged 15 s after the switch; the engine reports `route_check: ok` throughout |

Every further switch on the same TUN adds another reader.

**Why the engine does not notice.** Its connection check dials through
the outbound, not through the TUN: the route really is up. Only traffic
from apps is lost.

**Confirmed cause.** `wb-client` built against a copy of sing-tun 0.8.9
with one change — `LinkEndpointFilter.Attach` passes `nil` through to the
wrapped endpoint — and nothing else: `keep.*.tunnel` passes in both
directions with 20 of 20 connections, and every replaced interface is
gone (`old_tun_gone: true`) straight after the switch.

**Not verified on a phone.** The rig is Linux; Android builds the same
sing-tun files (`tun_linux*.go`, `stack_gvisor*.go`) and its VpnService
fd is non-blocking like the lab's. Whether the phone shows it is for the
next phone pass to say — after one switch, do pages load?

**Fixed 2026-11-19 (repair pass of `phone-pass-fixes`).** The engine
carries the one-line fix: `third_party/sing-tun` is sing-tun 0.8.9 with
`LinkEndpointFilter.Attach(nil)` passed through, wired by a `replace` in
`core/go.mod`, `cmd/daal-core/go.mod`, `cmd/daal-soak-engine/go.mod` and
`labclient/go.mod` (`third_party/DAAL-PATCH.md`). `keep` — the order
`vpn/StartSequence.kt` uses — is a sound order again. Run after the fix:
`keep.vless-reality>hysteria2.tunnel got=pass`,
`keep.hysteria2>vless-reality.tunnel got=pass`,
`rotate.session.old_tuns_released got=pass`,
`check-rotate.session.old_tuns_released got=pass`; the entry is gone
from `known-findings.json`. Unit pin:
`go test -tags singbox,with_gvisor ./engine -run TestSingTunDetach` in
`core/` (red without the `replace`). A module that builds the engine
WITHOUT the `replace` line gets the defect back — the line is per module.
Still not verified on a phone.

**Reproduce.**

```
./run.sh --mgmt=tree --ops switch clean vless-reality hysteria2
#   keep.vless-reality>hysteria2.tunnel   expect=pass got=blocked
#   rotate.session.old_tuns_released      expect=pass got=held
WB_TUN_BLOCKING=1 …   # the same with a blocking TUN fd: no different
```

Acceptance (met): both checks green and the entry deleted.

## SW-1 — a switch to a route that carries nothing left nothing connected (fixed)

**Fixed 2026-11-19 (engine, branch `auto-connect`).** `engine_set_route(B)`
from a carrying A still stops A to try B — one TUN, one instance — but
when B carries nothing the engine now reconnects A, re-proves it, returns
B's error and records the episode in the diagnostics
(`switch_back: {failed_route, failed_family, category, restored_route,
restored}`). The rig's client does nothing between the failed call and
its look at the engine, and `check-rotate.unreachable.*` is green:
`old_route_still_connected`, `switch_back_recorded` (new), then `tunnel`
and `wire` on A's endpoint with B still dropped. The `restore.*` rows —
the host setting A again — no longer run, because there is nothing to
restore. The gap described below (B's check plus A's reconnect) is still
there; what is gone is ending up disconnected. The known-findings entry
is deleted. The text below is the finding as it was found.

**What.** `engine_set_route(B)` while A is connected stops A's instance
before B's is started, and learns whether B carries anything only
afterwards. When B does not (its endpoint is dropped on the path), the
engine tears B down and nothing is running: `active_route: ""`,
`route_running: false`, `route_check: failed`. The person was connected,
asked for a route that turned out not to work, and is now disconnected
until something sets A again.

**What is fine.** A switch the engine can refuse WITHOUT trying — B
cooling down after that failure, revoked, expired, needing a new file —
leaves A connected and carrying: `check-rotate.refused.*` is green
(`refused`, `refusal_recorded`, `old_route_still_connected`, `tunnel`,
`wire`). And going back works: `check-rotate.restore.*` sets A again with
B still unreachable and carries verified bytes on A's endpoint. That is
what `vpn/StartSequence.kt` does (`SwitchPolicy.AfterFailure.Restore`).

**Why it is still a finding.** Between the two there is a gap of the
connection check's length (5 s here) plus a reconnect, on every host that
goes back, and a disconnect on every host that does not. Closing it in
the engine means proving B beside A and swapping only then.

**Reproduce.**

```
./run.sh --mgmt=tree --ops switch clean vless-reality hysteria2
#   check-rotate.unreachable.vless-reality>hysteria2.old_route_still_connected  expect=pass got=disconnected
```

## AUTO-0 — the main screen's button did not connect; the engine now picks, tries, moves on, remembers and explains (rig coverage)

**What the phone showed (second phone pass, 2026-11-19).** One signed
file, four routes (vless-reality, websocket-tls, naive, hysteria2). The
main screen said "Press to connect." and pressing it opened a list of
protocol names. Every route connected when picked by hand. Nothing in
the engine used its ranking, its per-network memory, its carrying check
and its failure categories together.

**What changed.** `engine_connect_auto` (core/abi/connect_auto.go), and
the service, shell and UI that call it. This section is what the rig
proves of it — on a real TUN, against a real relay, with the lab censor
acting in between — and what it does not. **Nothing here was run on a
phone.**

**Proved (op `auto`, README "Client-side ops"; quick world `auto`, full
worlds `clean.auto`, `relay-ip-block`, `total-blackout`, `quic-drop`).**

* The first-ranked route blocked → it is tried first and named
  `not_carrying`, the engine moves on, `moved_on`, and verified bytes
  travel on the endpoint of the route it says it is on.
* A second Connect on the same network tries the route that carried
  there first (`why: carried_here`) — also when that route is the LAST in
  the ranking (connected once by hand), so the order is memory and not a
  side effect of the failed route cooling down.
* Everything blocked → `connected:false`, every candidate tried, verdict
  `relay_unreachable`, nothing running, the TUN released, no file of the
  app's closed, the verdict still in the diagnostics after the host's
  teardown; pressed again at once → every candidate tried again, the
  same verdict (revised 2026-11-19: a pass in which nothing answered
  rests no route; before, this press answered `all_cooling_down` with
  nothing started. Run on the rig after the change: `./daal e2e full`,
  6195 checks, `all-blocked.again.every_candidate_tried_again` and
  `all-blocked.again.verdict` green).
* Cancel during a check in flight → the call returns within 2 s,
  `cancelled`, nothing running.
* UDP dropped network-wide vs a dead address → `udp_blocked_here` vs
  `relay_unreachable` on the QUIC route (CEN-4, narrowed).
* Connected by the button, then the running route's endpoint dropped →
  the engine moves to another route in the same TUN with the host doing
  nothing, and verified bytes flow again.
* A failed manual switch goes back to the route that carried (SW-1).

**How it is known the checks can fail.** The quick world was run against
an engine with three mutations applied through `go build -overlay` (the
tree untouched): `routeMemory` returns nothing, `autoFallOver` returns at
once, `deriveAuto` skips the UDP refinement. Result: `FAIL — 8 unexpected
red check(s) … of 174`: `blocked.again.remembered_route_first`,
`memory.connect.remembered_route_ahead_of_the_ranking`,
`memory.udp.quic_route_tried_and_silent`, `memory.udp.verdict`,
`all-blocked.connect.verdict`, `all-blocked.connect.refined`,
`all-blocked.connect.nothing_left_running` (the kept verdict),
`fall-over.moved.engine_moved_by_itself`. Everything else stayed green.

**Not proved here.**

* How soon a phone moves off a dead route (AUTO-O1): the engine's clock
  is 180 s ±25 %, and on Android the only earlier kick,
  `engine_network_changed`, is sent by the page (client-ui App.tsx), so
  with the app in the background nothing else wakes it. The rig sets 3 s.
* The Android service, the Rust shell and the page: the rig's client is
  Go calling the same abi in the same order. Their own tests are the JVM
  and vitest suites; the first real compile of the service glue is the
  APK build.
* A pass with a tor route ahead of a working one (90 s per attempt, not
  shortened). (Parallel probing and a second network: since the next
  wave, section AUTO-3.)
* `name_blocked` / `address_blocked`: no world has two names on one
  address and port (CEN-4).

**Reproduce.**

```
./run.sh --mgmt=tree --ops auto clean vless-reality hysteria2     # the quick world, ~75 s
./e2e.sh full --only clean.auto,relay-ip-block,total-blackout,quic-drop
```

## AUTO-1 — a border that forwards nothing read as one relay not answering (open; fixed only for a host that reports no network)

**What it was.** Under `total-blackout` (every packet beyond the censor
dropped, the link itself up) one press of Connect tries every route,
each fails at TCP connect or in UDP silence, and the verdict was
`relay_unreachable`: "the server did not answer from this network". That
is true. It is also exactly what `relay-ip-block` gets, where one burned
address is the whole problem and a new file is the cure — and in a
blackout a new file changes nothing. The engine has no observation
outside its routes, and every route of a pack goes to the same address.

**Narrowed 2026-11-19 (branch `measure-and-probe`), still open.** Not
by a probe: the host already knows something.
`engine_network_facts(kind, id, validated, metered)`
(core/abi/network_facts.go; on Android the VPN service's
`ConnectivityManager.NetworkCallback`) tells the engine what the platform
found, and a pass in which nothing at all answered while the host says
kind `none` ends `network_down`. No packet is added. The rig's phone
calls it the way the service does — on its own thread, at the moment the
connect starts (`auto-net`, labclient/auto.go).

Validated 0 was taken for the same thing when this was first built, and
the wave's review took it out again: Android leaves a network
unvalidated whenever its own connectivity check does not get through,
which is ordinary on a filtered network where everything else works. On
such a network a null-routed relay read "this phone has no internet
right now" and the person was sent to their Wi-Fi settings instead of to
a new file. So:

* `total-blackout` (link up, nothing forwarded; the host says wifi,
  validated 0) → `scenario.connect.verdict` = `relay_unreachable`, where
  `network_down` is what is true. **Red and known** — this finding. The
  sentence a person reads for it names both possibilities ("this network
  has no working internet, or the server is blocked or off"), which is
  true. `scenario-untold.connect.verdict` (a host that says nothing) is
  the same.
* `relay-ip-block`: told validated 1 → `relay_unreachable`.
* Clean world, the relay null-routed by the rig, ONE phone, three presses
  that differ only in what the host says: `networks.down.verdict` =
  `network_down` (kind `none`), `networks.unvalidated.verdict` =
  `relay_unreachable` (wifi, validated 0), `networks.dead-relay.verdict`
  = `relay_unreachable` (validated 1).

**What would close it.** An observation of the engine's own that is not
one of its routes (a probe — traffic the design has so far refused to
add), or a host signal narrower than "not validated".

**Reproduce.**

```
./e2e.sh full --only total-blackout,relay-ip-block,auto-deep
```

## AUTO-2 — a silent address costs two attempt budgets, not one

**What.** The automatic connect sets `StopAtUnreachedRelay`: a route
whose first attempt never got as far as the relay is not asked a second
time (the attempts differ only in the far-side target, which is not
consulted until the relay answers). Backlog AC-30 states the cost as 4 s
for a silent address. On the rig, with the censor dropping the SYN, it is
8 s, for vless-reality and websocket-tls alike, through the tunnel's own
instance and through a side instance: the censor's packet log shows two
connections to the endpoint, the second 4 s after the first.

Why (read from core/engine/proof.go and proof_singbox.go, not changed
here): the outbound's timeout does not say which phase it died in
(`timeoutPhaseIsUnknown`), so the observation is not `PhaseReach` when
the loop looks at it; the reach check that would say so is started "to
run alongside the next attempt" and is read only after the loop. The
unit test that pins the stop (`TestRunProof_StopAtUnreachedRelay`) hands
the loop an observation that already says `PhaseReach`.

**What it costs.** Racing halves the wait, as designed — two dropped
routes are done in 8.3 s instead of 16.3 s
(`race.connect.faster_than_one_after_another`, green) — but from twice
the stated base. Four dead routes: 21 s on a first press (29 s before
racing; 29 s still on a press within three minutes of another, AUTO-O6).

**Severity.** Low: nothing false is said; the person waits longer than
the design says before the first route that works.

**Reproduce.**

```
./run.sh --mgmt=tree --ops auto clean vless-reality hysteria2
#   race.connect.a_silent_address_costs_one_attempt  expect=pass got=fail
#   evidence: auto_ms ≈ 8300, within_stated_ms 6950
#   race.connect.at_most_two_routes_in_flight evidence censor_saw:
#     tcp/443 22–7072 ms (2 flow(s)); tcp/8445 289–7392 ms (2 flow(s)); …
```

**What would close it.** Settle the first attempt's phase (wait for the
reach check, which costs nothing more on a silent address: it times out
with the attempt) before deciding to start the second. The day a pair of
silent routes is done within 6.95 s the entry in `known-findings.json`
fails the run as "did not reproduce".

## SW-3 — every connect leaves one open file behind

**What.** The rig counts the engine process's open files (the lab's own
sentinel files taken off) after a disconnect. One connect by hand and
disconnect later there is one more, an `anon_inode:[eventfd]`; four more
connects, four more. It is the stop eventfd gVisor's fd endpoint makes
for its packet reader (`gvisor/pkg/tcpip/link/stopfd.New`, used by
`fdbased`'s dispatchers): `Stop()` writes to it and nothing ever closes
it. The engine starts one TUN-attached instance per connect, per switch
and per move it makes by itself.

Found while building the leak check for side instances (which hold no
TUN and leave nothing: `leak-stopped.race.a_side_instance_leaves_nothing`
and `leak-cancel.race.…` are green, measured against what the same number
of connects by hand leave).

**Severity.** Low: one descriptor per connect against a limit in the
thousands. A phone that reconnects every few minutes for weeks in one
process gets there; the symptom would be "too many open files" from
whatever opens the next one — the store, as in SW-0.

**Reproduce.**

```
./e2e.sh full --only auto-deep
#   leak-stopped.cycle.a_connect_and_a_disconnect_leave_nothing expect=pass got=fail
#   before: fds=11 map[[eventfd]:5 [eventpoll]:2 …]; after one more connect by hand and disconnect: fds=12 map[[eventfd]:6 …]
```

**What would close it.** Closing the endpoint's stop eventfd once its
dispatch loops have returned — in the vendored sing-tun
(`third_party/sing-tun`, beside the SW-2 patch) or wherever the engine
closes the instance.

## AUTO-3 — two at a time, measured, moving for speed, told about the network (rig coverage)

**What changed** (branch `measure-and-probe`, 2026-11-19): the automatic
connect checks two routes beside each other in side instances
(core/abi/connect_race.go, core/engine/side_singbox.go), remembers per
network how each route did (core/netmem/measure.go), leaves a route that
has become slow for one that proves clearly faster
(core/abi/connect_speed.go), and is told about the network by the host
(core/abi/network_facts.go). This section is what the rig proves of it on
a real TUN against a real relay, and what it does not. **Nothing here
was run on a phone.**

**New in the rig.** `wb flows` (driver/flowtap.go): a packet socket on
the censor's client-side interface that logs when the client opens each
connection to the relay — the place a promise about what a censor sees is
checked. A per-endpoint delay at the censor (`slowEndpoint`: prio + netem
on a band only marked packets enter). The lab phone reports the network
(`net`, `auto-net`), lists what the Connections page reads (`listing`),
and says what its process holds (`res`).

**Proved (op `auto`: quick world `auto`, full `clean.auto` and the three
scenario worlds; op `auto-deep`: full world `auto-deep`).**

* **Never more than two.** On EVERY press of both ops the censor saw
  new connections to at most two of the relay's endpoints at one moment,
  and `auto.racing` never named more than two routes
  (`at_most_two_routes_in_flight`; what that cannot see: AUTO-O3).
* **The pair is checked together and the press is faster for it.** The
  two routes a fresh phone checks first (r1 vless-reality tcp/443 and r2
  websocket-tls tcp/8445 — the engine's choice: the QUIC route shares
  port 443 with r1 and is not paired with it) dropped at the censor: both
  `not_carrying` with each other as `raced_with`, a third route carries,
  `moved_on`, done in 8.3 s where one after the other costs 16.3 s. At
  the censor the second route's first packet follows the first's by
  0.2–0.35 s (the engine says 0.15–0.45 s). The stated budget is not met:
  AUTO-2.
* **A stopped check is not a failed one.** With only r1 dropped, r2
  proves while r1 is still waiting: r1 is `stopped`, no verdict is given,
  and this network's memory holds nothing against r1.
* **The remembered route alone.** Second press on the same network, the
  block still in place: one route tried, `carried_here`, nothing beside
  it, and the censor sees new connections to that one endpoint only.
* **Measured.** After a connect the route list and the connected route's
  summary carry `measured` for this network: the route that carried
  graded good, timed and counted; dropped routes `failing`; routes
  nothing was asked of `unknown`. A connect by hand is measured the same.
* **Slow.** A route connected by hand, then delayed 2.5 s per packet at
  the censor: within ~12 s of the engine's own checks (liveness set to
  3 s) the list says `slow`, with no failure counted.
* **Moving for speed.** Connected by the button on the remembered route;
  the censor starts delaying it; the host does nothing. After two slow
  checks the engine proves one other route beside the running one and
  moves: `moved_faster`, the old route named `carried` /
  `path_too_slow`, the same TUN, verified bytes on the new endpoint, the
  old route graded `slow`. Then the NEW route is delayed and the old one
  freed, with a third never-probed route available: the engine stays for
  the 30 s watched and the censor sees no new connection to any other
  endpoint (AUTO-O4).
* **Metered.** The same start on a network the host calls metered: the
  engine calls the route degraded, stays on it, and the censor sees no
  new connection to any other endpoint.
* **The network's identity.** A route that carried on network X is
  checked alone on X, is `unknown` on Y (another id, the same kind) and
  is not pulled ahead there, and is remembered again back on X. The
  answer carries a 16-hex id that is not the one sent; neither id sent is
  in any file under the engine's state directory or in anything the
  phone process wrote. Kind `none` refuses no press.
* **network_down on the host's word**: AUTO-1.
* **Nothing left behind.** A check stopped in flight, and a pair
  cancelled in flight by the person, leave no open file, no goroutine and
  no sing-box goroutine beyond what the same number of connects by hand
  leave (and those leave one eventfd each: SW-3).

**How it is known the checks can fail.** Both ops were run against
engines built with one-line mutations through `go build -overlay` (the
tree untouched), in three sets; every mutation turned the check that
names its behaviour red and nothing unrelated:

| mutation in the engine | red on the rig |
|---|---|
| the second probe's delay is 0 | `race.connect.second_route_starts_after_a_delay`; `first.connect.first_route_first_try` (both routes proved) |
| a stopped check is recorded as a failure | `blocked.connect.a_stopped_check_is_not_a_failure` |
| a third route is probed beside the pair (driver limit raised to 3) | `all-blocked.cancel.at_most_two_routes_in_flight`, `leak-cancel.race.at_most_two_routes_in_flight` ("3 of the relay's endpoints at the same time") |
| the remembered route is not tried alone | `memory.connect.remembered_route_alone`, `speed.connect.on_the_remembered_route_nothing_probed`, `metered.connect.…` |
| `measured` always says unknown | `first.connect.measured`, `race.connect.measured`, `slow.by-hand.a_connect_by_hand_is_measured`, `slow.by-hand.graded_slow_here` |
| the speed move never starts | `speed.moved.engine_moved_for_speed` |
| neither the hold nor the back-off is looked at | `speed.hold.stays_after_a_move_for_speed` ("the engine left r2 … a new connection to udp/443 during the hold") |
| the metered flag is ignored | `metered.slow.no_probe_on_a_metered_network` |
| the host's "down" is ignored | `networks.down.verdict`, `total-blackout` `scenario.connect.verdict` |
| the id is left out of the network's hash | `networks.y.another_id_is_another_network`, `networks.y.the_route_remembered_elsewhere_is_not_pulled_ahead` |
| the id is written to the engine's log | `networks.ids.the_clear_id_is_in_no_file` (found in the phone's `stderr.log`) |
| a side instance is never closed | `leak-stopped.race.a_side_instance_leaves_nothing` (one socket, one sing-box goroutine) |

Two checks turned out weaker than their names while doing this, and say
so now: `race.again.remembered_route_alone` and
`networks.x-again.remembered_route_alone` stay green without the
alone-first rule, because the remembered route there is one the engine
never side-probes (naive) or probed minutes before — it is `memory`,
`speed` and `metered` that hold the rule. And `leak-cancel` does not see
an unclosed side instance whose dials were cancelled (it holds nothing);
`leak-stopped` does. The flow arithmetic itself is unit-tested
(`driver/flowtap_test.go`: a pair then one is two; three together is
three; retransmissions and an older session's leftovers are not new
flows).

**Not proved here.**

* The Android service's callback, the JNI function and the pages: the
  lab phone is Go calling the same abi (the call's thread and moment are
  the service's; what Android reports, and when, is not modelled).
* How soon a phone moves for speed: the engine's clock is 180 s ±25 %;
  the rig sets 3 s (AUTO-O1).
* The hold and the back-off one by one (AUTO-O4); the hourly allowance
  of side probes; a race between a stream route and a datagram route (in
  the default file the only QUIC route shares its port number with r1, so
  the pair is two TCP routes; tuic would pair, behind the experimental
  gate).
* A race whose winner then fails through the tunnel; a phone restarted
  with its state (the measurements are read back from the store only by
  the engine's unit tests).
* The grade thresholds: a 2.5 s delay is far beyond them.

**Reproduce.**

```
./run.sh --mgmt=tree --ops auto clean vless-reality hysteria2     # quick world: first, blocked, race, …
./e2e.sh full --only auto-deep,clean.auto,total-blackout,relay-ip-block,quic-drop
WB_AUTO_ONLY=speed,metered ./e2e.sh full --only auto-deep        # single phones of an op
```

## ADD-1 — the Google channel refuses the standby key as the publisher holds it

**What.** Add-on 1 meets add-on 3: after "Switch to standby" the
publisher's app has the 26-character key to hand out, and the Google
channel is meant to carry it (`daal-refresh-v1`, member `standby_key`).
`daal-deploy standby promote` prints the key in its display form, five
groups separated by spaces (`bundle.StandbyKeyBytes.Text()`). The
container builder (`appsscript.Build`, behind `appsscript-check
--standby-key-file` and `publish-freshness --appsscript-standby-key-file`)
accepts only the 26 symbols run together and refuses the display form:
`appsscript: standby key must be 26 Crockford base32 symbols`. The
engine's own reader (`bundle.ParseStandbyKeyText`, used by
`engine_standby_key`) ignores spaces and dashes, so the two ends of one
key disagree on its spelling.

**Reproduce.** `./run.sh --mgmt=tree --ops standby-google clean
vless-reality` → `op:standby-google google.standby_key_as_printed_accepted
expect=pass got=fail`. The op then sends the same key with the spaces
removed, and everything after it is green: the phone, connected when the
primary is null-routed and the ordinary mirrors cut, finds the standby
through the Google front and reconnects on it.

**Fix.** Read the key in `container.go` with `bundle.ParseStandbyKeyText`
and write the canonical form; the wizard then needs to do nothing
special. The check turns green and this entry must go (the rig reports a
known finding that did not reproduce).

