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

Repo state: `main @ 257238a` + the uncommitted work of 2026-11-18 (the
"truth wave" and its review repairs).
Reproductions are run from `test-rigs/worldbox/`. "quick"/"full" are the
modes of `./daal e2e` (`./e2e.sh`); a world name is a row of its report.

### Fixed in this tree (20)

| id | severity | one line | status | reproduce (before the fix) | pinned by |
|---|---|---|---|---|---|
| FAM-1 | **high** (user-visible) | On naive, an app's name lookups (plain UDP/53) get no answer: "connected", nothing loads | **fixed** in `core/engine/config.go` — **names only**: every other app datagram on naive is still dropped (FAM-6, open); covers every TCP-only outbound (naive, http, tor, ssh, shadowtls, `network:tcp`), but the rig exercises naive only; needs one phone retest (Private DNS off, naive route and tor route, open a site by name) | revert the `hijack-dns` hunk, `./run.sh clean naive` → `family/naive dns` blocked | unit `TestBuildSingBoxConfigHijacksDNSForUDPLessOutbounds`, `TestTCPOnlyOutboundTypesMatchSingBox` (core/engine), and under `-tags singbox` (now run by `./daal test`) `TestHijackedDNSConfigIsAcceptedBySingBox` — the linked sing-box parses and starts the rule together with the legacy-format dns block; rig check `family/naive dns` in quick and full |
| LC-1 | low-to-medium (security, defence in depth) | A mgmt token already used once could be replayed with a different body (`users-revoke` against another recipient, etc.) | **fixed** in `cmd/daal-relay-mgmt/main.go` + spec §3/§4.8; **open on released relays** until the next mgmt release (the one F-002 needs) | `./run.sh --ops mgmtauth clean @default` (pinned release) → `replay.users-revoke` honoured | unit `TestMutatingTokensAreSingleUse` (cmd/daal-relay-mgmt); rig check `op:mgmtauth replay.users-revoke` green on the tree build in quick and full; on the pinned box tracked in known-findings.json (`LC-1`, box=pinned) |
| FAM-5 | low (latent) | Off Android the engine could never load Cronet from beside its own binary (a failed first try is cached for the process) | **fixed** in `core/engine/cronet_state.go`, `cronet_loader_naive.go` | revert, `./run.sh clean naive` → `tunnel` refused, "cronet: failed to load library" | unit `TestCronetLibraryArg` + `TestLoadCronetUsesCronetLibraryArg` (core/engine); rig: every `family/naive tunnel`. Android unchanged by construction, not device-tested |
| INT-2 | medium (intermittent; on the relay) | naive: sing-box 1.13.12 decides the naive inbound's ALPN with a start-up race; about 1 start in 1000 leaves naive/TCP answering every ClientHello with alert 120 (`no_application_protocol`; Cronet `net_error -107`) for the whole life of that sing-box process. Nothing is logged; the engine says Connected | **fixed** in `cmd/daal-relay-mgmt/singbox_users.go` (the daemon now writes `alpn` into `naive-in`, so nothing is left to race; an older inbound is healed on the next recipient add); **open on released relays** until the next mgmt release (the one F-002 and LC-1 need). Root cause is upstream sing-box, worth reporting there | `repro/int2-naive-alpn-race.sh` (no Daal involved: 3 dead instances in 3000 starts; `… pinned` → 0 in 3000) | unit `TestAppendNaiveUserCreatesInbound`, `TestNaiveALPNHealsAnOlderInbound` (cmd/daal-relay-mgmt); on the pinned box tracked in known-findings.json `INT-2` (box=pinned, signature `net_error -107`, budget 4); on a tree box the same face is an unexpected red |
| F-004 | **high** (security, design) | A pack's outbound profiles were not authenticated: anyone could rewrite the server address under the publisher's fingerprint | **fixed** — "signed endpoint, local credential": every route's server, port and server-authentication material is committed in the signed manifest (`_endpoint`), the importer refuses an outbound that disagrees (`endpoint_mismatch`, before any trust prompt), `SetRoute` re-checks. `bundle/go/bundle/endpoint.go`, `bundle/go/importer/endpoint_plan.go`, `publisher/deploy/relaypack/endpoint.go`, `core/abi/endpoint_guard.go`; spec `relaypack-v1.md` §"Endpoint commitment". **Not covered:** bundles that are not RelayPacks (section below) | at `257238a`: `./run.sh --ops tamper clean vless-reality` → `import_of_tampered_pack got=pass` | `op:tamper import_of_tampered_pack` and `.port` / `.tls_pin` / `.reality_public_key` / `.trusted_certificate` / `.tls_insecure` / `.folded_key` / `.shadowsocks_server_key`, `commitment_stripped.import`, `credential_rewrite.*` (quick + full); `tampered_pack.connect` (a phone told to connect with the tampered pack stops at import: no route listed, engine never started); `TestSetRoute_EndpointRefusalComesBeforeAnyConnectionAttempt` (core/abi: a refused route starts no engine, runs no connection check, records no attempt); `TestCheckOutbound_RefusesEveryEndpointRewrite`, `TestCheckOutbound_RefusesFoldedKeySpellings` (a second, case-folded spelling of a checked member name), `TestImport_TamperedEndpointIsRefusedNotPrompted`, `TestImportSBP_RefusesAPackWhoseEndpointWasRewritten` |
| F-006 | medium (security) | A bundle with no `relay_pack` slot — same publisher, same route ids, profiles rewritten with no key — silently replaced committed routes and deleted their commitments | **fixed** — a commitment is sticky: an import that carries no signed endpoint for a route the device already holds with one (stored commitment or `relay_pack_id`, in any trust state) is refused whole, `endpoint_downgrade`, before any trust prompt; the store refuses the same write itself, before writing anything. `bundle/go/importer/endpoint_plan.go` (rule 5), `core/trust/state.go` (`RouteCommitted`, `SaveImport`); specs `relaypack-v1.md` §"A commitment is sticky", `sbp-v1.md` §"What the signature covers". **Not covered:** a plain bundle's routes under NEW ids are still unauthenticated (section below) | with both guards switched off: `./run.sh --mgmt=tree --ops tamper clean vless-reality` → `uncommitted_replacement.import expect=refused got=pass` | `TestImport_BundleWithoutCommitmentsDoesNotReplaceCommittedRoutes` (bundle/go/importer); `TestStoreAdapter_CommitmentIsSticky`, `TestStoreAdapter_KeepsWhenARouteEndpointWasSigned` (core/trust); `op:tamper uncommitted_replacement.{control.new_routes.import,import,routes_kept}` |
| LC-2 | **high** | The freshness channel could only deliver the credential-less signed skeleton, which REPLACED a polling recipient's working pack with one that could not connect | **fixed** — a signed pack with no credentials is MERGED: the device keeps its credentials and takes the new signed endpoint; a profile with no outbound never replaces one that has one; the same file imported on a phone that holds nothing is refused (`pack_has_no_credentials`). After L2 and L3 a polling phone recovers with **no new file**. **Still needs a new file:** L1 (that one recipient) and L4–L6 (everyone) — section below | at `257238a`: `./run.sh --mgmt=tree --ops freshness clean vless-reality` → `unchanged.signed-pack-hosted.tunnel got=refused` | `op:freshness unchanged.signed-pack-hosted.{tunnel,routes_kept}`, `signed-pack-alone.import`, `published.*.holds_no_credentials`, `rotated.polled.tunnel`; `op:l2 no-new-file.cover-host-moved.*` (7 families); `op:l3 no-new-file.address-blocked.*` — including `.route_checked`: the merged route passed the engine's own connection check (`route_check=ok`) before it was Connected; `TestSetRoute_MergedRouteIsConnectedOnlyAfterTheConnectionCheck`, `TestSetRoute_MergedRouteThatCarriesNothingIsNotConnected` (core/abi); `TestApplyVerifiedRefresh_MergesSignedEndpointIntoDeviceCredentials`, `TestRotationHealsAnImportedPackOverTheNetwork` |
| LC-4 | medium (security) | A signed, credential-less pack from BEFORE a rotation, handed over as a file, was merged into a phone that had already moved on: its routes went back to the old cover host / port / relay key, silently (the publisher is already trusted) | **fixed** — a file only moves a route forward: outside the freshness path a merge needs the incoming manifest's `bundle.created_at` to be strictly later than the one the route's commitment came from (kept by the store beside the commitment); the manifest the route is already on is a no-op. An older one is reported `older_than_device` (`pack_is_older` when nothing else is in the file) and the route is untouched. Section below | importer: import v1, merge v2's skeleton (same pack id, REALITY key rotated), import v1's skeleton → `Imported, Merged=2`, both routes back on the old key. Rig, with the rule switched off: `./run.sh --mgmt=tree --ops freshness clean vless-reality` → `rotated.stale-signed-pack-by-file.tunnel got=blocked` (`reality verification failed`) | `TestImport_AnOlderSkeletonDoesNotRollARouteBack`, `TestImport_AnOlderSkeletonRouteIsReportedAndLeftAlone`, `TestImport_SkeletonDoesNotMergeIntoARouteOfUnknownAge` (bundle/go/importer); `TestStoreAdapter_KeepsWhenARouteEndpointWasSigned` (core/trust); `op:freshness rotated.stale-signed-pack-by-file.{not_merged,routes_kept,tunnel}` |
| LC-3 | medium | After an L3 address move naive could not connect to the new address (the box certificate named only the first-boot address) | **fixed for relays provisioned from this tree** — cloud-init adds one stable DNS name to the certificate; naive verifies against it when (and only when) the address it dials is not in the certificate (`bundle.NaiveVerificationName`). A relay provisioned BEFORE this change has no such name and still loses naive on L3 until it is rebuilt. The "engine says Connected" half was CEN-1 | at `257238a`: `./run.sh --mgmt=tree --ops l3 clean naive hysteria2` → naive `new-file.address-blocked got=blocked` | `op:l3/naive new-file.address-blocked.{tunnel,wire}` and `no-new-file.address-blocked.tunnel` (full); `TestNaiveVerificationName`, `TestClientOutbound_NaiveVerificationNameFollowsTheCertificate` |
| F-003 | medium | Routes the minter "dropped" still imported, listed and could be activated on the client | **fixed** — a RelayPack route whose profile holds no outbound is not stored: it is not listed, not selectable, not activatable; the import verdict names it (`Unavailable`, reason `not_offered` / `no_credentials` / `needs_new_file`) and the app has copy for each | at `257238a`: `./run.sh clean anytls` (pinned): `routes` lists r5–r7, `error` carries a parse error | `family/* import.unconnectable_not_listed` in every session of every world (red only where a pack has a dropped route: world release.all-families); `TestImport_RoutesTheMinterDroppedAreNotStored`, `TestDroppedRouteIsNeitherListedNorActivatable` |
| INT-1 | **high** (intermittent) | naive: the whole engine process died with SIGSEGV inside Cronet when a connection was closed at the moment its stream terminated — a use-after-free race in the pinned `cronet-go` (`Close`→`Cancel` against `terminate`→`Destroy`). Seen in the rig only; never observed on a device | **fixed** by bumping `cronet-go` (and `cronet-go/all`, `lib/*`) in `core/go.mod` to `v0.0.0-20260912104727-0d28acc44093`, the first module build with upstream `172bb4ede18c` "Fix bidirectional stream cancel racing with destroy" (it is what sing-box 1.14.1 ships; it builds against the pinned sing-box 1.13.12). **Linux proven here; Android NOT verified, and the phone needs a rebuilt `libcronet.so`** — the bump changes the library's C ABI (see the section) | `for i in 1 2 3 4; do WB_RESTART_CYCLES=25 ./run.sh --mgmt=tree --ops restarts clean naive & done; wait` → before: 3 engine deaths in 520 naive sessions; after: 0 in 1040 | unit `TestCronetGoCarriesTheCancelDestroyFix`, `TestCronetLibModulesMoveTogether`, `TestCronetGoCloseCancelsUnderTheLock` (`core/engine/cronet_pin_test.go`); rig: `*/naive engine.survived` is no longer excused by anything — one engine death fails the run; `tools/cronet/check-libcronet-stamp.sh` refuses a mismatched Android library |
| FAM-2 | medium | The app could not enable shadowsocks, anytls or tuic at all: the wizard hard-coded an empty family list | **fixed** in `client-ui/src/publisher/` — a collapsed, default-off "More ways to connect" section on the plan screen (`MoreWaysToConnect.tsx`, `extraFamilies.ts`), en+fa. **The switches are locked, with the reason, until F-002's release** (`cloudinit.PinnedMgmtServesOptInFamilies`; section below). *Basis: unit-tested and type-checked; the app itself was not run* | `grep -n enabledFamilies client-ui/src/publisher/PublisherWizard.tsx` (was a constant `[]`) | vitest `src/publisher/extraFamilies.test.tsx` (26 tests); not pinned by the rig (above the ABI) |
| FAM-3 | medium | `provision --families` was a silent filter: a typo dropped the family, a short list dropped the defaults, exit 0 either way | **fixed** in `publisher/deploy/cli/cli_families.go`: a name the profile does not offer is exit 2 before any cloud call, naming the value and the valid set; what the list drops is stated (stderr, or a `provision_families` progress event) — as "will be asked to serve", naming what the pinned release cannot serve, until F-002's release. L6 keeps working: `reprovision` narrows the record it hands on | `daal-deploy provision … --dry-run --families vless-reality,tiuc` (section below) | unit `publisher/deploy/cli/cli_families_test.go`; not pinned by the rig |
| FAM-4 | low | De-selecting a default family did not take it off the box: 4 open, listening ports the pack never mentions | **fixed in the tree** (cloud-init + `daal-relay-mgmt` + both firewalls; backlog W5-1 with it); reaches a relay only with the planned re-release and a fresh provision | `./run.sh --mgmt=tree --relay-families shadowsocks,anytls clean shadowsocks anytls` | rig world narrow-relay (full): `mint/* not_served` green with `listener_on_box: false`, and `censor/prove.relay-tls-answers` asserted CLOSED on a relay without a 443/tcp family; unit `TestProvision_NarrowRelayBindsOnlyItsFamilies` and neighbours (`cmd/daal-relay-mgmt/families_test.go`), `TestFirewallPortsForFollowsTheFamilySet`, `TestSingBoxConfig_EveryInboundFollowsTheFamilySet`, `TestProvision_NarrowFamilySetLeavesNothingElseOpen` (hetzner, vultr), `TestRender_UFWOpensExactlyTheDataPlanePorts` |
| F-001 | low (latent) | `daal-fetch-verify` failed with a misleading message when `/tmp` and `/usr/local/bin` are different mounts | **fixed** in `publisher/deploy/cloudinit/shim.sh.tmpl` (stages beside the destination, prints the per-mirror reason); shim hash and cloud-init golden re-pinned; reaches a relay with the next provision | mount a tmpfs on the box's `/tmp` in `box/init.py` (section below) | unit `TestVerifierShim_InstallsAcrossMounts`, `_SaysWhyAMirrorFailed`, `_RefusesBadSignature`, `_FallsBackToSecondMirror` (`shim_exec_test.go` — they run the embedded shim) |
| CEN-1 | **high** | A route that carried nothing was "Connected", recorded as a success, and came out `proven: true`, `health_pct: 100`; the engine never classified a data-plane failure | **fixed** — a route is Connected only after one real round trip through its own outbound (`core/engine/proof.go`, `core/abi/route_check.go`): `verifying` → `ok` / `degraded` / `failed`; a failed proof is torn down, classified, cooled down and recorded, and `SetRoute` returns the error; a connected route is re-proved every ~3 min (jittered) and on a network change. Spec `engine-abi-v1.md`. **Not verified:** the phone (SetRoute now blocks for the proof, up to 8 s on a dead route, 90 s per attempt on tor) and the default public targets, which the lab cannot reach | at `257238a`: `./run.sh --mgmt=tree relay-ip-block vless-reality hysteria2` → `engine.category got=none`, posture `ImportedActive`, `proven_after=true` | `family/* engine.category` in every blocking scenario (40 sessions in full: 26 named exactly, 14 named as the coarser thing one route can see — CEN-4); unit `TestSetRoute_StartedButCarriesNothingIsNotConnected`, `TestSetRoute_IsVerifyingUntilProved`, `TestCheckActiveRoute_ConnectedToFailedAndBack`, `TestLiveness_TimerAndNetworkChange`, `TestSetRoute_RefusedLeavesTheConnectedRouteWatched`, `TestSetRoute_RefusedForCooldownKeepsTheRecoveryLoop` (a refused `SetRoute` used to stop the liveness loop of the route that stayed up — review finding, fixed), `TestSetRoute_RefusedLeavesTheCheckInFlightRunning` (a refused `SetRoute` used to cancel the connection check of another `SetRoute` still in flight and strand its instance in `verifying`, unproven and unwatched — review finding, fixed) (core/abi), `TestProveInstance_*` (core/engine, `-tags singbox`); vitest `src/lib/routeCheck.test.ts` |
| CEN-2 | medium | `diagnostics.Classify` could not tell a reset after the ClientHello from a reset of the address, and filed a TLS-phase timeout under `tcp_connect_timeout` | **fixed as far as one route can see** — the engine classifies a failed proof from an observation (phase reach / handshake / carry, UDP or TCP, TLS first flight or not: `core/diagnostics/observe.go`, `ClassifyObservation`); the locked string table is unchanged and still decides where the observation settles nothing. Name-keyed vs address-keyed reset is CEN-4 | at `257238a`: `echo 'read tcp4 1.2.3.4:5->6.7.8.9:443: i/o timeout' \| bin/wb-client --classify` → `tcp_connect_timeout` | `family/* engine.category` under sni-rst, sni-rst-stateless, sni-drop (the engine's category equals the raw probe's); unit `TestClassifyObservation_PhaseSeparatesWhatTheStringCannot`, `_FallsBackToTheLockedTable`, `TestSetRoute_FailedProofIsClassifiedByPhase`, `TestProveInstance_SwallowedHelloIsNotADeadAddress` |
| CEN-3 | medium (spec) | The failure taxonomy had no word for three things a censor does: UDP dropped toward ONE address, UDP dropped on ONE port, and "connects but too slow to use" | **fixed** — `specs/failure-taxonomy-v1.md` revision 2 adds `udp_address_blocked`, `udp_port_blocked`, `path_too_slow` (a degraded outcome, never a failure or a cooldown) and `udp_no_reply` (what one silent UDP route can honestly say). The engine produces `udp_no_reply` and `path_too_slow`; the two narrower UDP words need a second observation (CEN-4) | at `257238a`: scenarios relay-ip-block, port-whitelist, throttle-56k declared the nearest category (`unknown`, `udp_unavailable`, `none`) | `censor/* truth.category` now declares and raw-proves the new words; `family/* engine.category` under throttle-56k (`path_too_slow` where the proof sees it); unit `TestSetRoute_SlowProofIsDegradedNotFailed`, `TestPathTooSlowIsNotACooldownClass`, `TestClassifyObservation_SilentUDPIsNeverANetworkClaim`; `driver/censor_test.go` |
| CEN-5 | **high** (user-visible) | After a connect that failed the app said "Connecting…" for good while nothing was running — on Android with no error at all (the connect call resolves before the engine has tried the route). Same words as a connected route the engine really is retrying | **fixed** — the diagnostics blob says `route_running` (true exactly while an engine instance for a route is up); the app shows a failed connect as an error, "Could not connect on this route. Try another one.", and a lost connection as "Connection lost. Trying again…" (en + fa). Spec `engine-abi-v1.md`. **Not verified:** on a phone; the rig does not render the app, it checks the engine field the app reads. **Still open:** while a lost connection is being retried the main button does not disconnect (section below) | at `257238a` + CEN-1: any blocked session, e.g. `./run.sh --mgmt=tree relay-ip-block vless-reality` → the error event's `diag` has `posture: Recovery`, `route_check: failed` and nothing that says the engine stopped; `connStateWithCheck('connecting','failed')` → `connecting` → headline "Connecting…" / «در حال اتصال…» | `family/* engine.failed_connect_not_running` in every blocked session; unit `TestRouteRunning_TellsAFailedConnectFromALostConnection`, `TestRouteRunning_LostConnectionKeepsRunning` (core/abi); vitest `src/lib/routeCheck.test.ts` |
| CEN-6 | **high** (the rig hid it; one product defect under it) | throttle-56k could not go red: a first phone whose connect FAILED ("the route started but carried no traffic", `tls_handshake_failed` / `unknown`, a 5–30 min cooldown) was replaced by a fresh phone and only that one was judged; the cell accepted `path_too_slow|none`; and a connect that took 4.7–5.5 s read plain "Connected" | **fixed** — engine: a proof is slow when the WHOLE proof took longer than `slow_after_ms`, failed attempts included (`core/engine/proof.go` `proofWasSlow`; specs `engine-abi-v1.md`, `failure-taxonomy-v1.md`). Rig: every connect attempt is recorded and the first is judged alone (`engine.first_verdict`); the scenario declares `path_too_slow` and the cell is decided per connect by its time; a session waits for the censor's shaper to drain the session before it (the first-phone failures were the previous QUIC family's queue — rig cross-talk, measured). **Left as it is:** what the engine says on a link that already has seconds of queue (CEN-O5) | before: `./run.sh --mgmt=tree throttle-56k` → exit 0 with `connect_attempts: 2` on naive and vless-reality and `route_check: ok` after `set_route_ms` ≈ 5000. Now, the same failure made visible: `WB_NO_QUIET=1 ./run.sh --mgmt=tree throttle-56k` → `engine.first_verdict` red | `family/* engine.first_verdict`, `family/* engine.category` under throttle-56k; unit `TestRunProofTimedOutCarryAttemptThenSuccessIsSlow`, `TestProofWasSlowJudgesTheWholeProof` (core/engine); `driver/first_verdict_test.go` |

### Open — need a decision, a release or a dependency fix (4)

| id | severity | one line | status | reproduce | pinned by |
|---|---|---|---|---|---|
| CEN-4 | medium | One route cannot tell apart what needs two observations: every silent UDP route is `udp_no_reply` (network-wide UDP loss, a QUIC-only filter, a dead address, a dead port), and a reset after the ClientHello is `tls_sni_or_cert_block_suspected` whether the filter is keyed on the name or on the address | open — the prober's job (selection stage): a second datagram / a second name. What the engine says is true, cools down only the one route, and is never the wrong network-wide claim | `./run.sh --mgmt=tree relay-ip-block hysteria2` → `engine.category expect=udp_address_blocked got=udp_no_reply`; `./run.sh --mgmt=tree tcp-reset-mid-handshake vless-reality` → `expect=tcp_reset got=tls_sni_or_cert_block_suspected` | known-findings.json `CEN-4` (14 checks in full: 11 UDP, 3 reset); the report's ENGINE CATEGORY line lists each truth → reported pair |
| F-002 | **high** | A relay provisioned from `main` cannot serve shadowsocks, anytls or tuic: the pinned `daal-relay-mgmt` predates them | open — needs a release (release key); the code is right | `./run.sh clean` (pinned) vs `./run.sh --mgmt=tree clean` | known-findings.json `F-002` (box=pinned): world release.all-families in full. Acceptance after the release: that world all green, and the run then fails with "F-002 did not reproduce" until the entry is deleted |
| F-005 | **high** (the app; code-reading) | The app signs a relay BEFORE it has the relay's connection material: `bind-and-sign` can commit a route only to what the OperatorRecord carries, and the wizard passes no `--endpoint-creds` | open — wizard work (`commands.rs`, `cli_bridge.rs`). *Basis: established by reading the wizard source; the app was not run. The CLI behaviour it would meet is unit-tested* | `daal-deploy bind-and-sign` on a record with no `reality_public_key`/`tls_cert_sha256` → exit 1 (`TestBindAndSign_EndpointMaterial`) | not pinned: the rig is not the app (it provisions a recipient first and passes `--endpoint-creds`) |
| FAM-6 | medium (user-visible) | naive carries **no app UDP except DNS**: QUIC without a TCP fallback, calls, games get nothing while the route is "Connected". The rig's `udp = blocked` cell for naive is this limitation written down as an expectation — it is green because the product still has the limitation, not because anything works | open — product decision: one line in the pack's naive outbound (`udp_over_tcp`) carries it, tried here against the released box; it changes what is minted for a default family | `./run.sh clean naive` → `family/naive udp expect=blocked got=blocked` | not in known-findings.json (the check is green by declaration): `families/naive.json` `"udp": "blocked"` is the pin — the day a pack carries UDP on naive that check goes red (`expect=blocked got=pass`) and the declaration must be flipped to `pass` |

### Observations (no verdict; recorded so the day they change is visible)

| id | one line | where to see it |
|---|---|---|
| O-1 | The protect callback the phone registers is never called; only the uid exclusion keeps the engine out of its own TUN | `engine_protect_calls` in every `control.after` |
| O-2 | **Fixed in the tree.** Disconnect blocked ~5 s when the relay was blackholed (vless-reality, websocket-tls): closing sing-box waited out a dial already in flight. The instance's context is now cancelled before it is closed, and a connection check in flight is abandoned, not waited for | unit `TestCloseInstance_DoesNotWaitForADialToADeadRelay` (core/engine, `-tags singbox`), `TestClearRoute_DoesNotWaitForAConnectionCheck` (core/abi). The rig no longer reaches the old state: a blackholed route never becomes connected |
| O-3 | Backlog W5-1, **fixed in the tree with FAM-4**: a default relay no longer binds `ss-in`/`anytls-in`. A relay built from the pinned release still does (firewalled) | `listener_on_box` in `mint/* not_served` — `false` on `--mgmt=tree` worlds |
| O-4 | The three opt-in families connect with the experimental-families gate OFF | every session of anytls, shadowsocks, tuic |
| LC-O1 | `rotate-tls` says every recipient needs a new pack; only vless-reality stops working | `op:l2 old-pack.tunnel` per family |
| LC-O2 | `/whoami` has a handler and no caller that can authenticate to it (`MintToken` refuses the op) | section below |
| LC-O3 | The first freshness poll after an import always downloads the whole pack | `op:freshness` evidence |
| LC-O4 | L1, L2, L3, revoke and multi-recipient all work end to end on the pinned release artefacts (default families) | world release.lifecycle (full) |
| INT-O1 | **Fixed in the tree.** The kick wrapper's `SIGUSR2` ("graceful inbound drop") was a no-op — sing-box 1.13.12 registers handlers for INT, TERM and HUP only — so every kick was `sleep 2` + a full restart, and `users-revoke` / `rotate-credentials` kicked twice (~4.7 s, two restarts). Now one in-process reload (SIGHUP via `ExecReload`, verified in `cmd/sing-box/cmd_run.go`): the verbs take ~0.1 s and the relay's sing-box pid does not change. A relay on the pinned daemon still applies twice (two reloads, no sleep) until the re-release | relay `sing-box.service.lifecycle.log` (one `start`, no restarts); `ms` of the verbs in `publisher-verbs.jsonl`; unit `TestUsersRevoke_RemovesAndReloadsExactlyOnce`, `TestRotateCreds_ReloadsExactlyOnce`, `TestRenderV2_ApplyWrapperIsOneReloadAndNoSleep` |
| CEN-O1 | The relay's shadowsocks and anytls ports answer a few opaque bytes with a TCP reset within a millisecond; naive and websocket-tls wait, REALITY forwards — an active-probing tell, for triage | section below |
| CEN-O2 | Only vless-reality puts a name on the wire; its ClientHello is 600 bytes in one TCP segment, so even a first-packet-only SNI filter reads it | scenarios sni-rst, sni-rst-stateless |
| CEN-O3 | Under 30% random loss the QUIC families still complete the fetch (7–11 s) and every TCP family fails it | scenario heavy-loss |
| CEN-O4 | naive's first request can end in `EOF` after ~0.5 s on a lossy or slow path, where the other families retry and get through — not root-caused | section below |
| CEN-O5 | On a link that already has seconds of queue the connection proof (2 × 4 s) finishes nothing, and the engine says what it says for a swallowed handshake: "could not connect", `tls_handshake_failed` or `unknown`, a cooldown. One route cannot tell a handshake that is still crawling from one that was dropped | section below (under CEN-6) |

---

## F-002 — the pinned mgmt artefact predates Wave 5; three families are unprovisionable from main

**What.** `publisher/deploy/cloudinit/artifacts.go` pins
`daal-relay-mgmt-0.1.0-linux-amd64` at SHA-256 `e8cb16e8…65df66b` (the file
was last changed 2026-08-18 09:14). The mgmt-side support for shadowsocks,
anytls and tuic users landed in `a656a27` ("Wave 5: every family a
self-hosted relay can actually serve", 2026-08-18 15:30) and the pin was not
moved. A build of today's tree with the release flags hashes to
`f11cf36a…38bc5dcc`.

So every relay provisioned from `main` downloads a mgmt daemon that:

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
./run.sh clean                 # pinned: 3 families red
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

**Not fixed here** because the fix is a release, not a code change: rebuild
with `tools/release/relay-v1.5.0.sh` (or a v1.5.1), sign with the release
key, upload, bump `Sha256` + `SigHex` in `artifacts.go` **and, in the same
commit, set `PinnedMgmtServesOptInFamilies` (same file) and its mirror
`RELEASED_RELAY_SERVES_EXTRA_FAMILIES` (`client-ui/src/publisher/
extraFamilies.ts`) to `true`** — that is what unlocks the wizard's "More
ways to connect" switches and turns `provision --families`' "will be
asked to serve" back into "will serve" (FAM-2, FAM-3). `go test
./deploy/cloudinit/` fails on a bump without the flip and on a flip
without a bump. After that,
`./run.sh clean` (no flag) is the acceptance test: it downloads through the
real verifier, so a wrong hash or signature fails it too.

Worth adding to the release checklist: `./daal e2e full` before a tag. Its
world `release.all-families` is exactly `./run.sh clean` without
`--mgmt=tree`; once the release is out it goes green and the run reports
"F-002 did not reproduce" until the entry is deleted from
`known-findings.json`.

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

## F-005 — the app signs before it has what a signed endpoint needs

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

## FAM-6 — naive carries no app UDP except DNS (the `blocked` cell is a limitation, not a pass)

**What.** FAM-1's fix makes names resolve on naive by answering UDP/53
inside the engine. It does nothing for any other datagram. The naive
outbound the publisher mints (`relaypack/client_outbound.go`, case
`"naive"`) is HTTP/2 CONNECT with no `udp_over_tcp`, so sing-box builds it
with `networks = [tcp]` (`protocol/naive/outbound.go:199-211`) and every
app datagram that is not port 53 is refused inside the engine: the app
gets ICMP port-unreachable, or silence.

**Why it matters.** naive is a default family. On a naive route a browser
falls back from QUIC to TCP and looks fine; anything that is UDP-only —
voice/video calls, most games, QUIC-only clients, an app doing its own DNS
on another port — gets nothing, while the engine reports Connected
(CEN-1). Nothing in the app says "this route carries no UDP".

**How the rig shows it — and how not to read it.** `families/naive.json`
declares `"udp": "blocked"`, so the matrix prints `blocked` in naive's
`udp` column as an `ok` cell:

```
./run.sh clean naive
  ok   family/naive  udp  expect=blocked  got=blocked
```

That `ok` means "the product still behaves as declared". It is the only
family whose `udp` expectation is not `pass`, and it is a product
limitation the rig is holding still, not something that works.

**The candidate fix, tried.** sing-box's naive outbound takes
`udp_over_tcp` (it then advertises UDP and tunnels datagrams in a CONNECT
stream to the UoT magic address), and the naive **inbound** accepts that
unconditionally — `protocol/naive/inbound.go:60` wraps its router in
`uot.NewRouter`, exactly like the shadowsocks inbound whose client side
Daal already mints with `udp_over_tcp` (`client_outbound.go`, case
`"shadowsocks"`). So no box-side change and no relay release is needed.
Tried on 2026-11-18 in a scratch copy of this tree (not in the tree
itself) with one line added to the naive outbound,
`"udp_over_tcp": {"enabled": true, "version": 2}`:

```
./run.sh clean naive            (released sing-box 1.13.12 + pinned mgmt; same with --mgmt=tree)
  ok   family/naive  tunnel  expect=pass     got=pass
  FAIL family/naive  udp     expect=blocked  got=pass     {"small_ok":true,"big_ok":true,"big_bytes":1400,"target_saw":"192.0.2.2"}
  ok   family/naive  dns     expect=pass     got=pass
  ok   family/naive  wrongcreds / wrongserver  blocked
relay sing-box log:  inbound/naive[naive-in]: inbound UoT connection to 192.0.2.80:7
                     inbound/naive[naive-in]: inbound UoT connection to 1.1.1.1:53
```

Both datagram sizes round-trip and the target sees them from the relay.
(`outboundCarriesUDP` in `core/engine/config.go` already reads
`udp_over_tcp` on a naive outbound, so with it the DNS hijack steps aside
and lookups ride UoT too — the second log line.) Only the clean scenario
was run this way; no censor scenario, no soak.

**Why it is not applied here.** It changes the bytes minted for a default
family, and three things the rig cannot answer need deciding first:

* an app build already in the field whose engine does not know
  `udp_over_tcp` on the naive outbound would reject the whole outbound
  (sing-box refuses unknown fields) — a re-minted pack could cost such a
  recipient the route. Not checked: which sing-box each shipped APK embeds;
* datagrams over one TCP stream (head-of-line blocking; QUIC inside TCP)
  through Cronet on a real phone — throughput and battery are unknown, and
  INT-1's close race gets a new kind of long-lived stream to hit;
* packs already issued do not change: recipients need a re-mint.

**When it is fixed:** flip `"udp"` to `"pass"` in `families/naive.json`
(the check goes red the moment a pack carries UDP on naive, so this cannot
be missed), move this entry to "Fixed", and run `./e2e.sh full` — naive's
`udp` under every censor scenario is then asserted for the first time.

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
relay downloads serves none of the three. Reproduced on the pinned box:

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
`publisher/deploy/cloudinit/artifacts.go` (false today), mirrored for the
UI as `RELEASED_RELAY_SERVES_EXTRA_FAMILIES` in `extraFamilies.ts`. While
it is false the section is still there and still explains each option,
but every switch is disabled and unticked, one line says why ("You cannot
turn these on yet. The software that a new server installs does not
include them…", en+fa), the collapsed line reads "Not available yet", and
`enabledFamiliesFor` returns `[]` whatever was ticked or remembered in
`localStorage` — the wizard cannot ask a server for them. The feature is
not removed: flipping the two constants in the commit that bumps the pin
restores exactly the behaviour described above, and that state keeps its
tests (they run with the gate open).

Held by: `TestPinnedMgmtOptInGateMatchesThePin` (stale hash ⇔ gate shut;
a bump that forgets the flip, or a flip without a bump, fails),
`TestOptInFamiliesOfMgmtAreTheProfilesOptInFamilies`,
`tools/check-toolbox-profiles.mjs` §5 and the vitest suite "while the
released relay software cannot serve them" (which also reads the Go
constant). **Not pinned by the rig** (above the ABI), and, as before,
**the app was not run**. The rig evidence for the underlying fact is
unchanged: F-002 stays open and `release.all-families` stays KNOWN-red
until the release.

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
`TestResolveFamilies_UnservedComesFromThePin`.

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

**Fixed in the tree** — the box now learns its own family set, and
everything follows it:

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
cloud-init has no upgrade path: this needs the planned relay re-release
(new `daal-relay-mgmt`) AND a fresh provision. A relay with new
cloud-init and the currently pinned daemon serves the default set
correctly (world `release`) but still creates `ss-in`/`anytls-in`, and
cannot be provisioned at all without vless-reality (the old daemon
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

## O-3 — W5-1, observed (fixed in the tree with FAM-4)

**Now:** on a `--mgmt=tree` world the same checks record
`listener_on_box: false` — the tree daemon creates inbounds only for the
families in `/etc/daal/families` (FAM-4). A relay on the pinned daemon
still binds both. As found:

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
* After an L3, naive presents that DNS name as SNI — the cover host the
  relay was provisioned with, on the relay's own address. If a later L2
  moved REALITY's cover host because the old name was being filtered,
  naive on a moved address still shows the old one. Re-issuing the
  certificate with the same key on `rotate-tls` would close that; it is a
  change to `daal-relay-mgmt` and was not made here.
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

## LC-1 — a mgmt token already used once could be replayed with a different body (fixed in the tree; shipped relays still accept it)

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

**What the fix does not cover (residual, stated in spec §4.8).** The nonce
set is in memory, so single use holds for the life of the mgmt process
only: restart `daal-relay-mgmt` (or reboot the box) inside the accept
window and a captured token is presentable once more — e.g. a used
`users-revoke` token replayed against another recipient. This was already
true of the two address verbs; six verbs now rely on it. And a token is
spent when it verifies, even if the handler then rejects the body
(400/405/500). Signing `sha256(body)` into the token remains the full fix
(a coordinated wire change on both ends); it closes the restart case too,
because a replayed token could then only repeat the identical request.
Not exercised by the rig: `mgmtauth` does not restart the daemon mid-op.

**Still true of every relay in the field**, and of every relay provisioned
until the mgmt artefact is rebuilt, signed and re-pinned (the same release
F-002 needs). `./run.sh --ops mgmtauth clean vless-reality` (pinned) is red
on `replay.users-revoke`; `--mgmt=tree` is green.

**Everything else the op tried was refused** on both binaries: no
`Authorization`, a valid token under `Bearer`, garbage, an empty signature,
a stranger's key, the publisher's signature for another endpoint
(`users-list` → `/users/revoke`, `rotate-credentials` → `/users/revoke`),
a token 400 s old, a token 400 s in the future, unsigned `/rotate-tls` and
`/bind-address`, and a replayed `/bind-address` token aimed at a second
address. After all of it the box's sing-box config was byte-identical and
the targeted recipient still connected.

## LC-O1 — `rotate-tls` says every recipient needs a new pack; six of seven families keep working

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

## LC-O2 — `/whoami` cannot be called by the publisher

The box serves `/whoami` behind a token whose op must be `whoami`
(`opFromPath`). `mgmt.MintToken` refuses to mint that op (it is not in its
switch), and nothing under `publisher/` or the wizard calls the endpoint.
The route is one of the nine the spec counts, has a handler, a counter and
a response type — and no caller that could authenticate to it. Either wire
it (the helper-IP "verified" source the wizard's DB already has a slot for)
or drop it from the surface.

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
the **pinned** `daal-relay-mgmt` (the one relays in the field run),
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

**Still open (found while fixing, not changed).** While a lost
connection is being retried the page is in the "connecting" state, where
a tap means *connect*: it calls `connect` for the same route, which the
cooldown refuses, and the recovery sheet opens. There is no way to
disconnect from that state on the Connection page. And the error state
stays until the user picks a route or disconnects — it does not clear
when the cooldown ends.

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

That is recorded, not fixed. From one route's seat a handshake still
crawling when the budget ends is the same silence as one a filter
dropped (`specs/failure-taxonomy-v1.md`, "What one route can see", now
says so). What would tell them apart is a measurement the engine does not
make: how long the bare SYN to the relay took in the reach check (seconds
behind a queue, milliseconds under an SNI filter), or bytes still
arriving when the attempt timed out. Until then a phone on a link this
congested is told "could not connect" and waits out a cooldown, and the
publisher's recommender is sent the SNI-block signal for it.

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
IMC 2020; `research/protocol-level-anatomy.md`). Whether it matters for
shadowsocks-2022 as sing-box implements it is for someone who knows that
code to decide; it is recorded because the rig can now measure it in one
line and nothing had. It also shaped the rig: an opaque-first-flight
family's "reset after data" is attributed to the censor only when the
censor's own DPI log shows a rule fired on that flow.

Reproduce: `./run.sh --mgmt=tree --shell clean`, then
`ip netns exec client bin/wb rawprobe --kind bytes --addr 203.0.113.10 --port 8446`.

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

*Also not verified*: iOS/darwin/windows builds; `cmd/daal-soak-engine`
beyond `go build`.

*Upstream report*: none to file — upstream found and fixed it. If a
reference is wanted for a sing-box 1.13.x backport request: "naive
outbound: process SIGSEGV in `cronet-go` `BidirectionalConn.Close` →
`BidirectionalStream.Cancel` racing `terminate` → `Destroy` (fixed in
cronet-go 172bb4ede18c, shipped in 1.14.1); 1.13.21 still pins
cronet-go ec9a39c5ba3b, which has the race."

## INT-2 — naive: a relay whose naive inbound refuses every TLS handshake until sing-box restarts (root-caused: sing-box start-up race; fixed in the tree daemon)

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

**Fix (in the tree).** `appendNaiveUser` now writes
`"alpn": ["h2", "h3"]` into `naive-in`'s tls block — exactly the value the
usual interleaving produces, so a good start behaves as before — and with
the key present neither branch writes, so there is no race. It is applied
on every user add, so an inbound created by an older daemon is healed by
the next provision; an explicit alpn is left alone. Pinned by
`TestAppendNaiveUserCreatesInbound` and `TestNaiveALPNHealsAnOlderInbound`.
3000 starts with the key: 0 dead (3000 without: 3). That count alone would
be thin; the argument is the source — with the key set there is no write.

**What is still open.**

- **Released relays.** The pinned `daal-relay-mgmt` does not write the
  key, so every fielded relay still runs the race until a mgmt release
  ships AND a recipient is added afterwards (the heal runs on add; a
  relay nobody touches keeps its old `naive-in`). `known-findings.json`
  therefore keeps INT-2 for `box=pinned` only, as an intermittent with a
  budget of 4. On a tree box a naive session with this face is now an
  unexpected red.
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
