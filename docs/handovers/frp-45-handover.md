# Phase 45 handover — Data plane: in-process sing-box + Android VpnService

**Status:** **SHIPPED.** As written on 2026-08-14 the exit gate was blocked on a live relay + test `.sbpx` (not on code). It was met on **2026-08-15**: all four transport tiers — vless-reality, websocket-tls, naive/Cronet, hysteria2 — carried real tunneled traffic on the device against a live relay, through the proper publisher pipeline. The sections below are preserved as the 2026-08-14 record; read `docs/backlog-post-45.md` for what happened after.
**Session:** 2026-08-14. **Device:** Samsung SM-S931B, One UI 16 / Android 16 / API 36, wireless adb `192.168.0.172:39471`.
**Commits:** `ff7b822`..`HEAD` on `main` (see below).

## 1. What this session did

The Phase 45 code had been committed in `73f6c21` ("daal-platform plugin") but **never compiled with `-tags singbox`** — the driver half was missing and the sing-box call sites were written against a stale API. This session made it build, tested it both ways, cross-compiled all Android ABIs, and drove the app to the connect screen on the real device.

| Commit | What |
|---|---|
| `ff7b822` | fix(engine): make the singbox driver compile against sing-box v1.13 — new `platform_singbox.go` (androidPlatform: TUN fd via `OpenInterface`, protect via `AutoDetectInterfaceControl`, static no-op interface monitor), cgo protect shim (+ no-cgo fallback), `engine_singbox.go` ported to `include.Context` + `json.UnmarshalExtendedContext` + `service.ContextWith[adapter.PlatformInterface]`; abi `newEngineDriver` seam. |
| `6b4a2c7` | build: `-tags cshared` → `cshared,singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api` + `-ldflags "-s -w"` in both engine build scripts. |
| `52afc55` | test(trust): anchor rotation tests to the fixture window (were time-bombed since 2026-06-05). |
| `9776c48` | feat(desktop): recvmsg/SCM_RIGHTS `open_fd` + `deliver_tun_fd` in the tun-helper client + socketpair tests (Part 4, additive half). |
| `d928fff` | fix(abi): publish the global `Core` via `atomic.Pointer` — fixes a pre-existing `go test -race ./abi/` failure. |
| `54abbf4` | docs(gate): record the overdue 2026-Q3 public-directory gate eval (HOLD, as designed). |
| `15493dd` | docs(handover): retroactive FRP-14 handover. |
| `3ed9397` | docs(spec): renumber the double-assigned RP024 → RP025. |

## 2. Exit checklist status (mirrors the phase doc)

**Green (verified this session):**
- `go test ./core/...` (no tag) green, incl. the `!singbox` driver-selection twin.
- `go test -tags singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api ./core/...` green, incl. the `singbox` twin + `TestSetTunFdOwnershipSemantics` + `TestProtectCallbackRegistration`.
- `libdaalcore.so` built with the full tag set for arm64-v8a / armeabi-v7a / x86_64. (**Reconciled 2026-08-17:** the build matrix is **3** ABIs — arm64-v8a, armeabi-v7a, x86_64. `tools/build-engine-android.sh` still builds 3; `x86` is deliberately not in the matrix. The phase doc's "4 ABIs" wording was wrong and the phase doc now says 3.)
- ABI symbol gate = **56** `T engine_` on every ABI (checked with `llvm-nm -D --defined-only`). Sizes 41.5 / 36.7 / 41.5 MB, all under the 60 MB budget. *(Correct as measured; the count is **58** from `05d0e30` (2026-08-15) onward.)*
- APK builds (universal, 182 MB signed), installs, launches. No `UnsatisfiedLinkError`, no native crash; onboarding → language → permissions → add-source → Connection screen all render.
- Merged manifest (`app/build/intermediates/merged_manifests/universalRelease/.../AndroidManifest.xml`) carries `DaalVpnService` + `BIND_VPN_SERVICE` + `FOREGROUND_SERVICE_SPECIAL_USE` + the `vpn` FGS-subtype property + the `android.net.VpnService` intent filter + `POST_NOTIFICATIONS`.

**Blocked on a live relay + test `.sbpx` (NOT on code):**
- VPN consent dialog + foreground notification on first Connect. Verified the app reaches the connect screen and that `vpn_start` correctly no-ops when no route is selected (the guard works); the consent path fires only once a route is imported.
- In-tunnel curl returns the relay egress IP (device WAN baseline: **92.34.5.244**).
- Clean disconnect tears down the VPN network + notification.

**Deferred within the phase (per spec, after the Android gate is green):**
- Part 4 desktop convergence: the recvmsg fd-receive path landed (`9776c48`), but retiring `daal-desktop-core/src/singbox.rs` + the Clash REST path and flipping desktop builds to `-tags singbox` is intentionally still pending. Desktop builds (`./daal`, `appveyor.yml`) deliberately keep `-tags cshared` (stub) because the real driver hard-fails without a TUN fd.
- `libsing_box.so` deletion — this session's `tauri android init` did not regenerate the stale 58 MB blob; confirm with `unzip -l` on the APK and delete any staged copy before release.

## 3. How to finish the exit gate (next session)

1. Get a test `.sbpx` (or `.sbp`) whose active route points at a **reachable relay with an egress IP ≠ 92.34.5.244**. A self-contained test pack that points nowhere real cannot prove egress rewriting.
2. Push it to the device: `adb -s 192.168.0.172:39471 push pack.sbpx /sdcard/Download/`, then import via the app's "Add a source" screen (or the AddEntryModal `.sbpx` magic-sniff path).
3. Select the route on the Connection screen, tap **Press to connect** → accept the system VPN consent dialog → confirm the "Daal — Tunnel active" foreground notification.
4. `adb -s … shell curl -s https://api.ipify.org` → must return the relay egress IP.
5. Disconnect → `adb … shell dumpsys connectivity | grep -i vpn` shows no active VPN network.
6. Then: delete stale `libsing_box.so` if present, tick the last checklist boxes, do the Part 4 desktop convergence, and bump the tag per the orphan-branch pattern.

## 3b. FRP-4a packaging fix (daal-deploy bundled for the on-device wizard)

Surfaced mid-session: the on-device Family Relay Publisher wizard errored
`pricing: daal-deploy not on PATH; install FRP-4a binary` at Step 3. The
wizard shells out to `daal-deploy` (Rust `resolve_deploy_binary()` expects
`libdaal_deploy.so` in the native-lib dir), but the binary was never
cross-compiled or packaged — the FRP-4a packaging the Phase 45 spec left
out of scope. Fixed (`63b9a70`):

- `tools/build-deploy-android.sh` (NEW) cross-compiles `cmd/daal-deploy`
  as a PIE executable named `libdaal_deploy.so` (the only place modern
  Android permits exec) into jniLibs per ABI.
- Plugin manifest forces `android:extractNativeLibs=true` (tools:replace).
  NOTE: AGP 8 ignores that manifest attribute and honours the gradle
  `packaging { jniLibs { useLegacyPackaging = true } }` DSL instead —
  which is what actually flips the merged manifest to `extractNativeLibs
  ="true"`. That DSL already lives in `tools/patch-android-signing.sh`
  (line ~121); the manifest attribute is belt-and-suspenders.

Verified on device: `libdaal_deploy.so` extracted to
`…/lib/arm64/libdaal_deploy.so` (mode `-r-xr-xr-x`), runs directly
(`adb shell <path> --help` prints the daal-deploy usage), and the wizard
now advances past Step 1 → Step 2 (Cloud account / token entry) where it
previously dead-ended. Still needs a Hetzner token (entered on-device)
to exercise the pricing/provision steps.

**Canonical Android build sequence** (the manual `tauri android init`
this session skipped the patch steps): `tauri android init` →
`tools/build-engine-android.sh` → `tools/build-deploy-android.sh` →
`tools/patch-android-signing.sh` (signing + useLegacyPackaging + strips
the dead `assets/resources/libdaalcore.so`) →
`tools/patch-android-mainactivity.sh` → `tauri android build`. Neither
`build-deploy-android.sh` nor `patch-android-mainactivity.sh` is wired
into a committed CI android workflow yet — wire both in beside
`build-engine-android.sh`.

## 3c. MainActivity.shareFile was missing from version control

Surfaced when the "Send relay pack" button threw `NoSuchMethodError:
MainActivity.shareFile`. The Rust shell JNI-calls a static
`MainActivity.shareFile(String,String,String)` (lib.rs ~1744/1830), but
`tauri android init` regenerates a vanilla MainActivity.kt and the
custom method existed only in a past session's gitignored `gen/` tree —
it was never committed. Restored durably as
`tools/patch-android-mainactivity.sh` (`instance` holder + `shareFile`
using the existing `org.daal.desktop.fileprovider`, whose
`cache-path "."` already covers the staging dir). This is a general
lesson: anything hand-added to `gen/android` is lost on re-init unless
captured in a committed patch script.

## 3d. Publisher wizard bugs found driving a real Hetzner deploy

Driving the on-device Family Relay Publisher against a live Hetzner
token surfaced a chain of real bugs, each fixed:

- **`fix(hetzner)` `dd6d24c`** — `ListServerTypes` offered retired
  server types (cx11) that still carry a pricing entry for the region;
  the wizard auto-picks the cheapest, so provision failed with
  "unsupported location for server type". Now filters on the
  per-location `Available` flag.
- **`fix(publisher)` `ab772a4`** — two linked bugs left a
  successfully-provisioned operator un-resumable: (a) hetzner
  `recordFromServer` read ServerType/Region from the ServerCreate
  response, which Hetzner can return empty, overwriting the good
  pre-provision profile → fall back to the requested opts; (b)
  `derive_wizard_step` then regressed the provisioned operator to the
  `pricing` step, but the PIN is only collected on the `provider` step,
  so resume landed on a PIN-gated dead end ("invalid PIN", no field to
  fix it). Now a provisioned operator resumes at the PIN-free
  `distribute`/`sign` step.

- **`fix(publisher)` `e9ba2de`** — the Step 7 "Add recipient" inline PIN
  field was `{!pin && <Input value={pin} onChange={setPin}/>}`, so it
  unmounted on the first keystroke (pin non-empty → `!pin` false) and
  the PIN could never be entered — every Add recipient failed "invalid
  PIN". The helper-IP input had the same defect. Now gated on a
  snapshot taken when Step 7 opens (`recipientPinFieldOpen` /
  `recipientHelperIpFieldOpen`).
- **Systemic: the custom Android Kotlin layer was never committed.**
  `MainActivity.shareFile` and `DaalKeystore` both lived only in a past
  session's gitignored `gen/android` and were lost on a clean
  `tauri android init` — a clean build was missing them. Restored via
  `tools/patch-android-mainactivity.sh` (now the source of truth for
  that layer, with R8 keep rules). More classes may still be missing
  further down the recipient-import/connect flow.

**Known follow-up (not yet fixed):** operators still mid-setup
(pricing/keys/provision) that need the PIN on resume have no inline
PIN-unlock — the user must step back to the provider step, where the
token field is empty on resume (re-pasting the token defeats the
encrypted-token design). The intended UX is "click existing server →
enter PIN → continue" without re-entering the token; that unlock
affordance still needs building. Also minor: the wizard's `error`
state persists across step changes (stale "invalid PIN" shows on
unrelated steps).

## 3e. THE REMAINING BLOCKER: routes carry no client sing-box config

After every plumbing fix above, the on-device flow reaches the real
exit gate and stops there: `engine_set_route("r1")` returns **-1**,
`DaalVpnService` logs "tearing down", the VPN network never comes up,
and the in-tunnel curl still returns the device WAN IP. The consent
dialog, TUN fd handoff, protect callback, and VpnService lifecycle all
work — the failure is one layer deeper, in the *content* of the route.

**Root cause (traced end to end, not a Phase 45 regression):** the
`.sbp`/`.sbpx` route profiles contain only RelayPack *metadata*, never
a client sing-box outbound. Chain of evidence:

- `publisher/deploy/relaypack/candidate_render.go:60-107` writes each
  `profiles/<id>.json` as `{ ...Params, "port": <n>, "_relaypack": {…} }`.
- `publisher/deploy/providers/hetzner/profile_render.go:44` builds the
  `CandidateMeta` with only Family/ExposureMode/Port/risk-tags and
  **no `Params`** — so the profile has no `type`, `server`, `uuid`, or
  reality keys. (I verified the exported `My_Family_Relay.sbp`: every
  profile is literally `{"_relaypack":{…},"port":443}`.)
- `core/engine/config.go` `BuildSingBoxConfig` wraps that stub as the
  `active` outbound (adds only `tag`), producing an outbound with **no
  `type`** → sing-box `box.New`/`instance.Start` rejects it →
  `core/abi/abi.go` `SetRoute` returns the error → ABI returns -1.
- The per-recipient credentials that *would* populate an outbound
  (`vless_uuid`, `reality_short_id`, `ws_path`, …) are minted by
  `/users/provision` and stored in the wizard DB, but the `.sbpx`
  wraps the credential-less operator-level `{operator_id}.sbp` —
  `client-shell/tauri/daal-wizard/src/recipient_book.rs:180-185`
  says so verbatim: *"The inner `.sbp` is the operator-level Step-6
  output (shared creds for now; per-recipient inbound rewriting lands
  in Tier-2)."*
- Worse, even the minted creds are insufficient: `UserCreds`
  (`publisher/deploy/mgmt/users.go:20`, `cmd/daal-relay-mgmt/users.go:41`)
  has **no `reality_public_key`**, which a vless-reality client
  requires. It is never derived from the box's reality private key or
  shipped to the recipient.
- Also note the relay only ships the `vless-in` (443) inbound plus a
  per-recipient `ws-r<id>` inbound; hysteria2 and naive inbounds are
  deliberately NOT on the box
  (`hetzner/profile_render.go:63-70`), so of the four routes only r1
  (vless-reality) and r2 (websocket-tls) could ever connect even once
  the config is assembled.

**What it takes to close the gate (a follow-on phase, "FRP-14 Tier-2"):**
1. Capture the box's REALITY public key at provision (derive from the
   cloud-init private key) and add it to `UserCreds` + the wizard DB.
2. Assemble a real client sing-box outbound per family from
   IP (in `_relaypack` public_risk_tags) + port + per-recipient creds
   + reality pubkey, and write it into the per-recipient `.sbp`
   `profiles/<id>.json` before `users-pack-sbpx` wraps it.
3. Scope to the transports the box actually serves (vless-reality,
   websocket-tls) until the hy2/naive inbounds ship.

Until that exists, no imported pack can produce a working tunnel — the
data plane is proven right up to the sing-box config handoff.

## 3f. FRP-14 Tier-2: the client-config assembly — BUILT (2026-08-14)

The gap in §3e is now closed in code (commits `f26ec3b`, `183ed76`,
`eb4f6d6` + mgmt/publisher changes), all unit-tested locally:

- **mgmt plane** (`cmd/daal-relay-mgmt`): `/users/provision` now echoes
  the box-wide `reality_public_key` (from `/etc/daal/reality.pub`,
  already written at cloud-init) and `tls_cert_sha256` (base64 SPKI pin
  of the self-signed leaf), so the publisher never SSHes the box.
- **assembler** (`publisher/deploy/relaypack/client_outbound.go`):
  `ClientOutboundForFamily` renders a concrete client outbound per
  family — vless-reality (REALITY, bare-IP-friendly, no cert),
  websocket-tls / hysteria2 / naive (TLS pinned via
  `certificate_public_key_sha256`, never `insecure`).
- **rewrite** (`relaypack/client_pack.go`):
  `RewriteProfilesForRecipient` swaps each `profiles/<id>.json` in the
  signed operator `.sbp` with the assembled outbound and re-emits
  WITHOUT re-signing — profiles aren't covered by the manifest
  signature; the `.sbpx` age envelope carries per-recipient integrity.
  Fails closed on any unserviceable route.
- **pipeline**: `daal-deploy users-pack-sbpx` gained `--creds-file` +
  `--server`; the wizard's `recipient_provision` captures the creds
  JSON (incl. reality pubkey/tls pin) and the relay IP from the
  operator record and passes them through.
- **validated locally** (`core/engine/client_outbound_singbox_test.go`,
  `-tags singbox`): the assembled vless-reality, websocket-tls, and
  hysteria2 outbounds all parse cleanly through sing-box's own option
  decoder after `BuildSingBoxConfig` — so the recipient engine accepts
  them. No device needed to catch config-field bugs.

**What still blocks a green on-device tunnel:**
1. The running relay box has the OLD `daal-relay-mgmt` (no reality-pub
   echo), so a **fresh provision is mandatory** to pick up the new
   binary — cost + the operator's Hetzner token. The APK's bundled
   `libdaal_deploy.so` also needs rebuilding from the new code.
2. **Box-side TLS for ws/hy2/naive (§3g / task 13, NOT done):** the box
   ships only `vless-in` (REALITY, no cert); `appendHy2User`/
   `appendNaiveUser` no-op when their inbounds are absent, and the ws
   inbound sets `tls.enabled` with no certificate. Making those three
   serviceable on a bare IP needs a self-signed cert
   (`/etc/daal/tls-cert.pem`) generated at cloud-init, hy2-in/naive-in
   inbounds added to the default config, and the ws inbound given the
   cert — then the client pins it via the `tls_cert_sha256` the mgmt
   plane already returns. Until then, **only vless-reality is
   serviceable**, and the default profile still advertises all four —
   so recipients get two dead routes (hy2/naive) + one unverified
   (ws). Robustness fix: either finish the box TLS story or gate the
   advertised set to what the box serves.

**Bottom line:** vless-reality is code-complete, sing-box-validated, and
ready to prove on-device the moment a box is re-provisioned with the new
mgmt binary. The other three transports are client-complete but need the
box-side self-signed-TLS build.

## 4. Toolchain notes (this machine)

- Android SDK at `~/Android/sdk` (cmdline-tools symlinked so tauri's env check passes: `cmdline-tools/bin -> latest/bin`), NDK **r27 / 27.0.12077973** at `~/Android/android-ndk-r27`, symlinked into `~/Android/sdk/ndk/27.0.12077973`.
- **Java:** the system OpenJDK packages are JRE-only (no `javac`) — gradle needs a full JDK. Temurin JDK 21 unpacked at `~/Android/jdk21`; build with `JAVA_HOME=~/Android/jdk21`.
- Test keystore: `gen/android/daal-phase45-test.jks` (alias `daaltest`, storepass/keypass `daal1234`) — dev-only, do NOT ship. The old on-device app was signed by a keystore not on this machine, so the update required uninstall.
- `gen/android/` is gitignored; the jniLibs must be re-copied after any `tauri android init` (it wipes `gen/android`).

## 5. Known-red / follow-ups (tracked, not blocking Phase 45)

- `bundle/go` `TestSubkeySignedSampleArtefact` red since 2026-08-01 (90-day cert window). Regeneration needs `samples/keys-A/publisher.priv`, which is gitignored and only exists on the FRP-7.5 machine. `TestDeterministicBuildIsByteIdentical` was fixed (`5daddf5`).
- Pre-existing `abi.Init` race fixed (`d928fff`).
- FRP-14 was undocumented — retroactive handover added (`15493dd`); its own follow-ups (mission E2E scripts, `v2-closure-v1.md` update, FA strings) are listed there.
