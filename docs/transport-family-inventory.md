# Transport family inventory — can we serve it, can we dial it

**What this answers:** for every value in the `TransportFamily`
enum, three separate questions that this repo has repeatedly
collapsed into one:

1. **Can a self-hosted Daal publisher SERVE it?** — is there a
   relay inbound, a port, a firewall rule, and a per-recipient
   credential path.
2. **Can the shipped client DIAL it?** — does sing-box 1.13.12
   register an outbound of that type, and does
   `core/engine/config.go` build a config that can hold it.
3. **What label does the user see?** — the maturity badge on the
   route card.

They are not the same question and a family can fail any one of
them. **A family that mints but cannot be dialled is worse than
no family: it is a route the user selects and loses.**

**Authority.** The machine-readable answer is
`core/routestore/family.go`'s `familyMaturity` map;
`client-ui/src/contract/derive_tree.ts` mirrors it for the UI and
must never drift. `specs/transport-families-v1.md` mirrors this
document. Where any of them disagrees with the engine's outbound
registry, **the registry is right**.

Derived 2026-08-18 on `wave5-transport-families`.

## The engine's outbound registry, quoted rather than remembered

`github.com/sagernet/sing-box@v1.13.12/include/registry.go`
`OutboundRegistry()` registers exactly:

```
direct  block  selector  urltest  socks  http
shadowsocks  vmess  trojan  naive  tor  ssh  shadowtls  vless  anytls
+ under -tags with_quic:  hysteria  hysteria2  tuic
+ stubs that RETURN AN ERROR: shadowsocksr, wireguard
```

`tools/build-engine-android.sh` and `build-engine-ios.sh` both
pass `with_quic`, so the QUIC three are present in shipped
builds. WireGuard is an `endpoints[]` adapter, not an outbound,
and `core/engine/config.go`'s `SingBoxConfig` has no `Endpoints`
field. **There is no `webtunnel`, `snowflake`, `masque`,
`psiphon`, `conjure` or wasm-module outbound and there never
was.**

## The inventory

| # | Family | Can we SERVE it | Can we DIAL it | Label | Action taken in Wave 5 |
|---|---|---|---|---|---|
| 1 | `vless-reality` | **yes** — 443/tcp, rendered by `hetzner/profile_render.go` | **yes** — `vless` outbound | `stable` | none; field-proven tier |
| 2 | `naive` | **yes** — 8444/tcp, `daal-relay-mgmt` | **yes** — naive outbound | `stable` | none; field-proven tier |
| 3 | `websocket-tls` | **yes** — 8445/tcp, shared `ws-in` inbound | **yes** — vless+ws outbound | `stable` | none; field-proven tier |
| 4 | `hysteria2` | **yes** — 443/udp, `profile_render.go` | **yes** — `with_quic` | `stable` | none; field-proven tier |
| 5 | `tuic` | **yes, but** — 8443/udp, optional `tuic-in`; **8443 is not whitelisted egress in Iran, so the route is worth ~zero there** | **yes** — `with_quic` | `experimental` | none; Wave 1 demoted it from `stable`. Kept as the exemplar experimental family in `core/abi/abi_test.go` |
| 6 | `shadowsocks` | **yes** (Wave 5, relay lane) — 8446/tcp, shadowsocks-2022 only; same not-whitelisted caveat | **yes** — shadowsocks outbound | `experimental` | none by this lane; label already correct |
| 7 | `anytls` | **yes** (Wave 5, relay lane) — 8447/tcp; same not-whitelisted caveat | **yes** — `anytls` outbound | `experimental` | new enum value this wave; gated on `spec_version >= 5` |
| 8 | `tor-bridge` | **n/a — publisher-independent.** No relay inbound, no credentials, no firewall rule. The only route Daal offers with no Daal relay in existence | **NO, not by any artifact that exists.** The `tor` outbound is real and registered, but it EXECS a tor binary and no build packages one: jniLibs carries no `libtor.so` for any ABI, and `tools/build-tor-android.sh` says "STATUS: NEVER RUN" in its own header. Every tor route fails at config time on every installable build | `unsupported` | promoted to `experimental` by the tor lane; **returned to `unsupported` by the repair pass** — the label is a claim about the artifact, not the code. The desktop resolver was also repaired (it looked for the Android filename and could never reach its own PATH fallback), so a Linux desktop with the distro `tor` package now resolves; that is not an artifact Daal ships |
| 9 | `wireguard` | **no** — port assigned (51820/udp) and a default-off `iran-default` profile candidate, but no relay inbound, no credential, no firewall rule. Paste/import only | **yes** (Wave 5, wireguard lane) — `core/engine/config.go` gained the `endpoints[]` slot and the importer emits a real endpoint object; the Android build passes `with_wireguard` | `experimental` | **fixed the docs** that still called it `stable`, and reconciled `derive_tree.ts`, which the wireguard lane had not yet updated. Note the copy constraint that lane recorded: plain WireGuard is a named immediate-block target in Iran and must not borrow AmneziaWG's track record |
| 10 | `amneziawg` | **no** | **NO** — sing-box 1.13.12 contains no AmneziaWG code at all, so there is nowhere to put the `Jc/S1/H1..H4` parameters that ARE the family. An AmneziaWG conf imports as a **downgraded plain-wireguard** route, labelled `wireguard`, because WireGuard is what goes on the wire | `unsupported` | **fixed the docs**; became the "never widens" exemplar in `core/abi/d2_summaries_proven_test.go` after wireguard vacated the role |
| 11 | `webtunnel` | **no** | **not as a family.** It is a Tor pluggable transport; reachable only as `Bridge webtunnel …` inside a `tor-bridge` route (`core/engine/torbin.go` → `libwebtunnel.so`) | `unsupported` (was `experimental`) | **demoted.** Marked `bundle/go/publisher/webtunnel.go` dormant; the `daal-publish webtunnel-bridge` verb now warns at the point of use. **Re-scoped: effective in China, FAILS in Iran** |
| 12 | `snowflake` | **no** | **not as a family.** Same shape — `Bridge snowflake …` under `tor-bridge` (`libsnowflake.so`) | `unsupported` (was `experimental`) | **demoted. Deleted `core/transports/snowflake`** (Phase 3B WebRTC handler + tests, zero references). We are not vendoring `pion/webrtc` into `core/go.mod` for a transport the tor outbound already carries |
| 13 | `masque` | **NO, structurally.** A self-hosted MASQUE proxy is one QUIC endpoint with one tenant — none of the provider-anonymity-set value that motivates RFC 9298 | **NO** — no masque outbound in sing-box 1.13.12 | `unsupported` (was `experimental`) | **demoted.** `core/transports/masque` marked DORMANT with both reasons; reason written onto the enum value. Kept: `IsKnownSubmode` has a live (label-only) caller |
| 14 | `psiphon` | **NO, structurally.** A third party's proprietary network. You can hand a client off to Psiphon Inc.; you cannot host it. There is no server side for a publisher to run | **NO** — psiphon-tunnel-core has never been in `core/go.mod` | `unsupported` (was `experimental`) | **demoted. Deleted `core/transports/psiphon`** (zero references). Fixed `psiphon_compiled_in` (see below). Reason written onto the enum value |
| 15 | `conjure` | **NO, structurally.** Refraction needs a COOPERATING ISP running a station on a transit link it owns, answering for unused addresses in its own space. A rented VPS has no link to tap and no space to phantom into | **NO** — gotapdance has never been in `core/go.mod` | `unsupported` (was `experimental`) | **demoted.** Fixed `conjure_compiled_in`. `core/transports/conjure` marked DORMANT — kept only because `HashPhantom` is the sole implementation of a privacy invariant the soak rig asserts. Reason written onto the enum value |
| 16 | `transport_module` | n/a — modules travel inside the pack, not on a relay | **NO, but the only genuine "not yet" here.** The wazero runtime is real and compiled in; `core/wasm.Dial` has **no production caller** and nothing turns a loaded module into a sing-box outbound | `unsupported` (was `experimental`) | **demoted.** Restore to `experimental` when a production dial path exists — not before |
| 17 | `lifeline_relay` | **no** — partner-operated by design | **NO** — `core/lifelinerelay` does not exist. No code at all | `unsupported` (was `experimental`) | **demoted** |
| 18 | `other` | n/a | n/a — parser-only forward-compat slot | `unhandled` | none |

**Totals after this wave and its repair pass: 4 stable · 4
experimental · 9 unsupported · 1 unhandled = 18.** Nine of eighteen
values in the recipient-side vocabulary cannot be dialled by the
client that reads it.

### Serving rows 5–7 needs a re-release, and rows 6–7 need a FRESH relay

Rows 5, 6 and 7 (`tuic`, `shadowsocks`, `anytls`) say "yes" about the
CODE. No relay in the field serves any of them today, and the gap is
not a deploy:

- `cmd/daal-relay-mgmt` ships as a **hash-pinned artifact**
  (`publisher/deploy/cloudinit/artifacts.go`). That file is UNCHANGED
  by this wave, so every existing relay boots an mgmt binary with no
  `ss-in`, no `anytls-in` and no tuic user handling. Reaching a relay
  means: rebuild, re-sign, re-upload, bump the pin — **and rebuild
  `libdaal_deploy.so`**, which embeds the publisher CLI.
- `cloudinit/template.yaml.tmpl` and `v2.yaml.tmpl` DID change, and
  **cloud-init has no upgrade path**. A relay picks those up only on a
  fresh provision. `tuic-in` in particular is written by cloud-init,
  so an existing relay cannot gain tuic at all without being rebuilt.

`publisher/deploy/profiles/loader.go` records the same coupling from
the code side. Read rows 5–7 as "this repository can serve it", not as
fleet capability.

**Concurrency note, stated rather than hidden.** Four lanes wrote
into this worktree at once (relay/shadowsocks+anytls, tor,
wireguard, and this one). Rows 6–9 are other lanes' work, read out
of the tree at the end of this pass rather than assumed. Two
drifts were found and fixed here because the label is this lane's
deliverable: `derive_tree.ts` still had `wireguard: unsupported`
and no `anytls` entry at all — a family absent from that map
renders as `unhandled`, which is the same class of silent
mislabelling the map was written to end. That gate now exists:
`tools/check-family-maturity.mjs` compares `types.go`, `family.go`
and `derive_tree.ts` and runs in `tools/hooks/pre-push`. It compares
LABELS, not the prose beside them — the repair pass found three stale
rationales that no gate can see, so a reason left next to a value you
change is still on you.

## The three that cannot be built by anyone self-hosting

`psiphon`, `conjure` and `masque` are not deferrals. The obstacle
is a property of the protocol, and no amount of engineering in
this repository removes it:

- **conjure** needs a cooperating ISP running a refraction
  station.
- **psiphon** is somebody else's network; hand-off only.
- **masque** has no server implementation in sing-box 1.13.12,
  and its value is infrastructure Daal does not have.

The reasons are written onto the enum values themselves in
`bundle/go/bundle/types.go`, not only here, because that is the
file the next engineer opens. **The enum values stay reserved
forever** — removing one is a wire break for older clients (the
parser rejects unknown values with `bundle_corrupted`) and buys
nothing.

Two more were re-scoped rather than ruled out: **`webtunnel`**
works in China and fails in Iran, and **`snowflake`** must arrive
as a Tor PT. Both are already reachable through `tor-bridge`; what
is unreachable is the family *value*.

## The lie that was fixed

`core/abi/psiphon_compiled.go` hard-coded `psiphonCompiledIn =
true` and `conjure_compiled.go` hard-coded `conjureCompiledIn =
true`. Both flags are surfaced verbatim in
`ExportDiagnostics()` as `psiphon_compiled_in` and
`conjure_compiled_in`, and their documented meaning is *"the
running binary links the vendored tree for this family"*.

**Neither tree has ever been in `core/go.mod`** — not directly,
not indirectly. Every diagnostics blob a user could export
asserted that two vendor trees were linked into a binary
containing not one line of either. The `-tags no_psiphon` escape
that nominally flipped the first flag is passed by **no build
script in the repository**, so the false branch was unreachable
in practice as well as untrue in principle.

**Who saw it.** `ExportDiagnostics()` is the exportable
diagnostics blob — the artefact a user sends when reporting a
problem, and the artefact `test-rigs/distribution-failure` asserts
against. The `psiphon-blob-rotation` soak scenario states in its
own description that it asserts `psiphon_compiled_in` is true.

**What changed.** Both constants are now `false`, in one untagged
file (`core/abi/refraction_compiled.go`) carrying the audit; the
build-tag pair is deleted, because *a build tag whose false branch
is the only reachable branch is a worse lie than a constant*. Both
recorders in `core/abi/refraction.go` now refuse a non-empty route
ID — the engine must not name an active route on a family it
cannot dial — so `psiphon_active_route`, `conjure_active_route`
and `conjure_phantom_in_use` are permanently empty strings. The
key NAMES are unchanged: they are a documented shape read by the
rig, and the names were never the problem.

**Consequence for the rig, stated rather than hidden:** the two 3D
soak scenarios (`psiphon-blob-rotation`, `conjure-phantom-pool`)
now drive a refusal instead of a fiction. Their no-leak invariant
still passes (nothing is recorded, so no raw IP can leak).
Retiring them belongs to the rig lane.

## Dead code: what was deleted, what was marked, and why

The rule applied: **delete only when nothing references it and the
deletion is provable; otherwise mark dormant with the reason.**

| Item | Verdict | Why |
|---|---|---|
| `core/transports/psiphon` | **DELETED** | Zero references repo-wide outside its own tests. A 357-line skeleton documenting a GPLv3 vendoring posture for a tree that is not and will not be in the module graph |
| `core/transports/snowflake` | **DELETED** | Zero references outside its own tests. A `WebRTCDialer` state machine for a path we are not taking. `core/rendezvous`, which it imported, stays — the ABI uses it |
| `core/transports/conjure` | **DORMANT** | Referenced by `core/abi/refraction.go`. `HashPhantom` is the only implementation of the no-raw-IP redaction contract the soak rig asserts against; deleting the package would delete a privacy invariant in order to remove an unreachable dialer |
| `core/abi/refraction.go` | **DORMANT** | Referenced by `ExportDiagnostics`. Recorders now refuse; header states that nothing can activate and why |
| `core/transports/masque` | **DORMANT** | `IsKnownSubmode` has a live caller (`core/abi/masque.go`) and `core/netmem/store.go` names the sub-mode list. The 3-sub-mode cascade has zero production callers and is kept as the clearest existing statement of a sub-mode ladder — **not** as a step toward shipping MASQUE |
| `bundle/go/publisher/webtunnel.go` | **DORMANT** | Referenced by the `daal-publish webtunnel-bridge` CLI verb. Marked, re-scoped, and the verb now prints the caveat so an operator learns it at the point of use rather than from a spec |

"Dormant" here is the sibling of the `INERT` status introduced in
`docs/capability-matrix.md` §4b. INERT describes a *user-reachable
control whose value nothing reads*; DORMANT describes *code that
cannot run and is kept for a stated reason*. Both exist so a gap is
named rather than implied.

Note the interaction: the **MASQUE sub-mode override** is INERT
(capability-matrix **CM-6**) — a persisted setting with no
production reader. Wiring a reader would connect a user preference
to a family that cannot be dialled. **CM-6 must not be "fixed"
while `masque` is unsupported.**

## What the user sees

**On mobile, historically, only the badge word.** Every per-family
value claim this wave wrote was delivered through a `title=`
attribute — a hover tooltip, which never fires in an Android WebView,
on the primary target platform and the only hardware this project
has. The repair pass made the family chip a button: `title` still
serves desktop hover, and a tap expands the same sentence inline
(`NetworkPage.tsx`, `FamilyChipView`). Without that, tuic's "this is
not a new way in" and wireguard's "one of the first shapes Iranian
operators block on sight" were desktop-only text.

The badge on a route card comes from the maturity label, via
`derive_tree.ts` → `FamilyChip.maturity`, and the copy already
exists in both languages:

- `network.family.unsupported` / `.help` — *"This build of Daal
  cannot dial this transport. Routes of this kind will not
  connect."* / *«این نسخهٔ دال نمی‌تواند این حامل را برقرار کند.
  مسیرهای از این نوع وصل نمی‌شوند.»*
- `network.family.experimental.help` — *"Experimental transport —
  unproven in the field. It may fail to connect."*

Because the labels moved, nine families' worth of route cards now
carry the honest badge without a copy change. That is the whole
point of the maturity label being the single source: fix the
table, and the app tells the truth in both languages at once.
