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

Repo state: `main @ 4808569` + the uncommitted work of 2026-11-18.
Reproductions are run from `test-rigs/worldbox/`. "quick"/"full" are the
modes of `./daal e2e` (`./e2e.sh`); a world name is a row of its report.

### Fixed in this tree (4)

| id | severity | one line | status | reproduce (before the fix) | pinned by |
|---|---|---|---|---|---|
| FAM-1 | **high** (user-visible) | On naive, an app's name lookups (plain UDP/53) get no answer: "connected", nothing loads | **fixed** in `core/engine/config.go` — **names only**: every other app datagram on naive is still dropped (FAM-6, open); covers every TCP-only outbound (naive, http, tor, ssh, shadowtls, `network:tcp`), but the rig exercises naive only; needs one phone retest (Private DNS off, naive route and tor route, open a site by name) | revert the `hijack-dns` hunk, `./run.sh clean naive` → `family/naive dns` blocked | unit `TestBuildSingBoxConfigHijacksDNSForUDPLessOutbounds`, `TestTCPOnlyOutboundTypesMatchSingBox` (core/engine), and under `-tags singbox` (now run by `./daal test`) `TestHijackedDNSConfigIsAcceptedBySingBox` — the linked sing-box parses and starts the rule together with the legacy-format dns block; rig check `family/naive dns` in quick and full |
| LC-1 | low-to-medium (security, defence in depth) | A mgmt token already used once could be replayed with a different body (`users-revoke` against another recipient, etc.) | **fixed** in `cmd/daal-relay-mgmt/main.go` + spec §3/§4.8; **open on released relays** until the next mgmt release (the one F-002 needs) | `./run.sh --ops mgmtauth clean @default` (pinned release) → `replay.users-revoke` honoured | unit `TestMutatingTokensAreSingleUse` (cmd/daal-relay-mgmt); rig check `op:mgmtauth replay.users-revoke` green on the tree build in quick and full; on the pinned box tracked in known-findings.json (`LC-1`, box=pinned) |
| FAM-5 | low (latent) | Off Android the engine could never load Cronet from beside its own binary (a failed first try is cached for the process) | **fixed** in `core/engine/cronet_state.go`, `cronet_loader_naive.go` | revert, `./run.sh clean naive` → `tunnel` refused, "cronet: failed to load library" | unit `TestCronetLibraryArg` + `TestLoadCronetUsesCronetLibraryArg` (core/engine); rig: every `family/naive tunnel`. Android unchanged by construction, not device-tested |
| INT-2 | medium (intermittent; on the relay) | naive: sing-box 1.13.12 decides the naive inbound's ALPN with a start-up race; about 1 start in 1000 leaves naive/TCP answering every ClientHello with alert 120 (`no_application_protocol`; Cronet `net_error -107`) for the whole life of that sing-box process. Nothing is logged; the engine says Connected | **fixed** in `cmd/daal-relay-mgmt/singbox_users.go` (the daemon now writes `alpn` into `naive-in`, so nothing is left to race; an older inbound is healed on the next recipient add); **open on released relays** until the next mgmt release (the one F-002 and LC-1 need). Root cause is upstream sing-box, worth reporting there | `repro/int2-naive-alpn-race.sh` (no Daal involved: 3 dead instances in 3000 starts; `… pinned` → 0 in 3000) | unit `TestAppendNaiveUserCreatesInbound`, `TestNaiveALPNHealsAnOlderInbound` (cmd/daal-relay-mgmt); on the pinned box tracked in known-findings.json `INT-2` (box=pinned, signature `net_error -107`, budget 4); on a tree box the same face is an unexpected red |

### Open — need a decision, a release or a dependency fix (14)

| id | severity | one line | status | reproduce | pinned by |
|---|---|---|---|---|---|
| CEN-1 | **high** | A route that carries nothing is "Connected", recorded as a success, and comes out `proven: true`, `health_pct: 100`; the engine never classifies a data-plane failure, so every failure category, cooldown and network signal is fed nothing | open — design decision (what proves a tunnel works) | `./run.sh --mgmt=tree relay-ip-block vless-reality hysteria2` | known-findings.json `CEN-1`: `family/* engine.category` in every blocking scenario (11 checks in quick, 37 in full) |
| LC-2 | **high** | The freshness channel, as the app drives it, can only deliver the credential-less signed skeleton: a polling recipient's working pack is replaced by one that cannot connect (or, if the operator hosts the connectable file, nothing is delivered) | open — design decision. *Basis: the engine's behaviour is observed; "as the app drives it" is established by reading the wizard source — the CLI stands in for the app* | `./run.sh --mgmt=tree --ops freshness clean vless-reality` | known-findings.json `LC-2`: `op:freshness unchanged.signed-pack-hosted.tunnel` (full: worlds clean.rotation, release.lifecycle) |
| F-002 | **high** | A relay provisioned from `main` cannot serve shadowsocks, anytls or tuic: the pinned `daal-relay-mgmt` predates them | open — needs a release (release key); the code is right | `./run.sh clean` (pinned) vs `./run.sh --mgmt=tree clean` | known-findings.json `F-002` (box=pinned): world release.all-families in full. Acceptance after the release: that world all green, and the run then fails with "F-002 did not reproduce" until the entry is deleted |
| F-004 | **high** (security, design) | A pack's outbound profiles are not authenticated: anyone can rewrite the server address under the publisher's fingerprint | open — format decision | `./run.sh --ops tamper clean vless-reality` | known-findings.json `F-004`: `op:tamper import_of_tampered_pack` in quick and full |
| INT-1 | **high** (intermittent) | naive: the whole engine process dies with SIGSEGV inside Cronet when a connection is closed at the moment its stream terminates — a use-after-free race in the pinned `cronet-go`. Observed in the rig only; on the phone the same code would take the VPN service down with it, which is inferred, not yet seen on a device (see the section for the logcat check) | open — upstream dependency (`github.com/sagernet/cronet-go`); needs a bump or a fork | `for i in 1 2 3 4; do WB_RESTART_CYCLES=25 ./run.sh --mgmt=tree --ops restarts clean naive & done; wait` → 3 engine deaths in 104 naive sessions here; identical signature each time | known-findings.json `INT-1` (intermittent, pinned to the crash signature): `*/naive engine.survived`; unit `TestCrashSignature` (fixture `driver/testdata/cronet-cancel-crash.stderr`) |
| LC-3 | medium | After an L3 address move naive cannot connect to the new address (the box certificate's SAN is the first-boot address); the engine reports "Connected" | open — every fix moves something recipients pin | `./run.sh --mgmt=tree --ops l3 clean naive hysteria2` | known-findings.json `LC-3`: `op:l3/naive new-file.address-blocked.{tunnel,wire}` (full) |
| F-003 | medium | Routes the minter "dropped" still import, list and can be activated on the client; nothing client-side reads the marker | open — touches what is offered for selection | `./run.sh clean anytls` (pinned), then the `routes` and `error` events in `out/latest/clients/*/events.jsonl` | not pinned on its own: it is only reachable through F-002 today (the `family/* engine.category = unknown` reds of world release.all-families are this). Needs a check of its own once F-002 is released |
| FAM-2 | medium | The app cannot enable shadowsocks, anytls or tuic at all: the wizard hard-codes an empty family list | open — UI work. *Basis: established by reading the wizard source; the app was not run* | `grep -n enabledFamilies client-ui/src/publisher/PublisherWizard.tsx` | not pinned (above the ABI; the rig enables them through the CLI flag) |
| FAM-3 | medium | `provision --families` is a silent filter: a typo drops the family, a short list drops the defaults, exit 0 either way | open — the same intersection is load-bearing for L6 | `daal-deploy provision … --dry-run --families vless-reality,tiuc` (section below) | not pinned |
| FAM-6 | medium (user-visible) | naive carries **no app UDP except DNS**: QUIC without a TCP fallback, calls, games get nothing while the route is "Connected". The rig's `udp = blocked` cell for naive is this limitation written down as an expectation — it is green because the product still has the limitation, not because anything works | open — product decision: one line in the pack's naive outbound (`udp_over_tcp`) carries it, tried here against the released box; it changes what is minted for a default family | `./run.sh clean naive` → `family/naive udp expect=blocked got=blocked` | not in known-findings.json (the check is green by declaration): `families/naive.json` `"udp": "blocked"` is the pin — the day a pack carries UDP on naive that check goes red (`expect=blocked got=pass`) and the declaration must be flipped to `pass` |
| CEN-2 | medium | Even shown the error, `diagnostics.Classify` cannot tell an SNI block from an address block, and files a TLS-phase timeout under `tcp_connect_timeout` | open — the mapping table is locked; needs context the string does not carry | `./run.sh --mgmt=tree sni-rst vless-reality`, then `wb-client --classify` on the raw probe's error (section below) | not pinned: masked by CEN-1 (no error reaches the classifier). The `censor/* truth.category` checks hold the ground truth it will be compared with |
| CEN-3 | medium (spec) | The failure taxonomy has no word for three things a censor does: UDP dropped toward ONE address, UDP dropped on ONE port, and "connects but too slow to use" | open — spec revision | scenarios relay-ip-block, port-whitelist, throttle-56k declare the nearest category (`unknown`, `udp_unavailable`, `none`) | `driver/censor_test.go` (every declared category must exist in `specs/failure-taxonomy-v1.md`) |
| FAM-4 | low | De-selecting a default family does not take it off the box: 4 open, listening ports the pack never mentions | open — same root as backlog W5-1 | `./run.sh --mgmt=tree --relay-families shadowsocks,anytls clean shadowsocks anytls` | known-findings.json `FAM-4`: `mint/* not_served` in world narrow-relay (full) |
| F-001 | low (latent) | `daal-fetch-verify` fails with a misleading message when `/tmp` and `/usr/local/bin` are different mounts | open — the shim's bytes are hash-pinned | mount a tmpfs on the box's `/tmp` in `box/init.py` (section below) | not pinned (needs a modified box) |

### Observations (no verdict; recorded so the day they change is visible)

| id | one line | where to see it |
|---|---|---|
| O-1 | The protect callback the phone registers is never called; only the uid exclusion keeps the engine out of its own TUN | `engine_protect_calls` in every `control.after` |
| O-2 | Disconnect blocks ~5 s when the relay is blackholed (vless-reality, websocket-tls) | `ms` of `control.after` under relay-ip-block |
| O-3 | Confirms backlog W5-1: a default relay binds `ss-in`/`anytls-in` (firewalled) | `listener_on_box` in `mint/* not_served` |
| O-4 | The three opt-in families connect with the experimental-families gate OFF | every session of anytls, shadowsocks, tuic |
| LC-O1 | `rotate-tls` says every recipient needs a new pack; only vless-reality stops working | `op:l2 old-pack.tunnel` per family |
| LC-O2 | `/whoami` has a handler and no caller that can authenticate to it (`MintToken` refuses the op) | section below |
| LC-O3 | The first freshness poll after an import always downloads the whole pack | `op:freshness` evidence |
| LC-O4 | L1, L2, L3, revoke and multi-recipient all work end to end on the pinned release artefacts (default families) | world release.lifecycle (full) |
| INT-O1 | The kick wrapper's `SIGUSR2` ("graceful inbound drop") is a no-op: sing-box 1.13.12 registers handlers for INT, TERM and HUP only, and a Go program ignores an unhandled SIGUSR2. Every kick is therefore `sleep 2` + a full restart; `users-revoke` and `rotate-credentials` kick twice, so the relay restarts twice, 2 s apart, and the verb takes ~4.7 s | relay `sing-box.service.log` (instances that live exactly 2 s); `ms` of the verbs in `publisher-verbs.jsonl`; `cmd_run.go:147` in sing-box |
| CEN-O1 | The relay's shadowsocks and anytls ports answer a few opaque bytes with a TCP reset within a millisecond; naive and websocket-tls wait, REALITY forwards — an active-probing tell, for triage | section below |
| CEN-O2 | Only vless-reality puts a name on the wire; its ClientHello is 600 bytes in one TCP segment, so even a first-packet-only SNI filter reads it | scenarios sni-rst, sni-rst-stateless |
| CEN-O3 | Under 30% random loss the QUIC families still complete the fetch (7–11 s) and every TCP family fails it | scenario heavy-loss |
| CEN-O4 | naive's first request can end in `EOF` after ~0.5 s on a lossy or slow path, where the other families retry and get through — not root-caused | section below |

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
key, upload, bump `Sha256` + `SigHex` in `artifacts.go`. After that,
`./run.sh clean` (no flag) is the acceptance test: it downloads through the
real verifier, so a wrong hash or signature fails it too.

Worth adding to the release checklist: `./daal e2e full` before a tag. Its
world `release.all-families` is exactly `./run.sh clean` without
`--mgmt=tree`; once the release is out it goes green and the run reports
"F-002 did not reproduce" until the entry is deleted from
`known-findings.json`.

---

## F-004 — pack profiles are outside the signature; the server address can be rewritten by anyone

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

**Not fixed here**: it is a format decision (bind profiles into what is
signed — e.g. a per-recipient signature over the profile set by the
publisher key or a certified sub-key, for which `bind-and-sign
--subkey-cert` already has machinery — or have the client refuse a profile
whose `server`/port disagrees with the signed `public_risk_tags`). No
signature check was weakened or bypassed to demonstrate it. The check stays
red, reported as `KNOWN [F-004]` — but only in this exact shape: the
known-findings entry requires `got=pass` with evidence `rewritten=profiles`
and `manifest_rewrite=refused`. If the manifest control is not refused
(signature verification lost), neither red is F-004 and the run fails.

---

## F-003 — "dropped" routes are still routes on the client

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

**Not fixed here**: the natural fix (import or `AvailableRoutes` treats a
marked profile as unavailable-with-reason and never attempts it) changes
what is offered for selection, which this work was told not to touch.

---

## F-001 — the artefact verifier needs `/tmp` and `/usr/local/bin` on one mount, and hides it when they are not

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

**Not fixed here**: the shim's bytes are pinned by a test
(`VerifierShimSource` SHA-256) and "must stay stable"; the two-line fix
(create the temp file in the target directory, and print the exception
instead of swallowing it) deserves its own change with that pin updated.

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

## O-2 — disconnect takes ~5 s when the relay is unreachable

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

## FAM-2 — the app has no way to turn on shadowsocks, anytls or tuic

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

**Not fixed here**: it is a wizard screen (which families, with what
warning about the extra open ports), not a seam.

---

## FAM-3 — `--families` filters silently

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

**Not fixed here.** Rejecting unknown names inside `CandidatesForProfile`
would be two lines, and wrong: the L6 rung calls the same function with the
record's families against a NEW profile and relies on the intersection
(`refuseEmptyProfileIntersection`), and the second half of a reprovision
runs `provision --families` after the old server is already deleted. The
check belongs at the operator-input boundary only (the wizard screen of
FAM-2, or a first-provision-only validation in `cli.go`).

---

## FAM-4 — a default family you did not ask for is still on the box

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

**Not fixed here**: the box has to learn its own family set, which is the
change backlog item W5-1 already describes as deliberate work.

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

## O-3 — W5-1, observed

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

## LC-2 — the freshness channel, as the app drives it, replaces a working pack with one that cannot connect

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

**Not fixed.** It is a design gap, not a typo. One public pack cannot carry
per-recipient credentials, so "publish the recipient's pack" is not the
answer either. The two shapes that would work: (a) the document names the
*shared* pack (`users-pack-sbp` for `r0`) and the app uploads/points at that
one — which only helps recipients of the shared file; or (b) a
freshness-fetched skeleton is **merged** into the routes already on the
device (new address / cover host / ports from the signed skeleton, existing
credentials kept) instead of replacing their profiles. Until one of them
exists the importer should at least refuse to swap a profile that parses to
no outbound over one that does.

**What stands in.** The storage (`wb storage`) and the upload to it: the
rig copies `publish-freshness --out-file`'s signed document and the pack
onto a static HTTPS host the phone reaches through the censor.
`publish-freshness`'s R2 and GitHub uploaders are not exercised.

## LC-3 — after an L3 address move, naive cannot connect to the new address (and the engine says "Connected")

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

**Not fixed.** Every fix moves something recipients pin: re-issuing the
certificate with both addresses in `/bind-address` changes
`tls_cert_sha256` for every family (harmless after an L3, since everybody
needs a new file anyway, but it would break the grace period in which old
files still work on the old address); giving the naive outbound a
`server_name` the existing certificate covers needs Cronet to accept a
verification name that differs from the dialled address, which I did not
verify. Needs a decision.

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

## CEN-1 — a blocked route is "Connected", a success, and proven; the engine never classifies a data-plane failure

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

**Not done, and why.** Not small and not obviously one thing. The engine
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

## CEN-2 — the classifier cannot say what the taxonomy asks of it

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

**Not done.** The mapping table is declared locked, and no string rule
fixes it; the classification has to be made where the stage is known (the
dialer) and, for SNI-vs-address, by a second probe.

## CEN-3 — three things a censor does that the taxonomy cannot name

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

**Not done.** A spec revision, not a code fix.

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

## INT-1 — naive: the engine process dies with SIGSEGV in Cronet when a connection closes as its stream terminates

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

and look for `KNWN … engine.survived … [INT-1]` in the output; each hit keeps its stderr under
`out/<run>/clients/NN-naive/stderr.log`.

**What the rig does now.** A session whose engine process dies records a
red `engine.survived` with the crash signature, removes the dead VPN's
routing the way Android would, and repeats the session once — so the crash
is one red check with a name, not (as on first sight) "DNS blocked on
naive" plus "ip rule: File exists" on the next family. Because it is a
race, its `known-findings.json` entry is marked `intermittent` and is
pinned to the signature (`BidirectionalStreamCancel`, family naive) with a
budget of 6 per full run (a full matrix has seen 0, 1 and 2) and 2 per quick run (quick has seen 0 and 1; the count is printed in the pre-push result line): any other engine death, on any family, fails the
run, and so does this one if it starts happening in every session.

**Not fixed here**: the defect is in a dependency. The fix is upstream's
(hold `c.access` across the CAS and the native call in `Close`/`Read`/
`Write`, and across `Destroy` in `terminate`, or reference-count the
stream); Daal's part is to bump `cronet-go` once it lands, or carry a
`replace` to a patched fork. Worth checking upstream first: newer
`cronet-go` commits may already serialise this.

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
