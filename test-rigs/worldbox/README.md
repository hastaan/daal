# worldbox — a whole Daal world on one machine

Rootless, hermetic, seconds. An outsider provisions a relay, mints a signed
pack; an insider imports it and connects; a censor we control sits in the
middle. Every hop runs the **production binary or the production code path**
— the bugs this project keeps finding live in the seams between components,
and a rig that re-implements a seam cannot see them.

```
../../daal e2e            # quick: 16 worlds, ~1450 checks, ~1 minute. The pre-push hook runs this.
../../daal e2e full       # everything: 19 worlds, ~4450 checks, 4–5 minutes.
```

That is the entry point (`./e2e.sh [quick|full] [-j N] [--only world,…] [--plan]`
is the same thing without the wrapper). One world at a time, for digging:

```
./run.sh clean vless-reality            # one family, pinned release artefacts   (~7 s)
./run.sh clean                          # every family the product can provision
./run.sh clean @default                 # the families a relay serves by default
./run.sh --mgmt=tree clean              # …with THIS TREE's daal-relay-mgmt and daal-relay-health on the box
./run.sh --ops revoke,wrongcreds clean  # + publisher-side operations
./run.sh --mgmt=tree --ops lifecycle clean   # everything that happens AFTER first contact (see "Lifecycle ops")
./run.sh udp-blackhole                  # another censor
./run.sh --json clean                   # one JSON line per check on stdout
./run.sh --shell clean vless-reality    # leave me a shell inside the world afterwards
./run.sh --list                         # scenarios, families, ops
```

No sudo, no network, no VPS, no phone.

## One entry point: quick and full

| mode | worlds | what it covers |
|---|---|---|
| **quick** (~1 min) | `clean` | no censor × all 7 families on the tree's mgmt daemon, plus the ops `switch` (a live route switch, TCP family ↔ QUIC family), `revoke`, `l1`, `mgmtauth`, `tamper` |
| | `auto` | the **automatic connect** — the main screen's one button, no route named — on the four routes a default relay serves: op `auto` (see "Client-side ops") |
| | `release` | the **pinned release artefacts** (what a relay provisioned today really downloads) × the default families, plus `revoke`, `mgmtauth` |
| | one per censor scenario (14) | the scenario's raw proofs, and its verdict for one TCP family (vless-reality) and one QUIC family (hysteria2) |
| **full** (4–5 min) | one per censor scenario (14) | every scenario × all 7 families |
| | `clean.recipients`, `clean.rotation` | the whole lifecycle on the tree daemon × all 7 families: recipients, revoke, wrong credentials, tamper, mgmt-auth, repeated relay restarts; then L1, **L2 then L3** (the cover host moves, then the address — the order in which naive's certificate matters), freshness, capability honesty |
| | `clean.switch` | one phone, many routes: `switch`, then `switch-all` — a live switch between **every ordered pair** of the 7 families (42) in one session |
| | `clean.auto` | op `auto` with all 7 families' routes on the phone (three of them behind the experimental gate, which the op leaves off) |
| | `relay-ip-block`, `total-blackout`, `quic-drop` (+`auto`) | one press of the button **under the scenario**: nothing can carry (and the verdict that must come back), or only the QUIC routes are stopped |
| | `release.lifecycle` | the whole lifecycle again on the pinned release artefacts × the default families |
| | `udp-blackhole` (+ops) | recipients and the three rotation rungs (L1, L3, L2 — the other order) **under a censor** |
| | `release.all-families` | the pinned artefacts × all 7 families — FINDINGS F-002, kept visible until the release. **Until the pin moves, every pinned world stops at `provision`: this tree's publisher will not pin a management fingerprint the pinned health binary cannot authenticate (FINDINGS BOOT-1), and could not authenticate to the pinned daemon if it did (REL-1)** |
| | `narrow-relay` | a relay provisioned with `--families shadowsocks,anytls` only — FINDINGS FAM-4 |

Which daemon a world's box runs is in its plan line (`./e2e.sh quick
--plan`) and in every check's `box` field. In quick, **every world except
`release` runs this tree's `daal-relay-mgmt` and `daal-relay-health`**: a green quick run is about
the tree, not about relays already deployed (Known gaps).

`driver/known_test.go` fails if a scenario, family or op exists that no
mode reaches. Worlds run side by side (default: half the cores, at most 8);
each is its own set of namespaces and its own evidence directory. The
report (`out/e2e/<run>/report.txt`) has one scenario × family table, the
full per-check matrix of the no-censor worlds, one line per op per world,
and the verdict.

### Exit status — and why a red check does not always mean exit 1

| status | meaning |
|---|---|
| `0` | every world ran; no red check that an **open finding** does not explain |
| `1` | an unexpected red check — or a known finding that **did not reproduce** |
| `2` | a world did not run (`run.sh` died, or recorded nothing to judge): the rig is broken, Daal was not judged. A world that a red check stopped before its first client session is *not* this — it is reported as `STOPPED EARLY at <phase>/<check>` and judged, exit `1` |
| `77` | **SKIPPED**: this machine cannot host the rig (no unprivileged user namespaces, no subuid range, no usable nftables/NFQUEUE, a missing tool or release artefact). Never a pass: `./daal e2e` says so in so many words, and the pre-push hook **fails** on it unless the push opts in with `DAAL_E2E_ALLOW_SKIP=1` |

The rig found defects in Daal that need a design decision or a release
(FINDINGS.md). Their checks are red and stay red — `ok:false` in
`results.jsonl`, `~got(ID)` in every table. But a gate that exits 1 on every
run is a gate nobody reads, and the next real regression would drown in
it. So `known-findings.json` lists, narrowly (phase + family + check,
optionally which box artefacts), the red checks each **open** finding
explains. Those are reported under `KNOWN` and do not fail the run. Every
other red check does. And an entry whose checks ran and were all green
fails the run too, with "did not reproduce": either the defect was fixed —
delete the entry, mark the finding fixed — or the check stopped seeing it.
`driver/known_test.go` refuses an entry that has no open section in
FINDINGS.md, and one broad enough to be a blanket.

An entry excuses a **defect, not a cell**. Besides its scope it can state
what the red check must look like to be this finding: `got` (the observed
value) and `evidence` (keys of the check's evidence). A check in scope that
is red some other way is UNEXPECTED. CEN-4 is "the engine reported
`udp_no_reply`" (or, under one scenario, `tls_sni_or_cert_block_suspected`).
(The mechanism was built for F-004, since fixed: "a profile rewrite was
accepted **while** the manifest rewrite of the same op was refused" —
`op:tamper` still runs that control first and puts its outcome in the
evidence; `known_test.go` keeps the mechanism tested on a rebuilt entry.)
And every report prints `ENGINE CATEGORY — …
correctly in N of M blocked sessions`, and for the rest lists each
truth → reported pair an open finding explains (CEN-4: the engine named
the coarser thing one route can see). Were it ever 0 of M with nothing
listed, the `engine.category` column would be the censor restated, not
coverage — which is what it was while CEN-1 was open.

One open finding is a race (INT-2, a start-up race in sing-box that now
and then leaves a relay's naive inbound refusing every handshake until the
next restart — fixed in the tree daemon, so excused on the pinned box
only; INT-1, an engine crash inside Cronet, was the other until its
dependency fix, and an engine death is no longer excused by anything). A
race cannot be required to reproduce, so its entry is marked
`intermittent` — and is held tighter for it: it is pinned to a signature
in the red check's detail
(`detail_contains`), and has a budget (`max`) of red checks per run. Over
budget, none of them is excused: a race shows once or twice; a regression
with the same face shows in every session. A race is told from a regression
by its rate, and one world has none — so a world judged alone (`./run.sh …`)
has a budget of **zero**: a red check with a race's signature fails that
run, and says so (re-run it; red twice is not the race). Only the matrix
(`e2e.sh`, which re-judges every world's checks together) excuses them. The quick matrix has a smaller
budget of its own (`max_quick`), sized to what quick has shown, and every
report states the count against the budget (`INTERMITTENT — … INT-2 ×0
(budget 4)`); the pre-push hook repeats that line next to its ✓.

An entry can also say what a red check must have GOT to be excused
(`got`). CEN-4 is "the engine reports `udp_no_reply` for a silent UDP
route": an engine that reports nothing (`none` — what CEN-1 was), or some
other wrong category, is red in the same check and is NOT excused — it is
unexpected.

**An engine that dies.** If the engine process exits mid-session without
being asked to, the session records a red `engine.survived` carrying the
crash signature, the dead VPN's routing is removed (as Android does), and
the session is repeated once. One crash is one named red check, not a
trail of misattributed ones. The forged-pack controls do the same per
forged field (`wrongcreds.<field>.engine.survived`): a crash is never
counted as a refusal of the forged value. A failed session's red checks also carry the
tail of the engine's stderr — the only place the native network stack
(Cronet) says why.

### Needs

Linux with unprivileged user namespaces, a subordinate uid range for
your user (`/etc/subuid`, `newuidmap`), `/dev/net/tun`, nftables with
conntrack and NFQUEUE usable inside a user namespace, and `go gcc ip nft tc
ss python3(+PyYAML) openssl flock timeout`. `run.sh --preflight` checks all
of it and says what is missing (exit 77). The release artefacts this
tree PINS must be staged in `dist-release/relay-v1.5.1/` (`gh release
download relay-v1.5.1 --dir dist-release/relay-v1.5.1`, as CI does). The
release script builds a release FROM THIS TREE into its own tag's
directory and, without `--upload`, publishes nothing;
`tools/release/README.md` says how the "pinned" box is pointed at such a
candidate to prove it before anything is uploaded.

## Topology

```
 [client]  eth0 198.51.100.2 ─── 198.51.100.1 [censor] 203.0.113.1 ─── eth0 203.0.113.10 [relay1]
  the phone                                    nft / tc                 "public" address    │ eth1 192.0.2.2
                                                                                            │
 [publisher] eth0 198.18.0.2 ─── 198.18.0.1 [internet] 192.0.2.1 ───────────────────────────┘
  the wizard's laptop                         192.0.2.80  target      the blocked site (HTTP + UDP echo)
                                              192.0.2.20  api.hetzner.cloud   (fake cloud API)
                                              192.0.2.30  github.com          (release mirror)
                                              192.0.2.44  every other website (REALITY cover dest)
                                              192.0.2.53  DNS
```

All of it lives inside one `unshare --user --net --mount --pid` whose PID 1
is the driver. **Teardown is the kernel's job**: when PID 1 exits — pass,
fail, panic, `kill -9`, Ctrl-C — every process in the pid namespace is
killed and the namespaces vanish with it. Nothing exists outside it except
files under `out/`.

The relay is a host, not a router (`ip_forward=0`), and the censor routes
nowhere but the relay's network. So the only way from the client to the
target is inside a tunnel the relay terminates. Every session proves that
three ways: the fetch fails before connecting, succeeds while connected
**and the target sees the relay's egress address** (192.0.2.2), and fails
again after disconnecting.

## What happens in a run

| phase | what runs | real? |
|---|---|---|
| world | namespaces, veths, routes; target / cloud / mirror / DNS / cover site start | rig |
| provision | `daal-deploy provision --provider hetzner …` → hcloud-go → HTTPS → the lab cloud API. Creating the server **boots a box**: the user-data, byte for byte, is executed by `box/init.py` (bootcmd, write_files, runcmd). The runcmd downloads the three artefacts from the lab mirror with the unmodified `daal-fetch-verify`, which checks the real SHA-256 pins and the real Ed25519 release signature, generates the REALITY keypair and TLS cert, and starts `sing-box`, `daal-relay-health`, `daal-relay-mgmt` from the unit files the template wrote. The publisher then polls the real health endpoint and pins the mgmt TLS fingerprint. | **product**, end to end |
| mint | **the app's order**: `relay-identity` (opens the cloud firewall window through the cloud API, signs a request-bound token, calls the real mgmt `GET /identity` over pinned TLS) → `bind-and-sign --relay-identity <that answer>` with nobody on the relay (this lab's record has no REALITY key or TLS pin because there is no sshd to read them over — the record the Vultr adapter writes) → `users-provision` → `bind-and-sign` again iff the reply disagrees with what was signed (it must, exactly when the relay said a family was pending: shadowsocks) → `users-pack-sbp`. On the pinned release artefact, which predates the route, `relay-identity` must exit 3 and the old order (`users-provision` → `bind-and-sign --endpoint-creds`) is used | **product** verbs in the order the wizard drives them (FINDINGS F-005); the wizard's own Rust is proven separately, against its fake relay |
| family | `wb-client`: the real engine (`daal/core/abi`, sing-box data plane) imports the pack, answers the trust prompt, is handed a TUN fd, `SetRoute`s the family's route. `wb probe` (an ordinary process under another uid) fetches the target. | **product** engine; rig plays the Android shell |
| ops | scripted publisher operations with insider-side assertions | **product** verbs |

## What is real and what is not

Real, unmodified: `daal-deploy` (built from this tree), `sing-box` /
`daal-relay-mgmt` / `daal-relay-health` (the **pinned release artefacts**,
verified by the product's own verifier; `--mgmt=tree` swaps in a tree build
of the mgmt daemon and says so on every line that matters), the cloud-init
template and everything it renders, the engine and its sing-box config
builder, pack format, signatures, trust prompt, mgmt tokens, TLS pinning,
REALITY.

Stand-ins, each chosen so the product cannot tell — and each a place where
the rig could be wrong instead of the product:

| stand-in | for | why it is needed | what it does NOT exercise |
|---|---|---|---|
| `wb fakecloud` | Hetzner Cloud API | provisioning calls a paid API | only the endpoints listed in `fakecloud.go`; an unmodelled call returns 501 and fails the `cloud.api_fully_modelled` check. Floating IPs ARE modelled (`fakecloud_fip.go`: reserve / assign / unassign / delete, enforced as "the provider routes this address to this server or to nobody"); action locking, protection, PTR and IPv6 are not. Rebuild, pricing, server-type listing: not modelled yet. One server slot. |
| `wb storage` (`storage.go`) | the static hosting a publisher's freshness mirrors and pack URL point at (R2 public URL, GitHub Pages, a CDN) | the insider must reach it WITHOUT a tunnel | the providers' upload APIs: `publish-freshness`'s R2/GitHub uploaders. The rig copies the signed document and pack onto it. |
| `wb mgmtprobe` (`mgmtprobe.go`) | somebody other than the publisher talking to the mgmt API | the real publisher cannot be made to send an unsigned / wrong-op / replayed request | it stands past both firewalls (loopback in the relay's namespace); the firewalls are asserted separately |
| lab CA via `SSL_CERT_FILE`, `/etc/hosts` bind | public PKI + DNS for `api.hetzner.cloud`, `github.com` | the unmodified binaries insist on those names over TLS | nothing of the product's own trust (packs, mgmt pin, release signature, REALITY) goes through it |
| `box/init.py` | Ubuntu 24.04 + cloud-init | first boot | only `bootcmd`, `write_files`, `runcmd`. `packages`, `users`, `hostname`, `ssh_authorized_keys` are ignored. The "base image" is this laptop's `/usr` and `/etc`, not Ubuntu's. |
| `box/shims/systemctl` | systemd | units must start/reload/restart | no `User=`, capabilities, `Restart=`, ordering. `reload` without `ExecReload` fails as in systemd (the product depends on that). Jobs on one unit are serialised and every stop/start is journalled (`var/log/wb-units/<unit>.lifecycle.log`: pids, TERM/KILL, listeners left behind), because a failure right after a restart is not evidence about the product until the shim is ruled out (FINDINGS INT-2). **Privilege is therefore not what it is on a relay**: every process on the box is root of the user namespace with a full capability set, whatever its unit says. `daal-relay-mgmt` advertises `bind-address` because it reads `CAP_NET_ADMIN` in its own `CapEff` — here it holds it by construction, on a relay only through `AmbientCapabilities=CAP_NET_ADMIN` in `daal-relay-mgmt.service`. Deleting that line from the template would leave `l3` and `caps` green. See "Known gaps: privilege on the box". |
| `box/shims/ufw` | ufw | box-side firewall | translated to a real, enforcing nft ruleset; only the grammar the template uses, anything else exits 1 |
| cloud firewall → nft | Hetzner Cloud Firewall | the mgmt port's only gate | `in` rules only |
| `box/shims/sleep` | time | the 300 s provisioning window | scaled ÷20 (`--timescale`), so the window still closes during a longer run |
| `box/shims/chown` | the `daal` service account | a rootless userns has no such user | unprivileged-user separation on the box |
| **no sshd** | the provisioning SSH log observer | — | `sshCloudInitTail`, `sshReadFile(reality.pub)`: the record's `reality_public_key` stays empty (packs get it from `/users/provision`, as on newer boxes). A first-boot failure surfaces as a failed create call with the box's log instead. |
| `labclient/` (`wb-client`) | the Android app around the engine | TUN + VPN routing | see below |
| publisher keypair, file plumbing | the wizard's keystore and UI state | — | the Tauri shim / Rust bridge / TS UI are not in the loop |
| Cronet from the Go module cache | the `libcronet.so` an APK ships in `lib/<abi>/` | naive's client is Chromium's network stack | the Android build of the library (`tools/cronet/`). If the module is not in the cache the family is SKIPPED with that reason. |
| a linux/amd64 glibc process (`go build`, the engine linked in as a Go package) | the engine as the phone runs it: an android/arm64 gomobile library loaded over JNI into the app's process | there is one laptop | the gomobile/JNI binding, bionic, arm64, the app's process lifecycle. Same Go source and build tags; a different binary. |
| `wb probe` sending plain UDP/53 to 1.1.1.1 / 9.9.9.9 | Android's resolver | something must ask for a name | Private DNS (the opportunistic upgrade to DNS-over-TLS on TCP/853, or a named provider), resolver fallback and caching. A green `dns` is the "Private DNS: Off" case only. |

### The client: no lab inlet in the engine

Nothing was added to the engine to push traffic through it. `wb-client`
does what `DaalVpnService.kt` does, in the same order: register the protect
callback, establish a TUN (non-blocking, as `Builder.establish()` hands it
over; `WB_TUN_BLOCKING=1` for the other kind), `abi.SetTunFD(fd)`,
`abi.SetRoute(id)` — and, on `switch <order> <family>`, the service's
route switch (see "Client-side ops"). The
"VPN" is per-uid policy routing, exactly as on Android: every uid but the
engine's own is routed into the TUN (`ip rule uidrange 1-65535 → table
51820`), which is `addDisallowedApplication(self)`. The probe runs as uid
10100. The engine's hard-coded TUN inbound, MTU and gVisor stack are the
ones the phone uses.

`driver/isolation_test.go` (run by `./daal test`) fails if any product
module, product Go file or release script ever references the rig.

## Layout — who owns what

```
e2e.sh                 THE entry point (`./daal e2e`): the plan of worlds for quick/full, run in parallel, one report
run.sh                 one world: preflight, build, enter the namespaces. Nothing else.
known-findings.json    the red checks each OPEN finding in FINDINGS.md explains (see "Exit status")
driver/                the `wb` binary (stdlib + hcloud schema types)
  world.go             address plan, namespaces, links, routes
  run.go               phases, RunCtx, Session() — the insider's session and its checks
  results.go           Check (the JSON contract) and the matrix
  known.go             known-findings.json: KNOWN vs UNEXPECTED vs "did not reproduce"
  summary.go           `wb summary`: many worlds → one report, one exit status
  registry.go          Family / Scenario declarations and loaders
  censor.go            scenario → nft/tc/dpi; the control host; prove, truth.category, engine.category
  censor_dpi.go        `wb dpi`: the payload-aware box (NFQUEUE, TLS SNI, forged RSTs)
  censor_probe.go      `wb rawprobe` (Daal-free probes) and `wb elsewhere` (the unblocked control host)
  wire.go              the wire tap: per-family packet counters at the censor
  family.go            per-family checks: pack.route, not_served, wire, wrongcreds, wrongserver
  resolver.go          the public resolvers the phone is configured with (1.1.1.1, 9.9.9.9)
  publisher.go         one helper per daal-deploy verb
  client.go            wb-client and probe control
  fakecloud.go inet.go target.go probe.go labca.go     the outside world
  ops.go ops_*.go      publisher-side operations, ONE FILE EACH (ops_switch.go, ops_auto.go: the client-side ones — a live route switch; the automatic connect)
  lifecycle.go         shared plumbing for the lifecycle ops (verb helpers, Rebuild, box views, --ops lifecycle)
  fakecloud_fip.go     floating IPs (the cloud half of L3)
  mgmtprobe.go         hand-built mgmt requests (`wb mgmtprobe`)
  storage.go           static hosting the insider reaches without a tunnel (`wb storage`)
  *_test.go            hermetic: isolation + declaration validation
labclient/             `wb-client`: real engine + the lab's VpnService (switch.go: route switch, fd sentinels, store checks; auto.go: the one button — engine_connect_auto, cancel, disconnect and connect again in one process)
box/init.py            cloud-init first boot
box/shims/             systemctl ufw sleep chown
families/<name>.json   ONE FILE PER FAMILY
scenarios/<name>.json  ONE FILE PER SCENARIO
out/<run>/             evidence of one world (git-ignored; newest 10 kept, 60 under e2e.sh; out/latest → newest)
out/e2e/<run>/         one e2e run: report.txt, and per world the JSON stream, log, exit status
                       (pruned per kind — newest 8 quick, 4 full, 4 of each --only kind —
                       so pre-push quick runs never evict the last full report)
FINDINGS.md            defects the rig found in Daal, with reproduction
```

Three people can work in parallel without touching the same file: one adds
`scenarios/*.json` (and extends `censor.go` if a censor needs a new
mechanism), one adds `families/*.json` and client build tags, one adds
`driver/ops_*.go` and fake-cloud endpoints. `run.go`'s `Session()` and
`results.go` are the shared contract; change them deliberately.

## Contracts

### (a) A family — `families/<name>.json`

```json
{
  "name": "tuic",
  "endpoint": {"port": 8443, "proto": "udp"},
  "udp": "pass",
  "dns": "pass",
  "secrets": ["tuic_uuid", "tuic_password"],
  "pins": ["tls_cert_sha256"],
  "needs": "",
  "experimental": false,
  "skip": "",
  "note": ""
}
```

* `name` is the product's family string — the same in the toolbox profile,
  the pack and the engine's route list. `declarations_test.go` fails if the
  set of files differs from the families in
  `publisher/deploy/profiles/iran-default.json`.
* `endpoint` is asserted four times: the OperatorRecord's candidate port,
  an accepting rule in **both** firewalls (`firewalls.open`), a bound
  socket in the relay namespace after the first recipient exists
  (`relay.listens`), and the port the minted profile dials (`pack.route`).
  It is also where the wire tap looks.
* `udp`: expected outcome of an app's UDP through the tunnel — a small
  datagram **and** a 1400-byte one (`pass` | `blocked` | omitted = not
  asserted). Every family declares `pass`. naive declared `blocked`
  until its pack carried `udp_over_tcp` (FINDINGS FAM-6, fixed): a
  declared product limitation printed as a green cell, which is why the
  note in `families/naive.json` says what the cell means.
* `dns`: expected outcome of the phone's own name resolution — plain
  UDP/53 to the two resolvers `DaalVpnService.kt` configures (1.1.1.1,
  9.9.9.9; in this world they live next to the target) — followed by a
  fetch by name. The sender is the rig's probe, not Android's resolver:
  this is the "Private DNS: Off" case and no other (Known gaps).
* `secrets`: the fields of the relay's credential reply that authenticate a
  recipient on this family. Required (a test refuses a family without).
* `pins`: the fields that identify the relay to the client. Omit for a
  family whose shared key authenticates both ends (shadowsocks); the cell
  then reads `skipped` with that reason.
* `needs`: a run-time dependency outside the engine binary (`cronet`). When
  it is missing the family is SKIPPED with the reason instead of failing.
* `experimental`: the client turns the experimental-families gate on. No
  family sets it: the gate is not wired to anything today (FINDINGS O-4).
* `skip`: non-empty means the client side cannot be exercised; the reason is
  printed on every run and recorded as `got=skipped`. Never delete a family
  to make a matrix green.

Per family the matrix has these columns (ids are stable):

| check | expect | proves |
|---|---|---|
| `firewalls.open` | pass | box-side ufw **and** the cloud firewall admit the endpoint |
| `relay.listens` | pass | something is bound to it on the box |
| `pack.route` | pass | the minted pack has exactly one connectable route for the family, dialling that endpoint; the minter did not drop it |
| `not_served` | blocked | *(families the relay was NOT provisioned with)* both firewalls shut, no route in the pack — "default-off" is a claim too |
| `control.before` | blocked | no tunnel ⇒ target out of reach (so a later pass means something) |
| `import` | pass | pack verified, trust prompt answered, routes listed |
| `import.unconnectable_not_listed` | pass | no route the pack cannot connect on (dropped by the minter, or holding no outbound) is in the engine's route list |
| `tunnel` | *the scenario's expectation* | fresh nonce echoed; 256 KiB downloaded and SHA-256-verified; 96 KiB **uploaded** and verified by the far end; 32 simultaneous connections; **the target saw the relay's egress IP** |
| `wire` | *same as `tunnel`* | at the censor: the session's packets went to **this family's** port/proto, at least the payload came back, and the client opened no flow to anything else on the relay. A "tuic" route that is really a vless outbound passes `tunnel` and fails here. Under a blocking scenario: the client did try (blocked ≠ never attempted) The tap counts what was SENT, ahead of the censor's filter; under a scenario declared `"random_loss": true` (heavy-loss) a session whose probe did not receive its payload is `blocked` whatever the byte count — packets dropped after the tap, and their retransmissions, are not delivery (`wireUnderRandomLoss`) |
| `udp` | the family's `udp` | both datagram sizes round-trip, seen by the target from the relay |
| `dns` | the family's `dns` | the resolver saw the query arrive from the relay; the name then fetches |
| `control.after` | blocked | disconnecting really takes the path away |
| `wrongcreds` | blocked | each `secrets` field, forged **alone** in an otherwise genuine pack (minted by the real `users-pack-sbp`), reaches the family's endpoint and carries nothing |
| `wrongserver` | blocked | each `pins` field forged alone: the client refuses the genuine relay because it no longer matches the pack |

`wrongcreds` / `wrongserver` run only after the genuine pack passed; under
a scenario that blocks the family they are `skipped` with that reason
(a forged pack failing there would prove nothing). A forged value that the
client's own config parser rejects is reported as a failed control, not a
pass: the point is that the *relay* (or the handshake) says no.

`mint/pack.spec_version` asserts the format version follows the pack's
content: exactly 5 when the pack names anytls, below 5 otherwise.

Which families a relay serves: the profile's default-enabled set plus any
opt-in family under test (`--relay-families a,b` overrides). `--families`
is passed to `provision` only when that differs from the default — which is
the one mechanism the product has for enabling shadowsocks, anytls and tuic
(FINDINGS FAM-2, FAM-3).

naive is dialled for real: `run.sh` builds the client with the phone's
engine tags (`with_naive_outbound,with_purego`) and stages the linux
`libcronet.so` that sing-box's own dependency ships as a Go module, from
the module cache, beside the binary.

### (b) A censor scenario — `scenarios/<name>.json`

```json
{
  "name": "sni-rst",
  "description": "…what the censor does to traffic, and why families differ…",
  "analogue": "…which documented real-world behaviour this models — and where the model stops…",
  "censor": {
    "nft": ["ip saddr $CLIENT_IP udp dport != 53 drop"],
    "tc":  [{"dev": "$DEV_RELAY", "args": "netem delay 60ms loss 3%"}],
    "dpi": [{"when": "tls_sni", "sni": ["$COVER_SNI"], "reassemble": true, "action": "rst", "rst_to": "both"}]
  },
  "prove": [
    {"name": "cover-sni-blocked", "probe": "tls", "to": "relay",     "port": 443, "sni": "$COVER_SNI",             "expect": "reset_after_hello"},
    {"name": "other-sni-spared",  "probe": "tls", "to": "relay",     "port": 443, "sni": "www.wb-control.example", "expect": "ok"},
    {"name": "no-sni-spared",     "probe": "tls", "to": "elsewhere", "port": 443,                                  "expect": "ok"}
  ],
  "expect":   {"*": "pass", "vless-reality": "blocked"},
  "category": {"vless-reality": "tls_sni_or_cert_block_suspected"}
}
```

**Three mechanisms** (`censor`), all in the censor namespace:

* `nft`: rule lines, in order, in the forward chain (`table inet wb_censor`,
  hook forward, priority 0, policy accept). Both directions pass through it.
  `nft_raw`: a complete nft file appended after it, for other hooks or sets.
* `tc`: `tc qdisc replace dev <dev> root <args>`.
* `dpi`: payload rules run by `wb dpi` (`driver/censor_dpi.go`), an in-path
  box that gets every client TCP packet the static rules let through, over
  NFQUEUE, and keeps per-flow state. Rules, evaluated in order:

  | `when` | fires on | parameters |
  |---|---|---|
  | `tls_sni` | a TLS ClientHello whose `server_name` is in `sni` | `reassemble`: follow the hello across TCP segments (false = first data packet only) |
  | `first_data` | the first packet of a flow that carries payload | — |
  | `first_bytes_not` | a first payload that does not begin like `allow` | `allow`: `tls` (record 0x16) and/or `http` (a request verb) |

  all take optional `dst` / `port` (only flows to that address / port) and
  `action`: `drop` (swallow this and every later client packet of the flow,
  silently) or `rst` (the same, plus forged resets: `rst_to` `both` — toward
  client and server — or `client`). The queue has no `bypass`: if the box
  dies, traffic stops, and the scenario's own "spared" probes go red. Every
  fired rule is a line in `out/<run>/dpi-events.jsonl`.
* Variables (the complete list): `$CLIENT_IP $RELAY_IP $ELSEWHERE_IP
  $DEV_CLIENT $DEV_RELAY $COVER_SNI` (the relay's actual cover host).

**Three claims**, each checked on every run:

* `prove` — raw probes (`wb rawprobe`, `driver/censor_probe.go`): plain
  sockets from the client namespace, **no engine, no pack, no tunnel**. They
  run right after the scenario is applied (phase `censor`, check
  `prove.<name>`). A scenario with a blocking rule must declare at least one
  probe the rule stops **and** one it lets through — a block nobody proved
  is a guess, and a block with no spared neighbour may just be a dead link.
  `declarations` tests refuse a scenario that has neither.

  | `probe` | observes |
  |---|---|
  | `tcp` | `ok` `connect_timeout` `connect_reset` `unreachable` |
  | `tls` (`sni`, `split`: hello in two TCP segments) | `ok` `reset_after_hello` `timeout_after_hello` + the connect ones |
  | `bytes` (8 opaque bytes) | `answered` `reset_after_data` `silent` + the connect ones |
  | `udp` (`shape`: `plain`, `quic`) | `delivered` `dropped` — read off a counter placed **after** the censor's rules (`table inet wb_tap`), because nothing answers a probe datagram |
  | `tcp_burst` | `all` `some` `none` of 40 one-SYN connects (random loss) |
  | `bulk` | `fast` `slow` — 32 KiB echoed within 2 s or not (throttling) |

  `to`: `relay` (its public address), `elsewhere` (198.19.0.2 — a host
  behind the same censor that no scenario has a quarrel with: TLS on 443,
  echo on 80 and 8443; it is the control for every blocking claim), or
  `gateway` (the censor's own client-side address: "is the link up at all").

* `expect` — family → `pass` | `blocked`; `"*"` is the default; a family
  with no entry and no `"*"` is an error. **A check passes when observed ==
  expected**: a scenario that should block a family passes by observing
  `blocked`, and a censor that fails to block is a red cell.
* `category` — for every family expected `blocked`: the failure category
  from `specs/failure-taxonomy-v1.md` that describes what this censor does
  to it (`"*"` allowed; `path_too_slow` = it connects and is merely too
  slow; `unasserted` = not deterministic, e.g. random loss). No scenario
  declares an alternation (`a|b`): a cell that accepts either answer
  checks nothing. These checks hang off it:

  | check | expect | got | proves |
  |---|---|---|---|
  | `censor / truth.category` | the declared category | what a **raw differential probe** of the family's own endpoint observes, shaped like the family's first flight (TLS with the pack's SNI, or opaque bytes, or a QUIC-Initial-shaped datagram) — the ladder is the comment on `truthCategory` in `censor.go` | the declaration describes the network, not a hope |
  | `family / engine.category` | the declared category (`none` for a family that passes) | what the **engine** reported for that route: `abi.DiagnosticsExplain().failures[].classification`, captured by `wb-client` while the route was active | the client's classification matches reality — the thing route selection will act on |
  | `family / engine.first_verdict` | `connected`, for every family with an `established` claim in a scenario that asserts a category | what the **first phone** was told: `connected`, or `failed:<category>` | a session under a degraded path may ask again with a fresh phone when the engine's connection proof fails (the later checks need a connected engine), and a fresh phone has no cooldown and no memory of the failure. This check is the first phone's answer alone — the one a real person gets — and a retry that works does not turn it green. Every attempt is in the `connects` evidence of `tunnel` |
  | `family / established` | `pass`, for every family the scenario expects `blocked` under `"established": {…: "pass"}` | one fresh nonce through the tunnel and back, seen by the target as arriving from the relay — taken from the session's own probe, or asked again (`wb probe --whoami-only`, up to 20 s) while the engine is still up | the family **connected and authenticated** before its payload ran out of budget. `throttle-56k` and `heavy-loss` block nothing; they expect `blocked` only because 256 KiB cannot finish in 5 s, and a dead family (no user on the relay, a shut port) produces exactly that. A scenario whose blocked family has category `none` or `unasserted` and no `established` claim is refused by the `declarations` tests. Shown in the matrix as `blocked:never-connected` when red |

  The differential matters: one reset after a ClientHello is an SNI block
  only if another name to the same address is answered, and a dropped
  datagram means "UDP is dead here" only if one to `elsewhere` dies too.

The scenario is applied after provisioning and minting (the publisher is
outside the censor) and stays for the whole matrix and all ops.

**One phone at a time on a shaped link.** A scenario with a `tc` rate cap
queues what it cannot forward, and the QUIC families go on sending for
seconds after their client is gone. Each session is a separate phone, so
before it starts the driver waits (up to 60 s) until the censor's qdiscs
hold nothing of the session before (`shaper_backlog_packets`,
`waited_for_quiet_ms` on `control.before`; a shaper that never drains is a
red `link.quiet`). Without it the family after hysteria2 and the one after
tuic spent their whole connection proof behind the previous phone's
packets. `WB_NO_QUIET=1` turns the wait off, to see what the engine says
on a link that already has seconds of queue (FINDINGS CEN-O5).
`./e2e.sh full` runs every scenario against every family and prints one
scenario × family table (`./e2e.sh full --only sni-rst,quic-drop` for a
few). It builds once into its own bin directory (`WB_BIN`, `run.sh
--build-only`) and starts each world with `WB_NO_BUILD=1`, so worlds
running side by side never relink what another is executing.

#### The library

| scenario | technique | models (see each file's `analogue` for sources and limits) | mechanism |
|---|---|---|---|
| `clean` | nothing | the control | — |
| `udp-blackhole` | every UDP datagram silently dropped | Iran's standing treatment of outbound UDP | nft |
| `port-whitelist` | only ports 53/80/443 leave, TCP and UDP | Iran's crisis whitelister, 2019–2025 (port half) | nft |
| `protocol-whitelist` | UDP/53 + TCP/80,443 only, **and** a TCP flow must begin like TLS or HTTP | Iran's "heavy mode", June 2025 / January 2026 | nft + dpi |
| `relay-ip-block` | the relay's address null-routed | a burned VPS address | nft |
| `total-blackout` | nothing crosses the border; the link stays up | data-plane shutdowns with BGP left announced | nft |
| `sni-drop` | ClientHello with the cover SNI swallowed, flow blackholed, no RST | GFW ESNI / fully-encrypted-traffic style in-path drop | dpi |
| `sni-rst` | same trigger, forged RST to both ends, reassembling | the GFW's classic SNI reset | dpi |
| `sni-rst-stateless` | same trigger, RST+ACK to the client only, first data packet only | Iran's SNI filter (no stream reassembly) | dpi |
| `tcp-reset-mid-handshake` | any TCP flow to the relay reset on its first data packet | RST against a suspected proxy address | dpi |
| `quic-drop` | QUIC v1 Initial datagrams dropped on every port | QUIC/HTTP3 blocking by protocol | nft (raw payload match) |
| `heavy-loss` | 30% random loss on TCP only | protocol-selective shaping | nft |
| `lossy-throttle` | 60 ms, 1% loss, 4 Mbit/s | a bad mobile path | tc |
| `throttle-56k` | 56 kbit/s, nothing dropped | throttling as blocking | tc |
| `deep-queue` | 1.2 s of delay each way (2.4 s per round trip), nothing dropped | seconds of standing queue: the engine's ordinary connection check finishes nothing, and it must still connect and say "slow" (FINDINGS CEN-O5). Sets `probe_patience_ms` so the raw probes outwait the delay | tc |

Expected outcome per family (`pass`, or `blocked:<category>`), as asserted
— the scenario rows of `./e2e.sh full` on 2026-11-18, every cell green
against `expect` and `truth.category`:

```
scenario                 prove  vless-reality                            websocket-tls                naive                        hysteria2                 anytls                       shadowsocks                  tuic
clean                    7/7    pass                                     pass                         pass                         pass                      pass                         pass                         pass
heavy-loss               3/3    blocked:unasserted                       blocked:unasserted           blocked:unasserted           pass                      blocked:unasserted           blocked:unasserted           pass
lossy-throttle           -      pass                                     pass                         pass                         pass                      pass                         pass                         pass
port-whitelist           6/6    pass                                     blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  pass                      blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:udp_unavailable
protocol-whitelist       7/7    pass                                     blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:udp_unavailable   blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:udp_unavailable
quic-drop                4/4    pass                                     pass                         pass                         blocked:quic_unavailable  pass                         pass                         blocked:quic_unavailable
relay-ip-block           4/4    blocked:tcp_connect_timeout              blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:unknown           blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:unknown
sni-drop                 6/6    blocked:tls_handshake_failed             pass                         pass                         pass                      pass                         pass                         pass
sni-rst                  6/6    blocked:tls_sni_or_cert_block_suspected  pass                         pass                         pass                      pass                         pass                         pass
sni-rst-stateless        6/6    blocked:tls_sni_or_cert_block_suspected  pass                         pass                         pass                      pass                         pass                         pass
tcp-reset-mid-handshake  5/5    blocked:tcp_reset                        blocked:tcp_reset            blocked:tcp_reset            pass                      blocked:tcp_reset            blocked:tcp_reset            pass
throttle-56k             2/2    blocked:none                             blocked:none                 blocked:none                 blocked:none              blocked:none                 blocked:none                 blocked:none
total-blackout           4/4    blocked:tcp_connect_timeout              blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:udp_unavailable   blocked:tcp_connect_timeout  blocked:tcp_connect_timeout  blocked:udp_unavailable
udp-blackhole            4/4    pass                                     pass                         pass                         blocked:udp_unavailable   pass                         pass                         blocked:udp_unavailable
```

The SNI scenarios bite on `vless-reality` alone, by construction: it is
the only family that puts a name on the wire. The other TLS/QUIC families
name the relay by IP literal (which is not sent as SNI) and shadowsocks is
not TLS (FINDINGS CEN-O2).

`engine.category` compares the engine's own account of each blocked
session with the cell above. The engine proves every route with one real
round trip before it calls it connected (FINDINGS CEN-1, fixed), so it
names the failure: exactly, in the TCP cells; as `udp_no_reply` in every
blocked UDP cell and as `tls_sni_or_cert_block_suspected` under
tcp-reset-mid-handshake, where the narrower truth needs a second
observation (FINDINGS CEN-4, open — listed under `KNOWN [CEN-4]`, apart
from any other red). Under throttle-56k the declaration is `path_too_slow`
and the cell is decided per connect by the time the connect took
(`slowCategoryFor`, `first_verdict.go`): longer than the engine's
`slow_after_ms` (2 s) and the engine must have said `path_too_slow`
("Connected" with nothing more is red); within it and the engine must have
said nothing — the engine sees a slow path only through its own proof
(the taxonomy's "What one route can see"). Either is accepted only in the
150 ms in which `set_route_ms` cannot say which side the proof was on. The
engine's connection check reaches the lab's own "internet" hosts: the
driver passes `--proof-targets` to `wb-client`, which writes them to the
engine's ordinary `engine-config.json` before `engine_init`.

#### Fidelity: what this censor is and is not

This models known blocking **techniques** — the mechanisms the literature
in `research/` documents — applied by rules we wrote and can read. It does
**not** model a national DPI's classifiers. A family that passes here has
been shown to survive that technique as implemented here; it has not been
shown to survive Iran or China. Specifically:

* **No classifier.** Nothing here scores entropy, packet-length sequences,
  TLS-in-TLS bursts, JA3/JA4, or flow volume, and nothing actively probes
  the relay. Those are how REALITY, Shadowsocks and Hysteria2 actually get
  caught; a green cell says nothing about them.
* **In-path and deterministic.** The DPI box holds each packet and decides.
  Real SNI resets are injected on-path and race the real ServerHello, come
  in threes, and fire probabilistically under load. The rig's `rst` drops
  the offending segment and sends exactly one reset per direction.
* **No residual censorship.** A trigger kills one flow. The 90–180 s
  3-tuple blocks that follow a real trigger (and that make a client's
  immediate retry fail for a different reason) are not modelled.
* **A simpler parser than the adversary's — and a stricter one than
  Iran's.** The ClientHello parser reads one TLS record; a hello fragmented
  across records is not seen (the real blind spot too). `sni-rst-stateless`
  reads only the first data packet (the real box reads two). No ECH, no
  QUIC Initial decryption (so no QUIC-SNI blocking), no certificate
  inspection, no HTTP Host matching, no DNS tampering at all.
* **One address, one flow direction.** Rules look at client→world packets.
  There is one relay address, one client, one ISP; no per-ISP differences,
  no IPv6, no whole-provider or whole-prefix blocks.
* **Loss and throttling are netem / `numgen random`**: independent
  per-packet loss and a fixed rate. Real shaping is bursty, selective and
  time-of-day dependent.
* **The control host is the only "rest of the internet"** on the client's
  side of a tunnel. There is no domestic network, no CDN, no DNS resolver
  reachable without the tunnel.
* **What the raw probes prove** is that a rule bites on the wire shape the
  probe sends. The probe's QUIC datagram is shaped by us (header only); it
  is the real families failing under `quic-drop` that shows real QUIC has
  that shape.

To add a scenario: one file, with `analogue`, `prove` (a biting probe and a
spared one), `expect`, and `category` for whatever it blocks; if it needs a
mechanism that does not exist, add a `when` to `censor_dpi.go` with a unit
test in `censor_test.go`. Then run it and paste what you measured — an
expectation nobody ran is a guess.

### (c) A publisher-side operation — `driver/ops_<name>.go`

```go
func init() { Ops["revoke"] = opRevoke }

func opRevoke(rc *RunCtx) {
    const phase = "op:revoke"
    pack2, ok := rc.MintRecipient("r2", phase)          // real users-provision + users-pack-sbp
    for _, f := range rc.activeFamilies() { rc.sub(f, phase, "before", pack2, Pass) }
    v := rc.Pub.UsersRevoke(rc.Ctx, "r2")                // a real verb
    rc.R.Add("", phase, "verb.users-revoke.r2", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0)
    for _, f := range rc.activeFamilies() {
        rc.sub(f, phase, "revoked",   pack2,   Blocked)  // the insider's view of the change
        rc.sub(f, phase, "bystander", rc.Pack, Pass)     // and of what must NOT have changed
    }
}
```

Rules: change the world only through `rc.Pub` (real verbs; add a typed
helper to `publisher.go` for a new verb); assert from the insider's seat
with `rc.sub(family, phase, label, pack, expect)`, which runs a full
`Session` whose check ids are prefixed `label.`; record every claim with
`rc.R.Add`; always pair the effect with a control (the thing that must not
change). Ops run after the matrix, in the order given to `--ops`, on the
same relay — an op that destroys state should create its own (`r2`), not
consume `r1`. After any verb that talks to the mgmt plane, call
`rc.MgmtWindowClosed(phase)`: the ephemeral cloud-firewall window must be
gone. What the publisher did to the cloud account is assertable
from `CloudRequests(p)`; what it did to the box, from `out/<run>/boxes/<id>/`.

Existing ops: `revoke` (revoked recipient blocked, bystander unaffected,
per family), `wrongcreds` (a validly signed pack with credentials the relay
never issued carries nothing), `tamper` (the negative controls for what is otherwise only ever seen to
succeed: one altered byte of the signed manifest, a stranger's valid
signature, a stranger's key, a pack minted 40 days ago by the real verbs,
and a mgmt endpoint that fails the TLS pin — each must be refused for the
reason named in the row; plus the unsigned half of a pack: the `server`,
port, TLS pin, REALITY public key, trusted certificate and shadowsocks
server key of the profiles rewritten one at a time, and the endpoint
commitment stripped from the manifest — each refused at import — and one
recipient CREDENTIAL rewritten, which imports, by design, and then goes to
the genuine relay and carries nothing), and the lifecycle ops below.

#### Lifecycle ops — what happens after first contact

`--ops lifecycle` runs them all, in this order (`LifecycleOps` in
`driver/lifecycle.go`); each also runs alone. Helpers they share
(`lifecycle.go`): one typed helper per verb (`RotateCredentials`,
`RotateTLS`, `AssignFIP`, `ReleaseFIP`), `rc.Rebuild(name, …)` (the app's
"Rebuild": revoke → provision → pack), `rc.BoxSingboxConfig()` /
`rc.userRows()` (the box's live config), `rc.MgmtProbe(…)`,
`rc.liveFamilies(phase)` (families the scenario does not block — a blocked
family gets one `skipped` line per op instead of sessions that prove
nothing).

| op | real verbs | what it asserts | controls |
|---|---|---|---|
| `recipients` | `users-provision`, `users-pack-sbp`, `users-list` | four recipients on one relay: every per-user secret differs, box-wide material is shared, each inbound has a row per recipient, **each one's pack carries verified bytes on every family** | `revoke` / `wrongcreds`: a missing or wrong row does not connect |
| `revoke` | `users-revoke` | the revoked recipient is cut off on every family | the others still connect — and if a bystander does not, the revoked recipient's `blocked` is not counted as revocation (`revoked.attributable`, never excused) |
| `l1` | `rotate-credentials --name r21` | every secret of r21 changed and none of the old ones is left in the box's config; no box-wide key moved; the relay names every inbound it rewrote; **old pack blocked, new pack connects** | two bystanders' rows are byte-identical and their packs still connect |
| `l3` | `assign-fip`, `bind-and-sign`, `users-pack-sbp`, `publish-freshness`, `floating-ip release` | the real `/bind-address`: record moved, box holds and persists the address; re-minted pack connects **while the censor blocks the old address**; **a phone holding a pre-move file polls the mirrors and connects with no new file** (`no-new-file.address-blocked.*`); then the real `/unbind-address`: record, box and cloud account are clean | new address dead before the swap; old pack still works until the block (grace), then does not; the released address stops serving. (`refused_before_reserving` — a relay that does not advertise `bind-address` is refused before anything is reserved — is coded but **runs in no world**: every daemon here advertises it, see "Known gaps: privilege on the box") |
| `l2` | `rotate-tls`, `bind-and-sign`, `publish-freshness`, then Rebuild | cover host moved in the record and in both places on the box; no key, no user row changed; **old pack per family = `l2OldPackExpect`** (vless-reality blocked, the rest pass); **a phone holding a pre-rotation file polls the mirrors and connects on every family with no new file** (`no-new-file.cover-host-moved.*`); rebuilt pack connects everywhere | the pre-rotation session passed |
| `mgmtauth` | (hand-built requests, `mgmtprobe.go`) | unsigned, wrong scheme, garbage, empty signature, stranger's key, wrong op, stale, future, signed for another body, signed for another relay, replayed address token, **replayed `users-revoke` token aimed at a second recipient** are all refused | a correctly signed request is honoured; afterwards the config is byte-identical and the targeted recipient still connects |
| `freshness` | `bind-and-sign --freshness-mirror`, `publish-freshness`, `rotate-tls`; engine: `abi.SchedulerTick` | what the app publishes — the digest of the SIGNED, credential-less pack, with that file at the pack URL — is **merged** by a polling phone: with nothing changed it still connects and keeps every route; after an L2 it connects **with no new file** (nothing is minted for it); the published file holds no credential (`published.*.holds_no_credentials`) | no poll → still blocked; a document signed by another key → refused, no pack downloaded; a pack whose digest does not match → refused; the signed pack handed as a file to a phone that holds nothing → refused; the signed pack from BEFORE the rotation handed as a file to a phone that has already moved on → not merged, routes kept, still connects (`rotated.stale-signed-pack-by-file.*`) |
| `caps` | — (reads this run's results) | every token `/health` advertises was observed to work in this run, and nothing that worked is unadvertised; a token with no evidence is `skipped` with the op that would produce it; a token the rig has no proof for fails. **It judges the binary's claim against the binary's behaviour, not the box's privilege**: `bind-address` is advertised because the daemon holds `CAP_NET_ADMIN`, which in this world every process does. It does not show that the systemd unit grants it, nor that a relay with an older unit advertises nothing | — |
| `restarts` | `users-provision`, `users-revoke` (N cycles, `WB_RESTART_CYCLES`, default 6) | the relay comes back serving **every** family after every restart of its data plane: each cycle restarts sing-box three times and then runs a bystander's session on each family | the bystander's pack is r1's, never touched by the verbs |

`l2` invalidates every vless-reality pack minted before it (for a phone
that does not poll), re-signs `base.sbp` (`rc.Resign`: the signed endpoints
name the cover host) and re-issues r1's at the end (`rc.Pack` is
replaced); `freshness` does the same. `l3` leaves the world as it found it.
Any op that moves an endpoint must `rc.Resign` before it mints from
`base.sbp`: `users-pack-sbp` refuses a signed pack that no longer
describes the relay. `caps` must run last. The rotation rungs
need a mgmt daemon that advertises them: the pinned release does for
L1/L2/L3 on the four default families (FINDINGS LC-O4).

#### Client-side ops — one phone that stays up

`switch` and `switch-all` (`driver/ops_switch.go`) change nothing on the
publisher's side. They are the only sessions in the rig that do not end
after one route: one `wb-client` stays connected and is told, on stdin,
`switch <order> <family>` (`labclient/switch.go`) — the person tapping
another route's Connect. They exist because the first real-phone pass
broke on exactly that (FINDINGS SW-0), in a place a connect → fetch →
disconnect session never visits.

| order | what the client does, through the same abi the phone uses | whose order |
|---|---|---|
| `rotate` | a NEW TUN → `SetTunFD(new)` → `SetRoute(B)`, no `ClearRoute` first | `DaalVpnService.kt` on the phone pass of 2026-11-19 — the only order in which the engine closes a TUN fd under a running instance |
| `keep` | `RouteConnectPrecheck(B)` → (refused: stop, touch nothing) → `SetRoute(B)` on the TUN already held | `vpn/StartSequence.kt` since |
| `check-rotate` | `RouteConnectPrecheck(B)` → (refused: stop) → a NEW TUN → `SetTunFD(new)` → `SetRoute(B)` | nobody's; the order that never shares a TUN between two instances (what FINDINGS SW-2 recommended before the engine carried the fix) |

Per switch (`<order>.<from>><to>.<check>`):

| check | expect | what it proves |
|---|---|---|
| `accepted` | pass | the engine took route B |
| `tunnel` | pass | a 256 KiB fetch verified through the relay **and 20 further connections, every one** — a tunnel that resets some of them is not carrying |
| `wire` | pass | at the censor the fetch travelled on B's endpoint, and the client opened nothing else on the relay |
| `store_survives` | pass | `SubscriptionList`, `AvailableRoutes`, `RouteSummary`, `DiagnosticsExplain` answer after the switch, the engine still lists its routes, and none of those calls failed while polled every 25 ms during it |
| `active_route` | pass | `ExportDiagnostics.active_route` / `active_route_family` and `DiagnosticsExplain.active_route` name B |
| `fds_intact` | pass | sentinel files the "app" opened before the switch and between the TUN rotate and the switch are still open, still the same file (fstat), still writable. In a rotating order the client keeps opening until one of them has the old TUN's fd number |

Per session: `connect.*` (the first route carries), `disconnect.*` (the
same `store_survives` / `fds_intact` after `ClearRoute` + `ClearTunFD`,
with sentinels opened between the two; `active_route_cleared`;
`control.after`), `session.fd_trap_armed` (a sentinel really did land on
an old TUN's number — otherwise `fds_intact` proved nothing) and
`session.old_tuns_released` (no TUN interface a switch replaced is still
held by the engine).

`switch` runs three sessions between one TCP family and one QUIC family
(vless-reality and hysteria2 where under test): `rotate` A→B→A; `keep`
A→B→A; and `check-rotate` with the two switches that must **not** take —
`unreachable.*` (B's endpoint dropped at the censor for the moment, a
private nft table `wb_switch`: the engine must not call B connected, and
A is connected again without the host doing anything, the diagnostics
say so in `switch_back`, and A carries — FINDINGS SW-1, fixed; `restore.*`,
the host setting A again, runs only if the engine did not) and `refused.*` (B is now cooling down:
refused by the pre-check, the reason is in the diagnostics, A is still
connected and still carries verified bytes on its own endpoint).
`switch-all` walks an Eulerian circuit of the families — every ordered
pair once, 42 switches for 7 — in one `rotate` session, then the ring of
them in one `keep` session. Both ops need a scenario that blocks neither
family (`clean`); elsewhere they record one `skipped` line.

`auto` (`driver/ops_auto.go`, `labclient/auto.go`) is the main screen's
one button: `engine_connect_auto`, no route named. The client is started
with `--auto`, imports the pack and waits; it then does what the Android
service does (`vpn/StartSequence.kt` `runAuto`) — a TUN only when none is
held, the blocking call, and, when nothing came up and nothing is
running, `ClearRoute` + `ClearTunFD` — on these commands: `auto`,
`auto-cancel <ms>` (Connect, then Cancel: `ClearRoute` every 100 ms until
the call returns), `connect <family>` (a route picked by hand),
`disconnect` (the process and its memory stay), `diag` (the diagnostics
and nothing else), `stop`. The censor's part is a private nft table
(`wb_auto`, or `wb_switch` for one endpoint) for the length of a step.

In a world whose scenario blocks nothing, seven phones, each a fresh
state directory (`<phone>.<step>.<check>`):

| phone | what happens | the checks that carry it |
|---|---|---|
| `first` | Connect with nothing in the way; Connect again; Disconnect | `first_route_first_try` (one route tried, the ranking's first; no verdict; experimental routes left out as `experimental_off`), `already_connected_is_a_no_op`, `disconnect.clean` (nothing running, `auto` idle, mode false) |
| `blocked` | the censor drops the first-ranked route's endpoint; Connect; Disconnect; block lifted; Connect | `blocked_route_tried_and_named` (tried FIRST, `not_carrying`, a category), `verdict` = `moved_on`, `progress_visible` (a page polling the diagnostics saw `trying` 1 of n, 2 of n), `again.remembered_route_first` (`why: carried_here`) |
| `memory` | the last-ranked (QUIC) route connected by hand once; Disconnect; Connect. Then every UDP datagram dropped; Connect | `by-hand.connected` (`auto.mode` false: a hand-picked route is the person's), `remembered_route_ahead_of_the_ranking` (r4 first where the ranking says r1), `udp.quic_route_tried_and_silent`, `udp.refined` = `udp_blocked_here`, `udp.verdict` = `moved_on` |
| `quic-only` | the same start; QUIC Initials dropped, plain UDP delivered; Connect | `refined` expects `quic_blocked_here` and gets `udp_blocked_here` — red, FINDINGS CEN-4 (what is left of it) |
| `all-blocked` | the relay's address null-routed. Cancel 1.5 s into a Connect; Connect; Connect again | `cancelled_promptly` (back within 2 s, `cancelled`), `every_candidate_tried_none_connected`, `verdict` = `relay_unreachable`, `refined` = `relay_unreachable` on the QUIC route (a dead address, not blocked UDP), `nothing_left_running` (no route, TUN released, the verdict still readable after the teardown, mode false), `again.verdict` = `all_cooling_down` with nothing started |
| `fall-over` | connected by the button; the censor starts dropping the running route; the host only looks | `engine_moved_by_itself`, `says_what_happened` (`tried[0]` is the lost route, `why: was_connected`; `moved_on`; mode still true), `same_tun`, `fds_intact`, then `tunnel` + `wire` on the new route |

Every "connected" is the switch op's `tunnel` + `wire` (a verified fetch,
20 further connections, bytes on that route's endpoint and no other),
plus `connected`: the call, `active_route`, `DiagnosticsExplain` and the
`auto` block agree. Every press records `store_survives` and `fds_intact`
over the whole pass (up to one engine instance per route on one TUN).

The fall-over phone runs the engine's liveness check every 3 s
(`connection_check.liveness_interval_s` in the engine's own configuration
file; production: 180 s ±25 %). Nothing on the host triggers the move in
either case — that is what the phone proves; how long a real phone waits
is not measured here (FINDINGS AUTO-O1).

In a world whose scenario blocks something there is one phone,
`scenario`: one press under the scenario as it stands.
`tried_agrees_with_the_censor` (no route the scenario stops is reported
as carrying, none it spares as failed); then either `connected` +
`tunnel` + `wire` on a route the scenario spares, or `not_connected`,
`verdict` (the one `AutoVerdictUnder` declares for the scenario:
relay-ip-block → `relay_unreachable`; total-blackout → `network_down`,
red and known as FINDINGS AUTO-1) and `nothing_left_running`.

That every one of those can fail: the op was run against an engine built
with three one-line mutations (no per-network memory; no fall-over; no
UDP refinement) through `go build -overlay`, the tree untouched — 8 red
checks, exactly the ones that name those behaviours (FINDINGS AUTO-0).

Controls: `connect.control.before` / `disconnect.control.after` (no
tunnel, no path); the wire tap (bytes on B's endpoint are not bytes on
A's); and the proof that `fds_intact` can fail at all — build the client
without the fd fix and it does (FINDINGS SW-0).

The client side of `freshness` uses `wb-client --idle`: import, then wait
for commands with the VPN off — `tick` calls the product's own
`abi.SchedulerTick` once, `import <file>` hands the phone another file
(the app's own `abi.ImportSBP`), `connect <family>` brings the VPN up.
Nothing was added to the engine for it.

### (d) Results

`out/<run>/results.jsonl`, and stdout with `--json`: **one JSON object per
check, one per line.**

```json
{"ts":"2026-11-18T13:26:58.40Z","run":"20261118-142651-113457","scenario":"clean",
 "family":"vless-reality","phase":"family","check":"tunnel",
 "expect":"pass","got":"pass","ok":true,"detail":"",
 "evidence":{"route_id":"r1","target_saw":"192.0.2.2","nonce_ok":true,
             "blob_bytes":262144,"blob_sha256_ok":true,"fetch_ms":12},"ms":19}
```

| field | meaning |
|---|---|
| `phase` | `world` \| `provision` \| `mint` \| `censor` \| `family` \| `op:<name>` |
| `family` | absent when the check is not about one family |
| `check` | stable dotted id; inside an op, prefixed with the session label |
| `expect`, `got` | `pass` \| `blocked` \| `refused` \| `fail` \| `skipped` — except checks named `*.category`, where both are a failure-taxonomy category or `none` |
| `box` | `pinned` \| `tree`: which `daal-relay-mgmt` the box runs (the release artefact, or `--mgmt=tree`) |
| `ok` | `expect == got`, always. Never rewritten |
| `known` | present on a red check an open finding explains: the FINDINGS.md id (see "Exit status") |
| `detail` | the error text when there is one |
| `evidence` | free-form facts a human would want next |
| `ms` | wall time of the checked action |

`blocked` = traffic did not get through; `refused` = the product itself said
no (import rejected, route cannot be activated); `fail` = something that
must work did not.

The human matrix (end of every run): one row per family, one column per
check of the scenario; a cell is the observed outcome, `!got(want X)` when
it is unexpected, or `~got(ID)` when open finding ID explains it.
Each op then gets a compact table of its `*.tunnel` verdicts, and the
non-family checks are counted per phase. `SKIPPED` lines and every failed
check are repeated underneath with their detail.

Other evidence in `out/<run>/`: `publisher-verbs.jsonl` (every verb: argv,
rc, stdout, stderr), `cloud-requests.jsonl` (every cloud/mirror call),
`censor.nft`, `clients/NN-family/{events.jsonl (engine events incl. the
diagnostics blob), stderr.log}` (the engine's own state directory lives in
the world's memory and is gone with it; `WB_STATE_ON_DISK=1` keeps it
there too), `boxes/<id>/{user-data.yaml, etc-upper/ (the box's /etc
as the product left it), rootfs/var/log/, state/}`, `logs/`.

## Changes to production code

**No lab seam in any product source file.** None was needed: the engine already
takes its TUN from the platform, the cloud client honours the system
resolver and trust store, and the box's binaries only need their real paths
(which the box's private root filesystem gives them).

Tooling: `./daal` lists `test-rigs/worldbox/driver` in `cmd_test` (the
isolation, declaration, plan and known-findings tests run in `./daal test`),
and has an `e2e` verb that calls `e2e.sh` and maps its exit status.
`tools/hooks/pre-push` runs `./daal e2e quick` as its last step: measured
at 62–70 s here, hermetic. On a machine that cannot host it (exit 77) the
hook fails; `DAAL_E2E_ALLOW_SKIP=1 git push` is the explicit opt-in that
turns that into a loud SKIPPED (never a pass). `driver/isolation_test.go` allows `./daal` to name the
rig in exactly those two places and nowhere a shippable artefact is built.

Family work added two product fixes, each with a test in the default build
(FINDINGS FAM-1, FAM-5):

* `core/engine/config.go` — a TCP-only outbound gets one route rule that
  hands UDP/53 to the engine's own DNS-over-TCP server; without it no name
  resolves. `TestBuildSingBoxConfigHijacksDNSForUDPLessOutbounds`,
  `TestTCPOnlyOutboundTypesMatchSingBox`. The rule applies to http, tor, ssh,
  shadowtls, any profile pinned to `network:tcp`, and a naive outbound
  minted without `udp_over_tcp`. **The rig no longer exercises it**: the
  one family it ran on, naive, carries UDP now (FAM-6) and its lookups
  ride the tunnel; no rig family dials tor. It is unit-tested, and
  parsed/started by the linked sing-box under `-tags singbox`, not
  carried.
* `core/engine/cronet_loader_naive.go`, `cronet_state.go` — off Android,
  load Cronet through cronet-go's own search (executable directory first)
  instead of by soname. Android is unchanged. `TestCronetLibraryArg`.

Lifecycle work added one product fix with a test (FINDINGS LC-1):

* `cmd/daal-relay-mgmt/main.go` — every MUTATING mgmt verb's token is now
  single-use (it was only the two address verbs); `users-list` and `whoami`
  stay replayable. `TestMutatingTokensAreSingleUse`; spec §3 and §4.8
  updated. Takes effect on relays only with the next mgmt release.

The wire tap uses connection tracking in the censor namespace (to tell a
flow the client opened from a straggler of the previous session); it needs
the `nf_conntrack` module, which `nft … ct state` loads or finds loaded.

## Known gaps (next)

* **Censor fidelity**: the scenario library models techniques, not
  classifiers — see "Fidelity" under contract (b). Not built: residual
  3-tuple blocking after a trigger, on-path (racing) injection, QUIC
  Initial decryption for QUIC-SNI blocking, DNS tampering, active probing
  of the relay (CEN-O1 is a first measurement), entropy / TLS-in-TLS /
  fingerprint classifiers, and per-scenario clocks (a censor that changes
  mid-session, which is what the rotation rungs react to).
* **Rotation rungs**: L1, L2, L3 are ops (`l1`, `l2`, `l3`). L3's cloud
  half is the lab's; a real reboot of the box (does the bound address come
  back?) is not performed — the boot unit and the persistence record are
  asserted to exist. L3's failure paths (probe fails after the bind →
  unbind → give the address back) are not driven. L4–L6 (`reprovision`,
  second provider) need server rebuild/delete-recreate (delete is modelled)
  and more than one slot; a Vultr fake is a second file next to
  `fakecloud.go`.
* **A phone that already holds the old pack imports the new one** (the
  `rotation_accepted` verdict; do two routes of one family now exist?):
  every session is a fresh state directory. `wb-client --idle` is the place
  to add a second import.
* **Freshness**: exercised for an L2 rotation on vless-reality with a
  first-ever poll. Not exercised: the cadence (15-minute floor, backoff,
  jitter — needs clock control; `cmd/daal-soak-engine` has `set-now` under
  `-tags soak`), a poll THROUGH an active tunnel, rollback (lower
  sequence), document expiry, every mirror blocked → bootstrap-pointer
  recovery, the R2/GitHub uploaders. (An L3 move and an L2 learned through
  freshness ARE exercised: `op:l3` / `op:l2` `no-new-file.*`.) Not
  exercised either: what a polling phone does after L1 (that recipient
  needs a new file — nothing in the published pack can help) and after a
  rebuild (everyone does).
* **Expiry / revocation lists**: no revocation mirror; packs are minted
  without one (the verb warns).
* **sshd on the box**, so the provisioning log observer and the
  `reality.pub` read run for real.
* **Reconnecting from existing state across a process restart**: op `auto` keeps one engine process through connects, disconnects and the engine's own move from one route to the next, but a phone that is killed and started again with its state directory is not modelled — every phone here starts fresh.
* **The network changing under the phone** (`engine_network_changed`): every phone of op `auto` sits on one network, the engine's "none reported" bucket. That a route remembered on one network is not preferred on another is covered by the engine's unit tests only.
* **The liveness clock of a real phone**: see FINDINGS AUTO-O1.
* **Sessions run one at a time** in the single client namespace; a blocked
  family costs its timeout (~5–10 s). More client namespaces would
  parallelise the matrix.
* **IPv6**: the world is IPv4-only.
* **Privilege on the box.** Every process in the world is root of one user
  namespace and holds every capability over its own network namespace; the
  `systemctl` shim reads no `User=`, `AmbientCapabilities=` or
  `CapabilityBoundingSet=`. So the `l3` and `caps` checks do **not** cover
  the two things hardware proved about privilege: that bind/unbind works on
  a relay only because `daal-relay-mgmt.service` (and the boot unit the
  daemon writes) carries `AmbientCapabilities=CAP_NET_ADMIN`, and that a
  relay provisioned before that line existed advertises nothing and is
  refused. The second has a branch in `ops_l3.go`
  (`refused_before_reserving`) that no world reaches — measured 2026-11-18:
  tree and pinned daemon both advertise `bind-address` and both take the
  full path. What does cover them is unit-level and on the product side
  (`cmd/daal-relay-mgmt/address_test.go`: `TestBindRefusesOnAnIncapableBox`,
  `TestHealthAdvertisesBindAddressWhenCapable`,
  `TestCapabilityProbeIsHonestOnThisHost`) and the phone + VPS run already
  done. Closing it here means a shim that applies the unit's bounding set
  (`setpriv`) and a world provisioned from a unit without the line. The
  same blindness covers `User=daal` (file ownership and modes on
  `/etc/daal`) — `box/shims/chown` is a no-op.
* **The client is not the phone's binary.** `wb-client` is linux/amd64,
  glibc, the engine linked as a Go package, Cronet from the Go module
  cache. The phone runs an android/arm64 gomobile library over JNI with the
  APK's own `libcronet.so`. And Android's resolver is replaced by a probe
  that sends plain UDP/53: Private DNS (the opportunistic DoT upgrade, or a
  named provider) does not exist here. Consequence for **FAM-1**: the fix
  is verified against the "Private DNS: Off" shape only; `naive dns pass`
  does not replace the phone retest written in that finding.
* **Code-reading, not observation**: that the APP publishes the signed
  pack's digest (`freshness.rs`), that it signs before it has a recipient
  (FINDINGS F-005), and all of FAM-2 rest on reading `freshness.rs`,
  `commands.rs` and `PublisherWizard.tsx`. Neither file is compiled or run by the rig; the
  CLI is driven with the arguments that reading says the app would pass
  (each finding says so).
* **Quick mode says little about relays in the field.** 14 of its 15
  worlds run **this tree's** `daal-relay-mgmt` (`--mgmt=tree`); only
  `release` runs the pinned artefact a relay provisioned today really
  downloads, and only on the four default families with `revoke` and
  `mgmtauth`. A green pre-push gate is a statement about the tree. For
  deployed relays read `release.lifecycle` and `release.all-families` in
  full mode — and those are the pinned artefacts on a simulated box, not a
  relay that has been up for a month.
* **No reboot of the box, and no restart of the mgmt daemon.** The
  `restarts` op restarts sing-box only. `daal-relay-mgmt` starts once per
  world and lives to the end, so nothing here shows what a restart does to its
  in-memory single-use nonce set. (Since token format v2 a token signs
  its request body, so a token replayed after a restart can only repeat
  the identical request — unit-tested in `cmd/daal-relay-mgmt`,
  `TestTokenIsBoundToTheRequest`; `mgmtauth` presents a never-used token
  signed for another body, and a v1 token, and both are refused.) Nor
  does anything show that a bound address is re-applied at
  boot (the persistence record and the boot unit are asserted to exist;
  the unit is never run).
* **Families a self-hosted relay does not serve are absent**: the family
  set is exactly `iran-default.json` (a test holds it to that). `tor-bridge`
  (with its obfs4 / meek / webtunnel / snowflake bridge lines) and paste-
  imported `wireguard` — both real routes in the engine — are not here,
  nor are bundles from any source other than a Daal relay's own pack.
  There is no tor binary, no bridge and no third-party endpoint in the
  world.
* The app layers above the ABI (Rust bridge, TS UI, route selection) and
  below the engine on Android (SELinux, real VpnService) are not here. The
  phone is still needed for those; it should no longer be needed to learn
  that a family cannot carry a byte.
