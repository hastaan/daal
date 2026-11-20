# Field Probe v2 — the network test

## Status

Engine side built (2026-11-20): `core/fieldprobe`, `core/abi/fieldprobe*.go`,
`bundle/go/fieldreport`, `bundle/go/envelope/report.go`, the publisher's
`daal-deploy report-keygen` / `report-open`, and the Tauri commands
`field_probe_{start,status,cancel,seal,discard}`. Not yet built: a
publisher-signed target list. Nothing has been run on a phone.

UI, shell and publisher (2026-11-20, third pass; Rust and Kotlin not yet
compiled):
- Recipient: Settings → Advanced → Network test
  (`client-ui/src/components/NetTestPage.tsx`, `lib/netTest.ts`), shown only
  while status says `has_test_relay` or a result is kept. Consent (the
  plan's `names` and `public_resolver`, and a "before you start" line
  right above Start), Start, step n of N with Cancel (leaving the app
  cancels with `backgrounded`; leaving the page cancels too), the
  summary, "Show everything" (the kept report as JSON), one "Send report"
  (`field_probe_share`: seal, always transient, then the share sheet),
  "Run again" (the consent over the kept result, which the new run
  replaces; first for a run that stopped early) and "Delete report";
  after a send it asks to delete.
- Android shell: `FieldProbeWatch.kt` in the platform plugin (Kotlin command
  `fieldProbeWatch`). `field_probe_start` asks it for the network's DNS
  servers, Private DNS mode, VPN up, global IPv6 and "blocked without VPN"
  and merges them into the start options; it then feeds
  `engine_network_facts` for the run and calls `field_probe_cancel("vpn_active")`
  (JNI `DaalCoreBridge.fieldProbeCancel`) when any VPN network appears
  (`"connecting"` when it is Daal's own). For the run it also keeps the
  screen on (FLAG_KEEP_SCREEN_ON) and cancels with `"backgrounded"` when
  Daal's activity stops. The watch stops when status says the run is
  over, on cancel and on discard, and after 6 minutes regardless. The FileProvider exposes
  `files/daal/fieldprobe-out/` (tools/patch-android-manifest.sh writes
  `res/xml/file_paths.xml`).
- Publisher: relay page ⋯ → "Use as test relay…" makes the report key on
  the phone (`daal-deploy report-keygen --out -`), keeps it in device
  custody as `daal.report.<id>.key` (`.retired` after "Stop"; both in the
  publisher backup when present) and signs the relay's pack again with
  `bind-and-sign --report-to` (every route gets `_report_to`). Nothing on
  the relay changes and no file is made again: every file already handed
  out (each person's and the everyone file) keeps working without the
  test. For a relay people connect with (anyone not removed, or an
  everyone file) the wizard refuses with `E_TEST_RELAY_IN_USE` unless the
  sheet's second confirmation, which names the count, was given.
  Deleting the relay deletes both report aliases. Relay list ⋯ → "Open a network test report"
  opens a `.dat` with any report key on the phone (`report-open`, key on
  stdin) and shows each stage in words, with "Copy as text".

Review fixes (2026-11-20, second pass): protect() refusals after a
disconnect no longer fail every probe; resolver answers are held to
per-role address blocks and Stage B certificates are verified; a stall
inside the server's flight is told apart from a TLS alert; the blackout
rule and a time reserve keep Stage C reachable on the worst networks; the
run stops when another VPN or a Daal connect appears mid-run; the report
key, the relay and its alt routes all come from one trusted pack; the
Test relay must be its own address; C1 is gone and relay flows are
capped at 9; lockdown is seen by a preflight that sends nothing.

v1 (`specs/field-probe-v1.md`) stays the contract for the standalone
`daal-probe` report; v2 is the test inside Daal. Everything v1 promises is
kept: opt-in, manually started, reviewed before it leaves, **never opens a
socket to send the report** — the report leaves only as a file the person
shares.

## What it is

A person who normally uses Daal turns every VPN off, starts the test
(Settings → Advanced → Network test), and for about three minutes the
engine makes about 20 short TCP connections, up to 4 QUIC handshakes and
about 12–18 DNS questions, to Google, GitHub, Cloudflare and the
publisher's Test relay. The result is kept on the device, encrypted, and
— only if the person taps Send after Daal is connected again — sealed to
the publisher and handed to the share sheet.

## Who may run it (engine-enforced)

`engine_field_probe_start` refuses with a closed code, never by running
anyway:

| code | when |
|---|---|
| `running` | a run is already going |
| `connected` | Daal has a route up, or an automatic connect is trying one |
| `vpn_active` | the page says another VPN is up (`TRANSPORT_VPN`), or the network the host reported is `vpn` |
| `no_network` | the host reported no network |
| `local_blocked` | the host passed `blocked: true` (`NetworkCallback.onBlockedStatusChanged`: "block connections without VPN" with Daal down) |
| `consent_required` | `consent_version` is not the engine's (1) |
| `no_report_key` | no held route in a trusted state (`trusted`, `tofu`) carries a valid `_report_to` |
| `no_test_relay` | no such route is a vless REALITY route on 443, at a public address, that the side instance can prove |
| `test_relay_shared` | the Test relay's address is also the address of a held route without `_report_to` |
| `rate_limited` | one run per network per 6 h, three a day (`retry_after_min` added); charged when the first packet goes out, not at start |

**The Test relay must be a separate address.** The test sends three plain
hellos with three different names (one of them `github.com`) to the relay
within about 20 s, which is the most scanner-like part of the run; the
family's daily relay must never be the one it does that to. The engine
refuses (`test_relay_shared`) when it can tell.

Lockdown is also caught by a **preflight** before the first probe: a UDP
`connect()` to `1.1.1.1:53` (sets a route, sends no packet). `EPERM`,
`EACCES` or `ENETUNREACH` stops the run with `abort_reason:
"local_blocked"`, no probe and the single summary line
`netTest.summary.localBlocked`. A first TCP socket failing the same way
does the same.

**protect().** Each probe socket is offered to the engine's protect
callback. On Android the callback stays registered after Daal
disconnects, and the host's protect then refuses every socket (its
VpnService is gone). With no TUN fd and no route that refusal is ignored:
there is nothing to bypass. With either present it is fatal for that
socket, recorded as `local_error` (never `timeout`), and a device that
refuses every socket ends the run at the preflight (`abort_reason:
"error"`).

During a run, the engine stops it (keeping the partial result) when the
network id changes or the host reports no network (`network_changed`),
when the local address of the probe sockets changes mid-run
(`network_changed`: another network, or another app's VPN now carrying
the probes, which protect() cannot prevent), when another VPN appears in
the host's network facts (`vpn_active`), when Daal connects or the
automatic connect starts trying (`connected`), when the page calls cancel
(`""` / `backgrounded` / `network_changed` / `vpn_active` / `connecting`),
on engine shutdown and panic wipe, and at the 4-minute hard stop
(`time_limit`). The engine checks these before each step and every
250 ms, and a stop cuts the step in flight. **The Android shell must call
`engine_field_probe_cancel("vpn_active")` from its NetworkCallback on
`TRANSPORT_VPN`, and keep calling `engine_network_facts` while the test
runs** (the facts callback is otherwise the VPN service's, which is down).

## Probe list (order is the plan)

Targets are named by **role** in the report; real names come only from the
target list (below), addresses only from DNS answers or the held pack.

| id | probe | answers |
|---|---|---|
| A1 | A + AAAA for the Google and GitHub names, link resolver | resolver alive; bogon on allowed names; `dns_wrong_public` |
| A2 | A + HTTPS (65) for `cloudflare-ech.com` | ECH config delivered or stripped |
| A3 | A for the white name | real CDN address or sinkhole |
| A4 | A, AAAA, CNAME, TXT of the known-answer records | recursion per record type, answer intact |
| A5 | A for `cloudflare-dns.com`, link resolver | calibration (expected bogon 10.10.34.34–36) |
| A6 | A for A5's and A4's first name to `1.1.1.1:53`; then, for each of Google/GitHub/Cloudflare/white whose link answer was missing, a lie or outside the role's blocks, one A to `1.1.1.1` (`fill_*`), held to the same blocks | on-path injection vs resolver poisoning; real addresses for Stage B |
| B1 | TLS Google, `GET /generate_204` | is international TLS up. **Blackout: B1 failed at reach/handshake (or had no address) and every A6 question timed out → short circuit: C2 only, then stop.** Link-resolver answers are not evidence: domestic resolvers keep answering in a shutdown |
| B2 | Google address, SNI Google, `Host:` front host, list path | does the Host switch pass (status class only) |
| B3 | one redirect, only to a name under `googleusercontent.com`, fronted the same way | claim 32 |
| B4 | GitHub, Atom feed path, ≤ 32 KB | claim 26 |
| B5 | white name on its real address (link → public → hint), ≥ 32 KB path | whitelisted names carry uncapped |
| B6 | `speed.cloudflare.com` on the Cloudflare address, `/__down?bytes=65536`, Chrome's unmodified hello (h2 or HTTP/1.1, whichever the server picks) | grey cap on an allowed CDN address |
| B7 | ECH (Go `crypto/tls`): outer `cloudflare-ech.com`, inner `crypto.cloudflare.com`, `/cdn-cgi/trace`; config from A2, else the list's; retry configs honoured once | ECH passes; `sni=encrypted` |
| B8 | B7 without ECH | control |
| B9 | QUIC (h3 ALPN) handshake to the Google and Cloudflare addresses | UDP/443 alive |
| C2 | REALITY route through `SideProber.SideProbe`, split **off**, one attempt, 12 s | REALITY as shipped |
| C3 | same with the split on: the pack's `_desync` offer, else `sni-cut`; if C2 and that failed, one more preset (`tlsrec-sni`, or `sni-cut` after a pack offer) | does the split change the outcome |
| C4 | Chrome's unmodified uTLS hello to relay:443, SNI = white name, `GET /` (h2 or HTTP/1.1), ≤ 32 KB / 8 s | claim 14, arm 1 |
| C5 | same, SNI = the route's own cover name | control |
| C6 | same, SNI = the list's neutral name | name-keyed vs address-keyed |
| C7 | up to two other TCP routes on the same relay address (other ports), via `SideProbe` | those ports |
| C8 | the relay's hysteria2/tuic route, via `SideProbe`, if side-probeable | UDP to our address |
| C9 | C2 again | did the test change anything |

Each side probe's split setting is handed to that one config build
(`engine.BuildSingBoxConfigWithDesync`); nothing remembered for a route
(`SetRouteDesync`) is touched, so a connect that races the test never
inherits a split the test was trying.

C1 (relay:80 `HEAD /`) is not run: with nothing on port 80 it is a
connect-and-reset, which the design rules out, and a `HEAD` with the
relay's address as `Host` is not a browser's request. Its id stays in the
schema. Connections to the relay are capped at 9 per run
(`MaxRelayFlows`; the full C2–C9 set would be 10).

Stage B probes connect only to an address inside the role's blocks
(`allow_nets`, below) and verify the server's chain for the name in the
hello against the device's roots. A chain that does not verify is
`cert_invalid`, and no HTTP request is sent to that host.

**C4–C6 and the cover forward.** REALITY hands a hello it does not own to
the cover site, so C4–C6 talk to the cover origin. A foreign name there
often gets an alert, a small 4xx or a close after the server's flight:
all of these prove the hello passed the path (`white_name_helps_on_relay_ip`
counts them as passed); only a reset, silence or stall is the path's
doing. Before relying on C4–C6, record a baseline from outside Iran when
signing the list (gap: not automated).

**Time reserve.** Past 150 s, whatever is left of Stage B is dropped and
the run goes to C2 (`short_circuit: true`, summary
`netTest.summary.incomplete`).

**Not measured in this build:** carry through the REALITY route (C2/C3 is
handshake + one far-side TLS handshake, the engine's connection proof);
`ProofConfig` has no byte target yet. C4–C6 measure carry on the relay's
address differentially.

### Signals (every TCP probe)

`connect_rtt` (the kernel's `tcpi_rtt` read right after connect on
Linux/Android — wall time around the dial includes the protect() hop to
the host; wall time elsewhere), whether the hello was ACKed
(`tcpi_unacked == 0` while `ESTABLISHED`, polled every 5 ms), time from
the hello write to the first event (bytes / RST / FIN / timeout), socket
bytes received, `handshake_end` (`ok | alert | rst | fin | timeout |
other`: how the handshake ended, apart from the first event),
`cert_valid` (Stage B), `hello_fp` (`chrome_auto` — uTLS Chrome
unmodified, what sing-box sends — for B6 and C4–C6; `chrome_auto_h1` —
ALPN http/1.1, no ALPS — only for B1–B5, which parse an HTTP/1.1 answer;
`go_std` for B7/B8). Side probes (C2/C3/C7–C9) carry no timing signals:
the side instance does not expose them (gap).

### Classification

| result | rule |
|---|---|
| `ok` | handshake completed (clean end) |
| `ok_carried` | handshake and ≥ 32 KB received |
| `reset_injected_likely` | RST as the first event after the hello, sooner than 0.6 × connect_rtt, connect_rtt ≥ 40 ms |
| `reset` | RST, timing not decisive |
| `closed` | FIN as the first event after the hello |
| `silent_drop_forward` | hello never ACKed until the handshake timeout |
| `silent_no_reply` | hello ACKed, zero bytes back |
| `flow_capped_suspected` | a stall or RST with < 16 KB received, either after a completed handshake on a carry probe (phase `carry`) or in the middle of the server's flight (first event bytes, `handshake_end` timeout/rst; phase `handshake`) — and **only when a control carried ≥ 32 KB on this network**: for C4–C6 another name to the same address, for Stage B another Stage B probe (B4, or B5 vs B6). Without one the stall is reported as itself (`timeout` / `reset`): a throttled link looks the same |
| `tls_alert` | a TLS alert record from the server, only |
| `closed` | FIN as the first event, or the server's flight then FIN / non-TLS bytes |
| `cert_invalid` | Stage B: handshake done, chain not valid for the name; nothing sent |
| `unreachable` | `ENETUNREACH` / `EHOSTUNREACH` on connect |
| `local_error` | the device refused the socket (protect(), a socket option); not tallied, not counted by any finding |
| `refused`, `timeout`, `auth_failed`, `skipped` | as named |
| DNS `bogon` | any A/AAAA in 10.10.34.0/24, RFC 1918, loopback, link-local, CGNAT, reserved |
| DNS `nxdomain`, `servfail`, `dns_timeout` | as named |
| DNS `type_dropped` | A answered, this type silent or empty where an answer is expected |
| DNS `answer_altered` | known-answer record present and not the expected value |
| DNS `dns_wrong_public` | an A answer that is public but outside the role's blocks (an Iranian resolver answering a foreign name with a domestic address): not used, the name is asked of `1.1.1.1` instead, held to the same blocks |

Side-probe outcomes follow the engine taxonomy
(`diagnostics.ClassifyObservation`); `relay_no_egress` counts as reached
(`ok`, phase `handshake`).

Timeouts: connect 6 s, handshake 8 s, carry 8 s, DNS 4 s, QUIC 6 s, side
probe 12 s. **No retries anywhere.**

## Budget and shape

Strictly sequential; 2–5 s jittered gap before steps of Stages A–B, 4–8 s
before Stage C; hard cap 30 TCP connections (side probes count), 4 QUIC
handshakes, 18 DNS questions; hard stop at 4 minutes. No port sweeps, no
bare SYN, no ICMP, no traceroute, no TTL tricks. At most five destination
addresses plus `1.1.1.1:53`. With Android Private DNS **strict** the phone
sends no cleartext DNS of its own, so the link-resolver questions
(A1–A5) are skipped; A6 (plain UDP/53 to `1.1.1.1`, named in the consent
text) still runs.

Every socket is offered to the host's `protect()` callback
(`engine.ProtectFD`, the callback sing-box's own sockets use) before it
connects.

## Target list

Compiled into the engine: `core/fieldprobe/targets-v2.json`; its version
and SHA-256 are in every report. The loader refuses `.ir` names, any entry
or list marked `domestic`, an address where a name belongs, any name under
Tor/Psiphon/Snowflake/Conjure/VPN-service infrastructure, a public resolver
other than `1.1.1.1:53` / `1.0.0.1:53`, unknown fields, relative paths.
Defaults the owner should confirm from outside Iran before the first real
run: the white name and its path (`hcaptcha.com`, `/1/api.js` — the
consent text must name its operator if it is not on Cloudflare), the
GitHub feed path, the neutral SNI for C6 (`github.com`), the ECH fallback
config (empty: B7 is skipped when A2 delivers none). `white_hints` is
empty: no address was invented.

`allow_nets` holds, per role (`google`, `github`, `cf_edge`,
`white_name`), the address blocks the operator announces; the loader
refuses a missing role, a block shorter than /8 (IPv4) or /19 (IPv6), and
any non-public block, and every `white_hints` entry must fall inside
`white_name`'s blocks. Current blocks: Google's own (not Cloud) ranges,
GitHub's web ranges, Cloudflare's published IPv4 list (also used for the
white name, on the assumption that `hcaptcha.com` is served from
Cloudflare). **Re-check all of them against the operators' published
lists when the list is re-signed**: an answer outside the blocks is
`dns_wrong_public` and its probe is skipped.

`resolver_recurses_foreign_zone` (A4) uses `github.com` / `google.com`
records, which every resolver has cached: it shows the record type
survives, not that the resolver recurses. A publisher-controlled zone is
needed to answer the question (gap).

A publisher-signed list carried in the Test pack is the next step;
`LoadTargets` is the function it will go through.

## Report — schema v2

`test-rigs/field-probe/schema/probe-report-v2.json`, Go twin
`bundle/go/fieldreport` (a test holds the two enum sets equal; the sample
`test-rigs/field-probe/sample-report-v2.json` validates). Everything v1
required is kept; `additionalProperties: false` throughout.

Privacy by construction: every string is a closed enum, a fixed-shape
token or the person's note. `variant` is `^[a-z0-9_+-]{0,40}$` — no dot,
no colon — so no name or address can appear even by mistake. `report_id`
is 26 random Crockford characters, **not** a ULID (a ULID encodes the
millisecond). Time is the hour bucket; duration is 60/120/180/240 s; RTT
and bytes are buckets. `relay_ref` is the first 8 hex of
SHA-256(relay_pack_id). The resolver appears only as its class
(`private | isp_public | well_known_public | unknown`).
`TestPrivacy_ReportCarriesNoAddressNameOrID` serialises a full run and
fails on any dotted quad, IPv6 shape, target name, relay address, cover
name, resolver, route id, pack id, path or minute.

`country_hint` is `IR` only when the person picked MCI, Irancell or
RighTel; otherwise `unknown`.

## Findings and summary

Findings questions: `reality_443_works`, `split_hello_helps`,
`white_name_helps_on_relay_ip`, `white_name_uncapped_on_cdn_ip`,
`grey_cap_seen_on_cdn_ip`, `reset_looks_injected`,
`cloudflare_edge_reachable`, `ech_passes`, `google_front_passes`,
`github_feed_fetchable`, `resolver_recurses_foreign_zone` (one per record
type, in `variant`), `dns_injection_on_path`, `quic_443_alive`,
`relay_alt_ports_open`, `test_changed_outcome`. A finding is emitted only
when a probe it rests on ran.

The summary shown before sending is a list of i18n keys
(`netTest.summary.*`, `core/fieldprobe/findings.go`), 2–8 lines, the
privacy line always last.

## Storage

One result is kept — a new run deletes any other — in the route store's
age-encrypted secrets table (`fieldprobe/result/<kind>`), with the report
address it will be sealed to; the run history behind the allowance under
`fieldprobe/history`. Both live in the state directory, so
`engine_panic_wipe` removes them. Results expire after 7 days (swept on
every status/seal call). Times at rest are kept to the hour (history
rounded up, results down). Sealed files written with `transient: true`
go in `<state_dir>/fieldprobe-out/` — the engine picks the folder; a path
from the page is ignored — so panic wipe takes them even if the process
died between the share and the discard. They are deleted by
`engine_field_probe_discard`, at engine shutdown, by the first
network-test call of the next process, and after an hour by status. The
Android FileProvider must expose that folder. A file the person saves, or
shares into a messenger, is outside the engine's reach from then on: the
send screen says so.

## Sealing and opening

See `specs/sealed-report-v1.md`. The key the app seals to is the
publisher's report address (`daal1…`), carried in the Test relay routes'
`family_specific_config._report_to` (signed with the pack; ignored by
builds that predate it). The publisher makes it with
`daal-deploy report-keygen --out <key>` (or `--out -`: the key comes back in
the JSON as `private_key_hex`, which is how the app makes it), signs the Test
relay's pack with `daal-deploy bind-and-sign … --report-to daal1…`, and opens
a file with
`daal-deploy report-open --in net-xxxxxxxx.dat --key <key> [--findings]`.

## ABI

`engine_field_probe_start / _status / _cancel / _seal / _discard`, see
`specs/engine-abi-v1.md` "Network test".

## Never tested

Tor, Snowflake, Psiphon, Conjure infrastructure; VPN ports; domestic
names or addresses; blocked social, news or political names; DoH/DoT
endpoints by connection; anything the person types.
