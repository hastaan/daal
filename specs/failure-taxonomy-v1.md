# Failure Taxonomy v1

## Status

Draft for V0 freeze. Locked enumeration; new categories require a spec revision.

**Revision 2** (this document) adds four categories — `udp_no_reply`,
`udp_address_blocked`, `udp_port_blocked`, `path_too_slow` — and two
sections, "Classification by phase" and "What one route can see". It
re-maps nothing: every category of revision 1 keeps its meaning and its
path-manager behaviour, and the error-string table in
`core/diagnostics/classify.go` is unchanged. See "Revision 2" below for
why each was needed.

**Revision 3** adds one category, `relay_no_egress`, and changes one
rule: `path_too_slow` can now also be the category of a connect that
FAILED — when the engine saw the path moving and nothing finished — and
stays what it was in every other respect (no cooldown, no failure
record, no network signal). See "Revision 3" below.

## Purpose

Every failure surfaced in diagnostics, every cooldown trigger, every "Why this route?" explanation refers back to this list.

## Categories

| Category | Meaning | Path-manager behavior | App-facing label |
|---|---|---|---|
| `dns_poisoned` | Resolver returned RFC1918 / known sinkhole / mismatched answer | Mark resolver suspect; switch to bundled DoT/DoH | "DNS appears blocked" |
| `dns_timeout` | Resolver did not respond in 5 s | Try alternate resolver; if all fail → `network_offline` | "DNS not responding" |
| `tcp_connect_timeout` | TCP SYN unanswered for 10 s | Cooldown route 5 min; try next in shortlist | "Connection timed out" |
| `tcp_reset` | RST mid-handshake | Cooldown route 30 min, family 5 min | "Connection blocked" |
| `tls_handshake_failed` | TLS error before app data | Try alternate transport family on same network | "Secure connection failed" |
| `tls_sni_or_cert_block_suspected` | TCP works, TLS resets immediately after ClientHello | Cooldown family 1 h on this network | "Encrypted connection blocked" |
| `udp_unavailable` | UDP probe to known echo target failed | Disable UDP-based families on this network for 2 h | "UDP not available on this network" |
| `quic_unavailable` | UDP works but QUIC handshake fails | Disable QUIC families specifically; keep raw UDP | "QUIC not available" |
| `udp_no_reply` | This route's UDP endpoint never answered. One observation: nothing is claimed about UDP anywhere else (rev. 2) | Cooldown route 5 min; **no** family or network-wide action | "No answer from this server" |
| `udp_address_blocked` | UDP toward this route's address is dropped while UDP to another host on the same port is delivered (rev. 2) | Cooldown route 30 min; the address is burned for UDP, the network is not | "This server's address is blocked" |
| `udp_port_blocked` | UDP on this route's port is dropped while UDP on another port is delivered (rev. 2) | Cooldown route 30 min; prefer UDP routes on another port | "This server's port is blocked" |
| `auth_failed` | Server reachable, credentials rejected | **No cooldown** — surface to UI | "Authentication failed — check credentials" |
| `route_expired` | `valid_until` passed | Disable route; offer refresh path | "Route expired" |
| `publisher_revoked` | Publisher key on revocation list | Mark all publisher's routes revoked; warn | "Provider revoked" |
| `publisher_key_changed` | Bundle signed by new key, no rotation chain | Block import; require user re-confirmation | "Provider key changed unexpectedly" |
| `subscription_unreachable` | Refresh URL not reachable | Use cached profiles; suggest tunneled refresh | "Cannot refresh subscription" |
| `engine_crash` | Engine reported error or died | Restart once; if persistent, fall back family | "Engine error" |
| `bundle_signature_invalid` | `.sbp` signature verification failed | Reject; never auto-retry | "Bundle signature invalid — do not import" |
| `bundle_corrupted` | Bundle parse error | Reject | "Bundle is corrupted" |
| `network_offline` | No network at all | Halt route attempts | "No internet connection" |
| `unknown` | None of the above match | No automatic action; surface raw diagnostic | "Unknown error — see details" |
| `path_too_slow` | The route connects and carries a round trip, but too slowly to be called usable. A **degraded** outcome, not a failure (rev. 2) | **No cooldown**, not a failure record; recorded as degraded and shown as such | "Connected, but very slow" |
| `relay_no_egress` | The relay completed its own handshake on a connection opened for the check, and no far-side host answered through it (rev. 3) | **No cooldown** of the route or its family; recorded on the route; not censorship-class; no network signal | "Reached the server, but the server itself cannot reach the internet" |
| `skipped_lifeline_strict` | Refresh attempt skipped because the engine is in `lifeline-strict` and the call is not user-triggered | None — recorded in audit ledger and dropped | not user-facing (audit-only) |

## Critical Rules

- `auth_failed` must never trigger censorship cooldown.
- Categories are not free-form strings; code must reference these constants.
- Adding a category requires a spec revision and either a fixture under
  `test-rigs/censor-lab/fixtures/failures/<category>/` or a worldbox
  scenario that declares it (`test-rigs/worldbox/scenarios/*.json`,
  `"category"`), whose raw differential probe reproduces it. The four
  revision-2 categories are covered the second way: `udp_address_blocked`
  by `relay-ip-block`, `udp_port_blocked` by `port-whitelist`,
  `path_too_slow` by `throttle-56k`, and `udp_no_reply` is what the engine
  reports in every scenario that blocks a UDP family.
- `path_too_slow` is not a failure of the route. It must never be
  written as one (`routestore.RecordFailure`), never start a cooldown,
  and never appear in `failures[]` of the diagnostics explanation; a
  route that connected slowly has its own list (`degraded[]`). A CONNECT
  can fail with it (rev. 3): then nothing is running and the connection
  check reads `failed` / `path_too_slow`, and the route's durable record
  is left exactly as it was.
- A timeout must never be read as a block while the engine has evidence
  the path was moving (rev. 3). In particular it is never
  `tls_handshake_failed`, and nothing derived from it may reach the
  publisher's rotation recommender as a name-keyed or address-keyed
  block.
- `relay_no_egress` must never cool down a route or count toward a
  family cooldown: every route to that relay shares the cause, and it is
  not on the network between the device and the relay.
- A network-wide category (`udp_unavailable`, `quic_unavailable`) must
  never be derived from one route's silence. See "What one route can
  see".

## Revision 2

The worldbox rig (`test-rigs/worldbox/FINDINGS.md`, CEN-2 and CEN-3)
declared, per censor scenario and family, which category describes what
the network really does, and had a raw probe check it. Three situations
had no word:

1. **UDP dropped toward one address.** A null-routed relay: UDP works to
   every other host. `udp_unavailable` is defined by a probe to a known
   echo target and disables every UDP family on the network for two hours
   — the wrong conclusion from one burned address — and
   `tcp_connect_timeout` is TCP by name. → `udp_address_blocked`.
2. **UDP dropped on one port.** A port whitelist: UDP/443 passes,
   UDP/8443 does not. Acting on `udp_unavailable` there disables a family
   that is carrying traffic on the open port in the same minute. →
   `udp_port_blocked`.
3. **Connects, and is too slow to use.** Every handshake completes; there
   is no failure to classify. → `path_too_slow`, a degraded outcome.

A fourth is the honest form of the first two as ONE ROUTE sees them: a
UDP route that hears nothing cannot tell a dead address from a dead port
from a network without UDP from a QUIC-only filter. → `udp_no_reply`.

`network_offline` ("no network at all") is likewise not observable from
a route's seat when the link is up and every packet is dropped: per route
that is `tcp_connect_timeout` / `udp_no_reply`, and only the aggregate
says "nothing works". No category was added for it.

## Revision 3

Two things the connection proof could see and had no way to say (backlog
TW-10 and TW-14; the end-to-end rig's observation CEN-O5).

1. **Slow is not silent.** Behind seconds of queue the proof's ordinary
   attempts finish nothing, and by revision 2's own rule ("a proof in
   which no attempt finishes is a failed connect, classified by phase")
   that was `tls_handshake_failed` or `unknown`, "could not connect", and
   5–30 minutes of cooldown on a route that connects ten seconds later.
   The rule stands where the engine saw nothing but silence. Where it
   saw the path MOVING — bytes back from the far side, a relay that took
   a second or more to answer a connection it did answer, a SYN answered
   that late — the proof makes one long attempt
   (`specs/engine-abi-v1.md`, "Slow is not silent"). A route that
   completes it is connected and degraded. One that does not has failed
   to connect with `path_too_slow`: the one category that says what was
   seen. → no new word; `path_too_slow` may now be the category of a
   failed connect.
2. **The relay answers and reaches nothing.** `carry` + no answer was
   `unknown` "on purpose", for want of a narrower word that would be
   true. With a connection to the relay opened for the check, one is:
   the relay completed its handshake a moment ago, and three far-side
   hosts run by three operators stayed silent through it. → 
   `relay_no_egress`. It is a statement about the relay, so it cools
   nothing down; it is what a relay whose provider has cut its outbound
   traffic looks like, and — indistinguishably, from one route — what a
   filter that lets a handshake through and swallows everything after it
   looks like. The user-facing sentence is the first; the second is why
   the category is recorded and not acted on.

The same fresh connection is what classifies a block that begins while a
route is connected ("Classification by phase", last paragraph).

Coverage: `path_too_slow` as a connect that needed the long attempt by
the worldbox scenario `deep-queue`; `relay_no_egress` by
`TestProveSubject_RelayThatReachesNothingIsRelayNoEgress` (the lab's
relay always has a way out; a scenario that removes it is not written).

## Classification by phase

An error string cannot carry where in the attempt a failure happened —
`i/o timeout` on a TCP socket is a dead address when the SYN went
unanswered and a swallowed ClientHello when the first read after it did —
so the engine classifies a failed connection proof
(`core/engine/proof.go`) from an *observation*: the phase the failure
happened in, whether the transport is UDP, whether the family's first
flight is a TLS ClientHello, and the kind of failure
(`core/diagnostics/observe.go`, `ClassifyObservation`). Failures that say
what they are (`auth_failed`, `network_offline`, `engine_crash`, …) keep
the category the string table gives them; where the observation settles
nothing, the string table decides, unchanged.

Phases: **reach** — opening the transport to the relay (the SYN; the
first datagram). **handshake** — the transport is open and the family's
own first flight is out; the relay has not answered it. **carry** — the
relay answered; the failure is in a round trip through it.

| Transport | Phase | What happened | Category |
|---|---|---|---|
| TCP | reach | SYN unanswered | `tcp_connect_timeout` |
| TCP | reach | SYN refused / reset | `tcp_reset` |
| TCP, TLS first flight | handshake | reset | `tls_sni_or_cert_block_suspected` |
| TCP, TLS first flight | handshake | no answer, or closed | `tls_handshake_failed` |
| TCP, opaque first flight | handshake | reset | `tcp_reset` |
| TCP | carry | reset | `tcp_reset` |
| TCP | carry | no answer, or closed | `unknown` |
| UDP | reach or handshake | no answer | `udp_no_reply` |
| UDP | carry | no answer, or closed | `unknown` |
| any | any | no answer, and the path was seen moving | `path_too_slow` (rev. 3) |
| any | carry, on a connection opened for the check | the relay's handshake completed; no answer from the far side | `relay_no_egress` (rev. 3) |

A timeout's phase is not taken from the error where the error cannot be
trusted to give it (a multiplexed outbound re-dials on the expired
context and reports a connect timeout for a connection whose SYN was
answered; a lazy outbound reports every timeout from the round trip). In
those cases the engine makes one bare TCP connect to the route's own
address and port — after the attempt has failed, never on a healthy
connect — and the phase is *reach* if that goes unanswered and
*handshake* if it is answered. It is made in those cases only. A timeout
whose phase the error does give (the carry phase of a family that dials
eagerly, which is how a liveness check usually fails) starts none: the
connect carries no payload, a failed route is checked again every
`recheck_interval_s`, and a connect-and-close to the relay's port at that
rhythm is a scanner's pattern, not the family's.

`carry` + no answer on the route's OWN outbound says nothing about the
relay: a family that multiplexes, pools sessions or rides one QUIC
connection hands over a stream from the session it already holds, so on
a route that has been connected for a while "the relay answered" is
minutes old. A block that began mid-session was therefore `unknown` on
exactly those families — most of them; only a family that dials per
connection named it. The engine now
asks once more on a connection it opens for the purpose (rev. 3) and
classifies by what THAT attempt saw, with the table above: the SYN
unanswered, the ClientHello swallowed or reset, the QUIC handshake
unheard. Where that connection's handshake completes and the far side is
still silent, the answer is `relay_no_egress`. What stays `unknown`:
`carry` + closed (a credential refused on a family that fails by closing
is not told apart from a relay that could not resolve a name), and
`carry` + no answer on a family whose dial does not include the relay's
answer.

## What one route can see

Several categories are statements about the NETWORK and need two
observations. The connection proof makes one. So the engine reports the
category that is true of what it saw, and never the narrower one it would
have to guess:

| The network does | Needs, to be told apart | One route reports |
|---|---|---|
| `udp_unavailable` | a UDP datagram to another host and port | `udp_no_reply` |
| `quic_unavailable` | a non-QUIC datagram to the same endpoint | `udp_no_reply` |
| `udp_address_blocked` | UDP to another host on the same port | `udp_no_reply` |
| `udp_port_blocked` | UDP on another port | `udp_no_reply` |
| `tcp_reset` keyed on the ADDRESS, on a TLS family | a ClientHello with another name to the same address | `tls_sni_or_cert_block_suspected` |
| `path_too_slow`, when a handshake still finishes quickly | a throughput measurement | nothing (`ok`) |

The second observation is the prober's job (the selection stage); until
it exists `udp_unavailable`, `quic_unavailable`, `udp_address_blocked` and
`udp_port_blocked` are produced by no engine code path, and
`tls_sni_or_cert_block_suspected` keeps the word "suspected" for exactly
this reason. `path_too_slow` is detected only by the proof itself taking
longer than the configured threshold — the whole proof, attempts that
failed included, in whatever phase they failed: on a capped path the
relay answers and the round trip through it still does not fit in one
attempt. A path fast enough for the whole proof to finish under the
threshold and too slow for a page is not detected (it is reported as
nothing, `ok`), and will not be until the engine counts bytes.

A proof in which NO attempt finishes is a failed connect. Where nothing
but silence was seen it is classified by phase like any other: a
handshake that is still crawling when the budget ends, on a path that
gave no sign of moving, is the same silence as one that was swallowed.
Where the path WAS seen moving the proof makes its one long attempt
first, and a connect that still does not finish fails as `path_too_slow`
(rev. 3) — never as a block.

What counts as "seen moving" is narrow on purpose, because it buys a
route twenty more seconds before "could not connect": bytes that came
back through the relay; a connection to the relay that completed, a
second or more after it was asked for; the relay's address answering a
bare SYN that late. A filter that swallows a ClientHello produces none
of these — the SYN before it is answered in milliseconds. Not covered: a
QUIC route whose handshake needs longer than one attempt shows nothing
(no TCP, no connection handed over) and is still `udp_no_reply`; that
needs the engine to count datagrams.

## Cross-References

- Censor lab: `specs/censor-lab-v1.md`.
- Field probe: `specs/field-probe-v1.md`.
- Bundle library error mapping: `bundle/go/bundle/errors.go`.
- Distribution channels (Phase 1.5C): `specs/failure-channels-v1.md`.
  The `subscription_unreachable` category is the per-attempt outcome
  produced by the rig's `subscription`, `revocation`, `directory`, and
  `ipfs` channels under StateDrop; it must NEVER cascade into
  `auth_failed` (rule `no_auth_failed_from_blackout` in the soak's
  invariant ledger).
- Per-family failure mapping (Phase 3A and later V3 sub-phases):
  every new transport family MUST map its handshake / runtime
  failure modes onto the categories above; no V3 sub-phase
  introduces a new category. WebTunnel's mapping is canonical
  in `specs/webtunnel-route-v1.md` "Failure category mapping"
  and serves as the template for 3B–3G.
- Snowflake's mapping (Phase 3B) lives in
  `specs/snowflake-route-v1.md` "Failure category mapping".
  Multi-channel rendezvous failures map onto the existing
  categories with NO new V0 category: an "all rendezvous
  channels failed" outcome surfaces as
  `tcp_connect_timeout` (the conservative aggregate) and is
  cosmetically annotated `rendezvous_unavailable` in
  diagnostics for operator legibility — the cooldown ledger
  uses the underlying V0 category. A future spec revision
  MAY promote the cosmetic annotation to a V0 category;
  3B does not.
- MASQUE's mapping (Phase 3C) lives in
  `specs/masque-ladder-v1.md` "Failure taxonomy". The three
  sub-mode failures map onto existing V0 categories with NO
  new V0 category at 3C:

  | Cosmetic surface          | V0 category             | When it fires                                                |
  |---------------------------|-------------------------|--------------------------------------------------------------|
  | `masque_h3_blocked`       | `udp_unavailable`       | h3_quic Dial fails because UDP is suppressed mid-session.    |
  | `masque_h2_blocked`       | `tls_handshake_failed`  | h2_connect Extended-CONNECT fails at TLS or HTTP/2 layer.    |
  | `masque_lifeline_blocked` | `tcp_reset`             | lifeline-rung TCP socket is reset by the censor.             |

  As with 3B, the cosmetic labels surface in the diagnostics
  ring buffer; the V0 category is what the path manager
  consumes for cooldown + trust state machinery.
- The Phase 3D refraction families (psiphon + conjure) map
  onto existing V0 categories with **no new V0 category at
  3D** (locked decision 6 in the 3D spec — cosmetic-only
  widening). Failure surfaces:

  | Cosmetic surface         | V0 category             | When it fires                                                                |
  |--------------------------|-------------------------|------------------------------------------------------------------------------|
  | `psiphon_handshake_fail` | `tls_handshake_failed`  | upstream psiphon-tunnel-core fails its protocol handshake.                  |
  | `psiphon_excluded`       | `route_unsupported`     | route activated on a build with `-tags no_psiphon` (vendor tree absent).    |
  | `conjure_register_fail`  | `tcp_connect_timeout`   | gotapdance fails to register the session through the decoy pool.            |
  | `conjure_phantom_drop`   | `tcp_reset`             | phantom-IP socket is reset by the censor or upstream after binding.         |

  As with 3B/3C, the cosmetic labels surface in the
  diagnostics ring buffer; the V0 category is what the path
  manager consumes for cooldown + trust state machinery.
- The Phase 3E WASM transport family maps onto existing V0
  categories with **no new V0 category at 3E** (locked
  decision 9 in the 3E spec — cosmetic-only widening).
  Failure surfaces:

  | Cosmetic surface              | V0 category             | When it fires                                                                |
  |-------------------------------|-------------------------|------------------------------------------------------------------------------|
  | `wasm_fuel_exhausted`         | `tcp_connect_timeout`   | the module's per-dial fuel budget (1e9 ops) is consumed before connecting.  |
  | `wasm_memory_cap`             | `tcp_connect_timeout`   | the wazero instance hits its 16 MiB memory cap.                              |
  | `wasm_dial_timeout`           | `tcp_connect_timeout`   | the host-side wall-clock dial timeout (5 s) fires.                           |
  | `wasm_host_callback_error`    | `tls_handshake_failed`  | the host-side `dial`/`read`/`write`/`close` callback returns an error.      |
  | `wasm_excluded`               | `route_unsupported`     | route activated on a build with `-tags no_wasm` (wazero compiled out).      |
  | `wasm_kill_switched`          | `route_unsupported`     | the module's sha256 is in the killed-set; refuses to load.                  |
  | `wasm_module_missing`         | `route_unsupported`     | the route's `transport_module_slug` is absent from the loaded bundle.       |

  The dial-outcome cosmetic surfaces (`wasm_fuel_exhausted`,
  `wasm_memory_cap`, `wasm_dial_timeout`,
  `wasm_host_callback_error`) match the closed-enum entries
  exposed in the `last_wasm_module_dial_outcome`
  diagnostic field; `wasm_kill_switched` and
  `wasm_module_missing` fire pre-dial and surface only as
  diagnostics ring-buffer entries.

  Locked at 3E: fuel exhaustion is NOT classified as a
  censorship signal. The route's `consecutive_failures`
  counter increments (the path manager treats it like any
  other `tcp_connect_timeout`), but `wasm_kill_switched_count`
  does NOT increment — a fuel-exhausted module is unloaded
  for the rest of the session, not project-killed.
