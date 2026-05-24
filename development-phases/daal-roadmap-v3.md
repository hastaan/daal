# Daal — Development Roadmap

*A bootstrap-resilient, signed-route-supply anti-censorship client for Iran (and analogous threat environments)*

**Version:** 3 · **Revised:** April 2026

> *Changes from v2:* Reframed V1.5 (embedded bootstrap material) to embed publisher keys and signed bootstrap-directory pointers rather than static route lists; the embedded artifact is now treated as extractable seed material, not steady-state capacity. Moved the lifeline *relay* (server-side component) from V2 to V3 by default; lifeline *mode* (local route-budget and selection policy) remains in V2. Locked telemetry as **Position B (no telemetry, ever)** in the baseline roadmap rather than as a CC.6-only recommendation; Position A is documented only for the record.
>
> *Changes from v1 (preserved here for traceability):* Added the five-module architecture frame. Expanded V0.2 with `Route` and `Publisher` runtime data structures and multi-format fingerprints. Added V0.3 failure taxonomy and V0.4 engine-control-boundary audit. Added "What not to build early." Strengthened calendar humility for small teams.

---

## North Star

The product is **not a new tunnel protocol**. The product is a **trustworthy, sustainable, abuse-resistant, scarcity-aware route-supply system**, exposed to end users as a small native client and to operators as a publishing toolchain. Protocols are interchangeable capacity underneath it; sing-box is the load-bearing engine; the durable contribution is the *route supply chain*: who produces a working access route, how it is signed, how it is distributed offline, how trust is communicated, how scarce capacity is rationed, and how compromised publishers and burned endpoints are retired without losing users.

Every phase below is judged against one question: **does the user still have working access when Telegram, GitHub, app stores, and their subscription URL are all blocked simultaneously?** If a feature does not move that needle, it belongs in the research track, not the production path.

---

## Phase map at a glance

| Phase | Codename | Calendar | Primary deliverable | Gate to next phase |
|---|---|---|---|---|
| V0 | *Foundations* | Months 0–2 | Threat model, wire-format specs, publisher protocol, test rigs, build/sign infra | Specs frozen; reference vectors published; CI green |
| V1 | *Bootstrap MVP (Android)* | Months 2–7 | Android client + signed `.sbp` bundles + offline sharing + embedded pool + first publisher | A user with no working subscription receives a route from a friend offline and is online in under 60 seconds |
| V1.5 | *Reliability hardening* | Months 7–10 | Subscription refresh, revocation, key rotation, desktop port, diagnostics | Client survives a 7-day Telegram+GitHub+CDN blackout in a lab simulation |
| V2 | *Survivability engine* | Months 10–15 | Route budgets, mode budgets, cooldown, per-network memory, iOS, lifeline mode | Bootstrap pool is not burned by user load over a 30-day soak test; iOS in TestFlight |
| V3 | *Ecosystem integrations* | Months 15–22 | WebTunnel, Snowflake-like relays, MASQUE ladder, Conjure/Psiphon hooks, WASM transport slot, optional partner-operated lifeline relay | New transport family ships as a signed module without an app update |
| V4+ | *Research & sustainability* | Continuous | UPGen-class transports, refraction partnerships, governance maturity | N/A |

Total runway to V3 ship: **~22 months for a full-time team of 4–6 engineers + 1 designer + 0.5 ops + 0.5 PM**.

Smaller teams scale roughly linearly *up to a point*: a 2-person execution doubles the calendar (~44 months) but loses non-trivial features (the second mobile platform takes longer than 2× a single platform because the tooling overhead doesn't halve). A solo execution will not finish V2 in any reasonable time and should explicitly drop iOS, drop the lifeline relay, drop the publisher portal, and target only V1 + V1.5 in roughly 12–18 months. **Be honest with yourselves about this in V0.5 (build-vs-contribute decision); the right answer for a 1–2 person team is almost certainly the toolkit-only Path C, integrated into Hiddify and NekoBox rather than a new client.**

---

## Module architecture (the five modules)

Every phase deliverable below maps to one of five modules. Naming them up front prevents the architecture from drifting phase-by-phase and makes ownership in a multi-engineer team possible.

**Module 1 — Distribution.** Everything that gets routes, code, trust lists, revocation lists, and emergency messages from the project (or a publisher) onto the user's device, especially when normal channels fail. Owns: app update channels (Play, F-Droid, direct APK, AltStore, MSI/DMG/AppImage); the bundle directory and its mirrors; QR import/export; animated/fountain QR; file import; clipboard auto-detect; LAN mDNS share; Bluetooth/Nearby/Multipeer where available; revocation distribution; emergency-message channel. The defining property of Module 1 is that *no two distribution channels share a single failure point*: UI updates, engine updates, route updates, trust-list updates, and emergency messages each have at least two independent paths.

**Module 2 — Config & Trust.** Everything between "blob of bytes claiming to be a route" and "validated, scarcity-tagged, provenance-marked entry in the route database." Owns: parsers for every input format (sing-box JSON, Clash YAML, vless/vmess/trojan/ss/hy2/tuic URIs, base64-multiline subscriptions, SIP008, WireGuard `.conf`, AmneziaWG, Tor bridge lines, `.sbp` archives); Ed25519 signature verification; publisher key pinning (TOFU); fingerprint display in multiple formats; trust-state transitions (`trusted` → `tofu` → `unknown` → `expired` → `revoked` → `changed_key`); route-expiry handling; per-route provenance tracking. **The trust score and the network score live here as separate fields**: a route can be trusted-but-failing or fast-but-untrusted, and the UI must never silently mix them.

**Module 3 — Network Diagnosis.** Local-only network probing and failure classification. Owns: DNS resolution test, TCP/443 reachability, HTTP/80 reachability, UDP probe, subscription-URL reachability, route-family failure aggregation, blackout-state inference (`normal` / `degraded` / `blackout-like`). The hard rule: this module never inspects user content, never logs visited domains, never records exact timestamps finer than the hour bucket. Its outputs feed the path manager (Module 4) and the user-facing "Why this route?" panel.

**Module 4 — Path Manager.** The deterministic state machine that decides which route to use right now. Owns: shortlist racing; stability-first scoring; trust-aware route choice; per-network local memory; route cooldown (per-route, per-publisher, per-route-family, per-network); route budgets (per-scarcity-class hourly/session caps); mode selection (lifeline/normal/bulk); the "Why did the app choose this?" explanation. **No machine learning, no opaque scoring.** State transitions are documented and visible.

**Module 5 — Transport Engine.** The protocol stack itself: sing-box (Go) plus the vendored extras (Psiphon, Cloak, obfs4, eventually Snowflake), platform bridges (gomobile bind for Android, XCFramework for iOS, sidecar for Tauri desktop), and the engine ABI through which Modules 1–4 talk to it. Research transports live here behind feature flags. **The engine ABI surface is small and stable** (≤15 functions, frozen at end of V0); UI iteration must never force engine ABI changes.

The modules are not delivered as five separate phases. V1 ships a minimal version of each; V1.5 hardens 1, 2, and 5; V2 fills out 3 and 4; V3 expands 5. But every V0 spec deliverable is owned by exactly one module, and CI gates are organized by module to keep ownership clear.

---

# Phase V0 — Foundations (Months 0–2)

V0 produces no end-user binary. Its outputs are specifications, reference implementations of cryptographic primitives, test fixtures, governance documents, and the publisher protocol. Skipping V0 to "just start coding" guarantees that V1's bundle format will be wrong and need to be re-rolled, which costs more than V0 itself.

## V0.1 — Threat model document

A 20–40 page internal document describing, for each of four explicit user classes, what the adversary can see, what the adversary will do, and what the app must and must not do.

**User classes (lock these in V0; everything downstream depends on them):**

1. *Ordinary user* — wants social media, news, app updates. Adversary risk: low. Acceptable defaults: route auto-import, opt-in to (V3+ partner-operated) lifeline relay if available, no telemetry (none exists; see CC.6).
2. *Blackout/lifeline user* — wants to know if a relative is alive during a shutdown. Adversary risk: low–medium. Acceptable defaults: aggressive offline modes, store-and-forward, low-bandwidth bias.
3. *Activist/journalist* — wants source protection and stronger anonymity. Adversary risk: high. Defaults: WebTunnel/Tor route preference, no lifeline relay (relay sees fetched URLs), warning banners on shared/unknown publishers, automatic route cooldown more aggressive.
4. *High-risk / device-seizure target* — wants minimal local trace and forensic resistance. Adversary risk: extreme. Defaults: no plaintext profile cache, optional PIN-locked profile vault, panic-wipe, no logs ever, no lifeline mode.

The mode is selected by the user in onboarding; the app's defaults, warnings, and engine-control flags vary by class. **No silent same-treatment-for-all.**

**Adversary capabilities to enumerate** (each gets a bullet list of mitigations downstream):

- TIC-level protocol allowlist (DNS/HTTP/HTTPS only on 53/80/443)
- SNI-based RST injection on TLS ClientHello
- DNS poisoning to RFC1918 sinkholes (10.10.34.34/.35/.36)
- TLS-in-TLS burst-pattern detection (Xue et al. 2024)
- Active probing of Shadowsocks-like flows
- BGP-intact "stealth blackout" with service-class denial (June 2025 model)
- Endpoint enumeration of well-known free pools
- Telegram channel takedowns
- App Store geo-removal
- ZTE/Huawei DPI gear (per ARTICLE 19 *Tightening the Net*)
- Provincial/operator divergence (MCI vs Irancell vs fixed-line)
- AmneziaWG H1–H4 / S1–S4 specific signature deployment

**Privacy invariants** (these are constitutional — every later phase tests against them):

- The control plane never collects browsing destinations.
- The control plane never collects exact user IP, exact location, contact graph, or persistent identifier.
- All learning is local-first. **No telemetry of any kind leaves the device** (locked at V0; see CC.6).
- Bundle imports do not implicitly trust new publishers; TOFU with a clearly visible, human-readable fingerprint is required.
- A stolen device must not yield route subscriptions in plaintext (V2+ requirement; V1 documents the gap).

**Deliverable:** `docs/threat-model-v1.md` reviewed and signed off by at least one external reviewer with measurement-research credentials (OONI, Citizen Lab, Censored Planet, Tor Project — pick one and pay for review time).

## V0.2 — Wire-format and runtime-object specifications

Five normative specs, each with reference test vectors. The first three define data formats that travel between users and machines; the last two define the runtime objects each client maintains.

**Spec A — `.sbp` (Signed Bundle Package) format.**

```
bundle.sbp = ZIP archive containing:
  manifest.json       — bundle metadata (publisher, version, expiry, route count, capacity class hint)
  manifest.sig        — Ed25519 signature over canonical-JSON-encoded manifest
  publisher.pub       — Ed25519 publisher public key (32 bytes, hex)
  profiles/           — directory of sing-box JSON outbound configs, one per file
  trust/              — optional: cross-signing chain for publisher key rotation
  revocation.json     — optional: list of revoked profile/publisher fingerprints
```

`manifest.json` schema (frozen in V0):

```json
{
  "spec_version": 1,
  "publisher": {
    "name": "Example Publisher",
    "key_fingerprint_hex": "a3f2...",
    "key_fingerprint_en": "river-village-strong-promise",
    "key_fingerprint_fa": "رود-روستا-محکم-وعده",
    "key_fingerprint_visual": "data:image/svg+xml;base64,...",
    "key_created_at": "2026-01-15T00:00:00Z",
    "trust_class": "official|provider|community|unknown"
  },
  "bundle": {
    "id": "uuid",
    "type": "provider|friend_share|emergency|revocation|trust_update",
    "created_at": "2026-04-25T12:00:00Z",
    "expires_at": "2026-05-25T12:00:00Z",
    "previous_bundle_id": "uuid|null",
    "supersedes_keys": ["fingerprint-a", "fingerprint-b"]
  },
  "routes": [
    {
      "id": "route-uuid",
      "scarcity_class": "emergency|low|normal|bulk-capable|lifeline-only",
      "transport_family": "vless-reality|hysteria2|webtunnel|...",
      "config_path": "profiles/route-uuid.json",
      "valid_from": "...",
      "valid_until": "..."
    }
  ]
}
```

**Spec B — Publisher key model.**

- Ed25519 long-term identity key (publisher root).
- Optional sub-keys with limited validity (1–4 weeks) signed by the root, used to sign individual bundles. This is what makes "the laptop with the publishing key got seized" survivable.
- Trust class is **declared** by publisher, **verified** by Daal's official directory of recognized publishers (V1.5+), and **finally adjudicated** by the user's own TOFU pin.

**Multi-format fingerprint** (this is the user-facing identity primitive, so it deserves a paragraph of its own). A 64-hex-char SHA-256 is unmemorable; pure-English BIP-39 assumes literacy in a language many target users don't have. Therefore every fingerprint is rendered in three formats simultaneously, and the user picks which to verify against:

1. **English BIP-39, four words.** First 44 bits of SHA-256 → four words from the standard 2048-word BIP-39 English list. Memorable, pronounceable, voice-relayable: *"river-village-strong-promise"*.
2. **Persian wordlist, four words.** Same 44 bits → four words from a curated 2048-word Persian wordlist. **The wordlist must be designed in V0**, not borrowed: BIP-39 has no official Persian list, and the unofficial ones in circulation have homophone collisions when relayed by voice. Pay a Persian-speaking lexicographer for two weeks of work in V0; this is cheap insurance.
3. **Short visual checksum.** A deterministically-rendered 5×5 colored-square SVG (the "identicon" pattern, but with a fixed palette so deuteranopia/protanopia/tritanopia don't collapse adjacent fingerprints to identity). Used when one user holds up a phone and another compares visually across a noisy room.

The full hex is shown only on a "details" affordance; ordinary users never see it.

**Spec C — Internal route representation.**

Every input format parses into a normalized **sing-box outbound JSON** plus a thin Daal metadata wrapper carrying scarcity class, provenance, publisher key fingerprint, expiry, and route family tag. Sing-box JSON is canonical because it expresses every required transport natively; nothing else does.

**Spec D — `Route` runtime object** (the in-memory and on-disk representation each client maintains):

```jsonc
{
  "route_id": "local-uuid",                    // never leaves the device
  "transport_family": "vless-reality | naive | websocket-tls | hysteria2 |
                       tuic | snowflake | webtunnel | masque | shadowsocks |
                       tor-bridge | other",
  "engine": "sing-box | tor | psiphon | external",
  "source_type": "official_bootstrap | trusted_provider | friend_shared |
                  manual | subscription | experimental",
  "publisher_id": "ed25519-key-fingerprint-hex",
  "publisher_label": "Provider's chosen display name",
  "trust_state": "trusted | tofu | unknown | expired | revoked | changed_key",
  "scarcity_class": "emergency | low | normal | bulk-capable |
                     experimental | lifeline-only",
  "modes_allowed": ["lifeline", "normal"],     // subset of {lifeline, normal, bulk}
  "expires_at": "iso-8601",
  "imported_at": "iso-8601",
  "last_success_bucket": "2026-04-25T14:00Z",  // hour-bucketed
  "last_failure_bucket": "2026-04-25T13:00Z",  // hour-bucketed
  "last_failure_category": "see V0.3 taxonomy",
  "consecutive_failures": 0,
  "cooldown_until": "iso-8601 | null",
  "bytes_used_this_hour": 0,                   // for budget enforcement
  "bytes_used_this_session": 0,
  "user_note": "optional, never leaves device"
}
```

Note what's *not* there: no full subscription URL after import (it lives encrypted at rest in a separate key-value store that only the engine reads); no list of destinations the route has been used for; no exact timestamps. The Route object is what the path manager and UI see; it is deliberately a smaller surface than the underlying secrets.

**Spec E — `Publisher` runtime object** (one row per publisher the user has ever encountered):

```jsonc
{
  "publisher_id": "ed25519-fingerprint-hex",
  "display_name": "Provider or friend name",
  "trust_level": "official | trusted_provider | tofu_friend |
                  unknown | revoked",
  "first_seen": "iso-8601",
  "last_seen_bundle": "iso-8601",
  "key_status": "active | rotated | compromised | revoked",
  "rotation_chain": ["prev-fingerprint-1", "prev-fingerprint-2"],
  "revocation_sources": ["official-list", "provider-list", "user-action"],
  "user_assigned_label": "optional human note"
}
```

Trust transitions (trust_level changes, key_status changes, rotation events) are append-only logged in a local audit table so the user can answer "wait, when did I trust this publisher?" months later.

**Deliverable:** `specs/sbp-v1.md`, `specs/publisher-keys-v1.md`, `specs/route-internal-v1.md`, `specs/route-object-v1.md`, `specs/publisher-object-v1.md`, the curated Persian wordlist, plus `specs/test-vectors/` containing 30+ valid and invalid bundles for parser testing and 50+ Route/Publisher object lifecycle scenarios for state-machine testing.

## V0.3 — Failure taxonomy

A locked enumeration of failure categories. Every failure that surfaces in the diagnostics UI, every cooldown trigger, every "Why did the app choose this route?" explanation refers back to this list. Add categories only by spec revision; never by code-side ad-hoc.

| Category | Meaning | Path-manager behavior | User-visible label (English) |
|---|---|---|---|
| `dns_poisoned` | Resolver returned RFC1918 / known-sinkhole / mismatched answer | Mark resolver suspect; switch to bundled DoT/DoH | "DNS appears blocked" |
| `dns_timeout` | Resolver did not respond in 5 s | Try alternate resolver; if all fail → `network_offline` | "DNS not responding" |
| `tcp_connect_timeout` | TCP SYN unanswered for 10 s | Cooldown route 5 min; try next in shortlist | "Connection timed out" |
| `tcp_reset` | RST mid-handshake | High suspicion of SNI/IP block; cooldown route 30 min, family 5 min | "Connection blocked" |
| `tls_handshake_failed` | TLS error before app data | Try alternate transport family on same network | "Secure connection failed" |
| `tls_sni_or_cert_block_suspected` | Heuristic: TCP works, TLS resets immediately after ClientHello | Cooldown family 1 h on this network | "Encrypted connection blocked" |
| `udp_unavailable` | UDP probe to known echo target failed | Disable UDP-based families on this network for 2 h | "UDP not available on this network" |
| `quic_unavailable` | UDP works but QUIC handshake fails | Disable QUIC families specifically; keep raw UDP available | "QUIC not available" |
| `auth_failed` | Server reachable, credentials rejected | **No cooldown** (user error, not censorship); surface to UI | "Authentication failed — check credentials" |
| `route_expired` | `valid_until` passed | Disable route; offer refresh path | "Route expired" |
| `publisher_revoked` | Publisher key on revocation list | Mark all publisher's routes revoked; surface warning | "Provider revoked" |
| `publisher_key_changed` | Bundle signed by new key, no rotation chain | Block import; require user re-confirmation | "Provider key changed unexpectedly" |
| `subscription_unreachable` | Refresh URL not reachable | Use cached profiles; suggest tunneled refresh | "Cannot refresh subscription" |
| `engine_crash` | sing-box reported error or process died | Restart engine once; if persistent, fall back family | "Engine error" |
| `bundle_signature_invalid` | `.sbp` signature verification failed | Reject bundle; log; never auto-retry | "Bundle signature invalid — do not import" |
| `bundle_corrupted` | Bundle parse error | Reject bundle | "Bundle is corrupted" |
| `network_offline` | No network at all | Halt route attempts | "No internet connection" |
| `unknown` | None of the above match | No automatic action; surface raw diagnostic | "Unknown error — see details" |

**Critical: `auth_failed` is treated entirely differently from all censorship-class failures.** Conflating them produces a vicious loop where a user with a wrong password silently exhausts their bootstrap pool. The path manager's first rule is "never cool down a route on an `auth_failed`."

**Deliverable:** `specs/failure-taxonomy-v1.md`, plus a fixture set in `specs/test-vectors/failures/` simulating each category for the diagnostics rig.

## V0.4 — Engine-control boundary audit

Before V1 begins, run a sharp audit of what sing-box (and any planned secondary engine) can actually expose. The audit's job is to discover whether the missing work is "just write a UI on top of sing-box" or "first add a sing-box plugin layer for things sing-box doesn't natively expose."

For each Module 4 (Path Manager) requirement, the audit answers yes/no/partial:

| Required engine capability | Sing-box exposes natively? | If no, the work item |
|---|---|---|
| Start/stop a specific outbound by ID | Yes | — |
| Tag an outbound with route-family / provenance metadata that round-trips through stats | **No** | Add a Daal metadata wrapper passed alongside outbound config |
| Query per-outbound bytes-in/bytes-out without exposing destinations | Partial (stats API leaks more than we want) | Wrap stats API; redact destination-side fields |
| Receive structured failure reasons (not just stringly-typed log lines) | Partial | Add a structured event channel |
| Per-route soft-pause without removing config | **No** | Implement at the Daal wrapper layer |
| Per-route byte-budget enforcement (drop new connections after threshold) | **No** | Daal-side rate limiter ahead of the dialer |
| Per-mode routing rules (lifeline mode → lifeline-only routes only) | Partial via routing rules | Generate sing-box rules from Daal mode state |
| Network-change notification (Wi-Fi → mobile) | Partial | Platform bridge handles this; engine resets affected routes |
| Inject a UDP probe and report result without starting a route | **No** | Add a probe utility outbound |

Every "No" is a V0/V1 work item, owned by the Module 5 engineer, scheduled before the platform UI work that depends on it. The audit's bottom-line deliverable is a single document — `docs/engine-gap-analysis-v1.md` — that is the gating input to V1.1's engine packaging plan.

**This is the single most under-rated V0 deliverable.** Skipping it means V2's route-budget engine and cooldown FSM discover, four months in, that sing-box won't tell them what they need to know.

## V0.5 — Build-vs-contribute decision (the V1 fork)

Before V1 starts, an explicit team decision, recorded in writing, between three paths:

- **Path A — Greenfield Daal client.** Maximum control, maximum effort, slowest user adoption.
- **Path B — Hiddify/sing-box upstream contribution.** Land bundle-format support, publisher trust UI, scarcity tagging, and a route-budget engine API as PRs to existing clients. Fastest path to real users, but you are at the mercy of upstream review and you don't control the UX of trust labels — which is the core differentiator.
- **Path C — Toolkit + reference client.** Ship the publisher tooling, the bundle libraries (Go + Rust + Swift + Kotlin), and a minimal reference Android client. Hiddify, NekoBox, v2rayNG, FoXray, and Streisand can all integrate the libraries on their own timelines. This is the highest-leverage but slowest-to-payoff option.

**Recommendation:** **Path C, with the toolkit and the reference client built together as a single coordinated effort.** This is a small but important reframe of v1's "Path C with Path A as a test bed" wording — the reference client is not a test bed, it is a first-class deliverable, because the trust UX and the offline-share UX are the project's actual differentiators and existing clients will not implement them correctly out of the box. The toolkit (libraries, bundle format, publisher CLI, engine ABI) is what lets Hiddify, NekoBox, v2rayNG, FoXray, and Streisand integrate over the following 12–24 months. The reference client is what lets ordinary users get the full Daal experience on day one without waiting for upstream.

The expert analysis converges on this framing — "Build the missing bootstrap/trust layer first; decide later whether it should live inside an existing client or become a new client" — except that "decide later" should be "do both, but design the toolkit so others can adopt it." The roadmap below assumes this dual-track Path C; if a smaller team picks toolkit-only (no reference client), the V1 schedule shrinks but iOS, Tauri desktop, and the polished onboarding flow disappear.

## V0.6 — Engineering infrastructure

Boring but load-bearing:

- **Monorepo layout.** Separate `core/` (Go, sing-box vendored + Daal plugins), `bundle/` (libraries, one per language), `client-android/`, `client-ios/`, `client-desktop/` (Tauri 2 + React + Rust), `publisher/` (CLI + web admin), `specs/`, `docs/`.
- **Reproducible builds.** Hermetic builds with locked toolchain versions. Bazel or Nix; pick one and stick with it. Reproducibility matters here because users sideload binaries and need to be able to verify them against a third party's rebuild.
- **Code-signing pipeline.** Hardware-token-protected signing keys (YubiHSM 2 or equivalent). Signing happens on an air-gapped host or, at minimum, a dedicated build machine with no developer SSH access. **This must exist before V1 ships any binary**; retrofitting it after the first compromised release is too late.
- **Symbol/binary archives.** Every release ships with `.dSYM` / debug symbols stored privately, plus a public SBOM (CycloneDX). Crash reports and CVE response depend on this.
- **CI matrix.** Linux/macOS/Windows runners, Android NDK r26+, Xcode 16+, Go 1.23+, Rust 1.80+. Every PR runs the spec test vectors.
- **Translations infrastructure.** Weblate or Transifex from day one. Persian (Farsi) is mandatory; Arabic, Russian, Mandarin, Turkish, Tigrinya, Burmese are likely future. Strings get IDs, never inline.

## V0.7 — Test rigs

Three rigs, each automatable:

- **DPI emulation rig.** A Docker-Compose stack with one client container, one censor container running modified `nDPI` + custom rules emulating GFW FET classifier, Iran SNI-RST, and AmneziaWG fingerprinting, and one server container. Used in CI to gate transport regressions. Build this from open-source pieces — `gfwprobe`, OONI's heuristics engine, the IRBlock methodology — but fork and lock versions; upstream changes will break tests.
- **Network-condition rig.** `tc netem` + custom UDP-drop / SNI-RST plugins to simulate MCI/Irancell/fixed-line latency profiles, IPv6 disabled, partial UDP drops, and 200–500 ms RTTs to common Iranian destinations.
- **Distribution-failure rig.** Simulates blocked Telegram, blocked GitHub, blocked CDNs. The lifeline tests run against this.

**Deliverable for V0 (the gate to V1):** seven specs frozen (threat model, `.sbp`, publisher keys, Route object, Publisher object, failure taxonomy, engine-control gap analysis); the Persian wordlist commissioned and reviewed; multi-format fingerprint rendering implemented in `bundle-go` and at least one client-side language port; CI green on all test vectors; the three rigs running and reproducing at least one known censor failure mode each. **No code that touches a real user's device until this gate clears.**

---

# Phase V1 — Bootstrap MVP (Android), Months 2–7

V1 ships a real Android client, the publisher CLI, and the first official bootstrap directory (with embedded keys, directory pointers, and a small set of seed routes per V1.5). **Android first** because: (a) Iran's app distribution is dominated by direct APK sideload, (b) `VpnService` has no memory ceiling and no Apple sanctions issue, (c) F-Droid gives an OSS distribution channel, and (d) iteration speed on Android is 5–10× faster than iOS.

## V1.1 — Core engine packaging (Months 2–3)

- Vendor sing-box at a frozen tag. Use `gomobile bind -target=android` to produce `libbox.aar`. Build tags trim out unused transports for size: drop V2Ray stats API, drop HTTP3 if not needed yet, keep VLESS+Reality, Hysteria2, Trojan, Shadowsocks-2022, WireGuard, Tor+obfs4, ShadowTLS.
- Hand-write a flat C ABI of ≤15 functions (`engine_start`, `engine_stop`, `engine_stats`, `engine_set_route`, `engine_event_callback`, `engine_set_route_budget`, `engine_set_mode`, `engine_cooldown`, `engine_health_probe`, `engine_logs_subscribe`, `engine_export_diagnostics`, `engine_version`). The ABI is documented in `specs/engine-abi-v1.md`. **Stability of this ABI is a contract**: V1.5 may add functions, never break them.
- The engine layer also vendors `psiphon-tunnel-core`, `cbeuw/Cloak`, and `yawning/obfs4` as Go imports. Snowflake is held for V3.
- Target binary size: ≤25 MB AAR including all `.so`s for arm64-v8a. If it's larger, audit transports.

## V1.2 — Bundle library (Month 3)

A pure-Go reference implementation of `.sbp` parsing, signing, and verification, with thin wrappers for each platform:

- `bundle-go` — canonical reference. Signs and verifies. Round-trips test vectors.
- `bundle-rs` — Rust port for Tauri desktop and the publisher web admin. Cross-checked against `bundle-go` byte-for-byte on every test vector.
- `bundle-swift` — Apple. Uses CryptoKit Ed25519.
- `bundle-kotlin` — Android. Uses BouncyCastle or Tink.
- `bundle-ts` — TypeScript port for any future webview-side validation. Defensive only; never the source of truth.

All five MUST agree on every test vector. This is checked in CI.

## V1.3 — Android client (Months 3–6)

Stack: Kotlin + Jetpack Compose + Hilt (DI) + SQLDelight (local DB) + Coroutines/Flow.

**Screens (UX-driven, not feature-driven):**

1. *Onboarding* — three-screen flow: choose user class (the four V0 classes, with plain-language explanations), set device PIN (mandatory for high-risk class, optional otherwise), grant VPN permission.
2. *Home* — one big "Connect" button. Below it: current route name, trust badge (Official / Trusted Provider / Friend-Shared / Unknown / Expired), connection state, simple traffic counter. **No protocol names by default.** A "details" affordance reveals the family.
3. *Routes* — list of routes grouped by trust class. Each row: route name, trust badge, scarcity class icon, last-tested status, last-used timestamp, "share" / "delete" actions.
4. *Add route* — five tabs:
   - Paste a link (clipboard auto-detect on screen open, with explicit confirmation)
   - Scan QR (static)
   - Scan animated QR (fountain-coded, see V1.5)
   - Receive over LAN (mDNS browse + 6-digit PIN)
   - Import file (system file picker; accepts `.sbp`, `.json`, `.yaml`, `.conf`, `.txt`)
5. *Share routes* — symmetric to "Add route." Generates a QR for a single route or an `.sbp` for many. Shows the trust label that the recipient will see.
6. *Diagnostics* — local-only. Shows: "DNS resolves: yes/no", "TCP/443 reachable: yes/no", "UDP probe: failed", "Last subscription refresh: 2 days ago", "Routes tested in last 24h: 7 of 12 working." No timestamps more precise than the hour. No counts of sites visited.
7. *Settings* — emergency pool toggle (allow/disallow use of embedded seed routes), lifeline mode toggle (V2-gated), language, privacy panic-wipe. **Note: no telemetry toggle exists, because there is no telemetry. See CC.6.**

**Trust UI is the single most important element of V1.** A friend-shared bundle from a publisher whose key the user has never seen MUST NOT silently install. The user sees:

> "This bundle was signed by **river-village-strong-promise**. You haven't trusted this publisher before. Do you recognize them?"
>
> [ I trust this publisher ]   [ Just for this one bundle ]   [ Cancel ]

The 4-word fingerprint is BIP-39 wordlist-derived, so it is memorable and pronounceable in voice, which matters when one Iranian relays it by phone.

**VpnService implementation:** Single-instance foreground service, `IBinder` IPC to UI, persistent notification, Android 14 foreground-service-type compliance (`specialUse` with declared use case "vpn"). The Go engine runs in the same process as the service (not the app) to keep the UI process lean.

**APK targets (ship from V1):**
- arm64-v8a: ≤45 MB
- armv7: ≤40 MB
- universal: avoid; Iranian users on metered plans care about every megabyte
- minSdk 24 (Android 7.0). Below that, modern crypto and `VpnService` features are absent.

## V1.4 — Offline sharing (Month 5–6)

**Static QR.** Encodes a single sing-box URI or a short HTTPS subscription URL. Version 20 QR holds ~900 bytes, which fits any single VLESS-Reality URL with room to spare.

**Animated fountain QR.** For payloads up to ~10 KB (a small `.sbp` bundle with a single route). Implementation: port `divan/txqr` Luby Transport codec into the Go engine, exposed via cgo to Android/iOS UI. 8–12 FPS, ~256 bytes per frame, receive any 1.05× of frames to decode. Test on cheap Android phones with poor cameras — many users in Iran use 5+ year old devices with mediocre optics, and frame-rate is the failure mode.

**LAN sharing.** mDNS-advertise `_daalshare._tcp.local.` from the sender. Sender spins up an HTTPS server on a random high port with a fresh self-signed cert. PIN exchange (sender shows 6 digits, receiver types). Receiver pulls the bundle, verifies signature, shows trust prompt. Code reuse from LocalSend's protocol is high; do not reinvent.

**Clipboard.** On app foreground, scan clipboard for known URI schemes (vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, base64-of-multi-line, https://-with-known-suffixes). On match, show "Found a route in your clipboard: import?" — never auto-import.

**File import.** Register intent filters for `.json`, `.yaml`, `.conf`, `.txt`, `.sbp`. System Share Sheet integration.

**USB / portable.** Documented manual flow only in V1: user plugs phone into desktop, copies an `.sbp` file from `Downloads/`, opens it in the app via file import. V2 adds a desktop-side "send to phone" affordance.

## V1.5 — Embedded bootstrap material (Month 6)

**This is the most operationally sensitive piece of V1.** Get it wrong and the project burns its first reputational hit. Read this section as a list of constraints, not features.

The single most important framing change from earlier drafts: **what gets embedded in the app binary is not a list of working routes. It is the cryptographic and topological material the client needs to *find* working routes once it has any network at all.** A static route list embedded in the APK is an enumerable artifact — once the app is popular enough to matter, every adversary has the same APK and can extract the same list. Build for that assumption.

The embedded artifact is therefore tiered:

**Tier 1 — Durable, embed in every build:**
- The project root signing key (Ed25519 public key).
- 3–5 official publisher root keys (project-operated and partner-operated bootstrap publishers).
- A signed bootstrap-directory pointer: a list of 6–10 URLs (across multiple domains, multiple TLDs, multiple CDNs, including IPFS gateways and at least one onion service) where the client can fetch the *current* bootstrap directory after first network reachability.
- A signed *fallback* directory pointer: the same idea, but addresses to fall back on if the primary set is blocked. Typically uses different ASNs and different TLD operators.

These are tiny (a few KB total), durable, and not directly burnable by extraction — extracting a list of public keys does not give the adversary anything they could not already learn from the project's website. The cost of "the embedded keys are public knowledge" is zero; that is what public keys are for.

**Tier 2 — Disposable seed routes, embed sparingly and short-lived:**
- 3–8 minimal route entries (not 20–30) — just enough to win the race for "first network connection of a fresh install" if all the directory pointers are blocked.
- Each entry has `valid_until` ≤30 days from app build (not 60–90).
- Each entry has `scarcity_class: emergency` and the path manager refuses to use it for more than ~30 minutes total per device.
- These exist only to bridge the gap to fetching a real bootstrap directory. They are expected to be burned within weeks of any release that gains traction — and that is fine, because by then the directory pointers should have served the client a fresh, signed directory.

**Tier 3 — Fetched on first network, signed by Tier 1 keys:**
- The actual current bootstrap-directory of 30–100 routes across transport families, fetched from one of the Tier 1 directory pointers.
- Refreshed every 24–72 hours over any working tunnel.
- Rotated server-side at the project's discretion; clients never need an app update to receive a new directory.

This shifts the threat model in an important way. An adversary who reverse-engineers the APK gets:
- The public keys (no value; already public).
- The directory pointer URLs (value: can block them, but the *fallback* directory pointers are by design diverse enough to make full blocking expensive).
- A handful of short-lived seed routes (value: ~30 days, then irrelevant).

What they do not get is the steady-state route inventory, which is fetched on demand, signed, and rotated.

**Bootstrap UX flow:**
1. First launch → no user routes, no fetched directory → use Tier 2 seeds to race a connection (parallel, max 5 concurrent attempts, 8 s timeout).
2. As soon as anything is up, fetch the signed bootstrap directory through the tunnel using a Tier 1 directory pointer. Verify the directory's signature against an embedded Tier 1 key.
3. On success, replace the Tier 2 seeds in the active pool with the Tier 3 directory contents. Tier 2 seeds remain as a fallback only.
4. Land the user on a built-in welcome page: *"You are connected via the shared emergency pool. This is rate-limited and shared. Import a real subscription for full speed: [paste link] [scan QR] [receive from friend]."*

**Per-user budget (V1):**
- 100 MB cumulative on emergency-class routes per device per 24 hours; UI nags at 80 MB.
- At 200 MB the emergency pool is paused for the day, with a clear "import a real route to continue" prompt.
- This applies whether the route came from Tier 2 seeds or Tier 3 directory.

**No background traffic on emergency routes.** When connected via emergency, the app additionally warns if it sees high-volume traffic (>5 MB/min) sustained on an emergency-class route.

**Honest labeling.** The trust badge on an emergency-class route is permanently visible while connected: *"Connected via shared emergency pool — limited capacity."* The user is never confused about what kind of route they are using.

The expert analysis is right that "embedded bootstrap can become the first thing the censor burns." The countermeasures are not "make the embedded pool bigger or more clever" but: keep the embedded *route* surface tiny and short-lived; embed *keys* and *directory pointers* instead; refresh the actual route inventory through any working tunnel; and ensure the UX always pushes the user *off* the emergency pool and toward a real subscription within minutes of first launch.

## V1.6 — Publisher CLI (Month 4–5)

`daal-publish` — a Go binary that:

- Generates Ed25519 publisher root keys, with hardware-token attestation if available (`daal-publish keygen --hsm`).
- Issues sub-keys: `daal-publish subkey --root key.pub --validity 14d`.
- Builds bundles: `daal-publish bundle --manifest manifest.json --profiles ./profiles/ --sign-with subkey.priv -o out.sbp`.
- Signs revocation lists: `daal-publish revoke --bundle-id <uuid> --reason "compromised endpoint"`.
- Verifies bundles: `daal-publish verify out.sbp`.

The CLI is what providers, diaspora groups, and emergency operators use. Its UX matters more than people typically think — bad publisher tooling produces unsigned bundles, which produces user trust prompts that everyone clicks through, which makes the trust system useless.

## V1.7 — First publisher and pilot

Before V1.0 ships:

- Stand up the project's own first publisher (call it `daal-bootstrap`).
- Stand up a second publisher run by a partner organization (an existing diaspora group, a university research lab, a press-freedom NGO). This proves the protocol is not single-party and exercises every code path that depends on a foreign key.
- Run a 4-week closed pilot with 100–500 users, mostly diaspora and trusted in-country contacts, before public release.

## V1 success metric (the gate to V1.5)

> An Iranian user with no working subscription, no Telegram access, and no GitHub access, who has Daal installed, can receive a route from a friend over QR or LAN and be online within 60 seconds. The friend's bundle was published 30 minutes earlier from a publisher the user has never seen, and the user is shown the publisher's 4-word fingerprint and chooses to trust it.

If this scenario does not pass end-to-end on the test rig, V1 is not done.

## V1 risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Bundle format wrong, requires breaking change | M | Spec freeze + 30+ test vectors before any client implementation begins |
| Embedded seed routes burn within ~30 days of release reaching adversaries | H (assumed) | Tier 2 seeds are explicitly designed to be expendable; Tier 1 keys + directory pointers are what carry the user past expiry; refresh path operational by V1.5 |
| Embedded directory pointers all blocked simultaneously | M | Tier 1 includes diverse ASNs, TLDs, IPFS, and onion fallbacks; "all blocked at once" requires the censor to coordinate across domains they don't all control |
| Signing key compromise on dev laptop | M | HSM/YubiHSM from day one; sub-keys with short validity |
| Publisher CLI misuse produces unsigned bundles | M | CLI refuses unsigned output by default; `--unsigned` flag exists only for development |
| Trust prompt ignored ("user clicks Trust on everything") | H | UX testing with non-technical users in V1.7 pilot; iterate copy 3+ times |
| Apple/Google removes the project's published bundle directories | H | Bundle directories are static signed files served from multiple mirrors and IPFS; V1.5 adds offline distribution paths |

---

# Phase V1.5 — Reliability hardening (Months 7–10)

V1.5 makes V1 actually survivable across blackouts longer than a few days. It also opens the desktop port and lays the groundwork for iOS.

## V1.5.1 — Subscription refresh through tunnel

When the user's subscription URL is blocked but a tunnel is up, refresh attempts go *through* the tunnel. This is non-trivial because:

- The refresh must not leak the subscription URL outside the tunnel (it leaks the user's provider).
- A failing tunnel must not poison the cache; previous good profiles persist.
- Refresh interval is hint from `profile-update-interval` response header, clamped to [1h, 7d].

Implementation: a thin HTTP client in the engine layer that uses the active outbound for the refresh request. Cache-write is atomic; bad responses don't replace good cached profiles.

## V1.5.2 — Revocation and key rotation

- Publishers issue `revocation.json` files signed by the root, listing revoked profile IDs and revoked sub-keys with reasons.
- Clients fetch revocation lists from a configurable list of mirrors (project mirror, IPFS gateway, partner-NGO mirror) at most once per 6 hours, opportunistically over the active tunnel.
- A revoked profile is greyed out in the UI with an explanation: "Provider revoked: server compromised."
- Key rotation: a publisher's new root key is signed by the old root for one transition window, then the old key is published as revoked. The "trust this publisher" relationship survives the rotation; the user is *informed* of the rotation, not re-prompted.

## V1.5.3 — Diagnostics expansion

A "Why did the app choose this route?" affordance, audit-trail style:

> "Used route 'Provider-Reality-7' because:
> - It was your last working route on this network type.
> - 'Provider-Reality-3' was demoted (4 consecutive failures in last 2 hours).
> - UDP routes were skipped (UDP probe failed at 14:30).
> - You have not enabled experimental routes."

This is the expert analysis's "auditable, predictable selector" requirement made concrete. It also doubles as a debugging tool for the team and a measurement tool for users to report nuanced failures.

## V1.5.4 — Desktop port (Tauri 2)

Stack: Rust backend (Tauri 2.x), React + TypeScript + Tailwind frontend, sing-box as a sidecar binary spawned by the Tauri Rust process and driven over the Clash-compatible REST API.

- Windows: WinTUN driver, NSIS installer, MSI for enterprise, portable ZIP. Code-signed with EV cert. **Plan for SmartScreen reputation building** — three months minimum to establish.
- macOS: Universal `.app`, Developer-ID signed, notarized, System Extension for the packet tunnel. DMG distribution.
- Linux: AppImage (~25 MB), `.deb`, `.rpm`. setcap-helper for `/dev/net/tun` access; GUI runs unprivileged. **Avoid Flatpak/Snap** — known TUN portal issues bite VPN apps.

The Rust backend reuses `bundle-rs`. The frontend reuses no UI code from Android (different platform conventions, different interaction model) but reuses **all view-model logic** specified in language-neutral form in V0.

Desktop ships as a separate V1.5 milestone, not bundled with the Android update.

## V1.5.5 — Bootstrap-directory operations and pointer rotation

V1 already fetches the active route directory through the Tier 1 directory pointers. V1.5 adds the operational machinery around it:

- **Pointer rotation.** The set of embedded directory pointer URLs is itself signed and re-fetched by the client. When a pointer is blocked or burned, the project signs a new pointer set and clients pick it up over any working tunnel. This is what makes "the censor blocked our primary directory URL" survivable without an app update.
- **Per-publisher bootstrap directories.** Trusted partner publishers can run their own signed directories, distinguished by trust class. A client may end up with multiple active directories (one project-operated, one or two partner-operated); their contents merge in the route database with provenance preserved.
- **Directory expiry and rollover.** Each fetched directory has its own short expiry (24–72 h). Clients refresh opportunistically; if all refresh attempts fail for >7 days, the UI surfaces "Bootstrap directory has not refreshed — your routes may be stale."
- **Diagnostic clarity.** When a directory fetch fails, the failure is classified per V0.3 taxonomy (`subscription_unreachable` for the directory URL, `bundle_signature_invalid` for tampering, `dns_poisoned` for upstream interference). The user-visible message distinguishes "we can't reach the directory" from "the directory we reached doesn't verify."

## V1.5 success metric

> The lab simulates: Telegram blocked, GitHub blocked, the user's subscription URL blocked, the project's main domain blocked. After this state begins, an existing Daal installation **continues to work for 30 days** by automatically refreshing routes through the active tunnel, falling back to alternate mirrors for the bootstrap directory, and surfacing clear UX when human intervention is needed (e.g., "Subscription dead — import a friend's bundle").

---

# Phase V2 — Survivability engine (Months 10–15)

V2 is where "session ecology" becomes real, route scarcity is enforced, and iOS finally ships. It also introduces local-only lifeline mode (the partner-operated relay form is deferred to V3).

## V2.1 — Route budget engine (Months 10–11)

Every route carries a `scarcity_class`. The engine layer enforces:

| Class | Per-hour cap | Per-session cap | Allowed modes |
|---|---|---|---|
| `emergency` (bootstrap) | 50 MB | 200 MB | lifeline only |
| `lifeline-only` | 100 MB | 500 MB | lifeline only |
| `low` (friend-shared) | 500 MB | 2 GB | lifeline, normal |
| `normal` (provider) | 5 GB | unlimited | lifeline, normal |
| `bulk-capable` | unlimited | unlimited | all |

When a cap is approached, the path manager either rotates to a fresh route (if available in the same family) or surfaces UX: "This route is rate-limited. Switch to bulk mode? (uses a paid subscription if available)"

Caps are advisory at the engine layer (sing-box doesn't natively know about them); enforced by a Daal middleware that counts bytes through each outbound and triggers route rotation. **The new engine ABI function `engine_set_route_budget` lands here**.

## V2.2 — Mode budget UI

Three explicit modes:
- **Lifeline** — small text, news, search, messaging. No video, no large downloads. Routes per-class capped tighter.
- **Normal** — full browsing. Default for ordinary users.
- **Bulk** — explicit opt-in, only on bulk-capable routes. Required for video streaming.

Mode is a UI-level toggle that translates to engine-level budget adjustment. The app suggests a mode change ("Your bootstrap route is rate-limited — try Lifeline mode?") but never silently switches.

## V2.3 — Cooldown state machine

Instead of "AI selector," a deterministic FSM, exactly as specified by the expert analysis:

```
States: NoRoute, BootstrapDiscovery, ImportedActive, SharedActive,
        Recovery, Lifeline, OfflineSharing, Experimental
```

**Transitions are documented** and visible to the user via the Diagnostics screen. No machine learning. No black box. A failing route family enters `cooldown` with an exponential backoff (5min, 15min, 1h, 4h, 24h, capped). The user sees: "VLESS-Reality routes are cooling down — last failure: 12 minutes ago. Trying Hysteria2 routes."

## V2.4 — Per-network memory

A small SQLite store of:
- Coarse network ID (Wi-Fi SSID hash *or* mobile carrier name + bucket — never raw SSID, never full carrier+plan).
- Route-family-level success/failure counts per network.
- UDP probe result per network.
- DNS poisoning indicator per network.

When the user moves between networks, the path manager reads the memory: "On 'mci-mobile-evening' the last 5 attempts on UDP failed; start with TCP/443 routes."

The store is **encrypted at rest** with a key derived from the device PIN (high-risk class) or a device-bound key (other classes). Panic-wipe in Settings deletes it.

## V2.5 — Lifeline mode (local policy only — relay deferred to V3)

Lifeline mode in V2 is **purely local**: a user-selectable mode flag that changes how the path manager and route-budget engine behave. It is not a server-side relay, and shipping it does not require any new infrastructure.

When the user selects Lifeline mode, the client:

- Tightens route-budget caps by ~3× across all scarcity classes (e.g., a `normal`-class route's hourly cap drops from 5 GB to ~1.5 GB).
- Biases route selection toward stability over speed (prefer routes whose recent failure rate on this network is lowest, even if their measured throughput is lower).
- Refuses to use `bulk-capable` routes for general traffic; reserves them for explicit user opt-in per session.
- Disables background refresh of large content (subscription refresh still runs, but only when actively triggered or when an existing subscription is approaching expiry).
- Surfaces a permanent banner: *"Lifeline mode: bandwidth is conserved and bulk traffic is restricted. Switch to Normal for full apps and video."*

This is most of what users actually need from "lifeline mode" during a partial blackout: their messaging works, news and search work, scarce routes are not burned by an Instagram session in the background. **No relay is involved; nothing leaves the device differently from Normal mode except for budget enforcement and route choice.**

The remote-fetch *relay* (a server-side component that fetches and strips public web content for the client at very low bandwidth) was originally scoped for V2 in earlier drafts. It is deferred to V3 by default for three reasons:

1. **It competes with V2's actually-essential work.** V2's success metric is route-budget correctness, cooldown FSM correctness, per-network memory, and iOS rollout. Adding a server-side relay with its own threat model, abuse-handling, and partner negotiation drains attention from those four.
2. **It introduces the largest privacy surface in the entire system.** A relay that sees the user's requested URLs is a single point of compromise; deferring its design until V3 lets the project stabilize the rest of the architecture and threat model first.
3. **The local-only lifeline mode delivers most of the user value.** A user on a degraded MCI evening connection who switches to local Lifeline mode gets working messaging, news, and search through their existing routes, with their scarce routes protected. The relay only adds value when even those routes can't carry standard HTTPS — a smaller failure mode than the V2 baseline addresses.

V3.7 (below) covers the optional relay design when and if a partner is ready to operate it. V2 ships without it, and the project is honest with users about what Lifeline mode does and does not do.

## V2.6 — iOS rollout

The constrained-target plan:

- **Bundle identifiers and entitlements decided in V0.6** survive third-party re-signing (AltStore, Sideloadly). Verify in V2 by actually re-signing a build through AltStore and confirming the Network Extension still works. Hiddify's discussion #1135 is the warning.
- **NEPacketTunnelProvider** target statically links the `Libbox.xcframework` produced by `gomobile bind`. Build tags trim to a 25–30 MB iOS Go core (drop unused transports, drop GeoIP city DB if not needed, lazy-load GeoSite).
- **WireGuard sub-engine.** If the NE process exceeds the ~50 MB ceiling under load, split WireGuard out to `boringtun` (Rust, ~1.5 MB) and load it conditionally. This is the Cloudflare WARP playbook.
- **Distribution:**
  - App Store via foreign legal entity (foundation, NGO, partner). Apple may region-restrict; assume so.
  - TestFlight (10k user cap, 90-day expiry — managed as a continuous re-issue pipeline).
  - Personal Apple ID self-signing instructions in docs (7-day re-sign, fine for activists, miserable for general public).
- **The political problem is not technical.** Document mitigations; do not promise stability.

iOS releases at the **end** of V2, not the beginning, because all the engine-level work (route budgets, cooldown, per-network memory) lands first on Android and gets battle-tested before being constrained into the iOS NE memory budget.

## V2 success metric

> Over a 30-day soak test in the lab simulating 1,000 concurrent users on an emergency-pool directory of ~50 routes (refreshed every 48 hours through a working tunnel), no route is burned (defined as: classifier-detected and dropped by the simulated DPI) faster than the directory's natural rotation cadence. The path manager rotates routes correctly, enforces budgets, and surfaces understandable failure reasons. iOS TestFlight build is live, re-sign-survivable, and re-distributable through AltStore.

---

# Phase V3 — Ecosystem integrations (Months 15–22)

V3 expands transport coverage and integrates with adjacent ecosystems. **Critically, V3 does not change the V1/V2 user experience** — new transports arrive as new route families that the path manager learns to use.

## V3.1 — WebTunnel-style routes (Months 15–16)

Tor's WebTunnel is the strongest current answer to protocol-allowlist environments. Integration:

- Vendor `webtunnel` PT support into the engine layer.
- Add a publisher tooling story for operators who want to run a WebTunnel bridge: `daal-publish webtunnel-bridge` generates the secret path, valid CA cert verification helper, and Tor `bridge` line.
- A single bundle can carry mixed VLESS + WebTunnel + Hysteria2 routes; the path manager treats WebTunnel as a TCP/443 family.
- **Note:** WebTunnel currently does not work in Iran (TLS fingerprint filtering). Either ship it as opt-in for users in regions where it works, or wait for upstream Tor Project mitigations. **Do not promise it works in Iran in V3 if it does not.**

## V3.2 — Snowflake-like ephemeral relays

The most architecturally interesting V3 piece. Two separable parts:

- **Snowflake direct integration.** Vendor `snowflake/client` Go library. Uses WebRTC + DTLS + SCTP DataChannel. A Daal route of family `snowflake` rendezvouses through the broker (domain-fronted or AMP-cache or SQS, as per upstream).
- **Multi-rendezvous design.** Daal-specific contribution: a small library that abstracts "rendezvous channel" so Snowflake-style ephemeral relays can be discovered through:
  - Domain-fronted broker (where fronting works)
  - SQS / AMP-cache (per the FOCI 2024 paper)
  - Push notification (FCM/APNS for diaspora-operated relays)
  - Offline-bundled rendezvous hints (fresh bundle includes broker URL + signed key)

This converts "the Snowflake broker is blocked" from a fatal failure to a degraded mode.

## V3.3 — MASQUE ladder

Per RFC 9298 (UDP over HTTP) and RFC 9484 (IP over HTTP). Implementation:

- HTTP/3 over QUIC where UDP works.
- HTTP/2 Extended CONNECT fallback when UDP fails.
- Lifeline mode at the bottom rung.

The path manager treats MASQUE as a single transport family with three sub-modes; the engine selects based on per-network UDP probe results. MASQUE is opportunistic, never required.

## V3.4 — Psiphon / Conjure / refraction hooks

- Vendor `psiphon-tunnel-core` deeply enough that a Psiphon bundle (signed by a Psiphon publisher key) can be used end-to-end through Daal's UI. This is the most direct way to get refraction-class capacity into the system without running a refraction backbone yourself.
- Conjure phantom-IPv6 decoy support: same library, opt-in route family.
- The strategic point: **Daal does not run refraction infrastructure; it consumes it**. Pursue partnerships with Merit Network / University of Colorado Boulder / Psiphon-the-org for capacity sharing.

## V3.5 — WASM transport slot (research → production gating)

A signed WASM module slot in the engine, conformant with WATER (Operator Foundation's WASM Anti-Censorship Transport spec). Modules are:
- Distributed as signed `.sbp` bundles with a new `transport_module` route type.
- Loaded into the engine via a `wasmtime` runtime hosted by the Go core.
- Enabled only for the Experimental route family in user UI.
- Gated by a kill-switch the project can flip remotely (signed delta over the bootstrap directory).

This is the "we shipped a new transport without an app update" feature. **Critical caveat:** in Iran's allowlist phases, "novel encrypted protocol the censor doesn't recognize" may simply be dropped. WASM transports are useful for iterating known-good HTTPS-shaped transports, not for inventing new shapes. Default to conservative.

## V3.6 — One-tap "send working routes"

Cosmetic but high-value: in the Routes screen, a "Share working routes with a friend" affordance that:

- Asks how the friend will receive (QR, LAN, file).
- Filters to routes the user owns (not friend-shared, not bootstrap).
- Builds an `.sbp` signed by the user's *delegate key* (a sub-key of the original publisher's key, where allowed by publisher policy). For routes the user is not allowed to redistribute, the option is greyed out with explanation.
- Tracks (locally) how many people the user shared with — surfaces "you've shared this route with 5 people; the publisher caps it at 10."

This is what turns "the friend asked me for routes over WhatsApp" into a structured, signed, trust-preserving action.

## V3.7 — Optional partner-operated lifeline relay (only if a partner is ready)

The remote-fetch lifeline relay was deferred from V2 because it introduces privacy and operational concerns that compete with V2's core deliverables. V3 revisits it — but only if a credible partner organization is prepared to operate it under the constraints below. **If no partner is ready, the relay simply does not ship; Daal continues to function fully without it.**

The relay is a small server (or set of servers) that accepts requests from authenticated Daal clients in Lifeline mode and returns stripped, compressed Reader-mode HTML for whitelisted public URLs. It exists for the narrow case where a user's regular tunnels are unavailable but a tiny amount of traffic can still reach a known relay endpoint.

Hard constraints (any single one not met = relay does not ship):

- **Operated by a partner, not the project.** Liability and abuse-handling reasons. The project provides the protocol and client integration; the partner provides the operational entity, the legal exposure, and the abuse response.
- **Default off.** User opts in.
- **Disabled for the high-risk user class.** Hard-coded, not togglable.
- **Public-content only.** Whitelisted URL patterns: news domains, public search engines, public Wikipedia, public AI endpoints, public academic sites. Refuses login pages, social-media post-creation endpoints, banking, personal email, and any URL containing query parameters that look like credentials or tokens.
- **No accounts.** No cookies persisted across requests. Each user's session uses a fresh ephemeral key.
- **Permanent operator-visibility banner in the UI.** *"Lifeline relay can see what public pages you request. Do not use it for sensitive activity. Switch to VPN mode for private browsing."*
- **No relay-side logging beyond rate limits and abuse counters.** Audited by the partner operator and, ideally, a third party.
- **Strip + compress.** The relay returns Reader-mode HTML, gzipped; on a 30–50 kb/s connection a news article opens in seconds.
- **Documented kill-switch.** The project can disable the relay client-side via signed configuration delta, in case of compromise.

The relay's threat model is publishable as a separate document at the time of launch and forms the basis of an external audit before public release.

This is the right scope for V3 — small, optional, partner-driven, not entangled with the rest of the architecture. If a partner doesn't materialize through V3 and V4, the feature simply remains undelivered, and Lifeline *mode* (V2.5) continues to provide most of the user-facing value through purely local route policy.

## V3 success metric

> A new transport family ships to all platforms via a signed `.sbp` bundle without an app update. iOS, Android, and desktop pick it up within 24 hours of publication, gated behind the Experimental flag. Existing trust UI works correctly for the new family. No regression on V1/V2 metrics.

---

# Phase V4+ — Continuous research and sustainability

V4 is not a phase; it is a posture. After V3, the codebase is mature and the work pivots toward sustainability and selective research.

## V4 candidate workstreams (parallel, not sequential)

**a. Refraction / Conjure deployment partnership.** Multi-quarter operations work. Find a US backbone university willing to run a Conjure station; integrate as a high-trust, high-capacity route family. Funding-dependent.

**b. Publisher economics.** Help publishers run sustainably: payment intake (Iranian rials, USDT, Mastercard for diaspora), abuse-reporting tools, automated endpoint retirement, capacity reporting. A publisher portal at `publish.daal-project.org` with all of `daal-publish` exposed as a web UI.

**c. Adversarial reverse engineering watch.** Hire (or partner with) a researcher whose job is to monitor Iranian DPI updates: subscribe to net4people/bbs, monitor academic publications, track AmneziaWG version updates, watch for new TLS fingerprints. Triage cycle: detection → reproduction in the test rig → engine fix → release within 72 hours of confirmed in-the-wild blocking.

**d. UPGen-style experiments (China-relevant, weak Iran fit).** A research track for users in PRC where the threat model is FET-classifier-driven rather than allowlist-driven. Output: a separate "advanced transports" channel, not the Iran default.

**e. Mesh / Bluetooth / Nearby.** Same-OS mesh route sharing (iOS MultipeerConnectivity, Android Nearby). Cross-OS Bluetooth is unreliable; do not promise it. Useful in protest contexts where cellular is shut down but groups of people are physically together.

**f. Decoupled UI updates from engine updates.** Already implicit in the architecture; V4 makes it explicit by allowing the UI to ship through F-Droid and direct-APK with monthly cadence while the engine ships with quarterly cadence and emergency hot-fix capability.

**g. Localization expansion.** Beyond Persian and English: Russian (Roskomnadzor users), Mandarin (PRC fork users), Burmese (Myanmar), Tigrinya (Eritrea), Arabic. Each needs in-country UX review.

**h. Formal verification of the bundle parser.** Memory-safe Rust port of `bundle-go` (already exists), plus a property-based test suite proving that no malformed bundle can crash the parser, leak memory, or trigger a timing side-channel that distinguishes "wrong signature" from "well-formed signature, wrong key."

**i. Hardware-token integration for high-risk users.** YubiKey 5C NFC for unlocking the route vault on Android (NFC tap to unlock).

**j. Government-of-foreign-country relations.** Diplomatic and policy advocacy is not engineering, but it touches App Store availability and donor funding. Pair with an existing organization (Open Tech Fund, Article 19, Access Now).

---

# Cross-cutting concerns

These do not fit a phase but bind every phase together.

## CC.1 — Security audits

- **End of V1:** External audit of the bundle format, parser implementations, and signing pipeline by a qualified firm (Trail of Bits, Cure53, NCC Group). Budget: $30k–$80k.
- **End of V2:** Audit of the full client (Android first, iOS as a follow-on), focused on: NE memory safety, key-storage at rest, panic-wipe correctness, DNS leakage, IPv6 leakage.
- **Continuous:** Public bug bounty starting V1.5. HackerOne or self-hosted; budget for non-trivial payouts ($500–$10k tiers).

## CC.2 — Reproducible builds and SBOM

- Reproducible builds at every release. Document the toolchain pin, publish hashes, allow third-party reproduction. **This is non-negotiable for an anti-censorship tool**: users sideload binaries and need to verify them.
- CycloneDX SBOM published per release. Helps users in regions with import restrictions audit dependencies.

## CC.3 — Funding model

The honest funding sources for an anti-censorship tool in 2026:
- **Open Technology Fund** (USAGM-funded; awards 1–3 year grants).
- **NLnet** (Next Generation Internet funding from EU; smaller awards).
- **Mozilla MOSS** / **Reset Tech** / **Internet Freedom Festival grants**.
- **Foundation partnerships** (Article 19, Access Now, Citizen Lab).
- **Diaspora donor channels** (paid subscription overlay where the user contributes to the operator's costs).

Do not depend on a single source. Three years of runway is the minimum for serious adoption.

## CC.4 — Operational security for the team

- All publishing keys live on hardware tokens.
- All build infrastructure isolated from developer machines.
- Two-person rule on releases (one signs, one verifies).
- The team's own communication uses Signal with mandatory 2FA; project repositories are mirrored across at least three providers (GitHub, Codeberg, self-hosted Gitea).
- Threat model the team itself: a state actor wants to ship a backdoored release. Reproducible builds + two-person sign + delayed publication mitigate. Document the procedure.

## CC.5 — Localization, accessibility, UX research

- **Persian (Farsi) at GA.** RTL layout, Persian numerals optionally, localized error messages. Budget for at least 40 hours of native-speaker UX review per major release.
- **Accessibility:** TalkBack on Android, VoiceOver on iOS, NVDA/JAWS on Windows. Many lifeline-mode users are older or have low literacy; the UX must be readable at a 6th-grade level in Persian.
- **In-country UX research is operationally hard** but essential. Partner with a diaspora research team or an NGO with secure communication channels. Recruit 5–10 representative users per release.

## CC.6 — Telemetry: there is none

**The baseline decision: Daal does not collect telemetry.** No opt-in toggle. No "anonymous usage statistics." No phone-home. The client emits no analytics under any condition; the code path does not exist in the binary.

The constants:
- No browsing data, ever.
- No exact location, no contact graph, no persistent user ID, no route-secret leakage in any error report.
- No connection-success rates, no route-family success rates, no per-network statistics — even k-anonymized — leave the device.
- Crash reports, if any: handled by an opt-in upload of a pre-redacted, locally-reviewable report file that the user can inspect before sending. No automatic upload. No third-party crash reporter SDK that ships data to a vendor.

Measurement of *whether the app works in the field* is sourced entirely from independent third parties:

- **OONI.** The project funds and supports OONI probe coverage in target geographies, integrates OONI test results into the threat-model update cycle, and treats OONI's published data as the canonical public source of "is the app actually working in Iran today."
- **Censored Planet.** Same posture.
- **IRBlock and successor measurement papers.** Treated as input to engineering work; the measurement community publishes data the project deliberately cannot collect itself, and that asymmetry is *the point* — it keeps user-side data outside the project's data perimeter.
- **Partner research labs.** Where a research lab can run measurements under their own ethical review board, the project provides build artifacts and answers methodology questions, but takes no telemetry input from the lab.

The cost of this posture is real: slower iteration on which transports work where, no in-product A/B experimentation, no dashboard showing the project's own deployment health. The benefit is real too: the app is a closed black box that emits only the user's actual traffic. There is no telemetry endpoint to compromise, no aggregated dataset to subpoena, no "anonymized" data whose anonymization can be re-examined and broken.

**For the record, Position A (opt-in, k-anonymized telemetry) was considered and rejected.** Both positions are defensible in theory; for an anti-censorship tool used in a state-adversary environment the asymmetry is too one-sided. Reversing the decision later would sound like an admission of a leak, even if it isn't, so locking the no-telemetry position now and refusing to revisit it is itself part of the security posture.

## CC.7 — Documentation

- **User docs in Persian and English** at every release. Not just app help — also: "what is a publisher key fingerprint?", "what is the difference between trusted and unknown?", "how do I share a route with a friend safely?"
- **Operator docs** for publishers: how to run a bundle directory, how to rotate keys, abuse handling, capacity planning.
- **Developer docs** for the bundle libraries: the spec, test vectors, language ports.
- **Threat-model document** is public from V0 and updated each phase.

## CC.8 — Incident response

A pre-written runbook for:
- A bootstrap-pool endpoint is detected and burned.
- A publisher key is compromised.
- A signing key is compromised.
- A release is identified as backdoored.
- An app store removes the app.
- Apple revokes the developer cert (the 2019 Iranian-app precedent).

Each runbook ends with a public communication template. Practice the runbook in the lab once per quarter.

---

# What not to build early

A roadmap is partly a list of what to build, partly a list of what to *resist* building. Each of the following is something that competing projects in this space have lost calendar months to, and that should be deferred or rejected outright:

- **A new tunnel protocol.** The protocol-engine ecosystem is Go-heavy and sing-box is the load-bearing wall. Reimplementing VLESS-Reality, Hysteria2, Snowflake, obfs4, or Cloak in another language is a multi-year detour with negative protocol-coverage ROI. The project's contribution is the supply chain, not the cipher.
- **A black-box ML route selector.** "AI picks the best route" is the wrong abstraction for an anti-censorship tool. The path manager is a deterministic, auditable state machine. A user must always be able to ask "why did the app choose this route?" and get a sentence-level answer that does not contain the word "model."
- **A unified UI framework (Flutter, React Native, Compose Multiplatform).** Hiddify proves Flutter works; it also ships a 114 MB Android APK. For users on metered Iranian cellular plans, every megabyte costs them. Native Swift on iOS, Kotlin on Android, Tauri on desktop — three UIs is the right answer.
- **A cloud telemetry dashboard.** See CC.6. The project does not have a telemetry product at any version. Independent third-party measurement (OONI, Censored Planet) replaces it.
- **A general-purpose remote browser as the main product.** "We render web pages on a server and stream them to you" is privacy-disastrous if marketed as a VPN replacement. The optional partner-operated lifeline relay (V3.7) is a narrow, auditable, partner-operated feature — not a remote browser, not a VPN, and not shipped at all unless a partner is ready.
- **Parser tricks, desync exploits, brittle domain-fronting loopholes.** These have short half-lives. Censors patch them within days of detection. They belong in a research track, behind a feature flag, never as a default route family.
- **UDP-first architecture.** UDP is suppressed in Iran's stricter phases. UDP-based families (Hysteria2, TUIC, MASQUE, QUIC, WireGuard) are *opportunistic*, used only after the network-diagnosis module confirms UDP works on this network. The default foundation is TCP/443 HTTPS-shaped.
- **Speed-first route selection.** A fast-but-untrusted route should never silently outrank a slower trusted route. Stability and trust come first; speed is the third tiebreaker.
- **App updates and route updates over the same channel.** If both depend on Telegram or both depend on the project's primary domain, a single block kills both. Distribution redundancy (CC.2 and Module 1) is non-negotiable from V1.
- **A design that assumes Telegram, GitHub, or app stores are reachable.** The whole point of V1 is being useful when they are not. Any V0 spec or V1 feature that *requires* one of these channels to function is a bug, not a feature.
- **Universal APKs.** Per-ABI splits matter. A 324 MB universal APK is a barrier, not a download.
- **UPX or other binary compression on signed binaries.** Breaks code-signing and SmartScreen reputation. The 30–50% on-paper savings are not real.
- **Premature multi-language localization.** Persian and English at V1; everything else after V2 ships and the strings have stabilized. Translation churn during V1's UX iteration burns translator goodwill.
- **A community contribution model in V1.** External PRs to a project this sensitive need a code-of-trust that the team won't have written by V1. Open the codebase in V1.5 once the threat-model document and signing process are mature; until then, accept issues but not PRs.
- **A "feature-flag everything" mindset.** Feature flags are a mitigation for shipping things you're not sure about. The right answer for things you're not sure about is to not ship them. The Experimental route family is the only feature-flagged surface; everything else is on or off in a release.

The pattern across all of these: **be boring where boring is safer; be innovative specifically and only around bootstrap, trust, sharing, scarcity, and survivability.** That is where the project's actual contribution lives.

---

# Decision points (chronological)

A roadmap that does not name decisions is just a wishlist. These are the irreversible choices the team must make on the indicated dates:

| Decision | Latest possible | Default | Notes |
|---|---|---|---|
| Path A (greenfield) vs Path B (Hiddify upstream) vs Path C (toolkit + reference) | End of V0 | C (toolkit + reference together) | Hardest to reverse |
| `.sbp` bundle format spec freeze | Mid-V0 | as drafted | Test vectors gate any further revision |
| Engine ABI freeze (≤15 functions) | End of V0 | as drafted | Can extend, never break |
| Failure-taxonomy lock | Mid-V0 | as drafted (V0.3) | Append-only after this |
| Engine-control gap-analysis sign-off | End of V0 | per V0.4 audit | Determines V1 engineering scope |
| Persian wordlist locked (4-word fingerprints) | End of V0 | as commissioned | Lexicographer review required |
| Telemetry: Position A (opt-in) vs Position B (none) | Locked at V0 | **B (none) — locked, not revisited** | The decision *itself* is part of the security posture; reopening it sounds like an admission of leak |
| Sing-box version pin for V1 | Start of V1 | latest stable at V1 kickoff | Re-pin for V2 |
| Android-first vs Windows-first | Start of V1 | Android | Iran's user base skews Android |
| iOS rollout timing | Start of V2 | end of V2 | Engine work lands on Android first |
| Tauri vs Qt vs Electron for desktop | Start of V1.5 | Tauri 2 | Already settled in the build doc |
| Lifeline relay: ship in V3 / never | Start of V3 | ship only if partner ready; otherwise never | Local-only Lifeline *mode* ships in V2 regardless |
| Snowflake integration in V3 vs V4 | Start of V3 | V3.2 | Depends on rendezvous-channel maturity |
| WASM transport slot in V3 vs V4 | Start of V3 | V3.5 | Depends on stable WATER spec |
| Lifeline relay run by project vs partner | Pre-condition for V3.7 | partner only | If no partner, relay does not ship |

---

# What this roadmap deliberately omits

- **Specific dollar budgets.** They depend on team composition, country of incorporation, and donor mix. A 4-engineer team with hardware, audit, hosting, and travel: rough order $1.2–1.8M/year all-in.
- **Specific person assignments.** Architecture-driven, not Conway-driven. Re-org the team around the phase, not vice versa.
- **Marketing and community strategy.** Not because they don't matter — because they are downstream of the V1.7 pilot and adopt-or-die feedback.
- **Specific endpoints, IP ranges, or operator names.** A roadmap document is read by adversaries too.

---

# The thing that has to be true at the end

After 22 months: an Iranian user, on a degraded MCI evening connection, with no Telegram, no GitHub, no working subscription, and a phone that hasn't seen an app update in 6 weeks, can:

1. Walk to a friend's apartment.
2. Receive a fresh signed route bundle by QR code.
3. See the publisher's 4-word fingerprint and confirm trust.
4. Be online, in lifeline mode, within 30 seconds of leaving the friend's apartment.
5. The route survives for at least the next 24 hours of moderate use because the path manager rations the friend-shared bundle's capacity correctly.
6. When the friend's bundle expires, the user is told that, given two days of notice, with options to refresh.

If that scenario works, every other thing in this roadmap was worth doing. If it doesn't, the roadmap was wrong somewhere and needs to be rewritten before the next phase starts.
