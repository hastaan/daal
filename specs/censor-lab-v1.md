# Censor Lab v1

## Status

Draft for V0 freeze.

## Purpose

The censor lab is a Linux-first, netns-only test rig that simulates Iran-/China-class hostile network behavior plus distribution-channel failures. It produces deterministic, replayable failure fixtures keyed to the Daal failure taxonomy.

The lab is a developer tool. It does not ship to users and does not collect anything from anyone.

## Non-Goals

- No production DPI reproduction.
- No real captures from real networks.
- No real Iranian endpoints, real CDN IPs, or live traffic.
- No machine learning, no DPI training.
- No Docker / Podman.
- No telemetry.

## Architecture

The lab is driven by `lab-driver`, a Go binary, which:

- Creates Linux network namespaces (`client`, `censor`, `origin`, `dist-origin`).
- Wires veth pairs and routing.
- Applies `tc qdisc` / `netem` for latency/jitter/loss.
- Applies `nftables` rules for protocol whitelisting and UDP blackhole.
- Spawns small Go helpers in the censor namespace for DNS forgery, SNI/IP RST injection, first-bytes whitelist, fingerprint dropping, and stateful reassembly.
- Runs an origin server (TCP/UDP echo, DNS, TLS with self-signed cert).
- Records hour-bucketed events, failure categories, and small pcap snippets.

Root or `CAP_NET_ADMIN` is required for live runs. Without those, the rig still builds, parses scenarios, and replays fixtures in user space.

## Scenario Schema

Scenarios are JSON files (one scenario per file) so the rig stays stdlib-only and offline-friendly.

```json
{
  "id": "stateless-sni-rst",
  "v0_failure_categories": ["tls_sni_or_cert_block_suspected", "tcp_reset"],
  "description": "Iran-style first-two-packets stateless DPI that RST-injects on SNI match.",
  "network": {
    "client": "10.0.0.2/24",
    "origin": "10.0.0.3/24",
    "latency_ms": 80,
    "jitter_ms": 20,
    "loss_pct": 0.5
  },
  "censor": {
    "dns": { "poison": { "blocked.example": ["10.10.34.34"] } },
    "tls_sni_rst": { "block_list": ["blocked.example"] },
    "protocol_whitelist": { "enabled": false }
  },
  "expectations": [
    { "flow": "tls_to_blocked", "outcome": "tcp_reset" },
    { "flow": "tls_to_allowed", "outcome": "ok" }
  ]
}
```

Adding scenarios requires updating the failure taxonomy spec when a new category is referenced.

## Replay Output

`lab-driver replay <scenario>` produces a JSON fixture under
`test-rigs/censor-lab/fixtures/failures/<category>/<scenario>.json`.

```json
{
  "scenario_id": "stateless-sni-rst",
  "category": "tls_sni_or_cert_block_suspected",
  "outcome": "tcp_reset",
  "hour_bucket": "2026-04-26T19:00Z",
  "notes": ""
}
```

Fixtures must contain no exact timestamps, no real IPs of real services, and no user-supplied data.

## What the Lab Models

- DNS poisoning to RFC1918 / known sinkholes.
- DNS timeout.
- Encrypted-DNS bootstrap kill via SNI block on resolver hostnames.
- ECH bootstrap fail via withheld HTTPS/SVCB record.
- TLS SNI RST injection on ClientHello.
- TCP RST mid-handshake on suspected proxy IPs.
- Iran-style protocol whitelist on first ≥8 bytes (DNS / HTTP-verb / TLS record `0x16`).
- UDP blackhole / loss / jitter profiles.
- QUIC unavailable while UDP is otherwise OK.
- WireGuard signature drop (148 B init, type `0x01000000`).
- AmneziaWG fingerprint placeholder.
- TLS-in-TLS burst-pattern detection placeholder.
- `auth_failed` on reachable server (must NOT trigger censorship cooldown).
- Bundle tampering scenarios (corrupt zip, invalid signature, invalid canonical JSON).
- Stateful reassembly variant defeating pre-ISN injection tricks.
- Network transition (Wi-Fi → mobile-like) mid-flow.

## Distribution-Failure Coverage

Each channel must fail independently:

- Telegram unreachable.
- GitHub unreachable.
- Project primary domain unreachable.
- App-store path unreachable.
- Subscription URL unreachable.
- Bootstrap-directory mirror unreachable.
- IPFS gateway unreachable.

## Privacy Constraints

- No telemetry, ever.
- The lab generates fixtures; it does not call out.
- Fixtures contain no real-user data.
- Scenarios must avoid embedding real CDN IPs or real route secrets.

## Test Vectors

Fixtures live in `test-rigs/censor-lab/fixtures/failures/` and are mirrored into
`specs/test-vectors/failures/` by category for downstream phases.
