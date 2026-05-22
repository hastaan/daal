# Phase 1D — Bootstrap Directory and Embedded Seed Material

## Roadmap Coverage

Addresses V1.5 embedded bootstrap material, V1.7 first publisher/pilot, and V1.5.5 pointer rotation foundations.

## Goal

Provide a zero-trust bootstrap path that does not rely on a static embedded route list.

## Scope

- Embedded project root public key.
- Embedded publisher public keys.
- Signed directory pointer format.
- Fetched bootstrap directory format.
- Minimal emergency seed route handling.
- Directory expiry.
- Basic pointer fallback.
- First publisher and closed-pilot preparation.

## Implementation Details

Embedded material should include:

- Public keys.
- Signed primary directory pointers: target 6–10 diverse URLs across domains, TLDs, CDNs, IPFS gateways, and at least one onion path where practical.
- Signed fallback directory pointers on different ASNs/TLD operators where practical.
- Very small, short-lived emergency seed entries only if necessary: target 3–8 entries, `valid_until` no more than 30 days from build.

Rules:

- Embedded seed routes are disposable.
- Directory contents are signed.
- Directories expire within a short window.
- Emergency routes have strict budget and visible UI label.
- Emergency routes enforce V1 budget targets: warn near 100 MB/day, pause around 200 MB/day, and avoid background bulk traffic.
- The app must push users toward real trusted routes.
- No embedded IP or endpoint is treated as durable.

Bootstrap flow:

1. Try user routes first if available.
2. If no route works, attempt emergency discovery.
3. Fetch signed directory through any working path.
4. Verify signature.
5. Import routes with provenance.
6. Retire stale emergency material.

Pilot preparation:

- Stand up a project-operated bootstrap publisher.
- Stand up or simulate a second independent publisher.
- Prepare a small closed pilot package.
- Record operational risks for burned endpoints, blocked pointers, and compromised publisher keys.

## Testing Requirements

- Directory signature verification.
- Expired directory rejection.
- Tampered pointer rejection.
- All pointers blocked scenario.
- Emergency route budget enforcement.
- Seed count and expiry validation.
- Primary/fallback pointer diversity validation.
- Directory refresh through active tunnel.
- Multi-publisher directory merge with provenance preserved.

## Exit Criteria

- Client can fetch and verify a signed bootstrap directory.
- Client handles blocked primary pointer.
- Client handles stale directory without silent failure.
- Emergency pool is visibly labeled and capped.
- Embedded seed material remains extractable/disposable, not steady-state capacity.
- First-publisher pilot package is ready.

## Handover to Phase 1.5

Phase 1.5 receives:

- Directory pointer model.
- Directory import path.
- Bootstrap UX.
- Expiry behavior.
- Initial operational assumptions and risks.
- Pilot readiness notes.
