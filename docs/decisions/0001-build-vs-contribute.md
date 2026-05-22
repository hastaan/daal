# Decision 0001 — Build vs Contribute

## Status

Accepted as default for V0/V1 planning.

## Decision

Daal defaults to **Path C — toolkit + reference client**.

This means the project builds:

- reusable bundle/trust libraries,
- publisher tooling,
- a reference Android client,
- and later desktop/iOS clients,

while keeping the architecture adoptable by existing clients such as Hiddify, NekoBox, v2rayNG, FoXray, and Streisand.

## Alternatives Considered

### Path A — Greenfield Client

Maximum control and best UX consistency, but highest effort and slowest adoption.

### Path B — Upstream-First

Fastest access to existing users, but trust UX, offline sharing, and scarcity labels may be compromised by upstream priorities and review timelines.

### Path C — Toolkit + Reference Client

Highest leverage: the reference client proves the full trust/offline UX, while the toolkit lets other clients integrate the signed route-supply layer.

## Rationale

Daal's durable contribution is not a new tunnel protocol. It is the route supply chain: signed bundles, publisher trust, offline sharing, scarcity-aware route handling, and survivability when normal distribution channels fail.

Path C preserves this core product while creating an adoption path for existing ecosystems.

## Revisit Criteria

Revisit only at explicit roadmap decision points or if the team lacks capacity to maintain both toolkit and reference client.
