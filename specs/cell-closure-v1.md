# Cell closure v1 (FRP-11)

**Status**: HOLD. Pending V2 cell alpha pilot.
**Gate criterion**: per supplement §17.2 — the six abuse-handling-maturity conditions (measured against ≥30% of FRPs in cells across ≥3 providers and ≥2 EU regions).

## 1 Purpose

This document is the FRP-13 gate input. When the §17.2 conditions are met AND the V2 cell alpha pilot survives a documented rotation cycle without family-side outage, this status flips to SHIPPED, FRP-13 (public directory gate) becomes unblocked, and the V3 supplement (§22.4) can record a public-directory success metric attempt.

Until that flip the public directory is OFF, by deliberate design.

## 2 Closure record fields (to be filled when status flips)

```yaml
status: SHIPPED
flipped_at: 20XX-YY-ZZ
soak_evidence:
  cells: ...
  providers: ...
  abuse_handling_conditions: [met, met, met, met, met, met]
  rotation_cycle_observed: ...
gate_to: FRP-13 public directory
```

End — HOLD pending pilot.
