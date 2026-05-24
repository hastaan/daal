# Engine Gap Analysis v1 Checklist

## Purpose

This checklist prepares the V0.4 engine-control boundary audit. It determines whether sing-box and any secondary engine expose the controls required by Daal's path manager, diagnostics, privacy model, and budget engine.

## Checklist Format

Each capability should be filled in during the audit:

```text
Capability:
Required by:
Native support: yes/no/partial/unknown
Risk if missing:
Planned mitigation:
Owner:
Status:
```

## Capabilities To Audit

### Start/Stop Specific Outbound

```text
Capability: start/stop a specific outbound by ID
Required by: Path Manager, diagnostics, route switching
Native support: unknown
Risk if missing: route-level control becomes coarse and unreliable
Planned mitigation:
Owner:
Status: pending
```

### Route Metadata Wrapper

```text
Capability: carry route-family and provenance metadata beside outbound config
Required by: Config & Trust, diagnostics, redacted stats
Native support: unknown
Risk if missing: trust/network scoring may be mixed or lost
Planned mitigation:
Owner:
Status: pending
```

### Redacted Per-Outbound Stats

```text
Capability: query per-outbound bytes without exposing destinations
Required by: route budgets, diagnostics
Native support: unknown
Risk if missing: budget enforcement may leak sensitive metadata
Planned mitigation:
Owner:
Status: pending
```

### Structured Failure Events

```text
Capability: emit structured failure categories instead of only logs
Required by: failure taxonomy, cooldowns, user explanations
Native support: unknown
Risk if missing: stringly-typed parsing causes incorrect route decisions
Planned mitigation:
Owner:
Status: pending
```

### Soft-Pause Route

```text
Capability: pause one route without deleting config
Required by: cooldowns, budget enforcement
Native support: unknown
Risk if missing: path manager becomes disruptive and stateful recovery is harder
Planned mitigation:
Owner:
Status: pending
```

### Byte-Budget Enforcement

```text
Capability: enforce per-route byte budgets
Required by: emergency pool, lifeline mode, scarcity control
Native support: unknown
Risk if missing: scarce routes can be burned by user load
Planned mitigation:
Owner:
Status: pending
```

### Mode-Specific Routing

```text
Capability: apply lifeline/normal/bulk routing rules
Required by: mode budget UI, local lifeline mode
Native support: unknown
Risk if missing: UI mode labels will not match engine behavior
Planned mitigation:
Owner:
Status: pending
```

### Network-Change Handling

```text
Capability: react to Wi-Fi/mobile/network changes
Required by: per-network memory, cooldown reset, diagnostics
Native support: unknown
Risk if missing: stale network assumptions cause bad route choices
Planned mitigation:
Owner:
Status: pending
```

### Probe Utility

```text
Capability: run UDP/TCP/DNS probes without starting a full route
Required by: Network Diagnosis, UDP-gating
Native support: unknown
Risk if missing: the app may burn routes just to diagnose network state
Planned mitigation:
Owner:
Status: pending
```

### Redacted Diagnostics Export

```text
Capability: export local diagnostics without sensitive data
Required by: user-reviewable reports, debugging
Native support: unknown
Risk if missing: support workflows may leak route secrets or user metadata
Planned mitigation:
Owner:
Status: pending
```
