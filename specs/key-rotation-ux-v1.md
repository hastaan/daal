---
name: key-rotation-ux-v1
phase: 1.5A
status: draft
---

# key-rotation-ux-v1 — surfacing rotations to the user

## Status

Draft, Phase 1.5A.

## Purpose

Phase 1B's importer (`bundle-go/importer.verifyRotation`) already
accepts a publisher's signed `trust/rotation.json`. Phase 1.5A adds the
**non-modal user surfacing**: rotations are informative, not interactive.

## Surfaces

### 1. Successful rotation acceptance — home-screen card

After the importer returns `VerdictRotationAccepted`, the host UI shows
a one-shot, dismissable card:

> **<Publisher> rotated their signing key.**
>
> Trust was preserved through the rotation chain. No action needed.
>
> Previous: <old EN fingerprint phrase>
> Now:      <new EN fingerprint phrase>
>
> [Dismiss]

The card MUST be:
- Non-modal (the user can keep using the app).
- Dismissable (single tap; no "are you sure" confirmation).
- Logged to `trust_audit` under the existing schema (no new column);
  reason = `"key_rotation_accepted"`.

The card MUST NOT:
- Force a re-acceptance flow.
- Show the URL the rotation arrived from.

### 2. Rotation rejected (no chain present, key unexpectedly different)

Falls back to the existing `VerdictTrustPromptNeeded` path. The prompt
copy is reworded to make the unexpected-key signal clear:

> **This bundle is signed by a key you have not seen before.**
>
> The previous publisher key (<old EN phrase>) did not endorse this
> rotation. If you are sure this is the same publisher, you may trust
> the new key — otherwise cancel and contact the publisher through a
> trusted channel.
>
> [I trust this publisher] [Just for this one bundle] [Cancel]

### 3. UI pieces (Compose)

- `KeyRotationCard.kt` — the home-screen card.
- Existing trust prompt strings extended with `trust_prompt_rotation_*`
  keys (Phase 1.5A added two per locale).

## Backwards compatibility

`trust_audit` schema is unchanged. The card is a UI-only addition; older
Phase 1B/1C/1D builds simply do not show it.
