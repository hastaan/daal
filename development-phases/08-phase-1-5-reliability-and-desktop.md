# Phase 1.5 — Reliability Hardening and Desktop

## Roadmap Coverage

Addresses V1.5: subscription refresh through tunnel, revocation, key rotation, diagnostics expansion, desktop port, and bootstrap-directory operations.

## Goal

Turn the Android MVP into a blackout-resilient system and bring the architecture to desktop without changing the trust model.

## Scope

- Subscription refresh through active tunnel.
- Atomic profile cache updates.
- Revocation list fetch/verify/apply.
- Key rotation UX.
- "Why this route?" diagnostics.
- Desktop client foundation.
- Pointer rotation operations.
- Platform packaging plan for Windows, macOS, and Linux.

## Implementation Details

Subscription refresh:

- Refresh through active tunnel when direct refresh fails.
- Never overwrite a good cache with a bad response.
- Clamp refresh intervals.
- Respect subscription metadata such as `profile-update-interval`, `subscription-userinfo`, `profile-title`, `support-url`, and moved-permanently hints.
- Store subscription secrets separately and encrypted where possible.

Diagnostics:

- Explain selected route.
- Explain skipped route families.
- Show failure categories, not raw confusing errors.
- Avoid exact timestamps where not needed.

Desktop:

- Tauri 2 frontend.
- Rust backend.
- sing-box sidecar.
- Use `bundle-rs`.
- Windows and Linux first if macOS hardware is unavailable.
- macOS build path prepared through CI or external tester.
- Shared view-model behavior must remain language-neutral so Android, desktop, and later Apple clients explain trust/route choices consistently.

Packaging targets:

- Windows: NSIS installer, MSI, portable ZIP, WinTUN path, signing plan.
- macOS: universal `.app`, Developer-ID signing, notarization, packet tunnel/System Extension plan.
- Linux: AppImage, `.deb`, `.rpm`, privileged TUN helper.

The first implementation may land Windows/Linux before macOS, but the architecture must not block macOS packaging.

## Testing Requirements

- 7-day simulated blackout.
- 30-day simulated blackout as the detailed V1.5 success gate; 7-day run may be used as an interim milestone.
- Blocked subscription URL with active tunnel refresh.
- Revoked publisher invalidates routes.
- Key rotation preserves trust only when signed chain verifies.
- Desktop import verifies same vectors as Android.
- Snowflake/Psiphon feasibility spike or fixture review, without moving product integration earlier than planned.
- Package smoke test for each available desktop target.

## Exit Criteria

- Existing installation survives a simulated multi-day blackout.
- Existing installation survives the 30-day detailed V1.5 blackout simulation before phase completion.
- Revocation and rotation work.
- Desktop can import and verify bundles.
- Diagnostics explain route choice.
- Bootstrap pointers can rotate without app update.

## Handover to Phase 2

Phase 2 receives:

- Hardened route database.
- Revocation/key-rotation flows.
- Desktop foundation.
- Diagnostics model.
- Bootstrap operations model.

Phase 2 should focus on survivability policy and Apple rollout, not reworking trust.
