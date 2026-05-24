# UI: Share With a Friend (Phase 3F)

**Status**: locked at Phase 3F.
**Engine version**: `daal-core 0.9.0+v3-share`.
**ABI surface used**: `engine_redistribute_route` (release symbol 48); diagnostics fields `delegate_share_compiled_in`, `delegate_share_counters`, `last_delegate_share_outcome`.
**Spec dependencies**: `delegate-keys-v1.md`, `share-bundle-v1.md`, `route-object-v1.md`.

This document specifies the cross-platform UI for the **one-tap delegate-share** affordance. It is consumed by the Android (Compose), Desktop (Tauri), and iOS (SwiftUI) clients. The locked invariants are **language-neutral**; copy lists are provided for English (`en`) and Farsi (`fa-IR`) only — additional languages are out of scope at 3F and will be added at a later phase.

## 1 Scope

The "Share with a friend" affordance is the user-facing path that:

1. Reads a single in-store route's redistribution policy and cap.
2. Reads the device-local re-share counter.
3. Either:
   - Renders a disabled affordance with the locked-at-3F greyed-out semantics, OR
   - Renders an active affordance whose primary action invokes `engine_redistribute_route`.
4. On success, presents the recipient with a QR + URI containing the `.sbp.share` envelope.
5. On any non-`ok` outcome, presents the locked closed-enum copy.

The UI **never** persists or transmits the recipient's delegate fingerprint outside of the in-process call to `engine_redistribute_route`. The receiver MUST exchange their fingerprint out-of-band before scanning the share.

## 2 Visibility rules (locked)

| Route's `redistribution_policy` | Affordance state |
|----|----|
| `""` (legacy / unset) | **Hidden**. The route did not opt-in; do not advertise. |
| `none` | **Visible, disabled (greyed)**. Tooltip explains why. |
| `delegated_n` with `shared_with_count >= cap` | **Visible, disabled (greyed)**. Counter displayed inline. |
| `delegated_n` with `shared_with_count < cap` | **Visible, enabled**. Counter displayed inline. |
| `transitive` | **Visible, enabled**. No counter (the cap is on chain depth, enforced receiver-side). |

When `delegate_share_compiled_in == false` the affordance MUST NOT render at all (regardless of policy). UI surfaces consult the diagnostics flag once at app start; flipping it at runtime is not supported.

## 3 Counter display

For `delegated_n` routes, the counter is rendered in the format:

- **en**: `Shared with N of M` (e.g., `Shared with 3 of 10`).
- **fa**: `با N از M نفر به اشتراک گذاشته شده` (RTL).

For `transitive` routes, no counter is shown; the affordance instead carries a small disclosure icon (`info` glyph) that opens the chain-disclosure modal (§5).

## 4 Primary action — "Share now"

Triggered from the enabled affordance; the flow is:

1. **Recipient capture**. The UI prompts the user to scan or paste the recipient's delegate fingerprint hex (the same `delegate_fp_hex` exchanged out-of-band; pre-3F installs label this as the friend's "device QR").
2. **Engine call**. `engine_redistribute_route(route_id, recipient_fp_hex)` is invoked synchronously.
3. **Outcome dispatch** (closed enum):
   - `ok` → render the QR + URI; counter increments by 1; show success toast. The `.sbp.share` envelope is the engine's return body — render it verbatim.
   - `policy_refuses` → toast `(en) "This route can't be shared."` / `(fa) "این مسیر قابل اشتراک‌گذاری نیست."`
   - `cap_exhausted` → toast `(en) "You've already shared this with the maximum number of friends."` / `(fa) "این مسیر را با حداکثر تعداد دوستان به اشتراک گذاشته‌اید."`. The affordance flips to disabled at this point.
   - `chain_depth_exceeded` → toast `(en) "Forwarding limit reached for this share."` / `(fa) "حد ارسال این اشتراک پر شده است."`
   - `route_unknown` → log + silent error (this state should never reach a user; it indicates a UI bug).
   - `identity_unavailable` → toast `(en) "Sharing is unavailable on this build."` / `(fa) "اشتراک‌گذاری در این نسخه فعال نیست."`. Hide the affordance for the rest of the session.

The UI MUST NOT retry on a non-`ok` outcome. The user re-initiates the action manually.

## 5 Chain-disclosure modal

For `transitive` routes (and for `.sbp.share` bundles received from a friend), the user can tap a small info glyph to open a modal showing:

- The number of hops in the redistribution chain (`hops/5`).
- Each hop's `delegate_fp_hex` (rendered as the EN/FA fingerprint words from the existing 1C wordlist; never raw hex unless the user expands a "show technical details" disclosure).
- The signed-at timestamp of each hop, in the user's locale.

The modal is **read-only**; there is no UI affordance to "trim" or "edit" the chain at 3F. Receivers who do not trust an intermediate hop must drop the entire share.

## 6 Disabled-state copy (locked)

When the affordance is rendered greyed-out:

| Reason | en | fa |
|----|----|----|
| `policy = none` | "This route is single-device only." | "این مسیر فقط برای این دستگاه است." |
| `cap_exhausted` (delegated_n) | "Already shared with the maximum number of friends." | "با حداکثر دوستان به اشتراک گذاشته شده." |
| `delegate_share_compiled_in = false` | (affordance hidden entirely) | (affordance hidden entirely) |

## 7 Accessibility & locale

- The affordance MUST be focusable and screen-reader-labelled in both languages.
- Counter text uses the locale's numerals (Persian numerals `۰۱۲۳…` in `fa-IR`).
- The chain-disclosure modal is RTL-aware: hops render top-to-bottom in `en`, right-to-left visual flow in `fa-IR`.
- The recipient-capture step MUST support QR scan AND clipboard paste; an offline-only deployment is the locked default at 3F (online directory lookup is out of scope).

## 8 Telemetry & privacy

The UI surfaces only what the engine already exposes via `engine_export_diagnostics`:

- The local re-share counter (`delegate_share_counters[route_id].shared_with_count`).
- The cap (`delegate_share_counters[route_id].cap`).
- The most recent outcome (`last_delegate_share_outcome`).

The UI **never** persists the recipient's fingerprint, never logs the `.sbp.share` envelope, and never sends either off-device. Position B (no telemetry) is preserved.

## 9 Test surface (per-platform owners)

Each client tracks its own UI tests; this spec only fixes the contract:

1. The disabled-state for each of the four greyed reasons renders the correct copy.
2. The `ok` outcome increments the counter by 1 in the diagnostics surface.
3. The `cap_exhausted` outcome flips the affordance to disabled without a re-render of the counter.
4. The chain-disclosure modal renders 1..5 hops correctly and rejects ≥6.
5. The `delegate_share_compiled_in = false` build hides the affordance entirely (parity test on `-tags no_delegate_share`).

End — locked at 3F.
