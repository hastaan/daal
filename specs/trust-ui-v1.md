# Trust UI v1

## Status

Phase 1B deliverable; copy is locked in EN and FA.
**Phase 3A adds the Experimental badge, the one-time
explainer modal, and the per-family region-caveat banner
plumbing for V3 transport families. Copy locked en + fa.**

## Goal

Make a non-technical user understand, in their language, *who* signed the
bundle they are about to import — and refuse to silently install routes
from unknown publishers.

## Invariants

1. A first-seen publisher's bundle MUST surface this dialog. There is no
   "remember my decision per device" affordance; trust is per publisher.
2. The dialog is modal; routes from the bundle are not usable while the
   dialog is open.
3. Cancel is the default choice (no auto-confirm timer).
4. The dialog MUST display three fingerprint renderings:
   - 4-word English (BIP-39-style),
   - 4-word Persian (curated; locked in V0),
   - hex (full hex behind a "details" affordance).
5. Network success NEVER upgrades trust (see `specs/publisher-keys-v1.md`).
6. Rotation accepted from an already-pinned publisher informs but does not
   re-prompt.

## English copy

```
Title:   New publisher
Body:    This bundle was signed by:

         <english fingerprint>
         <persian fingerprint>

         You have not seen this publisher before. If you recognize the
         fingerprint, you can trust it; otherwise cancel.

Buttons: [I trust this publisher] [Just for this one bundle] [Cancel]
```

## Persian copy

```
عنوان:  ناشر جدید
متن:    این بسته توسط این ناشر امضا شده است:

        <اثرانگشت انگلیسی>
        <اثرانگشت فارسی>

        شما این ناشر را پیش از این ندیده‌اید. اگر اثرانگشت را
        می‌شناسید، می‌توانید به آن اعتماد کنید؛ در غیر این صورت لغو کنید.

دکمه‌ها: [به این ناشر اعتماد دارم] [فقط برای همین بسته] [لغو]
```

## Trust badges

| Badge | Shown when |
|---|---|
| Official | publisher trust_level = `official` |
| Trusted provider | publisher trust_level = `trusted_provider` |
| Friend-shared | publisher trust_level = `tofu_friend` and bundle.type = `friend_share` |
| Unknown | publisher trust_level = `unknown` (only after explicit "just this one bundle") |
| Expired | bundle or route past `valid_until` |
| Revoked | publisher or route on revocation list |
| Experimental | route's `transport_family` is at Experimental maturity per `specs/transport-families-v1.md` |
| Promotion candidate | route's family is at Promotion-candidate maturity *(reserved at 3A; no family at this level until a roadmap-level decision)* |

The Experimental badge rides ON TOP OF the trust badge: a
"Trusted Provider" WebTunnel route shows BOTH "Trusted
provider" AND "Experimental." The two namespaces never merge.

## Phase 3A — Experimental gate UI

### One-time explainer modal

Surfaced the FIRST time the user toggles the experimental
gate ON in Settings. Modal; the user must acknowledge before
the toggle takes effect.

```
EN:
Title:   Allow experimental transports?
Body:    Some transports in your bundles are still experimental.
         Daal hides them by default.

         If you turn this on:
         • Experimental routes appear in your route list.
         • Daal will not auto-promote to Lifeline (local-only)
           when only experimental routes are available.
         • Experimental routes may fail fast or behave
           differently in some regions.

Buttons: [Turn on] [Cancel]

FA:
عنوان:  انتقال‌های آزمایشی فعال شود؟
متن:    برخی از انتقال‌ها در بسته‌های شما هنوز آزمایشی هستند.
        دال به‌طور پیش‌فرض آن‌ها را پنهان می‌کند.

        اگر این گزینه را فعال کنید:
        • مسیرهای آزمایشی در فهرست مسیرهای شما ظاهر می‌شوند.
        • دال هنگامی که فقط مسیرهای آزمایشی در دسترس باشند،
          به‌طور خودکار به خط نجات (محلی) ارتقا نمی‌دهد.
        • مسیرهای آزمایشی ممکن است به‌سرعت شکست بخورند یا در
          برخی مناطق رفتار متفاوتی داشته باشند.

دکمه‌ها: [فعال کن] [لغو]
```

The modal fires once per device per user-id. Subsequent
toggle-ons skip the modal.

### Region-caveat banner

Per-family informational banner, shown when the user's
detected locale is `fa-IR` and the user opens the route
detail screen for an experimental-family route for the first
time. Each family supplies its own copy via either the
family's spec OR the route's `caveat_fa_ir` override.

The 3A locked WebTunnel copy lives in
`specs/webtunnel-route-v1.md`; the spec there is the
authoritative source.

The banner is informational, not blocking. Shown ONCE per
route on first detail open; never again on that route.

### Anti-pattern register (Phase 3A additions)

- No "Always trust experimental" affordance. The gate is
  binary; per-route opt-in does not exist.
- No per-network experimental memory. The gate is global;
  the user's choice in network A applies to network B.
- No silent promotion of experimental → stable from network
  success. Promotion is a roadmap-level decision.

## Anti-pattern register

- No "Trust all" / "Always trust" affordance.
- No green-checkmark on a freshly imported but unverified bundle.
- No silent toast when trust state changes.
- No mixing of network-quality colors with trust-state colors.
