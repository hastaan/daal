# Decision 0003 — Persian Fingerprint Wordlist Plan

## Status

Planned for V0 completion.

## Decision

Daal will use a curated 2048-word Persian fingerprint wordlist for publisher-key fingerprints. This list must be designed and reviewed before the bundle/trust UX ships.

## Requirements

- 2048 words.
- Low homophone collision risk.
- Suitable for voice relay.
- Suitable for low-literacy and noisy-room comparison contexts.
- Reviewed by native Persian speakers.
- Reviewed by a lexicographer if funding allows.
- Stable once V0 locks fingerprint rendering.

## Fingerprint Formats

Daal should render publisher fingerprints in:

- English four-word format.
- Persian four-word format.
- deterministic visual checksum.
- full hex only in details.

## Visual Checksum Constraints

The visual checksum must account for:

- deuteranopia,
- protanopia,
- tritanopia,
- low-end phone screens,
- and noisy in-person comparison.

## Rationale

English-only BIP-39 assumes literacy and language comfort many target users may not have. The Persian wordlist is a trust UX primitive, not a cosmetic localization task.
