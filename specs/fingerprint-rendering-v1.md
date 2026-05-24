# Fingerprint Rendering v1

## Status

Draft for V0 freeze.

## Purpose

Publisher fingerprints must be memorable, voice-relayable, and visually comparable. The user should not need to compare a 64-character hex string during normal import.

## Source Fingerprint

The source fingerprint is:

```text
SHA-256(ed25519_public_key_32_bytes)
```

## Renderings

### English Four-Word

Use 44 bits of the fingerprint mapped to four words from a 2048-word English list.

### Persian Four-Word

Use the same 44-bit value mapped to a curated 2048-word Persian list.

The Persian list is not production-ready until native-speaker and lexicographer review is complete. Test-only wordlists must be clearly marked non-production.

### Visual Checksum

Render a deterministic 5×5 visual checksum from fingerprint bits.

Constraints:

- deterministic,
- fixed palette,
- distinguishable under common color-vision deficiencies,
- suitable for low-end phone screens,
- no network access.

### Full Hex

Full hex is available only in details.

## Security Notes

- Fingerprints help humans confirm publisher identity.
- Fingerprints do not prove route safety or reachability.
- Network success must not change publisher trust.
