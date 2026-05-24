# `daal1...` recipient addresses — v1

**Status:** locked at FRP-14 (FRP-14 phase doc 44). **Spec version:** 1.
**Owner crates:** `core/recipient/address` (Go), `client-shell/tauri/daal-recipient-addr` (Rust).

This document specifies the on-the-wire and on-the-screen identifier
used to name a single Daal recipient. The address is the public half
of an X25519 keypair held in the recipient app's keystore; the
publisher app uses it to (a) target an age-encrypted relay pack
(`.sbpx`) and (b) request a per-recipient credentials slot from
the on-box `daal-relay-mgmt` service.

The address is **not** a publisher identity. It does not sign
anything. It is purely an asymmetric encryption identity, deliberately
separated from the publisher's Ed25519 signing key so a compromise of
one does not break the other.

## 1. Scope

* In scope:
  - Wire format of the address string.
  - QR / URI encoding.
  - Round-trip rules between the string form and the 32-byte raw
    X25519 public key.
  - Cross-implementation compatibility (Go ↔ Rust).
* Out of scope (future specs):
  - Address rotation / migration (a recipient changing devices).
  - Multi-address-per-person (the cell case — FRP-11).
  - Address-verification ceremonies (safety-number / fingerprint UX).
  - Directory publication of addresses (FRP-13).

## 2. Wire format

The address is the bech32m (BIP-350) encoding of the 32-byte X25519
public key, with the human-readable part `daal`.

```
daal1<bech32m-payload>
```

* **HRP:** `daal` (4 chars, lowercase).
* **Separator:** `1` (literal).
* **Payload:** 32 raw bytes (X25519 pub) → 52 chars 5-bit data
  (with 1-bit zero pad) + 6 chars checksum = 58 chars.
* **Total length:** 63 chars (`d` `a` `a` `l` `1` + 58 = 63).
  Implementations MUST reject any string whose length is not exactly
  63 chars.

Bech32m (not bech32) is mandatory: the constant `0x2BC830A3` in the
polymod, not `1`. This matches the post-2020 cryptocurrency-address
ecosystem (Bitcoin Taproot, Cosmos SDK ≥ 0.40) and detects a
single-character substitution with probability `1 − 2^−30 ≈ 1 − 10^−9`.

Mixed-case strings are rejected outright (bech32m is case-insensitive
on input but emits lowercase; mixed case is a strong signal of
copy/paste damage).

## 3. Text rendering

* The publisher app, recipient app, and any documentation MUST render
  the address as lowercase `daal1...`. UI text shown to humans uses
  the bare form.
* A short fingerprint MAY be shown alongside for voice-verification:
  the last 8 chars of the address (e.g. `daal1...7xk2pq8w`). This is
  cosmetic; do not derive trust decisions from short forms.
* Copy buttons MUST copy the bare form (`daal1...`) without
  surrounding whitespace, quotes, or the URI prefix below.

## 4. QR / URI encoding

QR codes wrap the bare address with a `daal://addr/` URI prefix:

```
daal://addr/daal1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrkckut
```

(Example above is the zero-pubkey address; real addresses look like
random 58-char tails.)

* Recipient app QR generation MUST emit this URI form.
* Publisher app QR scanning MUST accept both forms (with prefix and
  bare) and strip the `daal://addr/` prefix before validation.
* Other Daal URI schemes (`daal://invite/...`, etc.) are reserved;
  parsers for `daal://addr/` MUST NOT route on path components other
  than the literal `addr/`.

## 5. Round-trip rules

### 5.1. Encode

```
Encode(pub [32]byte) string
```

* Input: 32 raw X25519 pubkey bytes.
* Output: a 62-char lowercase `daal1...` string.
* Deterministic: same input → same output across calls and across
  implementations (Go + Rust pinned).

### 5.2. Decode

```
Decode(s string) ([32]byte, error)
```

* Tolerates the bare form and the `daal://addr/` URI prefix.
* Rejects mixed case (returns `ErrMixedCase`).
* Rejects wrong length (returns `ErrInvalidLength`).
* Rejects wrong HRP (returns `ErrWrongHRP`).
* Rejects bech32m checksum failure (returns `ErrChecksum`).
* Rejects raw payload != 32 bytes (returns `ErrPayloadLength`).
* Returns the 32 raw bytes on success.

### 5.3. ParseURI

```
ParseURI(s string) ([32]byte, error)
```

A convenience wrapper that REQUIRES the `daal://addr/` prefix, then
calls Decode on the suffix. Used by deep-link handlers; not the
default address-validation surface.

## 6. Cross-implementation invariants

Both the Go and Rust implementations MUST agree on every byte of
output for any given input. The pinning mechanism is a shared golden
test vector:

```
specs/test-vectors/recipient-address-v1/
  golden.json
```

`golden.json` is a list of 1024 entries:

```jsonc
[
  {
    "pub_hex": "00000000000000000000000000000000000000000000000000000000000000000",
    "address": "daal1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkcsrn5"
  },
  ...
]
```

Both impls run a test that loads `golden.json` and asserts every
`Encode(pub_hex) == address` and `Decode(address) == pub_hex`.

Fuzz coverage: each impl generates 256 random pubkeys and asserts
round-trip. Cross-impl fuzz is part of the FRP-14 CI gate
(`mission/frp-14-address-cross-impl.sh`).

## 7. Error names (exported)

| Error | Trigger |
|---|---|
| `ErrInvalidLength` | input is not exactly 62 chars (after URI prefix strip) |
| `ErrMixedCase` | input contains both upper and lowercase letters |
| `ErrWrongHRP` | HRP is not exactly `daal` |
| `ErrChecksum` | bech32m polymod check fails |
| `ErrPayloadLength` | decoded raw payload is not exactly 32 bytes |
| `ErrInvalidURI` | URI form is missing the `daal://addr/` prefix |

These names appear in error wraps; UI surfaces translate them via
`recipients.add.invalid` (single user-facing message — the underlying
cause is for logs, not end users).

## 8. HRP collision review

`daal` is not registered in SLIP-0173
(github.com/satoshilabs/slips/blob/master/slip-0173.md) as of 2026-05.
There is no overlap with existing bech32 ecosystems (Bitcoin `bc` /
`tb`, Cosmos `cosmos`, Lightning `ln`, etc.). The HRP is reserved here
by spec; we do not publish to SLIP-0173 because the address namespace
is application-internal (Daal-to-Daal only) and not part of any
cross-system addressing convention.

## 9. Security notes

* The 32-byte payload is an X25519 *public* key. Leaking it is harmless
  in the strict cryptographic sense — but in the Daal threat model,
  knowing a recipient's address lets an adversary mount a Sybil attack
  by claiming to be a publisher who wants to send a relay pack to that
  recipient. The recipient app MUST refuse to import `.sbpx` files
  whose embedded `bundle.recipient_fp_hex` does not match the local
  identity; see `specs/sbpx-envelope-v1.md` §4.
* Bech32m provides excellent corruption detection but is not
  cryptographically authenticated. A determined adversary who controls
  the channel can substitute the address. Out-of-band verification
  (voice, in-person QR scan, second messenger) is the recommended
  mitigation.
* The X25519 priv lives in the recipient's OS keystore, sealed under
  PIN via Argon2id + AES-GCM (the same two-layer custody used for
  publisher keys; see `specs/key-vault-v1.md`).

## 10. Test surface

| File | Tests |
|---|---|
| `core/recipient/address_test.go` | encode/decode round-trip, golden vectors, mixed-case reject, wrong-length reject, single-char-corruption reject, URI prefix strip, random 256-key fuzz |
| `client-shell/tauri/daal-recipient-addr/src/lib.rs` | mirror of above; loads same `golden.json` |
| `mission/frp-14-address-cross-impl.sh` | Runs Go encode N random keys → pipes to Rust decoder → asserts equality, then vice versa |

## 11. Carry-overs

* The address book on the publisher side (`recipients` table in the
  wizard DB) is specified in `specs/per-recipient-credentials-v1.md`,
  not here.
* The QR rendering library is the existing
  `client-ui/src/lib/qr.ts` — no new dependency; the only change is
  emitting the `daal://addr/` URI form.
