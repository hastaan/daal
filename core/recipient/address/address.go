// Package address implements the Daal recipient address codec —
// `daal1...` bech32m strings carrying a 32-byte X25519 public key.
//
// Spec: specs/recipient-address-v1.md. The Rust mirror lives at
// client-shell/tauri/daal-recipient-addr/. Both impls share a
// golden vector file (specs/test-vectors/recipient-address-v1/golden.json)
// that pins cross-impl agreement.
//
// Bech32m (BIP-350) is used, not bech32. The HRP is the literal
// 4-char string "daal". Encoded addresses are exactly 62 chars and
// always lowercase on emit; mixed-case input is rejected to flag
// copy/paste damage.
//
// This package has no other Daal package imports — it is a leaf
// dependency. It deliberately re-implements the bech32m primitives
// inline (no external bech32 dep) so the cross-language pinning
// boils down to byte equality without library-version skew.
package address

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Errors returned by Decode / ParseURI.
var (
	ErrInvalidLength = errors.New("daal address: invalid length")
	ErrMixedCase     = errors.New("daal address: mixed case not permitted")
	ErrWrongHRP      = errors.New("daal address: wrong human-readable part")
	ErrChecksum      = errors.New("daal address: bech32m checksum mismatch")
	ErrPayloadLength = errors.New("daal address: payload is not 32 bytes")
	ErrInvalidURI    = errors.New("daal address: not a daal://addr/ URI")
)

// AddressLen is the fixed length of a daal1... address string.
// 32 bytes → 52 5-bit groups (with 1-bit pad) + 6 bech32m checksum
// = 58 data chars; plus "daal" (4) + "1" (1) separator = 63 chars.
const AddressLen = 63

// HRP is the human-readable part of every Daal address. The
// literal "daal" prefix the user sees in their address book.
const HRP = "daal"

// URIPrefix is the QR / deep-link prefix. The bare daal1...
// string is what humans see; QR encoders wrap with this prefix.
const URIPrefix = "daal://addr/"

// Encode produces a lowercase daal1... address from a 32-byte
// X25519 public key. Deterministic and pinned by the cross-impl
// golden vectors.
func Encode(pub [32]byte) string {
	conv, err := convertBits(pub[:], 8, 5, true)
	if err != nil {
		// 32 bytes is always representable; this never errors
		// in practice, but the convertBits signature surfaces
		// the error path for symmetry with Decode.
		panic("daal address: unreachable convertBits encode error: " + err.Error())
	}
	check := createChecksum(HRP, conv)
	combined := append(append([]byte{}, conv...), check...)
	var b strings.Builder
	b.Grow(AddressLen)
	b.WriteString(HRP)
	b.WriteByte('1')
	for _, c := range combined {
		b.WriteByte(charset[c])
	}
	return b.String()
}

// Decode tolerates both the bare daal1... form and the
// daal://addr/daal1... URI form. Returns the 32 raw X25519 pubkey
// bytes on success.
func Decode(s string) ([32]byte, error) {
	var zero [32]byte
	s = strings.TrimPrefix(s, URIPrefix)
	if len(s) != AddressLen {
		return zero, ErrInvalidLength
	}
	hasLower, hasUpper := false, false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return zero, ErrMixedCase
	}
	lower := strings.ToLower(s)
	sep := strings.LastIndex(lower, "1")
	if sep < 1 || sep+7 > len(lower) {
		return zero, ErrInvalidLength
	}
	hrp := lower[:sep]
	if hrp != HRP {
		return zero, ErrWrongHRP
	}
	dataPart := lower[sep+1:]
	data := make([]byte, 0, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		idx := strings.IndexByte(charset, dataPart[i])
		if idx < 0 {
			return zero, ErrChecksum
		}
		data = append(data, byte(idx))
	}
	if !verifyChecksum(hrp, data) {
		return zero, ErrChecksum
	}
	payload := data[:len(data)-6]
	raw, err := convertBits(payload, 5, 8, false)
	if err != nil {
		return zero, ErrChecksum
	}
	if len(raw) != 32 {
		return zero, ErrPayloadLength
	}
	copy(zero[:], raw)
	return zero, nil
}

// ParseURI requires the URI prefix to be present and returns the
// 32 raw pubkey bytes. Use this when handling a deep link; use
// Decode when handling pasted text or scanned-QR payloads that
// may or may not carry the prefix.
func ParseURI(s string) ([32]byte, error) {
	var zero [32]byte
	if !strings.HasPrefix(s, URIPrefix) {
		return zero, ErrInvalidURI
	}
	return Decode(s[len(URIPrefix):])
}

// Fingerprint returns the SHA-256 of the 32-byte X25519 pub,
// hex-encoded (64 lowercase chars). This is the value that lives
// in `bundle.recipient_fp_hex` in a .sbpx-wrapped relay pack.
func Fingerprint(pub [32]byte) string {
	sum := sha256.Sum256(pub[:])
	return hex.EncodeToString(sum[:])
}

// ----------------------------------------------------------------
// Bech32m primitives. Inlined so the cross-language pinning is on
// byte equality, not library-version equality. See BIP-173 / BIP-350.
// ----------------------------------------------------------------

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32mConst is the constant in the polymod (BIP-350); for
// bech32 (BIP-173) this would be 1. We use bech32m exclusively.
const bech32mConst = 0x2BC830A3

func polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>i)&1 != 0 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&0x1f)
	}
	return out
}

func verifyChecksum(hrp string, data []byte) bool {
	all := append(hrpExpand(hrp), data...)
	return polymod(all) == bech32mConst
}

func createChecksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ bech32mConst
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((mod >> (5 * (5 - i))) & 31)
	}
	return out
}

// convertBits converts a byte slice from `frombits` per element
// to `tobits` per element, with optional padding. Mirrors BIP-173
// reference impl.
func convertBits(data []byte, frombits, tobits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	out := []byte{}
	maxv := uint32(1<<tobits) - 1
	for _, v := range data {
		if uint32(v) >= (1 << frombits) {
			return nil, errors.New("convertBits: input out of range")
		}
		acc = (acc << frombits) | uint32(v)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(tobits-bits))&maxv))
		}
	} else if bits >= frombits || (acc<<(tobits-bits))&maxv != 0 {
		return nil, errors.New("convertBits: invalid padding")
	}
	return out, nil
}
