package envelope

// Internal helpers: build an age X25519 recipient / identity from
// raw 32-byte keys. age's exported constructors only accept the
// bech32-encoded `age1...` / `AGE-SECRET-KEY-...` strings, so we
// encode locally and call the parser.
//
// We deliberately reuse the bech32 (BIP-173) primitives from the
// Daal `core/recipient/address` codec — except age uses *bech32*
// (constant 1), not bech32m (constant 0x2BC830A3). So we cannot
// share the polymod constant; this file ships a local bech32
// implementation pinned to the BIP-173 constant.

import (
	"errors"
	"strings"

	"filippo.io/age"
)

const ageRecipientHRP = "age"
const ageIdentityHRP = "AGE-SECRET-KEY-"
const ageBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const bech32Const uint32 = 1

func ageBech32Polymod(values []byte) uint32 {
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

func ageHrpExpand(hrp string) []byte {
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

func ageBech32Checksum(hrp string, data []byte) []byte {
	values := append(ageHrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	m := ageBech32Polymod(values) ^ bech32Const
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((m >> (5 * (5 - i))) & 31)
	}
	return out
}

func ageConvertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	out := []byte{}
	maxv := uint32(1<<to) - 1
	for _, v := range data {
		if uint32(v) >= (1 << from) {
			return nil, errors.New("ageConvertBits: input out of range")
		}
		acc = (acc << from) | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(to-bits))&maxv))
		}
	}
	return out, nil
}

func encodeAgeBech32(hrp string, raw []byte) (string, error) {
	// age's bech32 checksum is computed over the *lowercased* HRP;
	// the surrounding string then mirrors the original HRP case
	// (all-upper or all-lower; mixed-case HRPs are rejected). For
	// "AGE-SECRET-KEY-" the final string is entirely uppercase
	// including the data tail.
	lowerHRP := strings.ToLower(hrp)
	conv, err := ageConvertBits(raw, 8, 5, true)
	if err != nil {
		return "", err
	}
	check := ageBech32Checksum(lowerHRP, conv)
	var b strings.Builder
	b.WriteString(lowerHRP)
	b.WriteByte('1')
	for _, c := range conv {
		b.WriteByte(ageBech32Charset[c])
	}
	for _, c := range check {
		b.WriteByte(ageBech32Charset[c])
	}
	if hrp != lowerHRP {
		return strings.ToUpper(b.String()), nil
	}
	return b.String(), nil
}

func newX25519Recipient(pub [32]byte) (*age.X25519Recipient, error) {
	s, err := encodeAgeBech32(ageRecipientHRP, pub[:])
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Recipient(s)
}

func newX25519Identity(priv [32]byte) (*age.X25519Identity, error) {
	s, err := encodeAgeBech32(ageIdentityHRP, priv[:])
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(s)
}
