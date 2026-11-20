// Report-address codec: a byte-for-byte copy of core/recipient/address
// (bech32m, HRP "daal", 32-byte X25519 key), so the publisher module,
// which does not depend on core, can print and parse the `daal1…`
// report address. Pinned to the same golden vectors
// (specs/test-vectors/recipient-address-v1/golden.json) by addr_test.go.

package fieldreport

import (
	"errors"
	"strings"
)

// ErrBadAddress: not a valid daal1… address.
var ErrBadAddress = errors.New("fieldreport: not a valid daal1 address")

const (
	addrLen    = 63
	addrHRP    = "daal"
	addrURIPfx = "daal://addr/"
)

// EncodeAddress is address.Encode.
func EncodeAddress(pub [32]byte) string {
	conv, _ := convertBits(pub[:], 8, 5, true)
	check := createChecksum(addrHRP, conv)
	var b strings.Builder
	b.WriteString(addrHRP)
	b.WriteByte('1')
	for _, c := range append(conv, check...) {
		b.WriteByte(charset[c])
	}
	return b.String()
}

// DecodeAddress is address.Decode (bare or daal://addr/ form; mixed case
// refused).
func DecodeAddress(s string) ([32]byte, error) {
	var zero [32]byte
	s = strings.TrimPrefix(strings.TrimSpace(s), addrURIPfx)
	if len(s) != addrLen || (strings.ToLower(s) != s && strings.ToUpper(s) != s) {
		return zero, ErrBadAddress
	}
	lower := strings.ToLower(s)
	sep := strings.LastIndex(lower, "1")
	if sep < 1 || sep+7 > len(lower) || lower[:sep] != addrHRP {
		return zero, ErrBadAddress
	}
	data := make([]byte, 0, len(lower)-sep-1)
	for i := sep + 1; i < len(lower); i++ {
		idx := strings.IndexByte(charset, lower[i])
		if idx < 0 {
			return zero, ErrBadAddress
		}
		data = append(data, byte(idx))
	}
	if polymod(append(hrpExpand(addrHRP), data...)) != bech32mConst {
		return zero, ErrBadAddress
	}
	raw, err := convertBits(data[:len(data)-6], 5, 8, false)
	if err != nil || len(raw) != 32 {
		return zero, ErrBadAddress
	}
	copy(zero[:], raw)
	return zero, nil
}

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
