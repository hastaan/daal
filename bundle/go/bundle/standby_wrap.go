package bundle

// standby_wrap.go — the wrapped standby code
// (specs/update-ladder-v2.md §3; docs/update-ladder-v2.md §3.4).
//
// The plain standby code a person types is the standby key itself,
// salt ‖ ipv4: anyone who reads the message reads the address. The
// wrapped code is
//
//	wrapped = key XOR HKDF-SHA256(ikm = u, salt = "daal/update-v2",
//	                              info = "wrap" ‖ commit)[0:16]
//
// with u the audience's update secret (update_secret.go) and commit the
// 32 raw bytes of the signed `_standby.commit`. It is shown in the same
// 26 symbols and the same 6-5-5-5-5 groups (StandbyKeyBytes.Text), so a
// person cannot tell the two forms apart and does not need to: the app
// tries the code as typed, then unwrapped with each secret it holds, and
// the signed commitment decides which (if any) is the key.
//
// WHY A LEAKED WRAPPED CODE PLUS THE PUBLIC PACK REVEALS NOTHING. The
// reader has `wrapped` and `commit` (and the rest of the signed pack, the
// Everyone file included). The pad is HKDF keyed by u, a 32-byte secret
// that is in neither: as a PRF output under an unknown key it is
// indistinguishable from 16 random bytes, so `wrapped` is a one-time pad
// encryption of the key. The pad is used once: its input binds the commit
// and the commit is SHA-256 of the key, so one pad never covers two
// different keys, and the "wrap" label keeps it apart from every other
// pad derived from u (the note pads of the ladder use "pad"). What
// remains is the commit itself, SHA-256 over 12 random salt bytes and the
// address: guessing the 2^32 addresses needs the 2^96 salts too. The
// Everyone secret is public, which is why that audience never wraps.
//
// FALSE MATCHES. A code is used only when SHA-256("daal/standby-v1" ‖
// candidate) equals the signed commit. A plain code that also unwraps to
// a match, or a wrapped one that matches as typed, needs a pad of zero or
// a SHA-256 collision; neither happens.

import (
	"encoding/base64"
	"fmt"
)

// standbyWrapLabel is the HKDF info prefix of the wrap pad.
const standbyWrapLabel = "wrap"

// StandbyWrapPad is HKDF(u, "wrap" ‖ commit)[0:16]. commit is the
// `_standby.commit` as signed (standard base64 of 32 bytes).
func StandbyWrapPad(secret [UpdateSecretLen]byte, commit string) ([StandbyKeyLen]byte, error) {
	var pad [StandbyKeyLen]byte
	c, err := base64.StdEncoding.Strict().DecodeString(commit)
	if err != nil || len(c) != 32 {
		return pad, fmt.Errorf("%w: commit is not standard base64 of 32 bytes", ErrStandbyMalformed)
	}
	info := make([]byte, 0, len(standbyWrapLabel)+len(c))
	info = append(info, standbyWrapLabel...)
	info = append(info, c...)
	copy(pad[:], UpdateHKDF(secret[:], info, StandbyKeyLen))
	return pad, nil
}

// WrapStandbyKey is the wrapped form of k under the audience secret, for
// the standby whose commit is StandbyCommit(k).
func WrapStandbyKey(k StandbyKeyBytes, secret [UpdateSecretLen]byte) StandbyKeyBytes {
	pad, _ := StandbyWrapPad(secret, StandbyCommit(k)) // StandbyCommit is always well-formed
	return xorStandby(k, pad)
}

// UnwrapStandbyKey turns a code read as text back into the candidate
// key for the standby with this commit. The result is a CANDIDATE: use
// it only when Standby.Matches says so.
func UnwrapStandbyKey(code StandbyKeyBytes, secret [UpdateSecretLen]byte, commit string) (StandbyKeyBytes, error) {
	pad, err := StandbyWrapPad(secret, commit)
	if err != nil {
		return StandbyKeyBytes{}, err
	}
	return xorStandby(code, pad), nil
}

// MatchStandbyCode is "try plain, then unwrap": the key a typed code
// stands for on this sealed standby, or false. secret nil, or an
// audience that does not wrap (Everyone): the plain form only.
func (s *Standby) MatchStandbyCode(code StandbyKeyBytes, secret *UpdateSecret) (StandbyKeyBytes, bool) {
	if s == nil || s.Mode != StandbyModeSealed {
		return StandbyKeyBytes{}, false
	}
	if s.Matches(code) {
		return code, true
	}
	if !secret.Wraps() {
		return StandbyKeyBytes{}, false
	}
	k, err := UnwrapStandbyKey(code, secret.Secret, s.Commit)
	if err != nil || !s.Matches(k) {
		return StandbyKeyBytes{}, false
	}
	return k, true
}

func xorStandby(a StandbyKeyBytes, pad [StandbyKeyLen]byte) StandbyKeyBytes {
	var out StandbyKeyBytes
	for i := range out {
		out[i] = a[i] ^ pad[i]
	}
	return out
}
