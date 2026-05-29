package share

import "encoding/base64"

func base64URLNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeFountainFrame inverts the b64url framing applied by
// EncodeFountainFrameQR.
func DecodeFountainFrame(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
