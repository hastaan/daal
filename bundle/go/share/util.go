package share

import "encoding/base64"

func base64URLNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
