package share

import (
	"errors"

	qrcode "github.com/skip2/go-qrcode"
)

// QRStaticCap is the maximum byte payload we accept in a single static QR.
// Version 20 with low EC holds ~858 bytes in byte mode; we cap at 800 to
// leave headroom for a comfortable scan on cheap cameras.
const QRStaticCap = 800

// EncodeStaticQR returns a PNG of the QR code containing the given URI.
// Returns an error if the URI is too long to fit comfortably; callers
// should switch to animated/fountain QR or LAN at that point.
func EncodeStaticQR(uri string, sizePx int) ([]byte, error) {
	if len(uri) == 0 {
		return nil, errors.New("share: empty URI")
	}
	if len(uri) > QRStaticCap {
		return nil, errors.New("share: URI too long for static QR; use fountain or LAN")
	}
	q, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	q.DisableBorder = false
	if sizePx <= 0 {
		sizePx = 512
	}
	return q.PNG(sizePx)
}

// EncodeFountainFrameQR turns one fountain frame (binary) into a QR PNG.
// Frames are base64url-encoded so QR alphanumeric fallback is allowed; the
// receiver decodes base64url before feeding fountain.Decoder.
func EncodeFountainFrameQR(frame []byte, sizePx int) ([]byte, error) {
	if len(frame) == 0 {
		return nil, errors.New("share: empty frame")
	}
	q, err := qrcode.New(b64urlEncode(frame), qrcode.Low)
	if err != nil {
		return nil, err
	}
	if sizePx <= 0 {
		sizePx = 512
	}
	return q.PNG(sizePx)
}

func b64urlEncode(b []byte) string {
	return base64URLNoPad(b)
}
