# Static QR v1

## Status

Phase 1C deliverable. Pass-through encoding only.

## Encoding

A static QR carries exactly one of:

- A single sing-box URI: `vless://`, `vmess://`, `trojan://`, `ss://`,
  `hysteria2://`, `hy2://`, `tuic://`.
- An `https://` URL of an HTTPS subscription that returns a base64
  multi-line envelope (Iranian provider envelope).

## Cap

Library: `github.com/skip2/go-qrcode` with EC level Medium.

Maximum payload: **800 bytes** (chosen to stay below Version 20's ~858
byte byte-mode capacity at EC=M with comfortable scan margin on cheap
cameras).

`bundle/go/share.EncodeStaticQR` returns an error if `len(uri) > 800`.
Callers MUST in that case offer the user the LAN or animated-QR path.

## Receiver

The Android client scans with its camera (CameraX + ZXing) and, on
recognition of a known scheme prefix, calls
`engine_uri_import` directly. The Go core wraps the URI in a transient
single-route `.sbp` (signed by the device's per-app sharing identity)
and feeds it to the importer — exactly the same trust path as a friend
share.

## Recovery

Static QR carries no application-layer error correction. If the camera
fails to decode the QR after a reasonable number of frames, the user
falls back to the LAN or animated-QR tab.

## Privacy invariants

- The static QR contains nothing the receiver did not already volunteer
  to scan; in particular, the QR does not embed any device identifier of
  the sender. The QR is the URI the user chose to share, nothing more.
