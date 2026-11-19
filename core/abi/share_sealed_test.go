package abi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"daal/core/share"
)

// A per-person file arrives by QR as sealed bytes the importer cannot
// read. The receive path must hand them back intact (for the shell to
// unseal and verify) and must not invent a verdict for them.
func TestFountainFeedFrame_SealedFileComesBackSealed(t *testing.T) {
	sealed := append([]byte{'D', 'S', 'B', 'P', 0x00, 0x01}, bytes.Repeat([]byte("age-envelope-bytes-"), 200)...)
	tx := share.NewSenderSession("tx-sealed", sealed, 256, 7)
	const recv = "recv-sealed"
	for i := 0; i < 400; i++ {
		frame, err := tx.NextFrame()
		if err != nil {
			t.Fatalf("next frame: %v", err)
		}
		fed, err := FountainFeedFrame(recv, base64.RawURLEncoding.EncodeToString(frame))
		if err != nil {
			t.Fatalf("feed: %v", err)
		}
		var p map[string]any
		if err := json.Unmarshal([]byte(fed), &p); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if done, _ := p["done"].(bool); !done {
			if _, ok := p["sealed_b64"]; ok {
				t.Fatalf("sealed_b64 before done")
			}
			continue
		}
		if _, ok := p["verdict"]; ok {
			t.Fatalf("a sealed file must not get a verdict from the engine: %v", p["verdict"])
		}
		s, _ := p["sealed_b64"].(string)
		got, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("sealed_b64: %v", err)
		}
		if !bytes.Equal(got, sealed) {
			t.Fatalf("sealed bytes changed on the way through (%d vs %d bytes)", len(got), len(sealed))
		}
		return
	}
	t.Fatalf("fountain did not decode within 400 frames")
}
