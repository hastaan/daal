package fountain

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRoundTripSmall(t *testing.T) {
	payload := []byte("hello fountain code in a small payload")
	enc := NewEncoder(payload, 16, 42)
	dec := NewDecoder()
	for i := 0; i < 200; i++ {
		out, ok, err := dec.Add(enc.NextFrame())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if ok {
			if !bytes.Equal(out, payload) {
				t.Fatalf("payload mismatch: got %q", out)
			}
			t.Logf("decoded after %d frames (k=%d)", i+1, enc.SourceBlocks())
			return
		}
	}
	t.Fatalf("did not decode within 200 frames")
}

func TestRoundTrip4KB(t *testing.T) {
	payload := make([]byte, 4096)
	rand.Read(payload)
	enc := NewEncoder(payload, 256, 7)
	dec := NewDecoder()
	frames := 0
	for {
		frames++
		if frames > 1000 {
			t.Fatalf("did not decode within 1000 frames (k=%d)", enc.SourceBlocks())
		}
		out, ok, err := dec.Add(enc.NextFrame())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if ok {
			if !bytes.Equal(out, payload) {
				t.Fatalf("payload mismatch")
			}
			k := enc.SourceBlocks()
			t.Logf("decoded after %d frames; k=%d; oversample=%.2fx", frames, k, float64(frames)/float64(k))
			if frames > 3*k {
				t.Errorf("oversample too high: %d frames for k=%d", frames, k)
			}
			return
		}
	}
}

func TestProgress(t *testing.T) {
	payload := make([]byte, 1024)
	rand.Read(payload)
	enc := NewEncoder(payload, 64, 1)
	dec := NewDecoder()
	got, total := dec.Progress()
	if got != 0 || total != 0 {
		t.Errorf("initial progress: %d/%d", got, total)
	}
	for i := 0; i < 5; i++ {
		dec.Add(enc.NextFrame())
	}
	got, total = dec.Progress()
	if total != 16 {
		t.Errorf("k mismatch: %d", total)
	}
	if got > total {
		t.Errorf("progress > total")
	}
}

func TestBadFrameRejected(t *testing.T) {
	dec := NewDecoder()
	_, _, err := dec.Add([]byte{0, 0, 0, 0, 0})
	if err == nil {
		t.Errorf("expected error on tiny frame")
	}
}

func TestVersionMismatch(t *testing.T) {
	dec := NewDecoder()
	bad := make([]byte, headerLen+8)
	bad[6] = 99
	_, _, err := dec.Add(bad)
	if err == nil {
		t.Errorf("expected version error")
	}
}
