package fountain

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// A frame header arrives from a camera pointed at an arbitrary QR code.
// Every field in it is attacker-chosen. These are the headers that used to
// take the process down rather than return an error:
//
//   - blockSize == 0 panicked with "integer divide by zero" at the k
//     computation;
//   - payloadLen == 0xFFFFFFFF reached make([][]byte, 4294967295), i.e.
//     a 103 GB allocation and an unrecoverable "fatal error: out of
//     memory" — which no recover() can intercept.
//
// Both were reachable from an 18-character QR payload that passes the
// UI-side base64url validation in client-ui/src/recipient/frames.ts.
func TestAddRejectsHostileHeaders(t *testing.T) {
	hdr := func(payloadLen uint32, blockSize uint16, ver byte, body int) []byte {
		f := make([]byte, headerLen+body)
		binary.LittleEndian.PutUint32(f[0:4], payloadLen)
		binary.LittleEndian.PutUint16(f[4:6], blockSize)
		f[6] = ver
		return f
	}
	cases := []struct {
		name  string
		frame []byte
	}{
		{"block size zero (was: divide by zero panic)", hdr(1000, 0, version, 1)},
		{"payload len max (was: 103 GB alloc, fatal OOM)", hdr(0xFFFFFFFF, 1, version, 1)},
		{"payload len zero", hdr(0, 256, version, 256)},
		{"block size over ceiling", hdr(1000, MaxBlockSize+1, version, MaxBlockSize+1)},
		{"payload over ceiling", hdr(MaxPayloadLen+1, 256, version, 256)},
		{"k over ceiling", hdr(MaxPayloadLen, 1, version, 1)},
		{"body shorter than header claims", hdr(1000, 256, version, 4)},
		{"body longer than header claims", hdr(1000, 16, version, 64)},
		{"bad version", hdr(1000, 256, 9, 256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecoder()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			out, done, err := d.Add(tc.frame)
			if err == nil {
				t.Fatalf("accepted a hostile header: done=%v out=%d", done, len(out))
			}
			if done || out != nil {
				t.Fatalf("rejected but still reported progress: done=%v out=%v", done, out)
			}
			// A refused frame must leave the decoder untouched, so a
			// hostile frame cannot poison a session that is mid-decode.
			if d.k != 0 || d.known != nil {
				t.Fatalf("refused frame mutated decoder state: k=%d known=%v", d.k, d.known)
			}
		})
	}
}

// The exact wire strings from the reproduction, kept verbatim so a
// regression is recognisable as the same bug rather than a near miss.
// Both are valid base64url and both pass canonicalizeB64 in the UI.
func TestAddRejectsHostileWireStrings(t *testing.T) {
	for _, s := range []string{
		"6AMAAAAAAQAAAAAAAA", // blockSize = 0
		"_____wEAAQAAAAAAAA", // payloadLen = 0xFFFFFFFF, blockSize = 1
	} {
		frame, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%q is not the wire alphabet: %v", s, err)
		}
		d := NewDecoder()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%q panicked: %v", s, r)
				}
			}()
			if _, _, err := d.Add(frame); err == nil {
				t.Fatalf("%q was accepted", s)
			}
		}()
	}
}

// A hostile frame arriving mid-session must not disturb a decode that is
// already under way: the header ceilings are checked before the
// cross-frame consistency check, so the refusal has to be a no-op.
func TestHostileFrameDoesNotPoisonLiveSession(t *testing.T) {
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	enc := NewEncoder(payload, 256, 42)
	d := NewDecoder()
	if _, _, err := d.Add(enc.NextFrame()); err != nil {
		t.Fatalf("first good frame: %v", err)
	}
	k, known := d.k, len(d.known)

	bad := make([]byte, headerLen+1)
	binary.LittleEndian.PutUint32(bad[0:4], 0xFFFFFFFF)
	binary.LittleEndian.PutUint16(bad[4:6], 0)
	bad[6] = version
	if _, _, err := d.Add(bad); err == nil {
		t.Fatal("hostile frame accepted mid-session")
	}
	if d.k != k || len(d.known) != known {
		t.Fatalf("hostile frame resized a live session: k %d->%d", k, d.k)
	}

	for i := 0; i < 400; i++ {
		out, done, err := d.Add(enc.NextFrame())
		if err != nil {
			t.Fatalf("good frame %d after hostile frame: %v", i, err)
		}
		if done {
			if string(out) != string(payload) {
				t.Fatal("payload mismatch after a hostile frame was refused")
			}
			return
		}
	}
	t.Fatal("session never completed after a hostile frame was refused")
}
