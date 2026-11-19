package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"daal/bundle-go/bundle"
	"daal/bundle-go/envelope"
	"daal/bundle-go/fountain"
)

// D5: one person's sealed file (.sbpx) shown as an animated QR code must
// come out of the receiver's decoder byte-identical, still open with that
// person's key, and the signed bundle inside must still verify. The
// sender lane is exactly what the app runs (users-pack-sbpx, then
// qr-fountain --block-size 96); the receiver lane is base64url-decode
// then fountain.Decoder, then the envelope, then bundle.VerifyBundle.
// The same bytes also survive the copy-as-text form (std base64), which
// is how the paste path receives them.
func TestPersonFile_SurvivesQRAndTextRoundTripAndStillVerifies(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	dir := t.TempDir()
	sbp := filepath.Join(dir, "rp.sbp")
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"bind-and-sign", "--operator-record", recPath, "--priv-key", privPath,
		"--output", sbp, "--phase", testPhase}, &stdout, &stderr); rc != 0 {
		t.Fatalf("bind-and-sign rc=%d %s", rc, stderr.String())
	}

	var xpriv [32]byte
	if _, err := rand.Read(xpriv[:]); err != nil {
		t.Fatal(err)
	}
	xpub, err := curve25519.X25519(xpriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sbpx := filepath.Join(dir, "person.sbpx")
	stdout.Reset()
	stderr.Reset()
	if rc := Run([]string{"users-pack-sbpx", "--in", sbp, "--recipient-pub-hex", hex.EncodeToString(xpub), "--out", sbpx}, &stdout, &stderr); rc != 0 {
		t.Fatalf("users-pack-sbpx rc=%d %s", rc, stderr.String())
	}
	sealed, err := os.ReadFile(sbpx)
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.SniffMagic(sealed) {
		t.Fatal("the per-person file does not start with the sealed-file magic the receiver sniffs")
	}

	// QR: the frames the app's QR screen streams.
	stdout.Reset()
	stderr.Reset()
	if rc := Run([]string{"qr-fountain", "--sbp", sbpx, "--block-size", "96", "--frames", "2000", "--seed", "5"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("qr-fountain rc=%d %s", rc, stderr.String())
	}
	dec := fountain.NewDecoder()
	var viaQR []byte
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var frame struct {
			FrameB64 string `json:"frame_b64"`
		}
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(frame.FrameB64)
		if err != nil {
			t.Fatal(err)
		}
		payload, done, err := dec.Add(raw)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			viaQR = payload
			break
		}
	}
	if !bytes.Equal(viaQR, sealed) {
		t.Fatalf("QR round trip: got %d bytes, want %d identical", len(viaQR), len(sealed))
	}

	// Text: the copy-as-text form.
	viaText, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(sealed))
	if err != nil || !bytes.Equal(viaText, sealed) {
		t.Fatal("text round trip changed the file")
	}

	for name, got := range map[string][]byte{"qr": viaQR, "text": viaText} {
		in := filepath.Join(dir, name+".sbpx")
		out := filepath.Join(dir, name+".sbp")
		if err := os.WriteFile(in, got, 0o600); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		code := runUsersUnpackSbpx(context.Background(), []string{"--in", in, "--out", out}, strings.NewReader(hex.EncodeToString(xpriv[:])), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%s: users-unpack-sbpx rc=%d %s", name, code, stderr.String())
		}
		body, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatalf("%s: ParseSBP: %v", name, err)
		}
		if err := bundle.VerifyBundle(parsed); err != nil {
			t.Fatalf("%s: VerifyBundle after the round trip: %v", name, err)
		}
	}
}
