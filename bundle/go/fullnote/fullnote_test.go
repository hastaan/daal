package fullnote

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// Vector computed independently in Python: HChaCha20 written out in
// pure Python and checked against the known answer of
// draft-irtf-cfrg-xchacha-03 §2.2.1, the whole AEAD against §A.3.1's
// tag, then the IETF ChaCha20-Poly1305 of the `cryptography` package
// with the subkey (build/ux lane F, 2026-11-22). Key: key(gittag, 2968)
// of the `people` vector secret; nonce 40 41 … 57; container below,
// padded to 4 KiB.
const (
	vecPeople     = "92b41abddf99cd530b5f2603f924f47059d1614d763b9aa012b71e39870ca072"
	vecEpoch      = 2968
	vecUnix       = 1795305600
	vecContainer  = `{"kind":"daal-refresh-v2","slot":"x"}`
	vecSealedSHA  = "9f93800b695e3e89456d5bc4f3fad1ebc111a1f98b004c47ba40ef52e6fbcdee"
	vecSealedTag  = "f5be064af25dbd117ba7ec1e49a364d1"
	vecSealedHead = "404142434445464748494a4b4c4d4e4f505152535455565785fe4bff653ffabf5e21c8dc96f91505f285e99efcaff47c376b752ac6f626d6"
)

func vecSecret(t *testing.T) *bundle.UpdateSecret {
	t.Helper()
	b, _ := hex.DecodeString(vecPeople)
	u := &bundle.UpdateSecret{Audience: bundle.AudiencePeople}
	copy(u.Secret[:], b)
	return u
}

func vecNonce() []byte {
	n := make([]byte, 24)
	for i := range n {
		n[i] = byte(0x40 + i)
	}
	return n
}

func TestSeal_Vector(t *testing.T) {
	u := vecSecret(t)
	sealed, err := Seal(u.Secret, bundle.NoteCarrierGitTag, vecEpoch, []byte(vecContainer), bytes.NewReader(vecNonce()))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	if len(sealed) != 4136 || hex.EncodeToString(sum[:]) != vecSealedSHA ||
		hex.EncodeToString(sealed[len(sealed)-16:]) != vecSealedTag ||
		hex.EncodeToString(sealed[:56]) != vecSealedHead {
		t.Fatalf("sealed %d %x", len(sealed), sum)
	}
	got, err := OpenWith(u.Secret, bundle.NoteCarrierGitTag, vecEpoch, sealed)
	if err != nil || string(got) != vecContainer {
		t.Fatalf("open: %q %v", got, err)
	}
}

func TestOpen_TriesHeldSecretsAndTwoEpochs(t *testing.T) {
	u := vecSecret(t)
	other := &bundle.UpdateSecret{Audience: bundle.AudiencePeople}
	other.Secret[0] = 9
	now := time.Unix(vecUnix, 0)
	for _, e := range []uint64{vecEpoch, vecEpoch - 1} {
		sealed, _ := Seal(u.Secret, bundle.NoteCarrierGitTag, e, []byte(vecContainer), rand.Reader)
		o, err := Open(bundle.NoteCarrierGitTag, now, sealed, []*bundle.UpdateSecret{other, u})
		if err != nil || string(o.Container) != vecContainer || o.Epoch != e || o.Secret != u {
			t.Fatalf("e=%d: %+v %v", e, o, err)
		}
		want, _ := bundle.NoteName(u.Secret, bundle.NoteCarrierGitTag, e)
		if o.Slot != want {
			t.Fatalf("slot %s", o.Slot)
		}
	}
	old, _ := Seal(u.Secret, bundle.NoteCarrierGitTag, vecEpoch-2, []byte(vecContainer), rand.Reader)
	if _, err := Open(bundle.NoteCarrierGitTag, now, old, []*bundle.UpdateSecret{u}); !errors.Is(err, ErrOpen) {
		t.Fatalf("e-2: %v", err)
	}
	// Another carrier's key, filler, a flipped bit, a wrong size.
	dns, _ := Seal(u.Secret, bundle.NoteCarrierDNS, vecEpoch, []byte(vecContainer), rand.Reader)
	fill, _ := bundle.FullFiller(len(vecContainer), rand.Reader)
	flip, _ := Seal(u.Secret, bundle.NoteCarrierGitTag, vecEpoch, []byte(vecContainer), rand.Reader)
	flip[100] ^= 1
	for name, s := range map[string][]byte{"dns": dns, "filler": fill, "flipped": flip} {
		if _, err := Open(bundle.NoteCarrierGitTag, now, s, []*bundle.UpdateSecret{u}); !errors.Is(err, ErrOpen) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := Open(bundle.NoteCarrierGitTag, now, fill[:100], []*bundle.UpdateSecret{u}); !errors.Is(err, bundle.ErrNoteMalformed) {
		t.Fatalf("short: %v", err)
	}
	// Filler and a note of the same container are the same size.
	if len(fill) != len(dns) {
		t.Fatal("filler size")
	}
}

func TestSeal_Buckets(t *testing.T) {
	u := vecSecret(t)
	for n, want := range map[int]int{10: 4 << 10, 5000: 16 << 10, 40000: 64 << 10} {
		s, err := Seal(u.Secret, bundle.NoteCarrierGitTag, 1, make([]byte, n), rand.Reader)
		if err != nil || len(s) != 24+want+16 {
			t.Fatalf("%d: %d %v", n, len(s), err)
		}
	}
	if _, err := Seal(u.Secret, bundle.NoteCarrierGitTag, 1, make([]byte, bundle.MaxFullNoteContainer+1), rand.Reader); err == nil {
		t.Fatal("too large")
	}
}
