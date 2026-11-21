package appsscript

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// fakeDoc is a freshness document as far as the container reads one.
func fakeDoc(seq uint64, pack []byte) []byte {
	sum := sha256.Sum256(pack)
	b, _ := json.Marshal(map[string]any{
		"kind":                  "daal/freshness-v2",
		"sequence":              seq,
		"current_bundle_sha256": hex.EncodeToString(sum[:]),
		"signature_hex":         strings.Repeat("ab", 64),
	})
	return b
}

// The vector was computed outside Go (Python's hmac), so a change to
// the message layout breaks this test, not just both sides together.
func TestMACVector(t *testing.T) {
	got := MAC(testKey(), 1763600000, []byte(`{"kind":"daal-refresh-v1"}`))
	const want = "bb7fca8a54bb2a3e5f3cf61ce82ea773e2e42ab38bfebabd14c0b493ed7ee731"
	if got != want {
		t.Fatalf("MAC = %s, want %s", got, want)
	}
}

func TestBuildParseRoundTrip(t *testing.T) {
	pack := []byte("signed credential-less pack bytes")
	doc := fakeDoc(42, pack)
	key := "0123456789ABCDEFGHJKMNPQRR" // the last symbol's two padding bits are zero
	blob, err := Build(doc, pack, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Freshness, doc) || !bytes.Equal(p.Pack, pack) || p.StandbyKey != key {
		t.Fatalf("round trip lost a part: %+v", p)
	}
	if seq, _ := DocSequence(doc); seq != 42 {
		t.Fatalf("sequence %d", seq)
	}
}

func TestBuildRefusesAPackTheDocumentDoesNotName(t *testing.T) {
	doc := fakeDoc(1, []byte("the pack that was signed"))
	if _, err := Build(doc, []byte("somebody's personal file"), ""); err == nil {
		t.Fatal("a pack the document does not name must be refused")
	}
}

func TestBuildLimits(t *testing.T) {
	if _, err := Build(nil, nil, ""); err == nil {
		t.Error("no document")
	}
	big := bytes.Repeat([]byte("x"), MaxPack+1)
	if _, err := Build(fakeDoc(1, big), big, ""); !errors.Is(err, ErrPackTooLarge) {
		t.Errorf("oversized pack: %v", err)
	}
	// A pack under MaxPack whose base64 still overflows the container.
	near := bytes.Repeat([]byte("y"), MaxPack-10)
	if _, err := Build(fakeDoc(1, near), near, ""); !errors.Is(err, ErrPackTooLarge) {
		t.Errorf("container over 64 KiB: %v", err)
	}
	if _, err := Build(fakeDoc(1, nil), nil, "not-a-key"); err == nil {
		t.Error("malformed standby key")
	}
	if _, err := Build([]byte(`{"kind":"x"}`), nil, ""); err == nil {
		t.Error("a document with no sequence")
	}
}

func TestParse(t *testing.T) {
	p, err := Parse(Empty())
	if err != nil || p.Freshness != nil {
		t.Fatalf("the empty container is 'nothing new': %+v %v", p, err)
	}
	// Unknown members are ignored.
	if _, err := Parse([]byte(`{"kind":"daal-refresh-v1","later":1}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`not json`,
		`{"kind":"daal-refresh-v2"}`,
		`{"kind":"daal-refresh-v1","pack":"AAAA"}`,
		`{"kind":"daal-refresh-v1","freshness":"!!!"}`,
		`{"kind":"daal-refresh-v1","freshness":"e30=","standby_key":"lower-case-not-crockford00"}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	huge := append([]byte(`{"kind":"daal-refresh-v1","x":"`), bytes.Repeat([]byte("a"), MaxContainer)...)
	if _, err := Parse(append(huge, '"', '}')); err == nil {
		t.Error("over 64 KiB")
	}
}

func TestUpdateBody(t *testing.T) {
	b, err := UpdateBody(testKey(), 7, []byte(`{"kind":"daal-refresh-v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var u struct {
		Seq  uint64 `json:"seq"`
		Blob string `json:"blob"`
		MAC  string `json:"mac"`
	}
	if err := json.Unmarshal(b, &u); err != nil || u.Seq != 7 || u.MAC != MAC(testKey(), 7, []byte(u.Blob)) {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := UpdateBody(testKey(), 0, nil); err == nil {
		t.Error("seq 0")
	}
	if _, err := UpdateBody(testKey(), 1<<53, nil); err == nil {
		t.Error("seq past what the script can read")
	}
	if _, err := UpdateBody([]byte("short"), 1, nil); err == nil {
		t.Error("short key")
	}
}

// ADD-1: the key as `standby promote` prints it (grouped, any case) is
// carried, in the one canonical form a recipient's reader accepts; a
// key whose trailing bits are not zero is refused.
func TestBuildTakesTheStandbyKeyAsThePublisherHoldsIt(t *testing.T) {
	var k bundle.StandbyKeyBytes
	for i := range k {
		k[i] = byte(i*37 + 11)
	}
	shown := k.Text() // "XXXXXX XXXXX XXXXX XXXXX XXXXX"
	canon := strings.ReplaceAll(shown, " ", "")
	doc := fakeDoc(7, nil)
	for _, in := range []string{shown, canon, strings.ToLower(shown), strings.ReplaceAll(shown, " ", "-")} {
		blob, err := Build(doc, nil, in)
		if err != nil {
			t.Fatalf("%q refused: %v", in, err)
		}
		p, err := Parse(blob)
		if err != nil || p.StandbyKey != canon {
			t.Fatalf("%q carried as %q (%v), want %q", in, p.StandbyKey, err, canon)
		}
	}
	bad := []byte(canon)
	bad[25] = 'Z' // the last symbol's two low bits are padding
	if _, err := Build(doc, nil, string(bad)); err == nil {
		t.Fatal("a key with non-zero trailing bits was carried")
	}
}
