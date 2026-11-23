package gittag

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fullnote"
)

// Label is the carrier label every name, key and pad of this write uses.
const Label = bundle.NoteCarrierGitTag

// GoModCommentWidth is how many base64 characters each go.mod comment
// line carries. Readers must not depend on it: they join every comment
// line (see GoModNoteText).
const GoModCommentWidth = 64

// Writer-only derivations. Filler and the full note's nonce come from
// the audience secret, so the same publish writes the same bytes twice
// (idempotence) and nobody without u can tell them from a note. The
// purposes are this package's own; bundle's are "name", "key", "pad",
// "wrap", and the input format is bundle's (purpose ‖ 0x0A ‖ c ‖ 0x0A ‖
// uint64be(e) ‖ extra), so no output is shared with a reader's
// derivation.
const (
	purposeMicroFiller = "gittag-writer-micro-filler"
	purposeFullFiller  = "gittag-writer-full-filler"
	purposeNonce       = "gittag-writer-nonce"
)

func writerInfo(purpose string, e uint64, extra []byte) []byte {
	b := make([]byte, 0, len(purpose)+len(Label)+10+len(extra))
	b = append(b, purpose...)
	b = append(b, '\n')
	b = append(b, Label...)
	b = append(b, '\n')
	b = binary.BigEndian.AppendUint64(b, e)
	return append(b, extra...)
}

// MicroFiller is the epoch's micro filler for this audience: 16 bytes
// that look like a sealed micro note to anyone without u.
func MicroFiller(u [bundle.UpdateSecretLen]byte, e uint64) [bundle.MicroNoteLen]byte {
	var f [bundle.MicroNoteLen]byte
	copy(f[:], bundle.UpdateHKDF(u[:], writerInfo(purposeMicroFiller, e, nil), bundle.MicroNoteLen))
	return f
}

// fullFiller is the epoch's full filler for one bucket: the sealed size
// of that bucket, from an HMAC-SHA256 counter stream keyed from u.
func fullFiller(u [bundle.UpdateSecretLen]byte, e uint64, bucket int) ([]byte, error) {
	var bb [4]byte
	binary.BigEndian.PutUint32(bb[:], uint32(bucket))
	seed := bundle.UpdateHKDF(u[:], writerInfo(purposeFullFiller, e, bb[:]), 32)
	return bundle.FullFiller(bucket-bundle.FullNoteLenPrefix, &hmacStream{key: seed})
}

// hmacStream is HMAC-SHA256(key, uint64be(i)) for i = 0, 1, …
type hmacStream struct {
	key []byte
	i   uint64
	buf []byte
}

func (s *hmacStream) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(s.buf) == 0 {
			m := hmac.New(sha256.New, s.key)
			var ib [8]byte
			binary.BigEndian.PutUint64(ib[:], s.i)
			m.Write(ib[:])
			s.buf = m.Sum(nil)
			s.i++
		}
		k := copy(p[n:], s.buf)
		s.buf = s.buf[k:]
		n += k
	}
	return n, nil
}

// sealFull seals the container with a nonce derived from u, e and the
// container's hash: the same container gives the same note (and the
// same key never sees one nonce with two plaintexts).
func sealFull(u [bundle.UpdateSecretLen]byte, e uint64, container []byte) ([]byte, error) {
	h := sha256.Sum256(container)
	nonce := bundle.UpdateHKDF(u[:], writerInfo(purposeNonce, e, h[:]), bundle.FullNoteNonceLen)
	return fullnote.Seal(u, Label, e, container, bytes.NewReader(nonce))
}

// containerWire is the daal-refresh-v2 container (specs/relaypack-v1.md),
// in the member order every writer uses.
type containerWire struct {
	Kind       string `json:"kind"`
	Slot       string `json:"slot"`
	Freshness  string `json:"freshness,omitempty"`
	Pack       string `json:"pack,omitempty"`
	StandbyKey string `json:"standby_key,omitempty"`
}

const containerKind = "daal-refresh-v2"

// ErrContainer: the container to seal is not one Daal can carry.
var ErrContainer = errors.New("gittag: the container is not a daal-refresh-v2 container this write can carry")

// SlotContainer returns the container with its slot set to slot
// (bundle.NoteName(u, gittag, e)): a recipient accepts a full note only
// for the name it was found under. The parts are copied unchanged (each
// authenticates itself downstream); members other than the container's
// own are refused. commit, when non-empty, is the relay's
// _standby.commit: a standby key in the container must match it.
func SlotContainer(container []byte, slot, commit string) ([]byte, error) {
	if len(container) == 0 || len(container) > 64<<10 {
		return nil, ErrContainer
	}
	dec := json.NewDecoder(bytes.NewReader(container))
	dec.DisallowUnknownFields()
	var w containerWire
	if err := dec.Decode(&w); err != nil || dec.More() {
		return nil, ErrContainer
	}
	if w.Kind != containerKind {
		return nil, ErrContainer
	}
	if w.Freshness == "" {
		// An empty container means "nothing new": publish filler instead.
		return nil, fmt.Errorf("%w: it carries no freshness document", ErrContainer)
	}
	if w.StandbyKey != "" {
		k, err := bundle.ParseStandbyKeyText(w.StandbyKey)
		if err != nil {
			return nil, fmt.Errorf("%w: its standby key is malformed", ErrContainer)
		}
		if commit != "" && bundle.StandbyCommit(k) != commit {
			return nil, fmt.Errorf("%w: its standby key does not match the relay's commitment", ErrContainer)
		}
	}
	w.Slot = slot
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	if len(out) > bundle.MaxFullNoteContainer {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrContainer, len(out), bundle.MaxFullNoteContainer)
	}
	return out, nil
}

// RenderNote is the file n: the note's text and a newline.
func RenderNote(text string) []byte { return []byte(text + "\n") }

// RenderGoMod is the go.mod carrying the note's text in comment lines:
//
//	module github.com/<owner>/<repo>
//
//	go 1.21
//
//	// <64 base64 characters>
//	// …
func RenderGoMod(owner, repo, text string) []byte {
	var b strings.Builder
	b.WriteString(baseGoMod(owner, repo))
	b.WriteString("\n")
	for i := 0; i < len(text); i += GoModCommentWidth {
		j := min(i+GoModCommentWidth, len(text))
		b.WriteString("// ")
		b.WriteString(text[i:j])
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// GoModNoteText is the reader's side of RenderGoMod: every line that
// starts with "//", with the "//" and surrounding spaces dropped,
// joined. A reader passes it to bundle.DecodeFullNoteText. (For lane B's
// readers and the tests; the rule is in specs/update-ladder-v2.md.)
func GoModNoteText(gomod []byte) string {
	var b strings.Builder
	for _, line := range strings.Split(string(gomod), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "//"); ok {
			b.WriteString(strings.TrimSpace(rest))
		}
	}
	return b.String()
}

// Git object ids, computed here so a publish can tell, from one read of
// a commit, whether it already holds exactly these files.
func gitBlobSHA(content []byte) [20]byte {
	h := sha1.New()
	h.Write([]byte("blob " + strconv.Itoa(len(content)) + "\x00"))
	h.Write(content)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

// gitTreeSHA is the id of a tree of regular files (mode 100644), names
// sorted as git sorts them (plain byte order for files).
func gitTreeSHA(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var body bytes.Buffer
	for _, n := range names {
		id := gitBlobSHA(files[n])
		body.WriteString("100644 " + n + "\x00")
		body.Write(id[:])
	}
	h := sha1.New()
	h.Write([]byte("tree " + strconv.Itoa(body.Len()) + "\x00"))
	h.Write(body.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

// bucketOfText is the bucket of a note whose text (with or without a
// trailing newline) is n bytes long; 0 if no bucket gives that length.
func bucketOfText(n int) int {
	for _, b := range bundle.FullNoteBuckets {
		sealed := bundle.FullNoteNonceLen + b + bundle.FullNoteTagLen
		t := (sealed + 2) / 3 * 4
		if n == t || n == t+1 {
			return b
		}
	}
	return 0
}
