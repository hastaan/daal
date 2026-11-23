package bundle

// update_note.go — the names, keys and pads of update notes, the micro
// note and its text forms (specs/update-ladder-v2.md §4;
// docs/update-ladder-v2.md §3.3, §4.1, §4.3). Pure: no sockets, no clock
// (every function takes the time or the epoch it needs).
//
// TWO NOTES (study §3.1). The MICRO note is the 16-byte standby key
// (salt ‖ ipv4), sealed by XOR with a pad that binds the signed
// `_standby.commit`; it needs no tag because the commitment decides
// (Standby.OpenMicroNote). The FULL note is the daal-refresh-v2
// container, sealed with XChaCha20-Poly1305 under key(c, e); that seal
// lives in package daal-bundle-go/fullnote (it needs golang.org/x/crypto,
// which this package must not import: modules that import only this
// package, the end-to-end rig's driver among them, do not carry it in
// go.sum).
// The framing it uses (buckets, the length prefix) is fixed here.
//
// NOTHING HERE ADDS TRUST. A micro candidate is used only when SHA-256
// of it is the SIGNED commitment; a full note's container is verified
// exactly as a document from any mirror (signature chain, sequence,
// not_after, pack hash) and must name the slot name(c, e). The seal adds
// secrecy only: without the audience secret u nobody can find the names
// or read the notes.
//
// THE INFO ENCODING (fixed by this file; spec §4.1):
//
//	info(purpose, c, e) = purpose ‖ 0x0A ‖ c ‖ 0x0A ‖ uint64be(e)
//	name(c, e) = base32lower(HKDF(u, info("name", c, e))[0:10])     16 chars
//	key(c, e)  = HKDF(u, info("key", c, e))[0:32]
//	pad(c, e)  = HKDF(u, info("pad", c, e) ‖ commit)[0:16]          commit: 32 raw bytes
//
// c is 1–16 of [a-z0-9] (never 0x0A), e is always 8 bytes, commit is
// always 32, so every info string parses one way. The purposes "name",
// "key", "pad" and the wrap pad's "wrap" (standby_wrap.go, info "wrap" ‖
// commit) start with different bytes, so no two derivations share an
// info string.

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Carrier labels: the `c` of every name, key and pad. A label names a
// WRITE, not a reader: proxy.golang.org, goproxy.cn, goproxy.io and
// jsDelivr all read the git-tag write and use NoteCarrierGitTag.
const (
	// NoteCarrierGitTag: the git tag write (study §4.1): micro note in
	// the tag name, full note in a file of the tagged commit.
	NoteCarrierGitTag = "gittag"
	// NoteCarrierDNS: the DNS micro-note (study §4.3): six A records.
	// Micro only; never for the Everyone audience (MicroNoteAllowed).
	NoteCarrierDNS = "dns"
)

// Epoch periods (study §3.3): 7 days where a name can be reused or
// deleted (git tag, DNS), 28 days for write-once registries.
const (
	NoteEpochWeek  = 7 * 24 * time.Hour
	NoteEpoch4Week = 28 * 24 * time.Hour
)

// Sizes.
const (
	// MicroNoteLen is the micro note: a standby key.
	MicroNoteLen = StandbyKeyLen
	// NoteNameLen is the length of name(c, e): 10 bytes in lowercase
	// unpadded base32.
	NoteNameLen = 16
	// NoteKeyLen is the length of key(c, e).
	NoteKeyLen = 32
	// MicroTagTextLen is the micro note as a tag's text: 26 lowercase
	// base32 symbols (128 bits + 2 zero bits).
	MicroTagTextLen = 26
	// DNSNoteAnswers is how many A records carry one micro note.
	DNSNoteAnswers = 6
	// DNSNoteLabelPrefixLen is how much of name(dns, e) starts each of
	// the six labels (the index digit follows).
	DNSNoteLabelPrefixLen = 12
	// MaxNoteZoneLen bounds the zone of a DNS note so the whole query
	// name (13 + 1 + zone) stays under the 101-character cap seen in
	// January 2026 (study §4.3).
	MaxNoteZoneLen = 80
)

// Full-note framing (the seal itself is daal/bundle-go/fullnote). The
// plaintext is
//
//	uint32be(len(container)) ‖ container ‖ zero bytes
//
// padded to the smallest of FullNoteBuckets that holds it; the sealed
// note is nonce(24) ‖ ciphertext(bucket) ‖ tag(16).
const (
	FullNoteNonceLen = 24
	FullNoteTagLen   = 16
	// FullNoteLenPrefix is the length prefix inside the padded plaintext.
	FullNoteLenPrefix = 4
	// MaxFullNoteContainer is the largest container a full note holds:
	// the top bucket minus the prefix.
	MaxFullNoteContainer = 64<<10 - FullNoteLenPrefix
	// MaxSealedFullNote is the largest sealed full note (bytes).
	MaxSealedFullNote = FullNoteNonceLen + 64<<10 + FullNoteTagLen
)

// FullNoteBuckets are the padded plaintext sizes (study §3.3).
var FullNoteBuckets = [3]int{4 << 10, 16 << 10, 64 << 10}

// MaxSealedFullNoteText is the longest text form (standard base64 with
// padding) of a sealed full note: what a reader bounds its read at,
// plus whatever wrapping its carrier adds. (Not 64 KiB: the top bucket
// is 64 KiB of PLAINTEXT.)
var MaxSealedFullNoteText = (MaxSealedFullNote + 2) / 3 * 4

var (
	// ErrNoteCarrier: a carrier label that is not 1–16 of [a-z0-9].
	ErrNoteCarrier = errors.New("bundle: bad note carrier label")
	// ErrNoteMalformed: a note, or its text form, does not decode.
	ErrNoteMalformed = errors.New("bundle: malformed update note")
)

var noteLabelRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// NoteCarrierLabelOK: 1–16 of [a-z0-9].
func NoteCarrierLabelOK(c string) bool { return noteLabelRe.MatchString(c) }

// NoteEpochPeriod is the epoch period of a carrier label: 7 days for
// gittag and dns (and any other label until one needs 28 days).
func NoteEpochPeriod(c string) time.Duration {
	return NoteEpochWeek
}

// NoteEpochAt is floor(unix(t) / period) for the carrier's period. A
// time before 1970 is epoch 0.
func NoteEpochAt(c string, t time.Time) uint64 {
	return epochOf(t, NoteEpochPeriod(c))
}

// NoteEpoch7 and NoteEpoch28 are the two epoch clocks.
func NoteEpoch7(t time.Time) uint64  { return epochOf(t, NoteEpochWeek) }
func NoteEpoch28(t time.Time) uint64 { return epochOf(t, NoteEpoch4Week) }

func epochOf(t time.Time, p time.Duration) uint64 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s) / uint64(p/time.Second)
}

// NoteReaderEpochs is what a reader tries at t: e, then e−1 (just e at
// epoch 0). A writer writes at NoteEpochAt only.
func NoteReaderEpochs(c string, t time.Time) []uint64 {
	e := NoteEpochAt(c, t)
	if e == 0 {
		return []uint64{0}
	}
	return []uint64{e, e - 1}
}

// noteInfo is purpose ‖ 0x0A ‖ c ‖ 0x0A ‖ uint64be(e) ‖ extra.
func noteInfo(purpose, c string, e uint64, extra []byte) ([]byte, error) {
	if !NoteCarrierLabelOK(c) {
		return nil, ErrNoteCarrier
	}
	info := make([]byte, 0, len(purpose)+1+len(c)+1+8+len(extra))
	info = append(info, purpose...)
	info = append(info, 0x0A)
	info = append(info, c...)
	info = append(info, 0x0A)
	info = binary.BigEndian.AppendUint64(info, e)
	info = append(info, extra...)
	return info, nil
}

var noteBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NoteName is name(c, e): 16 lowercase base32 characters. A full note's
// container names it as its slot.
func NoteName(u [UpdateSecretLen]byte, c string, e uint64) (string, error) {
	info, err := noteInfo("name", c, e, nil)
	if err != nil {
		return "", err
	}
	return noteBase32.EncodeToString(UpdateHKDF(u[:], info, 10)), nil
}

// NoteKey is key(c, e), the full note's AEAD key.
func NoteKey(u [UpdateSecretLen]byte, c string, e uint64) ([NoteKeyLen]byte, error) {
	var k [NoteKeyLen]byte
	info, err := noteInfo("key", c, e, nil)
	if err != nil {
		return k, err
	}
	copy(k[:], UpdateHKDF(u[:], info, NoteKeyLen))
	return k, nil
}

// NotePad is pad(c, e) for the standby whose signed commit is commit
// (standard base64 of 32 bytes, as `_standby.commit` carries it).
func NotePad(u [UpdateSecretLen]byte, c string, e uint64, commit string) ([MicroNoteLen]byte, error) {
	var pad [MicroNoteLen]byte
	raw, err := decodeCommit(commit)
	if err != nil {
		return pad, err
	}
	info, err := noteInfo("pad", c, e, raw)
	if err != nil {
		return pad, err
	}
	copy(pad[:], UpdateHKDF(u[:], info, MicroNoteLen))
	return pad, nil
}

func decodeCommit(commit string) ([]byte, error) {
	c, err := base64StdStrict(commit)
	if err != nil || len(c) != 32 {
		return nil, fmt.Errorf("%w: commit is not standard base64 of 32 bytes", ErrStandbyMalformed)
	}
	return c, nil
}

// MicroNoteAllowed is the audience rule for micro notes: on DNS only an
// audience that wraps (every audience but Everyone; UpdateSecret.Wraps)
// may write or read one, because the national resolver logs the name
// and the Everyone secret is assumed known (study §4.3). Other carriers
// take any valid audience. A writer refuses, a reader skips.
func MicroNoteAllowed(c, audience string) bool {
	if !NoteCarrierLabelOK(c) || !UpdateAudienceOK(audience) {
		return false
	}
	if c == NoteCarrierDNS {
		return audience != AudienceEveryone
	}
	return true
}

// SealMicroNote is the micro note of key k for carrier c at epoch e:
// k XOR pad(c, e, StandbyCommit(k)).
func SealMicroNote(u [UpdateSecretLen]byte, c string, e uint64, k StandbyKeyBytes) ([MicroNoteLen]byte, error) {
	pad, err := NotePad(u, c, e, StandbyCommit(k))
	if err != nil {
		return [MicroNoteLen]byte{}, err
	}
	return [MicroNoteLen]byte(xorStandby(k, pad)), nil
}

// MicroNoteCandidate is sealed XOR pad(c, e, commit): a CANDIDATE key,
// to be used only when Standby.Matches says so (OpenMicroNote does both).
func MicroNoteCandidate(u [UpdateSecretLen]byte, c string, e uint64, commit string, sealed [MicroNoteLen]byte) (StandbyKeyBytes, error) {
	pad, err := NotePad(u, c, e, commit)
	if err != nil {
		return StandbyKeyBytes{}, err
	}
	return xorStandby(StandbyKeyBytes(sealed), pad), nil
}

// OpenMicroNote opens a micro note read from carrier c at time now: it
// tries each secret (newest first, as ParseHeldUpdateSecrets returns
// them) at each reader epoch (NoteReaderEpochs) and returns the first
// candidate that this sealed standby's SIGNED commitment accepts. The
// discipline of MatchStandbyCode: nothing is used that Matches did not
// accept. Secrets the audience rule excludes on c are skipped. false:
// "nothing new" (filler, another relay's note, a planted value).
func (s *Standby) OpenMicroNote(c string, now time.Time, sealed [MicroNoteLen]byte, secrets []*UpdateSecret) (StandbyKeyBytes, *UpdateSecret, uint64, bool) {
	if s == nil || s.Mode != StandbyModeSealed {
		return StandbyKeyBytes{}, nil, 0, false
	}
	for _, u := range secrets {
		if u == nil || !MicroNoteAllowed(c, u.Audience) {
			continue
		}
		for _, e := range NoteReaderEpochs(c, now) {
			k, err := MicroNoteCandidate(u.Secret, c, e, s.Commit, sealed)
			if err == nil && s.Matches(k) {
				return k, u, e, true
			}
		}
	}
	return StandbyKeyBytes{}, nil, 0, false
}

// MicroFiller is random bytes the size and shape of a micro note: what
// a writer puts at a name before there is anything to reveal.
func MicroFiller(r io.Reader) ([MicroNoteLen]byte, error) {
	var f [MicroNoteLen]byte
	_, err := io.ReadFull(r, f[:])
	return f, err
}

// --- Git tag text form ----------------------------------------------------

// MicroTagText is the micro note (or filler) as 26 lowercase base32
// symbols (RFC 4648 alphabet a–z 2–7; the last symbol carries 3 zero
// bits), for the pre-release part of a tag name.
func MicroTagText(sealed [MicroNoteLen]byte) string {
	return noteBase32.EncodeToString(sealed[:])
}

// ParseMicroTagText is the inverse, strict: exactly 26 symbols of the
// alphabet, the unused trailing bits zero.
func ParseMicroTagText(s string) ([MicroNoteLen]byte, error) {
	var out [MicroNoteLen]byte
	if len(s) != MicroTagTextLen {
		return out, fmt.Errorf("%w: tag text length", ErrNoteMalformed)
	}
	b, err := noteBase32.DecodeString(s)
	if err != nil || len(b) != MicroNoteLen || noteBase32.EncodeToString(b) != s {
		return out, fmt.Errorf("%w: tag text", ErrNoteMalformed)
	}
	copy(out[:], b)
	return out, nil
}

// GitNoteTag is the tag a git-tag write creates (study §4.1):
// "v0.<seq>.0-<MicroTagText>". seq is the writer's counter (any value;
// a higher one sorts later in a proxy's version list). It is a valid
// Go module pre-release version.
func GitNoteTag(seq uint64, sealed [MicroNoteLen]byte) string {
	return "v0." + strconv.FormatUint(seq, 10) + ".0-" + MicroTagText(sealed)
}

// ParseGitNoteTag reads a tag (or a Go proxy version) of that shape:
// seq in canonical decimal, then exactly the 26-symbol text. false for
// any other tag (a reader skips it).
func ParseGitNoteTag(tag string) (seq uint64, sealed [MicroNoteLen]byte, ok bool) {
	rest, found := strings.CutPrefix(tag, "v0.")
	if !found {
		return 0, sealed, false
	}
	num, text, found := strings.Cut(rest, ".0-")
	if !found || num == "" || len(num) > 20 {
		return 0, sealed, false
	}
	seq, err := strconv.ParseUint(num, 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != num {
		return 0, sealed, false
	}
	sealed, err = ParseMicroTagText(text)
	if err != nil {
		return 0, sealed, false
	}
	return seq, sealed, true
}

// --- DNS text form ----------------------------------------------------------

// DNSNoteFirstOctets is the fixed list of first octets of a DNS note's
// answers: ordinary, allocated, public unicast /8s, so no answer looks
// like a private, reserved or sinkhole address (Iran's sinkhole is
// 10.10.34.x) that some resolvers drop. A writer picks one at random for
// each answer; a reader refuses an answer whose first octet is not in
// the list (that is also how a sinkholed answer is told from a note).
var DNSNoteFirstOctets = [8]byte{23, 34, 35, 52, 54, 104, 151, 199}

// DNSNoteFirstOctetOK reports whether o is in DNSNoteFirstOctets.
func DNSNoteFirstOctetOK(o byte) bool {
	for _, v := range DNSNoteFirstOctets {
		if v == o {
			return true
		}
	}
	return false
}

// DNSNoteZoneOK is the zone rule for a DNS note (the same as the
// carriers member's dns.zone; UpdateCarriers).
func DNSNoteZoneOK(zone string) bool { return noteZoneOK(zone) }

// DNSNoteNames are the six query names of the DNS note at epoch e:
// "<name(dns, e)[0:12]><i>.<zone>", i = 0..5.
func DNSNoteNames(u [UpdateSecretLen]byte, e uint64, zone string) ([DNSNoteAnswers]string, error) {
	var out [DNSNoteAnswers]string
	if !noteZoneOK(zone) {
		return out, fmt.Errorf("%w: zone", ErrNoteMalformed)
	}
	n, err := NoteName(u, NoteCarrierDNS, e)
	if err != nil {
		return out, err
	}
	for i := range out {
		out[i] = n[:DNSNoteLabelPrefixLen] + strconv.Itoa(i) + "." + zone
	}
	return out, nil
}

// DNSNoteAddresses splits a micro note (or MicroFiller) over the six A
// records: answer i carries bytes 3i..3i+2 of sealed ‖ 2 random bytes in
// its low 24 bits, and a first octet drawn from DNSNoteFirstOctets. r
// supplies the octet choices and the 2 tail bytes (crypto/rand.Reader).
func DNSNoteAddresses(sealed [MicroNoteLen]byte, r io.Reader) ([DNSNoteAnswers]net.IP, error) {
	var out [DNSNoteAnswers]net.IP
	var block [DNSNoteAnswers * 3]byte
	copy(block[:], sealed[:])
	var rnd [2 + DNSNoteAnswers]byte
	if _, err := io.ReadFull(r, rnd[:]); err != nil {
		return out, err
	}
	block[16], block[17] = rnd[0], rnd[1]
	for i := range out {
		o := DNSNoteFirstOctets[int(rnd[2+i])%len(DNSNoteFirstOctets)]
		out[i] = net.IPv4(o, block[3*i], block[3*i+1], block[3*i+2]).To4()
	}
	return out, nil
}

// DNSNoteJoin puts the six answers (in index order) back together. It
// refuses an answer that is not IPv4 or whose first octet is not in
// DNSNoteFirstOctets. The 2 tail bytes are ignored.
func DNSNoteJoin(answers [DNSNoteAnswers]net.IP) ([MicroNoteLen]byte, error) {
	var out [MicroNoteLen]byte
	var block [DNSNoteAnswers * 3]byte
	for i, a := range answers {
		v4 := a.To4()
		if v4 == nil || !DNSNoteFirstOctetOK(v4[0]) {
			return out, fmt.Errorf("%w: answer %d", ErrNoteMalformed, i)
		}
		copy(block[3*i:], v4[1:4])
	}
	copy(out[:], block[:MicroNoteLen])
	return out, nil
}

// --- Full-note framing -----------------------------------------------------

// FullNoteBucket is the padded plaintext size for a container of n
// bytes, or 0 when it does not fit.
func FullNoteBucket(n int) int {
	for _, b := range FullNoteBuckets {
		if n >= 0 && n+FullNoteLenPrefix <= b {
			return b
		}
	}
	return 0
}

// FullNoteSealedLenOK reports whether n is the length of a sealed full
// note (or of its filler) in one of the buckets.
func FullNoteSealedLenOK(n int) bool {
	for _, b := range FullNoteBuckets {
		if n == FullNoteNonceLen+b+FullNoteTagLen {
			return true
		}
	}
	return false
}

// PadFullNote frames a container: uint32be(len) ‖ container ‖ zeros, to
// its bucket.
func PadFullNote(container []byte) ([]byte, error) {
	b := FullNoteBucket(len(container))
	if b == 0 {
		return nil, fmt.Errorf("%w: container is %d bytes, at most %d", ErrNoteMalformed, len(container), MaxFullNoteContainer)
	}
	out := make([]byte, b)
	binary.BigEndian.PutUint32(out, uint32(len(container)))
	copy(out[FullNoteLenPrefix:], container)
	return out, nil
}

// UnpadFullNote is the inverse, strict: a bucket size, a length that
// fits, and only zero bytes after the container.
func UnpadFullNote(p []byte) ([]byte, error) {
	ok := false
	for _, b := range FullNoteBuckets {
		ok = ok || len(p) == b
	}
	if !ok {
		return nil, fmt.Errorf("%w: padded size", ErrNoteMalformed)
	}
	n := int(binary.BigEndian.Uint32(p))
	if n > len(p)-FullNoteLenPrefix || FullNoteBucket(n) != len(p) {
		return nil, fmt.Errorf("%w: length", ErrNoteMalformed)
	}
	var z byte
	for _, x := range p[FullNoteLenPrefix+n:] {
		z |= x
	}
	if subtle.ConstantTimeByteEq(z, 0) != 1 {
		return nil, fmt.Errorf("%w: padding", ErrNoteMalformed)
	}
	return append([]byte(nil), p[FullNoteLenPrefix:FullNoteLenPrefix+n]...), nil
}

// FullFiller is random bytes the size of a sealed full note in the
// bucket that holds a container of containerLen bytes (pass the size the
// real note will have, or 0 for the smallest bucket).
func FullFiller(containerLen int, r io.Reader) ([]byte, error) {
	b := FullNoteBucket(containerLen)
	if b == 0 {
		return nil, fmt.Errorf("%w: container too large", ErrNoteMalformed)
	}
	out := make([]byte, FullNoteNonceLen+b+FullNoteTagLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeFullNoteText is the text form of a sealed full note: standard
// base64 with padding.
func EncodeFullNoteText(sealed []byte) string { return base64Std(sealed) }

// DecodeFullNoteText is the inverse, strict (canonical standard base64)
// and bounded; the length must be a sealed note's (FullNoteSealedLenOK).
// Surrounding ASCII whitespace is trimmed; none inside is accepted.
func DecodeFullNoteText(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxSealedFullNoteText {
		return nil, fmt.Errorf("%w: too long", ErrNoteMalformed)
	}
	b, err := base64StdStrict(s)
	if err != nil || !FullNoteSealedLenOK(len(b)) {
		return nil, fmt.Errorf("%w: full note text", ErrNoteMalformed)
	}
	return b, nil
}

// base64StdStrict decodes canonical standard base64 only (no newlines,
// no non-zero trailing bits).
func base64StdStrict(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrNoteMalformed
	}
	return b, nil
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
