package bundle

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Vectors computed independently in Python (stdlib hmac/hashlib HKDF,
// own info encoding and base32; build/ux lane F, 2026-11-22). u is the
// `people` vector of standby_wrap_test.go, the key the `_standby` vector,
// t = 2026-11-22T00:00:00Z (unix 1795305600, epoch7 2968, epoch28 742).
const (
	vecNoteUnix      = 1795305600
	vecNoteEpoch     = 2968
	vecGitName       = "tvkj5326y3wnq2dr"
	vecGitKey        = "cbb7c0a356c427f587020ae06d2db1eb6b1674f3f682a5f1df58ce584359b9e1"
	vecGitPad        = "c8e3e01ffff968c9b996464973ecc06b"
	vecGitSealed     = "c8e2e21cfbfc6eceb19f4c42b8ecb17f"
	vecGitTag        = "v0.7.0-zdroehh37rxm5mm7jrblr3frp4"
	vecDNSName       = "h5vbe4rwqtnl4xcu"
	vecDNSPad        = "e79b33bc5e41c35d784dd9b650105aae"
	vecDNSSealed     = "e79a31bf5a44c55a7044d3bd9b102bba"
	vecEveryoneGitNm = "xay52jfi2iavjgwa"
)

var vecDNSAnswers = [6]string{"23.231.154.49", "34.191.90.68", "35.197.90.112", "52.68.211.189", "54.155.16.43", "104.186.238.255"}

func vecU(t *testing.T, hexs string) [UpdateSecretLen]byte {
	t.Helper()
	var u [UpdateSecretLen]byte
	b, _ := hex.DecodeString(hexs)
	copy(u[:], b)
	return u
}

func vecStandby(t *testing.T) (*Standby, StandbyKeyBytes) {
	k := vecKey(t)
	s := SealedStandby(k)
	return &s, k
}

func TestNoteVectors(t *testing.T) {
	u := vecU(t, vecPeople)
	now := time.Unix(vecNoteUnix, 0)
	if e := NoteEpochAt(NoteCarrierGitTag, now); e != vecNoteEpoch {
		t.Fatalf("epoch %d", e)
	}
	if e := NoteEpoch28(now); e != 742 {
		t.Fatalf("epoch28 %d", e)
	}
	sb, k := vecStandby(t)
	check := func(what, got, want string) {
		t.Helper()
		if got != want {
			t.Fatalf("%s = %s, want %s", what, got, want)
		}
	}
	n, _ := NoteName(u, NoteCarrierGitTag, vecNoteEpoch)
	check("name(gittag)", n, vecGitName)
	key, _ := NoteKey(u, NoteCarrierGitTag, vecNoteEpoch)
	check("key(gittag)", hex.EncodeToString(key[:]), vecGitKey)
	pad, _ := NotePad(u, NoteCarrierGitTag, vecNoteEpoch, sb.Commit)
	check("pad(gittag)", hex.EncodeToString(pad[:]), vecGitPad)
	sealed, _ := SealMicroNote(u, NoteCarrierGitTag, vecNoteEpoch, k)
	check("sealed(gittag)", hex.EncodeToString(sealed[:]), vecGitSealed)
	check("tag", GitNoteTag(7, sealed), vecGitTag)

	n, _ = NoteName(u, NoteCarrierDNS, vecNoteEpoch)
	check("name(dns)", n, vecDNSName)
	pad, _ = NotePad(u, NoteCarrierDNS, vecNoteEpoch, sb.Commit)
	check("pad(dns)", hex.EncodeToString(pad[:]), vecDNSPad)
	sealed, _ = SealMicroNote(u, NoteCarrierDNS, vecNoteEpoch, k)
	check("sealed(dns)", hex.EncodeToString(sealed[:]), vecDNSSealed)
	names, err := DNSNoteNames(u, vecNoteEpoch, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	for i, q := range names {
		check("dns name", q, "h5vbe4rwqtnl"+string(rune('0'+i))+".example.org")
	}
	ans, err := DNSNoteAddresses(sealed, bytes.NewReader([]byte{0xee, 0xff, 0, 1, 2, 3, 4, 5}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ans {
		check("dns answer", ans[i].String(), vecDNSAnswers[i])
	}
	back, err := DNSNoteJoin(ans)
	if err != nil || back != sealed {
		t.Fatalf("join: %x %v", back, err)
	}

	ev, _ := NoteName(vecU(t, vecEveryone), NoteCarrierGitTag, vecNoteEpoch)
	check("name(everyone)", ev, vecEveryoneGitNm)
}

func TestMicroNote_OpensOnlyThroughTheCommitment(t *testing.T) {
	u := vecU(t, vecPeople)
	sb, k := vecStandby(t)
	people := &UpdateSecret{Audience: AudiencePeople, Secret: u}
	other := &UpdateSecret{Audience: AudiencePeople, Secret: vecU(t, vecPeople2)}
	now := time.Unix(vecNoteUnix, 0)

	for _, at := range []time.Time{now, now.Add(-NoteEpochWeek)} {
		sealed, _ := SealMicroNote(u, NoteCarrierGitTag, NoteEpochAt(NoteCarrierGitTag, at), k)
		got, by, _, ok := sb.OpenMicroNote(NoteCarrierGitTag, now, sealed, []*UpdateSecret{other, people})
		if !ok || got != k || by != people {
			t.Fatalf("at %v: %v %v", at, ok, by)
		}
	}
	// Two epochs back: not tried.
	old, _ := SealMicroNote(u, NoteCarrierGitTag, vecNoteEpoch-2, k)
	if _, _, _, ok := sb.OpenMicroNote(NoteCarrierGitTag, now, old, []*UpdateSecret{people}); ok {
		t.Fatal("e-2 opened")
	}
	// Another carrier's note, filler, a wrong secret, an open standby.
	dns, _ := SealMicroNote(u, NoteCarrierDNS, vecNoteEpoch, k)
	fill, _ := MicroFiller(rand.Reader)
	for name, s := range map[string][MicroNoteLen]byte{"other carrier": dns, "filler": fill} {
		if _, _, _, ok := sb.OpenMicroNote(NoteCarrierGitTag, now, s, []*UpdateSecret{people}); ok {
			t.Fatalf("%s opened", name)
		}
	}
	g, _ := SealMicroNote(u, NoteCarrierGitTag, vecNoteEpoch, k)
	if _, _, _, ok := sb.OpenMicroNote(NoteCarrierGitTag, now, g, []*UpdateSecret{other}); ok {
		t.Fatal("wrong secret opened")
	}
	open := OpenStandby("203.0.113.20")
	if _, _, _, ok := open.OpenMicroNote(NoteCarrierGitTag, now, g, []*UpdateSecret{people}); ok {
		t.Fatal("open standby opened")
	}
	// DNS: the Everyone audience is skipped, a person's opens.
	ev := &UpdateSecret{Audience: AudienceEveryone, Secret: u}
	if _, _, _, ok := sb.OpenMicroNote(NoteCarrierDNS, now, dns, []*UpdateSecret{ev}); ok {
		t.Fatal("everyone opened a dns note")
	}
	if _, _, _, ok := sb.OpenMicroNote(NoteCarrierDNS, now, dns, []*UpdateSecret{people}); !ok {
		t.Fatal("people did not open the dns note")
	}
}

func TestMicroNoteAllowed(t *testing.T) {
	for _, tc := range []struct {
		c, a string
		ok   bool
	}{
		{NoteCarrierDNS, AudiencePeople, true},
		{NoteCarrierDNS, UpdateAudiencePeople(3), true},
		{NoteCarrierDNS, AudienceEveryone, false},
		{NoteCarrierGitTag, AudienceEveryone, true},
		{NoteCarrierGitTag, "nobody", false},
		{"Bad", AudiencePeople, false},
	} {
		if MicroNoteAllowed(tc.c, tc.a) != tc.ok {
			t.Fatalf("%+v", tc)
		}
	}
}

func TestNoteInfo_LabelsAndEpochs(t *testing.T) {
	u := vecU(t, vecPeople)
	for _, c := range []string{"", "Git", "a\nb", "abcdefghijklmnopq"} {
		if _, err := NoteName(u, c, 1); !errors.Is(err, ErrNoteCarrier) {
			t.Fatalf("%q: %v", c, err)
		}
	}
	a, _ := NoteName(u, NoteCarrierGitTag, 1)
	b, _ := NoteName(u, NoteCarrierGitTag, 2)
	d, _ := NoteName(u, NoteCarrierDNS, 1)
	if a == b || a == d || len(a) != NoteNameLen {
		t.Fatal("names do not separate")
	}
	if got := NoteReaderEpochs(NoteCarrierGitTag, time.Unix(0, 0)); len(got) != 1 || got[0] != 0 {
		t.Fatalf("epoch 0: %v", got)
	}
	if NoteEpoch7(time.Unix(-5, 0)) != 0 {
		t.Fatal("negative time")
	}
	if _, err := NotePad(u, NoteCarrierGitTag, 1, "not a commit"); err == nil {
		t.Fatal("bad commit")
	}
}

func TestGitNoteTag_Strict(t *testing.T) {
	var s [MicroNoteLen]byte
	for i := range s {
		s[i] = byte(i * 17)
	}
	tag := GitNoteTag(12, s)
	seq, got, ok := ParseGitNoteTag(tag)
	if !ok || seq != 12 || got != s {
		t.Fatalf("%s: %v %d", tag, ok, seq)
	}
	text := MicroTagText(s)
	for _, bad := range []string{
		"v1.0.0", "v0.12.0", "v0.012.0-" + text, "v0..0-" + text, "v0.12.0-" + strings.ToUpper(text),
		"v0.12.0-" + text + "a", "v0.12.0-" + text[:25], "v0.12.1-" + text,
		"v0.12.0-" + text[:25] + "b", // non-zero trailing bits
	} {
		if _, _, ok := ParseGitNoteTag(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestDNSNote_RefusesOtherAddresses(t *testing.T) {
	var s [MicroNoteLen]byte
	ans, _ := DNSNoteAddresses(s, rand.Reader)
	for i := range ans {
		if !DNSNoteFirstOctetOK(ans[i][0]) {
			t.Fatalf("first octet %v", ans[i])
		}
	}
	sink := ans
	sink[2] = net.IPv4(10, 10, 34, 36)
	if _, err := DNSNoteJoin(sink); err == nil {
		t.Fatal("sinkhole answer accepted")
	}
	v6 := ans
	v6[0] = net.ParseIP("2001:db8::1")
	if _, err := DNSNoteJoin(v6); err == nil {
		t.Fatal("v6 accepted")
	}
	if _, err := DNSNoteNames(vecU(t, vecPeople), 1, "Example.org"); err == nil {
		t.Fatal("upper-case zone")
	}
	long := strings.Repeat("a", 70) + ".example.org"
	if _, err := DNSNoteNames(vecU(t, vecPeople), 1, long); err == nil {
		t.Fatal("long zone")
	}
}

func TestFullNoteFraming(t *testing.T) {
	for _, n := range []int{0, 1, 4092, 4093, 16380, 16381, MaxFullNoteContainer} {
		c := bytes.Repeat([]byte{'x'}, n)
		p, err := PadFullNote(c)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if p2, _ := UnpadFullNote(p); !bytes.Equal(p2, c) {
			t.Fatalf("%d: round trip", n)
		}
		f, _ := FullFiller(n, rand.Reader)
		if !FullNoteSealedLenOK(len(f)) || len(f) != FullNoteNonceLen+len(p)+FullNoteTagLen {
			t.Fatalf("%d: filler %d", n, len(f))
		}
	}
	if _, err := PadFullNote(make([]byte, MaxFullNoteContainer+1)); err == nil {
		t.Fatal("too large")
	}
	p, _ := PadFullNote([]byte("abc"))
	p[len(p)-1] = 1
	if _, err := UnpadFullNote(p); err == nil {
		t.Fatal("non-zero padding")
	}
	p, _ = PadFullNote(make([]byte, 5000)) // 16 KiB bucket
	p[0], p[1], p[2], p[3] = 0, 0, 0, 3    // claims a 4 KiB container
	if _, err := UnpadFullNote(p); err == nil {
		t.Fatal("length in the wrong bucket")
	}
	f, _ := FullFiller(0, rand.Reader)
	txt := EncodeFullNoteText(f)
	if b, err := DecodeFullNoteText(" " + txt + "\n"); err != nil || !bytes.Equal(b, f) {
		t.Fatal("text round trip")
	}
	for _, bad := range []string{txt[:len(txt)-4], txt[:100] + "\n" + txt[100:], "!!" + txt[2:]} {
		if _, err := DecodeFullNoteText(bad); err == nil {
			t.Fatal("bad text accepted")
		}
	}
	if len(EncodeFullNoteText(make([]byte, MaxSealedFullNote))) != MaxSealedFullNoteText {
		t.Fatal("max text")
	}
}
