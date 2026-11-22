package bundle

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Vectors computed independently in Python (hmac + hashlib HKDF-SHA256,
// own Crockford encoder; build/ux lane F, 2026-11-22):
//
//	root  = 00 01 … 1f, relay_pack_id = rp-0123456789abcdef0123456789abcdef
//	key   = salt 00 01 … 0b ‖ 203.0.113.20 (the `_standby` vector)
const (
	vecPackID   = "rp-0123456789abcdef0123456789abcdef"
	vecPeople   = "92b41abddf99cd530b5f2603f924f47059d1614d763b9aa012b71e39870ca072"
	vecEveryone = "0021e1088f401278348c56d9c449d97557de9106dd9ad0d2b0986655abdf34e2"
	vecPeople2  = "042011ad414559d3ba0b4d4c60725a0d261de2161222d8f800f64529f0ab9659"
	vecPad      = "6f018cd4e2ce853e3d2c23f9645338b6"
	vecPlain    = "000G40 R40M3 0E209 185WP 03H2G"
	vecWrapped  = "DW08XN Z6SE1 KJD95 57SAY MT9M8"
)

func vecRoot() []byte {
	r := make([]byte, 32)
	for i := range r {
		r[i] = byte(i)
	}
	return r
}

func vecKey(t *testing.T) StandbyKeyBytes {
	t.Helper()
	var k StandbyKeyBytes
	for i := 0; i < 12; i++ {
		k[i] = byte(i)
	}
	copy(k[12:], []byte{203, 0, 113, 20})
	if k.Text() != vecPlain {
		t.Fatalf("plain vector: %s", k.Text())
	}
	return k
}

func TestUpdateSecret_DerivationVectors(t *testing.T) {
	for aud, want := range map[string]string{
		AudiencePeople:          vecPeople,
		AudienceEveryone:        vecEveryone,
		UpdateAudiencePeople(2): vecPeople2,
	} {
		u := DeriveUpdateSecret(vecRoot(), vecPackID, aud)
		if got := hex.EncodeToString(u[:]); got != want {
			t.Errorf("%s: %s, want %s", aud, got, want)
		}
	}
	if UpdateAudiencePeople(1) != "people" || UpdateAudiencePeople(2) != "people/2" {
		t.Fatal("audience labels")
	}
}

func TestStandbyWrap_Vector(t *testing.T) {
	k := vecKey(t)
	u := DeriveUpdateSecret(vecRoot(), vecPackID, AudiencePeople)
	pad, err := StandbyWrapPad(u, StandbyCommit(k))
	if err != nil || hex.EncodeToString(pad[:]) != vecPad {
		t.Fatalf("pad %x %v", pad, err)
	}
	w := WrapStandbyKey(k, u)
	if w.Text() != vecWrapped {
		t.Fatalf("wrapped %s, want %s", w.Text(), vecWrapped)
	}
	// Same 26 symbols, same groups.
	if len(w.Text()) != len(k.Text()) || strings.Count(w.Text(), " ") != 4 {
		t.Fatal("wrapped text form differs in shape")
	}
	back, err := UnwrapStandbyKey(w, u, StandbyCommit(k))
	if err != nil || back != k {
		t.Fatalf("unwrap: %v", err)
	}
}

func TestStandbyWrap_TryPlainThenUnwrap(t *testing.T) {
	k := vecKey(t)
	sb := SealedStandby(k)
	people := &UpdateSecret{Audience: AudiencePeople, Secret: DeriveUpdateSecret(vecRoot(), vecPackID, AudiencePeople)}
	everyone := &UpdateSecret{Audience: AudienceEveryone, Secret: DeriveUpdateSecret(vecRoot(), vecPackID, AudienceEveryone)}
	other := &UpdateSecret{Audience: AudiencePeople, Secret: DeriveUpdateSecret(vecRoot(), "rp-other", AudiencePeople)}

	wrapped, _ := ParseStandbyKeyText(vecWrapped)
	plain, _ := ParseStandbyKeyText(vecPlain)

	cases := []struct {
		name   string
		code   StandbyKeyBytes
		secret *UpdateSecret
		ok     bool
	}{
		{"plain, no secret", plain, nil, true},
		{"plain, people secret", plain, people, true},
		{"wrapped, people secret", wrapped, people, true},
		{"wrapped, no secret (an older file)", wrapped, nil, false},
		{"wrapped, another relay's secret", wrapped, other, false},
		{"wrapped under people, Everyone file only", wrapped, everyone, false},
	}
	for _, c := range cases {
		got, ok := sb.MatchStandbyCode(c.code, c.secret)
		if ok != c.ok || (ok && got != k) {
			t.Errorf("%s: ok=%v", c.name, ok)
		}
	}
	// The Everyone audience never wraps, even with a code wrapped under
	// its own (public) secret.
	ew := WrapStandbyKey(k, everyone.Secret)
	if _, ok := sb.MatchStandbyCode(ew, everyone); ok {
		t.Fatal("an Everyone-wrapped code was accepted")
	}
	// An open standby takes no code at all.
	open := OpenStandby("203.0.113.20")
	if _, ok := open.MatchStandbyCode(plain, people); ok {
		t.Fatal("open standby matched a code")
	}
}

func TestUpdateSecret_MemberRoundTripAndStrictness(t *testing.T) {
	u := UpdateSecret{Audience: AudiencePeople, Secret: DeriveUpdateSecret(vecRoot(), vecPackID, AudiencePeople)}
	raw, err := MarshalUpdateSecret(u)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseUpdateSecretJSON(raw)
	if err != nil || *got != u {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{
		`{"v":2,"audience":"people","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"v":1,"audience":"friends","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"v":1,"audience":"people/1","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"v":1,"audience":"people/02","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"v":1,"audience":"people","secret":"AAAA"}`,
		`{"v":1,"audience":"people","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","x":1}`,
		`{"v":1,"audience":"people"}`,
		`[]`,
	} {
		if _, err := ParseUpdateSecretJSON([]byte(bad)); !errors.Is(err, ErrUpdateSecretMalformed) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if !UpdateAudienceOK(strings.Repeat("ab", 32)) || UpdateAudienceOK(strings.Repeat("AB", 32)) {
		t.Fatal("recipient fingerprint audience")
	}
}

func TestReadUpdateSecret_FromArchive(t *testing.T) {
	u := UpdateSecret{Audience: AudiencePeople}
	u.Secret[0] = 7
	raw, _ := MarshalUpdateSecret(u)
	zipOf := func(files map[string][]byte) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for n, d := range files {
			w, _ := zw.Create(n)
			w.Write(d)
		}
		zw.Close()
		return buf.Bytes()
	}
	got, err := ReadUpdateSecret(zipOf(map[string][]byte{"manifest.json": []byte("{}"), UpdateSecretPath: raw}))
	if err != nil || *got != u {
		t.Fatalf("%v", err)
	}
	if _, err := ReadUpdateSecret(zipOf(map[string][]byte{"manifest.json": []byte("{}")})); !errors.Is(err, ErrNoUpdateSecret) {
		t.Fatalf("absent: %v", err)
	}
	big := bytes.Repeat([]byte(" "), 2000)
	if _, err := ReadUpdateSecret(zipOf(map[string][]byte{UpdateSecretPath: big})); !errors.Is(err, ErrUpdateSecretMalformed) {
		t.Fatalf("oversized: %v", err)
	}
}
