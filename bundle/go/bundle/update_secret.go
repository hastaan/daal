package bundle

// update_secret.go — the per-audience update secret
// (specs/update-ladder-v2.md §2; docs/update-ladder-v2.md §3.2).
//
// A 32-byte secret `u` that only one AUDIENCE of a relay holds: every
// file made for a named person (`people`), or the Everyone file
// (`everyone`, whose secret must be assumed known to the censor). It is
// what later lets a phone find and open a small update note nobody else
// can find, and, today, what turns the standby code a person types into
// a form that is useless without their file (standby_wrap.go).
//
// WHERE IT TRAVELS. In the archive member UpdateSecretPath of the inner
// `.sbp`, beside the per-recipient profiles: NOT in manifest.json (the
// signed skeleton, which the freshness channel republishes in the open)
// and never in EngineFamilyConfigKeys. For a person's file the whole
// `.sbp` is inside the age envelope (`.sbpx`), so the secret is in the
// encrypted per-recipient half. The Everyone file is a plain `.sbp`; its
// secret is public by construction, which is why the `everyone` audience
// never wraps a standby code.
//
// WHY AN OLD BUILD IGNORES IT. Every reader of the archive (Go ParseSBP,
// Rust bundle-rs) keeps only the members it knows by name and skips the
// rest; nothing checks the member list. So a phone on a build from before
// this member imports the file exactly as before
// (bundle/go/importer/compat_old_test.go).
//
// IT IS NOT SIGNED. Like the profiles beside it, anyone who can hand a
// phone a file can put any secret here. That buys them nothing: the
// secret only ever turns a typed code into a candidate standby key, and
// a candidate is used only when SHA-256 of it is the SIGNED commitment
// (Standby.Matches). The worst a planted secret does is make a real
// wrapped code fail to open, as a wrong credential makes a route fail to
// connect.
//
// A malformed member is ABSENT, never a refusal: the file imports and its
// standby codes work in the plain form only, as an older file does.

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// UpdateSecretPath is the archive member carrying the update secret.
const UpdateSecretPath = "update/secret.json"

// UpdateSecretVersion is the only version of the member this build reads.
const UpdateSecretVersion = 1

// UpdateSecretLen is the length of `u`.
const UpdateSecretLen = 32

// maxUpdateSecretBytes bounds the member: a real one is under 100 bytes.
const maxUpdateSecretBytes = 1024

// Audiences.
const (
	// AudiencePeople: every file made for a named person. Generation 1
	// is the label itself; generation g ≥ 2 (after a removal rotated the
	// secret) is "people/<g>" (UpdateAudiencePeople).
	AudiencePeople = "people"
	// AudienceEveryone: the Everyone file. Assumed known to the censor;
	// never wraps a standby code.
	AudienceEveryone = "everyone"
)

// updateHKDFSalt is the HKDF-Extract salt of every derivation in the
// update ladder (specs/update-ladder-v2.md §2).
const updateHKDFSalt = "daal/update-v2"

var (
	// ErrNoUpdateSecret: the file carries no update secret.
	ErrNoUpdateSecret = errors.New("bundle: no update secret in this file")
	// ErrUpdateSecretMalformed: the member is present and unusable.
	// Callers treat it as absent.
	ErrUpdateSecretMalformed = errors.New("bundle: malformed update secret")
)

// UpdateSecret is one parsed member.
type UpdateSecret struct {
	Audience string
	Secret   [UpdateSecretLen]byte
}

// updateSecretWire is the member's JSON: exactly v, audience, secret.
type updateSecretWire struct {
	V        int    `json:"v"`
	Audience string `json:"audience"`
	Secret   string `json:"secret"`
}

// UpdateSecretStoreKey is the secrets_kv key under which a device keeps
// the update secret of a route's file (the member's JSON), beside the
// route's endpoint commitment and its `_standby`.
func UpdateSecretStoreKey(routeID string) string { return "update-secret:" + routeID }

// UpdateAudiencePeople is the `people` audience label of generation g:
// "people" for g ≤ 1, "people/<g>" after.
func UpdateAudiencePeople(g int) string {
	if g <= 1 {
		return AudiencePeople
	}
	return AudiencePeople + "/" + strconv.Itoa(g)
}

// UpdateAudienceOK: "everyone", "people", "people/<g>" with g ≥ 2 in
// canonical decimal, or a recipient fingerprint (64 lowercase hex; the
// per-recipient audience the study allows).
func UpdateAudienceOK(a string) bool {
	switch {
	case a == AudienceEveryone || a == AudiencePeople:
		return true
	case strings.HasPrefix(a, AudiencePeople+"/"):
		n := a[len(AudiencePeople)+1:]
		g, err := strconv.Atoi(n)
		return err == nil && g >= 2 && strconv.Itoa(g) == n
	case len(a) == 64:
		for i := 0; i < len(a); i++ {
			c := a[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	return false
}

// Wraps reports whether this audience may wrap a standby code: every
// audience but Everyone (whose secret is public).
func (u *UpdateSecret) Wraps() bool { return u != nil && u.Audience != AudienceEveryone }

// DeriveUpdateSecret is the publisher's derivation
//
//	u = HKDF-SHA256(ikm = update_root, salt = "daal/update-v2",
//	                info = relay_pack_id ‖ 0x0A ‖ audience)[0:32]
//
// relayPackID is the id the relay had when its secret was first made;
// the publisher keeps it for the relay's life, so a rotation that
// renames the pack does not change the secret the phones hold.
func DeriveUpdateSecret(root []byte, relayPackID, audience string) [UpdateSecretLen]byte {
	info := make([]byte, 0, len(relayPackID)+1+len(audience))
	info = append(info, relayPackID...)
	info = append(info, 0x0A)
	info = append(info, audience...)
	var u [UpdateSecretLen]byte
	copy(u[:], UpdateHKDF(root, info, UpdateSecretLen))
	return u
}

// UpdateHKDF is HKDF-SHA256 (RFC 5869) with the ladder's salt: the one
// derivation every name, key and pad of specs/update-ladder-v2.md uses.
// n ≤ 255·32.
func UpdateHKDF(ikm, info []byte, n int) []byte {
	ext := hmac.New(sha256.New, []byte(updateHKDFSalt))
	ext.Write(ikm)
	prk := ext.Sum(nil)
	out := make([]byte, 0, n+sha256.Size)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	for i := range prk {
		prk[i] = 0
	}
	return out[:n]
}

// MarshalUpdateSecret is the member's bytes.
func MarshalUpdateSecret(u UpdateSecret) ([]byte, error) {
	if !UpdateAudienceOK(u.Audience) {
		return nil, fmt.Errorf("%w: audience", ErrUpdateSecretMalformed)
	}
	return json.Marshal(updateSecretWire{
		V:        UpdateSecretVersion,
		Audience: u.Audience,
		Secret:   base64.StdEncoding.EncodeToString(u.Secret[:]),
	})
}

// ParseUpdateSecretJSON reads the member (as carried, or as a device
// stored it under UpdateSecretStoreKey). The member set is exact.
func ParseUpdateSecretJSON(raw []byte) (*UpdateSecret, error) {
	bad := func(what string) (*UpdateSecret, error) {
		return nil, fmt.Errorf("%w: %s", ErrUpdateSecretMalformed, what)
	}
	if len(raw) > maxUpdateSecretBytes {
		return bad("too long")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return bad("not an object")
	}
	if len(members) != 3 {
		return bad("unexpected members")
	}
	var w updateSecretWire
	if err := json.Unmarshal(members["v"], &w.V); err != nil || w.V != UpdateSecretVersion {
		return bad("version")
	}
	if err := json.Unmarshal(members["audience"], &w.Audience); err != nil || !UpdateAudienceOK(w.Audience) {
		return bad("audience")
	}
	if err := json.Unmarshal(members["secret"], &w.Secret); err != nil {
		return bad("secret")
	}
	s, err := base64.StdEncoding.Strict().DecodeString(w.Secret)
	if err != nil || len(s) != UpdateSecretLen || base64.StdEncoding.EncodeToString(s) != w.Secret {
		return bad("secret is not standard base64 of 32 bytes")
	}
	u := &UpdateSecret{Audience: w.Audience}
	copy(u.Secret[:], s)
	for i := range s {
		s[i] = 0
	}
	return u, nil
}

// ReadUpdateSecret finds the member in a `.sbp` archive (bounded read).
// ErrNoUpdateSecret when absent, ErrUpdateSecretMalformed when unusable.
func ReadUpdateSecret(sbp []byte) (*UpdateSecret, error) {
	zr, err := zip.NewReader(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpdateSecretMalformed, err)
	}
	for _, f := range zr.File {
		if f.Name != UpdateSecretPath {
			continue
		}
		if f.UncompressedSize64 > maxUpdateSecretBytes {
			return nil, fmt.Errorf("%w: too long", ErrUpdateSecretMalformed)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUpdateSecretMalformed, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxUpdateSecretBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUpdateSecretMalformed, err)
		}
		return ParseUpdateSecretJSON(data)
	}
	return nil, ErrNoUpdateSecret
}

// MaxHeldUpdateSecrets is how many distinct wrap-capable secrets a device
// keeps for one route.
const MaxHeldUpdateSecrets = 4

// heldMembers splits what a device holds under UpdateSecretStoreKey into
// raw members: a JSON array of members, newest first, or (as the first
// build that kept one wrote it) a single member. Malformed entries are
// dropped.
func heldMembers(raw []byte) []json.RawMessage {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return nil
	}
	var list []json.RawMessage
	if t[0] == '[' {
		if err := json.Unmarshal(t, &list); err != nil {
			return nil
		}
	} else {
		list = []json.RawMessage{t}
	}
	out := list[:0]
	for _, m := range list {
		if _, err := ParseUpdateSecretJSON(m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// ParseHeldUpdateSecrets reads what a device holds for a route (see
// heldMembers), newest first. Each one is a candidate only: the signed
// commitment decides (Standby.MatchStandbyCode), so an extra or planted
// secret costs nothing but a try.
func ParseHeldUpdateSecrets(raw []byte) []*UpdateSecret {
	var out []*UpdateSecret
	for _, m := range heldMembers(raw) {
		if u, err := ParseUpdateSecretJSON(m); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// MergeHeldUpdateSecrets is what to keep for a route after a file
// carrying member `in` arrived, given what is `held`; ok is false when
// nothing changes (or `in` is unusable).
//
// THE RULES (specs/update-ladder-v2.md §2, "On the device"). Nothing
// arriving costs the phone a secret it holds: the member is not signed,
// so an older copy of one's own file, or a signed public skeleton with a
// planted member, must not replace the one that opens the next code. A
// person's secret goes first, ahead of up to MaxHeldUpdateSecrets-1
// other distinct person's secrets (the oldest is let go). An Everyone
// secret is kept only where no person's secret is held.
func MergeHeldUpdateSecrets(held, in []byte) ([]byte, bool) {
	u, err := ParseUpdateSecretJSON(in)
	if err != nil {
		return nil, false
	}
	have := heldMembers(held)
	if !u.Wraps() {
		for _, m := range have {
			if h, err := ParseUpdateSecretJSON(m); err == nil && h.Wraps() {
				return nil, false
			}
		}
		return append([]byte(nil), in...), true
	}
	keep := []json.RawMessage{json.RawMessage(bytes.TrimSpace(in))}
	for _, m := range have {
		h, err := ParseUpdateSecretJSON(m)
		if err != nil || !h.Wraps() || hmac.Equal(h.Secret[:], u.Secret[:]) {
			continue
		}
		if len(keep) == MaxHeldUpdateSecrets {
			break
		}
		keep = append(keep, m)
	}
	out, err := json.Marshal(keep)
	if err != nil {
		return nil, false
	}
	return out, true
}
