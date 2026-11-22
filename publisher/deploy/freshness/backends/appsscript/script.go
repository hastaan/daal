// Package appsscript is the Google update channel (optional add-on 3,
// docs/optional-addons-plan.md §3, specs/optional-addons-v1.md §5): a
// tiny Apps Script web app, one per Google account, that serves each
// relay's signed "the relay moved" note as a daal-refresh-v2 container
// in that relay's slot.
//
// What lives here:
//
//   - script.go     the script (Code.gs) and its manifest, shipped in the
//     binary, with the account's write key put in; slots and their read
//     tokens;
//   - container.go  the daal-refresh-v2 container and the update MAC;
//   - appsscript.go the freshness backend (one HTTPS POST per update),
//     the fetch-back check done the way a recipient fetches, and the
//     account's connect check;
//   - api.go        Path A: the four Apps Script API calls made once with
//     a one-shot access token, and the OAuth code exchange for the
//     desktop sign-in.
//
// Setup is per Google account, once: the same script text, a web app
// deployed as "execute as me, anyone may call", and its /exec address
// (no query) with the write key in the publisher app's custody. A relay
// that turns the channel on gets a slot; its mirror URL is the address
// with ?s=<slot>&k=<read token>. No Google token outlives the deploy
// call.
//
// This directory is under publisher/deploy/freshness/backends/, which
// publisher/deploy/opsec_test.go allows to use net/http.
package appsscript

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

//go:embed Code.gs
var codeTemplate string

//go:embed appsscript.json
var manifestJSON string

const writeKeyPlaceholder = "__DAAL_WRITE_KEY_B64__"

// WriteKeySize is the write key's length: 32 random bytes the
// publisher's app generates (specs/relaypack-v1.md, "The update").
const WriteKeySize = 32

// TestSlot is the slot the account's connect check writes to and reads
// back. No relay is ever given it (NewSlot makes random ones).
const TestSlot = "connectTest"

var (
	slotRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
	readTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// NewWriteKey returns 32 fresh random bytes.
func NewWriteKey() ([]byte, error) {
	k := make([]byte, WriteKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// NewSlot returns 8 fresh random bytes as 11 base64url characters: one
// relay's place in the account's script.
func NewSlot() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidSlot reports whether s has a slot's shape.
func ValidSlot(s string) bool { return slotRe.MatchString(s) }

// ValidReadToken reports whether t has a read token's shape.
func ValidReadToken(t string) bool { return readTokenRe.MatchString(t) }

// ReadToken is a slot's read token, the k of its mirror URL: the first
// 16 bytes of HMAC-SHA256(write key, "daal-read-v2\n" + slot), as 22
// base64url characters. The script computes the same, so it keeps no
// list of slots. It is not a secret (every pack of that relay carries
// it); it keeps the script quiet for anyone who has not got a pack, and
// one relay's pack tells nothing of another relay's slot.
func ReadToken(writeKey []byte, slot string) string {
	m := hmac.New(sha256.New, writeKey)
	m.Write([]byte("daal-read-v2\n" + slot))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// SlotURL is the mirror URL of one slot of the script at base (the
// /exec address with no query).
func SlotURL(base string, writeKey []byte, slot string) (string, error) {
	if len(writeKey) != WriteKeySize {
		return "", errors.New("appsscript: write key must be 32 bytes")
	}
	if !ValidSlot(slot) {
		return "", errors.New("appsscript: a slot is 11 base64url characters")
	}
	if _, err := ValidateBaseURL(base); err != nil {
		return "", err
	}
	return base + "?s=" + slot + "&k=" + ReadToken(writeKey, slot), nil
}

// Script returns Code.gs with the write key put in, and the manifest.
// The same text serves Path A (uploaded through the API) and Path B
// (pasted by the publisher), and every relay of the account.
//
// The returned code carries the write key: callers must not log it.
func Script(writeKey []byte) (code, manifest string, err error) {
	if len(writeKey) != WriteKeySize {
		return "", "", errors.New("appsscript: write key must be 32 bytes")
	}
	// The value is from a fixed alphabet with no quote or backslash, so
	// substituting it into a JavaScript string literal cannot change the
	// script's meaning.
	code = strings.Replace(codeTemplate, writeKeyPlaceholder, base64.StdEncoding.EncodeToString(writeKey), 1)
	return code, manifestJSON, nil
}
