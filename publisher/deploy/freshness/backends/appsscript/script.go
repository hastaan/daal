// Package appsscript is the Google update channel (optional add-on 3,
// docs/optional-addons-plan.md §3, specs/optional-addons-v1.md §5): a
// tiny Apps Script web app that serves the signed "the relay moved"
// note as a daal-refresh-v1 container.
//
// What lives here:
//
//   - script.go     the script (Code.gs) and its manifest, shipped in the
//     binary, with this relay's write key and path token put in;
//   - container.go  the daal-refresh-v1 container and the update MAC;
//   - appsscript.go the freshness backend (one HTTPS POST per update)
//     and the fetch-back check, done the way a recipient fetches;
//   - api.go        Path A: the four Apps Script API calls made once with
//     a one-shot access token, and the OAuth code exchange for the
//     desktop sign-in.
//
// Both setup paths end in the same state: the same script text, a web
// app deployed as "execute as me, anyone may call", its /exec URL with
// ?k=<path token>, and the write key in the publisher app's custody.
// No Google token outlives the deploy call.
//
// This directory is under publisher/deploy/freshness/backends/, which
// publisher/deploy/opsec_test.go allows to use net/http.
package appsscript

import (
	"crypto/rand"
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

const (
	writeKeyPlaceholder  = "__DAAL_WRITE_KEY_B64__"
	pathTokenPlaceholder = "__DAAL_PATH_TOKEN__"
)

// WriteKeySize is the write key's length: 32 random bytes the
// publisher's app generates (specs/relaypack-v1.md, "The update").
const WriteKeySize = 32

var pathTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// NewWriteKey returns 32 fresh random bytes.
func NewWriteKey() ([]byte, error) {
	k := make([]byte, WriteKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// NewPathToken returns 16 fresh random bytes as 22 base64url
// characters: the k of the /exec URL. It is not a secret (every pack
// carries it); it keeps the script quiet for anyone who has not got a
// pack.
func NewPathToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidPathToken reports whether t has the path token's shape.
func ValidPathToken(t string) bool { return pathTokenRe.MatchString(t) }

// Script returns Code.gs with the write key and path token put in, and
// the manifest. The same text serves Path A (uploaded through the API)
// and Path B (pasted by the publisher).
//
// The returned code carries the write key: callers must not log it.
func Script(writeKey []byte, pathToken string) (code, manifest string, err error) {
	if len(writeKey) != WriteKeySize {
		return "", "", errors.New("appsscript: write key must be 32 bytes")
	}
	if !ValidPathToken(pathToken) {
		return "", "", errors.New("appsscript: path token must be 22 base64url characters")
	}
	// Both values are from fixed alphabets with no quote or backslash,
	// so substituting them into a JavaScript string literal cannot
	// change the script's meaning.
	code = strings.Replace(codeTemplate, writeKeyPlaceholder, base64.StdEncoding.EncodeToString(writeKey), 1)
	code = strings.Replace(code, pathTokenPlaceholder, pathToken, 1)
	return code, manifestJSON, nil
}
