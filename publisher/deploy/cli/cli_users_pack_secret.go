package cli

// The update secret of a file (specs/update-ladder-v2.md §2), as the
// app hands it to users-pack-sbpx / users-pack-sbp: two members of the
// creds JSON the app already writes to a 0600 staging file and deletes
// after the call. Never a flag (argv is visible to every process on the
// machine) and never printed: stdout says only whether one was written.
//
//	"update_secret":   "<standard base64 of 32 bytes>"   the derived u
//	"update_audience": "people" | "people/<g>" | "everyone"
//
// The app derives u from its update root; this binary never sees the
// root. Both members absent: no secret (an app that predates it), and the
// file is written exactly as before.

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"daal/bundle-go/bundle"
)

// errEveryoneFileSecret: a people secret offered for the Everyone file,
// which anyone may read.
var errEveryoneFileSecret = errors.New(
	"the Everyone file may carry only the Everyone audience's update secret")

// updateSecretFromCredsFile reads the two members; nil when both are
// absent.
func updateSecretFromCredsFile(path string) (*bundle.UpdateSecret, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c struct {
		Secret   string `json:"update_secret"`
		Audience string `json:"update_audience"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if c.Secret == "" && c.Audience == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(c.Secret)
	defer zeroBytes(raw)
	if err != nil || len(raw) != bundle.UpdateSecretLen {
		// The value itself is never echoed.
		return nil, errors.New("update_secret is not standard base64 of 32 bytes")
	}
	if !bundle.UpdateAudienceOK(c.Audience) {
		return nil, fmt.Errorf("update_audience %q is not an audience", c.Audience)
	}
	u := &bundle.UpdateSecret{Audience: c.Audience}
	copy(u.Secret[:], raw)
	return u, nil
}

// errInputCarriesSecret: users-pack-sbpx without --creds-file envelopes
// the input untouched, so an update secret already in it would ride into
// the person's file. The signed .sbp never has one; refuse rather than
// pass on whatever someone put there.
var errInputCarriesSecret = errors.New(
	"the input already carries an update secret; give --creds-file so the file is rewritten for this person")

// archiveHasUpdateSecret reports whether a .sbp archive has the member
// bundle.UpdateSecretPath. A non-archive input has none.
func archiveHasUpdateSecret(sbp []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name == bundle.UpdateSecretPath {
			return true
		}
	}
	return false
}
