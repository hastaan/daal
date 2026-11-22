package cli

// The carriers member of a person's file (specs/update-ladder-v2.md
// §4.5): WHERE that person's phone reads update notes. The app hands it
// to users-pack-sbpx in the creds JSON it already writes (0600 staging
// file, deleted after the call), as one more member:
//
//	"update_carriers": {"v":1, "gittag": {"owner": "...", "repo": "..."}, "dns": {"zone": "..."}}
//
// every carrier optional, exactly the shape of the archive member
// (bundle.ParseUpdateCarriersJSON, strict). Absent or null: no member,
// and the file is written exactly as before. Never a flag, never printed
// (it names the publisher's repository and zone): stdout says only
// "update_carriers": true|false.
//
// Rules this binary enforces:
//   - only with a wrapping update secret (a person's audience) in the
//     same creds: without u the phone can find no note, and the carriers
//     would tell a file's reader where the publisher writes for nothing;
//   - never in the Everyone file (users-pack-sbp): it is public, and the
//     repository and zone would be public with it;
//   - users-pack-sbpx without --creds-file refuses an input that already
//     carries the member, as it does for the secret.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"daal/bundle-go/bundle"
)

var (
	errEveryoneFileCarriers = errors.New(
		"the Everyone file may not carry update carriers (they would be public)")
	errCarriersNeedSecret = errors.New(
		"update_carriers needs a person's update_secret in the same creds")
	errInputCarriesCarriers = errors.New(
		"the input already carries update carriers; give --creds-file so the file is rewritten for this person")
)

// updateCarriersFromCredsFile reads the member; nil when absent or null.
func updateCarriersFromCredsFile(path string) (*bundle.UpdateCarriers, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c struct {
		Carriers json.RawMessage `json:"update_carriers"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(c.Carriers) == 0 || string(c.Carriers) == "null" {
		return nil, nil
	}
	got, err := bundle.ParseUpdateCarriersJSON(c.Carriers)
	if err != nil {
		// The value is not echoed.
		return nil, errors.New("update_carriers is malformed (see specs/update-ladder-v2.md §4.5)")
	}
	return got, nil
}

// archiveHasMember reports whether a .sbp archive has a member of that
// name. A non-archive input has none.
func archiveHasMember(sbp []byte, name string) bool {
	zr, err := zip.NewReader(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name == name {
			return true
		}
	}
	return false
}
