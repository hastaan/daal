package relaypack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"daal/publisher/deploy/provider"
)

// DeriveRelayPackID derives a deterministic RelayPackID from the
// stable parts of an OperatorRecord per the FRP-4b spec §2:
//
//	SHA-256( provider | server_id | region | public_ip | sorted-families ) [:16]
//
// The id is stable across:
//   - rotation of any single candidate (because we hash the family
//     SET, not per-candidate params);
//   - reprovision that keeps the same server (server_id stable);
//   - publisher key rotation (the id is bundle-level, not key-level).
//
// The id changes when:
//   - the operator decommissions and re-provisions onto a new VPS
//     (new server_id and likely new public_ip);
//   - the operator adds or removes a candidate family.
//
// The "rp-" prefix matches the supplement examples and the FRP-1
// fixtures (e.g. rp-frp1-direct-mode-base, rp-mismatch).
func DeriveRelayPackID(rec *provider.OperatorRecord) string {
	if rec == nil {
		return ""
	}
	h := sha256.New()
	publicIP := ""
	if rec.PublicIP != nil {
		publicIP = rec.PublicIP.String()
	}
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00",
		rec.Provider, rec.ServerID, rec.Region, publicIP)
	fams := make([]string, 0, len(rec.Candidates))
	for _, c := range rec.Candidates {
		fams = append(fams, c.Family)
	}
	sort.Strings(fams)
	for _, f := range fams {
		fmt.Fprintf(h, "%s\n", f)
	}
	return "rp-" + hex.EncodeToString(h.Sum(nil)[:16])
}
