package freshness

import (
	"encoding/json"

	bundle "daal/bundle-go/bundle"
)

// canonicalMembershipBytes serialises a membership doc preserving
// the admin_signatures field (so recipients fetching the doc from
// the cell directory can re-verify the M-of-N quorum). Differs from
// bundle.CanonicalCellMembership which strips admin_signatures for
// the SIGNED PAYLOAD; this helper produces the OUTPUT-SHAPED bytes.
func canonicalMembershipBytes(doc bundle.CellMembershipDoc) ([]byte, error) {
	return json.Marshal(doc)
}

// canonicalDelegationBytes serialises a delegation doc with the
// admin_signatures field preserved. Same rationale as above.
func canonicalDelegationBytes(doc bundle.CellDelegationDoc) ([]byte, error) {
	return json.Marshal(doc)
}
