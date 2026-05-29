// FRP-11 cell-internal revocation walk (recipient-side).
//
// A cell-admin-quorum-signed revocation document targets a
// publisher fingerprint inside the cell. The recipient receives it
// either:
//
//   - inline at directory-fetch time (cell publisher uploaded a
//     revocations.json the recipient pulls during freshness), or
//   - bundled with a fresh cell-aggregated `.sbp` (operator chose
//     to embed pending revocations alongside the directory).
//
// Either way the recipient feeds the doc into VerifyCellRevocation
// here, then calls into the existing V1.5.2 publisher-revocation
// surface (importer.State.MarkPublisherRevoked) so every route
// signed by the revoked publisher is filtered. The cell admins'
// authority terminates AT the cell boundary — no public directory
// promotion at FRP-11 (invariant 34).
package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	bundle "daal/bundle-go/bundle"
)

// Recipient-side closed errors specific to cell revocation.
var (
	ErrCellRevocationDocMalformed   = errors.New("cell revocation: doc malformed")
	ErrCellRevocationCellIDMismatch = errors.New("cell revocation: cell_id does not match cell membership")
	ErrCellRevocationQuorumNotMet   = errors.New("cell revocation: admin-quorum signature insufficient")
)

// CellRevocationDoc is the recipient-side view of the
// publisher/cell.CellRevocationDoc type. Independent type to keep
// the module direction clean (`core → bundle`; never `core →
// publisher`).
type CellRevocationDoc struct {
	CellID                string                      `json:"cell_id"`
	RevokedPublisherFPHex string                      `json:"revoked_publisher_fp_hex"`
	Reason                string                      `json:"reason"`
	IssuedAtUnix          int64                       `json:"issued_at_unix"`
	AdminSignatures       []bundle.CellAdminSignature `json:"admin_signatures"`
}

// VerifyCellRevocation runs the admin-quorum check against the
// supplied membership doc. Returns nil iff at least QuorumM
// independent admin signatures cover the canonical revocation
// bytes. Caller routes nil-result revocations into
// importer.State.MarkPublisherRevoked.
func VerifyCellRevocation(memb bundle.CellMembershipDoc, r CellRevocationDoc) error {
	if r.CellID == "" || r.RevokedPublisherFPHex == "" {
		return ErrCellRevocationDocMalformed
	}
	if r.CellID != memb.CellID {
		return ErrCellRevocationCellIDMismatch
	}
	canonical, err := canonicalCellRevocationBytes(r)
	if err != nil {
		return ErrCellRevocationDocMalformed
	}
	if len(r.AdminSignatures) < memb.QuorumM {
		return ErrCellRevocationQuorumNotMet
	}
	seen := map[int]bool{}
	valid := 0
	for _, s := range r.AdminSignatures {
		if s.AdminPubkeyIdx < 0 || s.AdminPubkeyIdx >= len(memb.AdminPubkeys) {
			return bundle.ErrCellAdminSignatureMalformed
		}
		if seen[s.AdminPubkeyIdx] {
			return bundle.ErrCellAdminQuorumDuplicateIdx
		}
		seen[s.AdminPubkeyIdx] = true
		pkRaw, err := base64.RawStdEncoding.DecodeString(memb.AdminPubkeys[s.AdminPubkeyIdx])
		if err != nil || len(pkRaw) != ed25519.PublicKeySize {
			return bundle.ErrCellAdminPubkeyMalformed
		}
		sigRaw, err := base64.RawStdEncoding.DecodeString(s.SignatureB64)
		if err != nil || len(sigRaw) != ed25519.SignatureSize {
			return bundle.ErrCellAdminSignatureMalformed
		}
		if ed25519.Verify(ed25519.PublicKey(pkRaw), canonical, sigRaw) {
			valid++
		}
	}
	if valid < memb.QuorumM {
		return ErrCellRevocationQuorumNotMet
	}
	return nil
}

func canonicalCellRevocationBytes(r CellRevocationDoc) ([]byte, error) {
	stripped := struct {
		CellID                string `json:"cell_id"`
		RevokedPublisherFPHex string `json:"revoked_publisher_fp_hex"`
		Reason                string `json:"reason"`
		IssuedAtUnix          int64  `json:"issued_at_unix"`
	}{
		CellID:                r.CellID,
		RevokedPublisherFPHex: r.RevokedPublisherFPHex,
		Reason:                r.Reason,
		IssuedAtUnix:          r.IssuedAtUnix,
	}
	return json.Marshal(stripped)
}
