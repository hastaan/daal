package cell

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	bundle "daal/bundle-go/bundle"
)

// FRP-11 abuse-ticket + cell-internal revocation primitives.
//
// Per supplement §16.5: a reporting FRP signs an abuse ticket
// referencing the offending publisher fingerprint. The cell-admin
// FRPs (admin-quorum M-of-N independent Ed25519) review and may
// sign a cell-internal revocation that propagates through the
// membership-doc + delegation-doc chain.
//
// Both shapes are JSON-serialisable, canonical-bytes friendly, and
// admin-quorum verifiable using the same M-of-N machinery as the
// membership and delegation docs. Living here (publisher/cell)
// keeps the bundle module free of abuse-handling concerns; the
// recipient-side core/trust/cell_revocation.go (added in this
// commit) consumes the JSON and routes hits into the existing
// publisher revocation surface (V1.5.2).

// Errors specific to abuse-ticket / cell-internal revocation
// production. The recipient-side core/trust/cell_revocation.go
// produces its own widening for parse + chain-walk failure modes.
var (
	ErrAbuseTicketUnsigned   = errors.New("abuse ticket: reporter signature missing or invalid")
	ErrAbuseTicketEmpty      = errors.New("abuse ticket: revoked_publisher_fp_hex / reason / cell_id required")
	ErrRevocationDocUnsigned = errors.New("cell-internal revocation: admin-quorum signature missing")
	ErrRevocationDocEmpty    = errors.New("cell-internal revocation: revoked_publisher_fp_hex / cell_id required")
)

// AbuseTicket is the on-disk shape of one reported-abuse signal
// from a cell member to the cell admins. The reporter is itself a
// publisher in the cell; the ticket signature uses the reporter's
// publisher key (NOT the cell admin key — admins are who decide
// what to do with the ticket, not who reports).
type AbuseTicket struct {
	CellID                 string `json:"cell_id"`
	ReporterPublisherFPHex string `json:"reporter_publisher_fp_hex"`
	RevokedPublisherFPHex  string `json:"revoked_publisher_fp_hex"`
	Reason                 string `json:"reason"`
	ObservedAtUnix         int64  `json:"observed_at_unix"`
	ReporterSignatureB64   string `json:"reporter_signature_b64"`
}

// CanonicalAbuseTicketBytes returns the canonical bytes the
// reporter's signature covers. The signature field is stripped
// (it cannot cover itself).
func CanonicalAbuseTicketBytes(t AbuseTicket) ([]byte, error) {
	stripped := struct {
		CellID                 string `json:"cell_id"`
		ReporterPublisherFPHex string `json:"reporter_publisher_fp_hex"`
		RevokedPublisherFPHex  string `json:"revoked_publisher_fp_hex"`
		Reason                 string `json:"reason"`
		ObservedAtUnix         int64  `json:"observed_at_unix"`
	}{
		CellID:                 t.CellID,
		ReporterPublisherFPHex: t.ReporterPublisherFPHex,
		RevokedPublisherFPHex:  t.RevokedPublisherFPHex,
		Reason:                 t.Reason,
		ObservedAtUnix:         t.ObservedAtUnix,
	}
	return json.Marshal(stripped)
}

// SignAbuseTicket produces the reporter's signature over the
// canonical bytes.
func SignAbuseTicket(t AbuseTicket, reporterPriv ed25519.PrivateKey) (AbuseTicket, error) {
	if t.CellID == "" || t.RevokedPublisherFPHex == "" || t.Reason == "" {
		return AbuseTicket{}, ErrAbuseTicketEmpty
	}
	canonical, err := CanonicalAbuseTicketBytes(t)
	if err != nil {
		return AbuseTicket{}, err
	}
	sig := ed25519.Sign(reporterPriv, canonical)
	t.ReporterSignatureB64 = base64.RawStdEncoding.EncodeToString(sig)
	return t, nil
}

// VerifyAbuseTicket checks the reporter's signature against a
// known reporter public key. The caller obtains the reporter's
// pubkey from the cell membership doc's members[] entry.
func VerifyAbuseTicket(t AbuseTicket, reporterPub ed25519.PublicKey) error {
	if t.CellID == "" || t.RevokedPublisherFPHex == "" || t.Reason == "" {
		return ErrAbuseTicketEmpty
	}
	canonical, err := CanonicalAbuseTicketBytes(t)
	if err != nil {
		return err
	}
	sig, err := base64.RawStdEncoding.DecodeString(t.ReporterSignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrAbuseTicketUnsigned
	}
	if !ed25519.Verify(reporterPub, canonical, sig) {
		return ErrAbuseTicketUnsigned
	}
	return nil
}

// CellRevocationDoc is the cell-admin-quorum-signed revocation
// record for a publisher within the cell. Recipients consume
// this through core/trust/cell_revocation.go and feed it into the
// existing publisher-revocation surface (state.MarkRevoked) so
// every route signed by the revoked publisher is filtered.
type CellRevocationDoc struct {
	CellID                string                      `json:"cell_id"`
	RevokedPublisherFPHex string                      `json:"revoked_publisher_fp_hex"`
	Reason                string                      `json:"reason"`
	IssuedAtUnix          int64                       `json:"issued_at_unix"`
	AdminSignatures       []bundle.CellAdminSignature `json:"admin_signatures"`
}

// CanonicalCellRevocationBytes returns the canonical bytes the
// admin quorum signs over (admin_signatures stripped).
func CanonicalCellRevocationBytes(r CellRevocationDoc) ([]byte, error) {
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

// SignCellRevocation produces ONE admin signature over the
// canonical revocation bytes. The cell-admin layer collects M of
// these.
func SignCellRevocation(r CellRevocationDoc, idx int, priv ed25519.PrivateKey) (bundle.CellAdminSignature, error) {
	canonical, err := CanonicalCellRevocationBytes(r)
	if err != nil {
		return bundle.CellAdminSignature{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	return bundle.CellAdminSignature{
		AdminPubkeyIdx: idx,
		SignatureB64:   base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyCellRevocation runs the M-of-N admin quorum check on a
// cell-internal revocation against its parent membership doc.
// Mirrors VerifyCellMembershipQuorum but covers the revocation's
// canonical bytes.
func VerifyCellRevocation(memb bundle.CellMembershipDoc, r CellRevocationDoc) error {
	if r.CellID == "" || r.RevokedPublisherFPHex == "" {
		return ErrRevocationDocEmpty
	}
	if r.CellID != memb.CellID {
		return bundle.ErrCellDelegationCellIDMismatch
	}
	canonical, err := CanonicalCellRevocationBytes(r)
	if err != nil {
		return err
	}
	if len(r.AdminSignatures) < memb.QuorumM {
		return bundle.ErrCellAdminQuorumNotMet
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
		return bundle.ErrCellAdminQuorumNotMet
	}
	return nil
}
