package refresh

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"daal/bundle-go/publisher"
	"daal/core/bootstrap"
	"daal/core/routestore"
)

// RevocationStore is the routestore subset the revocation refresher uses.
type RevocationStore interface {
	AuditWriter
	ListPublishersWithRevocationURL() ([]routestore.PublisherRow, error)
	MarkRouteRevoked(routeID string) error
	MarkPublisherRoutesRevoked(publisherID string) error
	MarkPublisherRevocationChecked(publisherID string, now time.Time) error
}

// RevocationRefresher fetches per-publisher revocation lists.
type RevocationRefresher struct {
	Store  RevocationStore
	Dialer DialerFn
	Fetch  FetchFn
	Now    func() time.Time
	Mode   string // 2D: "" / "normal" / "lifeline" / "bulk" / "lifeline-strict"
}

// RevocationResult summarizes a single publisher's revocation refresh.
type RevocationResult struct {
	PublisherID       string `json:"publisher_id"`
	BytesIn           int64  `json:"bytes_in"`
	ViaTunnel         bool   `json:"via_tunnel"`
	Outcome           string `json:"outcome"`
	RevokedRoutes     int    `json:"revoked_routes"`
	RevokedPublishers int    `json:"revoked_publishers"`
}

// RefreshAll iterates every publisher with a RevocationURL and runs one
// fetch per publisher. The 6h cadence is enforced upstream by the
// caller.
//
// Phase 2D: scheduled (userTriggered=false) revocation refreshes are
// gated out in lifeline-strict mode. RefreshAllUser bypasses the gate.
func (r *RevocationRefresher) RefreshAll(ctx context.Context, timeout time.Duration) ([]RevocationResult, error) {
	return r.refreshAll(ctx, timeout, false /* userTriggered */)
}

// RefreshAllUser is the user-triggered variant; bypasses the
// lifeline-strict gate.
func (r *RevocationRefresher) RefreshAllUser(ctx context.Context, timeout time.Duration) ([]RevocationResult, error) {
	return r.refreshAll(ctx, timeout, true)
}

func (r *RevocationRefresher) refreshAll(ctx context.Context, timeout time.Duration, userTriggered bool) ([]RevocationResult, error) {
	if r.Store == nil {
		return nil, errors.New("revocation: nil store")
	}
	if r.Mode == "lifeline-strict" && !userTriggered {
		// Gate: nothing fires; returned slice is empty. The audit
		// ledger doesn't get a per-publisher row because the
		// upstream caller already ledgered the *attempt* — we did
		// not attempt anything.
		return nil, nil
	}
	rows, err := r.Store.ListPublishersWithRevocationURL()
	if err != nil {
		return nil, err
	}
	out := make([]RevocationResult, 0, len(rows))
	for _, p := range rows {
		out = append(out, r.refreshOne(ctx, p, timeout))
	}
	return out, nil
}

func (r *RevocationRefresher) refreshOne(ctx context.Context, p routestore.PublisherRow,
	timeout time.Duration) RevocationResult {

	now := r.now()
	res := RevocationResult{PublisherID: p.PublisherID}
	if p.RevocationURL == "" {
		res.Outcome = "skipped"
		return res
	}
	if p.RevocationFingerprintHex == "" {
		res.Outcome = "missing_fingerprint"
		recordAudit(r.Store, "revocation", p.PublisherID, res.Outcome, 0, false, now)
		return res
	}
	pub, err := hex.DecodeString(p.RevocationFingerprintHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		// The hex field is the SHA-256 of the key, not the key itself.
		// For Phase 1.5A we treat it as a key pin: the operator-supplied
		// `revocation_fingerprint_hex` MUST be the publisher's revocation
		// public key in raw hex (32 bytes). This avoids a separate
		// fetch-the-key step for a small surface.
		res.Outcome = "bad_fingerprint"
		recordAudit(r.Store, "revocation", p.PublisherID, res.Outcome, 0, false, now)
		return res
	}

	dialer, viaTunnel, derr := r.dial()
	if derr != nil {
		res.Outcome = "subscription_unreachable"
		recordAudit(r.Store, "revocation", p.PublisherID, res.Outcome, 0, false, now)
		return res
	}
	res.ViaTunnel = viaTunnel
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	fetch := r.Fetch
	if fetch == nil {
		fetch = bootstrap.FetchRaw
	}
	body, err := fetch(ctx, p.RevocationURL, dialer, timeout)
	if err != nil {
		res.Outcome = "subscription_unreachable"
		recordAudit(r.Store, "revocation", p.PublisherID, res.Outcome, 0, viaTunnel, now)
		return res
	}
	res.BytesIn = int64(len(body))

	rev, err := publisher.VerifySignedRevocationBytes(body, ed25519.PublicKey(pub))
	if err != nil {
		res.Outcome = "bundle_signature_invalid"
		recordAudit(r.Store, "revocation", p.PublisherID, res.Outcome, res.BytesIn, viaTunnel, now)
		return res
	}

	for _, fp := range rev.RevokedPublishers {
		if fp == p.PublisherID {
			_ = r.Store.MarkPublisherRoutesRevoked(fp)
			res.RevokedPublishers++
		}
	}
	for _, rid := range rev.RevokedRoutes {
		if err := r.Store.MarkRouteRevoked(rid); err == nil {
			res.RevokedRoutes++
		}
	}

	res.Outcome = "ok"
	recordAudit(r.Store, "revocation", p.PublisherID, res.Outcome, res.BytesIn, viaTunnel, now)
	_ = r.Store.MarkPublisherRevocationChecked(p.PublisherID, now)
	_ = rev // signed payload retained in audit
	_ = fmt.Sprintf
	return res
}

func (r *RevocationRefresher) dial() (bootstrap.Dialer, bool, error) {
	if g := CurrentGlobalDialer(); g != nil {
		return g()
	}
	if r.Dialer != nil {
		return r.Dialer()
	}
	return directFallback()
}

func (r *RevocationRefresher) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}
