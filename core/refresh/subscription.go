package refresh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"daal/bundle-go/importer"
	"daal/bundle-go/publisher"
	"daal/core/bootstrap"
	"daal/core/routestore"
)

// Store is the subset of routestore.Store the Refresher uses. It is an
// interface so tests can inject a stub without spinning up sqlite.
type Store interface {
	AuditWriter
	GetSecret(key string) ([]byte, error)
	PutSecret(key string, value []byte) error
	GetSubscription(id string) (routestore.SubscriptionRow, error)
	UpsertSubscription(r routestore.SubscriptionRow) error
	ListSubscriptions() ([]routestore.SubscriptionRow, error)
	DeleteSubscription(id string) error
}

// DialerFn returns a Dialer to use for a fetch. The Refresher calls it
// once per fetch so callers can decide tunnel-vs-direct based on current
// engine state.
type DialerFn func() (bootstrap.Dialer, bool /* viaTunnel */, error)

// FetchFn fetches the body at url through dialer (or nil for direct).
// The default is bootstrap.FetchRaw. Tests inject a stub so they don't
// need a TLS server.
type FetchFn func(ctx context.Context, url string, dialer bootstrap.Dialer, timeout time.Duration) ([]byte, error)

// Refresher is the long-lived owner of subscription + revocation
// refresh. It holds no goroutines; the ABI layer (or a host scheduler)
// drives ticks.
//
// Phase 2D: the `Mode` field gates *scheduled* refresh in
// lifeline-strict — the gate is bypassed when the caller passes
// userTriggered=true through RefreshUser. The default zero-value
// `""` is treated as "normal" and bypasses the gate entirely so
// pre-2D callers behave identically.
type Refresher struct {
	Store    Store
	Identity Identity
	Adapter  importer.State
	Dialer   DialerFn
	Fetch    FetchFn
	Now      func() time.Time
	Mode     string // "" / "normal" / "lifeline" / "bulk" / "lifeline-strict"
}

// SkippedLifelineStrict is the outcome string recorded in the audit
// ledger when a scheduled refresh is gated out by lifeline-strict
// mode. NOT a failure; the audit row's `outcome` column carries it
// and the soak-rig invariants explicitly allow it.
const SkippedLifelineStrict = "skipped_lifeline_strict"

// shouldFireRefresh returns true iff a refresh attempt should
// proceed. The gate fires only in lifeline-strict mode.
func (r *Refresher) shouldFireRefresh(userTriggered bool) bool {
	if r.Mode != "lifeline-strict" {
		return true
	}
	return userTriggered
}

// AddInput is the user-facing payload for "add a subscription".
type AddInput struct {
	PublisherID string // pinned publisher this subscription belongs to
	URL         string // never logged
	DisplayName string
}

// AddResult is returned to the UI after a successful add.
type AddResult struct {
	SubscriptionID string `json:"subscription_id"`
}

// Add stores the subscription URL in the age-encrypted KV and creates a
// new subscriptions row. The URL is NEVER logged.
func (r *Refresher) Add(in AddInput) (AddResult, error) {
	if r.Store == nil {
		return AddResult{}, errors.New("refresher: nil store")
	}
	if in.PublisherID == "" {
		return AddResult{}, errors.New("refresher: publisher_id required")
	}
	if in.URL == "" {
		return AddResult{}, errors.New("refresher: url required")
	}
	id, err := newSubscriptionID()
	if err != nil {
		return AddResult{}, err
	}
	urlKey := "subscription-url:" + id
	if err := r.Store.PutSecret(urlKey, []byte(in.URL)); err != nil {
		return AddResult{}, fmt.Errorf("refresher: persist url: %w", err)
	}
	row := routestore.SubscriptionRow{
		SubscriptionID:   id,
		PublisherID:      in.PublisherID,
		DisplayName:      in.DisplayName,
		URLSecretKey:     urlKey,
		ProfileUpdateMin: 1440,
		ImportedAt:       r.now().UTC().Format(time.RFC3339),
	}
	if err := r.Store.UpsertSubscription(row); err != nil {
		return AddResult{}, fmt.Errorf("refresher: persist row: %w", err)
	}
	return AddResult{SubscriptionID: id}, nil
}

// Remove deletes a subscription and its URL secret. The associated
// imported routes are NOT removed by this call — the user manages them
// via the existing route delete affordance.
func (r *Refresher) Remove(subscriptionID string) error {
	return r.Store.DeleteSubscription(subscriptionID)
}

// RefreshResult summarizes a Refresh call for the UI / CLI.
type RefreshResult struct {
	SubscriptionID string `json:"subscription_id"`
	Format         string `json:"format"`
	RouteCount     int    `json:"route_count"`
	BytesIn        int64  `json:"bytes_in"`
	ViaTunnel      bool   `json:"via_tunnel"`
	Outcome        string `json:"outcome"`
	Verdict        string `json:"verdict_kind,omitempty"`
}

// Refresh runs one full subscription refresh:
//  1. Load the subscription row + decrypted URL.
//  2. Fetch (tunnel-first if available, else direct) via the same TLS
//     primitive that core/bootstrap uses.
//  3. Parse the body with ParseSubscriptionBody.
//  4. Wrap into a synthetic .sbp signed by the device delegate key.
//  5. Hand to the importer.
//  6. Write the audit row.
//
// On any failure, the previous "last good" route set in the routestore
// is left untouched. Phase 1.5A's atomic-cache invariant is provided by
// the importer's existing single-transaction UPSERT.
func (r *Refresher) Refresh(ctx context.Context, subscriptionID string, timeout time.Duration) (RefreshResult, error) {
	return r.refresh(ctx, subscriptionID, timeout, false /* userTriggered */)
}

// RefreshUser is the user-triggered refresh — bypasses the
// lifeline-strict gate. Wired into engine_subscription_refresh.
func (r *Refresher) RefreshUser(ctx context.Context, subscriptionID string, timeout time.Duration) (RefreshResult, error) {
	return r.refresh(ctx, subscriptionID, timeout, true /* userTriggered */)
}

func (r *Refresher) refresh(ctx context.Context, subscriptionID string, timeout time.Duration, userTriggered bool) (RefreshResult, error) {
	now := r.now()
	res := RefreshResult{SubscriptionID: subscriptionID}

	if !r.shouldFireRefresh(userTriggered) {
		// Phase 2D: gated out by lifeline-strict. Record the skip
		// in the audit ledger and return a non-error result; the
		// caller treats this as "did not attempt". Subscription
		// row's last_refresh_outcome is updated so diagnostics
		// reflects the skip.
		row, err := r.Store.GetSubscription(subscriptionID)
		if err == nil {
			recordAudit(r.Store, "subscription", subscriptionID, SkippedLifelineStrict, 0, false, now)
			_ = r.markOutcome(row, now, SkippedLifelineStrict)
		}
		res.Outcome = SkippedLifelineStrict
		return res, nil
	}

	row, err := r.Store.GetSubscription(subscriptionID)
	if err != nil {
		return res, fmt.Errorf("refresher: load subscription: %w", err)
	}
	urlBytes, err := r.Store.GetSecret(row.URLSecretKey)
	if err != nil {
		return res, fmt.Errorf("refresher: load url: %w", err)
	}
	if len(urlBytes) == 0 {
		return res, errors.New("refresher: missing url secret")
	}

	dialer, viaTunnel, err := r.dial()
	if err != nil {
		recordAudit(r.Store, "subscription", subscriptionID, "subscription_unreachable", 0, false, now)
		_ = r.markOutcome(row, now, "subscription_unreachable")
		return res, err
	}
	res.ViaTunnel = viaTunnel

	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	fetch := r.Fetch
	if fetch == nil {
		fetch = bootstrap.FetchRaw
	}
	body, err := fetch(ctx, string(urlBytes), dialer, timeout)
	if err != nil {
		recordAudit(r.Store, "subscription", subscriptionID, "subscription_unreachable", 0, viaTunnel, now)
		_ = r.markOutcome(row, now, "subscription_unreachable")
		return res, fmt.Errorf("refresher: fetch: %w", err)
	}
	res.BytesIn = int64(len(body))

	parsed, err := ParseSubscriptionBody(body, row.DisplayName)
	if err != nil {
		recordAudit(r.Store, "subscription", subscriptionID, "bundle_corrupted", res.BytesIn, viaTunnel, now)
		_ = r.markOutcome(row, now, "bundle_corrupted")
		return res, fmt.Errorf("refresher: parse: %w", err)
	}
	res.Format = parsed.Format
	res.RouteCount = len(parsed.Routes)

	sbp, err := BuildSyntheticSubscriptionBundle(parsed, r.Identity, row.DisplayName, subscriptionID, now)
	if err != nil {
		recordAudit(r.Store, "subscription", subscriptionID, "bundle_corrupted", res.BytesIn, viaTunnel, now)
		_ = r.markOutcome(row, now, "bundle_corrupted")
		return res, fmt.Errorf("refresher: synthetic: %w", err)
	}

	v, err := importer.ImportBytes(sbp, r.Adapter, publisher.DefaultWordlists(), now)
	res.Verdict = verdictKindString(v.Kind)
	if err != nil {
		recordAudit(r.Store, "subscription", subscriptionID, "import_failed", res.BytesIn, viaTunnel, now)
		_ = r.markOutcome(row, now, "import_failed")
		return res, fmt.Errorf("refresher: import: %w", err)
	}

	res.Outcome = "ok"
	recordAudit(r.Store, "subscription", subscriptionID, "ok", res.BytesIn, viaTunnel, now)
	_ = r.markOutcomeOK(row, now)
	return res, nil
}

// RefreshAll iterates every subscription and refreshes it.
func (r *Refresher) RefreshAll(ctx context.Context, timeout time.Duration) []RefreshResult {
	rows, err := r.Store.ListSubscriptions()
	if err != nil {
		return nil
	}
	out := make([]RefreshResult, 0, len(rows))
	for _, row := range rows {
		res, _ := r.Refresh(ctx, row.SubscriptionID, timeout)
		out = append(out, res)
	}
	return out
}

func (r *Refresher) dial() (bootstrap.Dialer, bool, error) {
	// The process-wide override (installed via SetGlobalDialer) wins
	// because it represents the host's authoritative view of "are we
	// connected through the tunnel right now." Only fall back to the
	// Refresher's own Dialer field if the override is unset.
	if g := CurrentGlobalDialer(); g != nil {
		return g()
	}
	if r.Dialer != nil {
		return r.Dialer()
	}
	return directFallback()
}

func (r *Refresher) markOutcome(row routestore.SubscriptionRow, now time.Time, outcome string) error {
	row.LastRefreshBucket = routestore.HourBucket(now)
	row.LastRefreshOutcome = outcome
	return r.Store.UpsertSubscription(row)
}

func (r *Refresher) markOutcomeOK(row routestore.SubscriptionRow, now time.Time) error {
	row.LastRefreshBucket = routestore.HourBucket(now)
	row.LastRefreshOutcome = "ok"
	row.LastGoodRefreshBkt = routestore.HourBucket(now)
	return r.Store.UpsertSubscription(row)
}

func (r *Refresher) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func newSubscriptionID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sub_" + hex.EncodeToString(b[:]), nil
}

func verdictKindString(k importer.VerdictKind) string {
	switch k {
	case importer.VerdictImported:
		return "imported"
	case importer.VerdictTrustPromptNeeded:
		return "trust_prompt_needed"
	case importer.VerdictRotationAccepted:
		return "rotation_accepted"
	case importer.VerdictRejected:
		return "rejected"
	}
	return "unknown"
}
