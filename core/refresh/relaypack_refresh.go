// relaypack_refresh.go is the caller core/refresh/relaypack.go never
// had: the thing that notices a publisher has rotated, fetches the new
// signed pack, and applies it — over the network, without a courier.
//
// It is the recipient half of Step 8. The publisher half writes a
// signed freshness document to N storage providers; this walks them.
//
// THE SHAPE OF ONE ATTEMPT
//
//	resolve endpoints   mirror set (signed, from the pack or from the
//	                    last verified document) ∪ the legacy scalar,
//	                    de-duplicated by host
//	shuffle             crypto/rand, every attempt, so no host is the
//	                    fleet's "primary" and a censor watching one
//	                    provider sees ~1/N of a publisher's recipients
//	dial once           through refresh.dial() — the SAME path the
//	                    subscription and revocation refreshers use, so
//	                    Wave 1's fail-closed guard applies here by
//	                    construction rather than by remembering to
//	                    check
//	walk                per-URL timeout, bounded total budget; a
//	                    blackholed first host costs one timeout, not
//	                    the attempt
//	verify              signature first, policy after: publisher
//	                    fingerprint, pack id, monotonic sequence,
//	                    signed expiry
//	compare             digest equal → done, no bundle fetch. This is
//	                    the common case and it keeps the request small
//	                    and constant
//	apply               fetch the signed .sbp, re-check it belongs to
//	                    THIS publisher and does not re-home another
//	                    publisher's routes, then hand to the importer's
//	                    atomic swap
//	recover             every endpoint dead → hand off to the
//	                    bootstrap-pointer layer, which is the only
//	                    thing left that can deliver a NEW endpoint set
//
// WHAT AN OBSERVER LEARNS, STATED PLAINLY
//
//   - Correlation. Every device fetching this host+path is a recipient
//     of the same publisher. That is inherent to a shared fixed
//     endpoint. N mirrors in randomised order splits the observation
//     across providers; it does not remove it. What removes it is not
//     polling in the clear — see the tunnel note below.
//   - Timing. The cadence is a fingerprint, and it is the one an
//     observer gets for free. It is owned by core/scheduler
//     (15-minute floor, 6-hour staleness ceiling, 5-minute BASE retry
//     gap) and by the tick pump that drives it. Two properties matter
//     and neither was there before this wave: every due time carries a
//     per-device random offset drawn from crypto/rand and persisted
//     beside the stamps, so devices holding the same pack do not share
//     a lattice; and the retry gap DOUBLES per consecutive failure up
//     to the staleness ceiling, so a device whose mirrors are all
//     blocked gets quieter instead of settling into a fixed-period
//     beacon from its real address — which is what a flat 5-minute
//     retry made it, in exactly the situation this file exists for.
//   - Size. The document is padded publisher-side to a fixed bucket, so
//     an observer cannot read "the object changed size today" as "a
//     rotation is in flight" and time an IP block to it. We cap reads
//     at 64 KB, which is above the bucket and below anything that could
//     be used to make us buffer.
//
// AND THE INTERACTION WITH WAVE 1's FAIL-CLOSED GUARD, precisely:
//
//   - Route ACTIVE + tunnel dialer installed → the poll rides the
//     tunnel; ViaTunnel is true and the audit row says so.
//   - Route ACTIVE + no tunnel dialer (today's Android without the
//     inlet) → refresh.ErrTunnelRequired. The fetch does NOT happen.
//     We record a failure stamp so the retry backoff applies and the
//     device does not re-attempt every tick, and we do NOT fall
//     through to the pointer layer, because that would be a direct
//     dial wearing a different name.
//   - No route active → a direct fetch is permitted. This is also the
//     case freshness exists for: the relay is burned, so the recipient
//     is fetching the recovery document in the clear, from its real
//     address, at the moment its traffic is most interesting. Every
//     mitigation available lives in that window — mirrors on
//     high-traffic shared providers, randomised order, constant object
//     size — and none of them makes the fetch invisible. The guard is
//     not weakened here to make the feature work.

package refresh

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/bundle-go/publisher"
	"daal/core/bootstrap"
	"daal/core/internal/selection"
	"daal/core/routestore"
	"daal/core/trust"
)

// RelayPackStore is the routestore subset the RelayPack refresher
// uses. Interface, not the concrete store, so tests do not need
// sqlite and so the ABI can inject an adapter.
type RelayPackStore interface {
	AuditWriter
	GetSecret(key string) ([]byte, error)
	PutSecret(key string, value []byte) error
	ListRoutes() ([]routestore.RouteRow, error)
}

// Audit kind for every row this file writes.
const auditKindFreshness = "freshness"

// Outcome strings. They are the only observability this path has on a
// device with no logs, so they are specific: "it failed" is not a
// diagnosis, and the difference between "every mirror is blocked" and
// "the publisher's document expired" is the difference between a
// censorship event and a publisher who stopped publishing.
const (
	OutcomeFreshnessOK           = "ok"
	OutcomeFreshnessUnchanged    = "ok_unchanged"
	OutcomeFreshnessNoEndpoints  = "freshness_no_endpoints"
	OutcomeFreshnessRateLimited  = "skipped_rate_limited"
	OutcomeFreshnessTunnel       = "tunnel_required"
	OutcomeFreshnessUnreachable  = "freshness_unreachable"
	OutcomeFreshnessRejected     = "freshness_rejected"
	OutcomeFreshnessBundleFetch  = "bundle_unreachable"
	OutcomeFreshnessBundleReject = "bundle_rejected"
	OutcomeFreshnessRebind       = "route_publisher_rebind"
	OutcomeFreshnessAmbiguous    = "relaypack_ambiguous"
	OutcomeFreshnessRecovery     = "pointer_recovery"
	OutcomeFreshnessImportFailed = "import_failed"
)

// Defaults for the walk. PerURL is short because a blocked host in
// Iran fails by timeout, not by RST, and the whole point of N mirrors
// is that the first one being a black hole costs one slot rather than
// the attempt. Total bounds the worst case so a scheduler tick cannot
// be occupied indefinitely by one pack.
const (
	defaultPerURLTimeout    = 8 * time.Second
	defaultTotalBudget      = 30 * time.Second
	defaultBundleTimeout    = 25 * time.Second
	maxFreshnessDocBytes    = 64 * 1024
	maxFreshnessBundleBytes = 8 << 20
)

// RelayPackRefresher polls freshness endpoints and applies the packs
// they point at. It holds no goroutines; the scheduler drives it.
type RelayPackRefresher struct {
	Store   RelayPackStore
	Adapter importer.State
	Dialer  DialerFn
	Fetch   FetchFn
	Now     func() time.Time
	Mode    string // "" / "normal" / "lifeline" / "bulk" / "lifeline-strict"

	// Policy is the FRP-8 trigger policy. The scheduler already gates
	// on it; we re-check here so a host that drives Refresh directly
	// (a UI button, a soak rig, a future ABI verb) cannot bypass the
	// floor and turn the endpoint into a per-tap beacon.
	Policy selection.FreshnessPolicy

	PerURLTimeout time.Duration
	TotalBudget   time.Duration

	// Recover is the bootstrap-pointer fallback, invoked only when
	// every endpoint failed AND the failure was not the tunnel guard.
	// nil means "no recovery layer wired" — the refresh simply fails,
	// which is honest.
	Recover func(ctx context.Context) (string, error)
}

// RelayPackTarget is one refreshable pack.
type RelayPackTarget struct {
	RelayPackID string
	// PublisherID is the pinned publisher fingerprint hex. Every
	// route of the pack must agree on it; if they do not, the pack is
	// ambiguous and is refused rather than guessed.
	PublisherID string
	Endpoints   []string
	// Providers is the number of DISTINCT hosts in Endpoints. One is
	// a real weakness and the UI must be able to say so.
	Providers int
}

// RelayPackResult summarises one refresh attempt.
type RelayPackResult struct {
	RelayPackID    string `json:"relay_pack_id"`
	Outcome        string `json:"outcome"`
	ViaTunnel      bool   `json:"via_tunnel"`
	BytesIn        int64  `json:"bytes_in"`
	EndpointsTried int    `json:"endpoints_tried"`
	Providers      int    `json:"providers"`
	Changed        bool   `json:"changed"`
	Applied        bool   `json:"applied"`
	Verdict        string `json:"verdict_kind,omitempty"`
	Recovered      bool   `json:"pointer_recovery_attempted"`
}

// freshnessRecord is the persisted per-pack state. Stored in
// secrets_kv (age-encrypted like every other secret) under
// freshnessKey(relayPackID).
//
// HighWaterSequence is the load-bearing field: rollback protection
// held only in memory protects a process, not a device, and the
// device is what an adversary gets to restart.
type freshnessRecord struct {
	V                   int               `json:"v"`
	LastSuccessAt       string            `json:"last_success_at,omitempty"`
	LastFailureAt       string            `json:"last_failure_at,omitempty"`
	LastOutcome         string            `json:"last_outcome,omitempty"`
	CurrentBundleSHA256 string            `json:"current_bundle_sha256,omitempty"`
	HighWaterSequence   uint64            `json:"high_water_sequence,omitempty"`
	Mirrors             []FreshnessMirror `json:"mirrors,omitempty"`

	// ConsecutiveFailures drives the escalating retry gap. Reset to
	// zero by a success.
	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`

	// JitterMillis is the persisted random offset added to every due
	// time for this pack, redrawn on every stamped attempt. It lives
	// here rather than being drawn at decision time because the
	// scheduler's projection and the trigger policy are two gates
	// that must produce the same instant, and because the policy is
	// Position B (no randomness, no clocks).
	JitterMillis int64 `json:"jitter_ms,omitempty"`
}

// jitterOffset renders the persisted jitter as a Duration.
func (f freshnessRecord) jitterOffset() time.Duration {
	if f.JitterMillis <= 0 {
		return 0
	}
	return time.Duration(f.JitterMillis) * time.Millisecond
}

// drawJitter picks a fresh offset in [0, MaxJitter) using crypto/rand
// — the same source ShuffleEndpoints uses, and for the same reason:
// a predictable schedule is a fingerprint, and math/rand seeded from
// a device clock is predictable to anyone who can observe two fetches.
//
// A failure to read the RNG yields zero, which is the pre-jitter
// behaviour: louder, never earlier than the un-jittered floor, and
// never a crash on a device that is already in trouble.
func drawJitter(maxJitter time.Duration) int64 {
	if maxJitter <= 0 {
		return 0
	}
	max := big.NewInt(maxJitter.Milliseconds())
	if max.Sign() <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0
	}
	return n.Int64()
}

func freshnessKey(relayPackID string) string { return "freshness:" + relayPackID }

func (r *RelayPackRefresher) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *RelayPackRefresher) policy() selection.FreshnessPolicy {
	p := r.Policy
	d := selection.DefaultPolicy()
	if p.MinInterval <= 0 {
		p.MinInterval = d.MinInterval
	}
	if p.MaxStaleness <= 0 {
		p.MaxStaleness = d.MaxStaleness
	}
	if p.RetryBackoff <= 0 {
		p.RetryBackoff = d.RetryBackoff
	}
	if p.MaxJitter <= 0 {
		p.MaxJitter = d.MaxJitter
	}
	return p
}

// dial mirrors Refresher.dial exactly: process-wide override first
// (the host's authoritative view of "are we tunnelled right now"),
// then the per-instance dialer, then the fail-closed default.
//
// Sharing the shape is deliberate. A freshness fetch that reached the
// network by any other route would be a second, unaudited egress path
// with the same leak Wave 1 closed on the first one.
func (r *RelayPackRefresher) dial() (bootstrap.Dialer, bool, error) {
	if g := CurrentGlobalDialer(); g != nil {
		return g()
	}
	if r.Dialer != nil {
		return r.Dialer()
	}
	return directFallback()
}

func (r *RelayPackRefresher) shouldFire(userTriggered bool) bool {
	if r.Mode != "lifeline-strict" {
		return true
	}
	return userTriggered
}

// Targets enumerates every imported RelayPack that has at least one
// usable freshness endpoint. Packs with none are omitted: emitting them
// would make the scheduler claim a capability the pack does not have.
func (r *RelayPackRefresher) Targets() ([]RelayPackTarget, error) {
	all, err := r.targetsAll()
	if err != nil {
		return nil, err
	}
	out := make([]RelayPackTarget, 0, len(all))
	for _, t := range all {
		if len(t.Endpoints) == 0 {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// targetsAll enumerates every imported RelayPack, endpoints or not.
// Refresh uses it so that "this pack publishes no freshness endpoint"
// is reported as itself rather than as "unknown pack" — one is a
// publisher who has not enabled remote replacement, the other is a bug.
func (r *RelayPackRefresher) targetsAll() ([]RelayPackTarget, error) {
	rows, err := r.Store.ListRoutes()
	if err != nil {
		return nil, err
	}
	type acc struct {
		publishers map[string]bool
		scalar     string
	}
	byPack := map[string]*acc{}
	order := []string{}
	for _, row := range rows {
		if row.RelayPackID == "" {
			continue
		}
		a := byPack[row.RelayPackID]
		if a == nil {
			a = &acc{publishers: map[string]bool{}}
			byPack[row.RelayPackID] = a
			order = append(order, row.RelayPackID)
		}
		if row.PublisherID != "" {
			a.publishers[row.PublisherID] = true
		}
		if a.scalar == "" {
			a.scalar = row.FreshnessURL
		}
	}
	out := make([]RelayPackTarget, 0, len(order))
	for _, id := range order {
		a := byPack[id]
		t := RelayPackTarget{RelayPackID: id}
		if len(a.publishers) == 1 {
			for p := range a.publishers {
				t.PublisherID = p
			}
		}
		t.Endpoints = r.endpointsFor(id, t.PublisherID, a.scalar)
		t.Providers = DistinctProviders(t.Endpoints)
		out = append(out, t)
	}
	return out, nil
}

// endpointsFor resolves the endpoint list for one pack as the union of
// three sources, deduped by host and truncated at maxFreshnessEndpoints.
//
// THE ORDER IS A TRUST ORDER, AND IT IS THE POINT OF THIS FUNCTION.
// ParseFreshnessEndpoints truncates at the budget, so position decides
// which sources survive a crowded union — NOT which is polled first,
// which is randomised per attempt by ShuffleEndpoints. Most-trusted
// first, therefore:
//
//  1. the manifest scalar. It arrived on the same signature the routes
//     did, so it is the only endpoint that cannot be altered without
//     breaking the whole pack. It must never be crowded out — and it
//     was: an imported set of MaxMirrors entries filled the budget
//     before the scalar was reached, so the one endpoint an attacker
//     could not touch was the one endpoint no device ever polled.
//  2. rec.Mirrors — the set from a document that verified over the
//     network, i.e. the publisher's most recent statement of where to
//     look, authenticated end-to-end.
//  3. the set that arrived inside the pack at import time. It is
//     verified (importedMirrors checks the publisher signature) but it
//     lives in an archive entry that is NOT covered by manifest.sig,
//     so a courier can substitute an older signed one. It is the
//     source with the weakest in-transit story and therefore the one
//     that loses slots first.
//
// Source 3 is still worth having: it is what makes the N-mirror
// contract true on day ONE. rec.Mirrors is only ever written by a
// SUCCESSFUL refresh, so before the first poll a recipient whose
// scalar host is blocked would otherwise have nothing — while the
// other N-1 endpoints sat unread inside the signed file already in
// their hands, in exactly the case they exist for.
func (r *RelayPackRefresher) endpointsFor(relayPackID, publisherID, scalar string) []string {
	rec := r.loadRecord(relayPackID)
	raw := make([]string, 0, len(rec.Mirrors)+MaxMirrors+1)
	raw = append(raw, ParseFreshnessEndpoints(scalar)...)
	for _, m := range rec.Mirrors {
		raw = append(raw, m.URL)
	}
	for _, m := range r.importedMirrors(relayPackID, publisherID) {
		raw = append(raw, m.URL)
	}
	// Re-run the full validation + host de-duplication over the union.
	joined, _ := json.Marshal(raw)
	return ParseFreshnessEndpoints(string(joined))
}

// importedMirrors returns the mirror set that arrived inside the pack
// at import time, verified here and not before.
//
// The bytes were stored raw by core/trust's StoreAdapter because
// `trust/freshness-mirrors.json` is NOT covered by manifest.sig: it can
// be rewritten in transit without breaking the pack, so anything that
// treated it as trusted-on-arrival would let a courier — or whoever
// handed over the file — choose which hosts a recipient polls. That is
// not a route-injection (a fetched pack is still signature-checked
// against the pinned publisher), but it is a beacon: N attacker URLs
// tell the attacker exactly which devices hold this publisher's pack
// and when they wake up.
//
// So the document's own publisher signature is checked against the
// PINNED fingerprint on every read, and the whole set is dropped on any
// failure. Dropped, never partially trusted: ValidateMirrorSet inside
// VerifyMirrorDocument already refuses a set that degraded below
// MinMirrors, and taking "the members that parsed" from a document that
// failed verification would be picking bytes an attacker chose.
//
// A failure here is silent by design — the pack is installed and its
// scalar endpoint still works, so a malformed spare-endpoint list must
// not cost the user their routes. It costs them redundancy, which the
// UI reads off RelayPackTarget.Providers.
func (r *RelayPackRefresher) importedMirrors(relayPackID, publisherID string) []FreshnessMirror {
	if r.Store == nil || relayPackID == "" || publisherID == "" {
		return nil
	}
	raw, err := r.Store.GetSecret(trust.FreshnessMirrorsKey(relayPackID))
	if err != nil || len(raw) == 0 {
		return nil
	}
	pub, err := PublisherKeyForFingerprint(peekPublisherPubHex(raw), publisherID)
	if err != nil {
		return nil
	}
	mirrors, err := VerifyMirrorDocument(raw, pub, relayPackID, r.now())
	if err != nil {
		return nil
	}
	return mirrors
}

// States projects the persisted per-pack stamps for the scheduler's
// planner.
func (r *RelayPackRefresher) States() ([]RelayPackFreshnessState, error) {
	targets, err := r.Targets()
	if err != nil {
		return nil, err
	}
	out := make([]RelayPackFreshnessState, 0, len(targets))
	for _, t := range targets {
		rec := r.loadRecord(t.RelayPackID)
		out = append(out, RelayPackFreshnessState{
			RelayPackID:         t.RelayPackID,
			LastSuccessAt:       parseStamp(rec.LastSuccessAt),
			LastFailureAt:       parseStamp(rec.LastFailureAt),
			ConsecutiveFailures: rec.ConsecutiveFailures,
			JitterOffset:        rec.jitterOffset(),
		})
	}
	return out, nil
}

// RelayPackFreshnessState is the projection the scheduler's Source
// adapter converts into scheduler.RelayPackState. Declared here rather
// than importing the scheduler so the dependency stays one-way.
type RelayPackFreshnessState struct {
	RelayPackID   string
	LastSuccessAt time.Time
	LastFailureAt time.Time
	// ConsecutiveFailures and JitterOffset are carried through
	// verbatim so the planner computes the same due instant the
	// trigger policy will accept. Re-deriving either on the
	// scheduler side would put the two gates on different lattices.
	ConsecutiveFailures int
	JitterOffset        time.Duration
}

// Refresh is the scheduler-driven entry point.
func (r *RelayPackRefresher) Refresh(ctx context.Context, relayPackID string) (RelayPackResult, error) {
	return r.refresh(ctx, relayPackID, false)
}

// RefreshUser is the user-triggered variant; bypasses the
// lifeline-strict gate, exactly as the subscription path does.
func (r *RelayPackRefresher) RefreshUser(ctx context.Context, relayPackID string) (RelayPackResult, error) {
	return r.refresh(ctx, relayPackID, true)
}

func (r *RelayPackRefresher) refresh(ctx context.Context, relayPackID string, userTriggered bool) (RelayPackResult, error) {
	now := r.now()
	res := RelayPackResult{RelayPackID: relayPackID}
	if r.Store == nil {
		return res, errors.New("relaypack refresh: nil store")
	}

	if !r.shouldFire(userTriggered) {
		res.Outcome = SkippedLifelineStrict
		recordAudit(r.Store, auditKindFreshness, relayPackID, SkippedLifelineStrict, 0, false, now)
		return res, nil
	}

	target, err := r.target(relayPackID)
	if err != nil {
		res.Outcome = OutcomeFreshnessAmbiguous
		r.markFailure(relayPackID, now, res.Outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, res.Outcome, 0, false, now)
		return res, err
	}
	res.Providers = target.Providers
	if len(target.Endpoints) == 0 {
		res.Outcome = OutcomeFreshnessNoEndpoints
		r.markFailure(relayPackID, now, res.Outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, res.Outcome, 0, false, now)
		return res, nil
	}

	rec := r.loadRecord(relayPackID)
	st := selection.FreshnessState{
		LastSuccessAt:       parseStamp(rec.LastSuccessAt),
		LastFailureAt:       parseStamp(rec.LastFailureAt),
		ConsecutiveFailures: rec.ConsecutiveFailures,
		JitterOffset:        rec.jitterOffset(),
	}
	if !userTriggered && !selection.ShouldAttemptRefresh(r.policy(), st, now) {
		// No network, no audit row: a suppressed attempt is not an
		// event, and writing one per tick would itself be a cadence
		// record on disk.
		res.Outcome = OutcomeFreshnessRateLimited
		return res, nil
	}

	dialer, viaTunnel, err := r.dial()
	if err != nil {
		// Wave 1's guard. This is NOT "unreachable" and must never be
		// retried as a direct dial, so we stamp a failure (backoff
		// applies) and stop — no pointer recovery either, since that
		// would egress from the same address by another name.
		res.Outcome = OutcomeFreshnessTunnel
		r.markFailure(relayPackID, now, res.Outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, res.Outcome, 0, false, now)
		return res, err
	}
	res.ViaTunnel = viaTunnel

	doc, docBytes, tried, err := r.walkEndpoints(ctx, target, rec, dialer, now)
	res.EndpointsTried = tried
	res.BytesIn += int64(len(docBytes))
	if err != nil {
		outcome := OutcomeFreshnessUnreachable
		if isVerificationError(err) {
			outcome = OutcomeFreshnessRejected
		}
		res.Outcome = outcome
		r.markFailure(relayPackID, now, outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, outcome, res.BytesIn, viaTunnel, now)

		// Every endpoint is gone. The pack's own endpoint set cannot
		// fix that — replacing it requires a channel that does not
		// depend on it. That channel is the bootstrap-pointer
		// envelope: a project-root-signed set of directory pointers
		// which can carry a directory whose routes bring a NEW
		// freshness endpoint set with them.
		if r.Recover != nil {
			res.Recovered = true
			if _, rErr := r.Recover(ctx); rErr == nil {
				recordAudit(r.Store, auditKindFreshness, relayPackID,
					OutcomeFreshnessRecovery, 0, viaTunnel, now)
			}
		}
		return res, err
	}

	res.Changed = !equalHex(doc.CurrentBundleSHA256, rec.CurrentBundleSHA256)
	// Adopt the advertised mirror set and advance the high-water mark
	// even on the unchanged path: both came out of a document that
	// verified, and adopting the endpoint rotation is the point of
	// polling at all when nothing else moved.
	r.adoptDocument(relayPackID, &rec, doc)
	// Persist the adopted state BEFORE the bundle fetch. If that fetch
	// fails we go down the markFailure path, which re-reads the record
	// from disk — so without this write the high-water sequence we
	// just learned would be discarded, and the replay it forbids would
	// become acceptable again on the next attempt.
	r.saveRecord(relayPackID, rec)

	if !res.Changed {
		res.Outcome = OutcomeFreshnessUnchanged
		r.markSuccess(relayPackID, rec, now, res.Outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, res.Outcome, res.BytesIn, viaTunnel, now)
		return res, nil
	}

	body, err := r.fetchBundle(ctx, doc.CurrentSignedURL, dialer)
	res.BytesIn += int64(len(body))
	if err != nil {
		res.Outcome = OutcomeFreshnessBundleFetch
		r.markFailure(relayPackID, now, res.Outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, res.Outcome, res.BytesIn, viaTunnel, now)
		return res, err
	}

	verdict, appliedPackID, applyErr := r.applyBundle(target, doc, body, now)
	res.Verdict = verdictKindString(verdict.Kind)
	if applyErr != nil {
		outcome := OutcomeFreshnessBundleReject
		switch {
		case errors.Is(applyErr, ErrFreshnessPublisher):
			outcome = OutcomeFreshnessRejected
		case errors.Is(applyErr, errRoutePublisherRebind):
			outcome = OutcomeFreshnessRebind
		case verdict.Kind == importer.VerdictRejected && verdict.Reason == "":
			outcome = OutcomeFreshnessImportFailed
		}
		res.Outcome = outcome
		r.markFailure(relayPackID, now, outcome)
		recordAudit(r.Store, auditKindFreshness, relayPackID, outcome, res.BytesIn, viaTunnel, now)
		return res, applyErr
	}

	res.Applied = true
	res.Outcome = OutcomeFreshnessOK
	rec.CurrentBundleSHA256 = doc.CurrentBundleSHA256

	// RE-KEY. The applied pack may carry a DIFFERENT relay_pack_id
	// than the one we polled under — that is the normal case for every
	// rung of the ladder that changes an attribute the id is derived
	// from (L3 address, L4 region, L5 provider, L6 families, L1/L2
	// server). The importer has just rewritten the route rows with the
	// new id, so the next Targets() enumeration will ask for the pack
	// under its new name and find no persisted state there: high-water
	// sequence back to zero, mirrors forgotten. Zero high-water is a
	// one-document replay window handed to whoever is watching, and
	// forgotten mirrors is losing the endpoint diversity right after
	// the event that needed it. So the record moves with the pack.
	//
	// Keyed writes only; nothing is deleted. The old key becomes
	// unreachable (no route row names it, so it is never a target
	// again) and the secrets store has no delete primitive on this
	// interface. A stale blob is cheaper than a delete that half-runs.
	packID := relayPackID
	if appliedPackID != "" && appliedPackID != relayPackID {
		packID = appliedPackID
		res.RelayPackID = appliedPackID
	}
	// The applied pack may itself carry a newer signed mirror set;
	// adopting it here is what lets a publisher move providers in the
	// same rotation that moves the relay. Verified against the pack's
	// OWN id, which is why this runs after packID is resolved.
	if mirrors, ok := r.mirrorsFromBundle(body, packID, target.PublisherID, now); ok {
		rec.Mirrors = mirrors
	}
	r.markSuccess(packID, rec, now, res.Outcome)
	recordAudit(r.Store, auditKindFreshness, packID, res.Outcome, res.BytesIn, viaTunnel, now)
	return res, nil
}

// target resolves one pack and refuses ambiguity rather than guessing.
func (r *RelayPackRefresher) target(relayPackID string) (RelayPackTarget, error) {
	targets, err := r.targetsAll()
	if err != nil {
		return RelayPackTarget{}, err
	}
	for _, t := range targets {
		if t.RelayPackID != relayPackID {
			continue
		}
		if t.PublisherID == "" {
			// Either no publisher, or two publishers claiming one
			// pack id. Both are states in which "whose document
			// governs this pack" has no answer, and inventing one is
			// how a fetched pack silently changes ownership.
			return t, fmt.Errorf("relaypack %s: no single pinned publisher", relayPackID)
		}
		return t, nil
	}
	return RelayPackTarget{}, fmt.Errorf("relaypack %s: not found or has no freshness endpoint", relayPackID)
}

// walkEndpoints tries the endpoints in randomised order under a total
// budget, returning the first document that verifies.
func (r *RelayPackRefresher) walkEndpoints(ctx context.Context, t RelayPackTarget,
	rec freshnessRecord, dialer bootstrap.Dialer, now time.Time) (*FreshnessDocument, []byte, int, error) {

	perURL := r.PerURLTimeout
	if perURL <= 0 {
		perURL = defaultPerURLTimeout
	}
	budget := r.TotalBudget
	if budget <= 0 {
		budget = defaultTotalBudget
	}
	fetch := r.Fetch
	if fetch == nil {
		fetch = bootstrap.FetchRaw
	}

	walkCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var lastErr error
	var lastBody []byte
	tried := 0
	for _, ep := range ShuffleEndpoints(t.Endpoints) {
		if walkCtx.Err() != nil {
			break
		}
		tried++
		epCtx, epCancel := context.WithTimeout(walkCtx, perURL)
		raw, err := fetch(epCtx, ep, dialer, perURL)
		epCancel()
		if err != nil {
			lastErr = err
			continue
		}
		if len(raw) > maxFreshnessDocBytes {
			raw = raw[:maxFreshnessDocBytes]
		}
		lastBody = raw
		pub, err := PublisherKeyForFingerprint(peekPublisherPubHex(raw), t.PublisherID)
		if err != nil {
			// A document that is not this publisher's is either a
			// mis-pointed URL or a substitution. Either way the next
			// mirror is worth trying.
			lastErr = err
			continue
		}
		doc, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
			PublisherRootPub:  pub,
			Now:               now,
			ExpectRelayPackID: t.RelayPackID,
			MinSequence:       rec.HighWaterSequence,
			// Feeds the equal-sequence rule: a document AT the
			// high-water mark is only acceptable while it names the
			// bundle we are already running.
			CurrentBundleSHA256: rec.CurrentBundleSHA256,
		})
		if err != nil {
			lastErr = err
			continue
		}
		return doc, raw, tried, nil
	}
	if lastErr == nil {
		lastErr = errors.New("freshness: no endpoint produced a document")
	}
	return nil, lastBody, tried, lastErr
}

// fetchBundle pulls the signed .sbp named by a verified document.
func (r *RelayPackRefresher) fetchBundle(ctx context.Context, url string, dialer bootstrap.Dialer) ([]byte, error) {
	fetch := r.Fetch
	if fetch == nil {
		fetch = bootstrap.FetchRaw
	}
	timeout := defaultBundleTimeout
	if r.TotalBudget > 0 && r.TotalBudget < timeout {
		timeout = r.TotalBudget
	}
	bCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := fetch(bCtx, url, dialer, timeout)
	if err != nil {
		return nil, err
	}
	if len(body) > maxFreshnessBundleBytes {
		return nil, fmt.Errorf("freshness: bundle exceeds %d bytes", maxFreshnessBundleBytes)
	}
	return body, nil
}

// errRoutePublisherRebind is returned when a fetched pack would take
// over a route id currently owned by a different publisher.
var errRoutePublisherRebind = errors.New("freshness: fetched pack would re-home another publisher's route")

// applyBundle is the gate in front of the importer's atomic swap.
//
// The importer already refuses an unpinned publisher on this path
// (ApplyVerifiedRefresh: "a freshness-driven swap MUST NOT introduce a
// new publisher"). That is necessary and not sufficient: a device
// typically has SEVERAL pinned publishers, so "pinned" does not mean
// "the one whose pack we asked to refresh". Two checks close the gap:
//
//  1. the fetched pack must be signed by the pack's OWN publisher —
//     the same fingerprint that signed the freshness document, which
//     is the same fingerprint the routes are pinned to;
//  2. no route id in the fetched pack may currently belong to a
//     DIFFERENT publisher. Without this, publisher B — pinned for its
//     own perfectly good reasons — could mint a pack reusing
//     publisher A's route ids and silently take ownership of A's
//     routes on the next refresh.
//
// It also reports the applied pack's OWN relay_pack_id, which the
// caller needs to re-key its persisted state: after any rung that
// changes an attribute DeriveRelayPackID hashes, the pack that
// arrives is named differently from the one that was polled.
func (r *RelayPackRefresher) applyBundle(t RelayPackTarget, doc *FreshnessDocument,
	body []byte, now time.Time) (importer.Verdict, string, error) {

	parsed, err := bundle.ParseSBP(newByteReaderAt(body), int64(len(body)))
	if err != nil {
		return importer.Verdict{Kind: importer.VerdictRejected, Reason: "bundle_corrupted"}, "", err
	}
	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	if !equalHex(fp.Hex, t.PublisherID) {
		return importer.Verdict{Kind: importer.VerdictRejected, Reason: "publisher_mismatch"}, "",
			fmt.Errorf("%w: pack is signed by %s, this relay pack belongs to %s",
				ErrFreshnessPublisher, fp.Hex, t.PublisherID)
	}
	rows, err := r.Store.ListRoutes()
	if err != nil {
		return importer.Verdict{Kind: importer.VerdictRejected, Reason: "lookup_failed"}, "", err
	}
	owner := map[string]string{}
	for _, row := range rows {
		owner[row.RouteID] = row.PublisherID
	}
	for _, route := range parsed.Manifest.Routes {
		if cur, ok := owner[route.ID]; ok && cur != "" && !equalHex(cur, t.PublisherID) {
			return importer.Verdict{Kind: importer.VerdictRejected, Reason: "route_publisher_rebind"}, "",
				fmt.Errorf("%w: route %s belongs to %s", errRoutePublisherRebind, route.ID, cur)
		}
	}
	appliedPackID := ""
	if parsed.Manifest.RelayPack != nil {
		appliedPackID = parsed.Manifest.RelayPack.RelayPackID
	}
	verdict, err := ApplyRefresh(body, doc, r.Adapter, publisher.DefaultWordlists(), now)
	if err != nil {
		return verdict, "", err
	}
	return verdict, appliedPackID, nil
}

// mirrorsFromBundle extracts and verifies the signed mirror set from
// an applied pack. A malformed or foreign set is dropped silently —
// the pack is already applied and the previously-known endpoints are
// still valid, so refusing the whole refresh over an unusable mirror
// document would trade a working recovery for a cosmetic one.
func (r *RelayPackRefresher) mirrorsFromBundle(body []byte, relayPackID, publisherID string,
	now time.Time) ([]FreshnessMirror, bool) {

	raw, ok := bootstrap.ArchiveEntry(body, MirrorsArchivePath)
	if !ok {
		return nil, false
	}
	pub, err := PublisherKeyForFingerprint(peekPublisherPubHex(raw), publisherID)
	if err != nil {
		return nil, false
	}
	// relayPackID is the APPLIED pack's own id, not the one we polled
	// under: the entry inside the new pack is bound to the new id, so
	// checking it against the old one would drop every mirror set on
	// exactly the rotations that change the id.
	mirrors, err := VerifyMirrorDocument(raw, pub, relayPackID, now)
	if err != nil {
		return nil, false
	}
	return mirrors, true
}

// adoptDocument folds a verified document's advertised state into the
// persisted record: the high-water sequence (monotonic — it only ever
// rises) and the advertised mirror set (only when it is a valid,
// multi-provider set, so a document can never shrink a recipient down
// to one endpoint).
func (r *RelayPackRefresher) adoptDocument(relayPackID string, rec *freshnessRecord, doc *FreshnessDocument) {
	if doc.Sequence > rec.HighWaterSequence {
		rec.HighWaterSequence = doc.Sequence
	}
	if len(doc.Mirrors) > 0 {
		if set, err := ValidateMirrorSet(doc.Mirrors); err == nil {
			rec.Mirrors = set
		}
	}
	_ = relayPackID
}

func (r *RelayPackRefresher) loadRecord(relayPackID string) freshnessRecord {
	rec := freshnessRecord{V: 1}
	if r.Store == nil {
		return rec
	}
	body, err := r.Store.GetSecret(freshnessKey(relayPackID))
	if err != nil || len(body) == 0 {
		return rec
	}
	var got freshnessRecord
	if err := json.Unmarshal(body, &got); err != nil {
		// A corrupt record must not resurrect a spent sequence, so we
		// keep the conservative zero value and let the next verified
		// document re-establish the high-water mark. That is a
		// one-document replay window on a device whose secrets store
		// is already damaged.
		return rec
	}
	got.V = 1
	return got
}

func (r *RelayPackRefresher) saveRecord(relayPackID string, rec freshnessRecord) {
	if r.Store == nil {
		return
	}
	rec.V = 1
	body, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = r.Store.PutSecret(freshnessKey(relayPackID), body)
}

func (r *RelayPackRefresher) markFailure(relayPackID string, now time.Time, outcome string) {
	rec := r.loadRecord(relayPackID)
	rec.LastFailureAt = now.UTC().Format(time.RFC3339)
	rec.LastOutcome = outcome
	// Escalation state. A device whose mirrors are ALL blocked is
	// the device this whole subsystem exists for, and it is also the
	// device with no tunnel — so every one of its attempts leaves the
	// user's real address, in the clear, aimed at a small set of
	// enumerable hosts. It should get quieter, not stay loud.
	rec.ConsecutiveFailures++
	rec.JitterMillis = drawJitter(r.policy().MaxJitter)
	r.saveRecord(relayPackID, rec)
}

func (r *RelayPackRefresher) markSuccess(relayPackID string, rec freshnessRecord, now time.Time, outcome string) {
	rec.LastSuccessAt = now.UTC().Format(time.RFC3339)
	// Clearing the failure stamp is what lets MinInterval (not
	// RetryBackoff) govern the next attempt after a recovery.
	rec.LastFailureAt = ""
	rec.ConsecutiveFailures = 0
	rec.LastOutcome = outcome
	rec.JitterMillis = drawJitter(r.policy().MaxJitter)
	r.saveRecord(relayPackID, rec)
}

func parseStamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// isVerificationError distinguishes "the network ate it" from "the
// bytes were wrong". The two demand different responses from a human:
// the first is a censorship signal, the second is a publisher error or
// an attack, and rendering both as "refresh failed" is how a device
// stops being able to tell the difference.
func isVerificationError(err error) bool {
	return errors.Is(err, ErrFreshnessSignature) ||
		errors.Is(err, ErrFreshnessVersion) ||
		errors.Is(err, ErrFreshnessExpired) ||
		errors.Is(err, ErrFreshnessRollback) ||
		errors.Is(err, ErrFreshnessWrongPack) ||
		errors.Is(err, ErrFreshnessPublisher)
}

// newByteReaderAt adapts a byte slice to io.ReaderAt for ParseSBP
// without pulling bytes.Reader's full surface into this file's API.
func newByteReaderAt(b []byte) *byteReaderAt { return &byteReaderAt{b: b} }

type byteReaderAt struct{ b []byte }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, errReaderEOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, errReaderEOF
	}
	return n, nil
}

var errReaderEOF = errors.New("EOF")
