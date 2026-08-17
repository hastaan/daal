package rotation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
)

// SignedSBP is the persistence shape for one signed RelayPack
// bundle. Mirrors the V003 SQLite history-table row (see
// client-shell/tauri/daal-wizard/migrations/V003__signed_sbps_history.sql)
// so the executor's transactional contract matches the DB shape
// byte-for-byte.
//
// The Active flag is the fast-read projection: a row with Active=1
// is the currently-published .sbp; rotation flips the prior row to
// 0 and inserts the fresh row at 1.
type SignedSBP struct {
	OperatorID     int64
	SignedAtUnix   int64
	SBPPath        string
	SBPSHA256      string
	RelayPackID    string
	RouteCount     int
	RotationReason string
	Active         bool
}

// Binder is the FRP-4b BindAndSign contract abstracted to an
// interface so the executor can be unit-tested without the full
// relaypackvalidate stack. It is INTENDED to be wired to
// publisher/deploy/relaypack.BindAndSign via [BinderFunc]; read
// [BinderFunc] for why nothing wires it today.
type Binder interface {
	Bind(rec *provider.OperatorRecord, priv ed25519.PrivateKey, now time.Time) (BinderResult, error)
}

// BinderResult is the executor's view of a bind. Matches the fields
// the rotation surface needs to persist.
type BinderResult struct {
	SBPBytes     []byte
	BundleSHA256 string
	RelayPackID  string
	RouteCount   int
}

// BinderFunc adapts a function to the [Binder] interface. Tests supply
// a fake.
//
// READ THIS BEFORE TRUSTING THE REST OF THIS FILE'S COMMENTS. There is
// no production caller of [Executor] anywhere in the repository, and
// the ones the surrounding comments used to name do not exist. The
// wizard drives rotation through a SECOND implementation in Rust
// (client-shell/tauri/daal-wizard/src/commands.rs, rotate_execute),
// which shells out to `daal-deploy` per level and runs its own
// signed_sbps transaction. So:
//
//   - the provider-side behaviour this package's L3 path depends on
//     (an address swap that actually moves rec.PublicIP and the
//     candidates' public_ip:* tags) IS live, because both paths go
//     through the same provider adapter and the same CLI;
//   - the ordering, rollback and post-commit release logic below is
//     NOT live, because only this executor implements it.
//
// Collapsing the two is its own piece of work (the plan's S3 item 18:
// delete the Rust re-implementation and call this). Until then, do not
// read a guarantee written here as a guarantee the shipped wizard
// makes.
type BinderFunc func(rec *provider.OperatorRecord, priv ed25519.PrivateKey, now time.Time) (BinderResult, error)

// Bind implements [Binder] for [BinderFunc].
func (f BinderFunc) Bind(rec *provider.OperatorRecord, priv ed25519.PrivateKey, now time.Time) (BinderResult, error) {
	return f(rec, priv, now)
}

// SBPStore is the persistence contract the executor uses to commit
// the signed_sbps history transaction (V003). No Go implementation
// exists: the Tauri layer runs the equivalent transaction in Rust
// against the same V003 schema rather than through this interface (see
// [BinderFunc]), so the only implementation here is the in-memory
// store the unit tests use. Insert/MarkInactive/UpdateOperatorActive happen
// inside the same transaction; on any error the caller MUST roll back.
type SBPStore interface {
	// Begin opens a new transaction. The returned [SBPTx] must be
	// followed by exactly one Commit() or Rollback().
	Begin() (SBPTx, error)
}

// SBPTx is the in-flight transaction handle returned by [SBPStore].
type SBPTx interface {
	// MarkPriorInactive flips every active=1 row for operatorID to
	// active=0 inside this transaction.
	MarkPriorInactive(operatorID int64) error
	// InsertActive writes the new row with active=1.
	InsertActive(row SignedSBP) error
	// UpdateOperatorActiveProjection updates the
	// operators.signed_sbp_* fast-read columns inside the same tx.
	UpdateOperatorActiveProjection(operatorID int64, row SignedSBP) error
	// Commit closes the transaction successfully.
	Commit() error
	// Rollback is idempotent; safe to call after Commit.
	Rollback() error
}

// SBPWritePath persists the fresh SBP bytes to the staging directory.
// Tests pass a fake; see [BinderFunc] on the absence of a production
// caller.
type SBPWritePath func(rec *provider.OperatorRecord, sbpBytes []byte, signedAt time.Time) (path string, err error)

// Clock abstracts time.Now for deterministic tests. [WallClock] is the
// real implementation; the wallclock-pin test passes a synthetic clock
// so the L3 budget assertion is reproducible.
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

// WallClock is the real-time clock.
type WallClock struct{}

// Now returns time.Now in UTC.
func (WallClock) Now() time.Time { return time.Now().UTC() }

// Since returns time.Since(t).
func (WallClock) Since(t time.Time) time.Duration { return time.Since(t) }

// L3FastPathBudget pins supplement §14.1's V1.5 wall-clock budget
// for the floating-IP swap path. The soak rig's
// `v1-5-l3-fast-path` scenario asserts this same value; any change
// is a roadmap amendment.
const L3FastPathBudget = 15 * time.Second

// Executor wires Provider + Binder + SBPStore into a single
// transactional rotate-step. Every field except VerifyReachable is
// required; a missing one is [ErrExecutorIncomplete] rather than a
// half-run rotation.
type Executor struct {
	Provider provider.Provider
	Binder   Binder
	Store    SBPStore
	WriteSBP SBPWritePath
	Clock    Clock

	// VerifyReachable is the OPTIONAL data-plane check between an L3
	// swap and the re-sign. Nil skips it.
	//
	// It exists because "the cloud API accepted the assignment" and
	// "packets reach port 443 on the new address" are different
	// claims, and only the first is checkable from inside this
	// process. The provider adapter proves the first by reading the
	// object back. The second needs a dial from outside the publisher's
	// machine — so this is a seam rather than an implementation, and
	// the honest reading of an L3 run with VerifyReachable==nil is
	// "the control plane agreed", not "the relay is reachable".
	//
	// A verifier that fails rolls the swap back, so a slow or flaky
	// probe costs the operator a failed rotation rather than a wrong
	// pack. Whatever is bound here must also fit inside
	// [L3FastPathBudget] together with the bind and the store write.
	VerifyReachable func(ctx context.Context, rec *provider.OperatorRecord) error

	// BindAddress is the GUEST-OS half of an L3 swap, and without it an
	// L3 cannot work at all.
	//
	// Attaching a floating IP routes packets to the server at the
	// provider's network layer; the operating system does not reply on
	// the address until it is configured on an interface. Measured on
	// real hardware 2026-08-17: the API reported the address attached
	// with both ownership labels while the box never answered on it.
	// mgmt.BindAddressWithFW is what fills the gap.
	//
	// The signature carries BOTH addresses because at this point in the
	// swap they differ and confusing them is unrecoverable: controlIP is
	// the address the relay still ANSWERS on (the pre-swap one, the only
	// route the request can travel), target is the address to bring up.
	//
	// It is a func field rather than a call, for the same reason
	// VerifyReachable is: this package is I/O-free by design and
	// delegates every network call to an injected seam (its own opsec
	// test enforces it).
	//
	// Nil skips the bind — which is honest only for a relay that already
	// holds the address. A production wiring must set it; leaving it nil
	// reproduces exactly the bug this field exists to fix, and
	// VerifyReachable is what will catch that.
	BindAddress func(ctx context.Context, rec *provider.OperatorRecord, controlIP, target net.IP) error

	// UnbindAddress is the inverse, used on two paths: rolling back a
	// swap whose probe failed (the box must not keep an address the
	// record no longer names), and giving the PREVIOUS address back
	// after a committed swap — before it is released, never after,
	// because a released address returns to the provider's pool and may
	// be issued to another customer while this box still claims it.
	//
	// Nil skips it, with a warning on the outcome rather than silence.
	UnbindAddress func(ctx context.Context, rec *provider.OperatorRecord, controlIP, target net.IP) error
}

// RotateRequest is the input to [Executor.Rotate].
type RotateRequest struct {
	// OperatorID is the wizard/operator DB primary key used for the
	// signed_sbps history transaction. It is not part of the
	// provider.OperatorRecord wire shape.
	OperatorID int64

	// Record is the OperatorRecord to rotate. Mutated in-place
	// across the rotation (e.g. ServerID changes on L4/L5).
	Record *provider.OperatorRecord

	// PrivKey is the publisher's Ed25519 private key. Stays in
	// memory; the executor passes it to the Binder and never
	// persists or logs it.
	PrivKey ed25519.PrivateKey

	// Recommendation is the recommender output; the wizard may
	// have overridden Level via the override dropdown.
	Recommendation RotationRecommendation

	// NewFloatingIPID is the address to move onto, for L3.
	//
	// Empty is now legal and is the normal case: leave it empty and the
	// executor reserves a fresh address for this relay (see
	// [FloatingIPProvisioner]). Before Step 9 it was mandatory, which
	// meant L3 — the cheapest and fastest recovery from the failure
	// that actually kills relays — was reachable only by an operator
	// who had reserved an address by hand in the provider console and
	// knew its numeric id, for which no input field existed anywhere.
	NewFloatingIPID string

	// ReprovisionOpts is required for L1, L2, L4, L5, L6.
	// L1 ⇒ RegenCredentials=true.
	// L2 ⇒ NewSNI / NewWSPath populated from context.
	// L4/L5 ⇒ NewToolboxProfile populated.
	// L6 ⇒ NewToolboxProfile populated (e.g. tcp-only-vps-native).
	ReprovisionOpts provider.ReprovisionOpts
}

// RotateResult is the output of [Executor.Rotate].
type RotateResult struct {
	// SignedSBP is the freshly persisted history row.
	SignedSBP SignedSBP

	// WallClock is the measured end-to-end duration. For L3 the
	// soak rig asserts WallClock < L3FastPathBudget.
	WallClock time.Duration

	// PriorWasActive reports whether a prior active row existed
	// for this operator. Used by the wizard to decide if Revert
	// is offered.
	PriorWasActive bool

	// L3 carries what the floating-IP swap actually did. Zero value
	// on every other level.
	L3 L3Outcome
}

// L3Outcome is the operator-facing account of a floating-IP swap: the
// address recipients will dial from now on, and what happened to the one
// they were dialing before.
type L3Outcome struct {
	// NewFloatingIPID / NewPublicIP are the address now attached.
	NewFloatingIPID string
	NewPublicIP     net.IP

	// PriorFloatingIPID is what the relay was on before, "" if it was
	// running on the server's own primary address.
	PriorFloatingIPID string

	// PriorReleased reports whether the prior address is actually gone
	// from the account. False with no error means it was detached but
	// left reserved because daal-deploy did not create it — still on
	// the operator's bill, so the caller must say so rather than show
	// a clean success.
	PriorReleased bool

	// ReservedHere is true when the executor reserved the new address
	// itself (as opposed to attaching one the operator supplied). It
	// is what makes rollback able to delete the address without
	// risking one the operator owns.
	ReservedHere bool

	// Warnings are non-fatal problems from the post-commit release
	// leg. That leg runs AFTER the pack is signed and stored, so its
	// failures cannot fail the rotation — but leaving them unsaid is
	// how an address quietly keeps billing.
	Warnings []string
}

// errors -------------------------------------------------------------

var (
	ErrNilRequest        = errors.New("rotation: nil RotateRequest")
	ErrNilRecord         = errors.New("rotation: nil OperatorRecord")
	ErrNilPrivKey        = errors.New("rotation: empty private key")
	ErrL3WallClockBudget = errors.New("rotation: L3 fast path exceeded the V1.5 wall-clock budget")
	ErrUnsupportedLevel  = errors.New("rotation: unsupported level")

	// ErrL3NoAddressSource: no floating-IP id was supplied AND the
	// Provider cannot reserve one. Previously this surfaced as
	// "L3 requires NewFloatingIPID", which named the missing input
	// without saying that on some providers there is no way to
	// produce it.
	ErrL3NoAddressSource = errors.New("rotation: L3 needs either NewFloatingIPID or a Provider that can reserve one")

	// ErrL3AddressUnchanged is the post-condition that makes an L3 on
	// an un-fixed provider fail loudly instead of quietly re-signing
	// against the burned address. See CheckAddressMoved.
	ErrL3AddressUnchanged = errors.New("rotation: L3 completed without moving the record's dialled address")

	// ErrRecordAddressInconsistent fires when rec.PublicIP and the
	// candidates' public_ip:* tags disagree — a record that would sign
	// a pack dialling one address while declaring another.
	ErrRecordAddressInconsistent = errors.New("rotation: record's public IP and candidate public_ip:* tags disagree")

	ErrExecutorIncomplete = errors.New("rotation: Executor missing required field")
)

// ErrL3MissingFipID is retained as an alias so callers that matched on
// it keep compiling and keep matching.
//
// Deprecated: use [ErrL3NoAddressSource].
var ErrL3MissingFipID = ErrL3NoAddressSource

// FloatingIPProvisioner is the OPTIONAL half of the provider contract
// that makes L3 self-service.
//
// It is deliberately not on provider.Provider. Reserving and releasing
// an address is a capability a provider adapter either has or does not
// (today: Hetzner does; Vultr and Stark attach an address the operator
// already owns and cannot mint one), and forcing it into the shared
// interface would mean two adapters growing methods that return
// "not implemented" — a shape this repository already has too much of.
// An optional interface lets the executor ask, and say plainly what is
// missing when the answer is no.
type FloatingIPProvisioner interface {
	// CreateFloatingIP reserves a fresh address for this relay,
	// unattached, and returns its provider id and the address itself.
	CreateFloatingIP(ctx context.Context, rec *provider.OperatorRecord) (id string, addr net.IP, err error)

	// ReleaseFloatingIP detaches an address and, if the adapter
	// created it, deletes it. deleted=false with a nil error means
	// "detached, still reserved, still billing, not ours to delete".
	ReleaseFloatingIP(ctx context.Context, rec *provider.OperatorRecord, id string) (deleted bool, err error)
}

// Rotate runs the chosen rotation level, re-signs the RelayPack,
// and commits the (mark-prior-inactive, insert-active, update-
// projection) triple inside one DB transaction.
//
// SCOPE, since Step 7 split the ladder's cheapest rungs in two: L1 and
// L2 here are the DESTROY-AND-REBUILD route. Every level except L3 goes
// through Provider.Reprovision, which deletes the box and builds a new
// one — new IP, new mgmt TLS pin, minutes not seconds. That is the
// correct behaviour for L4/L5/L6, and for L1/L2 it is the FALLBACK for a
// relay whose pinned mgmt artifact predates the in-place endpoints.
//
// The in-place path is not here and deliberately so: it is
// mgmt.RotateCredentialsWithFW / mgmt.RotateTLSWithFW, driven by
// `daal-deploy rotate-credentials` / `rotate-tls`, and it touches no
// signed_sbps transaction because the server survives. [ActionFor] is
// what tells a caller which of the two it is looking at; wiring a second
// execution path through this Executor would add a caller-less
// abstraction on top of a CLI the wizard already shells out to.
//
// FAILURE BEHAVIOUR, which differs by level and it matters.
//
// On Provider or Binder failure the transaction never opens; on store
// failure the transaction rolls back and the rec is left unchanged on
// disk. For the DESTROY-AND-REBUILD levels the in-memory rec may
// already reflect a successful Provider call and there is nothing to
// undo — the old box is gone — so the caller is responsible for
// retrying or surfacing the error to the operator.
//
// L3 is the exception and now genuinely unwinds. Every failure after
// the address is attached — bind, write, budget, transaction — restores
// the record's previous address and hands the new one back (deleting it
// if the executor reserved it). The invariant that buys is stated on
// [Executor.beginL3]: the record always names an address that is
// currently routed to this server, at every instant, on every path.
func (e *Executor) Rotate(ctx context.Context, req *RotateRequest) (*RotateResult, error) {
	if e.Provider == nil || e.Binder == nil || e.Store == nil || e.WriteSBP == nil || e.Clock == nil {
		return nil, ErrExecutorIncomplete
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Record == nil {
		return nil, ErrNilRecord
	}
	if len(req.PrivKey) != ed25519.PrivateKeySize {
		return nil, ErrNilPrivKey
	}

	start := e.Clock.Now()

	// 1. Provider call (or floating-IP swap).
	//
	// l3 is non-nil only on the L3 path and is what every later
	// failure unwinds through. Nothing else in this function has
	// anything to unwind: the rebuild levels have already deleted the
	// old box by the time they return.
	var l3 *l3Swap
	switch req.Recommendation.Level {
	case L3:
		st, err := e.beginL3(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("rotation L3: %w", err)
		}
		l3 = st
	case L1, L2, L4, L5, L6:
		if err := e.Provider.Reprovision(ctx, req.Record, req.ReprovisionOpts); err != nil {
			return nil, fmt.Errorf("rotation %s reprovision: %w", req.Recommendation.Level, err)
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLevel, req.Recommendation.Level)
	}

	// abort undoes the swap (L3 only) and returns the error. Every
	// early return below goes through it; a bare `return nil, err`
	// after this point is a bug, because it would leave the relay on
	// an address no signed pack names.
	abort := func(err error) (*RotateResult, error) {
		if l3 != nil {
			l3.rollback(ctx, e, req.Record)
		}
		return nil, err
	}

	// 2. Re-sign the RelayPack against the (possibly mutated) rec.
	now := e.Clock.Now()
	bind, err := e.Binder.Bind(req.Record, req.PrivKey, now)
	if err != nil {
		return abort(fmt.Errorf("rotation bind: %w", err))
	}

	// 3. Persist the bytes to the staging dir.
	sbpPath, err := e.WriteSBP(req.Record, bind.SBPBytes, now)
	if err != nil {
		return abort(fmt.Errorf("rotation write sbp: %w", err))
	}

	// 4. Enforce the L3 wall-clock budget before publishing the
	// new SBP as active. A budget miss is a failed rotation from
	// the operator's point of view, so the history projection must
	// not be committed after we already know the invariant broke.
	dur := e.Clock.Since(start)
	if req.Recommendation.Level == L3 && dur > L3FastPathBudget {
		return abort(fmt.Errorf("%w: took %s > %s", ErrL3WallClockBudget, dur, L3FastPathBudget))
	}

	// 5. Commit the history transaction.
	row := SignedSBP{
		OperatorID:     req.OperatorID,
		SignedAtUnix:   now.Unix(),
		SBPPath:        sbpPath,
		SBPSHA256:      bind.BundleSHA256,
		RelayPackID:    bind.RelayPackID,
		RouteCount:     bind.RouteCount,
		RotationReason: rotationReason(req.Recommendation),
		Active:         true,
	}
	tx, err := e.Store.Begin()
	if err != nil {
		return abort(fmt.Errorf("rotation tx begin: %w", err))
	}
	priorWasActive, err := commitRotationTx(tx, row)
	if err != nil {
		_ = tx.Rollback()
		return abort(fmt.Errorf("rotation tx commit: %w", err))
	}

	res := &RotateResult{
		SignedSBP:      row,
		WallClock:      dur,
		PriorWasActive: priorWasActive,
	}

	// 6. ONLY NOW release the address the relay just moved off.
	//
	// After the commit, never before. Until this line the relay is
	// answering on both addresses and every already-distributed pack
	// still works; releasing earlier would open a window in which a
	// failure leaves recipients holding a pack for an address that
	// routes nowhere. Failures here cost money, not connectivity, so
	// they are warnings on the result rather than a failed rotation —
	// the pack is signed and committed and undoing that to tidy up a
	// billing resource would be the wrong trade.
	if l3 != nil {
		res.L3 = l3.finish(ctx, e, req.Record)
	}
	return res, nil
}

// l3Swap is the in-flight state of a floating-IP rotation: enough to put
// the record back exactly as it was, and enough to know which cloud
// objects are ours to destroy.
type l3Swap struct {
	// priorIP / priorFIPID / priorTags are the pre-swap record. Tags
	// are captured per candidate because adopting an address rewrites
	// each candidate's public_ip:* tag in place.
	priorIP    net.IP
	priorFIPID string
	priorTags  [][]string

	// newFIPID is the address now attached.
	newFIPID string
	// reservedHere: the executor minted newFIPID, so rollback may
	// delete it. An address the operator supplied is never deleted.
	reservedHere bool
	// boundIP is the address the box was told to configure on its
	// interface, "" if the bind was skipped or never ran. Rollback needs
	// it: an address left on the interface of a relay whose record no
	// longer names it is one the box will still source traffic from.
	boundIP net.IP
}

// beginL3 performs the swap and leaves the record naming the new
// address. It is step one of three; steps two and three are
// [l3Swap.rollback] and [l3Swap.finish].
//
// THE SEQUENCE, and why it is this way round:
//
//	reserve (if needed) → attach NEW → provider reads it back →
//	record adopts the new address → BIND on the box → verify it answers →
//	re-sign → store → unbind OLD → release OLD
//	(the last two in Rotate/finish, after the commit)
//
// The old address is never detached first. A Hetzner server keeps its
// own primary IPv4 and can hold two floating IPs at once, so between
// attach and release the relay answers on both, and any failure in
// between leaves every already-distributed pack still working. The
// previous implementation unassigned first, which meant a failure at
// the assign step took the relay off the address every recipient had
// while the record still named it — an outage manufactured out of a
// recovery attempt.
//
// THE INVARIANT: rec.PublicIP always names an address that is currently
// routed to rec.ServerID. Before the swap that is the old address;
// after a successful swap the new one; after a rolled-back swap the old
// one again, because rollback restores the record BEFORE it detaches
// anything. There is no instant at which the relay is reachable on no
// address at all: the swap only ever ADDS an address, and the server's
// own primary address is never touched by any of this.
//
// WHAT IS NOT VERIFIED HERE, stated because the gap is the difference
// between this being correct and this being proven. The provider adapter
// reads the address back from the cloud API and refuses to claim an
// attachment it cannot see, which proves the control plane accepted the
// change. BindAddress adds the guest-OS half, and its response is the
// box's own claim about what it did. Neither proves a packet from Iran
// reaches port 443 on the new address — that needs a dial from outside,
// which no unit test and no offline publisher can do. VerifyReachable is
// the seam for it, and it stays MANDATORY in spirit even now that the
// bind exists: the 2026-08-17 finding was precisely a case where every
// layer that could report success did.
func (e *Executor) beginL3(ctx context.Context, req *RotateRequest) (*l3Swap, error) {
	rec := req.Record
	st := &l3Swap{
		priorIP:    append(net.IP(nil), rec.PublicIP...),
		priorFIPID: rec.FloatingIPID,
		priorTags:  snapshotCandidateTags(rec),
		newFIPID:   req.NewFloatingIPID,
	}

	if st.newFIPID == "" {
		res, ok := e.Provider.(FloatingIPProvisioner)
		if !ok {
			return nil, ErrL3NoAddressSource
		}
		id, _, err := res.CreateFloatingIP(ctx, rec)
		if err != nil {
			return nil, fmt.Errorf("reserve floating IP: %w", err)
		}
		st.newFIPID, st.reservedHere = id, true
	}

	if err := e.Provider.AssignFloatingIP(ctx, rec, st.newFIPID); err != nil {
		// Nothing has been adopted onto the record by a failed
		// assign, but an address we just minted would leak.
		st.releaseIfReservedHere(ctx, e, rec)
		return nil, fmt.Errorf("assign new floating IP: %w", err)
	}

	// POST-CONDITIONS. The provider contract says AssignFloatingIP
	// moves the record's dialled address; these two checks are what
	// make that a contract rather than a comment. They are exported
	// because the LIVE path is the CLI's assign-fip verb, not this
	// executor, and a post-condition that only one of two
	// implementations runs is a post-condition on neither.
	//
	// An adapter that only sets FloatingIPID — which is what every
	// adapter did before Step 9, and what the Vultr and Stark adapters
	// still do — now fails here instead of returning success and
	// letting the binder sign a pack aimed at the burned address.
	if err := CheckAddressMoved(st.priorIP, rec.PublicIP); err != nil {
		st.rollback(ctx, e, rec)
		return nil, err
	}
	if err := CheckRecordAddressConsistent(rec); err != nil {
		st.rollback(ctx, e, rec)
		return nil, err
	}

	// THE GUEST-OS STEP, and it goes HERE: after the provider has
	// attached the address (there is nothing to bind before that) and
	// before anything asks whether the address answers (the bind is what
	// makes it answer). Delivered over the PRE-swap address, because the
	// box does not yet reply on the new one — that is the request's
	// whole purpose.
	if e.BindAddress != nil {
		if err := e.BindAddress(ctx, rec, st.priorIP, rec.PublicIP); err != nil {
			st.rollback(ctx, e, rec)
			return nil, fmt.Errorf("relay did not bind the new address: %w", err)
		}
		st.boundIP = append(net.IP(nil), rec.PublicIP...)
	}

	if e.VerifyReachable != nil {
		if err := e.VerifyReachable(ctx, rec); err != nil {
			st.rollback(ctx, e, rec)
			return nil, fmt.Errorf("new address did not verify: %w", err)
		}
	}
	return st, nil
}

// rollback puts the record back on the address it had and gives up the
// one it just took. Record FIRST, cloud SECOND: if the process dies
// between the two, an operator is left with a record naming a routed
// address plus an orphaned reservation — recoverable, and far better
// than the reverse, which is a record naming an address that is gone.
//
// Best-effort by construction. rollback runs on a path that is already
// failing; the caller's error is the one that matters, so problems here
// are swallowed rather than allowed to mask it. The cost of a swallowed
// error is a leaked address, which the wizard's teardown path reports.
func (st *l3Swap) rollback(ctx context.Context, e *Executor, rec *provider.OperatorRecord) {
	if st == nil || rec == nil {
		return
	}
	// The box first, while the record still names the new address and
	// the old one is still the one that works. An address left on the
	// interface after a rolled-back swap is one the relay may keep
	// choosing as a source address for its own traffic, on an address
	// that is about to be handed back.
	if len(st.boundIP) > 0 && e.UnbindAddress != nil {
		_ = e.UnbindAddress(ctx, rec, st.priorIP, st.boundIP)
		st.boundIP = nil
	}
	if len(st.priorIP) > 0 {
		rec.PublicIP = st.priorIP
	}
	rec.FloatingIPID = st.priorFIPID
	restoreCandidateTags(rec, st.priorTags)
	st.releaseIfReservedHere(ctx, e, rec)
	if !st.reservedHere && st.newFIPID != "" && st.newFIPID != st.priorFIPID {
		// Operator-owned address: detach so it is not left routing to
		// a relay no pack names, but never delete it.
		if res, ok := e.Provider.(FloatingIPProvisioner); ok {
			_, _ = res.ReleaseFloatingIP(ctx, rec, st.newFIPID)
		}
	}
}

func (st *l3Swap) releaseIfReservedHere(ctx context.Context, e *Executor, rec *provider.OperatorRecord) {
	if !st.reservedHere || st.newFIPID == "" {
		return
	}
	if res, ok := e.Provider.(FloatingIPProvisioner); ok {
		_, _ = res.ReleaseFloatingIP(ctx, rec, st.newFIPID)
	}
	st.reservedHere = false
}

// finish releases the address the relay moved off, after the new pack is
// signed and committed. Returns the operator-facing account.
func (st *l3Swap) finish(ctx context.Context, e *Executor, rec *provider.OperatorRecord) L3Outcome {
	out := L3Outcome{
		NewFloatingIPID:   st.newFIPID,
		PriorFloatingIPID: st.priorFIPID,
		ReservedHere:      st.reservedHere,
	}
	if st.priorFIPID == "" || st.priorFIPID == st.newFIPID {
		// The relay was on the server's own primary address (or is
		// converging onto the same floating IP). Nothing to give back.
		return out
	}
	res, ok := e.Provider.(FloatingIPProvisioner)
	if !ok {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"floating IP %s is still attached to this relay and still billing: this provider adapter cannot release addresses",
			st.priorFIPID))
		return out
	}

	// UNBIND BEFORE RELEASE. A released address goes back to the
	// provider's pool and may be issued to another customer's server; a
	// box that still has it configured will keep choosing it as a source
	// address for its own outbound traffic, from an address that is by
	// then routed somewhere else. The control address is the NEW one,
	// which the probe above has just proven answers.
	//
	// A failure here does not fail the rotation — the pack is signed and
	// committed, and undoing that to tidy up an interface would be the
	// wrong trade — but it does stop the release: an address that is
	// still claimed by a live box is better left reserved (costing
	// money, visibly) than handed to a stranger.
	//
	// An executor with NEITHER seam wired never bound anything and has
	// no way to unbind, so there is nothing for it to undo and the
	// release goes ahead. An executor with a bind seam and no unbind
	// seam is asymmetrically configured — it can put addresses on a
	// relay and not take them off — and that one stops, because it is
	// the shape that quietly accumulates claimed-but-released addresses.
	switch {
	case len(st.priorIP) == 0:
		// Nothing known to be on the interface.
	case e.UnbindAddress != nil:
		if err := e.UnbindAddress(ctx, rec, rec.PublicIP, st.priorIP); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"could not tell the relay to drop its previous address %s (%v), so floating IP %s was NOT released: "+
					"handing it back while this relay still has it configured would give another customer an address this box still claims. "+
					"It is still reserved and still billing",
				st.priorIP, err, st.priorFIPID))
			return out
		}
	case e.BindAddress != nil:
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"floating IP %s (%s) was NOT removed from the relay's interface — this executor can bind addresses but has no unbind seam wired — "+
				"so it has not been released either; it is still reserved and still billing",
			st.priorFIPID, st.priorIP))
		return out
	}

	deleted, err := res.ReleaseFloatingIP(ctx, rec, st.priorFIPID)
	switch {
	case err != nil:
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"could not release the previous address (floating IP %s): %v — it is still on your account and still billing",
			st.priorFIPID, err))
	case !deleted:
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"floating IP %s was detached but left reserved because daal-deploy did not create it — it is still on your account and still billing",
			st.priorFIPID))
	}
	out.PriorReleased = deleted
	return out
}

// CheckAddressMoved is the post-condition that turns "the provider says
// it swapped" into "the record actually moved".
//
// The failure it catches is the whole reason Step 9 exists: an adapter
// that records the floating-IP id and leaves rec.PublicIP naming the
// burned address produces a rotation that reports success, re-signs a
// pack, and changes nothing a censor can see. That is strictly worse
// than a visible failure, because the operator stops looking.
func CheckAddressMoved(before, after net.IP) error {
	if len(after) == 0 {
		return fmt.Errorf("%w: the record has no public IP after the swap", ErrL3AddressUnchanged)
	}
	if len(before) > 0 && before.Equal(after) {
		return fmt.Errorf("%w: still %s — this provider adapter attaches the address without moving the record onto it, "+
			"so a pack signed now would point straight back at the address you are rotating away from", ErrL3AddressUnchanged, after)
	}
	return nil
}

// CheckRecordAddressConsistent enforces that the record's two copies of
// the dialled address agree: OperatorRecord.PublicIP, which the client
// outbound is built from, and each candidate's public_ip:* tag, which
// the risk graph groups on and the recommender reads back when deciding
// whether an address is in cooldown.
//
// They are separate fields, so they can drift, and a drifted record
// signs a pack that dials one address while declaring another — the
// address cooldown then keeps firing against a relay that has already
// moved, which reads to the operator as "rotation did not help".
func CheckRecordAddressConsistent(rec *provider.OperatorRecord) error {
	if rec == nil || len(rec.PublicIP) == 0 {
		return nil
	}
	want := publicIPTag + rec.PublicIP.String()
	for i, c := range rec.Candidates {
		seen := 0
		for _, t := range c.PublicRiskTags {
			if !strings.HasPrefix(t, publicIPTag) {
				continue
			}
			seen++
			if t != want {
				return fmt.Errorf("%w: candidate %d (%s) carries %q while the record says %s",
					ErrRecordAddressInconsistent, i, c.Family, t, rec.PublicIP)
			}
		}
		if seen == 0 {
			return fmt.Errorf("%w: candidate %d (%s) carries no %s tag at all",
				ErrRecordAddressInconsistent, i, c.Family, publicIPTag)
		}
	}
	return nil
}

// publicIPTag is the candidate-tag prefix carrying the dialled address.
// Mirrors the providers' own constant; the recommender keys its L3
// recommendation off the same string (recommender.go), so all three
// must stay in step.
const publicIPTag = "public_ip:"

func snapshotCandidateTags(rec *provider.OperatorRecord) [][]string {
	if rec == nil {
		return nil
	}
	out := make([][]string, len(rec.Candidates))
	for i, c := range rec.Candidates {
		out[i] = append([]string(nil), c.PublicRiskTags...)
	}
	return out
}

func restoreCandidateTags(rec *provider.OperatorRecord, tags [][]string) {
	if rec == nil || len(tags) != len(rec.Candidates) {
		// Length mismatch means the provider replaced the candidate
		// set wholesale, which no L3 path does. Restoring a
		// mismatched snapshot would corrupt the record, so leave it.
		return
	}
	for i := range rec.Candidates {
		rec.Candidates[i].PublicRiskTags = tags[i]
	}
}

// commitRotationTx runs the three-step transaction. Returns
// priorWasActive=true iff MarkPriorInactive flipped any row.
//
// The function is package-private and takes an [SBPTx] so the unit
// test can fault-inject at any of the three steps.
func commitRotationTx(tx SBPTx, row SignedSBP) (priorWasActive bool, err error) {
	// We cannot tell from MarkPriorInactive's signature whether it
	// flipped anything; conservatively report PriorWasActive=true
	// once we successfully complete the full rotation. The wizard
	// uses this to decide if "Revert" is shown — false-positives on
	// first rotate are acceptable (the wizard checks the history
	// table again before rendering the button).
	if err = tx.MarkPriorInactive(row.OperatorID); err != nil {
		return false, fmt.Errorf("mark prior inactive: %w", err)
	}
	if err = tx.InsertActive(row); err != nil {
		return false, fmt.Errorf("insert active: %w", err)
	}
	if err = tx.UpdateOperatorActiveProjection(row.OperatorID, row); err != nil {
		return false, fmt.Errorf("update projection: %w", err)
	}
	if err = tx.Commit(); err != nil {
		// Commit failed: ensure the tx is closed (the in-memory
		// fake honours Rollback after a failed Commit; SQLite
		// does too — Commit failures auto-rollback but we call
		// Rollback explicitly for symmetry).
		_ = tx.Rollback()
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// rotationReason is a one-line, identifier-free label persisted
// alongside the SignedSBP row. Used by the operator to read the
// rotation history; never shown to recipients.
func rotationReason(rec RotationRecommendation) string {
	return fmt.Sprintf("%s | %s | conf=%s", rec.Level, rec.Reason, rec.Confidence)
}

// Revert is the inverse of Rotate ONLY in the history table. The caller
// specifies which SignedSBP history row to restore (typically the most
// recent inactive one). The executor flips that row to active=1, marks
// the current active=0, and updates the projection. No Provider or
// Binder call is made — Revert is a pure DB operation; the underlying
// VPS keeps whatever state Rotate left it in.
//
// AFTER AN L3 THAT IS USUALLY THE WRONG THING TO DO, and the UI must
// not offer it as a symmetric undo. A committed L3 releases the
// previous address (Rotate step 6), so the pack Revert makes active
// again names an address that no longer routes to this relay — or, once
// the provider re-issues it, to somebody else's server entirely. Revert
// is meaningful for the levels where the packs differ only in
// credentials or cover host and every candidate address still points at
// the same box; for a completed address swap the way back is another
// rotation, not this.
//
// The narrow exception is a rotation that failed BEFORE its commit:
// there the swap has already been unwound in the cloud, no new row was
// inserted, and there is nothing for Revert to do either.
func (e *Executor) Revert(ctx context.Context, target SignedSBP) error {
	if e.Store == nil {
		return ErrExecutorIncomplete
	}
	tx, err := e.Store.Begin()
	if err != nil {
		return fmt.Errorf("revert tx begin: %w", err)
	}
	if err := tx.MarkPriorInactive(target.OperatorID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("revert mark inactive: %w", err)
	}
	target.Active = true
	if err := tx.InsertActive(target); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("revert insert active: %w", err)
	}
	if err := tx.UpdateOperatorActiveProjection(target.OperatorID, target); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("revert projection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("revert commit: %w", err)
	}
	_ = ctx // ctx accepted for symmetry with Rotate; reserved for future cancellation hooks
	return nil
}
