package rotation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
// relaypackvalidate stack. Production wires this to
// publisher/deploy/relaypack.BindAndSign via [BinderFunc].
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

// BinderFunc adapts a function to the [Binder] interface. The
// production caller (in wizard's commands.rs / TODO) supplies a
// closure over relaypack.BindAndSign; tests supply a fake.
type BinderFunc func(rec *provider.OperatorRecord, priv ed25519.PrivateKey, now time.Time) (BinderResult, error)

// Bind implements [Binder] for [BinderFunc].
func (f BinderFunc) Bind(rec *provider.OperatorRecord, priv ed25519.PrivateKey, now time.Time) (BinderResult, error) {
	return f(rec, priv, now)
}

// SBPStore is the persistence contract the executor uses to commit
// the signed_sbps history transaction (V003). Concrete implementation
// lives in the Tauri layer (Rust); for unit-test coverage we use an
// in-memory store. Insert/MarkInactive/UpdateOperatorActive happen
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

// SBPWritePath is a hook the production caller uses to persist the
// fresh SBP bytes to the staging directory. Tests pass a fake.
type SBPWritePath func(rec *provider.OperatorRecord, sbpBytes []byte, signedAt time.Time) (path string, err error)

// Clock abstracts time.Now for deterministic tests. Production
// passes [WallClock]; the wallclock-pin test passes a synthetic
// clock so the L3 budget assertion is reproducible.
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

// WallClock is the production clock.
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
// transactional rotate-step. One executor per wizard process; all
// fields are required.
type Executor struct {
	Provider provider.Provider
	Binder   Binder
	Store    SBPStore
	WriteSBP SBPWritePath
	Clock    Clock
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

	// NewFloatingIPID is required iff Recommendation.Level == L3.
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
}

// errors -------------------------------------------------------------

var (
	ErrNilRequest         = errors.New("rotation: nil RotateRequest")
	ErrNilRecord          = errors.New("rotation: nil OperatorRecord")
	ErrNilPrivKey         = errors.New("rotation: empty private key")
	ErrL3MissingFipID     = errors.New("rotation: L3 requires NewFloatingIPID")
	ErrL3WallClockBudget  = errors.New("rotation: L3 fast path exceeded the V1.5 wall-clock budget")
	ErrUnsupportedLevel   = errors.New("rotation: unsupported level")
	ErrExecutorIncomplete = errors.New("rotation: Executor missing required field")
)

// Rotate runs the chosen rotation level, re-signs the RelayPack,
// and commits the (mark-prior-inactive, insert-active, update-
// projection) triple inside one DB transaction. On Provider or
// Binder failure the transaction never opens; on store failure the
// transaction rolls back and the rec is left unchanged on disk
// (the in-memory rec may already reflect a successful Provider
// call — the caller is responsible for retrying or surfacing the
// error to the operator).
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
	switch req.Recommendation.Level {
	case L3:
		if err := e.runL3(ctx, req); err != nil {
			return nil, fmt.Errorf("rotation L3: %w", err)
		}
	case L1, L2, L4, L5, L6:
		if err := e.Provider.Reprovision(ctx, req.Record, req.ReprovisionOpts); err != nil {
			return nil, fmt.Errorf("rotation %s reprovision: %w", req.Recommendation.Level, err)
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLevel, req.Recommendation.Level)
	}

	// 2. Re-sign the RelayPack against the (possibly mutated) rec.
	now := e.Clock.Now()
	bind, err := e.Binder.Bind(req.Record, req.PrivKey, now)
	if err != nil {
		return nil, fmt.Errorf("rotation bind: %w", err)
	}

	// 3. Persist the bytes to the staging dir.
	sbpPath, err := e.WriteSBP(req.Record, bind.SBPBytes, now)
	if err != nil {
		return nil, fmt.Errorf("rotation write sbp: %w", err)
	}

	// 4. Enforce the L3 wall-clock budget before publishing the
	// new SBP as active. A budget miss is a failed rotation from
	// the operator's point of view, so the history projection must
	// not be committed after we already know the invariant broke.
	dur := e.Clock.Since(start)
	if req.Recommendation.Level == L3 && dur > L3FastPathBudget {
		return nil, fmt.Errorf("%w: took %s > %s", ErrL3WallClockBudget, dur, L3FastPathBudget)
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
		return nil, fmt.Errorf("rotation tx begin: %w", err)
	}
	priorWasActive, err := commitRotationTx(tx, row)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("rotation tx commit: %w", err)
	}

	return &RotateResult{
		SignedSBP:      row,
		WallClock:      dur,
		PriorWasActive: priorWasActive,
	}, nil
}

// runL3 executes the floating-IP fast path: unassign the current
// FIP (if any), assign the new one, update the in-memory record.
// At V1.5 the box's PublicIP slot is not mutated by AssignFloatingIP
// directly — the family-side QR carries the floating IP via the
// CandidateMeta render path; the Provider's Assign call updates
// rec.FloatingIPID and rec.PublicIP per the FRP-4a contract.
func (e *Executor) runL3(ctx context.Context, req *RotateRequest) error {
	if req.NewFloatingIPID == "" {
		return ErrL3MissingFipID
	}
	if req.Record.FloatingIPID != "" && req.Record.FloatingIPID != req.NewFloatingIPID {
		if err := e.Provider.UnassignFloatingIP(ctx, req.Record); err != nil {
			return fmt.Errorf("unassign prior floating IP: %w", err)
		}
	}
	if err := e.Provider.AssignFloatingIP(ctx, req.Record, req.NewFloatingIPID); err != nil {
		return fmt.Errorf("assign new floating IP: %w", err)
	}
	return nil
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

// Revert is the inverse of Rotate. The caller specifies which
// SignedSBP history row to restore (typically the most recent
// inactive one). The executor flips that row to active=1, marks
// the current active=0, and updates the projection. No Provider
// or Binder call is made — Revert is a pure DB operation; the
// underlying VPS keeps whatever state Rotate left it in.
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
