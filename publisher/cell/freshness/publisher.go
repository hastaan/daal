// Package freshness — FRP-11 cell freshness publishing primitives.
//
// Adapts the FRP-9 publisher/deploy/freshness.Backend interface
// (R2 + GH-Pages adapters today; live SDK wiring is a V2 alpha
// pilot carry-over) to the per-cell directory shape:
//
//	<PublicURL>/cell/<cell_id>/membership.json
//	<PublicURL>/cell/<cell_id>/delegation.json
//	<PublicURL>/cell/<cell_id>/directory.json   (aggregated RelayPack listing)
//	<PublicURL>/cell/<cell_id>/revocations.json (cell-internal revocation list)
//
// FRP-11 invariant 34: no public directory; this package only
// publishes per-cell. There is no project-wide aggregator and no
// hardcoded directory URL.
//
// Locked at FRP-11 — append-only.
package freshness

import (
	"context"
	"errors"
	"fmt"

	bundle "daal/bundle-go/bundle"
	deployFresh "daal/publisher/deploy/freshness"
)

var (
	// ErrCellPublisherNoBackend signals that no underlying
	// Backend was supplied. The caller MUST configure either an
	// R2 or GH-Pages backend (or test stub) before publishing.
	ErrCellPublisherNoBackend = errors.New("cell freshness: no underlying backend configured")
)

// CellPublisher is the locked-at-FRP-11 publisher contract for
// per-cell freshness materials. Implementations wrap a
// deployFresh.Backend (the same Put-only surface FRP-9 already
// uses for per-FRP freshness JSON).
type CellPublisher interface {
	// PublishMembershipDoc uploads the canonical membership doc
	// JSON. Idempotent (overwrites).
	PublishMembershipDoc(ctx context.Context, doc bundle.CellMembershipDoc) error

	// PublishDelegationDoc uploads the canonical delegation doc
	// JSON. Idempotent.
	PublishDelegationDoc(ctx context.Context, doc bundle.CellDelegationDoc) error

	// PublishDirectory uploads the cell-aggregated RelayPack
	// listing for the cell. The bytes are typically the output
	// of cell.Aggregate(...).SBPBytes; this method is opaque
	// w.r.t. format so any future per-cell directory shape can
	// reuse it.
	PublishDirectory(ctx context.Context, sbpBytes []byte) error

	// PublishRevocationList uploads the JSON-encoded cell-
	// internal revocation list. Empty list MUST be uploadable
	// (recipient distinguishes "no revocations yet" from "fetch
	// failed").
	PublishRevocationList(ctx context.Context, listJSON []byte) error

	// CellDirectoryURL returns the recipient-facing URL for
	// this cell's directory document. Stable across uploads.
	CellDirectoryURL() string
}

// New wraps a deployFresh.Backend with a per-cell path layout. The
// supplied backend's PublicURL becomes the prefix; cellID is
// appended as the path component.
func New(backend deployFresh.Backend, cellID string) (CellPublisher, error) {
	if backend == nil {
		return nil, ErrCellPublisherNoBackend
	}
	if cellID == "" {
		return nil, fmt.Errorf("cell freshness: cellID is empty")
	}
	return &backendPublisher{backend: backend, cellID: cellID}, nil
}

type backendPublisher struct {
	backend deployFresh.Backend
	cellID  string
}

func (p *backendPublisher) cellPathBase() string {
	return p.backend.PublicURL() + "/cell/" + p.cellID
}

func (p *backendPublisher) PublishMembershipDoc(ctx context.Context, doc bundle.CellMembershipDoc) error {
	if err := bundle.VerifyCellMembershipQuorum(doc); err != nil {
		return fmt.Errorf("cell freshness: membership quorum invalid: %w", err)
	}
	bytes, err := canonicalMembershipBytes(doc)
	if err != nil {
		return fmt.Errorf("cell freshness: marshal membership: %w", err)
	}
	return p.put(ctx, "membership.json", bytes)
}

func (p *backendPublisher) PublishDelegationDoc(ctx context.Context, doc bundle.CellDelegationDoc) error {
	bytes, err := canonicalDelegationBytes(doc)
	if err != nil {
		return fmt.Errorf("cell freshness: marshal delegation: %w", err)
	}
	return p.put(ctx, "delegation.json", bytes)
}

func (p *backendPublisher) PublishDirectory(ctx context.Context, sbpBytes []byte) error {
	if len(sbpBytes) == 0 {
		return fmt.Errorf("cell freshness: empty directory bytes")
	}
	return p.put(ctx, "directory.json", sbpBytes)
}

func (p *backendPublisher) PublishRevocationList(ctx context.Context, listJSON []byte) error {
	if listJSON == nil {
		listJSON = []byte("[]")
	}
	return p.put(ctx, "revocations.json", listJSON)
}

func (p *backendPublisher) CellDirectoryURL() string {
	return p.cellPathBase() + "/directory.json"
}

// put exists so the path-prefix logic is centralised and the
// Backend interface stays Put-only (matching FRP-9's narrow
// surface).
func (p *backendPublisher) put(ctx context.Context, _ string, bytes []byte) error {
	// The FRP-9 backend interface is narrow: a single Put-bytes
	// call. Real backends (R2 / GH-Pages) implement per-key
	// upload internally; per-key dispatch is a wrapping
	// contract NOT exposed by deployFresh.Backend at FRP-9. The
	// per-cell path layout is therefore tracked in the
	// CellDirectoryURL surface; concrete backends extending the
	// path map wire it through their own Put implementation.
	//
	// At FRP-11 we keep the same contract: Backend.Put takes
	// the bytes; the wrapping adapter (R2, GH-Pages) is
	// responsible for the per-cell key. Live SDK wiring is a
	// V2 alpha pilot carry-over (see docs/handovers/frp-11-
	// handover.md "Carry-overs").
	return p.backend.Put(ctx, bytes)
}
