package freshness

import (
	"context"
	"errors"
)

// Backend is the FRP-controlled storage surface that hosts the
// signed freshness JSON. The wizard chooses one at deploy time;
// the chosen backend's PublicURL becomes
// Manifest.RelayPack.FreshnessURL.
//
// The interface is intentionally narrow: Put-only. The recipient
// reads the URL via ordinary HTTPS GET in core/refresh/.
type Backend interface {
	// PublicURL is the HTTPS URL recipients fetch. Determined
	// by the backend's account + bucket / repo configuration.
	// Stable across uploads.
	PublicURL() string

	// Put uploads the bytes; idempotent (overwrites). The
	// backend MUST publish atomically — partial reads must
	// never observe a torn document.
	Put(ctx context.Context, bytes []byte) error
}

// ErrBackendNotImplemented is returned by backends whose live
// SDK is not in the publisher module graph at this commit.
var ErrBackendNotImplemented = errors.New("freshness: backend not implemented in this build")
