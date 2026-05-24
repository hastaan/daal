package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/bundle-go/publisher"
	"daal/core/routestore"
	"daal/core/trust"
)

// Manifest is the embedded Tier-1/2 material a build ships with. It is
// produced by tools/genfixtures (or test setup) and embedded via go:embed
// in the embedded sub-package. This struct is the canonical in-memory form.
type Manifest struct {
	ProjectRootPub        ed25519.PublicKey
	PublisherRootPubs     map[string]ed25519.PublicKey // fingerprintHex → pub
	PublisherDisplayNames map[string]string            // fingerprintHex → label
	PrimaryPointers       PointerSet
	FallbackPointers      PointerSet
	Tier2Seeds            [][]byte // raw .sbp bytes
}

// Provider is what core/abi calls into. It carries the embedded manifest
// plus the live store + dialer.
type Provider struct {
	store    *routestore.Store
	adapter  *trust.StoreAdapter
	manifest *Manifest
	dialerFn func() Dialer
	now      func() time.Time
}

// NewProvider constructs a bootstrap provider.
func NewProvider(store *routestore.Store, adapter *trust.StoreAdapter, m *Manifest, dialerFn func() Dialer, now func() time.Time) *Provider {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if dialerFn == nil {
		dialerFn = func() Dialer { return NewDirectDialer(15 * time.Second) }
	}
	return &Provider{
		store:    store,
		adapter:  adapter,
		manifest: m,
		dialerFn: dialerFn,
		now:      now,
	}
}

// Status describes the bootstrap state of the device.
type Status struct {
	HaveSeeds              bool   `json:"have_seeds"`
	HaveDirectory          bool   `json:"have_directory"`
	DirectoryExpiresAt     string `json:"directory_expires_at,omitempty"`
	DirectoryAgeHours      int    `json:"directory_age_hours,omitempty"`
	Tier2Remaining         int    `json:"tier2_remaining"`
	NextRefreshRecommended bool   `json:"next_refresh_recommended"`
}

// PinTier1 idempotently inserts a `publishers` row at trust_level="official"
// for every Tier-1 publisher in the manifest, plus the project root. Routes
// from these publishers will silently import (no trust prompt) per
// `specs/publisher-keys-v1.md`.
func (p *Provider) PinTier1() error {
	if p.manifest == nil {
		return errors.New("bootstrap: nil manifest")
	}
	bucket := routestore.HourBucket(p.now())
	pinOne := func(pub ed25519.PublicKey, displayName string) error {
		fp := bundle.PublisherFingerprint(pub).Hex
		if _, err := p.store.GetPublisher(fp); err == nil {
			return nil // already pinned
		}
		row := routestore.PublisherRow{
			PublisherID:       fp,
			DisplayName:       displayName,
			TrustLevel:        "official",
			FirstSeen:         bucket,
			LastSeenBundle:    bucket,
			KeyStatus:         "active",
			RotationChain:     []string{},
			RevocationSources: []string{},
		}
		if err := p.store.UpsertPublisher(row); err != nil {
			return err
		}
		return p.store.AppendTrustAudit(fp, "*", "official", "tier-1 pin (embedded)", p.now())
	}
	if p.manifest.ProjectRootPub != nil {
		if err := pinOne(p.manifest.ProjectRootPub, "Daal Project Root"); err != nil {
			return err
		}
	}
	for fpHex, pub := range p.manifest.PublisherRootPubs {
		name := p.manifest.PublisherDisplayNames[fpHex]
		if name == "" {
			name = "Daal Bootstrap Publisher"
		}
		if err := pinOne(pub, name); err != nil {
			return err
		}
	}
	return nil
}

// InstallSeedsResult is the JSON returned by engine_bootstrap_install_seeds.
type InstallSeedsResult struct {
	InstalledCount int `json:"installed_count"`
	SkippedCount   int `json:"skipped_existing"`
}

// InstallSeeds writes Tier-2 seed bundles into the routestore. Each seed
// is imported through the same importer the friend-share path uses; since
// the publisher fingerprint matches a Tier-1 pin, no trust prompt is
// raised.
//
// Idempotent: if a seed's bundle id is already represented (any of its
// route ids exist in the store), the seed is counted as skipped.
func (p *Provider) InstallSeeds() (InstallSeedsResult, error) {
	if err := p.PinTier1(); err != nil {
		return InstallSeedsResult{}, err
	}
	res := InstallSeedsResult{}
	for _, body := range p.manifest.Tier2Seeds {
		// Quick existence check by route id from the manifest.
		parsed, err := bundle.ParseSBP(bytesReader(body), int64(len(body)))
		if err != nil {
			continue
		}
		alreadyHave := true
		for _, r := range parsed.Manifest.Routes {
			if _, err := p.store.GetRoute(r.ID); err != nil {
				alreadyHave = false
				break
			}
		}
		if alreadyHave && len(parsed.Manifest.Routes) > 0 {
			res.SkippedCount++
			continue
		}
		v, err := importer.ImportBytes(body, p.adapter, publisher.DefaultWordlists(), p.now())
		if err != nil {
			return res, fmt.Errorf("bootstrap: install seed: %w", err)
		}
		if v.Kind != importer.VerdictImported {
			return res, fmt.Errorf("bootstrap: seed not silently imported (kind=%d, reason=%s)", v.Kind, v.Reason)
		}
		// Annotate routes: source_type = tier2_seed, scarcity = emergency.
		for _, r := range parsed.Manifest.Routes {
			row, err := p.store.GetRoute(r.ID)
			if err != nil {
				continue
			}
			row.SourceType = SourceTypeTier2Seed
			row.ScarcityClass = "emergency"
			row.ModesAllowed = []string{"lifeline"}
			_ = p.store.UpsertRoute(row)
		}
		res.InstalledCount++
	}
	return res, nil
}

// RefreshResult is the JSON returned by engine_bootstrap_refresh.
type RefreshResult struct {
	DirectoryFetched bool   `json:"directory_fetched"`
	PointerUsed      string `json:"pointer_used,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	RoutesAdded      int    `json:"routes_added"`
	RoutesUpdated    int    `json:"routes_updated"`
	Reason           string `json:"reason,omitempty"`
}

// Refresh fetches a Tier-3 bootstrap directory through whichever dialer
// the provider was configured with. It tries primary pointers in order,
// then falls back to the fallback set. On success the directory's routes
// are imported and any existing Tier-2 seeds are demoted to fallback-only.
func (p *Provider) Refresh(ctx context.Context, timeout time.Duration) (RefreshResult, error) {
	if err := p.PinTier1(); err != nil {
		return RefreshResult{}, err
	}
	now := p.now()

	// Verify both pointer sets first, against the project root pubkey.
	if err := VerifyPointerSet(p.manifest.PrimaryPointers, p.manifest.ProjectRootPub, now); err != nil {
		return RefreshResult{Reason: "primary_pointers_invalid: " + err.Error()},
			fmt.Errorf("bootstrap: primary pointers invalid: %w", err)
	}
	if err := VerifyPointerSet(p.manifest.FallbackPointers, p.manifest.ProjectRootPub, now); err != nil {
		return RefreshResult{Reason: "fallback_pointers_invalid: " + err.Error()},
			fmt.Errorf("bootstrap: fallback pointers invalid: %w", err)
	}

	dialer := p.dialerFn()
	tryOrder := append([]Pointer{}, p.manifest.PrimaryPointers.Pointers...)
	tryOrder = append(tryOrder, p.manifest.FallbackPointers.Pointers...)

	var lastErr error
	for _, ptr := range tryOrder {
		fr, err := Fetch(ctx, ptr.URL, ptr.ExpectedPublisherFingerprintHex, dialer, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		// Apply.
		added, updated, expiresAt, err := p.applyDirectory(fr.Bytes, now)
		if err != nil {
			lastErr = err
			continue
		}
		// Demote Tier-2 seeds.
		_ = p.demoteTier2(now)
		return RefreshResult{
			DirectoryFetched: true,
			PointerUsed:      ptr.URL,
			ExpiresAt:        expiresAt,
			RoutesAdded:      added,
			RoutesUpdated:    updated,
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("bootstrap: no pointers configured")
	}
	return RefreshResult{Reason: lastErr.Error()}, lastErr
}

// applyDirectory imports a directory .sbp into the store. The bundle's
// publisher must already be pinned (Tier-1) so the importer takes the
// silent-import path. Routes get scarcity_class=emergency and
// source_type=tier3_directory.
func (p *Provider) applyDirectory(body []byte, now time.Time) (added, updated int, expiresAt string, err error) {
	parsed, err := bundle.ParseSBP(bytesReader(body), int64(len(body)))
	if err != nil {
		return 0, 0, "", fmt.Errorf("apply: parse: %w", err)
	}
	if parsed.Manifest.Bundle.Type != BundleTypeDirectory {
		return 0, 0, "", fmt.Errorf("apply: expected bundle.type=directory, got %q", parsed.Manifest.Bundle.Type)
	}
	expiresAt = parsed.Manifest.Bundle.ExpiresAt

	v, err := importer.ImportBytes(body, p.adapter, publisher.DefaultWordlists(), now)
	if err != nil {
		return 0, 0, expiresAt, fmt.Errorf("apply: import: %w", err)
	}
	if v.Kind != importer.VerdictImported {
		return 0, 0, expiresAt, fmt.Errorf("apply: directory not silent-imported (kind=%d, reason=%s)",
			v.Kind, v.Reason)
	}
	// Walk imported routes; mark as tier-3.
	for _, r := range parsed.Manifest.Routes {
		row, err := p.store.GetRoute(r.ID)
		if err != nil {
			continue
		}
		isNew := row.SourceType != SourceTypeTier3Dir
		row.SourceType = SourceTypeTier3Dir
		// Directory routes are still emergency (shared pool) per V1.5;
		// publisher policy may opt them out in V2.
		row.ScarcityClass = "emergency"
		if len(row.ModesAllowed) == 0 {
			row.ModesAllowed = []string{"lifeline"}
		}
		_ = p.store.UpsertRoute(row)
		if isNew {
			added++
		} else {
			updated++
		}
	}
	return added, updated, expiresAt, nil
}

// demoteTier2 sets a UserNote marker on every Tier-2 route so the path
// manager and the diagnostics screen can render the "fallback only"
// status. We don't have a dedicated column for this in the V1 schema and
// don't need one — the source_type stays `tier2_seed` while the marker
// rides in user_note.
func (p *Provider) demoteTier2(now time.Time) error {
	rows, err := p.store.ListRoutes()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.SourceType != SourceTypeTier2Seed {
			continue
		}
		row.UserNote = "tier2_demoted_at=" + routestore.HourBucket(now)
		_ = p.store.UpsertRoute(row)
	}
	return nil
}

// Status returns a Status struct for engine_bootstrap_status.
func (p *Provider) Status() (Status, error) {
	rows, err := p.store.ListRoutes()
	if err != nil {
		return Status{}, err
	}
	st := Status{}
	var directoryExpiry time.Time
	for _, row := range rows {
		switch row.SourceType {
		case SourceTypeTier2Seed:
			st.HaveSeeds = true
			st.Tier2Remaining++
		case SourceTypeTier3Dir:
			st.HaveDirectory = true
			t, _ := time.Parse(time.RFC3339, row.ExpiresAt)
			if directoryExpiry.IsZero() || t.Before(directoryExpiry) {
				directoryExpiry = t
			}
		}
	}
	if !directoryExpiry.IsZero() {
		st.DirectoryExpiresAt = directoryExpiry.UTC().Format(time.RFC3339)
		hours := int(p.now().Sub(directoryExpiry).Hours())
		if hours < 0 {
			hours = -hours
			// "age" is how long since fetch; we don't track fetch_at, so
			// approximate: dir is fresh while now < expiry-72h.
			st.DirectoryAgeHours = 0
		} else {
			st.DirectoryAgeHours = hours
		}
		st.NextRefreshRecommended = p.now().After(directoryExpiry.Add(-12 * time.Hour))
	} else if st.HaveSeeds {
		st.NextRefreshRecommended = true
	}
	return st, nil
}

// bytesReader avoids an import cycle by inlining the trivial helper.
func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

type byteReader struct {
	b   []byte
	pos int64
}

func (r *byteReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, errEOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, errEOF
	}
	return n, nil
}

var errEOF = errors.New("EOF")
