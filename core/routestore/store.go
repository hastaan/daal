package routestore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store is a thread-safe wrapper around a sqlite database plus an
// age-encrypted secret key/value table. All on-disk timestamps are
// hour-bucketed by HourBucket().
type Store struct {
	db      *sql.DB
	dbPath  string
	keyPath string
	key     []byte // age X25519 identity bytes; zeroed on Close.
}

// Open creates or opens the store under dir. The directory and database
// file are created with 0700/0600 permissions on POSIX systems.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("routestore: dir required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "daal.db")
	keyPath := filepath.Join(dir, "secrets.key")

	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		zero(key)
		return nil, fmt.Errorf("routestore: open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		zero(key)
		db.Close()
		return nil, fmt.Errorf("routestore: apply schema: %w", err)
	}
	// Forward-only additive migrations. ALTER TABLE ADD COLUMN errors on
	// an already-present column; we tolerate that to allow re-opening
	// stores created on older builds.
	for _, m := range migrations {
		_, _ = db.Exec(m)
	}
	// Ensure file mode after sqlite created the file.
	_ = os.Chmod(dbPath, 0o600)

	return &Store{db: db, dbPath: dbPath, keyPath: keyPath, key: key}, nil
}

// Close shuts down the database and zeros the in-memory key bytes.
func (s *Store) Close() error {
	zero(s.key)
	s.key = nil
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// PanicWipe deletes the database, the secret key file, and zeros the
// in-memory key. It is the user-facing "panic wipe" affordance.
func (s *Store) PanicWipe() error {
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
	zero(s.key)
	s.key = nil
	var first error
	if err := os.Remove(s.dbPath); err != nil && !os.IsNotExist(err) {
		first = err
	}
	if err := os.Remove(s.keyPath); err != nil && !os.IsNotExist(err) && first == nil {
		first = err
	}
	// SQLite WAL/SHM should not exist with journal_mode=DELETE, but remove
	// defensively.
	for _, sfx := range []string{"-wal", "-shm", "-journal"} {
		_ = os.Remove(s.dbPath + sfx)
	}
	return first
}

// HourBucket truncates t to the hour and renders RFC3339Z (per V0.3 hour
// bucketing).
func HourBucket(t time.Time) string {
	return t.UTC().Truncate(time.Hour).Format("2006-01-02T15:04:05Z")
}

// PublisherRow mirrors the rows in `publishers`.
type PublisherRow struct {
	PublisherID       string
	DisplayName       string
	TrustLevel        string
	FirstSeen         string
	LastSeenBundle    string
	KeyStatus         string
	RotationChain     []string
	RevocationSources []string
	UserAssignedLabel string

	// Phase 1.5A v2 columns.
	RevocationURL            string
	RevocationFingerprintHex string
	LastRevocationCheck      string
}

// RouteRow mirrors a row in `routes`.
type RouteRow struct {
	RouteID              string
	TransportFamily      string
	Engine               string
	SourceType           string
	PublisherID          string
	PublisherLabel       string
	TrustState           string
	ScarcityClass        string
	ModesAllowed         []string
	ExpiresAt            string
	ImportedAt           string
	LastSuccessBucket    string
	LastFailureBucket    string
	LastFailureCategory  string
	ConsecutiveFailures  int
	CooldownUntil        string
	BytesUsedThisHour    int64
	BytesUsedThisSession int64
	UserNote             string

	// Phase 3A. Carried verbatim from the SBP-v1 manifest;
	// opaque to the routestore. See
	// specs/transport-families-v1.md and specs/sbp-v1.md.
	FamilySpecificConfigJSON     string
	CaveatFAIR                   string
	ExperimentalMinEngineVersion string

	// Phase 3B. RendezvousPriorityJSON is carried verbatim
	// from the SBP-v1 manifest as a JSON-encoded array of
	// channel IDs (per specs/rendezvous-channels-v1.md). The
	// `LastWinningRendezvousChannel` field is engine-recorded
	// on a successful Solicit and persists across session
	// epochs; empty string means "no winner recorded yet."
	RendezvousPriorityJSON       string
	LastWinningRendezvousChannel string

	// Phase 3C. MasqueEndpoint is the bundle-supplied target
	// URL for `transport_family = "masque"` routes (per
	// specs/masque-ladder-v1.md). Empty for non-MASQUE routes.
	// The bundle parser enforces `https://` + non-empty path
	// + non-MASQUE rejection; the routestore stores whatever
	// it is given.
	MasqueEndpoint string

	// Phase 3D. Refraction-family fields. The routestore is
	// opaque to the contents; the bundle parser is the
	// gatekeeper. See specs/psiphon-route-v1.md and
	// specs/conjure-route-v1.md.
	//
	//   - PsiphonBundleBlob — the opaque upstream-Psiphon
	//     publisher bundle bytes. Empty for non-psiphon
	//     routes; size sanity-checked at the parser layer.
	//   - ConjurePhantomSubnetsJSON — JSON array of CIDRs.
	//     Empty array (`"[]"`) for non-conjure routes.
	//   - ConjureStationPubkeyHex — 32-byte curve25519 station
	//     pubkey (64 hex chars). Empty for non-conjure routes.
	//   - ConjureDecoyPoolJSON — JSON array of RFC 1123
	//     hostnames. Empty array for non-conjure routes.
	PsiphonBundleBlob         []byte
	ConjurePhantomSubnetsJSON string
	ConjureStationPubkeyHex   string
	ConjureDecoyPoolJSON      string

	// Phase 3E. The locked-at-3E `transport_module_slug` field,
	// carried verbatim from the SBP-v1 manifest. Empty for
	// non-`transport_module` routes; the bundle parser is the
	// gatekeeper. The actual module bytes are NOT persisted in
	// the routestore — they live in the bundle's
	// `transport_modules[]` table and the engine's wasm Loader
	// holds the active module in memory. See
	// specs/wasm-transport-v1.md and specs/route-object-v1.md
	// "Phase 3E".
	TransportModuleSlug string

	// Phase 3F. RedistributionPolicy is the closed-enum re-share
	// policy declared by the publisher; one of {"", "none",
	// "delegated_n", "transitive"}. Empty (legacy / unset) is
	// treated as "none" by the engine (fail-closed).
	// RedistributionCap is the uint8 cap (0..255) — only
	// meaningful for `delegated_n`. Both are persisted in the
	// SAME `redistribution_policy` column on disk: the on-wire
	// shape is `<policy>` or `<policy>:<cap>`. The local
	// re-share counter is in `secrets_kv:delegate_share_counter:<route_id>`,
	// NOT here. See specs/delegate-keys-v1.md.
	RedistributionPolicy string
	RedistributionCap    uint8

	// FRP-2 (Phase 30) RelayPack profile additive fields. All
	// sentinel-empty for non-RelayPack routes. Per-candidate
	// fields are populated from the `_relaypack` sub-object
	// inside `RouteManifestEntry.FamilySpecificConfig`; bundle-
	// level fields (RelayPackID, FreshnessURL,
	// SharedRiskGraphJSON) are read from `Manifest.RelayPack`
	// and denormalised onto every per-route row for read-
	// locality at the FRP-3 selector boundary. The selector
	// reads them via the existing GetRoute / ListRoutes
	// scanners; no new method is needed. See
	// specs/relaypack-v1.md "Importer behaviour" and
	// `phases of development/30-phase-frp-2-import-store-preservation.md`.
	//
	//   - ExposureMode := direct_vps | cdn_fronted | "" (legacy)
	//   - FamilyClass  := vps-native | vps-possible | external-ecosystem | "" (legacy)
	//   - ProbingRiskClass := low | moderate | high | "" (legacy)
	//   - PublicRiskTags / OriginRiskTags — canonical-JSON-encoded
	//     in the `*_risk_tags_json` columns; default '[]'.
	//   - ModifiersJSON — canonical JSON of []bundle.Modifier;
	//     '' at V1.5/V1.6 (validator hard-rejects per RP013).
	//     FRP-12 lifts.
	//   - RelayPackID / FreshnessURL / SharedRiskGraphJSON —
	//     bundle-level metadata denormalised per route.
	//     FreshnessURL is '' at V1.5 (validator hard-rejects per
	//     RP021); FRP-8 lifts at V1.6.
	ExposureMode        string
	FamilyClass         string
	ProbingRiskClass    string
	PublicRiskTags      []string
	OriginRiskTags      []string
	ModifiersJSON       string
	RelayPackID         string
	FreshnessURL        string
	SharedRiskGraphJSON string
}

// EncodeRedistributionPolicy renders a RouteRow's policy + cap
// into the on-disk TEXT shape used by the
// `redistribution_policy` column. Empty in / empty out (the
// schema default). `delegated_n` MUST carry a non-zero cap; the
// caller is the bundle-import path which has already validated
// the publisher's manifest. See specs/route-object-v1.md
// "Phase 3F".
func EncodeRedistributionPolicy(policy string, cap uint8) string {
	switch policy {
	case "":
		return ""
	case "delegated_n":
		// uint8 max 255 → at most 3 ASCII chars; fmt is fine.
		return fmt.Sprintf("delegated_n:%d", cap)
	default:
		return policy
	}
}

// DecodeRedistributionPolicy parses the on-disk TEXT shape into
// (policy, cap). Unknown / malformed values map to ("none", 0)
// per fail-closed discipline; the bundle parser is the
// gatekeeper for what enters the column in the first place.
func DecodeRedistributionPolicy(s string) (string, uint8) {
	if s == "" {
		return "", 0
	}
	if s == "none" || s == "transitive" {
		return s, 0
	}
	const prefix = "delegated_n:"
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		var n int
		_, err := fmt.Sscanf(s[len(prefix):], "%d", &n)
		if err != nil || n < 0 || n > 255 {
			return "none", 0
		}
		return "delegated_n", uint8(n)
	}
	// Unknown shape — fail closed.
	return "none", 0
}

// UpsertPublisher writes a publisher row (insert or update).
func (s *Store) UpsertPublisher(p PublisherRow) error {
	rotation, _ := json.Marshal(p.RotationChain)
	revoc, _ := json.Marshal(p.RevocationSources)
	_, err := s.db.Exec(`
INSERT INTO publishers
  (publisher_id, display_name, trust_level, first_seen, last_seen_bundle, key_status,
   rotation_chain_json, revocation_sources_json, user_assigned_label)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(publisher_id) DO UPDATE SET
  display_name = excluded.display_name,
  trust_level = excluded.trust_level,
  last_seen_bundle = excluded.last_seen_bundle,
  key_status = excluded.key_status,
  rotation_chain_json = excluded.rotation_chain_json,
  revocation_sources_json = excluded.revocation_sources_json
`, p.PublisherID, p.DisplayName, p.TrustLevel, p.FirstSeen, p.LastSeenBundle, p.KeyStatus,
		string(rotation), string(revoc), p.UserAssignedLabel)
	return err
}

// GetPublisher returns the publisher row or sql.ErrNoRows.
func (s *Store) GetPublisher(id string) (PublisherRow, error) {
	row := s.db.QueryRow(`
SELECT publisher_id, display_name, trust_level, first_seen, last_seen_bundle, key_status,
       rotation_chain_json, revocation_sources_json, COALESCE(user_assigned_label, '')
FROM publishers WHERE publisher_id = ?`, id)
	var p PublisherRow
	var rotation, revoc string
	if err := row.Scan(&p.PublisherID, &p.DisplayName, &p.TrustLevel,
		&p.FirstSeen, &p.LastSeenBundle, &p.KeyStatus,
		&rotation, &revoc, &p.UserAssignedLabel); err != nil {
		return p, err
	}
	_ = json.Unmarshal([]byte(rotation), &p.RotationChain)
	_ = json.Unmarshal([]byte(revoc), &p.RevocationSources)
	return p, nil
}

// AppendTrustAudit logs a trust transition.
func (s *Store) AppendTrustAudit(publisherID, from, to, reason string, now time.Time) error {
	_, err := s.db.Exec(`
INSERT INTO trust_audit (ts_bucket, publisher_id, from_state, to_state, reason)
VALUES (?, ?, ?, ?, ?)`,
		HourBucket(now), publisherID, from, to, reason)
	return err
}

// UpsertRoute writes a route row.
func (s *Store) UpsertRoute(r RouteRow) error {
	modes, _ := json.Marshal(r.ModesAllowed)
	// Phase 3A: pass-through of the SBP-v1 widening fields. Default
	// empty values match the additive-ALTER defaults so pre-3A
	// callers that leave these fields zeroed continue to round-trip.
	fsc := r.FamilySpecificConfigJSON
	if fsc == "" {
		fsc = "{}"
	}
	// Phase 3B: rendezvous priority defaults to an empty array
	// (engine falls back to rendezvous.DefaultPriority).
	rp := r.RendezvousPriorityJSON
	if rp == "" {
		rp = "[]"
	}
	// Phase 3D: refraction-family JSON columns default to
	// empty-array shape so old data round-trips with the
	// additive-ALTER defaults.
	cps := r.ConjurePhantomSubnetsJSON
	if cps == "" {
		cps = "[]"
	}
	cdp := r.ConjureDecoyPoolJSON
	if cdp == "" {
		cdp = "[]"
	}
	// Phase 3D: nil []byte binds as SQL NULL on the
	// modernc.org/sqlite driver, which collides with the
	// NOT NULL constraint on `psiphon_bundle_blob`. Coerce
	// to an explicit empty slice so the column receives the
	// additive-ALTER default shape.
	psi := r.PsiphonBundleBlob
	if psi == nil {
		psi = []byte{}
	}
	// Phase 3F: encode the (policy, cap) pair into the single
	// `redistribution_policy` TEXT column. Empty in / empty out;
	// see EncodeRedistributionPolicy.
	rrp := EncodeRedistributionPolicy(r.RedistributionPolicy, r.RedistributionCap)
	// FRP-2: RelayPack additive columns. JSON-encode the tag
	// slices to canonical sentinel-empty TEXT defaults; copy
	// the bundle-level denormalised fields verbatim. nil
	// slices marshal to "null"; coerce to "[]" so on-disk
	// shape matches the `'[]'` schema default for legacy rows.
	prtBytes, _ := json.Marshal(r.PublicRiskTags)
	prt := string(prtBytes)
	if prt == "null" || prt == "" {
		prt = "[]"
	}
	ortBytes, _ := json.Marshal(r.OriginRiskTags)
	ort := string(ortBytes)
	if ort == "null" || ort == "" {
		ort = "[]"
	}
	srgj := r.SharedRiskGraphJSON
	if srgj == "" {
		srgj = "[]"
	}
	_, err := s.db.Exec(`
INSERT INTO routes
  (route_id, transport_family, engine, source_type, publisher_id, publisher_label,
   trust_state, scarcity_class, modes_allowed_json, expires_at, imported_at,
   last_success_bucket, last_failure_bucket, last_failure_category,
   consecutive_failures, cooldown_until, bytes_used_this_hour, bytes_used_this_session,
   user_note, family_specific_config_json, caveat_fa_ir, experimental_min_engine_version,
   rendezvous_priority_json, last_winning_rendezvous_channel, masque_endpoint,
   psiphon_bundle_blob, conjure_phantom_subnets_json, conjure_station_pubkey_hex,
   conjure_decoy_pool_json, transport_module_slug, redistribution_policy,
   exposure_mode, family_class, probing_risk_class,
   public_risk_tags_json, origin_risk_tags_json, modifiers_json,
   relay_pack_id, freshness_url, shared_risk_graph_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 0, NULL, 0, 0,
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(route_id) DO UPDATE SET
  transport_family = excluded.transport_family,
  scarcity_class = excluded.scarcity_class,
  expires_at = excluded.expires_at,
  trust_state = excluded.trust_state,
  modes_allowed_json = excluded.modes_allowed_json,
  publisher_label = excluded.publisher_label,
  source_type = excluded.source_type,
  user_note = excluded.user_note,
  family_specific_config_json = excluded.family_specific_config_json,
  caveat_fa_ir = excluded.caveat_fa_ir,
  experimental_min_engine_version = excluded.experimental_min_engine_version,
  rendezvous_priority_json = excluded.rendezvous_priority_json,
  masque_endpoint = excluded.masque_endpoint,
  psiphon_bundle_blob = excluded.psiphon_bundle_blob,
  conjure_phantom_subnets_json = excluded.conjure_phantom_subnets_json,
  conjure_station_pubkey_hex = excluded.conjure_station_pubkey_hex,
  conjure_decoy_pool_json = excluded.conjure_decoy_pool_json,
  transport_module_slug = excluded.transport_module_slug,
  redistribution_policy = excluded.redistribution_policy,
  exposure_mode          = excluded.exposure_mode,
  family_class           = excluded.family_class,
  probing_risk_class     = excluded.probing_risk_class,
  public_risk_tags_json  = excluded.public_risk_tags_json,
  origin_risk_tags_json  = excluded.origin_risk_tags_json,
  modifiers_json         = excluded.modifiers_json,
  relay_pack_id          = excluded.relay_pack_id,
  freshness_url          = excluded.freshness_url,
  shared_risk_graph_json = excluded.shared_risk_graph_json
  -- last_winning_rendezvous_channel is NEVER overwritten by an
  -- UpsertRoute (it is engine-recorded; bundle re-imports must
  -- not clobber the user's accumulated history). Use
  -- RecordRendezvousWinner to update it.
  -- (3D / 3E follow the same discipline; 3F is no different.
  -- The device-local re-share counter lives under
  -- secrets_kv key prefix delegate_share_counter:, NEVER on
  -- the route row, so a re-import that updates the
  -- redistribution_policy column can refresh the publisher
  -- policy without losing the user accumulated re-share count.)
  -- (FRP-2 RelayPack columns are publisher-declared bundle
  -- metadata; re-importing the same .sbp refreshes them with
  -- byte-identical values — Idempotence per phase-doc invariant 20.)
`, r.RouteID, r.TransportFamily, r.Engine, r.SourceType, r.PublisherID, r.PublisherLabel,
		r.TrustState, r.ScarcityClass, string(modes), r.ExpiresAt, r.ImportedAt, r.UserNote,
		fsc, r.CaveatFAIR, r.ExperimentalMinEngineVersion,
		rp, r.LastWinningRendezvousChannel, r.MasqueEndpoint,
		psi, cps, r.ConjureStationPubkeyHex, cdp, r.TransportModuleSlug, rrp,
		r.ExposureMode, r.FamilyClass, r.ProbingRiskClass,
		prt, ort, r.ModifiersJSON,
		r.RelayPackID, r.FreshnessURL, srgj)
	return err
}

// RecordRendezvousWinner persists the channel ID that just
// completed a successful Solicit on routeID. Phase 3B per-route
// persistence per specs/rendezvous-channels-v1.md.
//
// channelID MUST be a known channel from the v1 closed list;
// the routestore performs no validation (the caller is
// `core/abi.RecordRendezvousWinner`, which is the bridge from
// the rendezvous.Selector and which validates).
func (s *Store) RecordRendezvousWinner(routeID, channelID string) error {
	_, err := s.db.Exec(
		`UPDATE routes SET last_winning_rendezvous_channel = ? WHERE route_id = ?`,
		channelID, routeID)
	return err
}

// MarkRouteRevoked sets a route's trust_state to revoked.
func (s *Store) MarkRouteRevoked(routeID string) error {
	_, err := s.db.Exec(`UPDATE routes SET trust_state='revoked' WHERE route_id=?`, routeID)
	return err
}

// UpdateRouteScarcity assigns or updates a route's scarcity_class
// (a.k.a. budget tag). Phase 2A. Idempotent. The caller is expected to
// have validated the tag against the closed `core/budget` cap map; the
// routestore performs no semantic validation — it stores whatever it
// is given so old data can round-trip even if the tag set evolves.
func (s *Store) UpdateRouteScarcity(routeID, tag string) error {
	_, err := s.db.Exec(`UPDATE routes SET scarcity_class = ? WHERE route_id = ?`, tag, routeID)
	return err
}

// UpdateRouteBytesHour writes the routes.bytes_used_this_hour column
// for routeID. Phase 2A. The companion hour-bucket cursor is persisted
// by the budget engine in secrets_kv (see core/budget/persist.go).
func (s *Store) UpdateRouteBytesHour(routeID string, consumed int64) error {
	_, err := s.db.Exec(`UPDATE routes SET bytes_used_this_hour = ? WHERE route_id = ?`, consumed, routeID)
	return err
}

// MarkPublisherRoutesRevoked sets every route under publisherID to revoked.
func (s *Store) MarkPublisherRoutesRevoked(publisherID string) error {
	_, err := s.db.Exec(`UPDATE routes SET trust_state='revoked' WHERE publisher_id=?`, publisherID)
	return err
}

// ListRoutes returns all routes in insertion order.
func (s *Store) ListRoutes() ([]RouteRow, error) {
	rows, err := s.db.Query(`
SELECT route_id, transport_family, engine, source_type, publisher_id, publisher_label,
       trust_state, scarcity_class, modes_allowed_json, expires_at, imported_at,
       COALESCE(last_success_bucket, ''), COALESCE(last_failure_bucket, ''),
       COALESCE(last_failure_category, ''), consecutive_failures,
       COALESCE(cooldown_until, ''), bytes_used_this_hour, bytes_used_this_session,
       COALESCE(user_note, ''),
       COALESCE(family_specific_config_json, '{}'),
       COALESCE(caveat_fa_ir, ''),
       COALESCE(experimental_min_engine_version, ''),
       COALESCE(rendezvous_priority_json, '[]'),
       COALESCE(last_winning_rendezvous_channel, ''),
       COALESCE(masque_endpoint, ''),
       COALESCE(psiphon_bundle_blob, x''),
       COALESCE(conjure_phantom_subnets_json, '[]'),
       COALESCE(conjure_station_pubkey_hex, ''),
       COALESCE(conjure_decoy_pool_json, '[]'),
       COALESCE(transport_module_slug, ''),
       COALESCE(redistribution_policy, ''),
       COALESCE(exposure_mode, ''),
       COALESCE(family_class, ''),
       COALESCE(probing_risk_class, ''),
       COALESCE(public_risk_tags_json, '[]'),
       COALESCE(origin_risk_tags_json, '[]'),
       COALESCE(modifiers_json, ''),
       COALESCE(relay_pack_id, ''),
       COALESCE(freshness_url, ''),
       COALESCE(shared_risk_graph_json, '[]')
FROM routes ORDER BY imported_at, route_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouteRow
	for rows.Next() {
		var r RouteRow
		var modes, rrp, prt, ort string
		if err := rows.Scan(&r.RouteID, &r.TransportFamily, &r.Engine, &r.SourceType,
			&r.PublisherID, &r.PublisherLabel, &r.TrustState, &r.ScarcityClass, &modes,
			&r.ExpiresAt, &r.ImportedAt, &r.LastSuccessBucket, &r.LastFailureBucket,
			&r.LastFailureCategory, &r.ConsecutiveFailures, &r.CooldownUntil,
			&r.BytesUsedThisHour, &r.BytesUsedThisSession, &r.UserNote,
			&r.FamilySpecificConfigJSON, &r.CaveatFAIR, &r.ExperimentalMinEngineVersion,
			&r.RendezvousPriorityJSON, &r.LastWinningRendezvousChannel,
			&r.MasqueEndpoint,
			&r.PsiphonBundleBlob, &r.ConjurePhantomSubnetsJSON,
			&r.ConjureStationPubkeyHex, &r.ConjureDecoyPoolJSON,
			&r.TransportModuleSlug, &rrp,
			&r.ExposureMode, &r.FamilyClass, &r.ProbingRiskClass,
			&prt, &ort, &r.ModifiersJSON,
			&r.RelayPackID, &r.FreshnessURL, &r.SharedRiskGraphJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(modes), &r.ModesAllowed)
		r.RedistributionPolicy, r.RedistributionCap = DecodeRedistributionPolicy(rrp)
		_ = json.Unmarshal([]byte(prt), &r.PublicRiskTags)
		_ = json.Unmarshal([]byte(ort), &r.OriginRiskTags)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRoute returns a single route or sql.ErrNoRows.
func (s *Store) GetRoute(id string) (RouteRow, error) {
	row := s.db.QueryRow(`
SELECT route_id, transport_family, engine, source_type, publisher_id, publisher_label,
       trust_state, scarcity_class, modes_allowed_json, expires_at, imported_at,
       COALESCE(last_success_bucket, ''), COALESCE(last_failure_bucket, ''),
       COALESCE(last_failure_category, ''), consecutive_failures,
       COALESCE(cooldown_until, ''), bytes_used_this_hour, bytes_used_this_session,
       COALESCE(user_note, ''),
       COALESCE(family_specific_config_json, '{}'),
       COALESCE(caveat_fa_ir, ''),
       COALESCE(experimental_min_engine_version, ''),
       COALESCE(rendezvous_priority_json, '[]'),
       COALESCE(last_winning_rendezvous_channel, ''),
       COALESCE(masque_endpoint, ''),
       COALESCE(psiphon_bundle_blob, x''),
       COALESCE(conjure_phantom_subnets_json, '[]'),
       COALESCE(conjure_station_pubkey_hex, ''),
       COALESCE(conjure_decoy_pool_json, '[]'),
       COALESCE(transport_module_slug, ''),
       COALESCE(redistribution_policy, ''),
       COALESCE(exposure_mode, ''),
       COALESCE(family_class, ''),
       COALESCE(probing_risk_class, ''),
       COALESCE(public_risk_tags_json, '[]'),
       COALESCE(origin_risk_tags_json, '[]'),
       COALESCE(modifiers_json, ''),
       COALESCE(relay_pack_id, ''),
       COALESCE(freshness_url, ''),
       COALESCE(shared_risk_graph_json, '[]')
FROM routes WHERE route_id = ?`, id)
	var r RouteRow
	var modes, rrp, prt, ort string
	if err := row.Scan(&r.RouteID, &r.TransportFamily, &r.Engine, &r.SourceType,
		&r.PublisherID, &r.PublisherLabel, &r.TrustState, &r.ScarcityClass, &modes,
		&r.ExpiresAt, &r.ImportedAt, &r.LastSuccessBucket, &r.LastFailureBucket,
		&r.LastFailureCategory, &r.ConsecutiveFailures, &r.CooldownUntil,
		&r.BytesUsedThisHour, &r.BytesUsedThisSession, &r.UserNote,
		&r.FamilySpecificConfigJSON, &r.CaveatFAIR, &r.ExperimentalMinEngineVersion,
		&r.RendezvousPriorityJSON, &r.LastWinningRendezvousChannel,
		&r.MasqueEndpoint,
		&r.PsiphonBundleBlob, &r.ConjurePhantomSubnetsJSON,
		&r.ConjureStationPubkeyHex, &r.ConjureDecoyPoolJSON,
		&r.TransportModuleSlug, &rrp,
		&r.ExposureMode, &r.FamilyClass, &r.ProbingRiskClass,
		&prt, &ort, &r.ModifiersJSON,
		&r.RelayPackID, &r.FreshnessURL, &r.SharedRiskGraphJSON); err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(modes), &r.ModesAllowed)
	r.RedistributionPolicy, r.RedistributionCap = DecodeRedistributionPolicy(rrp)
	_ = json.Unmarshal([]byte(prt), &r.PublicRiskTags)
	_ = json.Unmarshal([]byte(ort), &r.OriginRiskTags)
	return r, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
