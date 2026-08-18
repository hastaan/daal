package routestore

import (
	"database/sql"
	"fmt"
	"time"
)

// SubscriptionRow mirrors a row in the subscriptions table.
type SubscriptionRow struct {
	SubscriptionID     string
	PublisherID        string
	DisplayName        string
	URLSecretKey       string // key into secrets_kv where the URL is age-encrypted
	ProfileUpdateMin   int
	ProfileTitle       string
	SupportURL         string
	LastRefreshBucket  string
	LastRefreshOutcome string
	LastGoodRefreshBkt string
	ImportedAt         string
}

// UpsertSubscription writes a subscription row.
func (s *Store) UpsertSubscription(r SubscriptionRow) error {
	_, err := s.db.Exec(`
INSERT INTO subscriptions
  (subscription_id, publisher_id, display_name, url_secret_key,
   profile_update_min, profile_title, support_url,
   last_refresh_bucket, last_refresh_outcome, last_good_refresh_bkt, imported_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(subscription_id) DO UPDATE SET
  display_name = excluded.display_name,
  profile_update_min = excluded.profile_update_min,
  profile_title = excluded.profile_title,
  support_url = excluded.support_url,
  last_refresh_bucket = excluded.last_refresh_bucket,
  last_refresh_outcome = excluded.last_refresh_outcome,
  last_good_refresh_bkt = excluded.last_good_refresh_bkt
`, r.SubscriptionID, r.PublisherID, r.DisplayName, r.URLSecretKey,
		clampInterval(r.ProfileUpdateMin), r.ProfileTitle, r.SupportURL,
		r.LastRefreshBucket, r.LastRefreshOutcome, r.LastGoodRefreshBkt, r.ImportedAt)
	return err
}

// GetSubscription returns a subscription row or sql.ErrNoRows.
func (s *Store) GetSubscription(id string) (SubscriptionRow, error) {
	row := s.db.QueryRow(`
SELECT subscription_id, publisher_id, display_name, url_secret_key,
       profile_update_min, profile_title, support_url,
       last_refresh_bucket, last_refresh_outcome, last_good_refresh_bkt, imported_at
FROM subscriptions WHERE subscription_id = ?`, id)
	return scanSubscription(row.Scan)
}

// ListSubscriptions returns all subscription rows in insertion order.
func (s *Store) ListSubscriptions() ([]SubscriptionRow, error) {
	rows, err := s.db.Query(`
SELECT subscription_id, publisher_id, display_name, url_secret_key,
       profile_update_min, profile_title, support_url,
       last_refresh_bucket, last_refresh_outcome, last_good_refresh_bkt, imported_at
FROM subscriptions ORDER BY imported_at, subscription_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubscriptionRow
	for rows.Next() {
		r, err := scanSubscription(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteSubscription removes a subscription row and its URL secret.
func (s *Store) DeleteSubscription(id string) error {
	row, err := s.GetSubscription(id)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM subscriptions WHERE subscription_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM secrets_kv WHERE k = ?`, row.URLSecretKey); err != nil {
		return err
	}
	return tx.Commit()
}

func scanSubscription(scan func(...any) error) (SubscriptionRow, error) {
	var r SubscriptionRow
	if err := scan(&r.SubscriptionID, &r.PublisherID, &r.DisplayName, &r.URLSecretKey,
		&r.ProfileUpdateMin, &r.ProfileTitle, &r.SupportURL,
		&r.LastRefreshBucket, &r.LastRefreshOutcome, &r.LastGoodRefreshBkt, &r.ImportedAt); err != nil {
		return r, err
	}
	return r, nil
}

func clampInterval(min int) int {
	if min < 60 {
		return 60
	}
	if min > 7*24*60 {
		return 7 * 24 * 60
	}
	return min
}

// SetPublisherRevocation sets the per-publisher revocation URL/fingerprint
// columns (Phase 1.5A v2 manifest).
func (s *Store) SetPublisherRevocation(publisherID, url, fpHex string) error {
	_, err := s.db.Exec(`
UPDATE publishers SET revocation_url = ?, revocation_fp_hex = ?
 WHERE publisher_id = ?`, url, fpHex, publisherID)
	return err
}

// MarkPublisherRevocationChecked records that revocation was refreshed at
// `now` for publisherID. It is hour-bucketed.
func (s *Store) MarkPublisherRevocationChecked(publisherID string, now time.Time) error {
	_, err := s.db.Exec(`
UPDATE publishers SET last_revocation_check = ? WHERE publisher_id = ?`,
		HourBucket(now), publisherID)
	return err
}

// ListPublishersWithRevocationURL returns publishers that have set a
// revocation URL — the targets of the per-publisher refresh loop.
func (s *Store) ListPublishersWithRevocationURL() ([]PublisherRow, error) {
	rows, err := s.db.Query(`
SELECT publisher_id, display_name, trust_level, first_seen, last_seen_bundle, key_status,
       rotation_chain_json, revocation_sources_json, COALESCE(user_assigned_label, ''),
       COALESCE(revocation_url, ''), COALESCE(revocation_fp_hex, ''),
       COALESCE(last_revocation_check, '')
FROM publishers WHERE revocation_url <> ''
ORDER BY publisher_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublisherRow
	for rows.Next() {
		var p PublisherRow
		var rotation, revoc, _u, _f, _l string
		if err := rows.Scan(&p.PublisherID, &p.DisplayName, &p.TrustLevel,
			&p.FirstSeen, &p.LastSeenBundle, &p.KeyStatus,
			&rotation, &revoc, &p.UserAssignedLabel,
			&_u, &_f, &_l); err != nil {
			return nil, err
		}
		p.RevocationURL = _u
		p.RevocationFingerprintHex = _f
		p.LastRevocationCheck = _l
		out = append(out, p)
	}
	return out, rows.Err()
}

// LocalHistoryWindow is the retention bound on every append-only local
// history table in this store: refresh_audit and diagnostics_explain.
// Rows in an hour bucket older than this are deleted at the next write.
//
// WHY THERE IS A BOUND AT ALL. Both tables were append-only with no
// prune and no cap until this pass, and — this is the part that decides
// the number — neither has a production READER. `refresh_audit` is
// never SELECTed anywhere in the tree; `LatestDiagnosticsExplain` has
// no caller. So what accumulated was pure liability: on a device that
// gets seized, a row per refresh attempt for the life of the install is
// an hour-resolution record of when this device was switched on and
// reaching the network, and 8,760 rows a year of it is a pattern of
// life. Nothing was reading it, so nothing is lost by bounding it.
//
// WHY 72 HOURS and not "the last N rows". A count bound is a promise
// nobody can state ("we keep 500 refreshes" means a different span on
// every device); a time bound is one sentence a user can be told and a
// reviewer can check: nothing here is older than three days. Three days
// is long enough to answer the only question these tables exist to
// answer — "have my refreshes been failing, and since when" — across a
// weekend, and short enough that the surviving rows describe an
// incident rather than a routine.
const LocalHistoryWindow = 72 * time.Hour

// AppendRefreshAudit records a single refresh attempt, then drops audit
// rows that have aged out of LocalHistoryWindow.
//
// The prune runs on the write path rather than on a scheduler tick
// deliberately: a retention bound enforced by a scheduled job is only
// as reliable as the scheduling, and this codebase has just finished
// paying for a 30-day TTL whose sweep had no caller (see
// specs/network-memory-v1.md). Pruning where the row is born means the
// bound holds on any host, with or without a tick pump. The cost is one
// indexed comparison against the `bucket` TEXT column per refresh
// attempt, of which there are single digits per minute at worst.
func (s *Store) AppendRefreshAudit(kind, refID, outcome string, bytesIn int64, viaTunnel bool, now time.Time) error {
	via := 0
	if viaTunnel {
		via = 1
	}
	if _, err := s.db.Exec(`
INSERT INTO refresh_audit (kind, ref_id, bucket, outcome, bytes_in, via_tunnel)
VALUES (?, ?, ?, ?, ?, ?)`, kind, refID, HourBucket(now), outcome, bytesIn, via); err != nil {
		return err
	}
	// Best-effort: a failed prune must never turn into a failed
	// refresh. The next write retries it.
	_, _ = s.db.Exec(`DELETE FROM refresh_audit WHERE bucket < ?`,
		HourBucket(now.Add(-LocalHistoryWindow)))
	return nil
}

// PruneLocalHistory drops every refresh_audit and diagnostics_explain
// row older than LocalHistoryWindow, without writing one first.
//
// WHY THIS EXISTS SEPARATELY FROM THE WRITE-PATH PRUNE. Pruning where
// the row is born makes the bound independent of any scheduler, which
// is the right default — but it means rows only age out when a NEW row
// is born, so the property it actually delivers is "these tables span
// at most 72 hours", not "nothing here is older than 72 hours". The
// difference is the whole forensic question: the refresh path is driven
// by DaalVpnService.startSchedulerPump, which runs only while the
// tunnel is up, so a user who disconnects — or whose phone is taken —
// freezes the table with its last 72 hours intact, indefinitely. A
// device seized in March otherwise still carries an hour-resolution
// record of the last three days it was reaching the network.
//
// Calling this on every open closes that gap with the one event that
// happens regardless of ticks, tunnels and pumps: the app starting. The
// clock is the caller's (abi.nowUTC) so the engine's single clock seam
// still governs and a simulated-time test cannot be surprised.
func (s *Store) PruneLocalHistory(now time.Time) error {
	cutoff := HourBucket(now.Add(-LocalHistoryWindow))
	if _, err := s.db.Exec(`DELETE FROM refresh_audit WHERE bucket < ?`, cutoff); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM diagnostics_explain WHERE bucket < ?`, cutoff)
	return err
}

// CountRefreshAudit returns the number of rows currently retained. It
// exists for the retention test and for a future diagnostics reader;
// nothing on the production path calls it.
func (s *Store) CountRefreshAudit() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM refresh_audit`).Scan(&n)
	return n, err
}

// PutDiagnosticsExplain upserts a "why this route?" record for the given
// hour bucket, then drops rows older than LocalHistoryWindow.
//
// The upsert collapses every call within one hour onto a single row,
// which matters: the Android UI polls engine_diagnostics_explain every
// 500 ms, and each poll lands here. The prune is therefore a no-op
// comparison the overwhelming majority of the time and only deletes at
// a bucket rollover.
func (s *Store) PutDiagnosticsExplain(bucket, why, skippedJSON string) error {
	if _, err := s.db.Exec(`
INSERT INTO diagnostics_explain (bucket, why_chose_route, skipped_families_json)
VALUES (?, ?, ?)
ON CONFLICT(bucket) DO UPDATE SET
  why_chose_route = excluded.why_chose_route,
  skipped_families_json = excluded.skipped_families_json
`, bucket, why, skippedJSON); err != nil {
		return err
	}
	// The cutoff is derived from the bucket the CALLER supplied, not
	// from time.Now(): this store has no clock of its own, and reading
	// one here would let a test that drives simulated time silently
	// delete the rows it just wrote.
	if t, err := time.Parse("2006-01-02T15:04:05Z", bucket); err == nil {
		_, _ = s.db.Exec(`DELETE FROM diagnostics_explain WHERE bucket < ?`,
			HourBucket(t.Add(-LocalHistoryWindow)))
	}
	return nil
}

// CountDiagnosticsExplain returns the number of retained rows. Test and
// future-reader surface only.
func (s *Store) CountDiagnosticsExplain() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM diagnostics_explain`).Scan(&n)
	return n, err
}

// LatestDiagnosticsExplain returns the most recent diagnostics_explain row
// (by bucket lexicographic order, which equals time order for hour
// buckets in RFC3339Z).
func (s *Store) LatestDiagnosticsExplain() (bucket, why, skipped string, err error) {
	row := s.db.QueryRow(`
SELECT bucket, why_chose_route, skipped_families_json
FROM diagnostics_explain ORDER BY bucket DESC LIMIT 1`)
	if err := row.Scan(&bucket, &why, &skipped); err != nil {
		if err == sql.ErrNoRows {
			return "", "", "[]", nil
		}
		return "", "", "", fmt.Errorf("diagnostics_explain: %w", err)
	}
	return
}
