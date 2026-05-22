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

// AppendRefreshAudit records a single refresh attempt.
func (s *Store) AppendRefreshAudit(kind, refID, outcome string, bytesIn int64, viaTunnel bool, now time.Time) error {
	via := 0
	if viaTunnel {
		via = 1
	}
	_, err := s.db.Exec(`
INSERT INTO refresh_audit (kind, ref_id, bucket, outcome, bytes_in, via_tunnel)
VALUES (?, ?, ?, ?, ?, ?)`, kind, refID, HourBucket(now), outcome, bytesIn, via)
	return err
}

// PutDiagnosticsExplain upserts a "why this route?" record for the given
// hour bucket.
func (s *Store) PutDiagnosticsExplain(bucket, why, skippedJSON string) error {
	_, err := s.db.Exec(`
INSERT INTO diagnostics_explain (bucket, why_chose_route, skipped_families_json)
VALUES (?, ?, ?)
ON CONFLICT(bucket) DO UPDATE SET
  why_chose_route = excluded.why_chose_route,
  skipped_families_json = excluded.skipped_families_json
`, bucket, why, skippedJSON)
	return err
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
