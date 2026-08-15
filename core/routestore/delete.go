package routestore

import "fmt"

// perRouteSecretKeys returns the secrets_kv keys owned by a single route,
// so a hard delete leaves no orphaned per-route secrets behind. Keep in
// sync with the writers: delegate.counterSecretKey (core/abi) and the
// budget engine (core/budget/persist.go, `budget:bucket:<route_id>`).
func perRouteSecretKeys(routeID string) []string {
	return []string{
		"delegate_share_counter:" + routeID,
		"budget:bucket:" + routeID,
	}
}

// DeleteRoute hard-deletes a single imported route and its per-route
// secrets. Unlike MarkRouteRevoked (a soft trust_state flip that keeps the
// row), this removes the route entirely so it vanishes from the UI and can
// never be re-selected. Deleting an absent route is a no-op (nil error).
func (s *Store) DeleteRoute(routeID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM routes WHERE route_id = ?`, routeID); err != nil {
		return fmt.Errorf("delete route: %w", err)
	}
	for _, k := range perRouteSecretKeys(routeID) {
		if _, err := tx.Exec(`DELETE FROM secrets_kv WHERE k = ?`, k); err != nil {
			return fmt.Errorf("delete route secret %q: %w", k, err)
		}
	}
	return tx.Commit()
}

// DeletePublisher hard-deletes a publisher and ALL of its imported routes
// (and their per-route secrets), plus the publisher's own device-local
// bookkeeping. Returns the number of routes removed. Because
// routes.publisher_id has a foreign key onto publishers, the routes MUST
// be deleted first; both happen in one transaction. Deleting an absent
// publisher is a no-op (0, nil).
func (s *Store) DeletePublisher(publisherID string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// Collect the route ids first so we can purge their secrets.
	rows, err := tx.Query(`SELECT route_id FROM routes WHERE publisher_id = ?`, publisherID)
	if err != nil {
		return 0, fmt.Errorf("list publisher routes: %w", err)
	}
	var routeIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		routeIDs = append(routeIDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

	for _, id := range routeIDs {
		for _, k := range perRouteSecretKeys(id) {
			if _, err := tx.Exec(`DELETE FROM secrets_kv WHERE k = ?`, k); err != nil {
				return 0, fmt.Errorf("delete route secret %q: %w", k, err)
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM routes WHERE publisher_id = ?`, publisherID); err != nil {
		return 0, fmt.Errorf("delete publisher routes: %w", err)
	}
	// trust_audit rows are keyed by publisher_id but carry no FK; drop them
	// so a re-import starts clean.
	if _, err := tx.Exec(`DELETE FROM trust_audit WHERE publisher_id = ?`, publisherID); err != nil {
		return 0, fmt.Errorf("delete trust audit: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM publishers WHERE publisher_id = ?`, publisherID); err != nil {
		return 0, fmt.Errorf("delete publisher: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(routeIDs), nil
}
