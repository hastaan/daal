package budget

import (
	"strings"
	"time"

	"daal/core/routestore"
)

// RoutestoreStore binds the budget Engine to the on-disk routestore.
// The hour-bucket cursor lives in `secrets_kv` under
// `budget:bucket:<route_id>` (RFC3339 string); the consumed counter
// lives in `routes.bytes_used_this_hour`.
//
// SetRouteScarcity uses the existing UpdateRouteScarcity helper added
// in 2A. SetRouteBytesHour writes the column and the secrets_kv key
// (not in a single SQL transaction today; the budget engine tolerates
// partial writes — a bucket rewind on next read just re-runs the
// truncate path).
type RoutestoreStore struct {
	S *routestore.Store
}

const bucketKeyPrefix = "budget:bucket:"

func bucketKey(routeID string) string { return bucketKeyPrefix + routeID }

// SetRouteScarcity updates the routes.scarcity_class column.
func (r *RoutestoreStore) SetRouteScarcity(routeID, tag string) error {
	return r.S.UpdateRouteScarcity(routeID, tag)
}

// SetRouteBytesHour writes the consumed counter and bucket cursor.
func (r *RoutestoreStore) SetRouteBytesHour(routeID string, consumed uint64, bucket time.Time) error {
	if err := r.S.UpdateRouteBytesHour(routeID, int64(consumed)); err != nil {
		return err
	}
	return r.S.PutSecret(bucketKey(routeID), []byte(bucket.UTC().Format(time.RFC3339)))
}

// GetRouteBudget reads the route's tag, consumed bytes, and bucket.
// Untagged or unknown routes return ("", 0, zero-time, nil).
func (r *RoutestoreStore) GetRouteBudget(routeID string) (string, uint64, time.Time, error) {
	row, err := r.S.GetRoute(routeID)
	if err != nil {
		// Route does not exist; treat as untagged.
		return "", 0, time.Time{}, nil
	}
	consumed := uint64(0)
	if row.BytesUsedThisHour > 0 {
		consumed = uint64(row.BytesUsedThisHour)
	}
	bucket := time.Time{}
	if raw, err := r.S.GetSecret(bucketKey(routeID)); err == nil && len(raw) > 0 {
		if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(raw))); perr == nil {
			bucket = t.UTC()
		}
	}
	return row.ScarcityClass, consumed, bucket, nil
}

// EnumerateBudgets returns one Row per route in the store.
func (r *RoutestoreStore) EnumerateBudgets() ([]Row, error) {
	rows, err := r.S.ListRoutes()
	if err != nil {
		return nil, err
	}
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		bucket := time.Time{}
		if raw, err := r.S.GetSecret(bucketKey(row.RouteID)); err == nil && len(raw) > 0 {
			if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(raw))); perr == nil {
				bucket = t.UTC()
			}
		}
		consumed := uint64(0)
		if row.BytesUsedThisHour > 0 {
			consumed = uint64(row.BytesUsedThisHour)
		}
		out = append(out, Row{
			RouteID:  row.RouteID,
			Tag:      row.ScarcityClass,
			Consumed: consumed,
			Bucket:   bucket,
		})
	}
	return out, nil
}
