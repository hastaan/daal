package refresh

import "time"

// AuditWriter is satisfied by routestore.Store. We declare it as an
// interface to keep this package dependency-free at compile time and to
// let tests inject a fake.
type AuditWriter interface {
	AppendRefreshAudit(kind, refID, outcome string, bytesIn int64, viaTunnel bool, now time.Time) error
}

// recordAudit writes a refresh attempt to the audit log. Failures here
// are non-fatal: an audit write that fails must never abort the refresh.
func recordAudit(w AuditWriter, kind, refID, outcome string, bytes int64, viaTunnel bool, now time.Time) {
	if w == nil {
		return
	}
	_ = w.AppendRefreshAudit(kind, refID, outcome, bytes, viaTunnel, now)
}
