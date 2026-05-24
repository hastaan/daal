package proxy

import (
	"errors"
	"strings"
)

// AuthFailedSentinel is the sentinel error type Pipe checks for. The
// upstream dialer returns this (or wraps it) when the remote side
// rejects the credentials. Pipe MUST NOT charge auth-failed bytes to
// the route's budget — a single misconfigured upstream could otherwise
// drain a healthy route's hourly cap with retries.
//
// Phase 2A defines the sentinel here. Future phases that integrate a
// real sing-box outbound wrap the sing-box error class into this
// sentinel at the seam.
type AuthFailedSentinel struct {
	Inner error
}

func (e *AuthFailedSentinel) Error() string {
	if e.Inner != nil {
		return "auth_failed: " + e.Inner.Error()
	}
	return "auth_failed"
}

func (e *AuthFailedSentinel) Unwrap() error { return e.Inner }

// AuthFailed wraps inner as an AuthFailedSentinel. Use this at the
// dialer-to-pipe seam.
func AuthFailed(inner error) error { return &AuthFailedSentinel{Inner: inner} }

// IsAuthFailed reports whether err's chain contains an
// AuthFailedSentinel. It also matches the literal substring
// "auth_failed" in the error string for upstream packages that have
// not yet been refactored to use the sentinel.
func IsAuthFailed(err error) bool {
	if err == nil {
		return false
	}
	var sentinel *AuthFailedSentinel
	if errors.As(err, &sentinel) {
		return true
	}
	return strings.Contains(err.Error(), "auth_failed")
}
