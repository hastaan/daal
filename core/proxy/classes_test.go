package proxy

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsAuthFailedSentinel(t *testing.T) {
	inner := errors.New("upstream rejected credentials")
	wrapped := AuthFailed(inner)
	if !IsAuthFailed(wrapped) {
		t.Fatalf("AuthFailed(...) should be IsAuthFailed: %v", wrapped)
	}
	// Wrapping in fmt.Errorf with %w must still match.
	deep := fmt.Errorf("dial: %w", wrapped)
	if !IsAuthFailed(deep) {
		t.Fatalf("wrapped sentinel should match: %v", deep)
	}
}

func TestIsAuthFailedSubstringFallback(t *testing.T) {
	// Pre-sentinel-refactor packages might still produce literal strings.
	literal := errors.New("dial vless-reality: auth_failed at remote 1.2.3.4")
	if !IsAuthFailed(literal) {
		t.Fatalf("literal substring should match: %v", literal)
	}
}

func TestIsAuthFailedNil(t *testing.T) {
	if IsAuthFailed(nil) {
		t.Fatalf("IsAuthFailed(nil) should be false")
	}
}

func TestIsAuthFailedNonMatching(t *testing.T) {
	if IsAuthFailed(errors.New("dial timeout")) {
		t.Fatalf("dial timeout must not match auth_failed")
	}
}
