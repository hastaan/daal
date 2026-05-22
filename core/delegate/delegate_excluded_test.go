//go:build no_delegate_share

package delegate

import (
	"errors"
	"testing"
	"time"
)

// TestExcluded_CompiledFlag locks the build-tag wiring.
func TestExcluded_CompiledFlag(t *testing.T) {
	if Compiled {
		t.Error("Compiled: expected false under -tags no_delegate_share")
	}
}

// TestExcluded_OutcomeIdentityUnavailable — every entrypoint
// MUST surface OutcomeIdentityUnavailable / ErrIdentityUnavailable
// under the excluder.
func TestExcluded_OutcomeIdentityUnavailable(t *testing.T) {
	if got := EnforcePolicy(PolicyDelegatedN, 10, 0); got != OutcomeIdentityUnavailable {
		t.Errorf("EnforcePolicy: %q", got)
	}
	if got := EnforceChainDepth(0); got != OutcomeIdentityUnavailable {
		t.Errorf("EnforceChainDepth: %q", got)
	}
	if _, err := AppendHop(nil, nil, "", nil, time.Time{}); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("AppendHop: %v", err)
	}
	if _, err := VerifyChain(nil, nil, ""); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("VerifyChain: %v", err)
	}
	if err := EnforceCap(nil); !errors.Is(err, ErrIdentityUnavailable) {
		t.Errorf("EnforceCap: %v", err)
	}
}
