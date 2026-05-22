//go:build no_delegate_share

// Phase 3F. Build-tag excluder for the delegate-share surface.
// Distributors who must strip the re-share/chain-walk code can
// pass `-tags no_delegate_share`; the diagnostics flag
// `delegate_share_compiled_in` flips to false; the engine refuses
// re-shares with `OutcomeIdentityUnavailable`.
//
// The release-surface symbol `engine_redistribute_route` is still
// present (append-only invariant) — under this tag it returns the
// JSON error envelope `{"error":"identity_unavailable",...}`.
//
// This file replaces the package's exported surface with stubs.
// The non-excluded twin lives in delegate.go.

package delegate

import (
	"crypto/ed25519"
	"errors"
	"time"
)

const Compiled = false

type Policy string

const (
	PolicyNone       Policy = "none"
	PolicyDelegatedN Policy = "delegated_n"
	PolicyTransitive Policy = "transitive"
	MaxChainDepth           = 5
)

func IsValidPolicy(p Policy) bool { return false }

type ChainHop struct {
	DelegateFPHex  string
	DelegatePub    string
	SignedAt       string
	RecipientFPHex string
	SignatureB64   string
}

type CapEntry struct {
	RouteID                   string
	SharedWithCountAtSignTime uint8
	CapAtSignTime             uint8
}

type Outcome string

const (
	OutcomeOK                  Outcome = "ok"
	OutcomePolicyRefuses       Outcome = "policy_refuses"
	OutcomeCapExhausted        Outcome = "cap_exhausted"
	OutcomeChainDepthExceeded  Outcome = "chain_depth_exceeded"
	OutcomeRouteUnknown        Outcome = "route_unknown"
	OutcomeIdentityUnavailable Outcome = "identity_unavailable"
)

var (
	ErrChainBroken         = errors.New("delegate: compiled out (-tags no_delegate_share)")
	ErrChainTooDeep        = ErrChainBroken
	ErrChainOrphan         = ErrChainBroken
	ErrCapExceeded         = ErrChainBroken
	ErrPolicyForbids       = ErrChainBroken
	ErrIdentityUnavailable = ErrChainBroken
	ErrRouteUnknown        = ErrChainBroken
	ErrPolicyMalformed     = ErrChainBroken
	ErrCapMalformed        = ErrChainBroken
)

func EnforcePolicy(_ Policy, _ uint8, _ uint8) Outcome { return OutcomeIdentityUnavailable }
func EnforceChainDepth(_ int) Outcome                  { return OutcomeIdentityUnavailable }

func AppendHop(_ []ChainHop, _ []byte, _ string, _ ed25519.PrivateKey, _ time.Time) ([]ChainHop, error) {
	return nil, ErrIdentityUnavailable
}

func VerifyChain(_ []ChainHop, _ []byte, _ string) (int, error) {
	return 0, ErrIdentityUnavailable
}

func EnforceCap(_ []CapEntry) error { return ErrIdentityUnavailable }

func OutcomeJSON(o Outcome, detail string) string {
	return `{"error":"` + string(o) + `","detail":"` + detail + `"}`
}

func ParseUint8Cap(_ string) (uint8, error) { return 0, ErrCapMalformed }
