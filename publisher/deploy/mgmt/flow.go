package mgmt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"daal/publisher/deploy/provider"
)

// EphemeralWindow is the default window the Helper opens on the
// cloud-provider firewall before each L1/L2 mgmt call. 5 minutes
// matches supplement §9.5.2.
const EphemeralWindowSeconds = 300

// RotateCredentialsWithFW orchestrates the V2 fast path for L1:
//
//  1. SetEphemeralFirewallRule(callerIP, port, 300s) on the
//     cloud-provider firewall.
//  2. RotateCredentials() against the box's mgmt-plane (TLS-pinned).
//  3. RemoveEphemeralFirewallRule() (defer; runs even on step 2
//     error).
//
// Returns the new credentials on success. Cleanup is best-effort —
// the cloud provider auto-expires the rule at 300s; the explicit
// removal is defense in depth.
func RotateCredentialsWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string) (*Credentials, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	if err := provider.ValidateMgmtPort(rec.MgmtPort); err != nil {
		return nil, fmt.Errorf("mgmt: OperatorRecord.MgmtPort invalid (V2 fast path not available; redeploy required): %w", err)
	}
	rule, err := prov.SetEphemeralFirewallRule(ctx, rec.ServerID, callerIP, rec.MgmtPort, EphemeralWindowSeconds)
	if err != nil {
		return nil, fmt.Errorf("mgmt: open ephemeral fw: %w", err)
	}
	defer func() {
		// Best-effort cleanup; ignore error (provider auto-expires
		// at EphemeralWindowSeconds anyway).
		_ = prov.RemoveEphemeralFirewallRule(ctx, rule)
	}()

	cli, err := NewClient(rec)
	if err != nil {
		return nil, err
	}
	return cli.RotateCredentials(ctx, rec, privKey)
}

// ProvisionUserWithFW orchestrates a /users/provision call,
// wrapped with the ephemeral firewall window. Returns the freshly
// minted per-recipient credentials.
func ProvisionUserWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP, name string) (*UserCreds, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	if err := provider.ValidateMgmtPort(rec.MgmtPort); err != nil {
		return nil, fmt.Errorf("mgmt: OperatorRecord.MgmtPort invalid: %w", err)
	}
	rule, err := prov.SetEphemeralFirewallRule(ctx, rec.ServerID, callerIP, rec.MgmtPort, EphemeralWindowSeconds)
	if err != nil {
		return nil, fmt.Errorf("mgmt: open ephemeral fw: %w", err)
	}
	defer func() { _ = prov.RemoveEphemeralFirewallRule(ctx, rule) }()
	cli, err := NewClient(rec)
	if err != nil {
		return nil, err
	}
	return cli.ProvisionUser(ctx, rec, privKey, name)
}

// RevokeUserWithFW is the /users/revoke equivalent. The on-box
// service runs the SIGUSR2 kick wrapper before responding.
func RevokeUserWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP, name string) (*RevokeResp, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	if err := provider.ValidateMgmtPort(rec.MgmtPort); err != nil {
		return nil, fmt.Errorf("mgmt: OperatorRecord.MgmtPort invalid: %w", err)
	}
	rule, err := prov.SetEphemeralFirewallRule(ctx, rec.ServerID, callerIP, rec.MgmtPort, EphemeralWindowSeconds)
	if err != nil {
		return nil, fmt.Errorf("mgmt: open ephemeral fw: %w", err)
	}
	defer func() { _ = prov.RemoveEphemeralFirewallRule(ctx, rule) }()
	cli, err := NewClient(rec)
	if err != nil {
		return nil, err
	}
	return cli.RevokeUser(ctx, rec, privKey, name)
}

// ListUsersWithFW lists the current recipient roster on the box.
func ListUsersWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string) ([]UserMeta, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	if err := provider.ValidateMgmtPort(rec.MgmtPort); err != nil {
		return nil, fmt.Errorf("mgmt: OperatorRecord.MgmtPort invalid: %w", err)
	}
	rule, err := prov.SetEphemeralFirewallRule(ctx, rec.ServerID, callerIP, rec.MgmtPort, EphemeralWindowSeconds)
	if err != nil {
		return nil, fmt.Errorf("mgmt: open ephemeral fw: %w", err)
	}
	defer func() { _ = prov.RemoveEphemeralFirewallRule(ctx, rule) }()
	cli, err := NewClient(rec)
	if err != nil {
		return nil, err
	}
	return cli.ListUsers(ctx, rec, privKey)
}
