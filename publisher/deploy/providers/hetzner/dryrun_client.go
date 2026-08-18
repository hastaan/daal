package hetzner

import (
	"context"
	"daal/publisher/deploy/relayports"
	"errors"
	"net"
	"time"
)

// dryRunClient is an hcloudClient implementation that errors on
// every live call. It is used by Provider.Provision when DryRun is
// true and no API token is available; Provision's DryRun branch
// short-circuits before reaching any of these methods, so a panic
// from one of them indicates a routing bug.
type dryRunClient struct{}

// NewDryRunClient returns an hcloudClient that errors on every
// method. Used by the CLI's --dry-run path when no token is set.
func NewDryRunClient() hcloudClient { return dryRunClient{} }

func (dryRunClient) ServerCreate(ctx context.Context, opts ServerCreateOpts) (*ServerInfo, error) {
	return nil, errors.New("hetzner: dry-run client cannot ServerCreate")
}

func (dryRunClient) ServerByID(ctx context.Context, id string) (*ServerInfo, error) {
	return nil, errServerNotFound
}

func (dryRunClient) ServerByName(ctx context.Context, name string) (*ServerInfo, error) {
	return nil, errServerNotFound
}

func (dryRunClient) ServerRebuild(ctx context.Context, id string, image string, userData string) (*ServerInfo, error) {
	return nil, errors.New("hetzner: dry-run client cannot ServerRebuild")
}

func (dryRunClient) ServerList(ctx context.Context) ([]*ServerInfo, error) {
	return nil, nil
}

func (dryRunClient) ServerDelete(ctx context.Context, id string) error {
	return errors.New("hetzner: dry-run client cannot ServerDelete")
}

func (dryRunClient) ServerTypePrice(ctx context.Context, region, serverType string) (float64, float64, error) {
	return 0, 0, errors.New("hetzner: dry-run client cannot ServerTypePrice")
}

func (dryRunClient) SSHKeyCreate(ctx context.Context, name string, publicKey []byte, labels map[string]string) (string, error) {
	return "", errors.New("hetzner: dry-run client cannot SSHKeyCreate")
}

func (dryRunClient) SSHKeyDelete(ctx context.Context, id string) error {
	return errors.New("hetzner: dry-run client cannot SSHKeyDelete")
}

func (dryRunClient) SSHKeyList(_ context.Context) ([]SSHKeyInfo, error) {
	return nil, errors.New("hetzner: dry-run client cannot SSHKeyList")
}

func (dryRunClient) FloatingIPCreate(_ context.Context, _ FloatingIPCreateOpts) (*FloatingIPInfo, error) {
	return nil, errors.New("hetzner: dry-run client cannot FloatingIPCreate")
}

func (dryRunClient) FloatingIPDelete(_ context.Context, _ string) error {
	return errors.New("hetzner: dry-run client cannot FloatingIPDelete")
}

func (dryRunClient) FloatingIPByID(_ context.Context, _ string) (*FloatingIPInfo, error) {
	return nil, errors.New("hetzner: dry-run client cannot FloatingIPByID")
}

func (dryRunClient) FloatingIPAssign(ctx context.Context, fipID, serverID string) error {
	return errors.New("hetzner: dry-run client cannot FloatingIPAssign")
}

func (dryRunClient) FloatingIPUnassign(ctx context.Context, fipID string) error {
	return errors.New("hetzner: dry-run client cannot FloatingIPUnassign")
}

func (dryRunClient) FirewallApplyCloudflareRule(_ context.Context, _ string, _, _ []string) (string, error) {
	return "", errors.New("hetzner: dry-run client cannot FirewallApplyCloudflareRule")
}

func (dryRunClient) FirewallAddEphemeralRule(_ context.Context, _, _ string, _ int, _ time.Time) (string, error) {
	return "", errors.New("hetzner: dry-run client cannot FirewallAddEphemeralRule")
}

func (dryRunClient) FirewallRemoveEphemeralRule(_ context.Context, _ string) error {
	return errors.New("hetzner: dry-run client cannot FirewallRemoveEphemeralRule")
}

func (dryRunClient) FirewallEnsureForServer(_ context.Context, _ string, _ []relayports.Endpoint) (string, error) {
	return "", errors.New("hetzner: dry-run client cannot FirewallEnsureForServer")
}

func (dryRunClient) FirewallDeleteForServer(_ context.Context, _ string) (FirewallTeardownResult, error) {
	return FirewallTeardownResult{}, errors.New("hetzner: dry-run client cannot FirewallDeleteForServer")
}

// suppress unused-import warning; net is referenced by other files
// in the package and Go vets each file independently.
var _ = net.IP(nil)
