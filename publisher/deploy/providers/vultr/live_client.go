package vultr

import (
	"context"
	"net"
	"time"
)

// liveClient implements vultrClient against the real
// vultr/govultr/v3 SDK. The body is intentionally a stub at
// FRP-10 engineering ship; every method returns
// ErrLiveNotImplemented. govultr/v3 SDK wiring is a documented
// FRP-10 carry-over (mirrors FRP-8's cf_client_live ship pattern
// where live wiring lands as a follow-up).
//
// The unit-test surface is covered by the in-memory fake at
// provider_test.go.
type liveClient struct {
	token string
}

// NewLiveClient returns a vultrClient bound to a live Vultr
// account. The token must be a Vultr API personal access token.
// The token is supplied by the wizard's keystore; FRP-10 does not
// store it.
func NewLiveClient(token string) vultrClient {
	return &liveClient{token: token}
}

func (l *liveClient) InstanceCreate(_ context.Context, _ InstanceCreateOpts) (*InstanceInfo, error) {
	return nil, ErrLiveNotImplemented
}
func (l *liveClient) InstanceByID(_ context.Context, _ string) (*InstanceInfo, error) {
	return nil, ErrLiveNotImplemented
}
func (l *liveClient) InstanceByLabel(_ context.Context, _ string) (*InstanceInfo, error) {
	return nil, ErrLiveNotImplemented
}
func (l *liveClient) InstanceDelete(_ context.Context, _ string) error {
	return ErrLiveNotImplemented
}
func (l *liveClient) PlanPrice(_ context.Context, _, _ string) (float64, float64, error) {
	return 0, 0, ErrLiveNotImplemented
}
func (l *liveClient) SSHKeyCreate(_ context.Context, _ string, _ []byte) (string, error) {
	return "", ErrLiveNotImplemented
}
func (l *liveClient) SSHKeyDelete(_ context.Context, _ string) error {
	return ErrLiveNotImplemented
}
func (l *liveClient) ReservedIPAttach(_ context.Context, _, _ string) error {
	return ErrLiveNotImplemented
}
func (l *liveClient) ReservedIPDetach(_ context.Context, _ string) error {
	return ErrLiveNotImplemented
}
func (l *liveClient) FirewallAddEphemeralRule(_ context.Context, _, _ string, _ int, _ time.Time) (string, error) {
	return "", ErrLiveNotImplemented
}
func (l *liveClient) FirewallRemoveEphemeralRule(_ context.Context, _ string) error {
	return ErrLiveNotImplemented
}

// suppress unused-import warning.
var _ = net.IP(nil)
