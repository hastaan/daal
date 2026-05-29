package rendezvous

import (
	"context"
	"errors"
)

// Solicitor is the per-channel function the engine layer wires
// to upstream code (Snowflake's domain-fronted broker call,
// AWS SQS SDK, AMP-cache fronting, FCM/APNS verifier, the
// offline-hint store). The rendezvous package itself stays free
// of those heavy dependencies; tests pass stubs.
type Solicitor func(ctx context.Context, req Request) (Hint, error)

// solicitorChannel is the canonical Channel impl. Each v1
// channel ID has a constructor returning one of these.
type solicitorChannel struct {
	id        string
	solicit   Solicitor
	enabledFn func() bool // nil → always enabled
}

func (c *solicitorChannel) ID() string { return c.id }

func (c *solicitorChannel) Solicit(ctx context.Context, req Request) (Hint, error) {
	if c.enabledFn != nil && !c.enabledFn() {
		return Hint{}, ErrChannelDisabled
	}
	if c.solicit == nil {
		return Hint{}, errors.New("rendezvous: no solicitor configured")
	}
	return c.solicit(ctx, req)
}

// NewDomainFrontedBroker constructs the
// `domain_fronted_broker` channel. The Solicitor is wired to
// the upstream Snowflake `snowflake/client` broker call by the
// engine layer.
func NewDomainFrontedBroker(s Solicitor) Channel {
	return &solicitorChannel{id: ChannelDomainFrontedBroker, solicit: s}
}

// NewSQS constructs the `sqs` channel.
func NewSQS(s Solicitor) Channel {
	return &solicitorChannel{id: ChannelSQS, solicit: s}
}

// NewAMPCache constructs the `amp_cache` channel.
func NewAMPCache(s Solicitor) Channel {
	return &solicitorChannel{id: ChannelAMPCache, solicit: s}
}

// NewPush constructs the `push` channel. The supplied
// `enabledFn` returns the engine-side opt-in flag (default
// false). When the flag is false, Solicit returns
// ErrChannelDisabled and the Selector skips the channel
// silently — it does NOT count as an all-fail contributor.
func NewPush(s Solicitor, enabledFn func() bool) Channel {
	return &solicitorChannel{id: ChannelPush, solicit: s, enabledFn: enabledFn}
}

// NewOfflineHint constructs the `offline_hint` channel. The
// Solicitor consults the active bundle's signed pre-bundled
// hints.
func NewOfflineHint(s Solicitor) Channel {
	return &solicitorChannel{id: ChannelOfflineHint, solicit: s}
}
