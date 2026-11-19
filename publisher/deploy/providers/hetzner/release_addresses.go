package hetzner

import (
	"context"
	"errors"
	"fmt"

	"daal/publisher/deploy/provider"
)

var _ provider.AddressReleaser = (*Provider)(nil)

// ReleaseRelayAddresses gives back every floating IP Daal reserved for
// rec's relay once its server is gone (decommission --release-addresses).
//
// Which addresses: rec.FloatingIPID when it carries both ownership
// labels for this relay, plus every floating IP on the account carrying
// both labels for this relay. An address without them is the person's
// own and is kept (not_daal). One attached to a server OTHER than the
// one just deleted is kept (still_attached). Unbinding on the relay is
// skipped: the relay is gone. A failed list or delete is release_failed,
// so the caller knows something may still be billing and can retry.
func (p *Provider) ReleaseRelayAddresses(ctx context.Context, rec *provider.OperatorRecord, deletedServerID string) []provider.AddressOutcome {
	out := []provider.AddressOutcome{}
	if rec == nil || len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		return out
	}
	relay := derivedServerName(rec.PublisherPubKey, rec.Region)
	seen := map[string]bool{}
	release := func(f *FloatingIPInfo) {
		seen[f.ID] = true
		o := provider.AddressOutcome{ID: f.ID, IP: ipv4String(f.IP)}
		switch {
		case !ownsFloatingIP(f, rec):
			o.Code = provider.AddrNotDaal
		case f.ServerID != "" && f.ServerID != deletedServerID:
			o.Code = provider.AddrStillAttached
			o.Error = "attached to server " + f.ServerID
		default:
			if err := p.c.FloatingIPDelete(ctx, f.ID); err != nil {
				o.Code, o.Error = provider.AddrReleaseFailed, err.Error()
			} else {
				o.Code, o.Released = provider.AddrReleased, true
			}
		}
		out = append(out, o)
	}
	if rec.FloatingIPID != "" {
		f, err := p.c.FloatingIPByID(ctx, rec.FloatingIPID)
		switch {
		case errors.Is(err, errFloatingIPNotFound):
			seen[rec.FloatingIPID] = true
			out = append(out, provider.AddressOutcome{ID: rec.FloatingIPID, Released: true, Code: provider.AddrReleased})
		case err != nil:
			seen[rec.FloatingIPID] = true
			out = append(out, provider.AddressOutcome{ID: rec.FloatingIPID, Code: provider.AddrReleaseFailed,
				Error: fmt.Sprintf("could not read it: %v", err)})
		default:
			release(f)
		}
	}
	fips, err := p.c.FloatingIPList(ctx)
	if err != nil {
		out = append(out, provider.AddressOutcome{Code: provider.AddrReleaseFailed,
			Error: fmt.Sprintf("could not list the account's floating IPs, so an address reserved for this relay may still be billing: %v", err)})
		return out
	}
	for _, f := range fips {
		if f == nil || seen[f.ID] {
			continue
		}
		if r, ok := markedRelay(f.Labels); !ok || r != relay {
			continue
		}
		release(f)
	}
	return out
}

var _ provider.ServerStater = (*Provider)(nil)

// ServerState reports whether the record's server exists and runs
// (relay-health). Read-only. A record without a server id is looked up
// by the derived name, which is proof of ownership (see resolveServerID).
func (p *Provider) ServerState(ctx context.Context, rec *provider.OperatorRecord) (string, error) {
	if rec == nil {
		return "", errors.New("hetzner: nil record")
	}
	var (
		srv *ServerInfo
		err error
	)
	switch {
	case rec.ServerID != "":
		srv, err = p.c.ServerByID(ctx, rec.ServerID)
	case len(rec.PublisherPubKey) > 0 && rec.Region != "":
		srv, err = p.c.ServerByName(ctx, derivedServerName(rec.PublisherPubKey, rec.Region))
	default:
		return "", errors.New("hetzner: record names no server and no relay")
	}
	if errors.Is(err, errServerNotFound) {
		return provider.ServerMissing, nil
	}
	if err != nil {
		return "", fmt.Errorf("hetzner: read server: %w", err)
	}
	return hetznerServerState(srv.Status), nil
}

// hetznerServerState maps Hetzner's server status vocabulary onto the
// four states the app words. Unknown values read as "starting": the
// server exists, and saying "switched off" about it would be a guess.
func hetznerServerState(status string) string {
	switch status {
	case "running":
		return provider.ServerRunning
	case "off", "stopping":
		return provider.ServerStopped
	case "deleting":
		return provider.ServerMissing
	}
	return provider.ServerStarting
}
