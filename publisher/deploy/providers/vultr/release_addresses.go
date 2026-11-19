package vultr

import (
	"context"
	"errors"
	"fmt"

	"daal/publisher/deploy/provider"
)

var _ provider.AddressReleaser = (*Provider)(nil)

// ReleaseRelayAddresses: see the Hetzner adapter; same rules, with
// Vultr's ownership mark in the reserved IP's label. Decommission
// already releases rec.FloatingIPID when it is Daal's, so finding it
// gone here is reported as released.
func (p *Provider) ReleaseRelayAddresses(ctx context.Context, rec *provider.OperatorRecord, deletedServerID string) []provider.AddressOutcome {
	out := []provider.AddressOutcome{}
	if rec == nil || len(rec.PublisherPubKey) == 0 || rec.Region == "" {
		return out
	}
	relay := derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
	seen := map[string]bool{}
	release := func(r *ReservedIPInfo) {
		seen[r.ID] = true
		o := provider.AddressOutcome{ID: r.ID, IP: ipv4String(r.IP)}
		switch {
		case !ownsReservedIP(r, rec):
			o.Code = provider.AddrNotDaal
		case r.InstanceID != "" && r.InstanceID != deletedServerID:
			o.Code = provider.AddrStillAttached
			o.Error = "attached to instance " + r.InstanceID
		default:
			if err := p.c.ReservedIPDelete(ctx, r.ID); err != nil {
				o.Code, o.Error = provider.AddrReleaseFailed, err.Error()
			} else {
				o.Code, o.Released = provider.AddrReleased, true
			}
		}
		out = append(out, o)
	}
	if rec.FloatingIPID != "" {
		r, err := p.c.ReservedIPByID(ctx, rec.FloatingIPID)
		switch {
		case errors.Is(err, errReservedIPNotFound):
			seen[rec.FloatingIPID] = true
			out = append(out, provider.AddressOutcome{ID: rec.FloatingIPID, Released: true, Code: provider.AddrReleased})
		case err != nil:
			seen[rec.FloatingIPID] = true
			out = append(out, provider.AddressOutcome{ID: rec.FloatingIPID, Code: provider.AddrReleaseFailed,
				Error: fmt.Sprintf("could not read it: %v", err)})
		default:
			release(r)
		}
	}
	rips, err := p.c.ReservedIPList(ctx)
	if err != nil {
		out = append(out, provider.AddressOutcome{Code: provider.AddrReleaseFailed,
			Error: fmt.Sprintf("could not list the account's reserved IPs, so an address reserved for this relay may still be billing: %v", err)})
		return out
	}
	for _, r := range rips {
		if r == nil || seen[r.ID] {
			continue
		}
		if rl, ok := relayFromMark(r.Label); !ok || rl != relay {
			continue
		}
		release(r)
	}
	return out
}

var _ provider.ServerStater = (*Provider)(nil)

// ServerState reports whether the record's instance exists and runs
// (relay-health). Read-only. A record without an id is looked up by the
// derived label, and an instance there without this relay's tags is
// reported as missing: it is not this relay's server.
func (p *Provider) ServerState(ctx context.Context, rec *provider.OperatorRecord) (string, error) {
	if rec == nil {
		return "", errors.New("vultr: nil record")
	}
	var (
		inst *InstanceInfo
		err  error
	)
	switch {
	case rec.ServerID != "":
		inst, err = p.c.InstanceByID(ctx, rec.ServerID)
	case len(rec.PublisherPubKey) > 0 && rec.Region != "":
		label := derivedInstanceLabel(rec.PublisherPubKey, rec.Region)
		inst, err = p.c.InstanceByLabel(ctx, label)
		if err == nil && inst != nil && !ownsInstance(inst, label) {
			return provider.ServerMissing, nil
		}
	default:
		return "", errors.New("vultr: record names no instance and no relay")
	}
	if errors.Is(err, errInstanceNotFound) || (err == nil && inst == nil) {
		return provider.ServerMissing, nil
	}
	if err != nil {
		return "", fmt.Errorf("vultr: read instance: %w", err)
	}
	return vultrServerState(inst), nil
}

// vultrServerState folds Vultr's three status fields into the four
// states the app words: status (pending|active|suspended|resizing),
// power_status (running|stopped) and server_status (none|locked|
// installingbooting|ok).
func vultrServerState(inst *InstanceInfo) string {
	switch {
	case inst.Status == "suspended", inst.PowerStatus == "stopped":
		return provider.ServerStopped
	case inst.Status == "active" && inst.ServerStatus == "ok" && (inst.PowerStatus == "" || inst.PowerStatus == "running"):
		return provider.ServerRunning
	}
	return provider.ServerStarting
}
