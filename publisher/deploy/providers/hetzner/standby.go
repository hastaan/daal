package hetzner

// standby.go — the provider half of the standby-address add-on
// (docs/optional-addons-plan.md §1, item S3; specs/optional-addons-v1.md
// §3).
//
// A standby is one more Hetzner Floating IPv4, homed in the relay's own
// location and assigned to its server from the day it is rented, but
// NOT adopted: rec.PublicIP and the candidates' public_ip:* tags keep
// naming the address recipients dial today. The record carries it in
// rec.Standby instead, and the binder signs only a commitment to it
// (sealed) or the address itself (open) into each route.
//
// Three operations, and the money rule that shapes all of them: Hetzner
// bills a Floating IP per hour, assigned or not, until it is DELETED.
//
//   - EnsureStandby rents (or finds) and assigns. It is safe to call
//     again after a run that was killed half way: a standby that run
//     rented carries this relay's labels plus daal-role=standby, so the
//     retry adopts it instead of renting a second one. It never deletes:
//     whatever it returns, the caller's rollback releases (after telling
//     the box to drop it, if the box was told to bind it).
//   - PromoteStandby moves it into PublicIP / FloatingIPID ("switch to
//     standby"). Record only: the address is already routed and bound.
//   - RemoveStandby releases one. The caller has already signed and
//     published a pack without it and told the box to drop it.
//
// Relay delete needs nothing from here: ReleaseRelayAddresses releases
// every Floating IP carrying this relay's labels once the server is
// gone, and the standby carries them.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"daal/publisher/deploy/provider"
)

// labelRole marks what a Floating IP is for. Only the standby sets it:
// it is what lets a retry tell "the standby a killed run rented" from an
// address an L3 swap reserved for the same relay.
const (
	labelRole        = "daal-role"
	labelRoleStandby = "standby"
)

// ErrStandbyLimit is Hetzner refusing another Floating IP on this
// account (resource_limit_exceeded). GATE S-1: the limit on new
// accounts is undocumented.
var ErrStandbyLimit = errors.New("hetzner: the account is not allowed another floating IP (resource_limit_exceeded)")

// StandbyResult is what EnsureStandby found or made.
type StandbyResult struct {
	// Standby is the address, assigned to the relay's server. Its Salt
	// is the record's own when the record already named this Floating
	// IP, and empty otherwise (the caller draws one).
	Standby provider.StandbyAddress
	// Created: rented by this call. Adopted: a standby an earlier run
	// rented for this relay, found by its labels.
	Created bool
	Adopted bool
	// Strays are further standbys an earlier run left for this relay
	// (labelled, not the one returned). They are billing; the caller
	// releases them through the same unbind-then-release path.
	Strays []provider.StandbyAddress
}

func isStandby(f *FloatingIPInfo) bool {
	return f != nil && f.Labels[labelRole] == labelRoleStandby
}

func standbyOf(f *FloatingIPInfo) provider.StandbyAddress {
	return provider.StandbyAddress{FloatingIPID: f.ID, IP: f.IP.To4()}
}

func requireStandbyRecord(rec *provider.OperatorRecord) error {
	switch {
	case rec == nil:
		return errors.New("hetzner: nil OperatorRecord")
	case rec.ServerID == "":
		return errors.New("hetzner: standby: the record names no server")
	case rec.Region == "":
		return errors.New("hetzner: standby: the record names no location")
	case len(rec.PublisherPubKey) == 0:
		return errors.New("hetzner: standby: the record has no publisher key, so ownership labels cannot be derived")
	}
	return nil
}

func isLimitErr(err error) bool {
	if err == nil {
		return false
	}
	return hcloud.IsError(err, hcloud.ErrorCodeResourceLimitExceeded) ||
		strings.Contains(err.Error(), string(hcloud.ErrorCodeResourceLimitExceeded))
}

// StandbyStrays lists every standby Daal rented for rec's relay that the
// record does not name: not rec.FloatingIPID (the advertised address,
// which may be a promoted standby), not rec.Standby. Attached to another
// server is never a stray of ours.
func (p *Provider) StandbyStrays(ctx context.Context, rec *provider.OperatorRecord) ([]provider.StandbyAddress, error) {
	if err := requireStandbyRecord(rec); err != nil {
		return nil, err
	}
	fips, err := p.c.FloatingIPList(ctx)
	if err != nil {
		return nil, fmt.Errorf("hetzner: list floating ips: %w", err)
	}
	keep := map[string]bool{rec.FloatingIPID: true}
	if rec.Standby != nil {
		keep[rec.Standby.FloatingIPID] = true
	}
	var out []provider.StandbyAddress
	for _, f := range fips {
		if f == nil || keep[f.ID] || !isStandby(f) || !ownsFloatingIP(f, rec) {
			continue
		}
		if f.ServerID != "" && f.ServerID != rec.ServerID {
			continue
		}
		out = append(out, standbyOf(f))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FloatingIPID < out[j].FloatingIPID })
	return out, nil
}

// EnsureStandby makes sure rec's relay has exactly one standby assigned
// to its server, and returns it. rec is not changed.
//
// In order: the standby the record names; else one an earlier run
// rented for this relay (adopted); else a new one. It is then assigned
// and read back, the same rule AssignFloatingIP keeps: the cloud's
// "accepted" is not "routed".
//
// On error the result is still returned whenever a Floating IP is in
// play, so the caller can release it — this function deletes nothing.
func (p *Provider) EnsureStandby(ctx context.Context, rec *provider.OperatorRecord) (*StandbyResult, error) {
	if err := requireStandbyRecord(rec); err != nil {
		return nil, err
	}
	res := &StandbyResult{}
	var cand *FloatingIPInfo

	if rec.Standby != nil && rec.Standby.FloatingIPID != "" {
		f, err := p.c.FloatingIPByID(ctx, rec.Standby.FloatingIPID)
		switch {
		case errors.Is(err, errFloatingIPNotFound):
			// The record names one that is gone; fall through and find
			// or rent another.
		case err != nil:
			return nil, fmt.Errorf("hetzner: read standby %s: %w", rec.Standby.FloatingIPID, err)
		case !ownsFloatingIP(f, rec):
			return nil, fmt.Errorf("hetzner: the record's standby %s does not carry this relay's labels; refusing to use it", f.ID)
		default:
			cand = f
			res.Standby.Salt = rec.Standby.Salt
		}
	}

	strays, err := p.StandbyStrays(ctx, rec)
	if err != nil {
		return nil, err
	}
	if cand == nil && len(strays) > 0 {
		f, err := p.c.FloatingIPByID(ctx, strays[0].FloatingIPID)
		if err != nil {
			return nil, fmt.Errorf("hetzner: read standby %s: %w", strays[0].FloatingIPID, err)
		}
		cand = f
		res.Adopted = true
		strays = strays[1:]
	}
	res.Strays = strays

	if cand == nil {
		relay := derivedServerName(rec.PublisherPubKey, rec.Region)
		var suffix [4]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, fmt.Errorf("hetzner: name standby: %w", err)
		}
		f, err := p.c.FloatingIPCreate(ctx, FloatingIPCreateOpts{
			Name:         fmt.Sprintf("%s-standby-%x", relay, suffix),
			HomeLocation: rec.Region,
			Description:  "daal relay standby address",
			Labels: map[string]string{
				labelManagedBy: labelManagedByValue,
				labelRelay:     relay,
				labelRole:      labelRoleStandby,
			},
		})
		if err != nil {
			if isLimitErr(err) {
				return nil, fmt.Errorf("%w: %v", ErrStandbyLimit, err)
			}
			return nil, fmt.Errorf("hetzner: create standby: %w", err)
		}
		if f == nil || f.IP.To4() == nil {
			// Something may have been created; without an id there is
			// nothing to name. Say so rather than guess.
			return nil, errors.New("hetzner: create standby returned no IPv4 address")
		}
		cand = f
		res.Created = true
	}
	res.Standby.FloatingIPID = cand.ID
	res.Standby.IP = cand.IP.To4()

	if res.Standby.IP == nil {
		return res, fmt.Errorf("hetzner: standby %s is not an IPv4 address", cand.ID)
	}
	if res.Standby.IP.Equal(rec.PublicIP) || cand.ID == rec.FloatingIPID {
		return res, fmt.Errorf("hetzner: standby %s is the address recipients already dial", cand.ID)
	}
	if cand.ServerID != "" && cand.ServerID != rec.ServerID {
		return res, fmt.Errorf("hetzner: standby %s is attached to server %s, not %s", cand.ID, cand.ServerID, rec.ServerID)
	}
	if err := coverSNIPlausibleForAddress(rec, cand); err != nil {
		return res, err
	}
	if cand.ServerID != rec.ServerID {
		if err := p.c.FloatingIPAssign(ctx, cand.ID, rec.ServerID); err != nil {
			return res, fmt.Errorf("hetzner: assign standby %s: %w", cand.ID, err)
		}
		after, err := p.c.FloatingIPByID(ctx, cand.ID)
		if err != nil {
			return res, fmt.Errorf("hetzner: confirm standby %s after assign: %w", cand.ID, err)
		}
		if after == nil || after.ServerID != rec.ServerID {
			return res, fmt.Errorf("hetzner: standby %s did not attach to server %s", cand.ID, rec.ServerID)
		}
		if !after.IP.Equal(cand.IP) {
			return res, fmt.Errorf("hetzner: standby %s changed address under us (%v → %v)", cand.ID, cand.IP, after.IP)
		}
	}
	return res, nil
}

// PromoteStandby makes the standby the relay's advertised address: it
// moves into rec.FloatingIPID and rec.PublicIP (and every public_ip:*
// tag), and rec.Standby is cleared. Nothing in the cloud changes — the
// address has been routed and bound since it was rented — but the
// assignment is read back first, so a pack is never re-signed onto an
// address that is not routed here.
//
// The previous address is returned. When it was a Floating IP it stays
// attached and billing: packs already out still name it, and releasing
// it is the publisher's call.
func (p *Provider) PromoteStandby(ctx context.Context, rec *provider.OperatorRecord) (priorFIPID string, priorIP net.IP, err error) {
	if err := requireStandbyRecord(rec); err != nil {
		return "", nil, err
	}
	sb := rec.Standby
	if sb == nil || sb.FloatingIPID == "" {
		return "", nil, errors.New("hetzner: this relay has no standby address")
	}
	f, err := p.c.FloatingIPByID(ctx, sb.FloatingIPID)
	if err != nil {
		return "", nil, fmt.Errorf("hetzner: read standby %s: %w", sb.FloatingIPID, err)
	}
	if f.ServerID != rec.ServerID {
		return "", nil, fmt.Errorf("hetzner: standby %s is not attached to this relay's server (attached to %q)", f.ID, f.ServerID)
	}
	if !f.IP.Equal(sb.IP) {
		return "", nil, fmt.Errorf("hetzner: standby %s is %v at the provider but the record says %v", f.ID, f.IP, sb.IP)
	}
	priorFIPID = rec.FloatingIPID
	priorIP = append(net.IP(nil), rec.PublicIP...)
	rec.FloatingIPID = f.ID
	adoptPublicIP(rec, f.IP.To4())
	rec.Standby = nil
	return priorFIPID, priorIP, nil
}

// RemoveStandby releases one standby. Refused for the relay's advertised
// address (a promoted standby is that address now) and for a Floating IP
// that is neither the record's standby nor labelled as one. deleted is
// false with a nil error for an address Daal did not create, exactly as
// ReleaseFloatingIP reports it. rec.Standby is cleared when it named it.
//
// The caller has already (1) signed and published a pack without it and
// (2) told the box to drop it. Releasing first would hand the address
// back to Hetzner's pool while packs and the box still claim it.
func (p *Provider) RemoveStandby(ctx context.Context, rec *provider.OperatorRecord, fipID string) (bool, error) {
	if err := requireStandbyRecord(rec); err != nil {
		return false, err
	}
	if fipID == "" {
		return false, errors.New("hetzner: remove standby: no floating ip named")
	}
	if fipID == rec.FloatingIPID {
		return false, fmt.Errorf("hetzner: floating ip %s is the address this relay is advertised on; it is not a standby", fipID)
	}
	named := rec.Standby != nil && rec.Standby.FloatingIPID == fipID
	f, err := p.c.FloatingIPByID(ctx, fipID)
	switch {
	case errors.Is(err, errFloatingIPNotFound):
		if named {
			rec.Standby = nil
		}
		return true, nil
	case err != nil:
		return false, fmt.Errorf("hetzner: read standby %s: %w", fipID, err)
	}
	if !named && !isStandby(f) {
		return false, fmt.Errorf("hetzner: floating ip %s is not this relay's standby; refusing to release it", fipID)
	}
	deleted, err := p.ReleaseFloatingIP(ctx, rec, fipID)
	if err != nil {
		return false, err
	}
	if named && deleted {
		rec.Standby = nil
	}
	return deleted, nil
}

// StandbyPrice is one Floating IPv4's monthly price in one location, as
// Hetzner's pricing API states it (decimal strings, unrounded).
type StandbyPrice struct {
	Location     string `json:"location"`
	Currency     string `json:"currency"`
	VATRate      string `json:"vat_rate"`
	MonthlyNet   string `json:"monthly_net"`
	MonthlyGross string `json:"monthly_gross"`
}

// floatingIPPricer is the optional client surface for the price. Kept
// off hcloudClient so the fakes and the dry-run client that do not
// price anything need not grow a method.
type floatingIPPricer interface {
	FloatingIPMonthlyPrice(ctx context.Context, location string) (StandbyPrice, error)
}

// ErrNoStandbyPrice: the client cannot read prices (dry run, fakes).
var ErrNoStandbyPrice = errors.New("hetzner: this client cannot read prices")

// StandbyMonthlyPrice reads the live monthly price of one Floating IPv4
// homed in region. Read-only.
func (p *Provider) StandbyMonthlyPrice(ctx context.Context, region string) (StandbyPrice, error) {
	pr, ok := p.c.(floatingIPPricer)
	if !ok {
		return StandbyPrice{}, ErrNoStandbyPrice
	}
	if region == "" {
		return StandbyPrice{}, errors.New("hetzner: standby price: no location")
	}
	return pr.FloatingIPMonthlyPrice(ctx, region)
}

// FloatingIPMonthlyPrice reads GET /pricing and picks the IPv4 Floating
// IP entry for location.
func (l *liveClient) FloatingIPMonthlyPrice(ctx context.Context, location string) (StandbyPrice, error) {
	pr, _, err := l.c.Pricing.Get(ctx)
	if err != nil {
		return StandbyPrice{}, err
	}
	for _, t := range pr.FloatingIPs {
		if t.Type != hcloud.FloatingIPTypeIPv4 {
			continue
		}
		for _, lp := range t.Pricings {
			if lp.Location == nil || lp.Location.Name != location {
				continue
			}
			cur := lp.Monthly.Currency
			if cur == "" {
				cur = pr.Currency
			}
			vat := lp.Monthly.VATRate
			if vat == "" {
				vat = pr.VATRate
			}
			return StandbyPrice{Location: location, Currency: cur, VATRate: vat,
				MonthlyNet: lp.Monthly.Net, MonthlyGross: lp.Monthly.Gross}, nil
		}
	}
	return StandbyPrice{}, fmt.Errorf("hetzner: no IPv4 floating ip price for %s", location)
}
