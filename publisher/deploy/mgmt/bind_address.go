package mgmt

// ADDRESS BINDING — the half of L3 that makes the swap actually work.
//
// THE HARDWARE FINDING (measured 2026-08-17, real Hetzner relay). An L3
// swap did everything right at the API layer: reserved the address,
// attached it to the server, stamped both ownership labels, rewrote
// rec.PublicIP. The API reported success in under a second. The box
// never answered on the new address — a TLS probe to it timed out while
// the old address kept serving.
//
// A Hetzner floating IP is ROUTED to the server at the provider's
// network layer, but the GUEST OS does not reply on it until the address
// is configured on its interface. Nothing in this tree did that:
// cloud-init never writes it and the assign path is pure API.
// health.AddressServes made that fail closed (6a7903c). This file is
// what makes it succeed: the publisher tells the box to put the address
// on its interface, and only then asks whether it answers.
//
// No sing-box change is needed and none is made. Every inbound already
// listens on 0.0.0.0 (profile_render.go:125,130; singbox_users.go:474,
// 565,673,678), so the moment the OS holds the address, sing-box accepts
// on it. Adding the address to the interface is sufficient.
//
// THREAT MODEL — this is root-level network configuration driven by a
// remote request, so it gets defence in depth rather than "the signature
// covers it".
//
// The only authenticated caller is the publisher: /bind-address sits
// behind the same Ed25519 request signing as every other mutating verb
// (requireAuth + MintToken, and the box binds the token's op to the
// route, so a token minted for users-list cannot drive a bind). The
// mgmt port is additionally firewalled to the caller's IP for the
// duration of one ephemeral window. That is the primary control and it
// is strong. What follows exists because the primary control failing
// (a leaked publisher key, a bug in the caller, a confused-deputy path
// that lets some other code pick the address) must not escalate into
// "attacker configures arbitrary addresses on the relay's interface":
//
//   - ADDRESS CLASS. Only a plausible public unicast address may be
//     bound. Binding 127.0.0.1, 169.254.169.254 (the cloud metadata
//     service), an RFC1918 or CGNAT address, or a multicast/broadcast
//     address would let a caller shadow a route the host relies on —
//     the metadata address is the sharpest case, since owning it locally
//     redirects the box's own credential lookups — or make the box
//     answer for traffic that is not its own. BindableAddress refuses
//     all of it, and refuses BEFORE any firewall window is opened, so a
//     request we are going to reject never widens the box's exposure.
//
//   - QUANTITY. MaxBoundAddresses bounds how many addresses the relay
//     may hold at once. A compromised or looping caller cannot walk the
//     interface up to thousands of addresses (an ARP/ND and memory
//     exhaustion surface, and an unbounded persisted-config file). The
//     box is the enforcement point — it is the only party that knows the
//     true count — and the publisher refuses the moment the box reports
//     a count past the bound, so a box that forgets to enforce still
//     produces a visible failure here.
//
//   - INJECTION. Nothing the caller typed is ever interpolated into a
//     command line. This package accepts a net.IP (already parsed
//     bytes — never a string), validates it, and re-renders it with
//     net.IP.String(). The JSON body therefore contains a canonical
//     address literal that cannot carry a shell metacharacter, a
//     newline, an "ip addr add" flag, or a second argument, whatever the
//     caller believed it was passing. The box is expected to parse it
//     again on its side and re-render before use; both ends doing so is
//     the point.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"daal/publisher/deploy/provider"
)

// CapBindAddress is the capability token a box advertises in GET
// /health's `capabilities` array once it can configure an address on its
// own interface.
//
// ONE token covers both /bind-address and /unbind-address. They ship
// together, are useless apart (an unbind with no bind has nothing to
// undo), and a box that had one without the other would be a shape no
// release produces. The token names the semantics rather than a route,
// following CapRotateCredentialsScoped's rule.
//
// WIRE CONTRACT with cmd/daal-relay-mgmt. The literal here and the
// literal the box emits must match exactly; a rename on one side
// silently turns every L3 into a refusal.
const CapBindAddress = "bind-address"

// MgmtAPIVersionAddressBinding is the /health `mgmt_api_version` at
// which the two routes are part of the contract.
//
// IT IS NOT A SUFFICIENT SIGNAL, and that is the one place this
// capability differs from every other one in this package. The rotation
// verbs describe what the BINARY does, so a version number implies them.
// Address binding also needs CAP_NET_ADMIN, which the box's own systemd
// unit decides: the current cloud-init grants it, every relay
// provisioned before Wave 3c does not, and such a box refuses the whole
// capability rather than advertise a bind it could never undo (the boot
// unit it would otherwise delegate to can only ADD an address). So a
// relay can be running the right binary and still be unable to
// configure an address — reprovisioning is what fixes it. A version
// fallback would make the interlock assert a capability that does not
// exist and move the failure into the middle of a swap — the one place
// the fail-closed design exists to keep it out of.
//
// So [BoxCapabilities.Has] consults ONLY the token for this capability,
// and cmd/daal-relay-mgmt correspondingly keeps mgmt_api_version at 2
// and emits the token conditionally on a real probe. This constant
// remains as the documented version of the route contract; nothing reads
// it as permission.
const MgmtAPIVersionAddressBinding = 3

// MaxBoundAddresses bounds how many addresses one relay may hold.
//
// A relay needs at most a handful: its own primary address, the floating
// IP it is serving on, and — during a swap — the one it is moving onto
// while the old one is still live. Four leaves room for a v4/v6 pair on
// each side of a swap and no room for a runaway.
//
// The BOX is the enforcement point, because it is the only party that
// can see the interface. This constant is the shared number both ends
// check against: the publisher refuses a response reporting more than
// this, so a box that forgets to enforce produces a loud failure rather
// than a slowly filling interface.
const MaxBoundAddresses = 4

// ErrAddressNotBindable rejects an address that must never be
// configured on a relay's interface. See the threat model above.
var ErrAddressNotBindable = errors.New("mgmt: refusing to bind that address")

// ErrTooManyBoundAddresses fires when the relay reports holding more
// addresses than MaxBoundAddresses.
var ErrTooManyBoundAddresses = errors.New("mgmt: relay is holding more addresses than the contract allows")

// BindableAddress validates that ip is a plausible PUBLIC UNICAST
// address and returns it in canonical form.
//
// Canonicalisation is not cosmetic: the returned value is what gets
// rendered into the request body, so the box receives an address this
// process parsed and re-printed rather than anything a caller composed.
// An IPv4-mapped IPv6 address (::ffff:10.0.0.1) is unwrapped first, so
// the v4 rules below cannot be bypassed by spelling a private address
// the long way.
//
// WHAT IS DELIBERATELY ALLOWED: the documentation ranges (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32). They are not
// routable, so a relay cannot serve on one — but binding one shadows no
// internal route, hijacks no traffic on the host, and reaches no
// metadata service, which is the harm this function exists to prevent.
// They are also what every fixture and every provider dry-run in this
// tree uses, and the only addresses a reachability test can DIAL while
// being certain nobody answers, so rejecting them would fail closed on
// test data — and push every such test onto a third party's real
// address — while buying no security.
//
// THIS RULE IS SHARED WITH THE BOX and the two must not drift.
// cmd/daal-relay-mgmt's rejectedRanges originally refused these four
// ranges, so a bind of a documentation address passed here and came
// back 400 from the box: not a safety hole (the swap failed closed and
// the address was handed back) but a refusal that landed AFTER a
// reserve, an attach and an open firewall window, and one that made the
// box↔publisher seam impossible to exercise end to end. The box was
// relaxed to match this function; this function was tightened to match
// the box on 192.88.99.0/24, which is the one row where the harm is
// real. Each end adopted the other's better rule; changing either
// without the other reintroduces the drift.
func BindableAddress(ip net.IP) (net.IP, error) {
	if len(ip) == 0 {
		return nil, fmt.Errorf("%w: no address given", ErrAddressNotBindable)
	}
	// Unwrap ::ffff:a.b.c.d so the v4 rules apply to it too.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if len(ip) != net.IPv6len {
		return nil, fmt.Errorf("%w: %d-byte value is not an IP address", ErrAddressNotBindable, len(ip))
	}
	if ip.IsUnspecified() {
		return nil, fmt.Errorf("%w: the unspecified address", ErrAddressNotBindable)
	}
	if ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %s is loopback — binding it would shadow the host's own stack", ErrAddressNotBindable, ip)
	}
	if ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() {
		return nil, fmt.Errorf("%w: %s is multicast, not unicast", ErrAddressNotBindable, ip)
	}
	if ip.IsLinkLocalUnicast() {
		// 169.254.0.0/16 contains 169.254.169.254, the cloud metadata
		// service. A relay that answers for that address locally
		// intercepts its own credential lookups.
		return nil, fmt.Errorf("%w: %s is link-local — that range carries the cloud metadata service", ErrAddressNotBindable, ip)
	}
	if ip.IsPrivate() {
		return nil, fmt.Errorf("%w: %s is a private (RFC1918/ULA) address — binding it would shadow an internal route", ErrAddressNotBindable, ip)
	}
	if v4 := ip.To4(); v4 != nil {
		for _, bad := range v4Forbidden {
			if bad.net.Contains(v4) {
				return nil, fmt.Errorf("%w: %s is in %s (%s)", ErrAddressNotBindable, v4, bad.net, bad.why)
			}
		}
		return append(net.IP(nil), v4...), nil
	}
	for _, bad := range v6Forbidden {
		if bad.net.Contains(ip) {
			return nil, fmt.Errorf("%w: %s is in %s (%s)", ErrAddressNotBindable, ip, bad.net, bad.why)
		}
	}
	return append(net.IP(nil), ip...), nil
}

type forbiddenRange struct {
	net *net.IPNet
	why string
}

func mustCIDR(s, why string) forbiddenRange {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("mgmt: bad forbidden CIDR " + s + ": " + err.Error())
	}
	return forbiddenRange{net: n, why: why}
}

// v4Forbidden covers the special-purpose IPv4 space net.IP's own
// predicates do not: net.IsPrivate knows RFC1918 but not CGNAT, and
// nothing in the stdlib knows "this network", the reserved class, or the
// benchmark range. 240.0.0.0/4 subsumes the all-ones broadcast address.
var v4Forbidden = []forbiddenRange{
	mustCIDR("0.0.0.0/8", "\"this network\" — never a host address"),
	mustCIDR("100.64.0.0/10", "CGNAT/shared address space — an internal route, not a public address"),
	mustCIDR("192.0.0.0/24", "IETF protocol assignments"),
	// Added to match cmd/daal-relay-mgmt, which had it and this table
	// did not. It is not a documentation range: 6to4 relay anycast has
	// real routing meaning, so binding it can attract or shadow traffic
	// that is not this relay's. The v6 half of the same mechanism
	// (2002::/16) was already refused below, so this row also removes
	// an inconsistency inside this table.
	mustCIDR("192.88.99.0/24", "deprecated 6to4 relay anycast — real routing meaning, not a host address"),
	mustCIDR("198.18.0.0/15", "benchmarking range"),
	mustCIDR("224.0.0.0/4", "multicast"),
	mustCIDR("240.0.0.0/4", "reserved, and contains the all-ones broadcast address"),
}

// v6Forbidden is the IPv6 equivalent. Link-local, ULA and multicast are
// already caught by the stdlib predicates above; these are the ones that
// are not.
var v6Forbidden = []forbiddenRange{
	mustCIDR("100::/64", "discard-only prefix"),
	mustCIDR("64:ff9b::/96", "NAT64 translation prefix — an embedded v4 destination, not a host address"),
	mustCIDR("2001::/32", "Teredo tunnelling"),
	mustCIDR("2002::/16", "6to4 tunnelling"),
}

// bindAddressReq is the POST body for both verbs. One field, always
// re-rendered from parsed bytes (see the injection note above).
type bindAddressReq struct {
	IP string `json:"ip"`
}

// BindAddressResp is what POST /bind-address answers: what the box
// actually did, not merely that it returned 200.
//
// EVERY FIELD THE BOX SENDS MUST EXIST HERE. encoding/json drops unknown
// keys silently, and this project has already shipped one inert feature
// exactly that way — the box echoed cover_sni and mux_inbound and the
// struct in the middle swallowed them, so the value died between two
// ends that both had it right. A value the box learns and the publisher
// needs has to be declared here or it does not exist.
type BindAddressResp struct {
	// IP is the address the box says it configured, echoed back. The
	// publisher checks it against what was asked: a box that answers 200
	// for a different address did not do what was requested, and the
	// caller is about to re-sign every pack on the strength of this.
	IP string `json:"ip"`

	// Interface is the interface the address landed on (e.g. "eth0").
	// Diagnostic: a bind that lands somewhere unexpected is worth seeing
	// in the operator's log.
	Interface string `json:"interface,omitempty"`

	// AlreadyBound reports that the address was present before the call.
	// The verb is idempotent, so this is the normal answer on a re-run
	// (and on a relay whose bind survived a reboot) — success, not a
	// warning.
	AlreadyBound bool `json:"already_bound"`

	// Persisted reports that the address will still be configured after
	// a reboot. It is the field that separates "works now" from "works",
	// and it is reported rather than enforced: see BindAddress.
	Persisted bool `json:"persisted"`

	// PersistPath names where the box wrote that persistence, so an
	// operator debugging a relay knows which file to look at.
	PersistPath string `json:"persist_path,omitempty"`

	// BoundAddresses is every address the box now holds. It is what
	// makes MaxBoundAddresses checkable from this side rather than
	// merely asserted.
	BoundAddresses []string `json:"bound_addresses,omitempty"`

	// AppliedAtUnix is the box's own clock when the change went live.
	AppliedAtUnix int64 `json:"applied_at_unix,omitempty"`

	// Warnings is whatever the box wants said out loud. Rendered
	// verbatim, never summarised.
	Warnings []string `json:"warnings,omitempty"`
}

// UnbindAddressResp is what POST /unbind-address answers.
type UnbindAddressResp struct {
	// IP is the address the box removed, echoed back.
	IP string `json:"ip"`

	// Removed reports that the address is no longer configured. False
	// with WasBound false is the idempotent no-op (nothing to remove);
	// false with WasBound true is a failure the box chose to report as a
	// 200, and the caller must treat it as one.
	Removed bool `json:"removed"`

	// WasBound reports whether the address was there to begin with.
	WasBound bool `json:"was_bound"`

	// PersistenceRemoved reports that the reboot-time configuration is
	// gone too. An address removed from the live interface but left in
	// the persisted config comes back on the next reboot — on an address
	// that by then may belong to another customer.
	PersistenceRemoved bool `json:"persistence_removed"`

	// StillConfigured reports that the address is ON the box's interface
	// after this call. It is the machine-readable form of the one thing
	// the box could previously only say in prose.
	//
	// The case it exists for: the address is not in the box's record set
	// (so the record gate refuses to touch it — it could be the box's
	// own primary address, and removing that is an unrecoverable outage
	// on a relay with no SSH) but it IS configured on the interface. The
	// box answers 200 with WasBound=false, Removed=false — which reads
	// as the idempotent no-op — plus a warning. Every call site
	// discarded the struct, so `floating-ip release` went on to hand the
	// address back to the provider's pool while the relay was still
	// answering on it. UnbindAddress now turns this field into an error
	// so no caller can drop the signal by ignoring the response.
	//
	// An older box does not send it; absent decodes as false, which is
	// the pre-existing behaviour.
	StillConfigured bool `json:"still_configured"`

	// BoundAddresses is every address the box still holds.
	BoundAddresses []string `json:"bound_addresses,omitempty"`

	AppliedAtUnix int64    `json:"applied_at_unix,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// BindAddress calls POST /bind-address {"ip":"<addr>"}: add the address
// to the relay's primary interface, idempotently, persisted across
// reboot.
//
// Callers should reach this through BindAddressWithFW, which opens the
// firewall window, points the client at an address the box is KNOWN to
// answer on, and runs the capability interlock.
//
// PERSISTENCE IS REPORTED, NOT ENFORCED. A box that answers
// persisted=false has configured the address now and will lose it on the
// next reboot — a latent outage, since by then every pack names it. That
// is a warning rather than a refusal on purpose: refusing would abort the
// swap and leave the relay on the address the operator is rotating away
// from, which is the failure they are trying to escape. A relay that
// works today and needs attention beats a relay that is still blocked.
func (c *Client) BindAddress(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, ip net.IP) (*BindAddressResp, error) {
	addr, err := BindableAddress(ip)
	if err != nil {
		return nil, err
	}
	var got BindAddressResp
	if err := c.addressVerb(ctx, rec, privKey, "bind-address", addr, &got); err != nil {
		return nil, err
	}
	if err := checkEchoedAddress("bind-address", addr, got.IP); err != nil {
		return nil, err
	}
	if err := checkBoundCount(got.BoundAddresses); err != nil {
		return nil, err
	}
	got.IP = addr.String()
	if !got.Persisted {
		got.Warnings = append([]string{
			fmt.Sprintf("relay bound %s but reports persisted=false: the address is live now and will be GONE after the next reboot, "+
				"while every pack signed from here on names it — check the relay's address persistence before you rely on this rotation", addr),
		}, got.Warnings...)
	}
	return &got, nil
}

// UnbindAddress calls POST /unbind-address {"ip":"<addr>"}: remove the
// address from the interface, idempotently, removing the persistence
// with it.
//
// Why the publisher bothers, when the provider has already stopped
// routing the address here: a box that keeps an address it no longer
// owns will still pick it as a source address for its own outbound
// traffic, and the provider is free to hand that address to another
// customer's server. The relay then talks from an address that is routed
// to somebody else. Giving the address back to the provider pool while a
// live box still claims it locally is the state this verb exists to
// avoid.
func (c *Client) UnbindAddress(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, ip net.IP) (*UnbindAddressResp, error) {
	// Validated with the same rule as bind. An unbind is not
	// destructive to the host in the way a bind is, but a caller that
	// hands this loopback or a link-local address is a caller that is
	// confused about which address it is operating on, and answering
	// "removed" to that would be worse than refusing.
	addr, err := BindableAddress(ip)
	if err != nil {
		return nil, err
	}
	var got UnbindAddressResp
	if err := c.addressVerb(ctx, rec, privKey, "unbind-address", addr, &got); err != nil {
		return nil, err
	}
	if err := checkEchoedAddress("unbind-address", addr, got.IP); err != nil {
		return nil, err
	}
	got.IP = addr.String()
	if got.WasBound && !got.Removed {
		return &got, fmt.Errorf("mgmt: unbind-address: relay reports %s is still configured on its interface", addr)
	}
	// THE 200 THAT IS NOT A SUCCESS. The box refuses to remove an
	// address it did not bind — that gate is what makes it impossible to
	// delete the relay's own primary address through this API — so an
	// address that is live but foreign comes back as
	// was_bound=false, removed=false, i.e. the same shape as the
	// ordinary "there was nothing to remove" no-op, with the difference
	// stated only in Warnings. The caller's next move after this
	// function returns nil is to hand the address back to the provider's
	// pool, where another customer may be issued an address this live
	// box still answers on. So it is an ERROR here rather than a field
	// the caller is trusted to read: the release path already stops on
	// an error and says the address stays reserved and billing.
	if got.StillConfigured && !got.Removed {
		return &got, fmt.Errorf("mgmt: unbind-address: relay reports %s is still configured on its interface and that it "+
			"did NOT bind it, so it refused to remove it (this API only removes addresses it added, because removing the "+
			"box's primary address would be an unrecoverable outage). Do not release this address while that relay is alive", addr)
	}
	if got.Removed && !got.PersistenceRemoved {
		got.Warnings = append(got.Warnings, fmt.Sprintf(
			"relay removed %s from the live interface but reports persistence_removed=false: it will come back on the next reboot, "+
				"on an address this relay no longer owns", addr))
	}
	return &got, nil
}

// addressVerb is the shared POST for both verbs: mint, send the
// canonical address, decode. Kept in one place so the two cannot drift
// in how they authenticate or how they render the body.
func (c *Client) addressVerb(ctx context.Context, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, op string, addr net.IP, out any) error {
	tok, err := MintToken(privKey, op, c.now())
	if err != nil {
		return err
	}
	// The address is re-rendered from the bytes BindableAddress
	// returned. Nothing a caller typed reaches the wire.
	body, err := json.Marshal(bindAddressReq{IP: addr.String()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.boxURL(rec, "/"+op), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Daal-Mgmt-Token "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mgmt: %s: %w", op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("mgmt: %s %d: %s", op, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("mgmt: %s: decode: %w", op, err)
	}
	return nil
}

// checkEchoedAddress refuses a box that answers 200 about a different
// address than the one asked for. Same rule RotateCredentials applies to
// the recipient name, and for the same reason: the caller is about to
// act on this answer.
//
// An empty echo is accepted — an older-shaped response that omits the
// field is not evidence of the wrong address — but a MISMATCHED echo is
// a hard stop.
func checkEchoedAddress(op string, want net.IP, echoed string) error {
	got := strings.TrimSpace(echoed)
	if got == "" {
		return nil
	}
	parsed := net.ParseIP(got)
	if parsed == nil {
		return fmt.Errorf("mgmt: %s: relay echoed %q, which is not an IP address", op, got)
	}
	if !parsed.Equal(want) {
		return fmt.Errorf("mgmt: %s asked for %s but the relay answered for %s", op, want, parsed)
	}
	return nil
}

// checkBoundCount is the publisher's half of the quantity bound. The box
// enforces it (only the box can see the interface); this catches a box
// that does not.
func checkBoundCount(bound []string) error {
	if len(bound) > MaxBoundAddresses {
		return fmt.Errorf("%w: %d addresses (%s), limit %d — refusing to add another",
			ErrTooManyBoundAddresses, len(bound), strings.Join(bound, ","), MaxBoundAddresses)
	}
	return nil
}

// controlRecord returns a copy of rec that the mgmt client will dial at
// controlIP instead of rec.PublicIP.
//
// THIS IS THE WHOLE ORDERING PROBLEM IN ONE FUNCTION. By the time the
// publisher asks the box to bind the new address, the provider adapter
// has already moved rec.PublicIP onto that address — and the box does
// not answer there yet, because binding it is precisely what we are
// about to ask for. Dialling rec.PublicIP would deadlock the swap on
// itself: the call that fixes the box can only be delivered over the
// address the box still serves.
//
// So the caller passes the address the relay is KNOWN to answer on
// today (the pre-swap one), and everything else — the pinned TLS
// fingerprint, the mgmt port, the server id the firewall window is
// opened against — comes from the real record unchanged. The pin is on
// the certificate, not on a hostname, so reaching the same box by a
// different address verifies exactly as strictly.
func controlRecord(rec *provider.OperatorRecord, controlIP net.IP) (*provider.OperatorRecord, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	if len(controlIP) == 0 {
		return nil, errors.New("mgmt: no working address to reach the relay on (the mgmt call cannot be delivered over the address it is meant to bring up)")
	}
	ctrl := *rec
	ctrl.PublicIP = append(net.IP(nil), controlIP...)
	return &ctrl, nil
}

// BindAddressWithFW is the publisher-side entry point: validate, open
// the ephemeral firewall window, run the capability interlock, bind.
//
// controlIP is the address the relay currently ANSWERS on — normally the
// pre-swap address. target is the address to bring up. They are separate
// parameters because at this point in an L3 they are different addresses
// and confusing them is unrecoverable; see controlRecord.
func BindAddressWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string, controlIP, target net.IP) (*BindAddressResp, error) {
	// Validate BEFORE anything is opened: a request we are going to
	// refuse must never cause a firewall rule to exist.
	addr, err := BindableAddress(target)
	if err != nil {
		return nil, err
	}
	ctrl, err := controlRecord(rec, controlIP)
	if err != nil {
		return nil, err
	}
	return withFirewallWindow(ctx, prov, ctrl, callerIP, func(cli *Client) (*BindAddressResp, error) {
		if err := requireCapability(ctx, cli, ctrl, CapBindAddress); err != nil {
			return nil, err
		}
		return cli.BindAddress(ctx, ctrl, privKey, addr)
	})
}

// UnbindAddressWithFW is the mirror. controlIP is again an address the
// relay answers on — for a release that is the address it is FALLING
// BACK to, never the one being removed, so the call cannot cut the
// ground out from under itself.
//
// A box too old to bind is also a box that never bound anything, so
// callers should read ErrCapabilityUnsupported here as "nothing to
// unbind" and carry on rather than stranding the address.
func UnbindAddressWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string, controlIP, target net.IP) (*UnbindAddressResp, error) {
	addr, err := BindableAddress(target)
	if err != nil {
		return nil, err
	}
	ctrl, err := controlRecord(rec, controlIP)
	if err != nil {
		return nil, err
	}
	if len(controlIP) > 0 && controlIP.Equal(addr) {
		return nil, fmt.Errorf("mgmt: unbind-address: refusing to reach the relay on %s in order to remove %s — "+
			"detach the address at the provider first so the record falls back to an address that survives the unbind", controlIP, addr)
	}
	return withFirewallWindow(ctx, prov, ctrl, callerIP, func(cli *Client) (*UnbindAddressResp, error) {
		if err := requireCapability(ctx, cli, ctrl, CapBindAddress); err != nil {
			return nil, err
		}
		return cli.UnbindAddress(ctx, ctrl, privKey, addr)
	})
}
