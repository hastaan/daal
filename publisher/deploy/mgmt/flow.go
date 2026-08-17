package mgmt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"daal/publisher/deploy/provider"
)

// EphemeralWindow is the default window the Helper opens on the
// cloud-provider firewall before each L1/L2 mgmt call. 5 minutes
// matches supplement §9.5.2.
const EphemeralWindowSeconds = 300

// teardownGrace bounds the explicit firewall-rule removal.
//
// It exists because the removal must not inherit the caller's context.
// The common failure is precisely the one where cleanup matters most: a
// rotation that hangs until ctx's deadline fires, at which point a
// teardown on that same (now-cancelled) ctx fails instantly and the
// window is left open for the rest of its 300 seconds. Deriving from
// context.WithoutCancel and giving it its own short budget means the
// close still happens on the timeout path.
const teardownGrace = 30 * time.Second

// realityHandshakePort is the port the box dials for its REALITY
// handshake, and the port cloud-init writes into
// reality.handshake.server_port. A cover host that is not reachable on
// 443 is not a cover host.
const realityHandshakePort = 443

// withFirewallWindow is the ONE implementation of the ephemeral-window
// dance, shared by every mgmt call in this package.
//
// It used to be copy-pasted five times. That is a bad shape for this
// particular invariant: a window that leaks open on an error path is a
// security bug (the mgmt port is exposed to the caller's IP for as long
// as it stays open), and "every copy remembered its defer" is a
// property no test can hold down as copies are added. Funnelling every
// caller through one function makes open-then-always-close structural
// instead of aspirational, and the fn callback cannot skip the defer no
// matter how it returns or panics.
//
// Order matters and is load-bearing:
//
//  1. validate FIRST — a request we are going to refuse must never
//     cause a firewall rule to be opened;
//  2. open;
//  3. defer close on an uncancellable context;
//  4. run fn (which may itself probe capabilities — /health is behind
//     the same firewall, so the probe has to happen inside the window).
func withFirewallWindow[T any](
	ctx context.Context,
	prov provider.Provider,
	rec *provider.OperatorRecord,
	callerIP string,
	fn func(cli *Client) (T, error),
) (T, error) {
	var zero T
	if rec == nil {
		return zero, errors.New("mgmt: nil OperatorRecord")
	}
	if prov == nil {
		return zero, errors.New("mgmt: nil Provider (cannot open the ephemeral firewall window)")
	}
	if err := provider.ValidateMgmtPort(rec.MgmtPort); err != nil {
		return zero, fmt.Errorf("mgmt: OperatorRecord.MgmtPort invalid (V2 fast path not available; redeploy required): %w", err)
	}
	rule, err := prov.SetEphemeralFirewallRule(ctx, rec.ServerID, callerIP, rec.MgmtPort, EphemeralWindowSeconds)
	if err != nil {
		return zero, fmt.Errorf("mgmt: open ephemeral fw: %w", err)
	}
	defer func() {
		// Best-effort cleanup on a context the caller cannot cancel
		// (see teardownGrace); the provider auto-expires the rule at
		// EphemeralWindowSeconds anyway, so this is defense in depth
		// rather than the only close.
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), teardownGrace)
		defer cancel()
		_ = prov.RemoveEphemeralFirewallRule(tctx, rule)
	}()

	cli, err := NewClient(rec)
	if err != nil {
		return zero, err
	}
	return fn(cli)
}

// RotateCredentialsWithFW orchestrates the L1 fast path — a TARGETED
// REVOCATION of one recipient:
//
//  1. reject an empty name (before anything is opened);
//  2. SetEphemeralFirewallRule(callerIP, port, 300s);
//  3. probe GET /health and refuse a relay whose software predates the
//     scoped endpoint (capability.go explains why this interlock is
//     mandatory rather than cosmetic);
//  4. POST /rotate-credentials {"name":…} against the TLS-pinned
//     mgmt plane;
//  5. RemoveEphemeralFirewallRule (deferred; runs on every path).
//
// Blast radius: ONE recipient. Every other recipient keeps working, and
// no REALITY key material moves, so no already-distributed pack is
// invalidated. That is the whole point of the split — see
// RotateBoxKeysWithFW's absence, and the note at the bottom of this
// file.
func RotateCredentialsWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP, name string) (*RotatedCreds, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrRecipientNameRequired
	}
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*RotatedCreds, error) {
		if err := requireCapability(ctx, cli, rec, CapRotateCredentialsScoped); err != nil {
			return nil, err
		}
		return cli.RotateCredentials(ctx, rec, privKey, name)
	})
}

// RotateTLSWithFW orchestrates the L2 fast path: change the relay's
// cover SNI / TLS parameters in place, without touching REALITY
// keypairs or anybody's credentials.
//
// It mirrors RotateCredentialsWithFW exactly — same window, same
// interlock, same teardown discipline — and adds the two things only
// the publisher can do:
//
//   - CHOOSE the new cover host. An empty profile.NewSNI does not mean
//     "keep the current one"; it means "pick a fresh admissible host
//     from this relay's zone, excluding the one it is advertising
//     today" (provider.NextCoverSNI). Handing a relay back the same
//     cover host after its cover host was burned is not a rotation.
//   - RECORD what actually landed. rec.CoverSNI is updated from the
//     box's echo, because the box's live config is authoritative and
//     the record is only a memo of what was requested. A stale
//     rec.CoverSNI silently mints packs for the wrong cover host.
//
// The returned response is non-nil whenever the box applied something,
// even alongside an error, so a caller that hits the consistency check
// below can still persist what happened.
func RotateTLSWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string, profile TLSProfile) (*RotateTLSResp, error) {
	if rec == nil {
		return nil, errors.New("mgmt: nil OperatorRecord")
	}
	// Resolve the target cover host BEFORE the window opens: a pool with
	// no admissible host for this region is a refusal, and a refusal must
	// not leave a firewall rule behind it.
	if strings.TrimSpace(profile.NewSNI) == "" {
		next, err := provider.NextCoverSNI(rec, "", time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("mgmt: rotate-tls: choose new cover host: %w", err)
		}
		profile.NewSNI = next
	}
	if len(profile.NewDests) == 0 {
		profile.NewDests = []string{net.JoinHostPort(profile.NewSNI, strconv.Itoa(realityHandshakePort))}
	}

	resp, err := withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*RotateTLSResp, error) {
		if err := requireCapability(ctx, cli, rec, CapRotateTLSScoped); err != nil {
			return nil, err
		}
		return cli.RotateTLS(ctx, rec, privKey, profile)
	})
	if err != nil {
		return resp, err
	}
	if resp == nil {
		return nil, errors.New("mgmt: rotate-tls returned no response")
	}
	// Follow the box, not the request. If it echoed nothing (a box that
	// answers only applied_at_unix), fall back to what we asked for —
	// that is the best available answer, and it is still better than
	// leaving the record on the burned host.
	applied := strings.TrimSpace(resp.AppliedSNI)
	if applied == "" {
		applied = profile.NewSNI
		resp.AppliedSNI = applied
	}
	previous := rec.CoverSNI
	rec.CoverSNI = applied

	// A 200 alone cannot distinguish "rotated the cover host" from
	// "decided nothing needed rotating". Two independent tells, either
	// sufficient: the box's own `changed` list omits the cover host, or
	// the name it echoes is the one it already had. When we asked for a
	// move and neither confirms it, the relay is still advertising the
	// burned name — and an operator who believes it rotated will not
	// rotate again.
	askedToMove := previous != "" && !strings.EqualFold(profile.NewSNI, previous)
	stillOnOldHost := strings.EqualFold(applied, previous)
	boxSaysUnchanged := len(resp.Changed) > 0 && !containsFold(resp.Changed, "cover_sni")
	if askedToMove && (stillOnOldHost || boxSaysUnchanged) {
		return resp, fmt.Errorf("mgmt: rotate-tls asked for cover host %q but the relay reports applied_sni=%q changed=%v — the cover host was NOT replaced; the relay is still advertising %q", profile.NewSNI, resp.AppliedSNI, resp.Changed, previous)
	}

	// Wave 2's missing piece was that tls.server_name,
	// reality.server_names and reality.handshake.server have to move
	// TOGETHER; a config where the handshake target disagrees with the
	// advertised name is a relay that fails classification for a reason
	// nobody will find quickly. The box echoes both so the publisher can
	// check rather than trust a bare 200. The rotation HAS applied at
	// this point, so this is reported as an error with the record
	// already updated — the operator needs to know the box is in a state
	// that needs looking at, not to think nothing happened.
	if h := strings.TrimSpace(resp.AppliedHandshake); h != "" {
		host := h
		if hh, _, splitErr := net.SplitHostPort(h); splitErr == nil {
			host = hh
		}
		if !strings.EqualFold(host, applied) {
			return resp, fmt.Errorf("mgmt: rotate-tls applied SNI %q but handshake target %q — the box's server_name and reality.handshake.server disagree (Wave-2 invariant); inspect the relay before minting packs", applied, h)
		}
	}
	return resp, nil
}

// containsFold is a case-insensitive membership test over a small
// slice; the box's `changed` vocabulary is a closed set of lowercase
// tokens, but a comparison that depends on that is a comparison that
// breaks quietly.
func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(strings.TrimSpace(h), needle) {
			return true
		}
	}
	return false
}

// NOTE — the third operation, deliberately absent.
//
// Rotating the box's REALITY keypair is NOT reachable from this
// package. It is a different blast radius entirely: every recipient's
// pinned public key stops matching at once, so every pack ever
// distributed is dead until each recipient receives a new one — and
// under blackout, redistribution is exactly the thing that does not
// work. It therefore needs its own endpoint, its own explicit
// confirmation, and Step 8's freshness delivery underneath it. Adding
// it as a flag or a side effect of either function above would
// reintroduce the exact conflation Step 7 exists to undo.

// ProvisionUserWithFW orchestrates a /users/provision call,
// wrapped with the ephemeral firewall window. Returns the freshly
// minted per-recipient credentials.
func ProvisionUserWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP, name string) (*UserCreds, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*UserCreds, error) {
		return cli.ProvisionUser(ctx, rec, privKey, name)
	})
}

// RevokeUserWithFW is the /users/revoke equivalent. The on-box
// service runs the SIGUSR2 kick wrapper before responding.
func RevokeUserWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP, name string) (*RevokeResp, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*RevokeResp, error) {
		return cli.RevokeUser(ctx, rec, privKey, name)
	})
}

// ListUsersWithFW lists the current recipient roster on the box.
func ListUsersWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string) ([]UserMeta, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) ([]UserMeta, error) {
		return cli.ListUsers(ctx, rec, privKey)
	})
}

// CapabilitiesWithFW probes what the relay's in-box mgmt binary can do,
// without mutating anything.
//
// The publisher needs this on its own, not only as an interlock inside
// a rotation: the wizard has to decide whether to OFFER an in-place
// rotation button at all, and the rotation recommender has to know
// whether the rung it is about to name is reachable
// (publisher/deploy/rotation.RelayCapabilities). Asking by attempting
// is not an option here — see capability.go.
func CapabilitiesWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, callerIP string) (*BoxCapabilities, error) {
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*BoxCapabilities, error) {
		return cli.Capabilities(ctx, rec)
	})
}
