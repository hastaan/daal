package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"daal/publisher/deploy/provider"
)

// CAPABILITY DETECTION — why a probe exists at all, and why it is a
// safety interlock rather than a nicety.
//
// cmd/daal-relay-mgmt ships as a hash-pinned artifact
// (publisher/deploy/cloudinit/artifacts.go). A relay provisioned before
// this work keeps running the OLD binary until a human rebuilds,
// re-signs, re-uploads and bumps the pin, so at any moment the fleet
// contains both shapes and the publisher is the only party that can
// tell them apart.
//
// The naive detections do not work here:
//
//   - Route probing is useless. /rotate-credentials and /rotate-tls
//     have been REGISTERED since FRP-10 (main.go routes()). An old box
//     answers 200, not 404. "The endpoint exists" says nothing about
//     what it does.
//   - Probing by behaviour is unsafe. The old /rotate-credentials
//     ignores the request body entirely and rotates the box-wide
//     REALITY keypair as a side effect — that invalidates the pinned
//     public key in EVERY pack already distributed, and under blackout
//     redistribution is exactly what does not work. A probe whose
//     failure mode is "silently bricked every recipient" is not a
//     probe. So the publisher must never send the new request to an
//     unknown box "to see what happens".
//
// Therefore: POSITIVE, NON-MUTATING, FAIL-CLOSED. The box advertises
// what it can do on GET /health — a route that already exists (no
// eighth-route supplement amendment), needs no auth, and mutates
// nothing. Absence of an advertisement means "old box", the same rule
// /whoami already documents for feature detection and the same rule
// mgmt.UserCreds learned the hard way: a value the box does not send is
// the reliable signal, never an inference from a value it does send.
//
// An old box answers `{"ok":true}`, which decodes into BoxCapabilities
// with an empty verb set — so the fail-closed answer falls out of the
// wire format instead of needing a special case.
//
// The interlock is what makes the whole step safe to ship ahead of the
// re-release: an un-updated relay produces a clear, actionable refusal
// before a single byte of rotation request is sent.

// Capability tokens a box advertises in GET /health's `capabilities`
// array.
//
// The token names the SEMANTICS, not the route. "rotate-credentials"
// would be ambiguous — every box since FRP-10 has that route — so the
// token carries the "-scoped" suffix that distinguishes the Step-7
// split behaviour (targeted, per-recipient, no box-key side effect)
// from the old conflated one.
const (
	// CapRotateCredentialsScoped: POST /rotate-credentials {"name":"r1"}
	// rotates ONLY that recipient's per-user credentials, across every
	// inbound, and touches no REALITY keypair. Omitting "name" is an
	// error on such a box, never "rotate all".
	CapRotateCredentialsScoped = "rotate-credentials-scoped"

	// CapRotateTLSScoped: POST /rotate-tls rotates cover SNI / TLS
	// parameters only, leaving REALITY keypairs and user credentials
	// alone, and echoes what it applied.
	CapRotateTLSScoped = "rotate-tls-scoped"

	// CapShadowsocks2022: this relay's mgmt binary creates the ss-in
	// inbound (shadowsocks, 2022-blake3-aes-128-gcm, per-recipient uPSKs
	// on one shared box iPSK) when it provisions a recipient, and echoes
	// the assembled client password on /users/provision.
	//
	// WHAT CONSULTS THIS, stated plainly because it used to claim more
	// than it delivered. Nothing in the provision or pack path calls
	// Has() for this token; the two things that actually protect the
	// operator are (a) UserCreds.SSPassword arriving empty, which is
	// the safety interlock that makes the pack renderer refuse the
	// route, and (b) MissingFamilyCredentials at the bottom of this
	// file, which turns that empty value into a warning at provision
	// time. This token is for a PRE-PURCHASE probe: GET /health answers
	// it without provisioning anything, so an operator can learn before
	// renting a server that the artifact pin in cloudinit/artifacts.go
	// still points at a binary with no shadowsocks in it.
	//
	// Deliberately NO version fallback in Has(): the capability rides
	// the pinned artifact, and inferring it from mgmt_api_version is
	// how a box comes to claim a family it does not serve.
	CapShadowsocks2022 = "shadowsocks-2022"

	// CapAnyTLSInbound: this relay's mgmt binary creates the anytls-in
	// inbound (per-recipient passwords, per-relay padding scheme) when
	// it provisions a recipient, and echoes that recipient's password on
	// /users/provision.
	//
	// Same division of labour as CapShadowsocks2022, including what
	// does and does not consult it: this token serves a pre-purchase
	// /health probe, UserCreds.AnyTLSPassword arriving empty is the
	// safety interlock, and MissingFamilyCredentials is what turns that
	// into a warning the operator actually sees.
	//
	// Deliberately NO version fallback in Has(): the capability rides
	// the pinned artifact, and inferring it from mgmt_api_version is
	// exactly how a box comes to claim a family it does not serve.
	CapAnyTLSInbound = "anytls-inbound"

	// CapTUICUsers: this relay's mgmt binary knows how to add, rotate
	// and remove tuic users, and echoes the recipient's uuid+password
	// pair on /users/provision when the box really carries a tuic-in
	// row for them.
	//
	// READ THE VERB, NOT THE FAMILY. Unlike shadowsocks and anytls, this
	// token does NOT mean "this relay serves tuic". tuic is the first
	// opt-in family: the inbound is written by cloud-init only when the
	// toolbox profile selected it, and 8443/udp is opened in both
	// firewalls only for those relays. So the two facts are independent,
	// and the failure they guard against is the combination — a FRESH
	// relay whose cloud-init has the tuic-in inbound and whose pinned
	// mgmt artifact predates the family. That binary answers
	// /users/provision with a 200 and adds no tuic row.
	//
	// Same division of labour as the two tokens above: this one serves
	// a pre-purchase /health probe (the artifact pin in
	// cloudinit/artifacts.go is stale), UserCreds.TUICUUID/TUICPassword
	// arriving empty is the safety interlock, and
	// MissingFamilyCredentials is the provision-time warning.
	// Deliberately NO version fallback in Has(): the capability rides
	// the pinned artifact.
	CapTUICUsers = "tuic-users"
)

// MgmtAPIVersionSplitRotation is the /health `mgmt_api_version` at
// which BOTH split verbs above are part of the contract. It exists so a
// box that reports a version but forgets to enumerate the verb list is
// still usable; a box that enumerates is authoritative either way.
// Bumping this is a wire change and needs both ends moved together.
const MgmtAPIVersionSplitRotation = 2

// BoxCapabilities is GET /health's body.
//
// Every field is optional on purpose: this struct must decode a
// pre-Step-7 box's `{"ok":true}` without error, because that response
// IS the signal we are reading.
type BoxCapabilities struct {
	OK bool `json:"ok"`
	// MgmtAPIVersion is 0 on any box that predates the advertisement.
	MgmtAPIVersion int `json:"mgmt_api_version,omitempty"`
	// Capabilities is the verb set. nil on a pre-Step-7 box.
	Capabilities []string `json:"capabilities,omitempty"`

	// CapabilityNotes is the box's own diagnostic text about a
	// capability it is NOT advertising, and it must be declared here or
	// it does not exist: encoding/json drops unknown keys silently, and
	// this project has already shipped one inert feature exactly that
	// way (cover_sni and mux_inbound were echoed by the box and
	// swallowed by the struct in the middle).
	//
	// It earns its place because two completely different situations
	// present identically as a missing token. "This binary is too old"
	// is fixed by a re-release; "this binary is fine but was launched
	// without CAP_NET_ADMIN" is fixed by a unit-file change and a
	// reprovision. An operator who cannot SSH into the relay has no
	// other way to tell them apart, and the generic remediation sends
	// them to the wrong one. Rendered verbatim in the refusal.
	CapabilityNotes []string `json:"capability_notes,omitempty"`
}

// Has reports whether the box advertises the named capability.
//
// Two positive signals, either sufficient: an explicit token in the
// verb list, or an api_version at/after the version that defines the
// verb. Everything else — empty list, unparsable body, old box — is
// false. There is deliberately no "probably fine" branch.
func (b *BoxCapabilities) Has(name string) bool {
	if b == nil {
		return false
	}
	for _, c := range b.Capabilities {
		if strings.EqualFold(strings.TrimSpace(c), name) {
			return true
		}
	}
	switch name {
	case CapRotateCredentialsScoped, CapRotateTLSScoped:
		return b.MgmtAPIVersion >= MgmtAPIVersionSplitRotation
	}
	// CapBindAddress deliberately has NO version fallback: it depends on
	// the box's runtime privileges (CAP_NET_ADMIN), not only on which
	// binary is installed, so only the box's own probe can answer it.
	// See MgmtAPIVersionAddressBinding.
	return false
}

// Advertised renders the verb set for an error message, sorted so the
// operator-visible text is stable.
func (b *BoxCapabilities) Advertised() string {
	if b == nil || len(b.Capabilities) == 0 {
		return "(none)"
	}
	out := append([]string(nil), b.Capabilities...)
	sort.Strings(out)
	return strings.Join(out, ",")
}

// ErrCapabilityUnsupported is returned when the relay's in-box mgmt
// binary predates the operation the caller asked for. It is a terminal
// condition for this relay, not a retryable error: the fix is a human
// re-release of the pinned artifact (or a reprovision), so callers
// should surface the message and stop rather than back off and retry.
var ErrCapabilityUnsupported = errors.New("mgmt: relay software too old for this operation")

// remediation is the one sentence an operator can act on. Kept here so
// the CLI, the Rust bridge and the UI all quote the same words.
const remediation = "this relay's software is too old to rotate in place; " +
	"reprovision the relay, or re-release daal-relay-mgmt (rebuild, re-sign, re-upload, " +
	"bump the hash pin in publisher/deploy/cloudinit/artifacts.go) and reprovision"

// bindRemediation is the same sentence for the address-binding verbs.
// It has to differ, because "rotate in place" describes neither what the
// operator asked for nor what they lose: an L3 on a relay this old
// cannot work at all, since a floating IP that the guest OS never
// configures is an address the box does not answer on. The operator must
// know the swap was REFUSED rather than half-applied, and that the fix
// is a human release step and not a retry.
const bindRemediation = "this relay's software cannot configure a floating IP on its own interface, so an address " +
	"swapped onto it would route to the server and never be answered; nothing was changed. " +
	"Re-release daal-relay-mgmt (rebuild, re-sign, re-upload, bump the hash pin in " +
	"publisher/deploy/cloudinit/artifacts.go — and rebuild libdaal_deploy.so with it) and reprovision this relay. " +
	"BOTH halves are needed: the capability also depends on the service unit granting CAP_NET_ADMIN, which only a " +
	"reprovision (new cloud-init) changes. Or use reprovision now: a rebuilt server gets a new address without needing this endpoint"

// UnsupportedCapabilityError renders the standard refusal for a relay
// that does not advertise the named capability.
//
// Exported because the refusal has to be issued from two places. The
// interlock below fires INSIDE a firewall window, immediately before a
// mutating call. The L3 assign path has to refuse EARLIER than that —
// before it reserves an address or attaches anything — because attaching
// an address the box can never answer on is the failure this whole wave
// exists to prevent, and an operator should not be billed for a reserved
// address to learn it. One renderer means both refusals read alike.
func UnsupportedCapabilityError(caps *BoxCapabilities, name string) error {
	fix := remediation
	if name == CapBindAddress {
		fix = bindRemediation
	}
	// The box's own account of WHY comes first, ahead of our generic
	// remediation. It is the only thing that distinguishes "too old"
	// from "right binary, wrong privileges", and those have different
	// fixes.
	said := ""
	if caps != nil && len(caps.CapabilityNotes) > 0 {
		said = " The relay says: " + strings.Join(caps.CapabilityNotes, "; ") + "."
	}
	return fmt.Errorf("%w: relay advertises %s (mgmt_api_version=%d) and not %q.%s %s",
		ErrCapabilityUnsupported, caps.Advertised(), caps.MgmtAPIVersion, name, said, fix)
}

// Capabilities fetches GET /health and reads the box's advertisement.
//
// Reachability failures are errors; a reachable box that says nothing
// is NOT an error — it is a valid, meaningful answer ("I am old"), and
// conflating the two would turn a network blip into "reprovision your
// relay". A 200 whose body is not JSON is read the same way: reachable,
// silent, therefore old.
//
// The mgmt port is firewalled, so this call only succeeds inside an
// ephemeral firewall window; flow.go always probes inside the window it
// already opened.
func (c *Client) Capabilities(ctx context.Context, rec *provider.OperatorRecord) (*BoxCapabilities, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.boxURL(rec, "/health"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mgmt: health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mgmt: health %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("mgmt: health read: %w", err)
	}
	var got BoxCapabilities
	if err := json.Unmarshal(raw, &got); err != nil {
		// Reachable but unreadable: treat as "advertises nothing".
		return &BoxCapabilities{}, nil
	}
	return &got, nil
}

// requireCapability is the interlock every in-place rotation runs
// before it sends anything mutating. It fails closed on both the
// "advertises something else" and the "cannot tell" branches.
func requireCapability(ctx context.Context, cli *Client, rec *provider.OperatorRecord, name string) error {
	caps, err := cli.Capabilities(ctx, rec)
	if err != nil {
		// Cannot tell ⇒ do not fire. An unreachable box is also not a
		// box we should be rotating.
		return fmt.Errorf("mgmt: capability probe failed (refusing to rotate a box whose software we cannot identify): %w", err)
	}
	if !caps.Has(name) {
		return UnsupportedCapabilityError(caps, name)
	}
	return nil
}

// MissingFamilyCredentials reports which of the relay's OWN candidate
// families came back from /users/provision (or /rotate-credentials)
// with no credential.
//
// WHY THIS EXISTS, AND WHY IT IS NOT THE CAPABILITY TOKENS.
//
// CapShadowsocks2022, CapAnyTLSInbound and CapTUICUsers are asserted by
// the box on GET /health. Their doc comments used to promise an "early
// warning before you rent a server" — and nothing consulted them, so
// the warning did not exist and the operator's first notice was a
// missing route at pack time. This function is the warning made real,
// from data the provision call already has in hand: no extra request,
// no second firewall window, and it compares against the relay's actual
// candidate set rather than a version number.
//
// The tokens remain the right instrument for a PRE-PURCHASE probe (they
// answer "is the pinned artifact current?" without provisioning
// anything), and the empty credential remains the safety interlock that
// makes the pack renderer refuse the route. Three instruments, three
// jobs; the one that was missing was this one.
//
// Returns family names in candidate order. Empty means every family
// this relay offers reported a credential.
func MissingFamilyCredentials(rec *provider.OperatorRecord, creds *UserCreds) []string {
	if rec == nil || creds == nil {
		return nil
	}
	var out []string
	for _, c := range rec.Candidates {
		switch c.Family {
		case "shadowsocks":
			if creds.SSPassword == "" {
				out = append(out, c.Family)
			}
		case "anytls":
			if creds.AnyTLSPassword == "" {
				out = append(out, c.Family)
			}
		case "tuic":
			if creds.TUICUUID == "" || creds.TUICPassword == "" {
				out = append(out, c.Family)
			}
		}
	}
	return out
}

// StaleArtifactHint is the sentence to print beside
// MissingFamilyCredentials. It names the one action that fixes it,
// because "the relay does not serve X" is not actionable on its own and
// the fix is genuinely non-obvious: the mgmt binary is a hash-pinned
// artifact and cloud-init has no upgrade path.
const StaleArtifactHint = "the relay's daal-relay-mgmt binary predates the family: " +
	"rebuild, re-sign, re-upload, bump the hash pin in " +
	"publisher/deploy/cloudinit/artifacts.go, and provision a FRESH relay " +
	"(there is no in-place upgrade for cloud-init)"
