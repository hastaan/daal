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
		return fmt.Errorf("%w: relay advertises %s (mgmt_api_version=%d) and not %q — %s",
			ErrCapabilityUnsupported, caps.Advertised(), caps.MgmtAPIVersion, name, remediation)
	}
	return nil
}
