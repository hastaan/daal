package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func init() { Ops["caps"] = opCaps }

// capProof says how the rig decides whether a relay can really do what a
// /health capability token claims. Each proof reads checks recorded
// EARLIER IN THE SAME RUN — by the matrix or by another op — and reports
// worked / did not work / not exercised.
type capProof struct {
	// Token is the literal the relay advertises (a wire contract between
	// cmd/daal-relay-mgmt and publisher/deploy/mgmt).
	Token string
	// What a human would call it.
	Claim string
	// Needs: which op or family must have run for there to be evidence.
	Needs string
	// Decide returns ("pass"|"fail"|"", evidence). "" = not exercised.
	Decide func(rc *RunCtx) (string, []string)
}

// allOK folds a set of named checks: every one present and ok → pass; any
// present and not ok → fail; none present → "".
func (rc *RunCtx) allOK(phase, family string, checks ...string) (string, []string) {
	var seen, bad []string
	for _, want := range checks {
		for _, c := range rc.R.checksWhere(func(c Check) bool { return c.Phase == phase && c.Family == family && c.Check == want }) {
			seen = append(seen, fmt.Sprintf("%s/%s=%s", phase, c.Check, c.Got))
			if !c.OK {
				bad = append(bad, c.Check)
			}
		}
	}
	switch {
	case len(seen) == 0:
		return "", nil
	case len(bad) > 0 || len(seen) < len(checks):
		return Fail, seen
	}
	return Pass, seen
}

// familyCarries: did the family carry verified bytes in the matrix? Only
// judged when the relay was provisioned to serve it.
func familyCarries(family string) func(rc *RunCtx) (string, []string) {
	return func(rc *RunCtx) (string, []string) {
		if !contains(rc.Serve, family) {
			return "", nil // the token is about the binary, not about this relay's profile
		}
		hits := rc.R.checksWhere(func(c Check) bool { return c.Phase == "family" && c.Family == family && c.Check == "tunnel" })
		if len(hits) == 0 {
			// Not under test, but served: fall back to "is anything listening".
			hits = rc.R.checksWhere(func(c Check) bool { return c.Phase == "mint" && c.Family == family && c.Check == "relay.listens" })
			if len(hits) == 0 {
				return "", nil
			}
		}
		c := hits[0]
		if c.Got == Skipped {
			return "", nil
		}
		// "Carried bytes" is the observation, whatever the scenario
		// expected: under a censor that blocks the family there is no
		// evidence either way.
		if c.Got == Blocked && c.Expect == Blocked {
			return "", nil
		}
		return got(c.Got == Pass, Pass, Fail), []string{fmt.Sprintf("%s/%s %s=%s", c.Phase, c.Family, c.Check, c.Got)}
	}
}

var capProofs = []capProof{
	{"rotate-credentials-scoped", "rotates ONE named recipient, touching nobody else and no box-wide key", "--ops l1",
		func(rc *RunCtx) (string, []string) {
			return rc.allOK("op:l1", "", "verb.rotate-credentials.r21", "answer.every_secret_changed", "answer.box_material_unmoved",
				"box.old_secrets_gone", "box.only_the_named_recipient_changed")
		}},
	{"rotate-tls-scoped", "moves the cover identity only, leaving keys and credentials alone", "--ops l2",
		func(rc *RunCtx) (string, []string) {
			return rc.allOK("op:l2", "", "verb.rotate-tls", "record.cover_host_moved", "box.cover_host_agrees_with_record", "box.no_key_no_credential_moved")
		}},
	{"bind-address", "configures a routed address on its interface, persists it, and can remove it again", "--ops l3",
		func(rc *RunCtx) (string, []string) {
			return rc.allOK("op:l3", "", "verb.assign-fip", "box.address_bound_and_persisted", "verb.floating-ip-release", "released.record_box_and_account_clean")
		}},
	{"shadowsocks-2022", "creates the ss-in inbound and its per-recipient keys", "the shadowsocks family under test", familyCarries("shadowsocks")},
	{"anytls-inbound", "creates the anytls-in inbound and its per-recipient passwords", "the anytls family under test", familyCarries("anytls")},
	{"tuic-users", "adds, rotates and removes tuic users", "the tuic family under test", familyCarries("tuic")},
}

// opCaps: capability honesty. The relay's /health names what its
// management daemon can do, and the publisher decides what to attempt —
// and what to refuse before touching anything — from that list alone. So
// the list has to be TRUE in both directions:
//
//	advertised  ⇒ it works here   (else the publisher walks into a failure
//	                               mid-operation, the one place the
//	                               fail-closed design exists to avoid)
//	it works    ⇒ advertised      (else the publisher refuses, or warns
//	                               about, something that would have worked)
//
// One check per token the rig knows, judged against what this same run
// OBSERVED. A token with no evidence in this run is `skipped`, with the
// op or family that would produce it. A token the relay advertises that
// the rig has no proof for is a failure of the RIG, reported as such, so
// a new capability cannot arrive unexamined.
//
// Run it last: `--ops l1,l2,l3,caps`, or `--ops lifecycle`.
func opCaps(rc *RunCtx) {
	const phase = "op:caps"
	t0 := time.Now()
	caps, version, raw, err := rc.Health()
	if !rc.R.Add("", phase, "health", Pass, got(err == nil, Pass, Fail), errStr(err), map[string]any{"capabilities": caps, "mgmt_api_version": version, "raw": strings.TrimSpace(raw)}, t0) {
		return
	}
	known := map[string]bool{}
	for _, p := range capProofs {
		known[p.Token] = true
		t0 = time.Now()
		advertised := contains(caps, p.Token)
		outcome, evidence := p.Decide(rc)
		ev := map[string]any{"advertised": advertised, "observed": evidence, "claim": p.Claim}
		id := "honest." + p.Token
		switch {
		case outcome == "":
			rc.R.Add("", phase, id, Skipped, Skipped,
				fmt.Sprintf("advertised=%v, but nothing in this run exercised it (needs %s)", advertised, p.Needs), ev, t0)
		case advertised && outcome == Pass:
			rc.R.Add("", phase, id, Pass, Pass, "", ev, t0)
		case !advertised && outcome == Fail:
			// Honest absence: it says it cannot, and it cannot.
			ev["honestly_absent"] = true
			rc.R.Add("", phase, id, Pass, Pass, "", ev, t0)
		case advertised && outcome == Fail:
			rc.R.Add("", phase, id, Pass, Fail,
				fmt.Sprintf("the relay advertises %q (%s) and it did not work here: %s", p.Token, p.Claim, strings.Join(evidence, ", ")), ev, t0)
		default: // !advertised && outcome == Pass
			rc.R.Add("", phase, id, Pass, Fail,
				fmt.Sprintf("the relay does NOT advertise %q, yet it works here (%s): a publisher that believes /health refuses or warns about something that would have worked", p.Token, strings.Join(evidence, ", ")), ev, t0)
		}
	}
	t0 = time.Now()
	var unknown []string
	for _, c := range caps {
		if !known[c] {
			unknown = append(unknown, c)
		}
	}
	sort.Strings(unknown)
	rc.R.Add("", phase, "every_advertised_token_has_a_proof", Pass, got(len(unknown) == 0, Pass, Fail),
		got(len(unknown) == 0, "", "the relay advertises capabilities this rig cannot judge — add a capProof in ops_caps.go: "+strings.Join(unknown, ", ")), nil, t0)

	// The version number is the second signal the publisher accepts for
	// the two rotation verbs (and for nothing else).
	t0 = time.Now()
	scoped := contains(caps, "rotate-credentials-scoped") && contains(caps, "rotate-tls-scoped")
	rc.R.Add("", phase, "version_agrees_with_tokens", Pass, got((version >= 2) == scoped, Pass, Fail),
		fmt.Sprintf("mgmt_api_version=%d but scoped rotation tokens present=%v: the publisher treats either signal as sufficient, so they must agree", version, scoped),
		map[string]any{"mgmt_api_version": version}, t0)
}
