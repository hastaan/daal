package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func init() { Ops["mgmtauth"] = opMgmtAuth }

// opMgmtAuth: what the relay's management API does when the request is
// NOT one the publisher would send. Hand-built requests (mgmtprobe.go),
// sent from past both firewalls, each aimed at a route that would change
// something if it were honoured.
//
//	positive control   a correctly signed request IS honoured — otherwise
//	                   every "refused" below could be a broken probe
//	unsigned           no Authorization header
//	wrong scheme       a valid token under "Bearer"
//	garbage            a token that is not a token
//	stranger's key     well-formed, signed by a key the relay never saw
//	wrong op           the publisher's own signature, for a different
//	                   endpoint (a users-list token presented to
//	                   /users/revoke)
//	stale / future     the publisher's signature, outside the time window
//	another body       the publisher's signature for THIS endpoint, made
//	                   for a different body (a token is for one request:
//	                   method, path and body are under the signature)
//	another relay      the publisher's signature for THIS request, made
//	                   for a different relay (one publisher key can be
//	                   trusted by several; the relay's own name is under
//	                   the signature)
//	v1 token           the retired token shape, correctly signed by the
//	                   publisher: it did not sign the request
//	replay             a token the relay has already honoured once,
//	                   presented again with a DIFFERENT body: for an
//	                   address verb, and for /users/revoke (the same token
//	                   aimed at a second recipient)
//	negative control   after all of it, the box's config is byte-identical
//	                   to what the legitimate requests alone produce, and
//	                   the recipient the forgeries aimed at still connects
//
// The victim of every forged request is recipient r41, created here; r42
// is who the replay tries to revoke.
func opMgmtAuth(rc *RunCtx) {
	const phase = "op:mgmtauth"
	const victim, second = "r41", "r42"
	victimPack, ok := rc.MintRecipient(victim, phase)
	if !ok {
		return
	}
	if _, ok := rc.MintRecipient(second, phase); !ok {
		return
	}
	// A third, to be revoked LEGITIMATELY by the token that is then replayed.
	if _, ok := rc.MintRecipient("r43", phase); !ok {
		return
	}
	rc.MgmtWindowClosed(phase)
	sum := func() string {
		h := sha256.Sum256([]byte(rc.BoxSingboxConfig()))
		return hex.EncodeToString(h[:])
	}
	cfgBefore := sum()
	revoke := `{"name":"` + victim + `"}`

	t0 := time.Now()
	ans, err := rc.MgmtProbe([]MgmtReq{
		{ID: "control.signed", Method: "GET", Path: "/users/list", Token: "sign", Op: "users-list"},
		{ID: "unsigned", Method: "POST", Path: "/users/revoke", Body: revoke},
		{ID: "wrong_scheme", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", Scheme: "Bearer"},
		{ID: "garbage", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "raw:not-a-token"},
		{ID: "empty_signature", Method: "POST", Path: "/users/revoke", Body: revoke, Token: fmt.Sprintf("raw:v2:00112233445566778899aabbccddeeff:%d:users-revoke:", time.Now().Unix())},
		{ID: "signed_for_another_body", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", SignBody: `{"name":"r43"}`},
		{ID: "signed_for_no_body", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", SignBody: " "},
		{ID: "signed_for_another_relay", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", SignRelay: otherRelayFingerprint(rc.Rec.MgmtTLSFingerprint)},
		{ID: "v1_token", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", Format: "v1"},
		{ID: "stranger_key", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Key: "stranger", Op: "users-revoke"},
		{ID: "wrong_op", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-list"},
		{ID: "wrong_op.rotate_as_revoke", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "rotate-credentials"},
		{ID: "stale", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", TSOffset: -400},
		{ID: "future", Method: "POST", Path: "/users/revoke", Body: revoke, Token: "sign", Op: "users-revoke", TSOffset: 400},
		{ID: "unsigned.rotate_tls", Method: "POST", Path: "/rotate-tls", Body: `{}`},
		{ID: "unsigned.bind_address", Method: "POST", Path: "/bind-address", Body: `{"ip":"` + FloatingIPPool[2] + `"}`},
	})
	if err != nil && len(ans) == 0 {
		rc.R.Add("", phase, "probe", Pass, Fail, err.Error(), nil, t0)
		return
	}
	// accepted: the relay let the request past authentication. Anything
	// but 401/403 counts — a 400 for a bad body means the token was
	// honoured.
	verdict := func(a MgmtAns) string {
		switch {
		case a.Status == 0:
			return Fail
		case a.Status == 401 || a.Status == 403:
			return Refused
		}
		return Pass
	}
	add := func(id, expect string) {
		a := ans[id]
		rc.R.Add("", phase, id, expect, verdict(a), strings.TrimSpace(a.Body)+a.Error, map[string]any{"http_status": a.Status}, t0)
	}
	a := ans["control.signed"]
	rc.R.Add("", phase, "control.signed_request_honoured", Pass, got(a.Status == 200 && strings.Contains(a.Body, `"`+victim+`"`), Pass, Fail),
		strings.TrimSpace(a.Body)+a.Error, map[string]any{"http_status": a.Status}, t0)
	for _, id := range []string{"unsigned", "wrong_scheme", "garbage", "empty_signature", "signed_for_another_body", "signed_for_no_body", "signed_for_another_relay", "v1_token", "stranger_key", "wrong_op", "wrong_op.rotate_as_revoke",
		"stale", "future", "unsigned.rotate_tls", "unsigned.bind_address"} {
		add(id, Refused)
	}

	// None of the refused requests may have changed anything.
	t0 = time.Now()
	rc.R.Add("", phase, "refused_requests_changed_nothing", Pass, got(sum() == cfgBefore && !contains(rc.relayAddrs(), FloatingIPPool[2]), Pass, Fail),
		"the box's sing-box config or addresses changed while only refused requests were sent", nil, t0)

	// ---- replay ------------------------------------------------------
	//
	// (a) an address verb. The first use is refused by address
	// VALIDATION (a benchmarking-range address the relay will not bind),
	// which is after authentication — so the token has been honoured
	// once and nothing was configured. The second use must be refused as
	// a replay even though it now names a bindable address.
	t0 = time.Now()
	ans, err = rc.MgmtProbe([]MgmtReq{
		{ID: "addr.first", Method: "POST", Path: "/bind-address", Body: `{"ip":"198.18.0.99"}`, Token: "sign", Op: "bind-address"},
		{ID: "addr.replay", Method: "POST", Path: "/bind-address", Body: `{"ip":"` + FloatingIPPool[2] + `"}`, Token: "reuse:addr.first"},
	})
	if err != nil && len(ans) == 0 {
		rc.R.Add("", phase, "replay.bind-address", Refused, Fail, err.Error(), nil, t0)
	} else if contains(rc.healthCaps(), "bind-address") {
		first := ans["addr.first"]
		rc.R.Add("", phase, "replay.bind-address.first_use_authenticated", Pass, got(first.Status == 400, Pass, Fail),
			fmt.Sprintf("expected the first use to pass authentication and be refused by address validation (400); got %d %s", first.Status, strings.TrimSpace(first.Body)),
			map[string]any{"http_status": first.Status}, t0)
		a := ans["addr.replay"]
		bound := contains(rc.relayAddrs(), FloatingIPPool[2])
		rc.R.Add("", phase, "replay.bind-address", Refused, got(bound, Pass, verdict(a)), strings.TrimSpace(a.Body)+a.Error,
			map[string]any{"http_status": a.Status, "address_bound": bound}, t0)
		if bound { // do not leave it there
			_, _ = rc.MgmtProbe([]MgmtReq{{ID: "cleanup", Method: "POST", Path: "/unbind-address", Body: `{"ip":"` + FloatingIPPool[2] + `"}`, Token: "sign", Op: "unbind-address"}})
		}
	} else {
		rc.R.Add("", phase, "replay.bind-address", Skipped, Skipped,
			"this relay's daal-relay-mgmt does not advertise bind-address (run with --mgmt=tree)", map[string]any{"http_status": ans["addr.first"].Status}, t0)
	}

	// (b) a recipient verb. The token is used once, legitimately, to
	// revoke r43 — then presented again naming a recipient the publisher
	// never asked to revoke.
	t0 = time.Now()
	ans, err = rc.MgmtProbe([]MgmtReq{
		{ID: "revoke.first", Method: "POST", Path: "/users/revoke", Body: `{"name":"r43"}`, Token: "sign", Op: "users-revoke"},
		{ID: "revoke.replay", Method: "POST", Path: "/users/revoke", Body: `{"name":"` + second + `"}`, Token: "reuse:revoke.first"},
		{ID: "list", Method: "GET", Path: "/users/list", Token: "sign", Op: "users-list"},
		{ID: "list.replay", Method: "GET", Path: "/users/list", Token: "reuse:list"},
	})
	if err != nil && len(ans) == 0 {
		rc.R.Add("", phase, "replay.users-revoke", Refused, Fail, err.Error(), nil, t0)
		return
	}
	first := ans["revoke.first"]
	rc.R.Add("", phase, "replay.users-revoke.first_use_honoured", Pass, got(first.Status == 200 && !strings.Contains(ans["list"].Body, `"r43"`), Pass, Fail),
		strings.TrimSpace(first.Body)+first.Error, map[string]any{"http_status": first.Status}, t0)
	a = ans["revoke.replay"]
	secondGone := !strings.Contains(ans["list"].Body, `"`+second+`"`)
	rc.R.Add("", phase, "replay.users-revoke", Refused, got(secondGone, Pass, verdict(a)),
		got(secondGone, "a token already used to revoke r43 was honoured a second time and revoked "+second+", whom the publisher never named: "+strings.TrimSpace(a.Body), strings.TrimSpace(a.Body)+a.Error),
		map[string]any{"http_status": a.Status, second + "_still_on_relay": !secondGone}, t0)
	// The read-only verb is replayable ON PURPOSE (a GET may be re-sent
	// by the HTTP transport with the same token); pinned so a change
	// either way is seen.
	a = ans["list.replay"]
	rc.R.Add("", phase, "replay.users-list.readonly_stays_replayable", Pass, verdict(a), strings.TrimSpace(a.Body)+a.Error, map[string]any{"http_status": a.Status}, t0)

	// ---- negative control: the forgeries' victim is untouched ---------
	for _, f := range rc.liveFamilies(phase) {
		rc.sub(f, phase, "victim", victimPack, Pass)
		break // one family is enough: this asserts the roster, not a transport
	}
	t0 = time.Now()
	lv := rc.Pub.UsersList(rc.Ctx)
	rc.R.Add("", phase, "victim_still_on_roster", Pass, got(lv.OK() && strings.Contains(lv.Stdout, `"`+victim+`"`) && strings.Contains(lv.Stdout, `"r1"`), Pass, Fail),
		strings.TrimSpace(lv.Stdout)+" "+lv.Tail(), nil, t0)
	rc.MgmtWindowClosed(phase)
}

// otherRelayFingerprint is a well-formed mgmt TLS fingerprint that is not
// this relay's: the name of a sibling relay a token could have been
// minted for.
func otherRelayFingerprint(own string) string {
	h := sha256.Sum256([]byte("another relay than " + own))
	return hex.EncodeToString(h[:])
}

// healthCaps is Health() for callers that only branch on it.
func (rc *RunCtx) healthCaps() []string {
	caps, _, _, _ := rc.Health()
	return caps
}
