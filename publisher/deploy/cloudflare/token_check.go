package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// The token Daal asks for (docs/optional-addons-plan.md §2.5): exactly
// five zone permissions, Zone resources = the one zone, no account and
// no user permission.
var RequiredPermissions = []string{
	"Zone — Zone — Read",
	"Zone — DNS — Edit",
	"Zone — SSL and Certificates — Edit",
	"Zone — Zone Settings — Edit",
	"Zone — Origin Rules — Edit",
}

// Token check verdicts. Only VerdictOK may be stored.
const (
	VerdictOK                = "ok"
	VerdictInvalid           = "invalid"            // not a working, active token
	VerdictNoZone            = "no_zone"            // sees no active zone
	VerdictZoneNotVisible    = "zone_not_visible"   // the zone asked for is not the one it sees
	VerdictTooBroad          = "too_broad"          // more than one zone, or more than the five permissions
	VerdictMissingPermission = "missing_permission" // one of the five is absent
)

// TokenCheck is what `daal-deploy cdn-token-check` prints. It names no
// secret: the token id is Cloudflare's public handle, not the token.
type TokenCheck struct {
	Verdict     string   `json:"verdict"`
	TokenID     string   `json:"token_id,omitempty"`
	TokenStatus string   `json:"token_status,omitempty"`
	Zones       []Zone   `json:"zones"`
	Missing     []string `json:"missing,omitempty"`
	Extra       []string `json:"extra,omitempty"`
	// Unproven lists what a read probe cannot show: that each Edit
	// permission is Edit and not only Read. A token short of an Edit
	// fails at the first write of cdn-provision, which rolls back.
	Unproven []string `json:"unproven,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// probe is one GET whose answer stands for one permission.
type probe struct {
	Permission string
	Path       string
}

func zonePath(zoneID, rest string) string {
	return "/zones/" + url.PathEscape(zoneID) + rest
}

func originEntrypointPath(zoneID string) string {
	return zonePath(zoneID, "/rulesets/phases/http_request_origin/entrypoint")
}

// requiredProbes are reads each of the five permissions allows. Zone
// Read is proven by the zone listing itself. A 404 counts as allowed:
// it is how Cloudflare answers "no origin ruleset yet" to a token that
// may read one.
func requiredProbes(z Zone) []probe {
	return []probe{
		{"Zone — DNS", zonePath(z.ID, "/dns_records?per_page=1")},
		{"Zone — SSL and Certificates", zonePath(z.ID, "/origin_tls_client_auth/settings")},
		{"Zone — SSL and Certificates", "/certificates?zone_id=" + url.QueryEscape(z.ID)},
		{"Zone — Zone Settings", zonePath(z.ID, "/settings/ssl")},
		{"Zone — Origin Rules", originEntrypointPath(z.ID)},
	}
}

// forbiddenProbes are reads none of the five allows. Any of them
// answering 2xx means the token can do more than Daal needs. The list
// targets the shapes that matter most on a phone: anything that bills
// (registrar, billing), runs code (Workers), manages people or tokens,
// or reaches past this zone's DNS-and-TLS surface.
//
// It cannot be complete: Cloudflare has no call that lists a token's
// own permissions without a further permission (API Tokens Read, which
// is itself on this list). GATE C-1 confirms these paths on the real
// dashboard.
func forbiddenProbes(z Zone) []probe {
	ps := []probe{
		{"User — User Details", "/user"},
		{"User — API Tokens", "/user/tokens?per_page=1"},
		{"Zone — Workers Routes", zonePath(z.ID, "/workers/routes")},
		{"Zone — Firewall Services", zonePath(z.ID, "/firewall/access_rules/rules?per_page=1")},
		{"Zone — Page Rules", zonePath(z.ID, "/pagerules")},
	}
	// Deliberately not probed: GET /accounts. It can answer 200 with
	// an empty list for a token that has no account permission, so a
	// 2xx there proves nothing and would refuse a correct token.
	if z.AccountID != "" {
		acc := "/accounts/" + url.PathEscape(z.AccountID)
		ps = append(ps,
			probe{"Account — Workers Scripts", acc + "/workers/scripts"},
			probe{"Account — Registrar", acc + "/registrar/domains"},
			probe{"Account — Billing", acc + "/billing/profile"},
			probe{"Account — Members", acc + "/members?per_page=1"},
		)
	}
	return ps
}

// CheckToken decides whether a pasted token is exactly what Daal asks
// for. wantZone, when non-empty, is the zone the publisher said they
// picked; the token must see that zone and no other.
//
// Reads only. The order is cheap-first, and the first refusal stops:
// a token that sees two zones is refused before anything else is
// probed with it.
func CheckToken(ctx context.Context, cf CFClient, cfToken []byte, wantZone string) (TokenCheck, error) {
	out := TokenCheck{Zones: []Zone{}}
	if len(cfToken) == 0 {
		out.Verdict = VerdictInvalid
		out.Notes = "empty token"
		return out, nil
	}
	st, err := cf.VerifyToken(ctx, cfToken)
	if err != nil {
		if isAuthError(err) {
			out.Verdict = VerdictInvalid
			out.Notes = "Cloudflare does not accept this token"
			return out, nil
		}
		return out, scrub(err, cfToken)
	}
	out.TokenID, out.TokenStatus = st.ID, st.Status
	if st.Status != "active" {
		out.Verdict = VerdictInvalid
		out.Notes = "token status is " + st.Status
		return out, nil
	}

	zones, err := cf.ListZones(ctx, cfToken)
	if err != nil {
		return out, scrub(err, cfToken)
	}
	out.Zones = zones
	switch {
	case len(zones) == 0:
		out.Verdict = VerdictNoZone
		out.Notes = "the token sees no zone; pick the zone under Zone Resources"
		return out, nil
	case len(zones) > 1:
		out.Verdict = VerdictTooBroad
		out.Extra = append(out.Extra, fmt.Sprintf("Zone Resources: %d zones (must be the one zone)", len(zones)))
		return out, nil
	}
	z := zones[0]
	if wantZone != "" && !strings.EqualFold(strings.TrimSuffix(wantZone, "."), z.Name) {
		out.Verdict = VerdictZoneNotVisible
		out.Notes = "the token sees " + z.Name + ", not " + wantZone
		return out, nil
	}
	if z.Status != "active" {
		out.Verdict = VerdictNoZone
		out.Notes = "zone " + z.Name + " is " + z.Status + ", not active yet"
		return out, nil
	}

	for _, p := range forbiddenProbes(z) {
		r, err := cf.ProbeRead(ctx, cfToken, p.Path)
		if err != nil {
			return out, scrub(err, cfToken)
		}
		if r == ProbeAllowed {
			out.Extra = appendOnce(out.Extra, p.Permission)
		}
	}
	if len(out.Extra) > 0 {
		out.Verdict = VerdictTooBroad
		return out, nil
	}
	for _, p := range requiredProbes(z) {
		r, err := cf.ProbeRead(ctx, cfToken, p.Path)
		if err != nil {
			return out, scrub(err, cfToken)
		}
		if r == ProbeDenied {
			out.Missing = appendOnce(out.Missing, p.Permission)
		}
	}
	if len(out.Missing) > 0 {
		out.Verdict = VerdictMissingPermission
		return out, nil
	}
	out.Verdict = VerdictOK
	out.Unproven = []string{
		"DNS, SSL and Certificates, Zone Settings and Origin Rules are Edit, not only Read (shown by the first write)",
	}
	return out, nil
}

func appendOnce(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// authError marks a 401/403 from the API.
type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

func isAuthError(err error) bool {
	var ae *authError
	return errors.As(err, &ae)
}

// scrub removes every occurrence of the token from an error's text. The
// live client never puts the token in an error; this is the second
// fence, applied at every place an error leaves this package with a
// token in scope.
func scrub(err error, token []byte) error {
	if err == nil || len(token) == 0 {
		return err
	}
	msg := err.Error()
	t := string(token)
	if !strings.Contains(msg, t) {
		return err
	}
	return &scrubbedError{msg: strings.ReplaceAll(msg, t, "[token]"), inner: err}
}

type scrubbedError struct {
	msg   string
	inner error
}

func (e *scrubbedError) Error() string { return e.msg }

// Is lets errors.Is see a sentinel inside without exposing the
// original text through Unwrap.
func (e *scrubbedError) Is(target error) bool { return errors.Is(e.inner, target) }

// As lets errors.As find a typed error inside (authError, statusError)
// for the same reason.
func (e *scrubbedError) As(target any) bool { return errors.As(e.inner, target) }
