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
// no user permission. Only the five are required: a token with more
// zones or more permissions still works (see the verdicts below).
var RequiredPermissions = []string{
	"Zone — Zone — Read",
	"Zone — DNS — Edit",
	"Zone — SSL and Certificates — Edit",
	"Zone — Zone Settings — Edit",
	"Zone — Origin Rules — Edit",
}

// Token check verdicts. A token is refused only when it cannot do the
// job: not a working token, no zone, or short of one of the five
// permissions. A token that can do more works and is kept, with what it
// can do beyond the five named (VerdictOKBroad); a token that sees
// several zones is asked which one (VerdictPickZone), and the check is
// made again on the zone picked. Only VerdictOK and VerdictOKBroad may
// be stored (TokenCheck.Usable).
const (
	VerdictOK                = "ok"
	VerdictOKBroad           = "ok_broad"           // works; Extra names what it can do beyond the five
	VerdictPickZone          = "pick_zone"          // sees several zones and none was asked for: pick one, check again with it
	VerdictInvalid           = "invalid"            // not a working, active token
	VerdictNoZone            = "no_zone"            // sees no active zone
	VerdictZoneNotVisible    = "zone_not_visible"   // the zone asked for is not one it sees
	VerdictMissingPermission = "missing_permission" // one of the five is absent; Missing names which
)

// TokenCheck is what `daal-deploy cdn-token-check` prints. It names no
// secret: the token id is Cloudflare's public handle, not the token.
type TokenCheck struct {
	Verdict     string `json:"verdict"`
	TokenID     string `json:"token_id,omitempty"`
	TokenStatus string `json:"token_status,omitempty"`
	Zones       []Zone `json:"zones"`
	// Zone is the zone the permissions were checked on, and the one to
	// use: the zone asked for, or the only one the token sees. Empty
	// when no zone was checked (pick_zone, and refusals before it).
	Zone    string   `json:"zone,omitempty"`
	Missing []string `json:"missing,omitempty"`
	Extra   []string `json:"extra,omitempty"`
	// Unproven lists what a read probe cannot show: that each Edit
	// permission is Edit and not only Read. A token short of an Edit
	// fails at the first write of cdn-provision, which rolls back.
	Unproven []string `json:"unproven,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// Usable says whether the token may be kept and used: it is a working
// token on a zone it can do the five things on, whether or not it can
// do more.
func (c TokenCheck) Usable() bool {
	return c.Verdict == VerdictOK || c.Verdict == VerdictOKBroad
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
// answering 2xx means the token can do more than Daal needs: it is not
// refused for that (it works), but the extra is named so the publisher
// can make a narrower key. The list
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
	// 2xx there proves nothing and would warn about a correct token.
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

// CheckToken decides whether a pasted token can do what Daal needs.
// wantZone, when non-empty, is the zone the publisher picked; the token
// must see it, and the permissions are checked on it.
//
// Reads only, cheap first. It stops at the first thing that makes the
// token unusable as it stands (not working, no zone, several zones and
// none picked); past that both lists are filled, so one answer names
// everything to fix: what is missing (refused) and what is extra (kept,
// with the warning).
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
	if len(zones) == 0 {
		out.Verdict = VerdictNoZone
		out.Notes = "the token sees no zone; pick the zone under Zone Resources"
		return out, nil
	}
	want := strings.TrimSuffix(strings.TrimSpace(wantZone), ".")
	var z Zone
	switch {
	case want != "":
		found := false
		for _, c := range zones {
			if strings.EqualFold(c.Name, want) {
				z, found = c, true
				break
			}
		}
		if !found {
			out.Verdict = VerdictZoneNotVisible
			out.Notes = "the token does not see " + want
			return out, nil
		}
	case len(zones) > 1:
		out.Verdict = VerdictPickZone
		out.Notes = fmt.Sprintf("the token sees %d zones; pick one and check again with --zone", len(zones))
		return out, nil
	default:
		z = zones[0]
	}
	if z.Status != "active" {
		out.Verdict = VerdictNoZone
		out.Notes = "zone " + z.Name + " is " + z.Status + ", not active yet"
		return out, nil
	}
	out.Zone = z.Name

	for _, p := range requiredProbes(z) {
		r, err := cf.ProbeRead(ctx, cfToken, p.Path)
		if err != nil {
			return out, scrub(err, cfToken)
		}
		if r == ProbeDenied {
			out.Missing = appendOnce(out.Missing, p.Permission)
		}
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
	switch {
	case len(out.Missing) > 0:
		out.Verdict = VerdictMissingPermission
		return out, nil
	case len(out.Extra) > 0:
		out.Verdict = VerdictOKBroad
	default:
		out.Verdict = VerdictOK
	}
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
