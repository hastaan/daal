package mgmt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"daal/publisher/deploy/provider"
)

// users-renew (publisher-alone wave, contract D2): after a rebuild the
// new server knows none of the people the publisher gave files to. One
// call re-creates them all, inside ONE firewall window and after ONE
// read of the roster, and it is safe to run twice.
//
// The caller (the app) decides per person, from what it knows locally:
//
//	ensure   the person's file exists and was made for THIS server:
//	         leave them alone if the server has them; add them if not.
//	replace  their file was made for another server (or never written):
//	         give them fresh credentials whether or not the server has
//	         them.
//	revoke   the person was removed: make sure the server does not have
//	         them. A revoked name is never provisioned — RenewUsers
//	         refuses a name listed both for revoke and anything else.

// Renew actions requested, and the actions reported back.
const (
	RenewEnsure  = "ensure"
	RenewReplace = "replace"
	RenewRevoke  = "revoke"

	RenewKept        = "kept"
	RenewProvisioned = "provisioned"
	RenewRevoked     = "revoked"
	RenewAbsent      = "absent"
)

// Per-name error codes (closed set).
const (
	RenewErrUnreachable = "unreachable"
	RenewErrRelayFull   = "relay_full"
	RenewErrTooOld      = "too_old"
	RenewErrRefused     = "refused"
	RenewErrOther       = "other"
)

// renewNameRE is the recipient-name syntax the relay itself enforces.
var renewNameRE = regexp.MustCompile(`^r[0-9]{1,12}$`)

// RenewRequest is one name and what to do with it.
type RenewRequest struct {
	Name   string
	Action string // ensure | replace | revoke
}

// RenewResult is what happened to one name. Creds is set only for
// "provisioned" and only travels on stdout.
type RenewResult struct {
	Name      string     `json:"name"`
	Action    string     `json:"action"`
	OK        bool       `json:"ok"`
	ErrorCode string     `json:"error_code"`
	Error     string     `json:"error"`
	Creds     *UserCreds `json:"creds"`
}

// RenewReport is the whole answer.
type RenewReport struct {
	UsersBefore []string      `json:"users_before"`
	Results     []RenewResult `json:"results"`
}

// ErrRenewUsage is a request RenewUsersWithFW refuses before opening
// anything (bad name, unknown action, a name listed twice).
var ErrRenewUsage = errors.New("mgmt: users-renew: bad request")

// ErrRelayRosterTooOld means the relay's management service has no
// /users/list, so it cannot say who it knows and nothing was changed.
var ErrRelayRosterTooOld = errors.New("mgmt: relay software too old to list its people")

// ValidateRenewRequests checks names and actions. A name may appear
// once: "revoke r3" next to "ensure r3" is exactly the mistake that
// would bring a removed person back, so it is refused, not resolved.
func ValidateRenewRequests(reqs []RenewRequest) error {
	seen := map[string]string{}
	for _, r := range reqs {
		if !renewNameRE.MatchString(r.Name) {
			return fmt.Errorf("%w: name %q is not r<digits>", ErrRenewUsage, r.Name)
		}
		switch r.Action {
		case RenewEnsure, RenewReplace, RenewRevoke:
		default:
			return fmt.Errorf("%w: unknown action %q for %s", ErrRenewUsage, r.Action, r.Name)
		}
		if prev, dup := seen[r.Name]; dup {
			return fmt.Errorf("%w: %s is listed twice (%s and %s)", ErrRenewUsage, r.Name, prev, r.Action)
		}
		seen[r.Name] = r.Action
	}
	return nil
}

// RenewUsersWithFW runs the renew plan. The returned error means
// nothing could be done (the window or the roster read failed, or the
// request was refused before anything opened); per-name failures are
// inside the report. onUser, when set, is told "working" before each
// name is handled (progress; never carries credentials).
func RenewUsersWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string, reqs []RenewRequest, onUser func(name, status string)) (*RenewReport, error) {
	if err := ValidateRenewRequests(reqs); err != nil {
		return nil, err
	}
	if onUser == nil {
		onUser = func(string, string) {}
	}
	return withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (*RenewReport, error) {
		users, err := cli.ListUsers(ctx, rec, privKey)
		if err != nil {
			if s := HTTPStatus(err); s == http.StatusNotFound || s == http.StatusMethodNotAllowed {
				return nil, fmt.Errorf("%w: %v", ErrRelayRosterTooOld, err)
			}
			return nil, fmt.Errorf("mgmt: users-renew: read the relay's people: %w", err)
		}
		present := map[string]bool{}
		rep := &RenewReport{UsersBefore: []string{}, Results: []RenewResult{}}
		for _, u := range users {
			present[u.Name] = true
			rep.UsersBefore = append(rep.UsersBefore, u.Name)
		}
		for _, r := range reqs {
			onUser(r.Name, "working")
			rep.Results = append(rep.Results, renewOne(ctx, cli, rec, privKey, r, present[r.Name]))
		}
		return rep, nil
	})
}

func renewOne(ctx context.Context, cli *Client, rec *provider.OperatorRecord, priv ed25519.PrivateKey, r RenewRequest, present bool) RenewResult {
	res := RenewResult{Name: r.Name}
	fail := func(err error) RenewResult {
		res.OK, res.ErrorCode, res.Error = false, renewErrorCode(err), err.Error()
		res.Creds = nil
		return res
	}
	switch r.Action {
	case RenewRevoke:
		if !present {
			res.Action, res.OK = RenewAbsent, true
			return res
		}
		res.Action = RenewRevoked
		if _, err := cli.RevokeUser(ctx, rec, priv, r.Name); err != nil {
			return fail(err)
		}
		res.OK = true
		return res
	case RenewEnsure:
		if present {
			res.Action, res.OK = RenewKept, true
			return res
		}
	case RenewReplace:
		if present {
			if _, err := cli.RevokeUser(ctx, rec, priv, r.Name); err != nil && HTTPStatus(err) != http.StatusNotFound {
				res.Action = RenewProvisioned
				return fail(err)
			}
		}
	}
	res.Action = RenewProvisioned
	creds, err := cli.ProvisionUser(ctx, rec, priv, r.Name)
	if err != nil && isAlreadyExists(err) {
		// The roster was read a moment ago, but the box says this person
		// exists (a list that lagged, or a duplicate request). Once, and
		// only once: revoke and provision again, so the person ends with
		// credentials the publisher holds.
		if _, rerr := cli.RevokeUser(ctx, rec, priv, r.Name); rerr != nil && HTTPStatus(rerr) != http.StatusNotFound {
			return fail(rerr)
		}
		creds, err = cli.ProvisionUser(ctx, rec, priv, r.Name)
	}
	if err != nil {
		return fail(err)
	}
	res.OK, res.Creds = true, creds
	return res
}

// isAlreadyExists tells the box's two 409s apart: "user already exists"
// (retry with a revoke) and "max recipients reached" (relay_full).
func isAlreadyExists(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusConflict && strings.Contains(se.Body, "already exists")
}

func renewErrorCode(err error) string {
	var se *StatusError
	switch {
	case errors.Is(err, ErrFingerprintMismatch):
		return RenewErrRefused
	case errors.As(err, &se):
		switch {
		case se.Status == http.StatusConflict && strings.Contains(se.Body, "max recipients"):
			return RenewErrRelayFull
		case se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden:
			return RenewErrRefused
		case se.Status == http.StatusNotFound || se.Status == http.StatusMethodNotAllowed:
			return RenewErrTooOld
		}
		return RenewErrOther
	case errors.Is(err, context.DeadlineExceeded) || isNetError(err):
		return RenewErrUnreachable
	}
	return RenewErrOther
}
