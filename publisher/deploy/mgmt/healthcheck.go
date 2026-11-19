package mgmt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"time"

	"daal/publisher/deploy/provider"
)

// Management states relay-health reports (contract D3).
const (
	MgmtAnswers    = "answers"
	MgmtNoAnswer   = "no_answer"
	MgmtRefused    = "refused"
	MgmtTooOld     = "too_old"
	MgmtNotChecked = "not_checked"
	MgmtError      = "error"
)

// MgmtHealth is what the relay's management service said to the health
// check. Read-only on the box: the only change anywhere is the usual
// temporary firewall rule, which is removed on the way out.
type MgmtHealth struct {
	State    string         `json:"state"`
	Error    string         `json:"error"`
	Identity *RelayIdentity `json:"identity"`
	Users    []string       `json:"users"`
}

// HealthWithFW asks the relay two signed questions inside ONE firewall
// window, on ONE pinned client: who are you (GET /identity) and whom do
// you serve (GET /users/list). No new port and no new endpoint — these
// are the calls the app already makes.
//
// It never returns an error: every outcome is a state. A relay whose
// software predates /identity but lists its users "answers" with no
// identity. A certificate that is not the pinned one, or a token the box
// refuses, is "refused" — the address answers, but not as this relay.
func HealthWithFW(ctx context.Context, prov provider.Provider, rec *provider.OperatorRecord, privKey ed25519.PrivateKey, callerIP string, timeout time.Duration) *MgmtHealth {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	out := &MgmtHealth{}
	_, werr := withFirewallWindow(ctx, prov, rec, callerIP, func(cli *Client) (struct{}, error) {
		cli.httpClient.Timeout = timeout
		id, idErr := cli.Identity(ctx, rec, privKey)
		users, uErr := cli.ListUsers(ctx, rec, privKey)
		if idErr == nil {
			out.Identity = id
		}
		if uErr == nil {
			out.Users = []string{}
			for _, u := range users {
				out.Users = append(out.Users, u.Name)
			}
		}
		out.State, out.Error = classifyMgmt(idErr, uErr)
		return struct{}{}, nil
	})
	if werr != nil {
		// The window could not be opened (or the record cannot be
		// talked to at all): nothing was asked.
		out.State, out.Error = MgmtError, werr.Error()
	}
	return out
}

func classifyMgmt(idErr, uErr error) (string, string) {
	idOK := idErr == nil
	idOld := errors.Is(idErr, ErrIdentityUnsupported)
	uOK := uErr == nil
	uOld := isOldRoute(uErr)
	errText := ""
	for _, e := range []error{idErr, uErr} {
		if e != nil && !errors.Is(e, ErrIdentityUnsupported) {
			if errText != "" {
				errText += "; "
			}
			errText += e.Error()
		}
	}
	switch {
	case isRefusal(idErr) || isRefusal(uErr):
		return MgmtRefused, errText
	case idOK || uOK:
		return MgmtAnswers, errText
	case idOld && uOld:
		return MgmtTooOld, errText
	case isNetError(idErr) && isNetError(uErr):
		return MgmtNoAnswer, errText
	}
	if errText == "" && idErr != nil {
		errText = idErr.Error()
	}
	return MgmtError, errText
}

func isOldRoute(err error) bool {
	s := HTTPStatus(err)
	return s == http.StatusNotFound || s == http.StatusMethodNotAllowed
}

// isRefusal: the relay answered, but would not authenticate this call
// or did not prove itself to be the relay this record pins.
func isRefusal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrFingerprintMismatch) {
		return true
	}
	s := HTTPStatus(err)
	return s == http.StatusUnauthorized || s == http.StatusForbidden
}

// isNetError: nothing answered (refused connection, timeout, reset).
func isNetError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var oe *net.OpError
	return errors.As(err, &oe)
}
