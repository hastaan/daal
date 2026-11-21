package appsscript

// Path A ("Sign in with Google", docs/optional-addons-plan.md §3.4):
// the Apps Script API v1, called once with the publisher's short-lived
// access token to create the project, upload Code.gs and the manifest,
// make a version and deploy it as a web app. The token is then revoked
// and dropped; nothing here stores it. After this call both paths are
// the same: a URL and a write key.
//
// Scopes: script.projects (create, content, version) and
// script.deployments (deploy). Nothing else is asked for.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Scopes are the two OAuth scopes Path A asks for, and nothing else.
var Scopes = []string{
	"https://www.googleapis.com/auth/script.projects",
	"https://www.googleapis.com/auth/script.deployments",
}

// Endpoints are the Google hosts Path A talks to. Tests point HTTP at
// a fake Google; the URLs stay the real ones.
type Endpoints struct {
	API    string // Apps Script API base
	Token  string // OAuth token endpoint (desktop code exchange)
	Revoke string // OAuth revocation endpoint
	HTTP   *http.Client
}

// DefaultEndpoints are Google's.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		API:    "https://script.googleapis.com",
		Token:  "https://oauth2.googleapis.com/token",
		Revoke: "https://oauth2.googleapis.com/revoke",
		HTTP:   &http.Client{Timeout: 60 * time.Second},
	}
}

// Stages of a deploy, in order; an APIError names the one that failed.
const (
	StageAuth       = "auth"
	StageCreate     = "create"
	StageContent    = "content"
	StageVersion    = "version"
	StageDeployment = "deployment"
)

// API error reasons.
const (
	APIReasonNotEnabled   = "api_not_enabled" // the account has not turned the Apps Script API on
	APIReasonUnauthorized = "unauthorized"    // the token was refused or lacks a scope
	APIReasonFailed       = "failed"
)

// APIError is a failed deploy. ScriptID is set when a project was
// already created: the API cannot delete it (that needs a Drive scope
// Daal does not ask for), so the caller keeps the id to retry into the
// same project, and tells the publisher it exists.
type APIError struct {
	Stage    string
	Reason   string
	Status   int
	ScriptID string
	Message  string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("apps script %s: %s", e.Stage, e.Reason)
	if e.Status != 0 {
		s += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// AuthCode is what the desktop sign-in brought back from the browser:
// a one-time authorization code with its PKCE verifier. The client
// secret of a "Desktop app" OAuth client is not confidential (Google
// says so); it ships in the app.
type AuthCode struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ExchangeCode trades the code for an access token. Only the access
// token is read; a refresh token is never asked for (the desktop
// sign-in uses access_type=online) and is ignored if one comes.
func (e Endpoints) ExchangeCode(ctx context.Context, c AuthCode) ([]byte, error) {
	if c.Code == "" || c.CodeVerifier == "" || c.RedirectURI == "" || c.ClientID == "" {
		return nil, &APIError{Stage: StageAuth, Reason: APIReasonFailed, Message: "incomplete sign-in"}
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {c.Code},
		"code_verifier": {c.CodeVerifier},
		"redirect_uri":  {c.RedirectURI},
		"client_id":     {c.ClientID},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return nil, &APIError{Stage: StageAuth, Reason: APIReasonFailed, Message: "Google did not answer"}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxRead))
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode/100 != 2 || out.AccessToken == "" {
		msg := out.Error
		if out.Description != "" {
			msg += ": " + out.Description
		}
		return nil, &APIError{Stage: StageAuth, Reason: APIReasonUnauthorized, Status: resp.StatusCode, Message: msg}
	}
	return []byte(out.AccessToken), nil
}

// RevokeToken ends the grant. Best effort: the token expires within the
// hour anyway, and nothing here keeps it.
func (e Endpoints) RevokeToken(ctx context.Context, token []byte) error {
	if e.Revoke == "" || len(token) == 0 {
		return nil
	}
	form := url.Values{"token": {string(token)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Revoke, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("revoke: HTTP %d", resp.StatusCode)
	}
	return nil
}

// DeployResult is a deployed web app.
type DeployResult struct {
	ScriptID     string `json:"script_id"`
	DeploymentID string `json:"deployment_id"`
	Version      int    `json:"version"`
	// ExecURL is the web app's /exec address without the k.
	ExecURL string `json:"exec_url"`
}

// DeployOpts says what to deploy.
type DeployOpts struct {
	Title    string
	Code     string
	Manifest string
	// ScriptID, when set, is a project an earlier attempt created:
	// the create step is skipped and the rest goes into it.
	ScriptID string
}

// Deploy runs create (unless resuming), content, version, deployment.
func (e Endpoints) Deploy(ctx context.Context, token []byte, o DeployOpts) (*DeployResult, error) {
	if len(token) == 0 {
		return nil, &APIError{Stage: StageAuth, Reason: APIReasonUnauthorized, Message: "no access token"}
	}
	res := &DeployResult{ScriptID: o.ScriptID}
	if res.ScriptID == "" {
		var created struct {
			ScriptID string `json:"scriptId"`
		}
		title := o.Title
		if title == "" {
			title = "Notes"
		}
		if err := e.call(ctx, token, StageCreate, http.MethodPost, "/v1/projects",
			map[string]string{"title": title}, &created); err != nil {
			return nil, err
		}
		if !safeID(created.ScriptID) {
			return nil, &APIError{Stage: StageCreate, Reason: APIReasonFailed, Message: "no project id in the answer"}
		}
		res.ScriptID = created.ScriptID
	} else if !safeID(res.ScriptID) {
		return nil, &APIError{Stage: StageCreate, Reason: APIReasonFailed, Message: "bad project id"}
	}
	withID := func(err error) error {
		var ae *APIError
		if errors.As(err, &ae) {
			ae.ScriptID = res.ScriptID
		}
		return err
	}
	content := map[string]any{
		"files": []map[string]string{
			{"name": "Code", "type": "SERVER_JS", "source": o.Code},
			{"name": "appsscript", "type": "JSON", "source": o.Manifest},
		},
	}
	base := "/v1/projects/" + res.ScriptID
	if err := e.call(ctx, token, StageContent, http.MethodPut, base+"/content", content, nil); err != nil {
		return nil, withID(err)
	}
	var ver struct {
		VersionNumber int `json:"versionNumber"`
	}
	if err := e.call(ctx, token, StageVersion, http.MethodPost, base+"/versions",
		map[string]string{"description": "update channel"}, &ver); err != nil {
		return nil, withID(err)
	}
	if ver.VersionNumber <= 0 {
		return nil, withID(&APIError{Stage: StageVersion, Reason: APIReasonFailed, Message: "no version number in the answer"})
	}
	res.Version = ver.VersionNumber
	var dep struct {
		DeploymentID string `json:"deploymentId"`
		EntryPoints  []struct {
			EntryPointType string `json:"entryPointType"`
			WebApp         struct {
				URL string `json:"url"`
			} `json:"webApp"`
		} `json:"entryPoints"`
	}
	if err := e.call(ctx, token, StageDeployment, http.MethodPost, base+"/deployments", map[string]any{
		"versionNumber":    ver.VersionNumber,
		"manifestFileName": "appsscript",
		"description":      "update channel",
	}, &dep); err != nil {
		return nil, withID(err)
	}
	if !safeID(dep.DeploymentID) {
		return nil, withID(&APIError{Stage: StageDeployment, Reason: APIReasonFailed, Message: "no deployment id in the answer"})
	}
	res.DeploymentID = dep.DeploymentID
	res.ExecURL = "https://script.google.com/macros/s/" + dep.DeploymentID + "/exec"
	for _, ep := range dep.EntryPoints {
		if ep.EntryPointType == "WEB_APP" && ep.WebApp.URL != "" {
			// Prefer Google's own address when it has the plain
			// /macros/s/<id>/exec shape (a Workspace account's
			// /a/<domain>/ form does not, and is refused later).
			if u, err := url.Parse(ep.WebApp.URL); err == nil && u.Host == "script.google.com" &&
				strings.HasPrefix(u.Path, "/macros/s/") && strings.HasSuffix(u.Path, "/exec") {
				res.ExecURL = "https://script.google.com" + u.Path
			}
		}
	}
	return res, nil
}

func safeID(s string) bool {
	if len(s) < 10 || len(s) > 200 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// call does one API request. The token goes in the Authorization
// header only and never into an error.
func (e Endpoints) call(ctx context.Context, token []byte, stage, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(e.API, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return &APIError{Stage: stage, Reason: APIReasonFailed, Message: "Google did not answer"}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxRead))
	if resp.StatusCode/100 != 2 {
		return apiError(stage, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return &APIError{Stage: stage, Reason: APIReasonFailed, Status: resp.StatusCode, Message: "unreadable answer"}
		}
	}
	return nil
}

func apiError(stage string, status int, raw []byte) *APIError {
	var g struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &g)
	msg := g.Error.Message
	if len(msg) > 300 {
		msg = msg[:300]
	}
	reason := APIReasonFailed
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "apps script api") && (strings.Contains(low, "not enabled") || strings.Contains(low, "usersettings")):
		reason = APIReasonNotEnabled
	case status == http.StatusUnauthorized || g.Error.Status == "UNAUTHENTICATED":
		reason = APIReasonUnauthorized
	case status == http.StatusForbidden && strings.Contains(low, "scope"):
		reason = APIReasonUnauthorized
	}
	return &APIError{Stage: stage, Reason: reason, Status: status, Message: msg}
}
