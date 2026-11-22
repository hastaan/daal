package appsscript_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"daal/publisher/deploy/freshness/backends/appsscript"
	"daal/publisher/deploy/freshness/backends/appsscript/appsscripttest"
)

func deployOpts(t *testing.T) appsscript.DeployOpts {
	code, manifest, err := appsscript.Script(key())
	if err != nil {
		t.Fatal(err)
	}
	return appsscript.DeployOpts{Title: "Notes", Code: code, Manifest: manifest}
}

// Path A end to end against the fake: four calls, then the same POST
// and fetch-back as Path B.
func TestDeployThenTheChannelWorks(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	ctx := context.Background()
	res, err := f.Endpoints().Deploy(ctx, []byte(f.AcceptedToken), deployOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.ScriptID == "" || res.DeploymentID == "" || res.Version != 1 {
		t.Fatalf("%+v", res)
	}
	var api []string
	for _, c := range f.Calls {
		if strings.Contains(c, "script.googleapis.com") {
			api = append(api, c)
		}
	}
	want := []string{
		"POST script.googleapis.com /v1/projects",
		"PUT script.googleapis.com /v1/projects/" + res.ScriptID + "/content",
		"POST script.googleapis.com /v1/projects/" + res.ScriptID + "/versions",
		"POST script.googleapis.com /v1/projects/" + res.ScriptID + "/deployments",
	}
	if strings.Join(api, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(api, "\n"))
	}
	base, err := appsscript.NormalizeExecURL(res.ExecURL)
	if err != nil {
		t.Fatal(err)
	}
	// Path A ends where Path B does: the account check passes, and a
	// relay's slot takes updates.
	if r := f.Network().AccountCheck(ctx, base, key(), 1); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := f.Network().SendAndCheck(ctx, slotURL(t, base, slot), key(), 3, appsscript.Empty(slot)); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestDeployAPINotTurnedOn(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	f.APIDisabled = true
	_, err := f.Endpoints().Deploy(context.Background(), []byte(f.AcceptedToken), deployOpts(t))
	var ae *appsscript.APIError
	if !errors.As(err, &ae) || ae.Reason != appsscript.APIReasonNotEnabled || ae.Stage != appsscript.StageCreate {
		t.Fatalf("%v", err)
	}
	if f.Projects() != 0 {
		t.Fatal("nothing should exist")
	}
}

func TestDeployRefusedToken(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	_, err := f.Endpoints().Deploy(context.Background(), []byte("ya29.someone-elses"), deployOpts(t))
	var ae *appsscript.APIError
	if !errors.As(err, &ae) || ae.Reason != appsscript.APIReasonUnauthorized {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "ya29") {
		t.Fatal("the token must never be in an error")
	}
}

// A failure after the project exists names it, and a retry with that
// id goes into the same project instead of making a second one (the
// API cannot delete a project with the scopes Daal asks for).
func TestDeployPartialFailureResumesIntoTheSameProject(t *testing.T) {
	for _, stage := range []string{appsscript.StageContent, appsscript.StageVersion, appsscript.StageDeployment} {
		t.Run(stage, func(t *testing.T) {
			f := appsscripttest.New()
			defer f.Close()
			f.FailStage = stage
			e := f.Endpoints()
			o := deployOpts(t)
			_, err := e.Deploy(context.Background(), []byte(f.AcceptedToken), o)
			var ae *appsscript.APIError
			if !errors.As(err, &ae) || ae.Stage != stage || ae.ScriptID == "" {
				t.Fatalf("%v", err)
			}
			o.ScriptID = ae.ScriptID
			res, err := e.Deploy(context.Background(), []byte(f.AcceptedToken), o)
			if err != nil {
				t.Fatal(err)
			}
			if res.ScriptID != ae.ScriptID || f.Projects() != 1 {
				t.Fatalf("resumed into %s, %d projects", res.ScriptID, f.Projects())
			}
		})
	}
}

func TestExchangeCodeWithPKCEAndRevoke(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	e := f.Endpoints()
	ctx := context.Background()
	f.ExpectCode("4/code", "the-verifier-of-at-least-43-characters-aaaaaaa")
	ac := appsscript.AuthCode{Code: "4/code", CodeVerifier: "wrong-verifier", RedirectURI: "http://127.0.0.1:5000", ClientID: "cid"}
	if _, err := e.ExchangeCode(ctx, ac); err == nil {
		t.Fatal("a wrong verifier must be refused")
	}
	ac.CodeVerifier = "the-verifier-of-at-least-43-characters-aaaaaaa"
	tok, err := e.ExchangeCode(ctx, ac)
	if err != nil || string(tok) != f.AcceptedToken {
		t.Fatalf("%q %v", tok, err)
	}
	if _, err := e.ExchangeCode(ctx, ac); err == nil {
		t.Fatal("a code works once")
	}
	if err := e.RevokeToken(ctx, tok); err != nil || len(f.Revoked) != 1 {
		t.Fatalf("revoke: %v %v", err, f.Revoked)
	}
}
