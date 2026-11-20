package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The Apps Script API v1 and Google's OAuth token endpoints, as the
// publisher's Path A uses them (plan §3.4): create a project, put its
// content, make a version, deploy it as a web app — with the user's
// one-shot access token, which is then revoked. Served by `wb
// fakegoogle` (fakegfe.go) on script.googleapis.com and
// oauth2.googleapis.com; a deployment made here is a live web app on
// script.google.com at once.
//
// What it holds the publisher to:
//   - the token: exactly the one in google-access-token (what the
//     sign-in handed over), and not after it was revoked;
//   - the manifest: the web app must be ANYONE_ANONYMOUS / USER_DEPLOYING,
//     or the deployment answers like Google does for a script nobody
//     anonymous can run (a sign-in page) — the fake refuses to make one;
//   - the source: a deployment of a script that is not Daal's, or whose
//     write key and path token were not filled in, is refused.
//
// Knobs: api_disabled → 403 "Apps Script API has not been used in
// project … or it is disabled … script.google.com/home/usersettings";
// fail_stage → that one call fails once with 500.

var (
	reProject     = regexp.MustCompile(`^/v1/projects/([A-Za-z0-9_-]{10,200})/(content|versions|deployments)$`)
	reProjectRoot = regexp.MustCompile(`^/v1/projects$`)
)

func gError(w http.ResponseWriter, status int, gstatus, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": msg, "status": gstatus}})
}

func gJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (g *googleFake) acceptedToken() string {
	b, _ := os.ReadFile(filepath.Join(g.run, googleTokenFile))
	return strings.TrimSpace(string(b))
}

func (g *googleFake) api(w http.ResponseWriter, r *http.Request, body []byte, q *GoogleRequest) {
	tok := g.acceptedToken()
	if tok == "" || r.Header.Get("Authorization") != "Bearer "+tok || g.revoked[tok] {
		gError(w, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
		return
	}
	kn := g.knobs()
	if kn.APIDisabled {
		gError(w, 403, "PERMISSION_DENIED", "User has not enabled the Apps Script API. Enable it by visiting https://script.google.com/home/usersettings then retry.")
		return
	}
	stage := ""
	m := reProject.FindStringSubmatch(r.URL.Path)
	switch {
	case reProjectRoot.MatchString(r.URL.Path) && r.Method == "POST":
		stage = "create"
	case m != nil && m[2] == "content" && r.Method == "PUT":
		stage = "content"
	case m != nil && m[2] == "versions" && r.Method == "POST":
		stage = "version"
	case m != nil && m[2] == "deployments" && r.Method == "POST":
		stage = "deployment"
	default:
		gError(w, 501, "UNIMPLEMENTED", "worldbox: not modelled: "+r.Method+" "+r.URL.Path)
		return
	}
	q.Detail = stage
	if kn.FailStage == stage && !g.stageHit[stage] {
		g.stageHit[stage] = true
		gError(w, 500, "INTERNAL", "Internal error encountered.")
		return
	}
	if stage == "create" {
		var v struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal(body, &v)
		id := "1" + randKey(30)
		g.projects[id] = &gProject{title: v.Title}
		gJSON(w, map[string]any{"scriptId": id, "title": v.Title})
		return
	}
	p := g.projects[m[1]]
	if p == nil {
		gError(w, 404, "NOT_FOUND", "Requested entity was not found.")
		return
	}
	switch stage {
	case "content":
		var v struct {
			Files []struct {
				Name, Type, Source string
			} `json:"files"`
		}
		if json.Unmarshal(body, &v) != nil {
			gError(w, 400, "INVALID_ARGUMENT", "Invalid JSON payload received.")
			return
		}
		for _, f := range v.Files {
			switch {
			case f.Name == "Code" && f.Type == "SERVER_JS":
				p.code = f.Source
			case f.Name == "appsscript" && f.Type == "JSON":
				p.manifest = f.Source
			}
		}
		gJSON(w, map[string]any{"scriptId": m[1], "files": v.Files})
	case "version":
		p.versions++
		gJSON(w, map[string]any{"scriptId": m[1], "versionNumber": p.versions})
	case "deployment":
		var man struct {
			WebApp struct {
				Access, ExecuteAs string
			} `json:"webapp"`
		}
		if json.Unmarshal([]byte(p.manifest), &man) != nil || man.WebApp.Access != "ANYONE_ANONYMOUS" || man.WebApp.ExecuteAs != "USER_DEPLOYING" {
			gError(w, 400, "INVALID_ARGUMENT", "worldbox: the manifest does not deploy a web app anyone can run as the deploying user")
			return
		}
		key, ptok, err := parseDaalScript(p.code)
		if err != nil {
			gError(w, 400, "INVALID_ARGUMENT", "worldbox: "+err.Error())
			return
		}
		id := "AKfycb" + randKey(48)
		g.apps[id] = &gWebApp{id: id, writeKey: key, pathToken: ptok, source: "api"}
		gJSON(w, map[string]any{"deploymentId": id, "entryPoints": []any{map[string]any{"entryPointType": "WEB_APP",
			"webApp": map[string]any{"url": "https://script.google.com/macros/s/" + id + "/exec",
				"entryPointConfig": map[string]string{"access": "ANYONE_ANONYMOUS", "executeAs": "USER_DEPLOYING"}}}}})
	}
}

func (g *googleFake) oauth(w http.ResponseWriter, r *http.Request, body []byte) {
	form, _ := url.ParseQuery(string(body))
	switch r.URL.Path {
	case "/token":
		tok := g.acceptedToken()
		if form.Get("code") == "" || tok == "" {
			gJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		gJSON(w, map[string]any{"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})
	case "/revoke":
		if t := form.Get("token"); t != "" {
			g.revoked[t] = true
		}
		w.WriteHeader(200)
	default:
		http.Error(w, "Not Found", 404)
	}
}

// googleRevoked is read by ops: was the sign-in's token revoked?
func googleRevokeSeen(run string) bool {
	for _, q := range GoogleRequests(run) {
		if q.Host == "oauth2.googleapis.com" && q.Path == "/revoke" && q.Status == 200 {
			return true
		}
	}
	return false
}
