// Package appsscripttest is a fake Google for the update channel's
// tests: the Apps Script API (create, content, version, deploy), the
// OAuth token and revoke endpoints, and the deployed web app itself,
// on one TLS listener that answers for every Google name and routes by
// the request's authority, the way Google's front does. Nothing here
// reaches the network.
//
// The web app runs the rules of Code.gs in Go, with the write key and
// path token read out of the source that was actually uploaded (or
// pasted, for Path B), so a test proves what Daal deployed, not what
// the test assumed.
package appsscripttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"daal/publisher/deploy/freshness/backends/appsscript"
)

// Names the fake answers for.
var Names = []string{
	"www.google.com", "script.google.com", "script.googleusercontent.com",
	"script.googleapis.com", "oauth2.googleapis.com",
}

// Fake is one fake Google.
type Fake struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu sync.Mutex
	// Knobs.
	APIDisabled   bool   // every API call answers "has not enabled the Apps Script API"
	FailStage     string // "create" | "content" | "version" | "deployment": that call fails once
	SignInWall    bool   // web apps answer with a sign-in page (access not "Anyone")
	BlockFront    bool   // connections with SNI www.google.com are cut
	BlockPlain    bool   // connections with any other SNI are cut
	AcceptedToken string // the access token the API accepts (default "ya29.test-token")

	// Observations.
	SNIs     []string
	Calls    []string // "METHOD host path" of every request
	Revoked  []string
	projects map[string]*project
	apps     map[string]*webApp // by deployment id
	codes    map[string]string  // auth code -> PKCE challenge
	echo     map[string]echoed
	nextID   int
}

type project struct {
	code, manifest string
	versions       int
}

type webApp struct {
	writeKey  []byte
	pathToken string
	seq       uint64
	blob      string
	posts     int
}

type echoed struct {
	status      int
	contentType string
	body        string
}

// New starts a fake. Close it when done.
func New() *Fake {
	f := &Fake{
		AcceptedToken: "ya29.test-token",
		projects:      map[string]*project{},
		apps:          map[string]*webApp{},
		codes:         map[string]string{},
		echo:          map[string]echoed{},
	}
	cert, pool := selfSigned()
	f.pool = pool
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	// The cut connections are the point of some tests; keep them
	// out of the test log.
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			f.mu.Lock()
			f.SNIs = append(f.SNIs, h.ServerName)
			cut := (h.ServerName == appsscript.FrontSNI && f.BlockFront) ||
				(h.ServerName != appsscript.FrontSNI && f.BlockPlain)
			f.mu.Unlock()
			if cut {
				return nil, fmt.Errorf("cut")
			}
			return nil, nil
		},
	}
	f.srv.StartTLS()
	return f
}

// Close stops the fake.
func (f *Fake) Close() { f.srv.Close() }

func (f *Fake) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, f.srv.Listener.Addr().String())
}

// Network is an appsscript.Network that reaches this fake for every
// name.
func (f *Fake) Network() appsscript.Network {
	return appsscript.Network{Dial: f.dial, RootCAs: f.pool, Timeout: 10 * time.Second}
}

// Endpoints are the real Google URLs, carried to this fake.
func (f *Fake) Endpoints() appsscript.Endpoints {
	e := appsscript.DefaultEndpoints()
	e.HTTP = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:       f.dial,
			TLSClientConfig:   &tls.Config{RootCAs: f.pool},
			ForceAttemptHTTP2: true,
		},
	}
	return e
}

// ExpectCode registers a one-time authorization code bound to a PKCE
// verifier (S256).
func (f *Fake) ExpectCode(code, verifier string) {
	sum := sha256.Sum256([]byte(verifier))
	f.mu.Lock()
	f.codes[code] = base64.RawURLEncoding.EncodeToString(sum[:])
	f.mu.Unlock()
}

// ExpectChallenge registers a code bound to a PKCE challenge directly
// (what a browser test sees in the authorization URL).
func (f *Fake) ExpectChallenge(code, challenge string) {
	f.mu.Lock()
	f.codes[code] = challenge
	f.mu.Unlock()
}

// DeployByHand is Path B: the publisher pastes code into a new project
// and deploys it as a web app. It returns the address Google shows
// (no k).
func (f *Fake) DeployByHand(code string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.newID("AKfycbHand")
	app, err := appFromCode(code)
	if err != nil {
		return "", err
	}
	f.apps[id] = app
	return "https://script.google.com/macros/s/" + id + "/exec", nil
}

// Projects is how many projects exist.
func (f *Fake) Projects() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.projects)
}

// Stored is what a deployment's web app holds now.
func (f *Fake) Stored(deploymentID string) (seq uint64, blob string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.apps[deploymentID]
	if !ok {
		return 0, "", false
	}
	return a.seq, a.blob, true
}

// SetStored overwrites what a web app holds (a vandal with Google
// access, or an older script).
func (f *Fake) SetStored(deploymentID string, seq uint64, blob string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.apps[deploymentID]; ok {
		a.seq, a.blob = seq, blob
	}
}

// ResetObservations clears SNIs and Calls.
func (f *Fake) ResetObservations() {
	f.mu.Lock()
	f.SNIs, f.Calls = nil, nil
	f.mu.Unlock()
}

func (f *Fake) newID(prefix string) string {
	f.nextID++
	return fmt.Sprintf("%s%024d", prefix, f.nextID)
}

var (
	keyRe   = regexp.MustCompile(`var WRITE_KEY_B64 = '([A-Za-z0-9+/=]+)';`)
	tokenRe = regexp.MustCompile(`var PATH_TOKEN = '([A-Za-z0-9_-]{22})';`)
)

func appFromCode(code string) (*webApp, error) {
	k := keyRe.FindStringSubmatch(code)
	t := tokenRe.FindStringSubmatch(code)
	if k == nil || t == nil {
		return nil, fmt.Errorf("fake: the code is not Daal's script")
	}
	key, err := base64.StdEncoding.DecodeString(k[1])
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("fake: bad write key in the code")
	}
	return &webApp{writeKey: key, pathToken: t[1]}, nil
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, r.Method+" "+r.Host+" "+r.URL.Path)
	switch r.Host {
	case "script.googleapis.com":
		f.api(w, r, body)
	case "oauth2.googleapis.com":
		f.oauth(w, r, body)
	case "script.google.com":
		f.exec(w, r, body)
	case "script.googleusercontent.com":
		f.echoBack(w, r)
	default:
		http.NotFound(w, r)
	}
}

func apiErr(w http.ResponseWriter, code int, status, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg, "status": status}})
}

func (f *Fake) api(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Header.Get("Authorization") != "Bearer "+f.AcceptedToken {
		apiErr(w, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
		return
	}
	if f.APIDisabled {
		apiErr(w, 403, "PERMISSION_DENIED", "User has not enabled the Apps Script API. Enable it by visiting https://script.google.com/home/usersettings then retry.")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // v1 projects [id] [what]
	stage := ""
	switch {
	case len(parts) == 2 && r.Method == http.MethodPost:
		stage = appsscript.StageCreate
	case len(parts) == 4 && parts[3] == "content" && r.Method == http.MethodPut:
		stage = appsscript.StageContent
	case len(parts) == 4 && parts[3] == "versions" && r.Method == http.MethodPost:
		stage = appsscript.StageVersion
	case len(parts) == 4 && parts[3] == "deployments" && r.Method == http.MethodPost:
		stage = appsscript.StageDeployment
	default:
		apiErr(w, 404, "NOT_FOUND", "no such method")
		return
	}
	if f.FailStage == stage {
		f.FailStage = ""
		apiErr(w, 500, "INTERNAL", "Internal error encountered.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if stage == appsscript.StageCreate {
		id := f.newID("1ScriptProject")
		f.projects[id] = &project{}
		_ = json.NewEncoder(w).Encode(map[string]string{"scriptId": id})
		return
	}
	p, ok := f.projects[parts[2]]
	if !ok {
		apiErr(w, 404, "NOT_FOUND", "Requested entity was not found.")
		return
	}
	switch stage {
	case appsscript.StageContent:
		var c struct {
			Files []struct{ Name, Type, Source string } `json:"files"`
		}
		_ = json.Unmarshal(body, &c)
		for _, fl := range c.Files {
			switch {
			case fl.Name == "Code" && fl.Type == "SERVER_JS":
				p.code = fl.Source
			case fl.Name == "appsscript" && fl.Type == "JSON":
				p.manifest = fl.Source
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scriptId": parts[2], "files": c.Files})
	case appsscript.StageVersion:
		p.versions++
		_ = json.NewEncoder(w).Encode(map[string]any{"scriptId": parts[2], "versionNumber": p.versions})
	case appsscript.StageDeployment:
		var m struct {
			Access, ExecuteAs string
		}
		var man struct {
			Webapp struct {
				Access    string `json:"access"`
				ExecuteAs string `json:"executeAs"`
			} `json:"webapp"`
		}
		if json.Unmarshal([]byte(p.manifest), &man) != nil || man.Webapp.Access == "" {
			apiErr(w, 400, "INVALID_ARGUMENT", "the manifest has no web app")
			return
		}
		m.Access, m.ExecuteAs = man.Webapp.Access, man.Webapp.ExecuteAs
		app, err := appFromCode(p.code)
		if err != nil {
			apiErr(w, 400, "INVALID_ARGUMENT", err.Error())
			return
		}
		id := f.newID("AKfycbDeploy")
		f.apps[id] = app
		if m.Access != "ANYONE_ANONYMOUS" || m.ExecuteAs != "USER_DEPLOYING" {
			f.SignInWall = true
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deploymentId": id,
			"entryPoints": []map[string]any{{
				"entryPointType": "WEB_APP",
				"webApp":         map[string]any{"url": "https://script.google.com/macros/s/" + id + "/exec"},
			}},
		})
	}
}

func (f *Fake) oauth(w http.ResponseWriter, r *http.Request, body []byte) {
	form, _ := urlValues(string(body))
	switch r.URL.Path {
	case "/token":
		want, ok := f.codes[form["code"]]
		sum := sha256.Sum256([]byte(form["code_verifier"]))
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if !ok || got != want || form["grant_type"] != "authorization_code" || form["redirect_uri"] == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Bad Request"}`)
			return
		}
		delete(f.codes, form["code"])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": f.AcceptedToken, "expires_in": 3599, "token_type": "Bearer"})
	case "/revoke":
		f.Revoked = append(f.Revoked, form["token"])
		w.WriteHeader(200)
	default:
		http.NotFound(w, r)
	}
}

func urlValues(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range strings.Split(s, "&") {
		k, v, _ := strings.Cut(kv, "=")
		k2, err1 := urlUnescape(k)
		v2, err2 := urlUnescape(v)
		if err1 != nil || err2 != nil {
			continue
		}
		out[k2] = v2
	}
	return out, nil
}

func urlUnescape(s string) (string, error) {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", err
			}
			b.WriteByte(byte(n))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

// exec is the web app at /macros/s/<id>/exec. Like Google, it answers
// with a redirect to script.googleusercontent.com, which serves what
// the script returned.
func (f *Fake) exec(w http.ResponseWriter, r *http.Request, body []byte) {
	const pre, suf = "/macros/s/", "/exec"
	if !strings.HasPrefix(r.URL.Path, pre) || !strings.HasSuffix(r.URL.Path, suf) {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, pre), suf)
	app, ok := f.apps[id]
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><body>Sorry, unable to open the file at this time.</body></html>")
		return
	}
	var out echoed
	switch {
	case f.SignInWall:
		out = echoed{200, "text/html", "<html><body>Sign in - Google Accounts</body></html>"}
	case r.Method == http.MethodGet:
		out = echoed{200, "text/plain", app.doGet(r.URL.Query().Get("k"))}
	case r.Method == http.MethodPost:
		out = echoed{200, "application/json", app.doPost(body)}
	default:
		http.Error(w, "method", 405)
		return
	}
	key := f.newID("echo")
	f.echo[key] = out
	http.Redirect(w, r, "https://script.googleusercontent.com/macros/echo?user_content_key="+key, http.StatusFound)
}

func (f *Fake) echoBack(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("user_content_key")
	out, ok := f.echo[key]
	if !ok {
		http.NotFound(w, r)
		return
	}
	delete(f.echo, key)
	w.Header().Set("Content-Type", out.contentType)
	w.WriteHeader(out.status)
	_, _ = io.WriteString(w, out.body)
}

func (a *webApp) doGet(k string) string {
	if subtle.ConstantTimeCompare([]byte(k), []byte(a.pathToken)) != 1 {
		return "Nothing here."
	}
	if a.blob == "" {
		return `{"kind":"daal-refresh-v1"}`
	}
	return a.blob
}

func answer(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (a *webApp) doPost(body []byte) string {
	var req struct {
		Seq  *json.Number `json:"seq"`
		Blob *string      `json:"blob"`
		MAC  *string      `json:"mac"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if dec.Decode(&req) != nil || req.Seq == nil || req.Blob == nil || req.MAC == nil {
		return answer(map[string]any{"ok": false, "error": "malformed"})
	}
	seq, err := strconv.ParseUint(req.Seq.String(), 10, 64)
	if err != nil || seq < 1 || seq > 1<<53-1 {
		return answer(map[string]any{"ok": false, "error": "malformed"})
	}
	if len(*req.Blob) > 65536 {
		return answer(map[string]any{"ok": false, "error": "too_large"})
	}
	m := hmac.New(sha256.New, a.writeKey)
	m.Write([]byte(strconv.FormatUint(seq, 10) + "\n" + *req.Blob))
	want := hex.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(*req.MAC), []byte(want)) != 1 {
		return answer(map[string]any{"ok": false, "error": "refused"})
	}
	if seq < a.seq || (seq == a.seq && *req.Blob != a.blob) {
		return answer(map[string]any{"ok": false, "error": "stale", "seq": a.seq})
	}
	a.seq, a.blob = seq, *req.Blob
	a.posts++
	return answer(map[string]any{"ok": true, "seq": seq})
}

func selfSigned() (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake google"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              Names,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
