package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// `wb fakegoogle` is Google for the update channel (plan §3, item G7):
// one TLS listener on every address of 198.19.9.0/24 that answers for
// every Google name and ROUTES BY AUTHORITY, not by SNI — the property
// the recipient's fronted fetch depends on (SNI www.google.com,
// authority script.google.com). Behind it:
//
//   - the deployed web apps: /macros/s/<deployment id>/exec on
//     script.google.com, GET and POST, each answered the way Apps Script
//     answers — a 302 to script.googleusercontent.com/macros/echo?… whose
//     GET carries the script's output. The script's rules are Code.gs's
//     (protocol daal-refresh-v2: one script per Google account, one
//     container per relay slot; doGet: the slot's container for
//     ?s=<slot>&k=<the slot's read token>, a bland page otherwise; doPost:
//     MAC over slot, seq and blob checked, seq monotonic per slot,
//     stored), run in Go with the write key read out of the source that
//     was actually uploaded through the API or "pasted" by hand;
//   - the Apps Script API and OAuth (fakegas_api.go).
//
// Path B (by hand) is the publisher pasting the script into the editor
// and deploying it; here, a file google-paste/<deployment id>.gs that
// the op writes is what was pasted under that deployment.
//
// Knobs (google-knobs.json, read on every request): api_disabled (the
// "Apps Script API has not been used" answer), fail_stage (one API call
// fails), serve_previous (the web app answers, for every slot, with the
// container that slot held BEFORE its last update: a rollback), sign_in_wall (web apps answer
// with a sign-in page: access not "Anyone").
//
// Every request is a line in google-requests.jsonl: which address it
// reached, the SNI, the authority, method, path (never the query: the
// k and the echo key stay out of the log), status, and which part of
// Google answered it.

const (
	googleReqFile   = "google-requests.jsonl"
	googleKnobsFile = "google-knobs.json"
	googleTokenFile = "google-access-token" // the one access token the API accepts (the op's "sign-in")
	googlePasteDir  = "google-paste"
)

// GoogleKnobs are the fake's switches.
type GoogleKnobs struct {
	APIDisabled   bool   `json:"api_disabled,omitempty"`
	FailStage     string `json:"fail_stage,omitempty"` // create | content | version | deployment
	ServePrevious bool   `json:"serve_previous,omitempty"`
	SignInWall    bool   `json:"sign_in_wall,omitempty"`
}

// GoogleRequest is one line of google-requests.jsonl.
type GoogleRequest struct {
	TS     string `json:"ts"`
	Addr   string `json:"addr"`
	From   string `json:"from"`
	SNI    string `json:"sni"`
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Part   string `json:"part"` // front | webapp | echo | api | oauth | other
	Detail string `json:"detail,omitempty"`
}

func GoogleRequests(run string) []GoogleRequest {
	body, _ := os.ReadFile(filepath.Join(run, googleReqFile))
	var out []GoogleRequest
	for _, l := range strings.Split(string(body), "\n") {
		var q GoogleRequest
		if json.Unmarshal([]byte(l), &q) == nil && q.TS != "" {
			out = append(out, q)
		}
	}
	return out
}

type gProject struct {
	title, code, manifest string
	versions              int
}

type gWebApp struct {
	id       string
	writeKey []byte
	slots    map[string]*gSlot
	source   string // "api" | "paste"
}

type gSlot struct {
	seq  int64
	blob string
	prev string // the container before the last accepted update
}

type googleFake struct {
	mu       sync.Mutex
	run      string
	logf     *os.File
	projects map[string]*gProject
	apps     map[string]*gWebApp
	echo     map[string]string
	revoked  map[string]bool
	stageHit map[string]bool
}

func cmdFakeGoogle(args []string) int {
	fs := flag.NewFlagSet("fakegoogle", flag.ExitOnError)
	run := fs.String("run-dir", "", "")
	_ = fs.Parse(args)
	g := &googleFake{run: *run, projects: map[string]*gProject{}, apps: map[string]*gWebApp{}, echo: map[string]string{},
		revoked: map[string]bool{}, stageHit: map[string]bool{}}
	var err error
	if g.logf, err = os.OpenFile(filepath.Join(*run, googleReqFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		log.Fatalf("fakegoogle: %v", err)
	}
	labCA, labKey, err := loadCA(*run)
	if err != nil {
		log.Fatalf("fakegoogle: %v", err)
	}
	var cmu sync.Mutex
	cache := map[string]*tls.Certificate{}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(h.ServerName)
			if !googleName(name) {
				// Google's front answers an unknown name with its default
				// certificate, which does not cover it.
				name = "www.google.com"
			}
			cmu.Lock()
			defer cmu.Unlock()
			if c, ok := cache[name]; ok {
				return c, nil
			}
			c, err := mintLeaf(labCA, labKey, name)
			if err == nil {
				cache[name] = c
			}
			return c, err
		}}
	ln, err := net.Listen("tcp4", ":443")
	if err != nil {
		log.Fatalf("fakegoogle: %v", err)
	}
	fmt.Println("fakegoogle: listening")
	srv := &http.Server{Handler: g, TLSConfig: cfg, ReadHeaderTimeout: 20 * time.Second}
	log.Fatal(srv.ServeTLS(ln, "", ""))
	return 1
}

func googleName(n string) bool {
	return n == "google.com" || strings.HasSuffix(n, ".google.com") || strings.HasSuffix(n, ".googleusercontent.com") ||
		strings.HasSuffix(n, ".googleapis.com")
}

func (g *googleFake) knobs() GoogleKnobs {
	var k GoogleKnobs
	_ = loadJSON(filepath.Join(g.run, googleKnobsFile), &k)
	return k
}

func (g *googleFake) ServeHTTP(w0 http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w := &statusRecorder{ResponseWriter: w0, status: 200}
	q := GoogleRequest{From: r.RemoteAddr, Host: strings.ToLower(strings.Split(r.Host, ":")[0]), Method: r.Method, Path: r.URL.Path}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		q.Addr, _, _ = net.SplitHostPort(la.String())
	}
	if r.TLS != nil {
		q.SNI = strings.ToLower(r.TLS.ServerName)
	}
	defer func() {
		q.TS, q.Status = time.Now().UTC().Format(time.RFC3339Nano), w.status
		line, _ := json.Marshal(q)
		g.logf.Write(append(line, '\n'))
	}()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	switch q.Host {
	case "script.google.com":
		q.Part = "webapp"
		g.webApp(w, r, body, &q)
	case "script.googleusercontent.com":
		q.Part = "echo"
		k := r.URL.Query().Get("user_content_key")
		out, ok := g.echo[k]
		if r.URL.Path != "/macros/echo" || !ok {
			http.Error(w, "Not Found", 404)
			return
		}
		ct := "text/plain; charset=utf-8"
		if strings.HasPrefix(out, "{") && strings.Contains(out, `"ok"`) {
			ct = "application/json; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		_, _ = io.WriteString(w, out)
	case "script.googleapis.com":
		q.Part = "api"
		g.api(w, r, body, &q)
	case "oauth2.googleapis.com":
		q.Part = "oauth"
		g.oauth(w, r, body)
	case "www.google.com", "google.com":
		q.Part = "front"
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<!doctype html><title>Google</title>")
	default:
		q.Part = "other"
		http.Error(w, "404. That's an error.", 404)
	}
}

var (
	reExec     = regexp.MustCompile(`^/macros/s/([A-Za-z0-9_-]{20,120})/exec$`)
	reWriteKey = regexp.MustCompile(`var WRITE_KEY_B64 = '([A-Za-z0-9+/=]+)';`)
	reSlot     = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
)

// parseDaalScript reads the write key Code.gs is set up with; a source
// that is not Daal's account script (or was not filled in) is refused.
func parseDaalScript(src string) (key []byte, err error) {
	km := reWriteKey.FindStringSubmatch(src)
	if km == nil || !strings.Contains(src, "function doGet") || !strings.Contains(src, "function doPost") ||
		!strings.Contains(src, "'daal-refresh-v2'") {
		return nil, fmt.Errorf("not the update script, or its write key was not filled in")
	}
	key, err = base64.StdEncoding.DecodeString(km[1])
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("write key is not 32 bytes of base64")
	}
	return key, nil
}

func newWebApp(id string, key []byte, source string) *gWebApp {
	return &gWebApp{id: id, writeKey: key, slots: map[string]*gSlot{}, source: source}
}

func (g *googleFake) app(id string) *gWebApp {
	if a, ok := g.apps[id]; ok {
		return a
	}
	src, err := os.ReadFile(filepath.Join(g.run, googlePasteDir, id+".gs"))
	if err != nil {
		return nil
	}
	key, err := parseDaalScript(string(src))
	if err != nil {
		return nil
	}
	a := newWebApp(id, key, "paste")
	g.apps[id] = a
	return a
}

func randKey(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// webApp is one /exec request: run the script, answer with Apps
// Script's redirect to the output.
func (g *googleFake) webApp(w http.ResponseWriter, r *http.Request, body []byte, q *GoogleRequest) {
	m := reExec.FindStringSubmatch(r.URL.Path)
	var a *gWebApp
	if m != nil {
		a = g.app(m[1])
	}
	if a == nil {
		q.Detail = "no such deployment"
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><body>Sorry, unable to open the file at this time.</body></html>")
		return
	}
	kn := g.knobs()
	if kn.SignInWall {
		q.Detail = "sign-in wall"
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><title>Google Accounts</title><body>Sign in to continue to Google Drive</body></html>")
		return
	}
	var out string
	switch r.Method {
	case "GET":
		out = a.doGet(r.URL.Query().Get("s"), r.URL.Query().Get("k"), kn.ServePrevious)
	case "POST":
		out = a.doPost(body)
		q.Detail = out
	default:
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	k := randKey(24)
	g.echo[k] = out
	w.Header().Set("Location", "https://script.googleusercontent.com/macros/echo?user_content_key="+k+"&lib="+a.id)
	w.WriteHeader(http.StatusFound)
}

// readToken is Code.gs readToken_: the first 16 bytes of
// HMAC-SHA256(write key, "daal-read-v2\n" + slot), base64url.
func (a *gWebApp) readToken(slot string) string {
	m := hmac.New(sha256.New, a.writeKey)
	m.Write([]byte("daal-read-v2\n" + slot))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// doGet is Code.gs doGet: ?s=<slot>&k=<the slot's read token>.
func (a *gWebApp) doGet(slot, k string, previous bool) string {
	if !reSlot.MatchString(slot) || subtle.ConstantTimeCompare([]byte(k), []byte(a.readToken(slot))) != 1 {
		return "Nothing here."
	}
	st := a.slots[slot]
	if st == nil {
		return "Nothing here."
	}
	blob := st.blob
	if previous {
		blob = st.prev
	}
	if blob == "" {
		return "Nothing here."
	}
	return blob
}

// doPost is Code.gs doPost: {"slot","seq","blob","mac"}, mac =
// HMAC-SHA256(write key, "daal-refresh-v2\n" + slot + "\n" + decimal seq
// + "\n" + blob); seq only goes up, per slot.
func (a *gWebApp) doPost(body []byte) string {
	var req struct {
		Slot *string     `json:"slot"`
		Seq  json.Number `json:"seq"`
		Blob *string     `json:"blob"`
		MAC  *string     `json:"mac"`
	}
	answer := func(v map[string]any) string { b, _ := json.Marshal(v); return string(b) }
	if json.Unmarshal(body, &req) != nil || req.Slot == nil || !reSlot.MatchString(*req.Slot) || req.Blob == nil || req.MAC == nil {
		return answer(map[string]any{"ok": false, "error": "malformed"})
	}
	seq, err := strconv.ParseInt(string(req.Seq), 10, 64)
	if err != nil || seq < 1 || seq > 1<<53 {
		return answer(map[string]any{"ok": false, "error": "malformed"})
	}
	if len(*req.Blob) > 65536 {
		return answer(map[string]any{"ok": false, "error": "too_large"})
	}
	mac := hmac.New(sha256.New, a.writeKey)
	mac.Write([]byte("daal-refresh-v2\n" + *req.Slot + "\n" + strconv.FormatInt(seq, 10) + "\n" + *req.Blob))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(*req.MAC), []byte(want)) != 1 {
		return answer(map[string]any{"ok": false, "error": "refused"})
	}
	st := a.slots[*req.Slot]
	if st == nil {
		st = &gSlot{}
		a.slots[*req.Slot] = st
	}
	if seq < st.seq {
		return answer(map[string]any{"ok": false, "error": "stale", "seq": st.seq})
	}
	if seq == st.seq {
		if st.blob == *req.Blob {
			return answer(map[string]any{"ok": true, "seq": st.seq})
		}
		return answer(map[string]any{"ok": false, "error": "stale", "seq": st.seq})
	}
	st.prev, st.blob, st.seq = st.blob, *req.Blob, seq
	return answer(map[string]any{"ok": true, "seq": seq})
}
