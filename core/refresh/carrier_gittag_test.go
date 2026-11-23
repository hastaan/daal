package refresh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fullnote"
	"daal/core/bootstrap"
)

// noteWorld is one local TLS server standing in for every host the
// git-tag readers name (GitHub, raw, jsDelivr, the Go proxies, Google's
// front), routing by Host, serving one repository's note tags.
type noteWorld struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu    sync.Mutex
	owner string
	repo  string
	tags  []string          // newest first
	files map[string]string // tag → the text of n
	mods  map[string]string // tag → go.mod
	mode  string            // "", "redirect", "huge", "stall", "html", "404"
	// Observations.
	reqs []string // "sni|host path"
	snis []string
}

var noteWorldNames = []string{"github.com", "raw.githubusercontent.com", "data.jsdelivr.com",
	"cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net",
	"proxy.golang.org", "goproxy.cn", "goproxy.io", "www.google.com", "evil.example"}

func newNoteWorld(t *testing.T, owner, repo string) *noteWorld {
	t.Helper()
	w := &noteWorld{owner: owner, repo: repo, files: map[string]string{}, mods: map[string]string{}}
	cert, pool := noteWorldCert(t)
	w.pool = pool
	w.srv = httptest.NewUnstartedServer(http.HandlerFunc(w.serve))
	w.srv.EnableHTTP2 = true
	w.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	w.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			w.mu.Lock()
			w.snis = append(w.snis, h.ServerName)
			w.mu.Unlock()
			return nil, nil
		},
	}
	w.srv.StartTLS()
	t.Cleanup(w.srv.Close)
	return w
}

func noteWorldCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "fake world"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: noteWorldNames, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func (w *noteWorld) set(f func()) { w.mu.Lock(); f(); w.mu.Unlock() }

func (w *noteWorld) requests() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.reqs...)
}

func (w *noteWorld) serve(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	w.reqs = append(w.reqs, sni+"|"+r.Host+" "+r.URL.RequestURI())
	mode, owner, repo := w.mode, w.owner, w.repo
	tags := append([]string(nil), w.tags...)
	files, mods := w.files, w.mods
	w.mu.Unlock()

	switch mode {
	case "redirect":
		http.Redirect(rw, r, "https://evil.example/x", http.StatusFound)
		return
	case "huge":
		_, _ = rw.Write([]byte(strings.Repeat("v0.0.0\n", 11000)))
		return
	case "stall":
		rw.WriteHeader(200)
		rw.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		return
	case "html":
		_, _ = io.WriteString(rw, "<html><body>portal</body></html>")
		return
	case "404":
		http.NotFound(rw, r)
		return
	}
	p := r.URL.Path
	modBase := "/github.com/" + goModuleEscape(owner) + "/" + goModuleEscape(repo) + "/@v/"
	switch {
	case r.Host == "github.com" && p == "/"+owner+"/"+repo+"/tags.atom":
		rw.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
		_, _ = io.WriteString(rw, atomFeed(owner, repo, tags))
	case r.Host == "raw.githubusercontent.com" && strings.HasPrefix(p, "/"+owner+"/"+repo+"/") && strings.HasSuffix(p, "/n"):
		tag := strings.TrimSuffix(strings.TrimPrefix(p, "/"+owner+"/"+repo+"/"), "/n")
		serveText(rw, r, files, tag)
	case r.Host == "data.jsdelivr.com" && p == "/v1/packages/gh/"+owner+"/"+repo:
		type v struct {
			Version string `json:"version"`
			Links   any    `json:"links"`
		}
		doc := struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Versions []v    `json:"versions"`
		}{Type: "gh", Name: owner + "/" + repo}
		for _, tg := range tags {
			doc.Versions = append(doc.Versions, v{Version: strings.TrimPrefix(tg, "v"), Links: map[string]string{"self": "x"}})
		}
		_ = json.NewEncoder(rw).Encode(doc)
	case strings.HasSuffix(r.Host, ".jsdelivr.net") && strings.HasPrefix(p, "/gh/"+owner+"/"+repo+"@") && strings.HasSuffix(p, "/n"):
		tag := strings.TrimSuffix(strings.TrimPrefix(p, "/gh/"+owner+"/"+repo+"@"), "/n")
		serveText(rw, r, files, tag)
	case (r.Host == "proxy.golang.org" || r.Host == "goproxy.cn" || r.Host == "goproxy.io") && p == modBase+"list":
		shuffled := append([]string(nil), tags...)
		mrand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		_, _ = io.WriteString(rw, strings.Join(shuffled, "\n")+"\n")
	case (r.Host == "proxy.golang.org" || r.Host == "goproxy.cn" || r.Host == "goproxy.io") && strings.HasPrefix(p, modBase) && strings.HasSuffix(p, ".mod"):
		serveText(rw, r, mods, strings.TrimSuffix(strings.TrimPrefix(p, modBase), ".mod"))
	default:
		http.NotFound(rw, r)
	}
}

func serveText(rw http.ResponseWriter, r *http.Request, m map[string]string, key string) {
	s, ok := m[key]
	if !ok {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(rw, s)
}

// atomFeed is GitHub's tags.atom shape (newest 10 only; titles without
// the leading v, as wave 0 saw).
func atomFeed(owner, repo string, tags []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<feed xmlns="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/" xml:lang="en-US">` + "\n")
	fmt.Fprintf(&b, "  <id>tag:github.com,2008:https://github.com/%s/%s/releases</id>\n", owner, repo)
	fmt.Fprintf(&b, `  <link type="text/html" rel="alternate" href="https://github.com/%s/%s/releases"/>`+"\n", owner, repo)
	fmt.Fprintf(&b, "  <title>Tags from %s</title>\n  <updated>2026-11-22T10:00:00Z</updated>\n", repo)
	for i, tg := range tags {
		if i == 10 {
			break
		}
		b.WriteString("  <entry>\n")
		fmt.Fprintf(&b, "    <id>tag:github.com,2008:Repository/123456/%s</id>\n", tg)
		b.WriteString("    <updated>2026-11-22T10:00:00Z</updated>\n")
		fmt.Fprintf(&b, `    <link rel="alternate" type="text/html" href="https://github.com/%s/%s/releases/tag/%s"/>`+"\n", owner, repo, tg)
		fmt.Fprintf(&b, "    <title>%s</title>\n", strings.TrimPrefix(tg, "v"))
		b.WriteString("    <content type=\"html\">&lt;p&gt;note&lt;/p&gt;</content>\n")
		b.WriteString("    <author><name>pub</name></author>\n")
		b.WriteString(`    <media:thumbnail height="30" width="30" url="https://avatars.githubusercontent.com/u/1?s=60&amp;v=4"/>` + "\n")
		b.WriteString("  </entry>\n")
	}
	b.WriteString("</feed>\n")
	return b.String()
}

// goModWith is a go.mod carrying text in 64-character comment lines.
func goModWith(owner, repo, text string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module github.com/%s/%s\n\ngo 1.21\n\n", owner, repo)
	for len(text) > 0 {
		n := min(64, len(text))
		b.WriteString("// " + text[:n] + "\n")
		text = text[n:]
	}
	return b.String()
}

// worldDialer sends every dial to the world and records the address;
// hosts in fail are refused.
type worldDialer struct {
	target string
	fail   map[string]bool
	mu     sync.Mutex
	addrs  []string
}

func (d *worldDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	host, _, _ := net.SplitHostPort(address)
	if d.fail[host] {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

// testGitCarriers are the six readers, trusting the world's certificate.
func testGitCarriers(w *noteWorld, timeout time.Duration) []Carrier {
	o := bootstrap.BrowserGetOptions{RootCAs: w.pool, Timeout: timeout}
	fo := bootstrap.FrontOptions{RootCAs: w.pool}
	return []Carrier{
		&gitHubCarrier{opts: o},
		&jsDelivrCarrier{opts: o},
		&goProxyCarrier{name: "goproxy-front", host: bootstrap.GoProxyHost, front: true, class: ClassGoogle, rung: RungGoogle, opts: o, frontOptions: fo},
		&goProxyCarrier{name: "goproxy-direct", host: bootstrap.GoProxyHost, class: ClassGoProxy, rung: RungReaders, opts: o},
		&goProxyCarrier{name: "goproxy-cn", host: "goproxy.cn", class: ClassGoProxy, rung: RungReaders, opts: o},
		&goProxyCarrier{name: "goproxy-io", host: "goproxy.io", class: ClassGoProxy, rung: RungReaders, opts: o},
	}
}

const (
	testOwner = "Pub-Acct" // upper case: the Go proxies' case encoding is exercised
	testRepo  = "relay.notes"
)

type gitWrite struct {
	env       *CarrierEnv
	k         bundle.StandbyKeyBytes
	people    *bundle.UpdateSecret
	container []byte
	e         uint64
}

func newGitWrite(t *testing.T, w *noteWorld) (*gitWrite, *worldDialer) {
	t.Helper()
	env, k, people, _ := testNoteEnv(t)
	env.Carriers = &bundle.UpdateCarriers{GitTag: &bundle.GitTagCarrier{Owner: testOwner, Repo: testRepo}}
	d := &worldDialer{target: w.srv.Listener.Addr().String()}
	env.Dialer = d
	return &gitWrite{env: env, k: k, people: people,
		container: []byte(`{"kind":"daal-refresh-v2","slot":"x","freshness":"..."}`),
		e:         bundle.NoteEpochAt(bundle.NoteCarrierGitTag, env.Now)}, d
}

// publish puts a note tag (micro sealed for u at epoch e, or filler) and
// its full note (or filler) in the world.
func (g *gitWrite) publish(t *testing.T, w *noteWorld, seq uint64, u *bundle.UpdateSecret, e uint64, filler bool) string {
	t.Helper()
	var sealed [bundle.MicroNoteLen]byte
	var text string
	if filler {
		sealed, _ = bundle.MicroFiller(rand.Reader)
		f, err := bundle.FullFiller(len(g.container), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		text = bundle.EncodeFullNoteText(f)
	} else {
		var err error
		if sealed, err = bundle.SealMicroNote(u.Secret, bundle.NoteCarrierGitTag, e, g.k); err != nil {
			t.Fatal(err)
		}
		full, err := fullnote.Seal(u.Secret, bundle.NoteCarrierGitTag, e, g.container, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		text = bundle.EncodeFullNoteText(full)
	}
	tag := bundle.GitNoteTag(seq, sealed)
	w.set(func() {
		w.tags = append([]string{tag}, w.tags...)
		w.files[tag] = text + "\n"
		w.mods[tag] = goModWith(w.owner, w.repo, text)
	})
	return tag
}

func TestGitCarriers_Registered(t *testing.T) {
	want := map[string]string{"github": ClassGitHub, "jsdelivr": ClassJSDelivr, "goproxy-front": ClassGoogle,
		"goproxy-direct": ClassGoProxy, "goproxy-cn": ClassGoProxy, "goproxy-io": ClassGoProxy}
	got := map[string]string{}
	for _, c := range RegisteredCarriers() {
		got[c.Info().Name] = c.Info().Class
		if c.Info().Label != bundle.NoteCarrierGitTag && want[c.Info().Name] != "" {
			t.Fatalf("%s label", c.Info().Name)
		}
	}
	for n, cl := range want {
		if got[n] != cl {
			t.Fatalf("%s: class %q", n, got[n])
		}
	}
}

func TestGitCarriers_GoodNotes(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, _ := newGitWrite(t, w)
	w.set(func() { w.tags = []string{"v1.0.0", "v0.3.0"} }) // ordinary tags are skipped
	g.publish(t, w, 3, g.people, g.e-1, false)              // last week's
	g.publish(t, w, 4, g.people, g.e, false)                // this week's, newest
	slot, _ := bundle.NoteName(g.people.Secret, bundle.NoteCarrierGitTag, g.e)
	for _, c := range testGitCarriers(w, 5*time.Second) {
		name := c.Info().Name
		if !c.Usable(g.env) {
			t.Fatalf("%s: not usable", name)
		}
		notes, err := c.Fetch(context.Background(), g.env)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(notes) != 2 || notes[0].Kind != NoteMicro || notes[1].Kind != NoteFull {
			t.Fatalf("%s: notes %+v", name, notes)
		}
		m, f := notes[0], notes[1]
		if m.StandbyKey != g.k || !g.env.Standby.Matches(m.StandbyKey) || m.Carrier != name || m.Audience != bundle.AudiencePeople {
			t.Fatalf("%s: micro %+v", name, m)
		}
		if string(f.Container) != string(g.container) || f.Slot != slot || f.Epoch != g.e || f.Carrier != name {
			t.Fatalf("%s: full %+v", name, f)
		}
	}
	// The front carrier showed www.google.com; the direct one its own name.
	var sawFront, sawDirect bool
	for _, r := range w.requests() {
		if strings.HasPrefix(r, "www.google.com|proxy.golang.org /github.com/!pub-!acct/relay.notes/@v/") {
			sawFront = true
		}
		if strings.HasPrefix(r, "proxy.golang.org|proxy.golang.org /github.com/!pub-!acct/") {
			sawDirect = true
		}
		if strings.HasPrefix(r, "github.com|") && !strings.HasSuffix(r, "/tags.atom") {
			t.Fatalf("unexpected github request %q", r)
		}
	}
	if !sawFront || !sawDirect {
		t.Fatalf("front %v direct %v: %v", sawFront, sawDirect, w.requests())
	}
}

// Without the signed standby only the full note can be read.
func TestGitCarriers_FullOnlyWithoutStandby(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, _ := newGitWrite(t, w)
	g.publish(t, w, 1, g.people, g.e, false)
	g.env.Standby = nil
	for _, c := range testGitCarriers(w, 5*time.Second) {
		notes, err := c.Fetch(context.Background(), g.env)
		if err != nil || len(notes) != 1 || notes[0].Kind != NoteFull {
			t.Fatalf("%s: %v %+v", c.Info().Name, err, notes)
		}
	}
}

// Filler, a note for an audience we do not hold, a note two epochs old:
// nothing new, never an error.
func TestGitCarriers_NothingNew(t *testing.T) {
	other := &bundle.UpdateSecret{Audience: "people/other"}
	_, _ = rand.Read(other.Secret[:])
	for _, tc := range []struct {
		name string
		put  func(*testing.T, *gitWrite, *noteWorld)
	}{
		{"filler", func(t *testing.T, g *gitWrite, w *noteWorld) { g.publish(t, w, 9, g.people, g.e, true) }},
		{"another audience", func(t *testing.T, g *gitWrite, w *noteWorld) { g.publish(t, w, 9, other, g.e, false) }},
		{"two epochs old", func(t *testing.T, g *gitWrite, w *noteWorld) { g.publish(t, w, 9, g.people, g.e-2, false) }},
		{"no note tags", func(t *testing.T, g *gitWrite, w *noteWorld) {
			w.set(func() { w.tags = []string{"v1.2.3", "v0.1.0-beta.1"} })
		}},
		{"no repository", func(t *testing.T, g *gitWrite, w *noteWorld) { w.set(func() { w.mode = "404" }) }},
	} {
		w := newNoteWorld(t, testOwner, testRepo)
		g, _ := newGitWrite(t, w)
		tc.put(t, g, w)
		for _, c := range testGitCarriers(w, 5*time.Second) {
			notes, err := c.Fetch(context.Background(), g.env)
			if err != nil || len(notes) != 0 {
				t.Fatalf("%s / %s: %v %+v", tc.name, c.Info().Name, err, notes)
			}
		}
	}
}

// The newest note tag is filler, an older one this epoch's note: the
// micro note is still found; the full note (only the newest is read) is
// not.
func TestGitCarriers_NewestFirst(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, _ := newGitWrite(t, w)
	g.publish(t, w, 7, g.people, g.e, false)
	g.publish(t, w, 8, g.people, g.e, true)
	for _, c := range testGitCarriers(w, 5*time.Second) {
		notes, err := c.Fetch(context.Background(), g.env)
		if err != nil || len(notes) != 1 || notes[0].Kind != NoteMicro {
			t.Fatalf("%s: %v %+v", c.Info().Name, err, notes)
		}
	}
}

// A redirect is never followed and is "nothing new".
func TestGitCarriers_RedirectNotFollowed(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, d := newGitWrite(t, w)
	g.publish(t, w, 1, g.people, g.e, false)
	w.set(func() { w.mode = "redirect" })
	for _, c := range testGitCarriers(w, 5*time.Second) {
		notes, err := c.Fetch(context.Background(), g.env)
		if err != nil || len(notes) != 0 {
			t.Fatalf("%s: %v %+v", c.Info().Name, err, notes)
		}
	}
	for _, a := range d.addrs {
		if strings.HasPrefix(a, "evil.example") {
			t.Fatal("a redirect was followed")
		}
	}
	for _, r := range w.requests() {
		if strings.Contains(r, "evil.example") {
			t.Fatal("a redirect was followed")
		}
	}
}

// An answer past the bound, a portal page, a stalled server: errors (a
// strike), and none names the repository. A version list grown past the
// bound (jsDelivr, the Go proxies) is the repository's size, not the
// network: nothing new, no strike.
func TestGitCarriers_BadAnswersAreErrors(t *testing.T) {
	for _, mode := range []string{"huge", "html", "stall"} {
		w := newNoteWorld(t, testOwner, testRepo)
		g, _ := newGitWrite(t, w)
		g.publish(t, w, 1, g.people, g.e, false)
		w.set(func() { w.mode = mode })
		for _, c := range testGitCarriers(w, 300*time.Millisecond) {
			start := time.Now()
			notes, err := c.Fetch(context.Background(), g.env)
			if mode == "huge" && c.Info().Name != "github" {
				if err != nil || len(notes) != 0 {
					t.Fatalf("huge index / %s: %v %+v (want nothing new)", c.Info().Name, err, notes)
				}
				continue
			}
			if err == nil || len(notes) != 0 {
				t.Fatalf("%s / %s: %v %+v", mode, c.Info().Name, err, notes)
			}
			if el := time.Since(start); el > 3*time.Second {
				t.Fatalf("%s / %s: took %v", mode, c.Info().Name, el)
			}
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, strings.ToLower(testOwner)) || strings.Contains(msg, "relay.notes") || strings.Contains(msg, "v0.1.0-") {
				t.Fatalf("%s / %s: the error names the repository: %v", mode, c.Info().Name, err)
			}
		}
	}
}

// The ladder's ctx ends a fetch.
func TestGitCarriers_HonourContext(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, _ := newGitWrite(t, w)
	w.set(func() { w.mode = "stall" })
	for _, c := range testGitCarriers(w, 10*time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		start := time.Now()
		_, err := c.Fetch(ctx, g.env)
		cancel()
		if err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("%s: %v after %v", c.Info().Name, err, time.Since(start))
		}
	}
}

func TestGitCarriers_Unconfigured(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	for name, mut := range map[string]func(*CarrierEnv){
		"no member": func(e *CarrierEnv) { e.Carriers = nil },
		"no gittag": func(e *CarrierEnv) {
			e.Carriers = &bundle.UpdateCarriers{DNS: &bundle.DNSCarrier{Zone: "n.example.com"}}
		},
		"bad owner":   func(e *CarrierEnv) { e.Carriers.GitTag.Owner = "a/b" },
		"bad repo":    func(e *CarrierEnv) { e.Carriers.GitTag.Repo = "../x" },
		"no secrets":  func(e *CarrierEnv) { e.Secrets = nil },
		"nil secrets": func(e *CarrierEnv) { e.Secrets = []*bundle.UpdateSecret{nil} },
	} {
		g, d := newGitWrite(t, w)
		mut(g.env)
		for _, c := range testGitCarriers(w, time.Second) {
			if c.Usable(g.env) {
				t.Fatalf("%s / %s: usable", name, c.Info().Name)
			}
			if _, err := c.Fetch(context.Background(), g.env); !errors.Is(err, ErrCarrierUnconfigured) {
				t.Fatalf("%s / %s: %v", name, c.Info().Name, err)
			}
		}
		if len(d.addrs) != 0 {
			t.Fatalf("%s: dialled %v", name, d.addrs)
		}
	}
}

// jsDelivr: the next CDN host only when the previous one's network
// failed; the github carrier keeps its micro note when raw fails.
func TestGitCarriers_Fallbacks(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, d := newGitWrite(t, w)
	g.publish(t, w, 1, g.people, g.e, false)
	d.fail = map[string]bool{"cdn.jsdelivr.net": true, "raw.githubusercontent.com": true}
	cs := testGitCarriers(w, 5*time.Second)
	notes, err := cs[1].Fetch(context.Background(), g.env)
	if err != nil || len(notes) != 2 {
		t.Fatalf("jsdelivr: %v %+v", err, notes)
	}
	var fastly bool
	for _, r := range w.requests() {
		fastly = fastly || strings.HasPrefix(r, "fastly.jsdelivr.net|")
		if strings.HasPrefix(r, "gcore.jsdelivr.net|") {
			t.Fatal("gcore asked after fastly answered")
		}
	}
	if !fastly {
		t.Fatal("fastly not asked")
	}
	notes, err = cs[0].Fetch(context.Background(), g.env)
	if err != nil || len(notes) != 1 || notes[0].Kind != NoteMicro {
		t.Fatalf("github with raw cut: %v %+v", err, notes)
	}
	d.fail["github.com"] = true
	if _, err := cs[0].Fetch(context.Background(), g.env); err == nil {
		t.Fatal("github cut: no error")
	}
}

// The feed holds the newest 10 tags: a note pushed out of it by ten
// newer tags is not seen (and that is "nothing new").
func TestGitHubCarrier_FeedHoldsTen(t *testing.T) {
	w := newNoteWorld(t, testOwner, testRepo)
	g, _ := newGitWrite(t, w)
	g.publish(t, w, 1, g.people, g.e, false)
	for i := 0; i < 10; i++ {
		w.set(func() { w.tags = append([]string{fmt.Sprintf("v1.%d.0", i)}, w.tags...) })
	}
	notes, err := testGitCarriers(w, 5*time.Second)[0].Fetch(context.Background(), g.env)
	if err != nil || len(notes) != 0 {
		t.Fatalf("%v %+v", err, notes)
	}
}

func TestParseAtomTagNames(t *testing.T) {
	sealed, _ := bundle.MicroFiller(rand.Reader)
	tag := bundle.GitNoteTag(5, sealed)
	feed := atomFeed("o", "r", []string{tag, "v1.0.0"})
	names, err := parseAtomTagNames([]byte(feed))
	if err != nil {
		t.Fatal(err)
	}
	got := noteTagsFrom(names)
	if len(got) != 1 || got[0].name != tag || got[0].seq != 5 || got[0].sealed != sealed {
		t.Fatalf("%+v from %v", got, names)
	}
	// Only the title is there, without its v.
	only := `<feed><entry><title>` + strings.TrimPrefix(tag, "v") + `</title></entry></feed>`
	if names, _ := parseAtomTagNames([]byte(only)); len(noteTagsFrom(names)) != 1 {
		t.Fatalf("title only: %v", names)
	}
	for name, body := range map[string]string{
		"doctype":  `<!DOCTYPE feed [<!ENTITY x "` + tag + `">]><feed><entry><title>&x;</title></entry></feed>`,
		"entity":   `<feed><!ENTITY x "y"><entry></entry></feed>`,
		"not feed": `<html><body>` + tag + `</body></html>`,
		"too big":  `<feed>` + strings.Repeat(" ", noteIndexMax) + `</feed>`,
	} {
		if _, err := parseAtomTagNames([]byte(body)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Entities and markup in a text are skipped, not expanded.
	for _, body := range []string{
		`<feed><entry><title>v0.5.0-&amp;` + tag[7:] + `</title></entry></feed>`,
		`<feed><entry><title><![CDATA[` + tag + `]]></title></entry></feed>`,
	} {
		names, err := parseAtomTagNames([]byte(body))
		if err != nil || len(noteTagsFrom(names)) != 0 {
			t.Fatalf("%q: %v %v", body, names, err)
		}
	}
}

func TestNoteTagsFrom_OrderAndBound(t *testing.T) {
	var names []string
	for i := 0; i < 100; i++ {
		s, _ := bundle.MicroFiller(rand.Reader)
		names = append(names, bundle.GitNoteTag(uint64(i), s))
	}
	mrand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	names = append(names, names[0], "v0.01.0-aaaaaaaaaaaaaaaaaaaaaaaaaa", "garbage")
	got := noteTagsFrom(names)
	if len(got) != maxNoteTags || got[0].seq != 99 || got[maxNoteTags-1].seq != 99-maxNoteTags+1 {
		t.Fatalf("len %d first %d", len(got), got[0].seq)
	}
}

func TestGoModNoteText(t *testing.T) {
	text := strings.Repeat("QUJD", 40) + "RA=="
	mod := goModWith("o", "r", text) + "\nrequire example.com/x v1.0.0 // indirect\n// a comment in words\n"
	if got := string(goModNoteText([]byte(mod))); got != text {
		t.Fatalf("got %q", got)
	}
	if goModuleEscape("github.com/Pub-Acct/R.x") != "github.com/!pub-!acct/!r.x" {
		t.Fatal("escape")
	}
}

func TestParseJSDelivrVersions_BothShapes(t *testing.T) {
	for _, body := range []string{
		`{"type":"gh","name":"o/r","versions":[{"version":"0.1.0-abc","links":{}},{"version":"1.0.0"}]}`,
		`{"tags":{},"versions":["0.1.0-abc","1.0.0"]}`,
	} {
		v, err := parseJSDelivrVersions([]byte(body))
		if err != nil || len(v) != 2 || v[0] != "0.1.0-abc" {
			t.Fatalf("%s: %v %v", body, v, err)
		}
	}
	if _, err := parseJSDelivrVersions([]byte(`<html>`)); err == nil {
		t.Fatal("html accepted")
	}
	if _, err := parseJSDelivrVersions([]byte(`{"x":1}`)); err == nil {
		t.Fatal("no versions accepted")
	}
}
