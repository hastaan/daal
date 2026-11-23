// Package gittagtest is a fake GitHub REST API for the git-tag write's
// tests: the handful of calls gittag makes (who am I, repositories,
// contents, the Git Data API's trees, commits and refs), held in
// memory, with real git object ids for trees so a test proves what was
// stored. Nothing here reaches the network.
package gittagtest

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Account is a token's owner as /user answers it.
type Account struct {
	Login string
	Type  string // "User" by default
	// Scopes: nil = a fine-grained token (no X-OAuth-Scopes header);
	// non-nil = a classic token with these scopes.
	Scopes []string
	// Expires, when set, is the GitHub-Authentication-Token-Expiration header.
	Expires string
	// NoAdmin: creating a repository answers 403. NoContents: every
	// write answers 403.
	NoAdmin, NoContents bool
}

// Blob is one stored file.
type Blob struct{ Content []byte }

// Commit is one stored commit.
type Commit struct {
	SHA, Tree, Message string
	Parents            []string
}

// Repo is one repository.
type Repo struct {
	Owner, Name   string
	Private       bool
	Archived      bool
	DefaultBranch string
	Branches      map[string]string // name -> commit
	Tags          map[string]string // name -> commit
	Commits       map[string]*Commit
	Trees         map[string]map[string][]byte // tree sha -> path -> content
	CreateBody    map[string]any               // what POST /user/repos sent
}

// Fault makes one call fail. Match is "METHOD /path-suffix-or-prefix";
// see Fake.Fail.
type Fault struct {
	Match   string
	Status  int
	Headers map[string]string
	Body    string
	Times   int // how many times; 0 = always
}

// Fake is one fake GitHub.
type Fake struct {
	srv *httptest.Server

	mu       sync.Mutex
	Accounts map[string]*Account // token -> account
	Repos    map[string]*Repo    // "owner/name" (lower case) -> repo
	Calls    []string            // "METHOD path" of every request
	Bodies   []string            // every request body, in order
	faults   []*Fault
	next     int
}

// New starts a fake. Close it with Close.
func New() *Fake {
	f := &Fake{Accounts: map[string]*Account{}, Repos: map[string]*Repo{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// URL is the API base.
func (f *Fake) URL() string { return f.srv.URL }

// Client is an HTTP client for the fake.
func (f *Fake) Client() *http.Client { return f.srv.Client() }

// Close stops the fake.
func (f *Fake) Close() { f.srv.Close() }

// AddToken registers a token.
func (f *Fake) AddToken(token string, a *Account) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.Type == "" {
		a.Type = "User"
	}
	f.Accounts[token] = a
}

// Fail adds a fault: a request whose "METHOD path" starts with
// fault.Match answers fault.Status.
func (f *Fake) Fail(fault Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl := fault
	f.faults = append(f.faults, &fl)
}

// ClearFaults removes every fault.
func (f *Fake) ClearFaults() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = nil
}

// AddRepo stores a repository as it is (tests that start from an
// existing one). files, when non-nil, become its first commit.
func (f *Fake) AddRepo(owner, name string, private bool, files map[string][]byte) *Repo {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.newRepo(owner, name, private)
	if files != nil {
		tree := f.putTree(r, files)
		c := f.putCommit(r, tree, "init", nil)
		r.Branches[r.DefaultBranch] = c
	}
	return r
}

// Repo returns a stored repository (nil if none).
func (f *Fake) Repo(owner, name string) *Repo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Repos[strings.ToLower(owner+"/"+name)]
}

// Files returns the files of the commit a ref (branch or tag) names.
func (f *Fake) Files(owner, name, ref string) map[string][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.Repos[strings.ToLower(owner+"/"+name)]
	if r == nil {
		return nil
	}
	sha, ok := r.Tags[ref]
	if !ok {
		sha = r.Branches[ref]
	}
	c := r.Commits[sha]
	if c == nil {
		return nil
	}
	return r.Trees[c.Tree]
}

// TagNames returns a repository's tags, sorted.
func (f *Fake) TagNames(owner, name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.Repos[strings.ToLower(owner+"/"+name)]
	if r == nil {
		return nil
	}
	var out []string
	for t := range r.Tags {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Writes counts the requests that change something.
func (f *Fake) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if !strings.HasPrefix(c, "GET ") {
			n++
		}
	}
	return n
}

// CallCount counts every request.
func (f *Fake) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

func (f *Fake) newRepo(owner, name string, private bool) *Repo {
	r := &Repo{Owner: owner, Name: name, Private: private, DefaultBranch: "main",
		Branches: map[string]string{}, Tags: map[string]string{},
		Commits: map[string]*Commit{}, Trees: map[string]map[string][]byte{}}
	f.Repos[strings.ToLower(owner+"/"+name)] = r
	return r
}

// TreeSHA is git's id of a tree of regular files.
func TreeSHA(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var body bytes.Buffer
	for _, n := range names {
		h := sha1.New()
		h.Write([]byte("blob " + strconv.Itoa(len(files[n])) + "\x00"))
		h.Write(files[n])
		body.WriteString("100644 " + n + "\x00")
		body.Write(h.Sum(nil))
	}
	h := sha1.New()
	h.Write([]byte("tree " + strconv.Itoa(body.Len()) + "\x00"))
	h.Write(body.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

func (f *Fake) putTree(r *Repo, files map[string][]byte) string {
	sha := TreeSHA(files)
	r.Trees[sha] = files
	return sha
}

func (f *Fake) putCommit(r *Repo, tree, msg string, parents []string) string {
	f.next++
	h := sha1.Sum([]byte(fmt.Sprintf("commit %d %s", f.next, tree)))
	sha := hex.EncodeToString(h[:])
	r.Commits[sha] = &Commit{SHA: sha, Tree: tree, Message: msg, Parents: parents}
	return sha
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func msg(w http.ResponseWriter, status int, m string) {
	writeJSON(w, status, map[string]string{"message": m})
}

func (f *Fake) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	path := req.URL.EscapedPath()
	call := req.Method + " " + path
	f.Calls = append(f.Calls, call)
	f.Bodies = append(f.Bodies, string(body))

	for _, fl := range f.faults {
		if fl.Times < 0 || !strings.HasPrefix(call, fl.Match) {
			continue
		}
		if fl.Times > 0 {
			fl.Times--
			if fl.Times == 0 {
				fl.Times = -1
			}
		}
		for k, v := range fl.Headers {
			w.Header().Set(k, v)
		}
		b := fl.Body
		if b == "" {
			b = `{"message":"fault"}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fl.Status)
		_, _ = io.WriteString(w, b)
		return
	}

	tok, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	acct := f.Accounts[tok]
	if !ok || acct == nil {
		msg(w, http.StatusUnauthorized, "Bad credentials")
		return
	}

	if call == "GET /user" {
		if acct.Scopes != nil {
			w.Header().Set("X-OAuth-Scopes", strings.Join(acct.Scopes, ", "))
		}
		if acct.Expires != "" {
			w.Header().Set("GitHub-Authentication-Token-Expiration", acct.Expires)
		}
		writeJSON(w, 200, map[string]any{"login": acct.Login, "type": acct.Type, "id": 1})
		return
	}
	if call == "POST /user/repos" {
		if acct.NoAdmin {
			msg(w, http.StatusForbidden, "Resource not accessible by personal access token")
			return
		}
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		name, _ := in["name"].(string)
		if f.Repos[strings.ToLower(acct.Login+"/"+name)] != nil {
			msg(w, http.StatusUnprocessableEntity, "Repository creation failed.")
			return
		}
		private, _ := in["private"].(bool)
		r := f.newRepo(acct.Login, name, private)
		r.CreateBody = in
		writeJSON(w, 201, map[string]any{"name": name, "private": private})
		return
	}

	rest, ok := strings.CutPrefix(path, "/repos/")
	if !ok {
		msg(w, 404, "Not Found")
		return
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		msg(w, 404, "Not Found")
		return
	}
	r := f.Repos[strings.ToLower(parts[0]+"/"+parts[1])]
	if r == nil {
		msg(w, 404, "Not Found")
		return
	}
	sub := ""
	if len(parts) == 3 {
		sub = parts[2]
	}
	owns := strings.EqualFold(acct.Login, r.Owner)
	write := req.Method != http.MethodGet
	if write && (acct.NoContents || !owns) {
		msg(w, http.StatusForbidden, "Resource not accessible by personal access token")
		return
	}
	empty := len(r.Branches) == 0

	switch {
	case req.Method == "GET" && sub == "":
		writeJSON(w, 200, map[string]any{
			"name": r.Name, "private": r.Private, "archived": r.Archived,
			"default_branch": r.DefaultBranch, "owner": map[string]any{"login": r.Owner},
			"permissions": map[string]any{"push": owns && !acct.NoContents, "pull": true},
		})
	case req.Method == "GET" && strings.HasPrefix(sub, "git/ref/heads/"):
		if empty {
			msg(w, 409, "Git Repository is empty.")
			return
		}
		sha, ok := r.Branches[strings.TrimPrefix(sub, "git/ref/heads/")]
		if !ok {
			msg(w, 404, "Not Found")
			return
		}
		writeJSON(w, 200, map[string]any{"ref": "refs/heads/x", "object": map[string]any{"sha": sha, "type": "commit"}})
	case req.Method == "GET" && strings.HasPrefix(sub, "git/ref/tags/"):
		name := strings.TrimPrefix(sub, "git/ref/tags/")
		sha, ok := r.Tags[name]
		if !ok {
			msg(w, 404, "Not Found")
			return
		}
		writeJSON(w, 200, map[string]any{"ref": "refs/tags/" + name, "object": map[string]any{"sha": sha, "type": "commit"}})
	case req.Method == "GET" && strings.HasPrefix(sub, "git/matching-refs/tags/"):
		if empty {
			msg(w, 409, "Git Repository is empty.")
			return
		}
		prefix := strings.TrimPrefix(sub, "git/matching-refs/tags/")
		out := []any{}
		names := make([]string, 0, len(r.Tags))
		for n := range r.Tags {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				out = append(out, map[string]any{"ref": "refs/tags/" + n, "object": map[string]any{"sha": r.Tags[n], "type": "commit"}})
			}
		}
		// GitHub's paging: per_page (default 30, at most 100), page from 1.
		per, page := 30, 1
		if v, err := strconv.Atoi(req.URL.Query().Get("per_page")); err == nil && v > 0 {
			per = min(v, 100)
		}
		if v, err := strconv.Atoi(req.URL.Query().Get("page")); err == nil && v > 0 {
			page = v
		}
		lo := min((page-1)*per, len(out))
		hi := min(lo+per, len(out))
		writeJSON(w, 200, out[lo:hi])
	case req.Method == "GET" && strings.HasPrefix(sub, "git/commits/"):
		c := r.Commits[strings.TrimPrefix(sub, "git/commits/")]
		if c == nil {
			msg(w, 404, "Not Found")
			return
		}
		writeJSON(w, 200, map[string]any{"sha": c.SHA, "message": c.Message, "tree": map[string]any{"sha": c.Tree}})
	case req.Method == "GET" && strings.HasPrefix(sub, "git/trees/"):
		sha := strings.TrimPrefix(sub, "git/trees/")
		files, ok := r.Trees[sha]
		if !ok {
			msg(w, 404, "Not Found")
			return
		}
		var entries []any
		for n, c := range files {
			entries = append(entries, map[string]any{"path": n, "mode": "100644", "type": "blob", "size": len(c), "sha": "x"})
		}
		writeJSON(w, 200, map[string]any{"sha": sha, "tree": entries, "truncated": false})
	case req.Method == "PUT" && strings.HasPrefix(sub, "contents/"):
		p := strings.TrimPrefix(sub, "contents/")
		var in struct {
			Message, Content, SHA string
		}
		_ = json.Unmarshal(body, &in)
		raw, err := base64.StdEncoding.DecodeString(in.Content)
		if err != nil {
			msg(w, 422, "content is not base64")
			return
		}
		files := map[string][]byte{}
		var parents []string
		if head, ok := r.Branches[r.DefaultBranch]; ok {
			if _, exists := r.Trees[r.Commits[head].Tree][p]; exists && in.SHA == "" {
				msg(w, 422, `"sha" wasn't supplied.`)
				return
			}
			for k, v := range r.Trees[r.Commits[head].Tree] {
				files[k] = v
			}
			parents = []string{head}
		}
		files[p] = raw
		c := f.putCommit(r, f.putTree(r, files), in.Message, parents)
		r.Branches[r.DefaultBranch] = c
		writeJSON(w, 201, map[string]any{"commit": map[string]any{"sha": c}})
	case req.Method == "POST" && sub == "git/trees":
		if empty {
			msg(w, 409, "Git Repository is empty.")
			return
		}
		var in struct {
			BaseTree string `json:"base_tree"`
			Tree     []struct {
				Path, Mode, Type, Content string
			} `json:"tree"`
		}
		if err := json.Unmarshal(body, &in); err != nil || in.BaseTree != "" {
			msg(w, 422, "bad tree")
			return
		}
		files := map[string][]byte{}
		for _, e := range in.Tree {
			if e.Mode != "100644" || e.Type != "blob" {
				msg(w, 422, "bad entry")
				return
			}
			files[e.Path] = []byte(e.Content)
		}
		writeJSON(w, 201, map[string]any{"sha": f.putTree(r, files)})
	case req.Method == "POST" && sub == "git/commits":
		var in struct {
			Message string   `json:"message"`
			Tree    string   `json:"tree"`
			Parents []string `json:"parents"`
		}
		_ = json.Unmarshal(body, &in)
		if _, ok := r.Trees[in.Tree]; !ok {
			msg(w, 422, "tree missing")
			return
		}
		writeJSON(w, 201, map[string]any{"sha": f.putCommit(r, in.Tree, in.Message, in.Parents)})
	case req.Method == "PATCH" && strings.HasPrefix(sub, "git/refs/heads/"):
		b := strings.TrimPrefix(sub, "git/refs/heads/")
		var in struct {
			SHA   string `json:"sha"`
			Force bool   `json:"force"`
		}
		_ = json.Unmarshal(body, &in)
		c := r.Commits[in.SHA]
		if c == nil {
			msg(w, 422, "commit missing")
			return
		}
		old := r.Branches[b]
		ff := false
		for _, p := range c.Parents {
			if p == old {
				ff = true
			}
		}
		if !ff && !in.Force {
			msg(w, 422, "Update is not a fast forward")
			return
		}
		r.Branches[b] = in.SHA
		writeJSON(w, 200, map[string]any{"ref": "refs/heads/" + b})
	case req.Method == "DELETE" && strings.HasPrefix(sub, "git/refs/tags/"):
		name := strings.TrimPrefix(sub, "git/refs/tags/")
		if _, ok := r.Tags[name]; !ok {
			msg(w, 422, "Reference does not exist")
			return
		}
		delete(r.Tags, name)
		w.WriteHeader(http.StatusNoContent)
	case req.Method == "POST" && sub == "git/refs":
		var in struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		}
		_ = json.Unmarshal(body, &in)
		name, ok := strings.CutPrefix(in.Ref, "refs/tags/")
		if !ok || r.Commits[in.SHA] == nil {
			msg(w, 422, "bad ref")
			return
		}
		if _, exists := r.Tags[name]; exists {
			msg(w, 422, "Reference already exists")
			return
		}
		r.Tags[name] = in.SHA
		writeJSON(w, 201, map[string]any{"ref": in.Ref})
	default:
		msg(w, 404, "Not Found")
	}
}
