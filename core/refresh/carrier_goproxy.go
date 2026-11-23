// carrier_goproxy.go — the Go module proxies as readers of the git-tag
// note write (docs/update-ladder-v2.md §4.2 door 3, §4.4; wave 0 §1–2).
//
// A Go module proxy serves any public GitHub repository with a go.mod:
//
//	/github.com/<o>/<r>/@v/list           the versions, one per line, in
//	                                      no particular order: the note
//	                                      tags among them carry the micro
//	                                      note (carrier_gittag.go);
//	/github.com/<o>/<r>/@v/<version>.mod  that tag's go.mod, comments
//	                                      kept (wave 0 §1): the full note.
//
// Four readers, each one host, two requests:
//
//	goproxy-front   proxy.golang.org through Google's front
//	                (bootstrap.FrontSession: SNI www.google.com, no
//	                redirect, both requests on ONE connection, so it
//	                counts one of the walk's two connections to Google).
//	                Class google, rung 2 (door 3).
//	goproxy-direct  proxy.golang.org by its own name.
//	goproxy-cn      goproxy.cn.
//	goproxy-io      goproxy.io.                   (class goproxy, rung 4)
//
// The module path is case-encoded as the proxies require (each upper-
// case letter becomes '!' and its lower case), so the go.mod's module
// line must be github.com/<o>/<r> exactly as the carriers member spells
// them.
//
// THE FULL NOTE IN go.mod. Its text (bundle.EncodeFullNoteText) is the
// concatenation, in file order, of every line that is a "//" comment
// whose text (after "//" and any blanks) is non-empty and only of the
// base64 alphabet; every other line (module, go, a comment in words) is
// ignored. The writer puts no other base64-looking comment in it.
//
// The rules of carrier_gittag.go hold here: the repository only from the
// carriers member, candidates only, "nothing new" for anything that is
// not a note for us, nothing logged.

package refresh

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

func init() {
	RegisterCarrier(&goProxyCarrier{name: "goproxy-front", host: bootstrap.GoProxyHost, front: true,
		class: ClassGoogle, rung: RungGoogle})
	RegisterCarrier(&goProxyCarrier{name: "goproxy-direct", host: bootstrap.GoProxyHost,
		class: ClassGoProxy, rung: RungReaders})
	RegisterCarrier(&goProxyCarrier{name: "goproxy-cn", host: "goproxy.cn",
		class: ClassGoProxy, rung: RungReaders})
	RegisterCarrier(&goProxyCarrier{name: "goproxy-io", host: "goproxy.io",
		class: ClassGoProxy, rung: RungReaders})
}

// goProxyCarrier is one Go module proxy, direct or through the front.
type goProxyCarrier struct {
	name, host   string
	front        bool
	class        string
	rung         int
	opts         bootstrap.BrowserGetOptions // tests (RootCAs direct; Timeout both)
	frontOptions bootstrap.FrontOptions      // tests (front)
}

func (c *goProxyCarrier) Info() CarrierInfo {
	tcp := 2
	if c.front {
		tcp = 1 // one front connection carries both requests
	}
	return CarrierInfo{Name: c.name, Label: bundle.NoteCarrierGitTag, Class: c.class, Rung: c.rung,
		Cost: CarrierCost{TCP: tcp}, Kinds: NoteBoth}
}

func (*goProxyCarrier) Usable(env *CarrierEnv) bool { return gitTagUsable(env) }

func (c *goProxyCarrier) Fetch(ctx context.Context, env *CarrierEnv) ([]Note, error) {
	o, r, ok := gitTagConf(env)
	if !ok || !gitTagUsable(env) {
		return nil, ErrCarrierUnconfigured
	}
	base := "/" + goModuleEscape("github.com/"+o+"/"+r) + "/@v/"
	var sess *bootstrap.FrontSession
	defer func() { sess.Close() }()
	if c.front {
		timeout := c.opts.Timeout
		if timeout <= 0 {
			timeout = carrierRequestTimeout
		}
		var err error
		sess, err = bootstrap.OpenFrontSession(ctx, c.host, env.Dialer, 2*timeout,
			noteIndexMax+fullNoteReadMax, c.frontOptions)
		if err != nil {
			return nil, fmt.Errorf("refresh: %s: %w", c.name, err)
		}
	}
	list, found, err := c.get(ctx, env, sess, base+"list", noteIndexMax)
	if err != nil {
		if errors.Is(err, bootstrap.ErrResponseTooLarge) {
			// A version list grown past the bound: nothing new, no
			// strike (the proxy keeps every version it ever saw).
			return nil, nil
		}
		return nil, fmt.Errorf("refresh: %s: %w", c.name, err)
	}
	if !found {
		return nil, nil
	}
	if !goVersionListOK(list) {
		return nil, fmt.Errorf("refresh: %s: %w", c.name, errCarrierShape)
	}
	tags := noteTagsFrom(strings.Fields(string(list)))
	if len(tags) == 0 {
		return nil, nil
	}
	notes := microFromTags(env, c.name, tags)
	mod, found, err := c.get(ctx, env, sess, base+goModuleEscape(tags[0].name)+".mod", fullNoteReadMax)
	if err != nil {
		if len(notes) > 0 {
			return notes, nil
		}
		return nil, fmt.Errorf("refresh: %s: %w", c.name, err)
	}
	if found {
		if n, ok := fullFromText(env, c.name, goModNoteText(mod)); ok {
			notes = append(notes, n)
		}
	}
	return notes, nil
}

// get is one request on the carrier's host, direct or (sess set) on the
// one front connection, with browserFetch's three outcomes. Through the
// front, an answer from Google that is not a 200 (a 404 or 410 for an
// unknown version, a refused redirect) is "not here".
func (c *goProxyCarrier) get(ctx context.Context, env *CarrierEnv, sess *bootstrap.FrontSession, path string, max int) ([]byte, bool, error) {
	if sess == nil {
		return browserFetch(ctx, env, c.opts, c.host, path, "*/*", max)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	body, err := sess.Get(path, max)
	if err != nil {
		if errors.Is(err, bootstrap.ErrFrontRefused) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return body, true, nil
}

// goModuleEscape is the Go proxy protocol's case encoding of a module
// path or version: each upper-case ASCII letter becomes '!' and its
// lower case. The inputs here are already restricted to
// [A-Za-z0-9._/-] (bundle.GitOwnerOK, GitRepoOK, the tag shape).
func goModuleEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// goVersionListOK: a version list is lines of printable ASCII without
// markup (an HTML portal page is not one). Empty is a valid list.
func goVersionListOK(b []byte) bool {
	for _, c := range b {
		if c == '<' || c == '>' || (c < ' ' && c != '\n' && c != '\r' && c != '\t') || c >= 0x7f {
			return false
		}
	}
	return true
}

// goModNoteText extracts the full note's text from a go.mod (see the
// file comment).
func goModNoteText(mod []byte) []byte {
	var out []byte
	for _, line := range strings.Split(string(mod), "\n") {
		line = strings.TrimSpace(line)
		text, ok := strings.CutPrefix(line, "//")
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text != "" && base64Only(text) {
			out = append(out, text...)
		}
	}
	return out
}

func base64Only(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}
