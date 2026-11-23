// carrier_gittag.go — the readers of the git-tag note write on GitHub
// itself and on jsDelivr (docs/update-ladder-v2.md §4.1 "Read", §4.4;
// specs/update-ladder-v2.md §4.3 "Git tag form", §4.4).
//
// The publisher's app writes, in the repository the carriers member
// names (update/carriers.json, `gittag`), a tag
// v0.<seq>.0-<26 base32 symbols of the sealed micro note> on a commit
// whose file `n` holds the sealed full note's text (and whose go.mod
// holds the same text in comment lines, for the Go proxies:
// carrier_goproxy.go). Two readers here:
//
//	github    github.com/<o>/<r>/tags.atom → the tag names (the micro
//	          note); raw.githubusercontent.com/<o>/<r>/<tag>/n for the
//	          newest note tag → the full note. Two connections, both to
//	          GitHub (study: "at most two requests to GitHub per walk").
//	jsdelivr  data.jsdelivr.com/v1/packages/gh/<o>/<r> → the version
//	          list (tag names without the leading v, newest first);
//	          /gh/<o>/<r>@<tag>/n on cdn., then fastly., then
//	          gcore.jsdelivr.net (the next only when the previous one's
//	          NETWORK failed) → the full note.
//
// RULES EVERY READER HERE KEEPS (and carrier_goproxy.go too):
//   - owner and repository come only from the held carriers member;
//   - what is read is a CANDIDATE: a micro note only when the signed
//     commitment accepts it (env.OpenMicro), a full note only when a
//     held secret opens it, and the ladder checks both again;
//   - a tag of another shape, filler, a note for another audience or
//     epoch, a 404 or a redirect is "nothing new" (no notes, no error);
//     only a failed network or an answer of the wrong shape is an error
//     (a strike against the class);
//   - nothing is logged, and no error names the repository, a tag, a
//     path or a note.
//
// The feed holds the newest 10 tags only (wave 0, §2): the reader never
// depends on an older tag being in it, and the writer keeps note tags
// the repository's only tags.

package refresh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

const (
	// noteIndexMax bounds a tag feed or version list (study §4.4: 64 KiB).
	noteIndexMax = 64 << 10
	// maxNoteTags is how many note tags (newest first) a reader weighs.
	maxNoteTags = 64
	// carrierRequestTimeout bounds one request (the ladder's ctx bounds
	// the whole walk).
	carrierRequestTimeout = 15 * time.Second

	hostGitHub    = "github.com"
	hostGitHubRaw = "raw.githubusercontent.com"
	hostJSDData   = "data.jsdelivr.com"
)

// fullNoteReadMax bounds a full note's file or go.mod: the largest
// sealed note's text plus room for its carrier's wrapping (go.mod
// comment markers and line breaks, the module and go lines). Within
// bootstrap.FrontMaxBodyLimit and BrowserGetMaxBodyLimit.
var fullNoteReadMax = bundle.MaxSealedFullNoteText + 32<<10

// jsDelivrFileHosts are tried in this order for the full note.
var jsDelivrFileHosts = []string{"cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net"}

func init() {
	RegisterCarrier(&gitHubCarrier{})
	RegisterCarrier(&jsDelivrCarrier{})
}

// --- shared by every reader of the git-tag write ---------------------------

// gitTagConf is the repository the held carriers member names.
func gitTagConf(env *CarrierEnv) (owner, repo string, ok bool) {
	if env == nil || env.Carriers == nil || env.Carriers.GitTag == nil {
		return "", "", false
	}
	o, r := env.Carriers.GitTag.Owner, env.Carriers.GitTag.Repo
	if !bundle.GitOwnerOK(o) || !bundle.GitRepoOK(r) {
		return "", "", false
	}
	return o, r, true
}

// gitTagUsable: a repository is named and a held secret can open a full
// note there (a micro note further needs the signed standby).
func gitTagUsable(env *CarrierEnv) bool {
	_, _, ok := gitTagConf(env)
	return ok && len(env.Tries(bundle.NoteCarrierGitTag, NoteFull)) > 0
}

// noteTag is one tag of the note shape.
type noteTag struct {
	name   string // canonical, with the leading v
	seq    uint64
	sealed [bundle.MicroNoteLen]byte
}

// noteTagsFrom keeps the names of the note shape (a missing leading v
// is put back: jsDelivr and the feed's titles drop it), without
// duplicates, newest (highest seq) first, at most maxNoteTags.
func noteTagsFrom(names []string) []noteTag {
	seen := map[string]bool{}
	var out []noteTag
	for _, n := range names {
		if !strings.HasPrefix(n, "v") {
			n = "v" + n
		}
		seq, sealed, ok := bundle.ParseGitNoteTag(n)
		if !ok || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, noteTag{name: n, seq: seq, sealed: sealed})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].seq > out[b].seq })
	if len(out) > maxNoteTags {
		out = out[:maxNoteTags]
	}
	return out
}

// microFromTags is the first tag (newest first) whose micro note the
// signed commitment accepts, as a one-note slice; nil when none does.
func microFromTags(env *CarrierEnv, carrier string, tags []noteTag) []Note {
	if env.Standby == nil {
		return nil
	}
	for _, t := range tags {
		if n, ok := env.OpenMicro(carrier, bundle.NoteCarrierGitTag, t.sealed); ok {
			return []Note{n}
		}
	}
	return nil
}

// fullFromText opens a full note's text form: filler, a note no held
// secret opens, or text of the wrong shape is (Note{}, false).
func fullFromText(env *CarrierEnv, carrier string, text []byte) (Note, bool) {
	raw, err := bundle.DecodeFullNoteText(string(text))
	if err != nil {
		return Note{}, false
	}
	return env.OpenFull(carrier, bundle.NoteCarrierGitTag, raw)
}

// errCarrierAnswer is an answer of a status that is neither "here it
// is" nor "not here": a strike. The status alone is in the message.
type errCarrierAnswer struct{ status int }

func (e *errCarrierAnswer) Error() string {
	return fmt.Sprintf("refresh: carrier answered HTTP %d", e.status)
}

// errCarrierShape: a 200 whose body is not what this reader reads (a
// portal page, an error page): a strike.
var errCarrierShape = errors.New("refresh: carrier answer of the wrong shape")

// browserFetch is one GET through env.Dialer: (body, true, nil) for a
// 200; (nil, false, nil) for "not here" (404, 410, any redirect — never
// followed); an error for a failed network or another status.
func browserFetch(ctx context.Context, env *CarrierEnv, opts bootstrap.BrowserGetOptions, host, path, accept string, max int) ([]byte, bool, error) {
	o := opts
	o.Accept, o.MaxBody = accept, max
	if o.Timeout <= 0 {
		o.Timeout = carrierRequestTimeout
	}
	res, err := bootstrap.BrowserGet(ctx, env.Dialer, host, path, o)
	if err != nil {
		return nil, false, err
	}
	switch {
	case res.Status == 200:
		return res.Body, true, nil
	case res.Status == 404 || res.Status == 410 || (res.Status >= 300 && res.Status < 400):
		return nil, false, nil
	}
	return nil, false, &errCarrierAnswer{res.Status}
}

// --- github ----------------------------------------------------------------

// gitHubCarrier reads tags.atom and the raw file on GitHub.
type gitHubCarrier struct {
	opts bootstrap.BrowserGetOptions // tests: RootCAs, Timeout
}

func (*gitHubCarrier) Info() CarrierInfo {
	return CarrierInfo{Name: "github", Label: bundle.NoteCarrierGitTag, Class: ClassGitHub, Rung: RungGitTag,
		Cost: CarrierCost{TCP: 2}, Kinds: NoteBoth}
}

func (*gitHubCarrier) Usable(env *CarrierEnv) bool { return gitTagUsable(env) }

func (c *gitHubCarrier) Fetch(ctx context.Context, env *CarrierEnv) ([]Note, error) {
	o, r, ok := gitTagConf(env)
	if !ok || !gitTagUsable(env) {
		return nil, ErrCarrierUnconfigured
	}
	name := c.Info().Name
	feed, found, err := browserFetch(ctx, env, c.opts, hostGitHub, "/"+o+"/"+r+"/tags.atom",
		"application/atom+xml,application/xml;q=0.9,*/*;q=0.8", noteIndexMax)
	if err != nil {
		return nil, fmt.Errorf("refresh: %s: %w", name, err)
	}
	if !found {
		return nil, nil
	}
	names, err := parseAtomTagNames(feed)
	if err != nil {
		return nil, fmt.Errorf("refresh: %s: %w", name, err)
	}
	tags := noteTagsFrom(names)
	if len(tags) == 0 {
		return nil, nil
	}
	notes := microFromTags(env, name, tags)
	text, found, err := browserFetch(ctx, env, c.opts, hostGitHubRaw, "/"+o+"/"+r+"/"+tags[0].name+"/n",
		"*/*", fullNoteReadMax)
	if err != nil {
		if len(notes) > 0 {
			// The micro note is in hand; the raw host failing does not
			// take it back.
			return notes, nil
		}
		return nil, fmt.Errorf("refresh: %s: %w", name, err)
	}
	if found {
		if n, ok := fullFromText(env, name, text); ok {
			notes = append(notes, n)
		}
	}
	return notes, nil
}

// --- jsdelivr --------------------------------------------------------------

// jsDelivrCarrier reads jsDelivr's version list and file.
type jsDelivrCarrier struct {
	opts bootstrap.BrowserGetOptions
}

func (*jsDelivrCarrier) Info() CarrierInfo {
	return CarrierInfo{Name: "jsdelivr", Label: bundle.NoteCarrierGitTag, Class: ClassJSDelivr, Rung: RungReaders,
		Cost: CarrierCost{TCP: 1 + len(jsDelivrFileHosts)}, Kinds: NoteBoth}
}

func (*jsDelivrCarrier) Usable(env *CarrierEnv) bool { return gitTagUsable(env) }

func (c *jsDelivrCarrier) Fetch(ctx context.Context, env *CarrierEnv) ([]Note, error) {
	o, r, ok := gitTagConf(env)
	if !ok || !gitTagUsable(env) {
		return nil, ErrCarrierUnconfigured
	}
	name := c.Info().Name
	list, found, err := browserFetch(ctx, env, c.opts, hostJSDData, "/v1/packages/gh/"+o+"/"+r,
		"application/json", noteIndexMax)
	if err != nil {
		if errors.Is(err, bootstrap.ErrResponseTooLarge) {
			// A list grown past the bound is the repository's size,
			// not the network: nothing new, no strike.
			return nil, nil
		}
		return nil, fmt.Errorf("refresh: %s: %w", name, err)
	}
	if !found {
		return nil, nil
	}
	versions, err := parseJSDelivrVersions(list)
	if err != nil {
		return nil, fmt.Errorf("refresh: %s: %w", name, err)
	}
	tags := noteTagsFrom(versions)
	if len(tags) == 0 {
		return nil, nil
	}
	notes := microFromTags(env, name, tags)
	path := "/gh/" + o + "/" + r + "@" + tags[0].name + "/n"
	var last error
	for _, host := range jsDelivrFileHosts {
		if ctx.Err() != nil {
			break
		}
		text, found, err := browserFetch(ctx, env, c.opts, host, path, "*/*", fullNoteReadMax)
		if err != nil {
			var ans *errCarrierAnswer
			last = err
			if errors.As(err, &ans) {
				// jsDelivr answered; its other CDNs serve the same
				// origin and would answer the same.
				break
			}
			continue
		}
		last = nil
		if found {
			if n, ok := fullFromText(env, name, text); ok {
				notes = append(notes, n)
			}
		}
		break
	}
	if last != nil && len(notes) == 0 {
		return nil, fmt.Errorf("refresh: %s: %w", name, last)
	}
	return notes, nil
}

// parseJSDelivrVersions reads data.jsdelivr.com's package answer: its
// "versions" member is a list of objects {"version": "..."} (the
// /v1/packages shape wave 0 recorded) or of plain strings (the older
// /v1/package shape). Other members are ignored.
func parseJSDelivrVersions(b []byte) ([]string, error) {
	var doc struct {
		Versions []json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Versions == nil {
		return nil, errCarrierShape
	}
	out := make([]string, 0, len(doc.Versions))
	for _, raw := range doc.Versions {
		raw = bytes.TrimSpace(raw)
		var s string
		if len(raw) > 0 && raw[0] == '"' {
			if json.Unmarshal(raw, &s) != nil {
				continue
			}
		} else {
			var v struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(raw, &v) != nil {
				continue
			}
			s = v.Version
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// --- the Atom tag extractor ------------------------------------------------

// maxAtomEntries bounds the entries weighed (GitHub's feed has 10).
const maxAtomEntries = 64

// parseAtomTagNames reads the tag names out of a GitHub tags.atom feed.
// It is NOT an XML parser and expands nothing: a feed with a DOCTYPE or
// an entity declaration is refused, and a text holding '&', '<' or a
// CDATA section is skipped (no note tag ever needs one). For each
// <entry>, the names it offers are the end of its <id>
// (tag:github.com,2008:Repository/<n>/<tag>), the end of each <link>
// href after /releases/tag/, and its <title>; the caller keeps those of
// the note shape. A body without a <feed> is the wrong shape.
func parseAtomTagNames(b []byte) ([]string, error) {
	if len(b) > noteIndexMax {
		return nil, errCarrierShape
	}
	s := string(b)
	low := strings.ToLower(s)
	if strings.Contains(low, "<!doctype") || strings.Contains(low, "<!entity") {
		return nil, errCarrierShape
	}
	if _, ok := atomStartTag(s, "feed"); !ok {
		return nil, errCarrierShape
	}
	var out []string
	rest := s
	for n := 0; n < maxAtomEntries; n++ {
		at, ok := atomStartTag(rest, "entry")
		if !ok {
			break
		}
		rest = rest[at:]
		end := strings.Index(rest, "</entry>")
		if end < 0 {
			break
		}
		entry := rest[:end]
		rest = rest[end+len("</entry>"):]
		if id, ok := atomElementText(entry, "id"); ok {
			if i := strings.LastIndexByte(id, '/'); i >= 0 {
				out = append(out, id[i+1:])
			}
		}
		for _, href := range atomLinkHrefs(entry) {
			if _, tag, ok := strings.Cut(href, "/releases/tag/"); ok {
				out = append(out, tag)
			}
		}
		if title, ok := atomElementText(entry, "title"); ok {
			out = append(out, title)
		}
	}
	return out, nil
}

// atomStartTag is the index just past the '>' of the first start tag
// <name …> in s (an empty element <name/> counts).
func atomStartTag(s, name string) (int, bool) {
	from := 0
	for {
		i := strings.Index(s[from:], "<"+name)
		if i < 0 {
			return 0, false
		}
		i += from
		j := i + 1 + len(name)
		if j < len(s) && (s[j] == '>' || s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r' || s[j] == '/') {
			k := strings.IndexByte(s[j:], '>')
			if k < 0 {
				return 0, false
			}
			return j + k + 1, true
		}
		from = j
	}
}

// atomElementText is the trimmed text of the first <name>…</name> in s,
// false when absent or when it holds markup or an entity.
func atomElementText(s, name string) (string, bool) {
	at, ok := atomStartTag(s, name)
	if !ok || strings.HasSuffix(s[:at], "/>") {
		return "", false
	}
	end := strings.Index(s[at:], "</"+name+">")
	if end < 0 {
		return "", false
	}
	text := strings.TrimSpace(s[at : at+end])
	if text == "" || strings.ContainsAny(text, "&<>") {
		return "", false
	}
	return text, true
}

// atomLinkHrefs are the href values of the <link> start tags in s, those
// holding an entity skipped.
func atomLinkHrefs(s string) []string {
	var out []string
	rest := s
	for {
		i := strings.Index(rest, "<link")
		if i < 0 {
			return out
		}
		rest = rest[i+len("<link"):]
		k := strings.IndexByte(rest, '>')
		if k < 0 {
			return out
		}
		tag := rest[:k]
		rest = rest[k+1:]
		for _, q := range []string{`href="`, `href='`} {
			j := strings.Index(tag, q)
			if j < 0 {
				continue
			}
			v := tag[j+len(q):]
			e := strings.IndexByte(v, q[len(q)-1])
			if e < 0 {
				break
			}
			if v = v[:e]; !strings.ContainsAny(v, "&<>") {
				out = append(out, v)
			}
			break
		}
	}
}
