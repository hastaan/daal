package gittag

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// PublishInput is one publish for one audience of one relay.
type PublishInput struct {
	Owner, Repo string
	// Secret is the audience's u and its audience name.
	Secret bundle.UpdateSecret
	// StandbyCommit is the relay's signed _standby.commit (standard
	// base64 of 32 bytes). Required with StandbyKey; otherwise it lets a
	// filler run see that this epoch already has a reveal.
	StandbyCommit string
	// StandbyKey, when set, is revealed in the micro note (it must match
	// StandbyCommit). Nil: micro filler.
	StandbyKey *bundle.StandbyKeyBytes
	// Container, when set, is the daal-refresh-v2 container revealed in
	// the full note; its slot is set to name(gittag, e) here. Nil: full
	// filler.
	Container []byte
	// Seq numbers the tag. It must be above every seq already in the
	// repository (all audiences share one sequence).
	Seq uint64
	// Now picks the epoch. Zero: time.Now().
	Now time.Time
	// FillerBucket is the padded size of full filler (4096, 16384 or
	// 65536). Zero: the size of the note the repository holds now, or
	// 16384 when it holds none. A reveal's size is its container's.
	FillerBucket int
}

// Outcomes of the two notes.
const (
	NoteReveal = "reveal"
	NoteFiller = "filler"
)

// Reasons a publish changed nothing.
const (
	// ReasonAlreadyPublished: a tag already holds exactly this publish
	// (a retry, or a second run). Seq is that tag's.
	ReasonAlreadyPublished = "already_published"
	// ReasonEpochWritten: nothing to reveal, and this audience already
	// has a tag this epoch (filler, or a reveal filler must not hide).
	ReasonEpochWritten = "epoch_written"
)

// PublishResult is what a publish did. It names no tag, name or file
// content (they are derived from the secret).
type PublishResult struct {
	Changed     bool   `json:"changed"`
	Reason      string `json:"reason,omitempty"`
	CreatedRepo bool   `json:"created_repo"`
	Seq         uint64 `json:"seq"`
	HighestSeq  uint64 `json:"highest_seq"`
	Epoch       uint64 `json:"epoch"`
	Micro       string `json:"micro"`
	Full        string `json:"full"`
	FullBucket  int    `json:"full_bucket"`
}

// ErrSeqBehind: Seq is not above the highest seq in the repository.
// SeqBehindError carries that highest seq.
var ErrSeqBehind = errors.New("gittag: seq must be above every seq already published")

// SeqBehindError is ErrSeqBehind with the repository's highest seq.
type SeqBehindError struct{ Highest uint64 }

func (e *SeqBehindError) Error() string {
	return fmt.Sprintf("%v (highest is %d)", ErrSeqBehind, e.Highest)
}
func (e *SeqBehindError) Is(t error) bool { return t == ErrSeqBehind }

// ErrInput: the input cannot make a publish.
var ErrInput = errors.New("gittag: bad publish input")

// ErrTagTaken: the tag name is already used by another commit (two
// publishers with the same seq and the same micro note: not expected).
var ErrTagTaken = errors.New("gittag: the tag already exists on another commit")

type noteTag struct {
	name   string
	seq    uint64
	sealed [bundle.MicroNoteLen]byte
	commit string // "" for an annotated tag (not ours)
}

// planned is what a publish writes.
type planned struct {
	epoch  uint64
	micro  [bundle.MicroNoteLen]byte
	filler [bundle.MicroNoteLen]byte // this epoch's micro filler
	files  map[string][]byte
	tree   string
	res    PublishResult
}

func (in *PublishInput) validate() error {
	if !bundle.GitOwnerOK(in.Owner) || !bundle.GitRepoOK(in.Repo) {
		return ErrBadName
	}
	if !bundle.UpdateAudienceOK(in.Secret.Audience) {
		return fmt.Errorf("%w: not an audience", ErrInput)
	}
	if !bundle.MicroNoteAllowed(Label, in.Secret.Audience) {
		return fmt.Errorf("%w: this audience may not use the git tag", ErrInput)
	}
	if in.Seq == 0 {
		return fmt.Errorf("%w: seq starts at 1", ErrInput)
	}
	if in.StandbyCommit != "" {
		raw, err := base64.StdEncoding.Strict().DecodeString(in.StandbyCommit)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("%w: the standby commitment is not base64 of 32 bytes", ErrInput)
		}
	}
	if in.StandbyKey != nil {
		if in.StandbyCommit == "" {
			return fmt.Errorf("%w: revealing a standby key needs the relay's commitment", ErrInput)
		}
		if bundle.StandbyCommit(*in.StandbyKey) != in.StandbyCommit {
			return fmt.Errorf("%w: the standby key does not match the relay's commitment", ErrInput)
		}
	}
	if in.Container != nil {
		// Checked before any call, so a container Daal cannot carry
		// creates nothing. (plan sets the real slot.)
		if _, err := SlotContainer(in.Container, "", in.StandbyCommit); err != nil {
			return err
		}
	}
	switch in.FillerBucket {
	case 0, bundle.FullNoteBuckets[0], bundle.FullNoteBuckets[1], bundle.FullNoteBuckets[2]:
	default:
		return fmt.Errorf("%w: filler bucket is 4096, 16384 or 65536", ErrInput)
	}
	return nil
}

// plan builds the two notes and the files. headBucket is the bucket of
// the note the repository holds now (0: none).
func plan(in *PublishInput, now time.Time, headBucket int) (*planned, error) {
	u := in.Secret.Secret
	p := &planned{epoch: bundle.NoteEpochAt(Label, now)}
	e := p.epoch
	p.filler = MicroFiller(u, e)
	p.res.Epoch = e

	if in.StandbyKey != nil {
		m, err := bundle.SealMicroNote(u, Label, e, *in.StandbyKey)
		if err != nil {
			return nil, err
		}
		p.micro, p.res.Micro = m, NoteReveal
	} else {
		p.micro, p.res.Micro = p.filler, NoteFiller
	}

	var sealed []byte
	if in.Container != nil {
		slot, err := bundle.NoteName(u, Label, e)
		if err != nil {
			return nil, err
		}
		c, err := SlotContainer(in.Container, slot, in.StandbyCommit)
		if err != nil {
			return nil, err
		}
		if sealed, err = sealFull(u, e, c); err != nil {
			return nil, err
		}
		p.res.Full, p.res.FullBucket = NoteReveal, bundle.FullNoteBucket(len(c))
	} else {
		b := in.FillerBucket
		if b == 0 {
			b = headBucket
		}
		if b == 0 {
			b = bundle.FullNoteBuckets[1]
		}
		var err error
		if sealed, err = fullFiller(u, e, b); err != nil {
			return nil, err
		}
		p.res.Full, p.res.FullBucket = NoteFiller, b
	}
	text := bundle.EncodeFullNoteText(sealed)
	p.files = map[string][]byte{
		FileNote:  RenderNote(text),
		FileGoMod: RenderGoMod(in.Owner, in.Repo, text),
	}
	p.tree = gitTreeSHA(p.files)
	return p, nil
}

// Publish writes one publish (docs/update-ladder-v2.md §4.1):
//
//  1. EnsureRepo (create public if missing, first go.mod);
//  2. read the note tags (v0.<seq>.0-<26>; any other tag is ignored);
//  3. nothing changes when a tag already holds exactly this publish
//     (ReasonAlreadyPublished), or when there is nothing to reveal and
//     this audience already has a tag this epoch (ReasonEpochWritten:
//     filler never hides a reveal, and the start-of-epoch filler is
//     written once);
//  4. Seq must be above every seq present (ErrSeqBehind);
//  5. commit n and go.mod as the whole tree (skipped when the branch
//     already holds exactly these files: a half-finished run retried);
//  6. create the tag on that commit.
//
// The tag comes last, so a run killed at any step leaves no tag that
// points at missing files, and the next run finishes it.
func (c *Client) Publish(ctx context.Context, in PublishInput) (PublishResult, error) {
	if err := in.validate(); err != nil {
		return PublishResult{}, err
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	st, err := c.EnsureRepo(ctx, in.Owner, in.Repo)
	if err != nil {
		return PublishResult{}, err
	}
	headBucket := 0
	if e, ok := st.HeadFiles[FileNote]; ok {
		headBucket = bucketOfText(e.Size)
	}
	p, err := plan(&in, now, headBucket)
	if err != nil {
		return PublishResult{}, err
	}
	p.res.CreatedRepo = st.Created

	tags, err := c.noteTags(ctx, in.Owner, in.Repo)
	if err != nil {
		return p.res, err
	}
	for _, t := range tags {
		p.res.HighestSeq = max(p.res.HighestSeq, t.seq)
	}

	// 3. Nothing to do?
	if p.res.Micro == NoteFiller && p.res.Full == NoteFiller {
		for _, t := range tags {
			if t.sealed == p.filler || opensAt(&in, p.epoch, t.sealed) {
				p.res.Reason, p.res.Seq = ReasonEpochWritten, t.seq
				return p.res, nil
			}
		}
	}
	for _, t := range tags {
		if t.sealed != p.micro || t.commit == "" {
			continue
		}
		tree, err := c.commitTree(ctx, in.Owner, in.Repo, t.commit)
		if err != nil {
			return p.res, err
		}
		if tree == p.tree {
			p.res.Reason, p.res.Seq = ReasonAlreadyPublished, t.seq
			return p.res, nil
		}
	}

	// 4. Seq only grows.
	if in.Seq <= p.res.HighestSeq {
		return p.res, &SeqBehindError{Highest: p.res.HighestSeq}
	}

	// 5. The commit.
	commit := st.Head
	if st.HeadTree != p.tree {
		if commit, err = c.commitFiles(ctx, in.Owner, in.Repo, st.DefaultBranch, st.Head, p); err != nil {
			return p.res, err
		}
	}

	// 6. The tag.
	name := bundle.GitNoteTag(in.Seq, p.micro)
	if err := c.createTag(ctx, in.Owner, in.Repo, name, commit, p.tree); err != nil {
		return p.res, err
	}
	p.res.Changed, p.res.Seq = true, in.Seq
	p.res.HighestSeq = max(p.res.HighestSeq, in.Seq)
	// 7. Old note tags go, best effort: the readers bound their index
	// (a tag feed, a version list) and only the newest tags matter.
	c.pruneNoteTags(ctx, in.Owner, in.Repo, append(tags, noteTag{name: name, seq: in.Seq}))
	return p.res, nil
}

// KeepNoteTags is how many note tags (newest by seq) a publish leaves.
const KeepNoteTags = 40

// pruneNoteTags deletes the note tags beyond the newest KeepNoteTags by
// seq. Only note-shaped tags (they come from noteTags); a failure is
// ignored and never fails the publish.
func (c *Client) pruneNoteTags(ctx context.Context, owner, repo string, tags []noteTag) {
	if len(tags) <= KeepNoteTags {
		return
	}
	sorted := append([]noteTag(nil), tags...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].seq > sorted[j].seq })
	for _, t := range sorted[KeepNoteTags:] {
		if _, _, ok := bundle.ParseGitNoteTag(t.name); !ok || ctx.Err() != nil {
			continue
		}
		_, _, _ = c.call(ctx, "remove an old tag", http.MethodDelete,
			repoPath(owner, repo, "/git/refs/tags/"+url.PathEscape(t.name)), nil, nil, PermContents)
	}
}

// opensAt: the tag's micro note is a reveal of this relay's standby key
// for this audience at epoch e.
func opensAt(in *PublishInput, e uint64, sealed [bundle.MicroNoteLen]byte) bool {
	if in.StandbyCommit == "" {
		return false
	}
	k, err := bundle.MicroNoteCandidate(in.Secret.Secret, Label, e, in.StandbyCommit, sealed)
	return err == nil && bundle.StandbyCommit(k) == in.StandbyCommit
}

// tagPageSize and maxTagPages bound the tag listing (each page is also
// bounded by the client's response limit).
const (
	tagPageSize = 100
	maxTagPages = 50
)

// noteTags lists the repository's note tags. Tags of any other shape
// are not Daal's and are left alone.
func (c *Client) noteTags(ctx context.Context, owner, repo string) ([]noteTag, error) {
	type ref struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	// GitHub pages this list (30 by default): ask for full pages until
	// one comes back short.
	var refs []ref
	for page := 1; ; page++ {
		if page > maxTagPages {
			return nil, &APIError{Op: "list the tags", Status: http.StatusOK, Kind: KindGitHub}
		}
		var got []ref
		path := repoPath(owner, repo, "/git/matching-refs/tags/v0.") +
			"?per_page=" + strconv.Itoa(tagPageSize) + "&page=" + strconv.Itoa(page)
		status, _, err := c.call(ctx, "list the tags", http.MethodGet, path, nil, &got, "")
		if err != nil {
			if page == 1 && (status == http.StatusNotFound || status == http.StatusConflict) {
				return nil, nil
			}
			return nil, err
		}
		refs = append(refs, got...)
		if len(got) < tagPageSize {
			break
		}
	}
	var out []noteTag
	for _, r := range refs {
		name, ok := strings.CutPrefix(r.Ref, "refs/tags/")
		if !ok {
			continue
		}
		seq, sealed, ok := bundle.ParseGitNoteTag(name)
		if !ok {
			continue
		}
		t := noteTag{name: name, seq: seq, sealed: sealed}
		if r.Object.Type == "commit" {
			t.commit = r.Object.SHA
		}
		out = append(out, t)
	}
	return out, nil
}

// commitFiles writes the tree (n and go.mod, nothing else), a commit on
// parent, and moves the branch to it (fast-forward only).
func (c *Client) commitFiles(ctx context.Context, owner, repo, branch, parent string, p *planned) (string, error) {
	entries := make([]map[string]string, 0, 2)
	for _, name := range []string{FileGoMod, FileNote} {
		entries = append(entries, map[string]string{
			"path": name, "mode": "100644", "type": "blob", "content": string(p.files[name]),
		})
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if _, _, err := c.call(ctx, "write the files", http.MethodPost, repoPath(owner, repo, "/git/trees"),
		map[string]any{"tree": entries}, &tree, PermContents); err != nil {
		return "", err
	}
	if tree.SHA != p.tree {
		// GitHub stored something else than was sent.
		return "", &APIError{Op: "write the files", Status: http.StatusOK, Kind: KindGitHub}
	}
	body := map[string]any{"message": CommitMessage, "tree": tree.SHA, "parents": []string{parent}}
	var cm struct {
		SHA string `json:"sha"`
	}
	if _, _, err := c.call(ctx, "write the commit", http.MethodPost, repoPath(owner, repo, "/git/commits"), body, &cm, PermContents); err != nil {
		return "", err
	}
	if cm.SHA == "" {
		return "", &APIError{Op: "write the commit", Status: http.StatusOK, Kind: KindGitHub}
	}
	if _, _, err := c.call(ctx, "move the branch", http.MethodPatch,
		repoPath(owner, repo, "/git/refs/heads/"+url.PathEscape(branch)),
		map[string]any{"sha": cm.SHA, "force": false}, nil, PermContents); err != nil {
		return "", err
	}
	return cm.SHA, nil
}

// createTag makes refs/tags/<name> point at commit. If the name exists
// already (a retry whose answer was lost), it is accepted when it holds
// the same files.
func (c *Client) createTag(ctx context.Context, owner, repo, name, commit, tree string) error {
	_, _, err := c.call(ctx, "write the tag", http.MethodPost, repoPath(owner, repo, "/git/refs"),
		map[string]any{"ref": "refs/tags/" + name, "sha": commit}, nil, PermContents)
	if err == nil || !IsKind(err, KindConflict) {
		return err
	}
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if _, _, gerr := c.call(ctx, "read the tag", http.MethodGet, repoPath(owner, repo, "/git/ref/tags/"+url.PathEscape(name)), nil, &ref, ""); gerr != nil {
		return err
	}
	if ref.Object.SHA == commit {
		return nil
	}
	if ref.Object.Type == "commit" {
		if t, terr := c.commitTree(ctx, owner, repo, ref.Object.SHA); terr == nil && t == tree {
			return nil
		}
	}
	return ErrTagTaken
}
