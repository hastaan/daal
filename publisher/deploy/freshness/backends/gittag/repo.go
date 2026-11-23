package gittag

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"daal/bundle-go/bundle"
)

// File names in the repository.
const (
	FileNote  = "n"
	FileGoMod = "go.mod"
)

// CommitMessage is every commit's message: constant, so it says nothing.
const CommitMessage = "update"

// Errors about the repository itself.
var (
	ErrBadName = errors.New("gittag: the owner or repository name is not a GitHub name")
	// ErrRepoPrivate: Go proxies and raw.githubusercontent.com cannot
	// read a private repository. Daal does not change its visibility.
	ErrRepoPrivate = errors.New("gittag: the repository is private; readers cannot see it")
	// ErrRepoArchived: an archived repository takes no writes.
	ErrRepoArchived = errors.New("gittag: the repository is archived")
	// ErrRepoNotOurs: the repository holds other files than n and
	// go.mod. A publish replaces the whole tree, so Daal refuses to
	// write over someone's project.
	ErrRepoNotOurs = errors.New("gittag: the repository holds other files; pick a repository only Daal writes to")
	// ErrOtherAccount: the repository does not exist and the token
	// belongs to another account, so it cannot be created there.
	ErrOtherAccount = errors.New("gittag: the repository is missing and the token belongs to another account")
	// ErrRepoUnseen: GitHub says the name is taken but the token
	// cannot see the repository (a fine-grained token limited to other
	// repositories).
	ErrRepoUnseen = errors.New("gittag: the repository exists but the token cannot see it")
)

// RepoState is what EnsureRepo found or made.
type RepoState struct {
	Created       bool   // EnsureRepo created the repository
	Initialized   bool   // EnsureRepo wrote the first go.mod
	DefaultBranch string // e.g. "main"
	// Head is the default branch's commit, its tree, and the tree's
	// files (name -> entry). Empty Head only before Initialized.
	Head      string
	HeadTree  string
	HeadFiles map[string]treeEntry
}

type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
}

type repoInfo struct {
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
	Permissions *struct {
		Push bool `json:"push"`
	} `json:"permissions"`
}

// ModulePath is the Go module path of the repository.
func ModulePath(owner, repo string) string { return "github.com/" + owner + "/" + repo }

// baseGoMod is the go.mod of a repository with no note yet.
func baseGoMod(owner, repo string) string {
	return "module " + ModulePath(owner, repo) + "\n\ngo 1.21\n"
}

// EnsureRepo makes sure github.com/<owner>/<repo> exists, is public,
// takes writes, holds only Daal's files, and has a first commit with a
// valid go.mod (the Git Data API refuses an empty repository, and a Go
// proxy serves only a module with a go.mod). Missing: it is created
// public under the token's account. Run twice, it changes nothing.
//
// The name comes from the caller (the carriers member), never from the
// relay; nothing about the relay is sent.
func (c *Client) EnsureRepo(ctx context.Context, owner, repo string) (RepoState, error) {
	var st RepoState
	if !bundle.GitOwnerOK(owner) || !bundle.GitRepoOK(repo) {
		return st, ErrBadName
	}
	info, found, err := c.getRepo(ctx, owner, repo)
	if err != nil {
		return st, err
	}
	if !found {
		if err := c.createRepo(ctx, owner, repo); err != nil {
			return st, err
		}
		st.Created = true
		info, found, err = c.getRepo(ctx, owner, repo)
		if err != nil {
			return st, err
		}
		if !found {
			return st, ErrRepoUnseen
		}
	}
	if info.Private {
		return st, ErrRepoPrivate
	}
	if info.Archived {
		return st, ErrRepoArchived
	}
	if info.Permissions != nil && !info.Permissions.Push {
		return st, &APIError{Op: "write to the repository", Status: http.StatusForbidden, Kind: KindMissingPermission, Permission: PermContents}
	}
	st.DefaultBranch = info.DefaultBranch
	if st.DefaultBranch == "" {
		st.DefaultBranch = "main"
	}

	head, ok, err := c.branchHead(ctx, owner, repo, st.DefaultBranch)
	if err != nil {
		return st, err
	}
	if !ok {
		if err := c.initGoMod(ctx, owner, repo, st.DefaultBranch); err != nil {
			return st, err
		}
		st.Initialized = true
		head, ok, err = c.branchHead(ctx, owner, repo, st.DefaultBranch)
		if err != nil {
			return st, err
		}
		if !ok {
			return st, &APIError{Op: "read the branch", Status: http.StatusNotFound, Kind: KindGitHub}
		}
	}
	st.Head = head
	if st.HeadTree, err = c.commitTree(ctx, owner, repo, head); err != nil {
		return st, err
	}
	if st.HeadFiles, err = c.treeFiles(ctx, owner, repo, st.HeadTree); err != nil {
		return st, err
	}
	for name, e := range st.HeadFiles {
		if (name != FileNote && name != FileGoMod) || e.Type != "blob" {
			return st, ErrRepoNotOurs
		}
	}
	return st, nil
}

func (c *Client) getRepo(ctx context.Context, owner, repo string) (repoInfo, bool, error) {
	var info repoInfo
	_, _, err := c.call(ctx, "read the repository", http.MethodGet, repoPath(owner, repo, ""), nil, &info, "")
	if IsKind(err, KindNotFound) {
		return info, false, nil
	}
	return info, err == nil, err
}

func (c *Client) createRepo(ctx context.Context, owner, repo string) error {
	// POST /user/repos creates under the token's account: make sure
	// that is the account asked for before creating anything.
	var u struct {
		Login string `json:"login"`
	}
	if _, _, err := c.call(ctx, "check the token", http.MethodGet, "/user", nil, &u, ""); err != nil {
		return err
	}
	if !strings.EqualFold(u.Login, owner) {
		return ErrOtherAccount
	}
	body := map[string]any{
		"name":          repo,
		"private":       false,
		"has_issues":    false,
		"has_projects":  false,
		"has_wiki":      false,
		"has_downloads": false,
		"auto_init":     false,
	}
	_, _, err := c.call(ctx, "create the repository", http.MethodPost, "/user/repos", body, nil, PermAdministration)
	if IsKind(err, KindConflict) {
		// 422 "name already exists": another run created it, or it
		// exists and the token cannot see it (the re-read decides).
		return nil
	}
	return err
}

// branchHead is the commit the branch points at; ok false for an empty
// repository (GitHub answers 409) or a missing branch (404).
func (c *Client) branchHead(ctx context.Context, owner, repo, branch string) (string, bool, error) {
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	status, _, err := c.call(ctx, "read the branch", http.MethodGet, repoPath(owner, repo, "/git/ref/heads/"+url.PathEscape(branch)), nil, &ref, "")
	if err != nil {
		if status == http.StatusNotFound || status == http.StatusConflict {
			return "", false, nil
		}
		return "", false, err
	}
	if ref.Object.SHA == "" {
		return "", false, &APIError{Op: "read the branch", Status: status, Kind: KindGitHub}
	}
	return ref.Object.SHA, true, nil
}

// initGoMod writes the first commit (go.mod only) through the contents
// API, which, unlike the Git Data API, works on an empty repository.
func (c *Client) initGoMod(ctx context.Context, owner, repo, branch string) error {
	body := map[string]any{
		"message": CommitMessage,
		"content": base64.StdEncoding.EncodeToString([]byte(baseGoMod(owner, repo))),
	}
	_, _, err := c.call(ctx, "write the first go.mod", http.MethodPut, repoPath(owner, repo, "/contents/"+FileGoMod), body, nil, PermContents)
	if IsKind(err, KindConflict) {
		// Another run wrote it first (422: "sha" wanted for an
		// existing file). The re-read of the branch decides.
		return nil
	}
	return err
}

func (c *Client) commitTree(ctx context.Context, owner, repo, commit string) (string, error) {
	var cm struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if _, _, err := c.call(ctx, "read a commit", http.MethodGet, repoPath(owner, repo, "/git/commits/"+url.PathEscape(commit)), nil, &cm, ""); err != nil {
		return "", err
	}
	if cm.Tree.SHA == "" {
		return "", &APIError{Op: "read a commit", Status: http.StatusOK, Kind: KindGitHub}
	}
	return cm.Tree.SHA, nil
}

func (c *Client) treeFiles(ctx context.Context, owner, repo, tree string) (map[string]treeEntry, error) {
	var t struct {
		Tree      []treeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if _, _, err := c.call(ctx, "read a tree", http.MethodGet, repoPath(owner, repo, "/git/trees/"+url.PathEscape(tree)), nil, &t, ""); err != nil {
		return nil, err
	}
	if t.Truncated {
		return nil, ErrRepoNotOurs
	}
	out := make(map[string]treeEntry, len(t.Tree))
	for _, e := range t.Tree {
		out[e.Path] = e
	}
	return out, nil
}
