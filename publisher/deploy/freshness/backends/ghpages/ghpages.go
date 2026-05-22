// Package ghpages is the GitHub Pages freshness backend.
//
// Mechanism: PUT /repos/{owner}/{repo}/contents/{path} with a
// fine-grained PAT (Contents: Read+Write). GitHub Pages serves
// the file at https://<owner>.github.io/<repo>/<path> after
// a build cycle (typically ~30s). The recipient fetches that
// URL via plain HTTPS GET.
//
// This file is allowlisted by publisher/deploy/opsec_test.go to
// use net/http.

package ghpages

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config configures one GitHub Pages backend.
type Config struct {
	Owner string
	Repo  string
	Path  string // e.g. "freshness/<relay_pack_id>.json"
	// PAT is a fine-grained personal access token with
	// Contents: Read+Write on the repo. Caller zeroizes after
	// the upload.
	PAT []byte
	// Branch defaults to "main".
	Branch string
	// PublicReadURL is the recipient-facing https://owner.github.io/repo/path URL.
	PublicReadURL string
	HTTPClient    *http.Client
}

// Backend uploads signed freshness JSON to GitHub Pages.
type Backend struct {
	cfg Config
}

// New constructs a Backend.
func New(cfg Config) (*Backend, error) {
	if cfg.Owner == "" || cfg.Repo == "" || cfg.Path == "" {
		return nil, errors.New("ghpages: owner+repo+path required")
	}
	if len(cfg.PAT) == 0 {
		return nil, errors.New("ghpages: PAT required")
	}
	if cfg.PublicReadURL == "" {
		return nil, errors.New("ghpages: public read URL required")
	}
	if !strings.HasPrefix(cfg.PublicReadURL, "https://") {
		return nil, errors.New("ghpages: public read URL must be https")
	}
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Backend{cfg: cfg}, nil
}

// PublicURL returns the recipient-facing HTTPS URL.
func (b *Backend) PublicURL() string { return b.cfg.PublicReadURL }

// Put uploads body to the configured repo path. PUT
// /repos/{owner}/{repo}/contents/{path}; if the path already
// exists, the API requires the prior file's SHA — fetched by a
// preliminary GET. We follow the documented two-step pattern.
func (b *Backend) Put(ctx context.Context, body []byte) error {
	if len(body) == 0 {
		return errors.New("ghpages: empty body")
	}
	priorSHA, err := b.getCurrentSHA(ctx)
	if err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", b.cfg.Owner, b.cfg.Repo, b.cfg.Path)
	payload := map[string]string{
		"message": "freshness update",
		"content": base64.StdEncoding.EncodeToString(body),
		"branch":  b.cfg.Branch,
	}
	if priorSHA != "" {
		payload["sha"] = priorSHA
	}
	pj, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(pj))
	if err != nil {
		return fmt.Errorf("ghpages: build PUT: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(b.cfg.PAT))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("ghpages: PUT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ghpages: PUT status %d: %s", resp.StatusCode, string(preview))
	}
	return nil
}

// getCurrentSHA fetches the existing file's SHA so PUT replaces
// it atomically. Returns errNotFound if the path does not yet
// exist (first-time upload).
func (b *Backend) getCurrentSHA(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s",
		b.cfg.Owner, b.cfg.Repo, b.cfg.Path, b.cfg.Branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+string(b.cfg.PAT))
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errNotFound
	}
	if resp.StatusCode/100 != 2 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("ghpages: GET status %d: %s", resp.StatusCode, string(preview))
	}
	var meta struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&meta); err != nil {
		return "", err
	}
	return meta.SHA, nil
}

var errNotFound = errors.New("ghpages: not found")
