// edge_ranges.go fetches Cloudflare's published edge IP ranges so
// the Helper can apply them to the cloud-provider firewall rule
// that locks origin 443/tcp to Cloudflare-only sources.
//
// Per supplement §11.7, this fetch runs from the FRP Helper
// machine (not from the origin box). The Helper holds the
// cloud-provider token; the origin box does not. The fetch
// triggers at deploy, rotate, the wizard "Verify CDN posture"
// button, and (optionally) a local OS scheduled task on the
// Helper. The opsec test at publisher/deploy/opsec_test.go
// allowlists THIS FILE (and only this file) to use net/http.

package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudflareEdgeRangesV4URL is the canonical published list.
const (
	CloudflareEdgeRangesV4URL = "https://www.cloudflare.com/ips-v4"
	CloudflareEdgeRangesV6URL = "https://www.cloudflare.com/ips-v6"
)

// EdgeRanges holds one freshly-fetched snapshot of Cloudflare's
// edge IP ranges.
type EdgeRanges struct {
	V4        []string
	V6        []string
	FetchedAt time.Time
}

// EdgeRangeFetcher fetches the IP-range lists. The default impl
// makes plain HTTPS GETs; tests inject a fake.
type EdgeRangeFetcher interface {
	FetchV4(ctx context.Context) ([]string, error)
	FetchV6(ctx context.Context) ([]string, error)
}

// HTTPSEdgeRangeFetcher is the production fetcher. It uses the
// stdlib net/http client with a 15-second timeout per request.
type HTTPSEdgeRangeFetcher struct {
	Client  *http.Client
	V4URL   string
	V6URL   string
	Timeout time.Duration
}

// NewHTTPSEdgeRangeFetcher returns a fetcher targeting the
// canonical Cloudflare URLs with a 15-second per-request timeout.
func NewHTTPSEdgeRangeFetcher() *HTTPSEdgeRangeFetcher {
	return &HTTPSEdgeRangeFetcher{
		Client:  &http.Client{Timeout: 15 * time.Second},
		V4URL:   CloudflareEdgeRangesV4URL,
		V6URL:   CloudflareEdgeRangesV6URL,
		Timeout: 15 * time.Second,
	}
}

// FetchV4 GETs the v4 list.
func (f *HTTPSEdgeRangeFetcher) FetchV4(ctx context.Context) ([]string, error) {
	return f.fetchList(ctx, f.V4URL)
}

// FetchV6 GETs the v6 list.
func (f *HTTPSEdgeRangeFetcher) FetchV6(ctx context.Context) ([]string, error) {
	return f.fetchList(ctx, f.V6URL)
}

func (f *HTTPSEdgeRangeFetcher) fetchList(ctx context.Context, url string) ([]string, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("edge_ranges: URL must be https: %q", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("edge_ranges: build request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("edge_ranges: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("edge_ranges: GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("edge_ranges: read body: %w", err)
	}
	return parseRangesBody(body), nil
}

// parseRangesBody splits the published text response into one CIDR
// per line, trims comments and whitespace.
func parseRangesBody(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// FetchEdgeRanges returns one fresh snapshot using the supplied
// fetcher. now is passed in so tests can pin FetchedAt.
func FetchEdgeRanges(ctx context.Context, f EdgeRangeFetcher, now func() time.Time) (*EdgeRanges, error) {
	if f == nil {
		return nil, errors.New("edge_ranges: fetcher required")
	}
	if now == nil {
		now = time.Now
	}
	v4, err := f.FetchV4(ctx)
	if err != nil {
		return nil, err
	}
	v6, err := f.FetchV6(ctx)
	if err != nil {
		return nil, err
	}
	return &EdgeRanges{V4: v4, V6: v6, FetchedAt: now().UTC()}, nil
}

// FirewallApplier abstracts the cloud-provider firewall update.
// Hetzner's adapter (publisher/deploy/providers/hetzner/firewall_cf.go)
// implements this. Vultr / Stark (FRP-10) plug in later.
type FirewallApplier interface {
	// ApplyCloudflareRule creates or updates a firewall rule
	// allowing inbound 443/tcp ONLY from the supplied edge
	// ranges. Returns the rule's provider-side ID.
	ApplyCloudflareRule(ctx context.Context, firewallID string, ranges *EdgeRanges) (string, error)
}

// RefreshFirewall is the Helper-side entry point: fetch fresh
// Cloudflare edge ranges, apply them via the FirewallApplier,
// return the new firewall ID. The wizard's "Verify CDN posture"
// button calls this; the FRP-7 rotation executor calls this on
// every rotate; cloud-init NEVER calls this (rule 5 of §11.7:
// origin box must not hold the cloud-provider token).
func RefreshFirewall(
	ctx context.Context,
	f EdgeRangeFetcher,
	a FirewallApplier,
	firewallID string,
	now func() time.Time,
) (newFirewallID string, ranges *EdgeRanges, err error) {
	ranges, err = FetchEdgeRanges(ctx, f, now)
	if err != nil {
		return "", nil, err
	}
	id, err := a.ApplyCloudflareRule(ctx, firewallID, ranges)
	if err != nil {
		return "", ranges, err
	}
	return id, ranges, nil
}
