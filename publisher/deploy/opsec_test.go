package deploy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPublisherDeployHasNoTelemetry enforces invariant 22 (Position
// B). The publisher/deploy/ tree may open connections ONLY to:
//
//  1. The cloud-provider API (e.g. github.com/hetznercloud/hcloud-go).
//  2. The box's health endpoint over an IP-bound ufw rule, during
//     the 60-second provisioning window only.
//
// Any other outbound HTTP/TCP/DNS surface is a Position B violation.
//
// This test scans every non-test .go file under publisher/deploy/
// for forbidden tokens. Allowed tokens carry an explicit allowlist
// hint (the import path of hcloud-go, or the health-package's own
// types).
func TestPublisherDeployHasNoTelemetry(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(file) // .../publisher/deploy

	forbidden := []string{
		`"net/http"`,
		`net.Dial(`,
		`net.DialTimeout(`,
		`http.Post(`,
		`http.PostForm(`,
		`http.Get(`,
		`tls.Dial(`,
	}

	// Allowlisted import paths and call sites. A file containing
	// any of these is considered to be in the vetted set.
	allowlist := []string{
		"hetznercloud/hcloud-go",
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stripped := stripGoComments(string(body))

		// Per-package allowlist:
		//
		//  - publisher/deploy/health/ is the box-side handler +
		//    Helper-side poller (cmd/daal-relay-health); raw
		//    http.Server/Client types are expected.
		//
		//  - publisher/deploy/cloudflare/edge_ranges.go and
		//    cf_client_live.go are Helper-side Cloudflare API
		//    clients (§11.7): edge range refresh and live CDN
		//    provisioning happen from the Helper machine, never
		//    from the origin or recipient.
		isHealthPackage := strings.Contains(filepath.ToSlash(path), "/deploy/health/")
		isCloudflareAPIFile := strings.HasSuffix(filepath.ToSlash(path), "/deploy/cloudflare/edge_ranges.go") ||
			strings.HasSuffix(filepath.ToSlash(path), "/deploy/cloudflare/cf_client_live.go")
		// publisher/deploy/freshness/backends/r2 + ghpages
		// are the only places that PUT the signed freshness
		// JSON to FRP-controlled storage. Both are HTTPS
		// uploaders to FRP-supplied endpoints (Cloudflare R2
		// + GitHub API), called from the Helper at deploy +
		// rotate time.
		isFreshnessBackend := strings.Contains(filepath.ToSlash(path), "/deploy/freshness/backends/")
		// publisher/deploy/providers/stark is the FRP-10
		// REST wrapper (no SDK exists). Same trust model as
		// the Helper-side Cloudflare API client: token held in
		// Helper keystore, REST call to FRP-supplied provider
		// API, never from box or recipient.
		isStarkProviderClient := strings.HasSuffix(filepath.ToSlash(path), "/deploy/providers/stark/client.go")
		// publisher/deploy/mgmt is the Helper-side TLS-pinned
		// HTTPS client for daal-relay-mgmt running on the
		// FRP-owned box. It only ever connects to
		// rec.PublicIP:rec.MgmtPort with the cert fingerprint
		// pinned against rec.MgmtTLSFingerprint (FRP-10
		// invariant 26). Position B preserved: no telemetry
		// surface; only FRP-owned hosts.
		isMgmtClient := strings.Contains(filepath.ToSlash(path), "/deploy/mgmt/")

		for _, tok := range forbidden {
			if !strings.Contains(stripped, tok) {
				continue
			}
			if isHealthPackage {
				continue // health/ is allowed to use http.Client + http.Server
			}
			if isCloudflareAPIFile {
				continue // vetted Helper-side Cloudflare API calls
			}
			if isFreshnessBackend {
				continue // freshness/backends/* PUTs signed JSON to FRP-controlled storage
			}
			if isStarkProviderClient {
				continue // providers/stark/client.go is the FRP-10 REST wrapper (no SDK exists)
			}
			if isMgmtClient {
				continue // deploy/mgmt is the Helper-side TLS-pinned mgmt-plane client
			}
			ok := false
			for _, a := range allowlist {
				if strings.Contains(stripped, a) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s: forbidden token %q outside allowlist", path, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// stripGoComments removes line / block comments before scanning so
// docstrings discussing telemetry don't trigger false positives.
// Mirrors core/internal/selection/opsec_test.go::stripGoComments.
func stripGoComments(src string) string {
	var b strings.Builder
	inLineCmt := false
	inBlockCmt := false
	inString := false
	inRawString := false
	prev := byte(0)
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inLineCmt:
			if c == '\n' {
				inLineCmt = false
				b.WriteByte(c)
			}
		case inBlockCmt:
			if prev == '*' && c == '/' {
				inBlockCmt = false
			}
		case inString:
			b.WriteByte(c)
			if c == '"' && prev != '\\' {
				inString = false
			}
		case inRawString:
			b.WriteByte(c)
			if c == '`' {
				inRawString = false
			}
		default:
			if c == '/' && i+1 < len(src) && src[i+1] == '/' {
				inLineCmt = true
				i++
				continue
			}
			if c == '/' && i+1 < len(src) && src[i+1] == '*' {
				inBlockCmt = true
				i++
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				continue
			}
			if c == '`' {
				inRawString = true
				b.WriteByte(c)
				continue
			}
			b.WriteByte(c)
		}
		prev = c
	}
	return b.String()
}
