// Package r2 is the Cloudflare R2 freshness backend.
//
// R2 is S3-compatible: PUT signed-bytes to
// https://<account>.r2.cloudflarestorage.com/<bucket>/<key> with
// AWS Sig v4 (account scope: R2). The bucket is configured for
// public access (or fronted by a Cloudflare Worker that proxies
// reads) so recipients can fetch it with plain HTTPS GET — the
// FreshnessURL field stores that public URL.
//
// This file is allowlisted by publisher/deploy/opsec_test.go to
// use net/http; no other file in the freshness package may make
// network calls.

package r2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Config configures one R2 backend. The wizard supplies these
// values; the API token + secret-access-key live in the OS
// keystore (NEVER in OperatorRecord JSON).
type Config struct {
	// AccountID is the Cloudflare account ID (zone-independent).
	AccountID string
	// Bucket is the R2 bucket name.
	Bucket string
	// ObjectKey is the path inside the bucket; the recipient
	// fetches /<ObjectKey> off the public URL.
	ObjectKey string
	// AccessKeyID + SecretAccessKey are the R2 S3-compatible
	// credentials. Caller is responsible for zeroizing both
	// after the upload.
	AccessKeyID     string
	SecretAccessKey []byte
	// PublicReadURL is the HTTPS URL recipients fetch. It
	// becomes Manifest.RelayPack.FreshnessURL.
	PublicReadURL string
	// HTTPClient is optional. Defaults to a 30s-timeout client.
	HTTPClient *http.Client
}

// Backend uploads signed freshness JSON via S3-compatible PUT.
type Backend struct {
	cfg Config
}

// New constructs a Backend. Returns an error if mandatory fields
// are missing.
func New(cfg Config) (*Backend, error) {
	if cfg.AccountID == "" {
		return nil, errors.New("r2: account ID required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("r2: bucket required")
	}
	if cfg.ObjectKey == "" {
		return nil, errors.New("r2: object key required")
	}
	if cfg.PublicReadURL == "" {
		return nil, errors.New("r2: public read URL required")
	}
	if !strings.HasPrefix(cfg.PublicReadURL, "https://") {
		return nil, errors.New("r2: public read URL must be https")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Backend{cfg: cfg}, nil
}

// PublicURL returns the recipient-facing HTTPS URL.
func (b *Backend) PublicURL() string { return b.cfg.PublicReadURL }

// Put uploads body to R2 via PUT.
func (b *Backend) Put(ctx context.Context, body []byte) error {
	if len(body) == 0 {
		return errors.New("r2: empty body")
	}
	if len(b.cfg.SecretAccessKey) == 0 {
		return errors.New("r2: secret access key required")
	}
	if b.cfg.AccessKeyID == "" {
		return errors.New("r2: access key id required")
	}
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s/%s", b.cfg.AccountID, b.cfg.Bucket, b.cfg.ObjectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("r2: build PUT: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Content-Sha256", sha256Hex(body))
	signV4(req, b.cfg.AccessKeyID, string(b.cfg.SecretAccessKey), body, time.Now().UTC())
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("r2: PUT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("r2: PUT status %d: %s", resp.StatusCode, string(preview))
	}
	return nil
}

func signV4(req *http.Request, accessKeyID, secret string, body []byte, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		req.Header.Set("X-Amz-Content-Sha256", sha256Hex(body))
	}
	if req.Header.Get("Host") == "" {
		req.Host = req.URL.Host
	}
	canonicalHeaders, signedHeaders := canonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		req.Header.Get("X-Amz-Content-Sha256"),
	}, "\n")
	scope := date + "/auto/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	key := sigKey(secret, date, "auto", "s3")
	sig := hmacHex(key, []byte(stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, scope, signedHeaders, sig,
	))
}

func sigKey(secret, date, region, service string) []byte {
	kDate := hmacBytes([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacBytes(kDate, []byte(region))
	kService := hmacBytes(kRegion, []byte(service))
	return hmacBytes(kService, []byte("aws4_request"))
}

func canonicalHeaders(req *http.Request) (string, string) {
	headers := map[string]string{
		"host":                 req.URL.Host,
		"content-type":         req.Header.Get("Content-Type"),
		"x-amz-content-sha256": req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":           req.Header.Get("X-Amz-Date"),
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(headers[k]))
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(keys, ";")
}

func canonicalURI(u *url.URL) string {
	if u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

func canonicalQuery(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacBytes(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacHex(key, data []byte) string { return hex.EncodeToString(hmacBytes(key, data)) }
