package r2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNew_RequiresFields(t *testing.T) {
	cases := []Config{
		{},
		{AccountID: "a"},
		{AccountID: "a", Bucket: "b"},
		{AccountID: "a", Bucket: "b", ObjectKey: "k"},
		{AccountID: "a", Bucket: "b", ObjectKey: "k", PublicReadURL: "http://x"}, // not https
	}
	for i, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
}

func TestNew_HappyPath(t *testing.T) {
	b, err := New(Config{
		AccountID:     "acc-1",
		Bucket:        "buck",
		ObjectKey:     "key",
		PublicReadURL: "https://example.com/k",
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.PublicURL() != "https://example.com/k" {
		t.Errorf("PublicURL = %q", b.PublicURL())
	}
}

func TestPut_RejectsEmptyBody(t *testing.T) {
	b, _ := New(Config{
		AccountID:     "a",
		Bucket:        "b",
		ObjectKey:     "k",
		PublicReadURL: "https://x.example.com/k",
	})
	if err := b.Put(context.Background(), nil); err == nil {
		t.Error("want error on empty body")
	}
}

func TestPut_RequiresSecret(t *testing.T) {
	b, _ := New(Config{
		AccountID:     "a",
		Bucket:        "b",
		ObjectKey:     "k",
		PublicReadURL: "https://x.example.com/k",
	})
	err := b.Put(context.Background(), []byte("hi"))
	if err == nil || !strings.Contains(err.Error(), "secret access key") {
		t.Errorf("want secret-key error, got %v", err)
	}
}

func TestPut_SignsAndUploads(t *testing.T) {
	var gotAuth, gotHash string
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/bucket/freshness.json" {
			t.Errorf("path = %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotHash = r.Header.Get("X-Amz-Content-Sha256")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	b, _ := New(Config{
		AccountID:       "acc",
		Bucket:          "bucket",
		ObjectKey:       "freshness.json",
		AccessKeyID:     "AKIA_TEST",
		SecretAccessKey: []byte("secret"),
		PublicReadURL:   "https://cdn.example.com/freshness.json",
		HTTPClient:      &http.Client{Transport: rewriteR2{base: ts.URL}},
	})
	if err := b.Put(context.Background(), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != "payload" {
		t.Errorf("body = %q", string(gotBody))
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKIA_TEST/") {
		t.Errorf("missing SigV4 Authorization: %q", gotAuth)
	}
	if gotHash != sha256Hex([]byte("payload")) {
		t.Errorf("payload hash = %q", gotHash)
	}
}

type rewriteR2 struct{ base string }

func (rt rewriteR2) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, ".r2.cloudflarestorage.com") {
		newURL := strings.Replace(req.URL.String(), "https://"+req.URL.Host, rt.base, 1)
		newReq := req.Clone(req.Context())
		newReq.URL, _ = req.URL.Parse(newURL)
		newReq.Host = ""
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}
