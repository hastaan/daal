package ghpages

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNew_RequiresFields(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("want err on empty")
	}
	if _, err := New(Config{Owner: "o", Repo: "r", Path: "p"}); err == nil {
		t.Error("want err missing PAT")
	}
	if _, err := New(Config{Owner: "o", Repo: "r", Path: "p", PAT: []byte("t"), PublicReadURL: "http://insecure"}); err == nil {
		t.Error("want err on http URL")
	}
}

func TestPut_FirstUploadHappyPath(t *testing.T) {
	var gotPUT bool
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/contents/freshness.json", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			gotPUT = true
			body, _ := io.ReadAll(r.Body)
			var p map[string]string
			if err := json.Unmarshal(body, &p); err != nil {
				t.Errorf("PUT body parse: %v", err)
			}
			if p["content"] == "" {
				t.Error("missing content")
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	b, err := New(Config{
		Owner:         "o",
		Repo:          "r",
		Path:          "freshness.json",
		PAT:           []byte("token"),
		PublicReadURL: "https://o.github.io/r/freshness.json",
		HTTPClient:    ts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Re-target to the test server.
	b.cfg.HTTPClient = ts.Client()
	// Override URLs: rebuild putFunc by injecting our base
	// through the package's behaviour. Simplest: monkey-patch
	// requests by replacing the HTTPClient with one whose
	// Transport rewrites api.github.com -> ts.URL.
	b.cfg.HTTPClient = &http.Client{Transport: rewritingTransport{base: ts.URL}}

	if err := b.Put(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !gotPUT {
		t.Error("PUT was never called")
	}
}

func TestPut_ReplaceExisting_PassesSHA(t *testing.T) {
	var gotSHA string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/contents/freshness.json", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"sha":"deadbeef"}`))
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var p map[string]string
			_ = json.Unmarshal(body, &p)
			gotSHA = p["sha"]
			w.WriteHeader(http.StatusOK)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	b, err := New(Config{
		Owner:         "o",
		Repo:          "r",
		Path:          "freshness.json",
		PAT:           []byte("t"),
		PublicReadURL: "https://x.example.com/y",
	})
	if err != nil {
		t.Fatal(err)
	}
	b.cfg.HTTPClient = &http.Client{Transport: rewritingTransport{base: ts.URL}}
	if err := b.Put(context.Background(), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if gotSHA != "deadbeef" {
		t.Errorf("PUT did not include prior sha: %q", gotSHA)
	}
}

func TestPut_RejectsEmptyBody(t *testing.T) {
	b, _ := New(Config{Owner: "o", Repo: "r", Path: "p", PAT: []byte("t"), PublicReadURL: "https://x.example.com/y"})
	if err := b.Put(context.Background(), nil); err == nil {
		t.Error("want err")
	}
}

// rewritingTransport rewrites api.github.com host to base URL host.
type rewritingTransport struct{ base string }

func (rt rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.String(), "https://api.github.com") {
		newURL := strings.Replace(req.URL.String(), "https://api.github.com", rt.base, 1)
		newReq := req.Clone(req.Context())
		newReq.URL, _ = req.URL.Parse(newURL)
		newReq.Host = ""
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}
