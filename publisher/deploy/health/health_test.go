package health

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stubProbe is the in-memory Probe used by tests.
type stubProbe struct {
	out Status
	err error
}

func (s stubProbe) Snapshot(ctx context.Context) (Status, error) {
	return s.out, s.err
}

type sequenceProbe struct {
	out []Status
	i   int
}

func (s *sequenceProbe) Snapshot(ctx context.Context) (Status, error) {
	if s.i >= len(s.out) {
		return s.out[len(s.out)-1], nil
	}
	got := s.out[s.i]
	s.i++
	return got, nil
}

const testToken = "changeme-test-only-fixture-token-value"

func TestHandler_RejectsEmptyToken(t *testing.T) {
	if _, err := NewHandler(HandlerConfig{Token: "", Probe: stubProbe{}}); err == nil {
		t.Errorf("expected error for empty token")
	}
}

func TestHandler_RejectsNilProbe(t *testing.T) {
	if _, err := NewHandler(HandlerConfig{Token: testToken, Probe: nil}); err == nil {
		t.Errorf("expected error for nil probe")
	}
}

func TestHandler_404OnWrongToken(t *testing.T) {
	h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: stubProbe{}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz/wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d want 404", resp.StatusCode)
	}
}

func TestHandler_404OnWrongPath(t *testing.T) {
	h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: stubProbe{}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	for _, path := range []string{"/", "/health", "/healthcheck", "/healthz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("path %s: got %d want 404", path, resp.StatusCode)
		}
	}
}

func TestHandler_404OnWrongMethod(t *testing.T) {
	h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: stubProbe{}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/healthz/"+testToken, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST got %d want 404", resp.StatusCode)
	}
}

func TestHandler_404OnWrongRemoteIP(t *testing.T) {
	h, _ := NewHandler(HandlerConfig{
		Token:           testToken,
		AllowedClientIP: net.ParseIP("203.0.113.10"),
		Probe:           stubProbe{},
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz/"+testToken, nil)
	req.RemoteAddr = "198.51.100.20:44444"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("wrong remote IP got %d want 404", rec.Code)
	}
}

func TestHandler_AllowsConfiguredRemoteIP(t *testing.T) {
	h, _ := NewHandler(HandlerConfig{
		Token:           testToken,
		AllowedClientIP: net.ParseIP("203.0.113.10"),
		Probe:           stubProbe{out: Status{Healthy: true}},
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz/"+testToken, nil)
	req.RemoteAddr = "203.0.113.10:44444"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("allowed remote IP got %d want 200", rec.Code)
	}
}

func TestHandler_HappyPathReturnsJSON(t *testing.T) {
	probe := stubProbe{out: Status{
		Healthy:        true,
		BoxBootedAt:    time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		SingBoxRunning: true,
		DaalVersion:    "0.9.0+v3-share",
		UptimeSec:      42,
	}}
	h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: probe})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz/" + testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q want application/json", ct)
	}
}

func TestPoller_HitsBoxAndReturnsStatus(t *testing.T) {
	probe := stubProbe{out: Status{Healthy: true, DaalVersion: "0.9.0", UptimeSec: 1}}
	h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: probe})
	srv := httptest.NewServer(h)
	defer srv.Close()

	host, port, err := splitURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &Poller{
		BoxIP:   net.ParseIP(host),
		Port:    port,
		Token:   testToken,
		Timeout: 2 * time.Second,
	}
	st, err := p.Wait(context.Background(), 1, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !st.Healthy {
		t.Errorf("Healthy = false")
	}
}

func TestWaitForMgmtFingerprint_WaitsUntilFingerprintPresent(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	probe := &sequenceProbe{out: []Status{
		{Healthy: true},
		{Healthy: true, MgmtTLSFingerprint: fp},
	}}
	h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: probe})
	srv := httptest.NewServer(h)
	defer srv.Close()

	host, port, err := splitURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &Poller{
		BoxIP:   net.ParseIP(host),
		Port:    port,
		Token:   testToken,
		Timeout: 2 * time.Second,
	}
	got, err := p.WaitForMgmtFingerprint(context.Background(), 3, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForMgmtFingerprint: %v", err)
	}
	if got != fp {
		t.Fatalf("fingerprint = %q want %q", got, fp)
	}
}

func TestPoller_RejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		p    *Poller
	}{
		{"no-ip", &Poller{Token: "t"}},
		{"no-token", &Poller{BoxIP: net.ParseIP("127.0.0.1")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.p.Wait(context.Background(), 1, 10*time.Millisecond); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// splitURL is a tiny helper for tests to extract host+port from
// httptest URL.
func splitURL(u string) (string, int, error) {
	const prefix = "http://"
	u = u[len(prefix):]
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		return "", 0, err
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port, nil
}
