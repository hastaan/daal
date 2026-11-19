package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"daal/publisher/deploy/provider"
)

// TestClient_WhoAmI_AuthenticatesAndReadsTheAddress: /whoami had a
// handler on the box and no caller that could authenticate to it
// (MintToken refused the op — the end-to-end rig's finding LC-O2). The
// fake box verifies the token exactly as a relay does.
func TestClient_WhoAmI_AuthenticatesAndReadsTheAddress(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		if op, ok := boxVerifies(pub, r); !ok || op != "whoami" || r.Method != "GET" {
			http.Error(w, "bad token", 401)
			return
		}
		_, _ = w.Write([]byte(`{"source_ip":"198.51.100.7","server_time_unix":1700000000,"api_version":1}`))
	})
	ts, fp := startTLSServer(t, mux)
	rec := recForServer(t, ts, fp)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cli.WhoAmI(context.Background(), rec, priv)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if !got.SourceIP.Equal(net.ParseIP("198.51.100.7")) || got.ServerTimeUnix != 1700000000 || got.APIVersion != 1 {
		t.Errorf("got %+v", got)
	}
}

// TestClient_WhoAmI_OlderBoxIsNotAFailureOfAnythingElse: spec §4.7 —
// a 404/405 or an unusable body is "no answer", told apart from a relay
// that refuses the publisher's token.
func TestClient_WhoAmI_OlderBoxIsNotAFailureOfAnythingElse(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		status      int
		body        string
		unsupported bool
	}{
		"no such route":       {404, "404 page not found", true},
		"method refused":      {405, "method", true},
		"not an address":      {200, `{"source_ip":"relay.example"}`, true},
		"not json":            {200, `<html>`, true},
		"token refused":       {401, "unauthorized", false},
		"relay in trouble":    {500, "boom", false},
		"empty address":       {200, `{"source_ip":""}`, true},
		"address with a port": {200, `{"source_ip":"198.51.100.7:443"}`, true},
	} {
		mux := http.NewServeMux()
		mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		})
		ts, fp := startTLSServer(t, mux)
		rec := recForServer(t, ts, fp)
		cli, err := NewClient(rec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := cli.WhoAmI(context.Background(), rec, priv)
		if err == nil {
			t.Errorf("%s: got %+v, want an error", name, got)
			continue
		}
		if errors.Is(err, ErrWhoAmIUnsupported) != c.unsupported {
			t.Errorf("%s: errors.Is(ErrWhoAmIUnsupported) = %v, want %v (%v)", name, !c.unsupported, c.unsupported, err)
		}
	}
}

func recForServer(t *testing.T, ts *httptest.Server, fp string) *provider.OperatorRecord {
	t.Helper()
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	rec := mkRec(t, fp, port)
	rec.PublicIP = net.ParseIP(u.Hostname())
	return rec
}
