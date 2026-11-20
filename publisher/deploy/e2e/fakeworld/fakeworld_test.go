package fakeworld

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/cli"
	"daal/publisher/deploy/cloudflare"
)

// The listing verbs against an account that has nothing in it, through
// the real hcloud client and this package's proxy. The app reads their
// stdout as a JSON array; `null` (a nil slice) used to fail that parse
// and blocked the "use a server I already own" step for a new account.
//
// This test owns its process's proxy settings (net/http and crypto/x509
// read them once), which is why it lives in this package and not next to
// the CLI's own tests.
func TestEmptyAccountListsAsAnEmptyArrayNotNull(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, "tok-e2e", []string{"anytls"})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, kv := range w.Env() {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte("tok-e2e"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, verb := range [][]string{
		{"list-servers", "--provider", "hetzner", "--token-file", tok},
		// No such region in the fake's price list: nothing is sold there.
		{"list-server-types", "--provider", "hetzner", "--region", "ash", "--token-file", tok},
	} {
		var out, errb bytes.Buffer
		if rc := cli.Run(verb, &out, &errb); rc != 0 {
			t.Fatalf("%s rc=%d: %s", verb[0], rc, errb.String())
		}
		if got := strings.TrimSpace(out.String()); got != "[]" {
			t.Errorf("%s on an empty account printed %q, want []", verb[0], got)
		}
	}
	if st := w.State(); len(st.Unmodelled) != 0 || len(st.Requests) == 0 || st.CloudflareFetches != 0 {
		t.Fatalf("the calls must reach the fake and only modelled endpoints: %+v", st)
	}

	// Cloudflare's published ranges are modelled and counted (in this
	// test: the proxy settings are read once per process), so a test
	// can prove a verb did or did not contact Cloudflare. The fetch is
	// the product's own, through the same proxy as the rest.
	r, err := cloudflare.FetchEdgeRanges(context.Background(), cloudflare.NewHTTPSEdgeRangeFetcher(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.V4, ",") != strings.Join(CloudflareRangesV4, ",") || strings.Join(r.V6, ",") != strings.Join(CloudflareRangesV6, ",") {
		t.Fatalf("ranges = %+v", r)
	}
	if st := w.State(); st.CloudflareFetches != 2 || len(st.Unmodelled) != 0 {
		t.Fatalf("state = %+v", st)
	}
}
