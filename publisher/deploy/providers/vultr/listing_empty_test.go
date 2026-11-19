package vultr

import (
	"context"
	"encoding/json"
	"testing"
)

// An account with no instances lists as `[]`, not `null`: the app reads
// the verb's stdout as a JSON array, and a nil slice used to fail that
// parse and block the "use a server I already own" step.
func TestListServersOnAnEmptyAccountIsAnEmptyArray(t *testing.T) {
	f := newFakeVultr(t)
	lc := &ListingClient{c: newLiveClientAt(f.srv.URL, f.token)}
	got, err := lc.ListServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(got); string(b) != "[]" {
		t.Fatalf("empty account encodes as %s, want []", b)
	}
}
