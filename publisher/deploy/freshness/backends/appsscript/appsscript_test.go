package appsscript_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/freshness/backends/appsscript"
	"daal/publisher/deploy/freshness/backends/appsscript/appsscripttest"
)

const token = "AAAAAAAAAAAAAAAAAAAAAA"

func key() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func doc(seq uint64, pack []byte) []byte {
	sum := sha256.Sum256(pack)
	b, _ := json.Marshal(map[string]any{
		"kind": "daal/freshness-v2", "sequence": seq,
		"current_bundle_sha256": hex.EncodeToString(sum[:]),
	})
	return b
}

// byHand is Path B against the fake: the script pasted and deployed,
// the address Google shows pasted back.
func byHand(t *testing.T, f *appsscripttest.Fake) string {
	t.Helper()
	code, _, err := appsscript.Script(key(), token)
	if err != nil {
		t.Fatal(err)
	}
	shown, err := f.DeployByHand(code)
	if err != nil {
		t.Fatal(err)
	}
	u, err := appsscript.NormalizeExecURL(shown, token)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPutThenFetchBackThroughTheFront(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	url := byHand(t, f)
	pack := []byte("signed pack")
	be, err := appsscript.New(appsscript.Config{ExecURL: url, WriteKey: key(), Pack: pack, Network: f.Network()})
	if err != nil {
		t.Fatal(err)
	}
	if be.PublicURL() != url {
		t.Fatal("public url")
	}
	f.ResetObservations()
	d := doc(1763600000, pack)
	if err := be.Put(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	blob, _ := be.Container(d)
	r := f.Network().FetchAndCompare(context.Background(), url, sha(blob))
	if !r.OK || !r.ViaFront || r.Reason != "" {
		t.Fatalf("%+v", r)
	}
	for _, sni := range f.SNIs {
		if sni != appsscript.FrontSNI {
			t.Fatalf("a fronted exchange showed SNI %q", sni)
		}
	}
	// Exactly the exec call and its one redirect, twice (POST, GET).
	if len(f.Calls) != 4 || !strings.Contains(f.Calls[1], "script.googleusercontent.com") {
		t.Fatalf("calls %v", f.Calls)
	}
	p, err := appsscript.Parse([]byte(mustStored(t, f, url)))
	if err != nil || string(p.Pack) != "signed pack" {
		t.Fatalf("stored container: %+v %v", p, err)
	}
}

func mustStored(t *testing.T, f *appsscripttest.Fake, url string) string {
	t.Helper()
	id, _, err := freshness.ValidateAppsScriptURL(url)
	if err != nil {
		t.Fatal(err)
	}
	_, blob, ok := f.Stored(id)
	if !ok {
		t.Fatal("no such deployment")
	}
	return blob
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestFrontCutFallsBackToPlainOnce(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	url := byHand(t, f)
	f.BlockFront = true
	r := f.Network().SendAndCheck(context.Background(), url, key(), 5, appsscript.Empty())
	if !r.OK || r.ViaFront {
		t.Fatalf("%+v", r)
	}
	f.BlockPlain = true
	f.ResetObservations()
	r = f.Network().SendAndCheck(context.Background(), url, key(), 6, appsscript.Empty())
	if r.OK || r.Reason != appsscript.ReasonUnreachable {
		t.Fatalf("%+v", r)
	}
	if len(f.SNIs) > 2 {
		t.Fatalf("more than two connections to Google on one attempt: %v", f.SNIs)
	}
}

func TestReasons(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	url := byHand(t, f)
	ctx := context.Background()
	n := f.Network()

	other := make([]byte, 32)
	if r := n.SendAndCheck(ctx, url, other, 5, appsscript.Empty()); r.Reason != appsscript.ReasonRefused {
		t.Errorf("other key: %+v", r)
	}
	if r := n.SendAndCheck(ctx, url, key(), 5, appsscript.Empty()); !r.OK || !r.Posted {
		t.Errorf("first: %+v", r)
	}
	if r := n.SendAndCheck(ctx, url, key(), 4, appsscript.Empty()); r.Reason != appsscript.ReasonStale {
		t.Errorf("older: %+v", r)
	}
	// Someone with access to the Google account replaced the text.
	id, _, _ := freshness.ValidateAppsScriptURL(url)
	f.SetStored(id, 99, `{"kind":"daal-refresh-v1","freshness":"e30="}`)
	if r := n.FetchAndCompare(ctx, url, sha(appsscript.Empty())); r.Reason != appsscript.ReasonWrongContent {
		t.Errorf("replaced: %+v", r)
	}
	f.SignInWall = true
	if r := n.SendAndCheck(ctx, url, key(), 100, appsscript.Empty()); r.Reason != appsscript.ReasonNotDeployed {
		t.Errorf("not open to anyone: %+v", r)
	}
	f.SignInWall = false
	missing := strings.Replace(url, id, "AKfycbNoSuchDeployment000000000", 1)
	if r := n.SendAndCheck(ctx, missing, key(), 100, appsscript.Empty()); r.Reason != appsscript.ReasonNotDeployed {
		t.Errorf("no such deployment: %+v", r)
	}
	// The path token keeps it quiet: a wrong k gets the bland page.
	wrongK := strings.Replace(url, "k="+token, "k=BBBBBBBBBBBBBBBBBBBBBB", 1)
	if r := n.FetchAndCompare(ctx, wrongK, ""); r.Reason != appsscript.ReasonWrongContent {
		t.Errorf("wrong k: %+v", r)
	}
}

func TestNormalizeExecURL(t *testing.T) {
	id := "AKfycbx" + strings.Repeat("a", 30)
	good := "https://script.google.com/macros/s/" + id + "/exec"
	for _, in := range []string{good, good + "?k=" + token, "  " + good + "/  ", good + "?usp=sharing"} {
		out, err := appsscript.NormalizeExecURL(in, token)
		if err != nil || out != good+"?k="+token {
			t.Errorf("%q -> %q %v", in, out, err)
		}
	}
	for _, in := range []string{
		"http://script.google.com/macros/s/" + id + "/exec",
		"https://script.google.com/macros/s/" + id + "/dev",
		"https://script.google.com/a/macros/example.org/s/" + id + "/exec",
		"https://evil.example/macros/s/" + id + "/exec",
		good + "?k=BBBBBBBBBBBBBBBBBBBBBB",
		"https://script.google.com/macros/s/short/exec",
	} {
		if _, err := appsscript.NormalizeExecURL(in, token); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// The backend is an ordinary freshness target: alone it satisfies the
// floor (D-3); beside another provider it counts as one of two.
func TestPublishAllWithTheGoogleChannel(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	url := byHand(t, f)
	be, err := appsscript.New(appsscript.Config{ExecURL: url, WriteKey: key(), Network: f.Network()})
	if err != nil {
		t.Fatal(err)
	}
	d := doc(10, nil)
	res, err := freshness.PublishAll(context.Background(), d,
		[]freshness.Target{{Provider: freshness.ProviderAppsScript, Backend: be}})
	if err != nil || len(res) != 1 || !res[0].OK {
		t.Fatalf("google alone: %+v %v", res, err)
	}
	other := &memBackend{url: "https://o.github.io/r/f.json"}
	res, err = freshness.PublishAll(context.Background(), doc(11, nil), []freshness.Target{
		{Provider: freshness.ProviderGHPages, Backend: other},
		{Provider: freshness.ProviderAppsScript, Backend: be},
	})
	if err != nil || !res[0].OK || !res[1].OK || other.puts != 1 {
		t.Fatalf("beside ghpages: %+v %v", res, err)
	}
	// Any other single provider is still refused.
	_, err = freshness.PublishAll(context.Background(), doc(12, nil),
		[]freshness.Target{{Provider: freshness.ProviderGHPages, Backend: other}})
	if !errors.Is(err, freshness.ErrTooFewMirrors) {
		t.Fatalf("one ghpages mirror: %v", err)
	}
}

type memBackend struct {
	url  string
	puts int
}

func (m *memBackend) PublicURL() string { return m.url }
func (m *memBackend) Put(context.Context, []byte) error {
	m.puts++
	return nil
}

func TestNewRefusesBadConfig(t *testing.T) {
	if _, err := appsscript.New(appsscript.Config{ExecURL: "https://example.com/x", WriteKey: key()}); err == nil {
		t.Error("bad url")
	}
	if _, err := appsscript.New(appsscript.Config{
		ExecURL:  "https://script.google.com/macros/s/AKfycbx" + strings.Repeat("a", 30) + "/exec?k=" + token,
		WriteKey: []byte("short"),
	}); err == nil {
		t.Error("short key")
	}
}
