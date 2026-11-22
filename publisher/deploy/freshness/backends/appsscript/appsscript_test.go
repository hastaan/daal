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

const slot = "AAAAAAAAAAA"

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

// account is Path B against the fake: the account's script pasted and
// deployed, the address Google shows pasted back. It returns the
// script's own address.
func account(t *testing.T, f *appsscripttest.Fake) string {
	t.Helper()
	code, _, err := appsscript.Script(key())
	if err != nil {
		t.Fatal(err)
	}
	shown, err := f.DeployByHand(code)
	if err != nil {
		t.Fatal(err)
	}
	u, err := appsscript.NormalizeExecURL(shown)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// byHand is one relay's mirror URL in that script.
func byHand(t *testing.T, f *appsscripttest.Fake) string {
	t.Helper()
	return slotURL(t, account(t, f), slot)
}

func slotURL(t *testing.T, base, s string) string {
	t.Helper()
	u, err := appsscript.SlotURL(base, key(), s)
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
	id, s, _, err := freshness.ValidateAppsScriptURL(url)
	if err != nil {
		t.Fatal(err)
	}
	_, blob, ok := f.Stored(id, s)
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
	r := f.Network().SendAndCheck(context.Background(), url, key(), 5, appsscript.Empty(slot))
	if !r.OK || r.ViaFront {
		t.Fatalf("%+v", r)
	}
	f.BlockPlain = true
	f.ResetObservations()
	r = f.Network().SendAndCheck(context.Background(), url, key(), 6, appsscript.Empty(slot))
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
	if r := n.SendAndCheck(ctx, url, other, 5, appsscript.Empty(slot)); r.Reason != appsscript.ReasonRefused {
		t.Errorf("other key: %+v", r)
	}
	if r := n.SendAndCheck(ctx, url, key(), 5, appsscript.Empty(slot)); !r.OK || !r.Posted {
		t.Errorf("first: %+v", r)
	}
	if r := n.SendAndCheck(ctx, url, key(), 4, appsscript.Empty(slot)); r.Reason != appsscript.ReasonStale {
		t.Errorf("older: %+v", r)
	}
	// Someone with access to the Google account replaced the text.
	id, _, _, _ := freshness.ValidateAppsScriptURL(url)
	f.SetStored(id, slot, 99, `{"kind":"daal-refresh-v2","slot":"`+slot+`","freshness":"e30="}`)
	if r := n.FetchAndCompare(ctx, url, sha(appsscript.Empty(slot))); r.Reason != appsscript.ReasonWrongContent {
		t.Errorf("replaced: %+v", r)
	}
	f.SignInWall = true
	if r := n.SendAndCheck(ctx, url, key(), 100, appsscript.Empty(slot)); r.Reason != appsscript.ReasonNotDeployed {
		t.Errorf("not open to anyone: %+v", r)
	}
	f.SignInWall = false
	missing := strings.Replace(url, id, "AKfycbNoSuchDeployment000000000", 1)
	if r := n.SendAndCheck(ctx, missing, key(), 100, appsscript.Empty(slot)); r.Reason != appsscript.ReasonNotDeployed {
		t.Errorf("no such deployment: %+v", r)
	}
	// The read token keeps it quiet: a wrong k gets the bland page.
	wrongK := strings.Replace(url, "k="+appsscript.ReadToken(key(), slot), "k=BBBBBBBBBBBBBBBBBBBBBB", 1)
	if r := n.FetchAndCompare(ctx, wrongK, ""); r.Reason != appsscript.ReasonWrongContent {
		t.Errorf("wrong k: %+v", r)
	}
	// A URL whose k was made with another key is not this account's:
	// nothing is sent.
	if r := n.SendAndCheck(ctx, wrongK, key(), 200, appsscript.Empty(slot)); r.Reason != appsscript.ReasonRefused || r.Posted {
		t.Errorf("foreign k: %+v", r)
	}
	// Another slot's container served under this slot's address.
	f.SetStored(id, slot, 300, string(appsscript.Empty("BBBBBBBBBBB")))
	if r := n.FetchAndCompare(ctx, url, ""); r.Reason != appsscript.ReasonWrongContent {
		t.Errorf("another slot's container: %+v", r)
	}
	f.SetFull(id, true)
	if r := n.SendAndCheck(ctx, slotURL(t, strings.SplitN(url, "?", 2)[0], "CCCCCCCCCCC"), key(), 1, appsscript.Empty("CCCCCCCCCCC")); r.Reason != appsscript.ReasonFull {
		t.Errorf("full store: %+v", r)
	}
}

// One script, many relays: each slot keeps its own container and its
// own numbering, and a slot cleared leaves the others as they were.
func TestSlotsAreIndependent(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	base := account(t, f)
	ctx := context.Background()
	n := f.Network()
	a, b := slotURL(t, base, "AAAAAAAAAAA"), slotURL(t, base, "BBBBBBBBBBB")
	pa, pb := []byte("pack a"), []byte("pack b")
	ba, _ := appsscript.Build("AAAAAAAAAAA", doc(500, pa), pa, "")
	bb, _ := appsscript.Build("BBBBBBBBBBB", doc(7, pb), pb, "")
	if r := n.SendAndCheck(ctx, a, key(), 500, ba); !r.OK {
		t.Fatalf("a: %+v", r)
	}
	// b's numbers are its own: 7 is fine although a is at 500.
	if r := n.SendAndCheck(ctx, b, key(), 7, bb); !r.OK {
		t.Fatalf("b: %+v", r)
	}
	if r := n.SendAndCheck(ctx, b, key(), 8, appsscript.Empty("BBBBBBBBBBB")); !r.OK {
		t.Fatalf("clear b: %+v", r)
	}
	if r := n.FetchAndCompare(ctx, a, sha(ba)); !r.OK {
		t.Fatalf("a after b was cleared: %+v", r)
	}
	// A container meant for b, posted to a: the recipient of a would
	// refuse it, so the check does.
	if r := n.SendAndCheck(ctx, a, key(), 501, bb); r.OK || r.Reason != appsscript.ReasonWrongContent {
		t.Fatalf("b's container in a: %+v", r)
	}
}

// The account's connect check: the test slot is written and read back
// through the front; a script with another key, or none, is named.
func TestAccountCheck(t *testing.T) {
	f := appsscripttest.New()
	defer f.Close()
	base := account(t, f)
	ctx := context.Background()
	n := f.Network()
	f.ResetObservations()
	r := n.AccountCheck(ctx, base, key(), 1763600000000)
	if !r.OK || !r.ViaFront || !r.Posted {
		t.Fatalf("%+v", r)
	}
	id, _ := appsscript.ValidateBaseURL(base)
	_, first, _ := f.Stored(id, appsscript.TestSlot)
	// A second check writes a new nonce under a higher number.
	if r := n.AccountCheck(ctx, base, key(), 1763600000001); !r.OK {
		t.Fatalf("again: %+v", r)
	}
	if _, second, _ := f.Stored(id, appsscript.TestSlot); second == first {
		t.Fatal("the second check wrote the same container")
	}
	other := make([]byte, 32)
	if r := n.AccountCheck(ctx, base, other, 1763600000002); r.Reason != appsscript.ReasonRefused {
		t.Fatalf("another key: %+v", r)
	}
	missing := strings.Replace(base, id, "AKfycbNoSuchDeployment000000000", 1)
	if r := n.AccountCheck(ctx, missing, key(), 1763600000003); r.Reason != appsscript.ReasonNotDeployed {
		t.Fatalf("no such deployment: %+v", r)
	}
	if r := n.AccountCheck(ctx, base+"?x=1", key(), 1763600000004); r.OK {
		t.Fatalf("an address with a query: %+v", r)
	}
	if f.Slots(id) != 1 {
		t.Fatalf("the check used %d slots, want the one test slot", f.Slots(id))
	}
}

func TestNormalizeExecURL(t *testing.T) {
	id := "AKfycbx" + strings.Repeat("a", 30)
	good := "https://script.google.com/macros/s/" + id + "/exec"
	for _, in := range []string{good, "  " + good + "/  ", good + "?usp=sharing", good + "#x"} {
		out, err := appsscript.NormalizeExecURL(in)
		if err != nil || out != good {
			t.Errorf("%q -> %q %v", in, out, err)
		}
	}
	for _, in := range []string{
		"http://script.google.com/macros/s/" + id + "/exec",
		"https://script.google.com/macros/s/" + id + "/dev",
		"https://script.google.com/a/macros/example.org/s/" + id + "/exec",
		"https://evil.example/macros/s/" + id + "/exec",
		"https://u@script.google.com/macros/s/" + id + "/exec",
		"https://script.google.com/macros/s/short/exec",
	} {
		if _, err := appsscript.NormalizeExecURL(in); err == nil {
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
	base := "https://script.google.com/macros/s/AKfycbx" + strings.Repeat("a", 30) + "/exec"
	good := base + "?s=" + slot + "&k=" + appsscript.ReadToken(key(), slot)
	if _, err := appsscript.New(appsscript.Config{ExecURL: good, WriteKey: []byte("short")}); err == nil {
		t.Error("short key")
	}
	if _, err := appsscript.New(appsscript.Config{ExecURL: base, WriteKey: key()}); err == nil {
		t.Error("the script's own address is not a mirror")
	}
	if _, err := appsscript.New(appsscript.Config{ExecURL: base + "?k=AAAAAAAAAAAAAAAAAAAAAA", WriteKey: key()}); err == nil {
		t.Error("the single-relay shape")
	}
	other := make([]byte, 32)
	if _, err := appsscript.New(appsscript.Config{ExecURL: good, WriteKey: other}); err == nil {
		t.Error("another account's key")
	}
	if _, err := appsscript.New(appsscript.Config{ExecURL: good, WriteKey: key()}); err != nil {
		t.Error(err)
	}
}
