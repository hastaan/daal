package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/cloudflare"
)

// memNoteDNS is an in-memory cloudflare.NoteDNSAPI.
type memNoteDNS struct {
	zone    string
	recs    map[string]cloudflare.NoteRecord
	next    int
	writes  int
	calls   int
	gotToks []string
}

func (m *memNoteDNS) LookupZone(_ context.Context, tok []byte, name string) (cloudflare.Zone, bool, error) {
	m.calls++
	m.gotToks = append(m.gotToks, string(tok))
	if name == m.zone {
		return cloudflare.Zone{ID: "z1", Name: name, Status: "active"}, true, nil
	}
	return cloudflare.Zone{}, false, nil
}

func (m *memNoteDNS) ListNoteRecords(_ context.Context, _ []byte, _, name string) ([]cloudflare.NoteRecord, error) {
	m.calls++
	var out []cloudflare.NoteRecord
	for _, r := range m.recs {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memNoteDNS) CreateNoteRecord(_ context.Context, _ []byte, _, name, ip string) (string, error) {
	m.calls++
	m.writes++
	m.next++
	id := fmt.Sprintf("r%d", m.next)
	f := false
	m.recs[id] = cloudflare.NoteRecord{ID: id, Type: "A", Name: name, Content: ip, Proxied: &f, TTL: cloudflare.NoteRecordTTL}
	return id, nil
}

func (m *memNoteDNS) ReplaceNoteRecord(_ context.Context, _ []byte, _, id, name, ip string) error {
	m.calls++
	m.writes++
	f := false
	m.recs[id] = cloudflare.NoteRecord{ID: id, Type: "A", Name: name, Content: ip, Proxied: &f, TTL: cloudflare.NoteRecordTTL}
	return nil
}

func (m *memNoteDNS) DeleteDNSRecord(_ context.Context, _ []byte, _, id string) error {
	m.calls++
	m.writes++
	delete(m.recs, id)
	return nil
}

func withNoteDNSFake(t *testing.T, zone string) *memNoteDNS {
	t.Helper()
	m := &memNoteDNS{zone: zone, recs: map[string]cloudflare.NoteRecord{}}
	oc, on := newNoteDNSClient, noteDNSNow
	newNoteDNSClient = func() cloudflare.NoteDNSAPI { return m }
	noteDNSNow = func() time.Time { return time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { newNoteDNSClient, noteDNSNow = oc, on })
	return m
}

const noteTestToken = "cf-secret-token-123"

func noteCreds(t *testing.T, aud string, withKey bool) (string, [32]byte, bundle.StandbyKeyBytes) {
	t.Helper()
	var u [32]byte
	for i := range u {
		u[i] = byte(40 + i)
	}
	k, err := bundle.NewStandbyKey("5.6.7.8", bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]string{
		"cf_token":        noteTestToken,
		"update_secret":   base64.StdEncoding.EncodeToString(u[:]),
		"update_audience": aud,
		"zone":            "example.org",
	}
	if withKey {
		c["standby_key"] = k.Text()
	}
	b, _ := json.Marshal(c)
	return string(b), u, k
}

func runNote(t *testing.T, creds string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := runNoteDNS(context.Background(), args, strings.NewReader(creds), &out, &errb)
	return rc, out.String(), errb.String()
}

func TestNoteDNS_CLI_DryRunThenPublishThenRemove(t *testing.T) {
	m := withNoteDNSFake(t, "example.org")
	creds, u, k := noteCreds(t, "people", true)

	rc, out, errs := runNote(t, creds, "publish", "--creds-file", "-", "--dry-run")
	if rc != 0 || m.writes != 0 {
		t.Fatalf("dry-run rc %d writes %d: %s", rc, m.writes, errs)
	}
	var o struct {
		OK      bool   `json:"ok"`
		DryRun  bool   `json:"dry_run"`
		Mode    string `json:"mode"`
		Created int    `json:"created"`
		Removed int    `json:"removed"`
		Ops     []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &o); err != nil || !o.OK || !o.DryRun || o.Mode != "reveal" || o.Created != 6 || len(o.Ops) != 6 {
		t.Fatalf("dry-run out %s (%v)", out, err)
	}

	// From a file this time.
	p := filepath.Join(t.TempDir(), "creds.json")
	os.WriteFile(p, []byte(creds), 0o600)
	rc, out, errs = runNote(t, "", "publish", "--creds-file", p)
	if rc != 0 || m.writes != 6 {
		t.Fatalf("publish rc %d writes %d: %s", rc, m.writes, errs)
	}
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, noteDNSNow())
	names, _ := bundle.DNSNoteNames(u, e, "example.org")
	for _, s := range []string{out, errs} {
		for _, bad := range []string{noteTestToken, names[0][:12], "example.org", k.Address(), base64.StdEncoding.EncodeToString(u[:])} {
			if strings.Contains(s, bad) {
				t.Fatalf("output leaks %q: %s", bad, s)
			}
		}
	}
	for _, tk := range m.gotToks {
		if tk != noteTestToken {
			t.Fatal("token not passed through")
		}
	}

	rc, out, _ = runNote(t, strings.Replace(creds, `"standby_key"`, `"x_unused"`, 1), "remove", "--creds-file", "-")
	if rc != 2 {
		t.Fatalf("unknown member accepted: rc %d %s", rc, out)
	}
	credsNoKey, _, _ := noteCreds(t, "people", false)
	rc, out, _ = runNote(t, credsNoKey, "remove", "--creds-file", "-")
	if rc != 0 || len(m.recs) != 0 {
		t.Fatalf("remove rc %d left %d: %s", rc, len(m.recs), out)
	}
}

func TestNoteDNS_CLI_EveryoneRefusedBeforeAnyCall(t *testing.T) {
	m := withNoteDNSFake(t, "example.org")
	creds, _, _ := noteCreds(t, "everyone", false)
	rc, out, _ := runNote(t, creds, "publish", "--creds-file", "-")
	if rc != exitCDNRefused || m.calls != 0 || !strings.Contains(out, `"everyone_refused"`) {
		t.Fatalf("rc %d calls %d out %s", rc, m.calls, out)
	}
}

func TestNoteDNS_CLI_BadInputs(t *testing.T) {
	m := withNoteDNSFake(t, "example.org")
	good, _, _ := noteCreds(t, "people/2", false)
	for name, c := range map[string]string{
		"bad secret":   strings.Replace(good, `"update_secret":"`, `"update_secret":"!!`, 1),
		"bad zone":     strings.Replace(good, `"example.org"`, `"Example..org"`, 1),
		"no token":     strings.Replace(good, noteTestToken, "", 1),
		"not json":     "{",
		"bad key":      strings.Replace(good, `"zone"`, `"standby_key":"nope","zone"`, 1),
		"bad audience": strings.Replace(good, `"people/2"`, `"people/1"`, 1),
	} {
		rc, out, errs := runNote(t, c, "publish", "--creds-file", "-")
		if rc != 2 || strings.Contains(errs, noteTestToken) || strings.Contains(errs, "nope") {
			t.Errorf("%s: rc %d out %s err %s", name, rc, out, errs)
		}
	}
	if rc, _, _ := runNote(t, good, "publish", "--creds-file", "-", "extra"); rc != 2 {
		t.Error("argv input accepted")
	}
	if rc, _, _ := runNote(t, good, "nope"); rc != 2 {
		t.Error("unknown verb accepted")
	}
	if m.writes != 0 {
		t.Fatal("a bad input wrote")
	}
	// The zone the token does not see.
	other := strings.Replace(good, `"example.org"`, `"other.net"`, 1)
	rc, out, _ := runNote(t, other, "publish", "--creds-file", "-")
	if rc != exitCDNRefused || !strings.Contains(out, "zone_not_found") {
		t.Fatalf("rc %d out %s", rc, out)
	}
}
