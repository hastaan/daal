package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// fakeCFDNS is a fake Cloudflare v4 API for zones and DNS records only,
// served over httptest so the live client's wire code runs.
type fakeCFDNS struct {
	mu       sync.Mutex
	zones    map[string]string // name → id
	records  map[string]NoteRecord
	next     int
	writes   []string // method + record id, in order
	token    string
	seenTok  []string
	failList bool
}

func newFakeCFDNS(zone string) *fakeCFDNS {
	return &fakeCFDNS{zones: map[string]string{zone: "zid-1"}, records: map[string]NoteRecord{}, token: "cf-test-token"}
}

func (f *fakeCFDNS) add(r NoteRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	if r.ID == "" {
		r.ID = fmt.Sprintf("r%d", f.next)
	}
	f.records[r.ID] = r
}

func (f *fakeCFDNS) byName(name string) []NoteRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []NoteRecord
	for _, r := range f.records {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeCFDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seenTok = append(f.seenTok, r.Header.Get("Authorization"))
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(403)
		io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"auth"}]}`)
		return
	}
	ok := func(v any) {
		b, _ := json.Marshal(map[string]any{"success": true, "result": v})
		w.Write(b)
	}
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/zones":
		var out []map[string]string
		if id, ok := f.zones[r.URL.Query().Get("name")]; ok {
			out = append(out, map[string]string{"id": id, "name": r.URL.Query().Get("name"), "status": "active"})
		}
		ok(out)
	case strings.HasPrefix(p, "/zones/zid-1/dns_records"):
		rest := strings.TrimPrefix(strings.TrimPrefix(p, "/zones/zid-1/dns_records"), "/")
		switch {
		case r.Method == "GET" && rest == "" && f.failList:
			w.WriteHeader(500)
			io.WriteString(w, `{"success":false,"errors":[{"code":1,"message":"`+r.URL.Query().Get("name")+`"}]}`)
		case r.Method == "GET" && rest == "":
			out := []NoteRecord{}
			for _, rec := range f.records {
				if rec.Name == r.URL.Query().Get("name") {
					out = append(out, rec)
				}
			}
			ok(out)
		case r.Method == "POST" && rest == "":
			var in dnsRecordPayload
			json.NewDecoder(r.Body).Decode(&in)
			f.next++
			pr := in.Proxied
			rec := NoteRecord{ID: fmt.Sprintf("r%d", f.next), Type: in.Type, Name: in.Name, Content: in.Content, Proxied: &pr, TTL: in.TTL}
			f.records[rec.ID] = rec
			f.writes = append(f.writes, "POST "+rec.ID)
			ok(rec)
		case r.Method == "PUT" && rest != "":
			old, exists := f.records[rest]
			if !exists {
				w.WriteHeader(404)
				return
			}
			var in dnsRecordPayload
			json.NewDecoder(r.Body).Decode(&in)
			pr := in.Proxied
			rec := NoteRecord{ID: old.ID, Type: in.Type, Name: in.Name, Content: in.Content, Proxied: &pr, TTL: in.TTL}
			f.records[rest] = rec
			f.writes = append(f.writes, "PUT "+rest)
			ok(rec)
		case r.Method == "DELETE" && rest != "":
			delete(f.records, rest)
			f.writes = append(f.writes, "DELETE "+rest)
			ok(map[string]string{"id": rest})
		default:
			w.WriteHeader(405)
		}
	default:
		w.WriteHeader(404)
	}
}

func testSecret(b byte, aud string) bundle.UpdateSecret {
	u := bundle.UpdateSecret{Audience: aud}
	for i := range u.Secret {
		u.Secret[i] = b + byte(i)
	}
	return u
}

func testKey(t *testing.T) bundle.StandbyKeyBytes {
	t.Helper()
	k, err := bundle.NewStandbyKey("5.6.7.8", bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var noteNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, zone string) (*fakeCFDNS, NoteDNSAPI, []byte) {
	t.Helper()
	f := newFakeCFDNS(zone)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, newLiveCFClient(srv.URL, srv.Client()), []byte(f.token)
}

// readNote is what a phone would read back from the six records.
func readNote(t *testing.T, f *fakeCFDNS, u bundle.UpdateSecret, e uint64, zone string) ([bundle.MicroNoteLen]byte, bool) {
	t.Helper()
	names, err := bundle.DNSNoteNames(u.Secret, e, zone)
	if err != nil {
		t.Fatal(err)
	}
	var ips [bundle.DNSNoteAnswers]net.IP
	for i, n := range names {
		recs := f.byName(n)
		if len(recs) != 1 {
			return [16]byte{}, false
		}
		r := recs[0]
		if r.Type != "A" || r.Proxied == nil || *r.Proxied || r.TTL != NoteRecordTTL {
			t.Fatalf("record %d: type %s proxied %v ttl %d", i, r.Type, r.Proxied, r.TTL)
		}
		ips[i] = net.ParseIP(r.Content)
	}
	s, err := bundle.DNSNoteJoin(ips)
	return s, err == nil
}

func TestNoteDNS_FillerThenRevealThenSweep(t *testing.T) {
	const zone = "example.org"
	f, api, tok := setup(t, zone)
	u := testSecret(1, bundle.AudiencePeople)
	k := testKey(t)
	ctx := context.Background()
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, noteNow)

	// Records that must survive everything: the CDN route's proxied
	// record, a stranger's A record, a TXT record, and a proxied record
	// at a note name of an OLD epoch.
	yes := true
	no := false
	f.add(NoteRecord{ID: "cdn", Type: "A", Name: "cdn." + zone, Content: "203.0.113.9", Proxied: &yes, TTL: 1})
	f.add(NoteRecord{ID: "www", Type: "A", Name: "www." + zone, Content: "23.1.2.3", Proxied: &no, TTL: 300})
	f.add(NoteRecord{ID: "txt", Type: "TXT", Name: zone, Content: "v=spf1 -all", TTL: 300})
	oldNames, _ := bundle.DNSNoteNames(u.Secret, e-3, zone)
	f.add(NoteRecord{ID: "oldproxied", Type: "A", Name: oldNames[2], Content: "23.9.9.9", Proxied: &yes, TTL: 1})
	// Our own leftovers at e−3 (to be swept) and at e−1 (to stay).
	for i, n := range oldNames {
		f.add(NoteRecord{ID: fmt.Sprintf("old%d", i), Type: "A", Name: n, Content: "34.0.0.1", Proxied: &no, TTL: 300})
	}
	prevNames, _ := bundle.DNSNoteNames(u.Secret, e-1, zone)
	for i, n := range prevNames {
		f.add(NoteRecord{ID: fmt.Sprintf("prev%d", i), Type: "A", Name: n, Content: "35.0.0.1", Proxied: &no, TTL: 300})
	}

	// Filler.
	plan, err := PublishNoteDNS(ctx, api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow})
	if err != nil {
		t.Fatal(err)
	}
	s := plan.Summary()
	if s.Mode != "filler" || s.Created != 6 || s.Removed != 6 || s.Foreign != 1 || s.Epoch != e {
		t.Fatalf("filler summary %+v", s)
	}
	filler, ok := readNote(t, f, u, e, zone)
	if !ok {
		t.Fatal("filler not readable as six answers")
	}
	for i := range oldNames {
		if len(f.records[fmt.Sprintf("old%d", i)].ID) != 0 {
			t.Fatalf("old%d not swept", i)
		}
		if f.records[fmt.Sprintf("prev%d", i)].ID == "" {
			t.Fatalf("prev%d (e-1) removed", i)
		}
	}
	for _, id := range []string{"cdn", "www", "txt", "oldproxied"} {
		if f.records[id].ID != id {
			t.Fatalf("record %s was touched", id)
		}
	}

	// Filler again: nothing is written.
	nw := len(f.writes)
	if _, err := PublishNoteDNS(ctx, api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow}); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != nw {
		t.Fatalf("filler re-run wrote %v", f.writes[nw:])
	}
	if again, _ := readNote(t, f, u, e, zone); again != filler {
		t.Fatal("filler changed on re-run")
	}

	// Reveal replaces the six in place.
	plan, err = PublishNoteDNS(ctx, api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow, StandbyKey: &k})
	if err != nil {
		t.Fatal(err)
	}
	if s := plan.Summary(); s.Mode != "reveal" || s.Replaced != 6 || s.Created != 0 {
		t.Fatalf("reveal summary %+v", s)
	}
	got, ok := readNote(t, f, u, e, zone)
	if !ok {
		t.Fatal("revealed note not readable")
	}
	st := bundle.SealedStandby(k)
	ko, who, ep, ok := st.OpenMicroNote(bundle.NoteCarrierDNS, noteNow, got, []*bundle.UpdateSecret{&u})
	if !ok || ko != k || who.Audience != u.Audience || ep != e {
		t.Fatal("the phone cannot open the revealed note")
	}

	// Reveal again: the same note is there, nothing written.
	nw = len(f.writes)
	if _, err := PublishNoteDNS(ctx, api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow, StandbyKey: &k}); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != nw {
		t.Fatalf("reveal re-run wrote %v", f.writes[nw:])
	}
	// Filler after a reveal never hides it.
	if _, err := PublishNoteDNS(ctx, api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow}); err != nil {
		t.Fatal(err)
	}
	if again, _ := readNote(t, f, u, e, zone); again != got {
		t.Fatal("filler overwrote a revealed note")
	}

	// Remove: every note of this secret goes, nothing else.
	plan, err = PlanNoteDNSRemove(ctx, api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNoteDNS(ctx, api, tok, plan); err != nil {
		t.Fatal(err)
	}
	if s := plan.Summary(); s.Removed != 12 || s.Foreign != 1 {
		t.Fatalf("remove summary %+v", s)
	}
	f.mu.Lock()
	left := len(f.records)
	f.mu.Unlock()
	if left != 4 {
		t.Fatalf("%d records left, want the 4 foreign ones", left)
	}
}

func TestNoteDNS_ForeignRecordAtCurrentNameRefuses(t *testing.T) {
	const zone = "example.org"
	for _, tc := range []struct {
		name string
		rec  func(n string) NoteRecord
	}{
		{"proxied", func(n string) NoteRecord {
			y := true
			return NoteRecord{ID: "x", Type: "A", Name: n, Content: "23.1.1.1", Proxied: &y, TTL: 1}
		}},
		{"stranger", func(n string) NoteRecord {
			no := false
			return NoteRecord{ID: "x", Type: "A", Name: n, Content: "192.0.2.1", Proxied: &no, TTL: 300}
		}},
		{"cname", func(n string) NoteRecord {
			no := false
			return NoteRecord{ID: "x", Type: "CNAME", Name: n, Content: "other.example", Proxied: &no, TTL: 300}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, api, tok := setup(t, zone)
			u := testSecret(2, bundle.AudiencePeople)
			e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, noteNow)
			names, _ := bundle.DNSNoteNames(u.Secret, e, zone)
			f.add(tc.rec(names[4]))
			_, err := PublishNoteDNS(context.Background(), api, tok, NoteDNSInput{Secret: u, Zone: zone, Now: noteNow})
			if !errors.Is(err, ErrNoteNameTaken) {
				t.Fatalf("err %v, want ErrNoteNameTaken", err)
			}
			if len(f.writes) != 0 || f.records["x"].ID != "x" {
				t.Fatalf("wrote %v", f.writes)
			}
		})
	}
}

func TestNoteDNS_EveryoneRefused(t *testing.T) {
	f, api, tok := setup(t, "example.org")
	u := testSecret(3, bundle.AudienceEveryone)
	_, err := PublishNoteDNS(context.Background(), api, tok, NoteDNSInput{Secret: u, Zone: "example.org", Now: noteNow})
	if !errors.Is(err, ErrNoteAudience) {
		t.Fatalf("err %v", err)
	}
	if len(f.seenTok) != 0 {
		t.Fatal("the API was called for the Everyone audience")
	}
}

func TestNoteDNS_SubZoneAndNoZone(t *testing.T) {
	f, api, tok := setup(t, "example.org")
	u := testSecret(4, bundle.UpdateAudiencePeople(2))
	plan, err := PublishNoteDNS(context.Background(), api, tok, NoteDNSInput{Secret: u, Zone: "n.example.org", Now: noteNow})
	if err != nil || plan.ZoneID != "zid-1" {
		t.Fatalf("sub-zone: %v", err)
	}
	if _, ok := readNote(t, f, u, plan.Epoch, "n.example.org"); !ok {
		t.Fatal("sub-zone note not written")
	}
	_, err = PublishNoteDNS(context.Background(), api, tok, NoteDNSInput{Secret: u, Zone: "other.net", Now: noteNow})
	if !errors.Is(err, ErrNoteZoneNotFound) {
		t.Fatalf("err %v", err)
	}
}

func TestNoteDNS_ErrorsNameNothing(t *testing.T) {
	f, api, _ := setup(t, "example.org")
	u := testSecret(5, bundle.AudiencePeople)
	_, err := PublishNoteDNS(context.Background(), api, []byte("wrong-token"), NoteDNSInput{Secret: u, Zone: "example.org", Now: noteNow})
	if err == nil || !isAuthError(err) {
		t.Fatalf("err %v, want an auth error", err)
	}
	if strings.Contains(err.Error(), "example.org") || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("error text leaks: %q", err)
	}
	// A list failure must not carry the note name either.
	f.failList = true
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, noteNow)
	names, _ := bundle.DNSNoteNames(u.Secret, e, "example.org")
	_, err = PublishNoteDNS(context.Background(), api, []byte(f.token), NoteDNSInput{Secret: u, Zone: "example.org", Now: noteNow})
	if err == nil || strings.Contains(err.Error(), names[0][:12]) || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err %v", err)
	}
}

func TestNoteDNS_DryPlanWritesNothing(t *testing.T) {
	f, api, tok := setup(t, "example.org")
	u := testSecret(6, bundle.AudiencePeople)
	plan, err := PlanNoteDNS(context.Background(), api, tok, NoteDNSInput{Secret: u, Zone: "example.org", Now: noteNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || plan.Summary().Created != 6 {
		t.Fatalf("writes %v summary %+v", f.writes, plan.Summary())
	}
	b, _ := json.Marshal(plan.Summary())
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, noteNow)
	names, _ := bundle.DNSNoteNames(u.Secret, e, "example.org")
	if strings.Contains(string(b), names[0][:12]) || strings.Contains(string(b), "example.org") {
		t.Fatalf("summary leaks: %s", b)
	}
}
