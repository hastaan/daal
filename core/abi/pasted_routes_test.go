package abi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/uri"
	"daal/core/routestore"
)

// Wave 2 leftovers: a pasted WireGuard conf is stored manual-only and
// never raced; a pasted link's own name is the route's name; the
// routes pasted on this phone say so (pasted_by_you).

const testWGConf = "[Interface]\nPrivateKey = cGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGE=\nAddress = 10.0.0.2/32\n\n" +
	"[Peer]\nPublicKey = cGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGE=\nEndpoint = w.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"

const testPBK = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

// pasteAndTrust pastes one item and answers the first trust prompt.
func pasteAndTrust(t *testing.T, item string) {
	t.Helper()
	v, err := URIImport(item)
	if err != nil {
		t.Fatalf("paste: %v", err)
	}
	if fp := extractField(v, "Fingerprint"); fp != "" && strings.Contains(v, `"Kind":1`) {
		if _, err := ResolveTrustPrompt(fp, 0); err != nil {
			t.Fatal(err)
		}
	}
}

func pastedRows(t *testing.T) []routestore.RouteRow {
	t.Helper()
	rows, err := mustCore().store.ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	var out []routestore.RouteRow
	for _, r := range rows {
		if strings.HasPrefix(r.RouteID, "pasted-") {
			out = append(out, r)
		}
	}
	return out
}

func summaryOf(t *testing.T, id string) RouteSummaryDisplay {
	t.Helper()
	body, err := RouteSummary(id)
	if err != nil {
		t.Fatal(err)
	}
	var d RouteSummaryDisplay
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// The flag is checked before every other rule: a manual-only route of
// an experimental family is not raced with experimental routes on, and
// it is listed with its own refusal. The person can still pick it.
func TestConnectAuto_ManualOnlyRouteIsNeverRacedEvenWithExperimentalOn(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes[:1])
	seedAutoRoute(t, rig.c, "r-wg", "wireguard",
		`{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"a","peers":[{"address":"vpn.example","port":51820,"public_key":"b","allowed_ips":["0.0.0.0/0"]}]}`)
	row, err := rig.c.store.GetRoute("r-wg")
	if err != nil {
		t.Fatal(err)
	}
	row.ManualOnly = true
	if err := rig.c.store.UpsertRoute(row); err != nil {
		t.Fatal(err)
	}
	rig.c.mu.Lock()
	rig.c.experimentalFamiliesEnabled = true
	rig.c.mu.Unlock()

	rig.fail("r1", deadSYN())
	res := rig.connectAuto()
	if got := rig.provedRoutes(); !eq(got, []string{"r1"}) {
		t.Fatalf("started %v; the manual-only route was raced", got)
	}
	found := false
	for _, tr := range res.Tried {
		if tr.RouteID == "r-wg" {
			found = true
			if tr.Result != AutoResultRefused || tr.Refused != AutoRefusedChosenOnly {
				t.Fatalf("r-wg: %+v, want refused %s", tr, AutoRefusedChosenOnly)
			}
		}
	}
	if !found {
		t.Fatalf("r-wg not listed: %+v", res.Tried)
	}
	// The same route WITHOUT the flag would be a candidate with the gate
	// open: the refusal is the flag's, not the family's.
	seedAutoRoute(t, rig.c, "r-wg2", "wireguard",
		`{"type":"wireguard","address":["10.0.0.3/32"],"private_key":"a","peers":[{"address":"vpn2.example","port":51820,"public_key":"b","allowed_ips":["0.0.0.0/0"]}]}`)
	rig.c.mu.Lock()
	cands, _, _, err := rig.c.autoCandidatesLocked("")
	rig.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, cd := range cands {
		ids = append(ids, cd.routeID)
	}
	if !sameSet(ids, "r1", "r-wg2") {
		t.Fatalf("candidates %v", ids)
	}
	// Picked by the person, it is not refused for being manual-only.
	clearCooldowns(rig.c)
	if out, err := RouteConnectPrecheck("r-wg"); err != nil || strings.Contains(out, AutoRefusedChosenOnly) {
		t.Fatalf("precheck of a manual-only route: %s, %v", out, err)
	}
	if d := summaryOf(t, "r-wg"); !d.ManualOnly {
		t.Fatalf("summary: manual_only=%v", d.ManualOnly)
	}
}

// A pasted WireGuard conf is accepted, stored manual-only, and so is an
// AmneziaWG conf downgraded to WireGuard; the summary says so.
func TestURIImport_WireGuardConfIsStoredManualOnly(t *testing.T) {
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	pasteAndTrust(t, "  "+testWGConf)
	junk := strings.Replace(testWGConf, "Address = 10.0.0.2/32\n", "Address = 10.0.0.9/32\nJc = 4\nJmin = 40\nJmax = 70\n", 1)
	pasteAndTrust(t, "# from my provider\n"+junk)
	rows := pastedRows(t)
	if len(rows) != 2 {
		t.Fatalf("pasted rows: %d", len(rows))
	}
	for _, r := range rows {
		if r.TransportFamily != "wireguard" || !r.ManualOnly {
			t.Fatalf("%s: family %s manual_only %v", r.RouteID, r.TransportFamily, r.ManualOnly)
		}
		d := summaryOf(t, r.RouteID)
		if !d.ManualOnly || !d.PastedByYou || d.NameFromLink {
			t.Fatalf("summary %+v", d)
		}
	}
	c := mustCore()
	c.mu.Lock()
	c.experimentalFamiliesEnabled = true
	_, left, _, err := c.autoCandidatesLocked("")
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, l := range left {
		if l.Refused == AutoRefusedChosenOnly {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("left %+v; both confs are chosen_only", left)
	}
}

// An AmneziaWG conf this build cannot dial stays refused, and nothing
// of it is kept; a conf that is not one is refused as malformed without
// quoting it.
func TestURIImport_AmneziaUnsupportedAndBadConfsAreRefused(t *testing.T) {
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	awg := strings.Replace(testWGConf, "Address = 10.0.0.2/32\n", "Address = 10.0.0.2/32\nJc = 4\nS1 = 15\nH1 = 123456\n", 1)
	if _, err := URIImport(awg); uri.RefusalCode(err) != "transport_unsupported" {
		t.Fatalf("amneziawg: %v", err)
	}
	bad := "[Interface]\nPrivateKey = s3cr3tvalue\n"
	_, err := URIImport(bad)
	if uri.RefusalCode(err) != "link_malformed" || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("bad conf: %v", err)
	}
	if n := len(pastedRows(t)); n != 0 {
		t.Fatalf("%d route(s) stored", n)
	}
	if keys, _ := mustCore().store.ListSecretKeys("route-meta:"); len(keys) != 0 {
		t.Fatalf("meta left behind: %v", keys)
	}
}

// The certificate-check switches are refused through the paste too.
func TestURIImport_InsecureLinksAreRefused(t *testing.T) {
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	for _, l := range []string{
		"vless://u@v.example.com:443?security=tls&sni=v.example.com&allowInsecure=1",
		"trojan://pw@t.example.com:443?allowInsecure=true",
	} {
		if _, err := URIImport(l); uri.RefusalCode(err) != "insecure_refused" {
			t.Fatalf("%s: %v", l[:6], err)
		}
	}
}

// The link's #name is the route's name (cleaned: the bidi override that
// could reverse it is gone), said as name_from_link; the route id and
// everything else do not change. A route from someone else's file keeps
// its own nickname and is not pasted_by_you.
func TestURIImport_LinkNameIsTheRouteName(t *testing.T) {
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	pasteAndTrust(t, "vless://uuid@example.com:443?security=reality&pbk="+testPBK+"&sid=01#%E2%80%AEGermany%20%202%0A")
	pasteAndTrust(t, "vless://uuid-2@example.com:443?security=reality&pbk="+testPBK+"&sid=01")
	rows := pastedRows(t)
	if len(rows) != 2 {
		t.Fatalf("pasted rows %d", len(rows))
	}
	named := 0
	for _, r := range rows {
		d := summaryOf(t, r.RouteID)
		if !d.PastedByYou || d.ManualOnly {
			t.Fatalf("summary %+v", d)
		}
		if d.NameFromLink {
			named++
			if d.RouteNickname != "Germany 2" {
				t.Fatalf("nickname %q", d.RouteNickname)
			}
			if strings.Contains(r.RouteID, "Germany") {
				t.Fatalf("the name reached the route id: %s", r.RouteID)
			}
		} else if d.RouteNickname == "" || d.RouteNickname == "Germany 2" {
			t.Fatalf("unnamed link nickname %q", d.RouteNickname)
		}
	}
	if named != 1 {
		t.Fatalf("%d named routes, want 1", named)
	}
	// AvailableRoutes says the same.
	body, err := AvailableRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"route_nickname":"Germany 2"`) || !strings.Contains(body, `"pasted_by_you":true`) {
		t.Fatalf("available routes: %s", body)
	}
	// Another publisher's route: not pasted, no link name.
	seedAutoRoute(t, mustCore(), "r-file", "vless-reality", `{"type":"vless","server":"relay.example","server_port":443}`)
	if d := summaryOf(t, "r-file"); d.PastedByYou || d.NameFromLink {
		t.Fatalf("a file's route: %+v", d)
	}
	// Deleting the route takes its name with it.
	for _, r := range rows {
		if err := mustCore().store.DeleteRoute(r.RouteID); err != nil {
			t.Fatal(err)
		}
		if _, ok := mustCore().store.GetRouteMeta(r.RouteID); ok {
			t.Fatalf("%s: meta survived the delete", r.RouteID)
		}
	}
}

// ---- the person's survey ------------------------------------------------

// The person's survey is not bound by the hourly allowance: with the
// allowance spent, every route is still checked, and the
// probes still count against the allowance for what Daal does itself.
func TestSurvey_TheButtonPassesTheHourlyAllowance(t *testing.T) {
	rig := surveyRig(t, time.Hour)
	rig.c.mu.Lock()
	for i := 0; i < sideProbesPerHour; i++ {
		rig.c.sideNoteLocked(fmt.Sprintf("x%d", i))
	}
	rig.c.mu.Unlock()
	if _, err := SurveyRoutes(true); err != nil {
		t.Fatal(err)
	}
	b := surveyOver(t)
	if got := rig.sideProbed(); !sameSet(got, "r1", "r2", "r3", "r4", "r5") {
		t.Fatalf("checked %v with the allowance spent", got)
	}
	for id, r := range surveyResults(b) {
		if r["result"] != SurveyResultCarried {
			t.Fatalf("%s: %v", id, r)
		}
	}
	rig.c.mu.Lock()
	n := len(rig.c.side.perNet[activeNetworkID()])
	room := rig.c.sideCountOKLocked(1)
	rig.c.mu.Unlock()
	if n != sideProbesPerHour+5 || room {
		t.Fatalf("allowance after the button: %d noted, room=%v", n, room)
	}
}

// Routes never checked (a link just pasted) are checked first.
func TestSurvey_TheButtonChecksNeverCheckedRoutesFirst(t *testing.T) {
	rig := surveyRig(t, time.Hour)
	now := nowUTC()
	for _, id := range []string{"r1", "r4"} {
		if err := rig.c.store.RecordSuccess(id, now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	SurveyRoutes(true)
	surveyOver(t)
	got := rig.sideProbed()
	if len(got) != 5 || !sameSet(got[:3], "r2", "r3", "r5") {
		t.Fatalf("order %v; r2, r3, r5 were never checked and go first", got)
	}
}

// A paste of many routes is not many handshakes at once: one press
// checks at most surveyUserMax, names the rest "limit", and the next
// press checks those.
func TestSurvey_TheButtonHasACeiling(t *testing.T) {
	setClock(t, time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC))
	shortSurveyWaits(t, time.Hour)
	const total = surveyUserMax + 6
	var routes [][3]string
	for i := 0; i < total; i++ {
		routes = append(routes, [3]string{fmt.Sprintf("p%02d", i), "vless-reality",
			fmt.Sprintf(`{"type":"vless","server":"relay-%02d.example","server_port":443,"tls":{"enabled":true,"server_name":"cover.example"}}`, i)})
	}
	rig := newRaceRig(t, routes)
	fastRecheck(rig.c)
	SurveyRoutes(true)
	b := surveyOver(t)
	if n := len(rig.sideProbed()); n != surveyUserMax {
		t.Fatalf("one press checked %d, ceiling %d", n, surveyUserMax)
	}
	if b["total"] != float64(surveyUserMax) {
		t.Fatalf("total %v", b["total"])
	}
	limited := map[string]bool{}
	for id, r := range surveyResults(b) {
		if r["reason"] == SurveySkipLimit {
			limited[id] = true
		}
	}
	if len(limited) != total-surveyUserMax {
		t.Fatalf("%d named over the ceiling, want %d", len(limited), total-surveyUserMax)
	}
	SurveyRoutes(true)
	surveyOver(t)
	second := rig.sideProbed()[surveyUserMax:]
	if len(second) != total-surveyUserMax {
		t.Fatalf("second press checked %v", second)
	}
	for _, id := range second {
		if !limited[id] {
			t.Fatalf("second press checked %s, which the first had checked", id)
		}
	}
	// The ceiling is a real bound and above the allowance (THE
	// ALLOWANCE AND THE CEILING).
	if surveyUserMax <= sideProbesPerHour || surveyUserMax > 4*sideProbesPerHour {
		t.Fatalf("surveyUserMax %d", surveyUserMax)
	}
}
