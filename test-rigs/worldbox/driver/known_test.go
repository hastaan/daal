package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// known-findings.json is the one place a red check is allowed not to
// fail the run. These tests keep it honest.

func chk(scn, box, phase, fam, id, expect, got string) Check {
	return Check{Scenario: scn, Box: box, Phase: phase, Family: fam, Check: id, Expect: expect, Got: got, OK: expect == got}
}

// Every entry must point at a section of FINDINGS.md, and that section
// must not be recorded as fixed: a fixed finding has no business
// excusing a red check.
func TestKnownFindingsAreOpenFindings(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(rigDir(t), "FINDINGS.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	for _, k := range ks {
		if !regexp.MustCompile(`(?m)^## ` + regexp.QuoteMeta(k.ID) + ` — `).MatchString(doc) {
			t.Errorf("known-findings.json: %s has no \"## %s — …\" section in FINDINGS.md", k.ID, k.ID)
		}
		row := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(k.ID) + ` \|.*$`).FindString(doc)
		if row == "" {
			t.Errorf("FINDINGS.md: the index table has no row for %s", k.ID)
			continue
		}
		cells := strings.Split(row, "|")
		status := strings.ToLower(cells[len(cells)-4]) // | id | severity | one line | status | reproduce | pinned by |
		if !strings.Contains(status, "open") {
			t.Errorf("FINDINGS.md: %s is excused by known-findings.json but its status is %q, not open (for a fix that has not shipped, say \"open on released relays\" and restrict the entry with when.box)", k.ID, strings.TrimSpace(cells[len(cells)-4]))
		}
		if !strings.Contains(row, "known-findings.json") {
			t.Errorf("FINDINGS.md: the row for %s must say it is tracked in known-findings.json (the \"pinned by\" column)", k.ID)
		}
	}
}

// The mechanisms below — an entry restricted to the pinned box, and an
// intermittent entry with a budget — are tested on the two findings
// that first needed them, F-002 and INT-2. Both are "fixed in the tree,
// open on released relays", so both leave known-findings.json in the
// pin-bump commit (tools/release/README.md), and these tests must not
// go red with them: where the file no longer carries an entry it is
// rebuilt here, exactly as it stood, so the mechanism stays tested
// after the finding that motivated it is closed.
func withReleasedRelayFixtures(ks []KnownFinding) []KnownFinding {
	has := map[string]bool{}
	for _, k := range ks {
		has[k.ID] = true
	}
	out := append([]KnownFinding{}, ks...)
	if !has["F-002"] {
		f := KnownFinding{ID: "F-002", Severity: "high", Title: "the pinned release cannot provision shadowsocks, anytls and tuic",
			Match: []KnownMatch{
				{Phase: "mint", Family: "anytls,shadowsocks,tuic", Check: "relay.listens,pack.route"},
				{Phase: "family", Family: "anytls,shadowsocks,tuic", Check: "tunnel,engine.category"},
			}}
		f.When.Box = BoxPinned
		out = append(out, f)
	}
	if !has["INT-2"] {
		f := KnownFinding{ID: "INT-2", Severity: "medium", Title: "naive on a released relay: the start-up ALPN race",
			Intermittent: true, Max: 4,
			Match: []KnownMatch{{Phase: "*", Family: "naive", Check: "*tunnel,*wire", DetailContains: "net_error -107"}}}
		f.When.Box = BoxPinned
		out = append(out, f)
	}
	return out
}

func TestJudge(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ks = withReleasedRelayFixtures(ks)
	// A red check nothing explains fails the run.
	v := Judge(ks, []Check{chk("clean", BoxTree, "family", "tuic", "tunnel", Pass, Blocked)})
	if v.OK() || len(v.Unexpected) != 1 {
		t.Fatalf("an unexplained red check must fail the run: %+v", v)
	}
	// The same red check on the PINNED box is F-002 — and only there.
	v = Judge(ks, []Check{chk("clean", BoxPinned, "family", "tuic", "tunnel", Pass, Refused)})
	if !v.OK() || v.Known["F-002"] != 1 {
		t.Fatalf("F-002 should explain a refused tuic tunnel on the pinned box: %+v", v)
	}
	// …but never a default family there.
	v = Judge(ks, []Check{chk("clean", BoxPinned, "family", "hysteria2", "tunnel", Pass, Refused)})
	if v.OK() {
		t.Fatalf("F-002 must not excuse a default family: %+v", v)
	}
	// CEN-4: the engine names the coarser thing one route can see — and
	// only that is excused.
	v = Judge(ks, []Check{chk("relay-ip-block", BoxTree, "family", "hysteria2", "engine.category", "udp_address_blocked", "udp_no_reply")})
	if !v.OK() || v.Known["CEN-4"] != 1 {
		t.Fatalf("CEN-4: %+v", v)
	}
	v = Judge(ks, []Check{chk("tcp-reset-mid-handshake", BoxTree, "family", "vless-reality", "engine.category", "tcp_reset", "tls_sni_or_cert_block_suspected")})
	if !v.OK() || v.Known["CEN-4"] != 1 {
		t.Fatalf("CEN-4 (reset after the ClientHello): %+v", v)
	}
	v = Judge(ks, []Check{chk("clean", BoxTree, "family", "hysteria2", "engine.category", "none", "udp_no_reply")})
	if v.OK() {
		t.Fatalf("an engine that reports a failure on a working route is not CEN-4: %+v", v)
	}
	// CEN-1, fixed, was "the engine reports NOTHING". If that comes back
	// nothing in the file excuses it: unexpected, on TCP and on UDP.
	for _, c := range []Check{
		chk("relay-ip-block", BoxTree, "family", "naive", "engine.category", "tcp_connect_timeout", "none"),
		chk("relay-ip-block", BoxTree, "family", "hysteria2", "engine.category", "udp_address_blocked", "none"),
	} {
		if v = Judge(ks, []Check{c}); v.OK() || len(v.Unexpected) != 1 || len(v.Known) != 0 {
			t.Fatalf("an engine that says nothing about a blocked route (CEN-1, fixed) must be unexpected: %+v", v)
		}
	}
	// A WRONG category is a different defect again: unexpected, and —
	// being red — not "CEN-4 did not reproduce" either.
	v = Judge(ks, []Check{chk("sni-rst", BoxTree, "family", "vless-reality", "engine.category", "tls_sni_or_cert_block_suspected", "tcp_reset")})
	if v.OK() || len(v.Unexpected) != 1 || len(v.Known) != 0 || len(v.Stale) != 0 {
		t.Fatalf("a wrong category must be unexpected, not KNOWN: %+v", v)
	}
	v = Judge(ks, []Check{chk("udp-blackhole", BoxTree, "family", "tuic", "engine.category", "udp_unavailable", "quic_unavailable")})
	if v.OK() || v.Known["CEN-4"] != 0 {
		t.Fatalf("a network-wide claim from one silent route is not what CEN-4 excuses: %+v", v)
	}
	// A finding whose checks ran and were all green did not reproduce:
	// that fails the run until a human edits the list.
	v = Judge(ks, []Check{chk("relay-ip-block", BoxTree, "family", "hysteria2", "engine.category", "udp_address_blocked", "udp_address_blocked")})
	if v.OK() || len(v.Stale) != 1 || v.Stale[0] != "CEN-4" {
		t.Fatalf("a fixed finding must be reported as not reproducing: %+v", v)
	}
	// …but one green among reds is not "fixed".
	v = Judge(ks, []Check{
		chk("relay-ip-block", BoxTree, "family", "hysteria2", "engine.category", "udp_address_blocked", "udp_address_blocked"),
		chk("relay-ip-block", BoxTree, "family", "tuic", "engine.category", "udp_address_blocked", "udp_no_reply"),
	})
	if !v.OK() {
		t.Fatalf("%+v", v)
	}
	// An intermittent finding (a race) is excused only with its signature,
	// and is never required to show up.
	crash := chk("clean", BoxTree, "op:l1", "naive", "before.engine.survived", Pass, Fail)
	crash.Detail = "the engine process died mid-session: SIGSEGV: segmentation violation | github.com/sagernet/cronet-go/internal/cronet.BidirectionalStreamCancel"
	// INT-1 (the Cronet cancel/destroy crash) is fixed and no longer in
	// the file: with the real list, one engine death fails the run.
	if v = Judge(ks, []Check{crash}); v.OK() || len(v.Unexpected) != 1 || len(v.Known) != 0 {
		t.Fatalf("an engine crash in Cronet (INT-1, fixed) must be unexpected: %+v", v)
	}
	// The budget mechanism it motivated is still what INT-2 runs on, so
	// the entry is rebuilt here, as it stood, to keep the mechanism
	// tested on a tree box and with a quick budget.
	ks = append(ks, KnownFinding{
		ID: "INT-1", Severity: "high", Title: "naive: the engine dies with SIGSEGV in cronet-go's BidirectionalStream.Cancel",
		Intermittent: true, Max: 6, MaxQuick: 2,
		Match: []KnownMatch{{Phase: "*", Family: "naive", Check: "*engine.survived", DetailContains: "BidirectionalStreamCancel"}},
	})
	if v = Judge(ks, []Check{crash}); !v.OK() || v.Known["INT-1"] != 1 {
		t.Fatalf("INT-1: %+v", v)
	}
	other := crash
	other.Detail = "the engine process died mid-session: panic: runtime error: index out of range | daal/core/engine.(*Engine).SetRoute"
	if v = Judge(ks, []Check{other}); v.OK() {
		t.Fatalf("a different crash must not be excused as INT-1: %+v", v)
	}
	other = crash
	other.Family = "hysteria2"
	if v = Judge(ks, []Check{other}); v.OK() {
		t.Fatalf("INT-1 is about naive only: %+v", v)
	}
	// …and only up to its budget: the same signature in every session is
	// a regression wearing the race's clothes, and none of it is excused.
	budget := 0
	for _, k := range ks {
		if k.ID == "INT-1" {
			budget = k.Max
		}
	}
	many := []Check{}
	for i := 0; i < budget; i++ {
		many = append(many, crash)
	}
	if v = Judge(ks, many); !v.OK() || v.Known["INT-1"] != budget {
		t.Fatalf("INT-1 within its budget of %d: %+v", budget, v)
	}
	many = append(many, crash)
	if v = Judge(ks, many); v.OK() || len(v.Unexpected) != budget+1 || v.Known["INT-1"] != 0 {
		t.Fatalf("INT-1 over its budget must fail the run: %+v", v)
	}
	// The quick matrix (pre-push) has its own, smaller budget: a crash
	// rate that the full matrix's budget would absorb must fail a push.
	qs := ForMode(ks, "quick")
	quick := 0
	for _, k := range qs {
		if k.ID == "INT-1" {
			quick = k.Max
		}
	}
	if quick < 1 || quick >= budget {
		t.Fatalf("INT-1: quick budget %d must be set and below the full budget %d", quick, budget)
	}
	if ks2 := ForMode(ks, "full"); ks2[len(ks2)-1].Max != ks[len(ks)-1].Max {
		t.Fatalf("ForMode(full) must not change budgets")
	}
	many = many[:quick]
	if v = Judge(qs, many); !v.OK() || v.Known["INT-1"] != quick {
		t.Fatalf("INT-1 within its quick budget of %d: %+v", quick, v)
	}
	if l := v.intermittentLine(qs); !strings.Contains(l, fmt.Sprintf("INT-1 ×%d (budget %d)", quick, quick)) {
		t.Fatalf("the verdict must state the race count against its budget: %q", l)
	}
	many = append(many, crash)
	if v = Judge(qs, many); v.OK() {
		t.Fatalf("%d INT-1 crashes pass the full budget but must fail a quick run: %+v", quick+1, v)
	}
	if l := v.intermittentLine(qs); !strings.Contains(l, fmt.Sprintf("INT-1 ×%d OVER", quick+1)) {
		t.Fatalf("over budget, the line must say so and give the real count: %q", l)
	}
	if v = Judge(ks, many); !v.OK() {
		t.Fatalf("%d INT-1 crashes are within the full budget: %+v", quick+1, v)
	}
	// Findings whose checks did not run say nothing either way.
	v = Judge(ks, []Check{chk("clean", BoxTree, "family", "naive", "tunnel", Pass, Pass)})
	if !v.OK() || len(v.Stale) != 0 {
		t.Fatalf("%+v", v)
	}
}

// An entry may not be a blanket.
func TestKnownEntriesAreNarrow(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range ks {
		for _, m := range k.Match {
			// The check pattern is what must be specific; the phase may be
			// "*" (a crash can happen in any phase's session).
			for _, pat := range strings.Split(m.Check, ",") {
				if strings.Trim(pat, "*?. ") == "" {
					t.Errorf("%s: check pattern %q matches everything", k.ID, pat)
				}
			}
		}
	}
}

func e2ePlan(t *testing.T, mode string) map[string]string {
	t.Helper()
	out, err := exec.Command("bash", filepath.Join(rigDir(t), "e2e.sh"), "--plan", mode).Output()
	if err != nil {
		t.Fatalf("e2e.sh --plan %s: %v", mode, err)
	}
	plan := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		label, args, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("plan line without a tab: %q", line)
		}
		if _, dup := plan[label]; dup {
			t.Errorf("%s plan has two worlds labelled %q: one would overwrite the other's results", mode, label)
		}
		plan[label] = args
	}
	return plan
}

// The single entry point must reach everything that is declared: a
// scenario, family or op that no mode runs is code nothing calls — the
// exact failure this rig exists to catch.
func TestE2EPlanReachesEverything(t *testing.T) {
	rig := rigDir(t)
	_, families, err := LoadFamilies(rig)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"quick", "full"} {
		plan := e2ePlan(t, mode)
		scn := map[string][]string{} // scenario → family arguments of each world running it
		ops := map[string]bool{}
		pinnedDefault := false
		for label, args := range plan {
			var pos []string
			f := strings.Fields(args)
			for i := 0; i < len(f); i++ {
				switch {
				case f[i] == "--ops":
					for _, o := range strings.Split(f[i+1], ",") {
						if _, ok := Ops[o]; !ok {
							t.Errorf("%s/%s: unknown op %q", mode, label, o)
						}
						ops[o] = true
						if o == "lifecycle" {
							for _, l := range LifecycleOps {
								ops[l] = true
							}
						}
					}
					i++
				case strings.HasPrefix(f[i], "--"):
				default:
					pos = append(pos, f[i])
				}
			}
			if len(pos) == 0 {
				t.Fatalf("%s/%s: no scenario in %q", mode, label, args)
			}
			if _, err := LoadScenario(rig, pos[0]); err != nil {
				t.Errorf("%s/%s: %v", mode, label, err)
			}
			scn[pos[0]] = append(scn[pos[0]], strings.Join(pos[1:], " "))
			if !strings.Contains(args, "--mgmt=tree") && strings.Contains(args, "@default") {
				pinnedDefault = true
			}
		}
		for _, s := range listNames(rig, "scenarios") {
			if len(scn[s]) == 0 {
				t.Errorf("%s mode runs no world for scenarios/%s.json", mode, s)
			}
			if mode == "full" {
				all := false
				for _, fams := range scn[s] {
					all = all || fams == ""
				}
				if !all {
					t.Errorf("full mode must run scenario %s against every family (a world with no family arguments)", s)
				}
			}
		}
		// Every family carries bytes with no censor in both modes.
		all := false
		for _, fams := range scn["clean"] {
			all = all || fams == ""
		}
		if !all {
			t.Errorf("%s mode must run `clean` against all of %v", mode, families)
		}
		if !pinnedDefault {
			t.Errorf("%s mode must run the pinned release artefacts with the default families: that is what a relay provisioned today really runs", mode)
		}
		if mode == "full" {
			for name := range Ops {
				if name != "lifecycle" && !ops[name] {
					t.Errorf("full mode never runs op %q (ops_%s.go)", name, name)
				}
			}
		}
	}
}

// The report's exit status: 0 clean, 1 unexpected, 2 a world that did not run.
func TestReportExitStatus(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	good := worldRun{Label: "clean", RC: "0", Checks: []Check{chk("clean", BoxTree, "family", "naive", "tunnel", Pass, Pass)}}
	known := worldRun{Label: "relay-ip-block", RC: "0", Checks: []Check{
		chk("relay-ip-block", BoxTree, "family", "hysteria2", "tunnel", Blocked, Blocked),
		chk("relay-ip-block", BoxTree, "family", "hysteria2", "engine.category", "udp_address_blocked", "udp_no_reply")}}
	bad := worldRun{Label: "sni-rst", RC: "1", Checks: []Check{chk("sni-rst", BoxTree, "family", "naive", "tunnel", Pass, Blocked)}}
	dead := worldRun{Label: "quic-drop", RC: "2", Broken: "run.sh exit \"2\""}
	var buf bytes.Buffer
	if rc := report(&buf, "t", ks, []worldRun{good, known}); rc != 0 {
		t.Errorf("known findings only: exit %d, want 0\n%s", rc, buf.String())
	}
	if !strings.Contains(buf.String(), "~blocked:") && !strings.Contains(buf.String(), "CEN-4") {
		t.Errorf("the report does not name the known finding:\n%s", buf.String())
	}
	if rc := report(&buf, "t", ks, []worldRun{good, bad}); rc != 1 {
		t.Errorf("unexpected red: exit %d, want 1", rc)
	}
	if rc := report(&buf, "t", ks, []worldRun{good, dead}); rc != 2 {
		t.Errorf("broken world: exit %d, want 2", rc)
	}
}

// A world stopped before its first client session by a red check of its
// own is a verdict on Daal (exit 1, UNEXPECTED, the phase named), not a
// broken rig. Broken is only: run.sh died, or left nothing to judge.
func TestEarlyStopIsAVerdictNotABrokenRig(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	up := chk("clean", BoxTree, "world", "", "relay.up", Pass, Pass)
	red := chk("clean", BoxTree, "provision", "", "record", Pass, Fail)
	for _, tc := range []struct {
		name          string
		w             worldRun
		broken, early bool
	}{
		{"red check before any session", worldRun{RC: "1", Checks: []Check{up, red}}, false, true},
		{"run.sh died", worldRun{RC: "2", Checks: []Check{up, red}}, true, false},
		{"timeout", worldRun{RC: "124", Checks: []Check{up}}, true, false},
		{"nothing recorded", worldRun{RC: "1"}, true, false},
		{"no session, nothing red, exit 0", worldRun{RC: "0", Checks: []Check{up}}, true, false},
		{"no session, nothing red, exit 1", worldRun{RC: "1", Checks: []Check{up}}, true, false},
		{"sessions ran", worldRun{RC: "1", Checks: []Check{up, chk("clean", BoxTree, "family", "naive", "tunnel", Pass, Blocked)}}, false, false},
	} {
		w := tc.w
		w.classify(ks)
		if (w.Broken != "") != tc.broken || (w.Early != "") != tc.early {
			t.Errorf("%s: Broken=%q Early=%q, want broken=%v early=%v", tc.name, w.Broken, w.Early, tc.broken, tc.early)
		}
	}

	good := worldRun{Label: "sni-rst", RC: "0", Checks: []Check{chk("sni-rst", BoxTree, "family", "naive", "tunnel", Pass, Pass)}}
	early := worldRun{Label: "clean", RC: "1", Checks: []Check{up, red}}
	early.classify(ks)
	var buf bytes.Buffer
	if rc := report(&buf, "t", ks, []worldRun{early, good}); rc != 1 {
		t.Errorf("early stop on a red check: exit %d, want 1\n%s", rc, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"STOPPED EARLY at provision/record", "!STOPPED at provision/record", "UNEXPECTED — 1 check(s)", "RESULT: FAIL"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "BROKEN") {
		t.Errorf("a product defect is reported as a broken rig:\n%s", out)
	}
}

// The crash signature is what ties an engine death to a finding; it is
// cut from the dead process's stderr. testdata holds the head of the
// first one the rig saw (FINDINGS INT-1).
func TestCrashSignature(t *testing.T) {
	dir := t.TempDir()
	body, err := os.ReadFile(filepath.Join("testdata", "cronet-cancel-crash.stderr"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stderr.log"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := (&Client{Dir: dir}).CrashSignature()
	for _, want := range []string{"SIGSEGV", "cgo", "BidirectionalStreamCancel", "(*BidirectionalConn).Close"} {
		if !strings.Contains(sig, want) {
			t.Errorf("signature %q does not contain %q", sig, want)
		}
	}
	if empty := (&Client{Dir: t.TempDir()}).CrashSignature(); !strings.Contains(empty, "without a word") {
		t.Errorf("no stderr: %q", empty)
	}
}

// An entry is pinned to a DEFECT, not to a cell: a new regression that
// lands in the cell of an open finding must not be counted as it.
func TestKnownEntriesArePinnedToTheirDefect(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	// The mechanism, on the entry that first needed it. F-004 (fixed; no
	// longer in the file) was "a profile rewrite is accepted while a
	// manifest rewrite is refused": ops_tamper.go puts the control's
	// outcome in the evidence, and the entry required it. The entry is
	// rebuilt here so the mechanism stays tested after the finding that
	// motivated it was closed.
	pinned := append([]KnownFinding{{
		ID: "F-004", Severity: "high", Title: "pack profiles are outside the signature",
		Match: []KnownMatch{{Phase: "op:tamper", Check: "import_of_tampered_pack", Got: Pass,
			Evidence: map[string]string{"rewritten": "profiles", "manifest_rewrite": Refused}}},
	}}, ks...)
	tamper := func(manifest string) Check {
		c := chk("clean", BoxTree, "op:tamper", "", "import_of_tampered_pack", Refused, Pass)
		c.Evidence = map[string]any{"rewritten": "profiles", "manifest_rewrite": manifest}
		return c
	}
	if v := Judge(pinned, []Check{tamper(Refused)}); !v.OK() || v.Known["F-004"] != 1 {
		t.Fatalf("F-004: %+v", v)
	}
	// Signature verification lost: the manifest rewrite imports too. Same
	// cell, same got — and not F-004.
	if v := Judge(pinned, []Check{tamper(Pass)}); v.OK() || v.Known["F-004"] != 0 || len(v.Unexpected) != 1 || len(v.Stale) != 0 {
		t.Fatalf("an import that accepts a tampered pack while the manifest control is NOT refused must be unexpected, not KNOWN [F-004]: %+v", v)
	}
	// …nor when the control could not run, or the evidence is absent.
	if v := Judge(pinned, []Check{tamper(Fail)}); v.OK() {
		t.Fatalf("F-004 without a refused manifest control: %+v", v)
	}
	bare := chk("clean", BoxTree, "op:tamper", "", "import_of_tampered_pack", Refused, Pass)
	if v := Judge(pinned, []Check{bare}); v.OK() {
		t.Fatalf("F-004 without its evidence: %+v", v)
	}
	// …nor an import that is red for another reason (the client died).
	died := tamper(Refused)
	died.Got = Fail
	if v := Judge(pinned, []Check{died}); v.OK() {
		t.Fatalf("F-004 excuses only an ACCEPTED import: %+v", v)
	}
	// With the finding FIXED and its entry gone, an accepted tampered
	// pack is not excused by anything in the real file.
	if v := Judge(ks, []Check{tamper(Refused)}); v.OK() || len(v.Unexpected) != 1 {
		t.Fatalf("a tampered pack that imports must be an unexpected red now that F-004 is fixed: %+v", v)
	}
	// The cells the review named are pinned, in the file itself.
	for _, k := range ks {
		for _, m := range k.Match {
			switch k.ID {
			case "F-004", "LC-2", "LC-3":
				t.Errorf("%s is fixed (FINDINGS.md); it must not come back as an excuse: %+v", k.ID, m)
			case "CEN-1":
				t.Errorf("CEN-1 is fixed (FINDINGS.md); it must not come back as an excuse: %+v", m)
			case "CEN-4":
				// …and, in a pass of the automatic connect, to the one
				// refinement that is coarser than the truth (ops_auto.go
				// quicOnly).
				inPass := m.Phase == "op:auto" && m.Check == "quic-only.connect.refined" && m.Got == "udp_blocked_here"
				if m.Got != "udp_no_reply" && m.Got != "tls_sni_or_cert_block_suspected" && !inPass {
					t.Errorf("CEN-4 must be pinned to the coarser category the engine reports: %+v", m)
				}
			}
		}
	}
}

// One world judged alone never excuses an intermittent finding: a single
// naive session that fails with the race's signature is indistinguishable
// from a deterministic break carrying the same code.
func TestIntermittentIsNotExcusedInASingleWorld(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ks = withReleasedRelayFixtures(ks)
	tun := chk("clean", BoxPinned, "family", "naive", "tunnel", Pass, Blocked)
	tun.Detail = "probe: net_error -107 (ERR_SSL_PROTOCOL_ERROR)"
	wire := chk("clean", BoxPinned, "family", "naive", "wire", Pass, Fail)
	wire.Detail = tun.Detail
	oneSession := []Check{tun, wire}

	world := ForMode(ks, ModeWorld)
	v := Judge(world, oneSession)
	if v.OK() || len(v.Unexpected) != 2 || v.Known["INT-2"] != 0 {
		t.Fatalf("`./run.sh clean naive` with a -107 session must exit 1: %+v", v)
	}
	if !strings.Contains(v.Unexpected[0].Detail, "INT-2") || !strings.Contains(v.Unexpected[0].Detail, "single-world") {
		t.Errorf("the red check must say why the known race is not excused here: %q", v.Unexpected[0].Detail)
	}
	if l := v.intermittentLine(world); !strings.Contains(l, "INT-2 ×2 — NOT excused") {
		t.Errorf("verdict line: %q", l)
	}
	// What the world itself stores and prints is a plain red…
	if id := excusedNow(world, tun); id != "" {
		t.Errorf("a single world marked the check KNOWN [%s]", id)
	}
	// …so the matrix, which has a rate to judge by, decides with its budget.
	for _, mode := range []string{"quick", "full"} {
		if v := Judge(ForMode(ks, mode), oneSession); !v.OK() || v.Known["INT-2"] != 2 {
			t.Fatalf("%s matrix: one -107 session is within INT-2's budget: %+v", mode, v)
		}
	}
	// INT-2 is fixed in the tree daemon: on a tree box the same face is a
	// regression, in every mode.
	onTree := []Check{tun, wire}
	onTree[0].Box, onTree[1].Box = BoxTree, BoxTree
	for _, mode := range []string{"quick", "full"} {
		if v := Judge(ForMode(ks, mode), onTree); v.OK() || v.Known["INT-2"] != 0 {
			t.Fatalf("%s matrix: a -107 naive session on the TREE box must be unexpected: %+v", mode, v)
		}
	}
	// Non-intermittent findings are untouched by the mode.
	cen := chk("relay-ip-block", BoxTree, "family", "hysteria2", "engine.category", "udp_address_blocked", "udp_no_reply")
	if v := Judge(world, []Check{cen}); !v.OK() || v.Known["CEN-4"] != 1 {
		t.Fatalf("CEN-4 in a single world: %+v", v)
	}
}

// The report says outright how many blocked sessions the engine named
// correctly, how many it named as the coarser thing one route can see
// (and which truth became which report), and how many it got wrong — so
// a column of KNOWN reds is never read as coverage, and a regression to
// "the engine says nothing" (CEN-1) reads as exactly that.
func TestReportStatesEngineCategoryCoverage(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	blocked := worldRun{Label: "relay-ip-block", RC: "0", Checks: []Check{
		chk("relay-ip-block", BoxTree, "family", "naive", "tunnel", Blocked, Blocked),
		chk("relay-ip-block", BoxTree, "family", "naive", "engine.category", "tcp_connect_timeout", "tcp_connect_timeout"),
		chk("relay-ip-block", BoxTree, "family", "tuic", "tunnel", Blocked, Blocked),
		chk("relay-ip-block", BoxTree, "family", "tuic", "engine.category", "udp_address_blocked", "udp_no_reply"),
		chk("relay-ip-block", BoxTree, "family", "anytls", "engine.category", "none", "none")}}
	var buf bytes.Buffer
	report(&buf, "t", ks, []worldRun{blocked})
	out := buf.String()
	if !strings.Contains(out, "correctly in 1 of 2 blocked sessions") ||
		!strings.Contains(out, "in 1 more it reported what one route can see") ||
		!strings.Contains(out, "udp_address_blocked → udp_no_reply ×1") || strings.Contains(out, "NOT coverage") {
		t.Errorf("1 named, 1 coarser, each said as what it is:\n%s", out)
	}
	// The engine saying nothing at all (what CEN-1 was) is neither.
	blocked.Checks[1].Got, blocked.Checks[1].OK = "none", false
	blocked.Checks[3].Got = "none"
	buf.Reset()
	report(&buf, "t", ks, []worldRun{blocked})
	out = buf.String()
	if !strings.Contains(out, "correctly in 0 of 2 blocked sessions") || !strings.Contains(out, "2 misnamed with no finding") || !strings.Contains(out, "NOT coverage") {
		t.Errorf("0 of 2, both unexplained, and not coverage:\n%s", out)
	}
}
