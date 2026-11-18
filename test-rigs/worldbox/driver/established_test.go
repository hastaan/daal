package main

import (
	"bytes"
	"strings"
	"testing"
)

// A family expected "blocked" only because the payload outruns the probe's
// budget (category none | unasserted) is indistinguishable from a dead
// family unless the declaration also claims it connected. The validator
// must refuse the declaration without that claim: this is the hole that
// let throttle-56k report PASS for a hysteria2 the relay had no user for.
func TestBudgetBlockedFamiliesMustClaimEstablished(t *testing.T) {
	fams := []string{"vless-reality", "hysteria2"}
	tax := map[string]bool{"tcp_reset": true}
	base := func() Scenario {
		return Scenario{Name: "s", Analogue: "x",
			Prove: []Proof{{Name: "a", Probe: "bulk", To: "elsewhere", Port: 80, Expect: "slow"}, {Name: "b", Probe: "tls", To: "relay", Port: 443, Expect: "ok"}}}
	}
	has := func(errs []error, frag string) bool {
		for _, e := range errs {
			if strings.Contains(e.Error(), frag) {
				return true
			}
		}
		return false
	}
	for _, cat := range []string{CategoryNone, CategoryUnasserted} {
		s := base()
		s.Expect, s.Category = map[string]string{"*": Blocked}, map[string]string{"*": cat}
		if errs := ValidateScenario(s, fams, tax); !has(errs, "a dead family would pass too") {
			t.Errorf("category %s, no established: accepted (%v)", cat, errs)
		}
		s.Established = map[string]string{"vless-reality": Pass}
		if errs := ValidateScenario(s, fams, tax); !has(errs, `family "hysteria2"`) || has(errs, `family "vless-reality"`) {
			t.Errorf("category %s, established for one family only: %v", cat, errs)
		}
		s.Established = map[string]string{"*": Pass}
		if errs := ValidateScenario(s, fams, tax); len(errs) != 0 {
			t.Errorf("category %s, established declared: %v", cat, errs)
		}
	}
	// Blocked by a rule the client can name: no claim needed, none made.
	s := base()
	s.Expect, s.Category = map[string]string{"*": Blocked}, map[string]string{"*": "tcp_reset"}
	if errs := ValidateScenario(s, fams, tax); len(errs) != 0 {
		t.Errorf("rule-blocked scenario: %v", errs)
	}
	if s.MustEstablish("hysteria2") {
		t.Error("MustEstablish with nothing declared")
	}
	// The claim is only ever "pass", only about real families, and means
	// nothing for a family that is expected to carry the payload anyway.
	s.Established = map[string]string{"*": Blocked, "nosuch": Pass}
	if errs := ValidateScenario(s, fams, tax); !has(errs, `established["*"]="blocked"`) || !has(errs, `established for "nosuch"`) {
		t.Errorf("bad established entries accepted: %v", errs)
	}
	s = base()
	s.Expect, s.Category = map[string]string{"*": Blocked, "hysteria2": Pass}, map[string]string{"*": CategoryUnasserted}
	s.Established = map[string]string{"*": Pass}
	if s.MustEstablish("hysteria2") || !s.MustEstablish("vless-reality") {
		t.Error("MustEstablish must follow expect: only blocked families carry the claim")
	}
}

// The shipped degrading scenarios make the claim for every family they block.
func TestDegradingScenariosClaimEstablished(t *testing.T) {
	rig := rigDir(t)
	_, fams, err := LoadFamilies(rig)
	if err != nil {
		t.Fatal(err)
	}
	for name, spared := range map[string][]string{"throttle-56k": nil, "heavy-loss": {"hysteria2", "tuic"}} {
		s, err := LoadScenario(rig, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fams {
			if want := !contains(spared, f); s.MustEstablish(f) != want {
				t.Errorf("%s: MustEstablish(%s) = %v, want %v", name, f, !want, want)
			}
		}
	}
}

func TestEstablishedBy(t *testing.T) {
	for _, c := range []struct {
		pr   ProbeResult
		want bool
	}{
		{ProbeResult{NonceOK: true, Remote: Relay1EgressIP}, true},
		{ProbeResult{NonceOK: true, Remote: ClientIP}, false}, // a path, but not the tunnel
		{ProbeResult{NonceOK: false, Remote: Relay1EgressIP}, false},
		{ProbeResult{}, false},
	} {
		if got := establishedBy(c.pr); got != c.want {
			t.Errorf("establishedBy(%+v) = %v, want %v", c.pr, got, c.want)
		}
	}
}

// The matrix must not show a dead family as "blocked:none" in green.
func TestReportShowsAFamilyThatNeverConnected(t *testing.T) {
	checks := []Check{
		chk("throttle-56k", BoxTree, "family", "hysteria2", "tunnel", Blocked, Blocked),
		chk("throttle-56k", BoxTree, "censor", "hysteria2", "truth.category", "none", "none"),
		chk("throttle-56k", BoxTree, "family", "hysteria2", "established", Pass, Blocked),
		chk("throttle-56k", BoxTree, "family", "vless-reality", "tunnel", Blocked, Blocked),
		chk("throttle-56k", BoxTree, "censor", "vless-reality", "truth.category", "none", "none"),
		chk("throttle-56k", BoxTree, "family", "vless-reality", "established", Pass, Pass),
	}
	var b bytes.Buffer
	rc := report(&b, "t", nil, []worldRun{{Label: "throttle-56k", Checks: checks}})
	out := b.String()
	if !strings.Contains(out, "!blocked:never-connected(want pass)") {
		t.Errorf("the dead family is not flagged in the matrix:\n%s", out)
	}
	if !strings.Contains(out, " blocked:none") {
		t.Errorf("the live family lost its cell:\n%s", out)
	}
	if rc == 0 {
		t.Error("report() returned 0 with a red established check")
	}
}
