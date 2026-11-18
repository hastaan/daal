package main

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// A KnownFinding ties a red check to an OPEN entry in FINDINGS.md.
//
// The rig never turns a red check green: a check that does not match its
// expectation keeps ok=false in results.jsonl. What this file changes is
// the VERDICT. A rig that exits 1 on every run for a defect somebody has
// already read about is a rig nobody looks at, and the next real
// regression drowns in it. So:
//
//   - a red check that matches an entry here is reported as KNOWN, with
//     the finding's id, and does not fail the run;
//   - a red check that matches nothing fails the run;
//   - an entry whose checks RAN and were all green fails the run too
//     ("did not reproduce"): the finding was fixed, or the check stopped
//     looking. Either way known-findings.json and FINDINGS.md must be
//     edited by a human, so a fix is noticed the day it lands and an
//     entry can never rot into a blanket excuse.
//
// Entries are deliberately narrow (phase + family + check, optionally
// which box artefacts). known_test.go refuses an entry without an id
// that FINDINGS.md has a section for.
type KnownFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	// When restricts the entry to worlds whose box runs the "pinned"
	// release artefacts or the "tree" build of daal-relay-mgmt.
	When struct {
		Box string `json:"box,omitempty"`
	} `json:"when,omitempty"`
	// Intermittent: a defect that does not show on every run (a race).
	// It is excused when it appears and never required to appear, so the
	// "did not reproduce" rule does not apply to it — which is exactly
	// why such an entry must be pinned to a signature (detail_contains).
	Intermittent bool `json:"intermittent,omitempty"`
	// Max: how many red checks an intermittent entry may explain in one
	// judged set (one world, or one whole matrix). One more than that and
	// NONE of them is excused: a race shows up once or twice in a run; a
	// regression that happens to carry the same signature shows up in
	// every session, and must not be waved through as "the known race".
	Max int `json:"max,omitempty"`
	// MaxQuick: the same budget for the quick matrix (the one pre-push
	// runs), which has a fraction of the sessions of the full one. A
	// budget sized for the full matrix would let the push gate wave
	// through a crash rate several times the one on record.
	MaxQuick int          `json:"max_quick,omitempty"`
	Match    []KnownMatch `json:"match"`
}

// KnownMatch selects checks. Every field is a comma list of path.Match
// globs; empty means "any". Family "-" means "checks with no family".
type KnownMatch struct {
	Scenario string `json:"scenario,omitempty"`
	Phase    string `json:"phase,omitempty"`
	Family   string `json:"family,omitempty"`
	Check    string `json:"check,omitempty"`
	// ExpectNot excludes checks whose expectation is one of these (the
	// engine.category check expects "none" wherever nothing is blocked,
	// and that is not the finding).
	ExpectNot []string `json:"expect_not,omitempty"`
	// Got: a red check is EXCUSED only if what it got is one of these (a
	// comma list of globs). It does not narrow which checks the finding is
	// about: a check in scope that is red with some other value is not
	// this finding — it is unexpected, and fails the run. (CEN-4 is "the
	// engine names the coarser thing one route can see"; an engine that
	// says NOTHING, or something else, is a different defect and must
	// not hide behind it.)
	Got string `json:"got,omitempty"`
	// Evidence: like Got, a condition for EXCUSING a red check, never for
	// scoping it: every key must be present in the check's evidence with
	// exactly this value (compared as text). It pins an entry to the
	// defect rather than to the cell — F-004 is "a PROFILE rewrite is
	// accepted while a manifest rewrite is refused"; an import that accepts
	// a tampered pack because the signature is no longer checked at all
	// lands in the same cell and must not be counted as F-004.
	Evidence map[string]string `json:"evidence,omitempty"`
	// DetailContains: the red check's detail must contain this text (a
	// crash signature). Only red checks carry the detail, so an entry
	// using it can never be judged "did not reproduce".
	DetailContains string `json:"detail_contains,omitempty"`
}

func LoadKnown(rig string) ([]KnownFinding, error) {
	var ks []KnownFinding
	if err := loadJSON(filepath.Join(rig, "known-findings.json"), &ks); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, k := range ks {
		if k.ID == "" || len(k.Match) == 0 {
			return nil, fmt.Errorf("known-findings.json: an entry needs an id and at least one match (%+v)", k)
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("known-findings.json: duplicate id %s", k.ID)
		}
		seen[k.ID] = true
		if b := k.When.Box; b != "" && b != BoxPinned && b != BoxTree {
			return nil, fmt.Errorf("known-findings.json: %s: when.box=%q, want pinned|tree", k.ID, b)
		}
		if k.Intermittent != (k.Max > 0) {
			return nil, fmt.Errorf("known-findings.json: %s: intermittent entries, and only they, need max (how many hits one run may have before it is a regression, not a race)", k.ID)
		}
		if k.MaxQuick < 0 || k.MaxQuick > k.Max {
			return nil, fmt.Errorf("known-findings.json: %s: max_quick=%d must be between 1 and max=%d (the quick matrix is a subset of the full one)", k.ID, k.MaxQuick, k.Max)
		}
		for _, m := range k.Match {
			if m.Phase == "" || m.Check == "" {
				return nil, fmt.Errorf("known-findings.json: %s: every match needs a phase and a check — an entry must not be a blanket", k.ID)
			}
			if k.Intermittent != (m.DetailContains != "") {
				return nil, fmt.Errorf("known-findings.json: %s: intermittent entries, and only they, must pin every match to a signature with detail_contains", k.ID)
			}
		}
	}
	return ks, nil
}

func globList(patterns, s string) bool {
	if patterns == "" {
		return true
	}
	for _, p := range strings.Split(patterns, ",") {
		if ok, _ := path.Match(strings.TrimSpace(p), s); ok {
			return true
		}
	}
	return false
}

func (m KnownMatch) selects(c Check) bool {
	if !globList(m.Scenario, c.Scenario) || !globList(m.Phase, c.Phase) || !globList(m.Check, c.Check) {
		return false
	}
	switch {
	case m.Family == "-":
		if c.Family != "" {
			return false
		}
	case !globList(m.Family, c.Family):
		return false
	}
	for _, e := range m.ExpectNot {
		if c.Expect == e {
			return false
		}
	}
	if m.DetailContains != "" && !strings.Contains(c.Detail, m.DetailContains) {
		return false
	}
	return true
}

// Selects reports whether c is one of the checks this finding is about
// (red or green).
func (k KnownFinding) Selects(c Check) bool {
	if k.When.Box != "" && k.When.Box != c.Box {
		return false
	}
	for _, m := range k.Match {
		if m.selects(c) {
			return true
		}
	}
	return false
}

// Explains reports whether this finding accounts for the RED check c: c
// is in scope AND what it got is what the finding says happens.
func (k KnownFinding) Explains(c Check) bool {
	if c.OK || (k.When.Box != "" && k.When.Box != c.Box) {
		return false
	}
	for _, m := range k.Match {
		if m.selects(c) && globList(m.Got, c.Got) && m.evidenceMatches(c) {
			return true
		}
	}
	return false
}

func (m KnownMatch) evidenceMatches(c Check) bool {
	for key, want := range m.Evidence {
		got, ok := c.Evidence[key]
		if !ok || fmt.Sprint(got) != want {
			return false
		}
	}
	return true
}

// FindingCoarser is the finding behind an engine.category check that is
// red because the engine reported the coarser thing one route can see
// (FINDINGS CEN-4). The report counts those separately from "named
// correctly" and from "misnamed".
const FindingCoarser = "CEN-4"

// ModeWorld is the mode of a single world judged on its own (run.sh).
const ModeWorld = "world"

// ForMode returns the findings with the budgets of the given matrix mode
// applied ("quick" uses max_quick where an entry has one).
//
// ModeWorld gives every intermittent finding a budget of ZERO. A race is
// told from a regression by its RATE, and one world has no rate: with a
// single naive session, "the relay refused this session's handshakes"
// is two red checks whether it is the one-in-hundreds race or a TLS
// break that happens every time. So a world judged alone (run.sh) never
// excuses an intermittent finding — the check is red, the run exits 1,
// and the text says to re-run. Inside e2e.sh that exit 1 is not the
// verdict: `wb summary` re-judges every check of every world against
// the matrix budget.
func ForMode(ks []KnownFinding, mode string) []KnownFinding {
	out := append([]KnownFinding(nil), ks...)
	if mode == ModeWorld {
		for i := range out {
			if out[i].Intermittent {
				out[i].Max = 0
			}
		}
	}
	if mode == "quick" {
		for i := range out {
			if out[i].MaxQuick > 0 {
				out[i].Max = out[i].MaxQuick
			}
		}
	}
	return out
}

// excusedNow is knownFor for the live progress line and the stored
// `known` field of ONE world: a finding with no budget in this mode
// (intermittent, ModeWorld) excuses nothing, so the check is shown and
// stored as a plain red. The matrix judges it again with its own budget.
func excusedNow(ks []KnownFinding, c Check) string {
	id := knownFor(ks, c)
	for _, k := range ks {
		if k.ID == id && k.Intermittent && k.Max <= 0 {
			return ""
		}
	}
	return id
}

// knownFor returns the id of the finding a RED check belongs to, or "".
func knownFor(ks []KnownFinding, c Check) string {
	if c.OK {
		return ""
	}
	for _, k := range ks {
		if k.Explains(c) {
			return k.ID
		}
	}
	return ""
}

// Verdict is what a set of checks amounts to once the known findings
// are taken into account.
type Verdict struct {
	// Classified / ClassifiedOK: the engine.category checks that expected
	// the engine to name a failure (anything but "none"), and how many of
	// them it got right. Reported on its own line because a column of
	// KNOWN reds reads like coverage and is none (categoryLine).
	Classified, ClassifiedOK int
	// Coarser: of the misnamed ones, expect→got pairs an open finding
	// explains — the engine named something true of what one route can
	// see, and the narrower truth needs a second observation (CEN-4).
	// Misnamed with no finding behind it is in Unexpected, not here.
	Coarser    map[string]int
	Total      int
	Unexpected []Check        // red, and no finding explains it
	Known      map[string]int // finding id → red checks it explains
	Stale      []string       // findings whose checks ran and were all green
	Over       map[string]int // intermittent finding id → hits, where that is over its budget (none excused)
}

func (v Verdict) OK() bool { return len(v.Unexpected) == 0 && len(v.Stale) == 0 }

func Judge(ks []KnownFinding, checks []Check) Verdict {
	v := Verdict{Total: len(checks), Known: map[string]int{}, Over: map[string]int{}, Coarser: map[string]int{}}
	// ran: checks in the finding's scope; red: those of them that were red
	// for ANY reason. A finding is stale only when its whole scope is
	// green — a scope that is red with a value the finding does not
	// explain is not "fixed", it is unexpected (and reported as that).
	ran, red := map[string]int{}, map[string]int{}
	for _, c := range checks {
		if strings.HasSuffix(c.Check, "engine.category") && c.Expect != "none" && c.Got != Skipped {
			v.Classified++
			if c.OK {
				v.ClassifiedOK++
			} else if c.Known == FindingCoarser || knownFor(ks, c) == FindingCoarser {
				v.Coarser[c.Expect+" → "+c.Got]++
			}
		}
		for _, k := range ks {
			if !k.Intermittent && k.Selects(c) {
				ran[k.ID]++
				if !c.OK {
					red[k.ID]++
				}
			}
		}
		switch {
		case c.OK:
		case c.Known != "":
			v.Known[c.Known]++
		default:
			if id := knownFor(ks, c); id != "" {
				v.Known[id]++
			} else {
				v.Unexpected = append(v.Unexpected, c)
			}
		}
	}
	for id, n := range ran {
		if n > 0 && red[id] == 0 {
			v.Stale = append(v.Stale, id)
		}
	}
	// An intermittent finding over its budget explains nothing.
	for _, k := range ks {
		if !k.Intermittent || v.Known[k.ID] <= k.Max {
			continue
		}
		for _, c := range checks {
			if !c.OK && knownFor(ks, c) == k.ID {
				if k.Max <= 0 {
					c.Detail = fmt.Sprintf("[carries the signature of %s, a known INTERMITTENT finding, which a single-world run never excuses: one world cannot tell a race from a regression. Re-run it — red again means it is not the race. The matrix (e2e.sh) applies the finding's budget] %s", k.ID, c.Detail)
					v.Unexpected = append(v.Unexpected, c)
					continue
				}
				c.Detail = fmt.Sprintf("[%s is a known INTERMITTENT finding, excused up to %d times per run; this run has %d — that is a regression, not the race] %s", k.ID, k.Max, v.Known[k.ID], c.Detail)
				v.Unexpected = append(v.Unexpected, c)
			}
		}
		v.Over[k.ID] = v.Known[k.ID]
		delete(v.Known, k.ID)
	}
	sort.Strings(v.Stale)
	return v
}

func (v Verdict) knownLine(ks []KnownFinding) []string {
	var out []string
	for _, k := range ks {
		if n := v.Known[k.ID]; n > 0 {
			out = append(out, fmt.Sprintf("  %-6s %-6s ×%-3d %s", k.ID, k.Severity, n, k.Title))
		}
	}
	return out
}

// intermittentLine is the one line a gate should repeat: how often each
// race fired in this run against what it is allowed. A run that passes
// with a race at its budget is not the same news as one that passes at 0.
func (v Verdict) intermittentLine(ks []KnownFinding) string {
	var parts []string
	for _, k := range ks {
		switch {
		case !k.Intermittent:
		case k.Max <= 0 && v.Over[k.ID] > 0:
			parts = append(parts, fmt.Sprintf("%s ×%d — NOT excused in a single-world run (re-run; the matrix has the budget)", k.ID, v.Over[k.ID]))
		case k.Max <= 0:
			parts = append(parts, fmt.Sprintf("%s ×0 (a single-world run excuses none)", k.ID))
		case v.Over[k.ID] > 0:
			parts = append(parts, fmt.Sprintf("%s ×%d OVER its budget of %d — none excused", k.ID, v.Over[k.ID], k.Max))
		default:
			parts = append(parts, fmt.Sprintf("%s ×%d (budget %d)", k.ID, v.Known[k.ID], k.Max))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "INTERMITTENT — known races this run: " + strings.Join(parts, ", ")
}

// categoryLine says how much the engine.category column is worth: in
// how many blocked sessions the engine named what the censor did, and —
// for the rest — exactly which truth it reported as which coarser thing.
// A reader must be able to tell "the engine got it right" from "the
// engine said something true but less" from "the engine said nothing"
// without opening results.jsonl. (While FINDINGS CEN-1 was open this line
// read "0 of N": Start succeeding was taken for a tunnel and no failure
// was ever classified.)
func (v Verdict) categoryLine() string {
	if v.Classified == 0 {
		return ""
	}
	l := fmt.Sprintf("ENGINE CATEGORY — the engine named the failure correctly in %d of %d blocked sessions", v.ClassifiedOK, v.Classified)
	coarse := 0
	var pairs []string
	for pair, n := range v.Coarser {
		coarse += n
		pairs = append(pairs, fmt.Sprintf("%s ×%d", pair, n))
	}
	sort.Strings(pairs)
	if coarse > 0 {
		l += fmt.Sprintf("; in %d more it reported what one route can see and could not tell the narrower truth apart (truth → reported: %s) — FINDINGS CEN-4, needs a second observation", coarse, strings.Join(pairs, "; "))
	}
	if rest := v.Classified - v.ClassifiedOK - coarse; rest > 0 {
		l += fmt.Sprintf("; %d misnamed with no finding to explain it (listed under UNEXPECTED)", rest)
	}
	if v.ClassifiedOK == 0 && coarse == 0 {
		l += ". The engine.category column is therefore NOT coverage in this run: it restates what the censor did, nothing the engine reported"
	}
	return l
}

func staleText(id string) string {
	return fmt.Sprintf("  %s: every check this finding is recorded against ran and was green. If it was fixed, delete its entry from known-findings.json and mark it fixed in FINDINGS.md; if not, the check has stopped seeing it.", id)
}
