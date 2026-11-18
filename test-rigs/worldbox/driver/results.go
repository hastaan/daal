package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Outcome vocabulary. A check passes when Got == Expect — so a scenario
// that is SUPPOSED to block a family passes by observing "blocked".
const (
	Pass    = "pass"    // the thing worked and the evidence was verified
	Blocked = "blocked" // traffic did not get through (timeout / reset / unreachable)
	Refused = "refused" // the product itself said no (auth, signature, revocation)
	Fail    = "fail"    // an operation that must succeed did not
	Skipped = "skipped" // deliberately not exercised; Detail says why
)

// Check is the machine-readable result: exactly one JSON line each, in
// results.jsonl and (with --json) on stdout. Field names are a contract.
type Check struct {
	TS       string         `json:"ts"`
	Run      string         `json:"run"`
	Scenario string         `json:"scenario"`
	Box      string         `json:"box"`              // pinned | tree: which daal-relay-mgmt the box runs
	Family   string         `json:"family,omitempty"` // empty = not family-specific
	Phase    string         `json:"phase"`            // world | provision | mint | family | op:<name>
	Check    string         `json:"check"`            // stable dotted id
	Expect   string         `json:"expect"`
	Got      string         `json:"got"`
	OK       bool           `json:"ok"`
	Known    string         `json:"known,omitempty"` // red, and explained by this open FINDINGS.md entry (known.go)
	Detail   string         `json:"detail,omitempty"`
	Evidence map[string]any `json:"evidence,omitempty"`
	Ms       int64          `json:"ms"`
}

type Results struct {
	mu       sync.Mutex
	run      string
	scenario string
	file     *os.File
	jsonOut  io.Writer // nil = human progress on stdout
	human    io.Writer
	all      []Check
	prefix   string // prepended to check ids (ops run several sessions per family)
	note     string // appended to the detail of red checks while set (what the engine's own stderr said)
	box      string // pinned | tree
	known    []KnownFinding
}

// Which daal-relay-mgmt the box runs.
const (
	BoxPinned = "pinned" // the release artefact provisioning pins
	BoxTree   = "tree"   // a build of this tree (run.sh --mgmt=tree)
)

func NewResults(p Paths, run, scenario, box string, jsonMode bool) (*Results, error) {
	known, err := LoadKnown(p.Rig)
	if err != nil {
		return nil, err
	}
	f, err := os.Create(p.Run + "/results.jsonl")
	if err != nil {
		return nil, err
	}
	// One world judged alone: intermittent findings have no budget here
	// (known.go ForMode).
	known = ForMode(known, ModeWorld)
	r := &Results{run: run, scenario: scenario, file: f, human: os.Stdout, box: box, known: known}
	if jsonMode {
		r.jsonOut, r.human = os.Stdout, os.Stderr
	}
	return r, nil
}

// Add records one check. t0 is when the checked action started.
func (r *Results) Add(family, phase, id, expect, got, detail string, ev map[string]any, t0 time.Time) bool {
	c := Check{
		TS: time.Now().UTC().Format(time.RFC3339Nano), Run: r.run, Scenario: r.scenario, Box: r.box,
		Family: family, Phase: phase, Check: r.prefix + id, Expect: expect, Got: got, OK: expect == got,
		Detail: detail, Evidence: ev, Ms: time.Since(t0).Milliseconds(),
	}
	if !c.OK && r.note != "" {
		c.Detail += r.note
	}
	c.Known = excusedNow(r.known, c)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = append(r.all, c)
	line, _ := json.Marshal(c)
	r.file.Write(append(line, '\n'))
	if r.jsonOut != nil {
		r.jsonOut.Write(append(line, '\n'))
	}
	mark := "ok  "
	switch {
	case c.OK:
	case c.Known != "":
		mark = "KNWN" // red, and an open finding says why; see known.go
	default:
		mark = "FAIL"
	}
	who := phase
	if family != "" {
		who += "/" + family
	}
	extra := ""
	if !c.OK || got == Skipped {
		extra = "  — " + oneLine(detail, 300)
	}
	if c.Known != "" {
		extra = "  [" + c.Known + "]" + extra
	}
	fmt.Fprintf(r.human, "  %s %-22s %-30s expect=%-8s got=%-8s %5dms%s\n", mark, who, c.Check, expect, got, c.Ms, extra)
	return c.OK
}

// oneLine flattens s and, when it is too long, keeps the END: error
// chains and verb output put the cause last.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = "…" + s[len(s)-max:]
	}
	return s
}

// Verdict judges the run: red checks no open finding explains, and
// findings that did not reproduce (known.go).
func (r *Results) Verdict() Verdict {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Judge(r.known, r.all)
}

// Matrix prints the human summary: the family matrix for the scenario
// itself (one row per family, one column per check), then one compact
// table per op (only the columns that carry a verdict), then the
// non-family checks by phase. A cell is "<got>"; "!<got>(want X)" when it
// was not what was expected; "~<got>(ID)" when it was not, and the open
// finding ID in FINDINGS.md is why.
func (r *Results) Matrix(w io.Writer) {
	fmt.Fprintf(w, "\n== worldbox matrix — scenario %q — run %s ==\n", r.scenario, r.run)
	r.table(w, "", func(c Check) bool { return !strings.HasPrefix(c.Phase, "op:") })
	var opPhases []string
	seen := map[string]bool{}
	for _, c := range r.all {
		if strings.HasPrefix(c.Phase, "op:") && c.Family != "" && !seen[c.Phase] {
			seen[c.Phase] = true
			opPhases = append(opPhases, c.Phase)
		}
	}
	for _, ph := range opPhases {
		r.table(w, ph, func(c Check) bool {
			return c.Phase == ph && (strings.HasSuffix(c.Check, "tunnel") || !c.OK)
		})
	}

	// Non-family checks, grouped by phase.
	byPhase := map[string][2]int{}
	var phases []string
	for _, c := range r.all {
		if c.Family != "" {
			continue
		}
		v, seen := byPhase[c.Phase]
		if !seen {
			phases = append(phases, c.Phase)
		}
		v[0]++
		if c.OK {
			v[1]++
		}
		byPhase[c.Phase] = v
	}
	sort.Strings(phases)
	fmt.Fprintln(w)
	for _, ph := range phases {
		v := byPhase[ph]
		fmt.Fprintf(w, "%-14s %d/%d checks ok\n", ph, v[1], v[0])
	}
	for _, c := range r.all {
		if c.Got == Skipped {
			fmt.Fprintf(w, "SKIPPED  %s %s: %s\n", c.Family, c.Check, oneLine(c.Detail, 400))
		}
	}
	printVerdict(w, r.known, Judge(r.known, r.all), 0)
}

// printVerdict is the last block of every report, single world or matrix.
// broken is the number of worlds that did not run (matrix reports only):
// with any, there is no verdict to give.
func printVerdict(w io.Writer, ks []KnownFinding, v Verdict, broken int) {
	if len(v.Known) > 0 {
		n := 0
		for _, k := range v.Known {
			n += k
		}
		fmt.Fprintf(w, "\nKNOWN — %d red check(s) explained by open findings (FINDINGS.md); they stay red, they do not fail the run:\n", n)
		for _, l := range v.knownLine(ks) {
			fmt.Fprintln(w, l)
		}
	}
	if len(v.Stale) > 0 {
		fmt.Fprintf(w, "\nDID NOT REPRODUCE — %d known finding(s):\n", len(v.Stale))
		for _, id := range v.Stale {
			fmt.Fprintln(w, staleText(id))
		}
	}
	if len(v.Unexpected) > 0 {
		fmt.Fprintf(w, "\nUNEXPECTED — %d check(s) did not match their expectation and no finding explains them:\n", len(v.Unexpected))
		for _, c := range v.Unexpected {
			fmt.Fprintf(w, "  [%s %s] %s/%s %s: expect=%s got=%s — %s\n", c.Scenario, c.Box, c.Phase, c.Family, c.Check, c.Expect, c.Got, oneLine(c.Detail, 600))
		}
	}
	if l := v.intermittentLine(ks); l != "" {
		fmt.Fprintf(w, "\n%s\n", l)
	}
	if l := v.categoryLine(); l != "" {
		fmt.Fprintf(w, "\n%s\n", l)
	}
	switch {
	case broken > 0:
		fmt.Fprintf(w, "\nRESULT: BROKEN — %d world(s) did not run, so the rig gives no verdict (of the %d checks that did run: %d unexpected red, %d known finding(s) reproduced)\n", broken, v.Total, len(v.Unexpected), len(v.Known))
	case v.OK() && len(v.Known) == 0:
		fmt.Fprintf(w, "\nRESULT: PASS — %d checks, all as expected\n", v.Total)
	case v.OK():
		fmt.Fprintf(w, "\nRESULT: PASS — %d checks; nothing unexpected (%d known finding(s) reproduced, listed above)\n", v.Total, len(v.Known))
	default:
		fmt.Fprintf(w, "\nRESULT: FAIL — %d unexpected red check(s), %d known finding(s) that did not reproduce, of %d checks\n", len(v.Unexpected), len(v.Stale), v.Total)
	}
}

// table prints one family × check grid for the checks keep() selects.
func (r *Results) table(w io.Writer, title string, keep func(Check) bool) {
	var cols, fams []string
	seenC, seenF := map[string]bool{}, map[string]bool{}
	cell := map[string]map[string]Check{}
	for _, c := range r.all {
		if c.Family == "" || !keep(c) {
			continue
		}
		if !seenC[c.Check] {
			seenC[c.Check] = true
			cols = append(cols, c.Check)
		}
		if !seenF[c.Family] {
			seenF[c.Family] = true
			fams = append(fams, c.Family)
		}
		if cell[c.Family] == nil {
			cell[c.Family] = map[string]Check{}
		}
		cell[c.Family][c.Check] = c
	}
	if len(fams) == 0 {
		return
	}
	texts := map[string]map[string]string{}
	widths := map[string]int{}
	for _, c := range cols {
		widths[c] = len(c)
	}
	for _, f := range fams {
		texts[f] = map[string]string{}
		for _, c := range cols {
			txt := "-"
			if ch, ok := cell[f][c]; ok {
				txt = ch.Got
				switch {
				case ch.OK:
				case ch.Known != "":
					txt = "~" + ch.Got + "(" + ch.Known + ")"
				default:
					txt = "!" + ch.Got + "(want " + ch.Expect + ")"
				}
			}
			texts[f][c] = txt
			if len(txt) > widths[c] {
				widths[c] = len(txt)
			}
		}
	}
	fw := len("family")
	for _, f := range fams {
		if len(f) > fw {
			fw = len(f)
		}
	}
	if title != "" {
		fmt.Fprintf(w, "\n-- %s --\n", title)
	}
	fmt.Fprintf(w, "%-*s", fw, "family")
	for _, c := range cols {
		fmt.Fprintf(w, "  %-*s", widths[c], c)
	}
	fmt.Fprintln(w)
	for _, f := range fams {
		fmt.Fprintf(w, "%-*s", fw, f)
		for _, c := range cols {
			fmt.Fprintf(w, "  %-*s", widths[c], texts[f][c])
		}
		fmt.Fprintln(w)
	}
}
