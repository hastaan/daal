package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// `wb summary` folds the results of many worlds (one run.sh each, started
// by e2e.sh) into one report and one exit status:
//
//	0  every world ran; nothing red that an open finding does not explain
//	1  an unexpected red check, or a known finding that did not reproduce
//	2  a world did not run (the rig, not Daal, is broken)
//
// "Did not run" is narrow on purpose (classify): run.sh died with
// something other than its two verdicts, or it recorded nothing it can be
// judged by. A world that stopped before its first client session BECAUSE
// a check went red (provisioning refused, the box never came up) did run:
// that red check is Daal's, it is judged like any other, and the report
// says where the world stopped.
//
// Input is a directory holding, per world <label>: <label>.jsonl (the
// --json stream), <label>.rc, <label>.secs, <label>.log, and plan.tsv
// ("label<TAB>run.sh arguments", in display order).

type worldRun struct {
	Label, Args string
	RC          string
	Secs        string
	Checks      []Check
	Broken      string // the rig failed: no verdict from this world
	Early       string // "phase/check": the world stopped there, before any client session, on a red check
}

// classify decides whether a world's results can be judged. run.sh exits
// 0 or 1 exactly when the driver reached its verdict (run.go), 1 meaning
// that verdict was not clean; anything else is the rig dying.
func (w *worldRun) classify(ks []KnownFinding) {
	sessions := 0
	var red *Check
	for i, c := range w.Checks {
		if c.Phase == "family" {
			sessions++
		}
		if red == nil && !c.OK && c.Known == "" && knownFor(ks, c) == "" {
			red = &w.Checks[i]
		}
	}
	switch {
	case w.RC != "0" && w.RC != "1":
		w.Broken = fmt.Sprintf("run.sh exit %q", w.RC)
	case len(w.Checks) == 0:
		w.Broken = "the world recorded no checks at all (run.sh exit " + w.RC + ")"
	case sessions > 0:
	case w.RC == "1" && red != nil:
		// Stopped by a red check of its own: a verdict on Daal, not a
		// broken rig. The check is in w.Checks and fails the report.
		w.Early = red.Phase + "/" + red.Check
	default:
		w.Broken = "the world never reached a client session and no unexpected red check says why (run.sh exit " + w.RC + ")"
	}
}

func cmdSummary(args []string) int {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	rig := fs.String("rig", ".", "test-rigs/worldbox")
	dir := fs.String("dir", "", "directory with plan.tsv and the per-world results")
	title := fs.String("title", "worldbox", "report heading")
	mode := fs.String("mode", "", "matrix mode (quick|full): quick applies the max_quick budgets of intermittent findings")
	_ = fs.Parse(args)
	known, err := LoadKnown(*rig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wb summary:", err)
		return 2
	}
	known = ForMode(known, *mode)
	worlds, err := loadWorlds(*dir, known)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wb summary:", err)
		return 2
	}
	return report(os.Stdout, *title, known, worlds)
}

func loadWorlds(dir string, ks []KnownFinding) ([]worldRun, error) {
	plan, err := os.ReadFile(filepath.Join(dir, "plan.tsv"))
	if err != nil {
		return nil, err
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b))
	}
	var out []worldRun
	for _, line := range strings.Split(strings.TrimSpace(string(plan)), "\n") {
		label, args, _ := strings.Cut(line, "\t")
		if label == "" {
			continue
		}
		w := worldRun{Label: label, Args: args, RC: read(label + ".rc"), Secs: read(label + ".secs")}
		if f, err := os.Open(filepath.Join(dir, label+".jsonl")); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 16<<20)
			for sc.Scan() {
				if !strings.HasPrefix(sc.Text(), "{") {
					continue
				}
				var c Check
				if json.Unmarshal(sc.Bytes(), &c) == nil && c.Check != "" {
					w.Checks = append(w.Checks, c)
				}
			}
			f.Close()
		}
		w.classify(ks)
		if w.Broken != "" {
			log := strings.Split(read(label+".log"), "\n")
			if len(log) > 12 {
				log = log[len(log)-12:]
			}
			w.Broken += "; last lines of its log:\n      " + strings.Join(log, "\n      ")
		}
		out = append(out, w)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s/plan.tsv lists no worlds", dir)
	}
	return out, nil
}

// cellText renders one check the way every table in the rig does.
func cellText(ks []KnownFinding, c Check, text string) string {
	switch {
	case c.OK:
		return text
	case knownFor(ks, c) != "":
		return "~" + text + "(" + knownFor(ks, c) + ")"
	}
	return "!" + text + "(want " + c.Expect + ")"
}

func printGrid(w io.Writer, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	width := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if n := len([]rune(c)); n > width[i] {
				width[i] = n
			}
		}
	}
	for _, r := range rows {
		var b strings.Builder
		for i, c := range r {
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", width[i]-len([]rune(c))+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

func report(w io.Writer, title string, ks []KnownFinding, worlds []worldRun) int {
	var all []Check
	var fams []string
	seenFam := map[string]bool{}
	for _, wr := range worlds {
		all = append(all, wr.Checks...)
		for _, c := range wr.Checks {
			if c.Phase == "family" && c.Check == "tunnel" && !seenFam[c.Family] {
				seenFam[c.Family] = true
				fams = append(fams, c.Family)
			}
		}
	}

	// 1. every world × every family: what the real engine carried, and for
	// a blocked cell what a raw, Daal-free probe says the network did.
	fmt.Fprintf(w, "\n== %s — scenario × family ==\n", title)
	fmt.Fprintln(w, "cell: pass = verified bytes through the real engine | blocked:<what a raw probe saw the network do> | ~x(ID) = red, open finding ID | !x = UNEXPECTED")
	grid := [][]string{append([]string{"world", "box", "censor proofs"}, fams...)}
	for _, wr := range worlds {
		if wr.Broken != "" {
			grid = append(grid, append([]string{wr.Label, "?", "BROKEN"}, make([]string, len(fams))...))
			continue
		}
		if wr.Early != "" {
			grid = append(grid, append([]string{wr.Label, wr.Checks[0].Box, "!STOPPED at " + wr.Early}, make([]string, len(fams))...))
			continue
		}
		box, proofs, proofsOK := "", 0, 0
		tun, truth, est := map[string]Check{}, map[string]Check{}, map[string]Check{}
		for _, c := range wr.Checks {
			box = c.Box
			switch {
			case c.Phase == "censor" && strings.HasPrefix(c.Check, "prove."):
				proofs++
				if c.OK {
					proofsOK++
				}
			case c.Phase == "family" && c.Check == "tunnel":
				tun[c.Family] = c
			case c.Phase == "censor" && c.Check == "truth.category":
				truth[c.Family] = c
			case c.Phase == "family" && c.Check == "established":
				est[c.Family] = c
			}
		}
		row := []string{wr.Label, box, got(proofs == 0, "-", fmt.Sprintf("%d/%d", proofsOK, proofs))}
		for _, f := range fams {
			t, ok := tun[f]
			if !ok {
				row = append(row, "-")
				continue
			}
			text := t.Got
			worst := t
			if tr, ok := truth[f]; ok && t.Got != Pass {
				text += ":" + got(tr.Got == Skipped, "unasserted", tr.Got)
				if t.OK && !tr.OK {
					worst = tr
				}
			}
			// "blocked" that was claimed to be "connected, then too slow":
			// a family that never connected is not that, whatever the
			// payload did.
			if e, ok := est[f]; ok && !e.OK {
				text, worst = t.Got+":never-connected", e
			}
			row = append(row, cellText(ks, worst, text))
		}
		grid = append(grid, row)
	}
	printGrid(w, grid)

	// 2. the clean worlds in full: every per-family check.
	shown := map[string]bool{}
	for _, wr := range worlds {
		if wr.Broken != "" || wr.Early != "" || len(wr.Checks) == 0 || wr.Checks[0].Scenario != "clean" || shown[wr.Checks[0].Box] {
			continue
		}
		shown[wr.Checks[0].Box] = true
		var cols, rows []string
		seenC, seenR := map[string]bool{}, map[string]bool{}
		cell := map[string]Check{}
		for _, c := range wr.Checks {
			if c.Family == "" || strings.HasPrefix(c.Phase, "op:") || c.Phase == "censor" {
				continue
			}
			if !seenC[c.Check] {
				seenC[c.Check] = true
				cols = append(cols, c.Check)
			}
			if !seenR[c.Family] {
				seenR[c.Family] = true
				rows = append(rows, c.Family)
			}
			cell[c.Family+"\x00"+c.Check] = c
		}
		fmt.Fprintf(w, "\n== no censor, box runs the %s artefacts (world %q) — family × check ==\n", wr.Checks[0].Box, wr.Label)
		g := [][]string{append([]string{"family"}, cols...)}
		for _, f := range rows {
			row := []string{f}
			for _, col := range cols {
				if c, ok := cell[f+"\x00"+col]; ok {
					row = append(row, cellText(ks, c, c.Got))
				} else {
					row = append(row, "-")
				}
			}
			g = append(g, row)
		}
		printGrid(w, g)
	}

	// 3. publisher-side operations.
	og := [][]string{{"world", "box", "op", "checks", "ok", "skipped", "known", "UNEXPECTED"}}
	for _, wr := range worlds {
		var order []string
		type cnt struct{ n, ok, skip, known, bad int }
		by := map[string]*cnt{}
		box := ""
		for _, c := range wr.Checks {
			if !strings.HasPrefix(c.Phase, "op:") {
				continue
			}
			box = c.Box
			k := by[c.Phase]
			if k == nil {
				k = &cnt{}
				by[c.Phase] = k
				order = append(order, c.Phase)
			}
			k.n++
			switch {
			case c.Got == Skipped:
				k.skip++
			case c.OK:
				k.ok++
			case knownFor(ks, c) != "":
				k.known++
			default:
				k.bad++
			}
		}
		for _, ph := range order {
			k := by[ph]
			og = append(og, []string{wr.Label, box, strings.TrimPrefix(ph, "op:"), fmt.Sprint(k.n), fmt.Sprint(k.ok), fmt.Sprint(k.skip), fmt.Sprint(k.known), fmt.Sprint(k.bad)})
		}
	}
	if len(og) > 1 {
		fmt.Fprintf(w, "\n== publisher-side operations (real daal-deploy verbs, asserted from the insider's seat) ==\n")
		printGrid(w, og)
	}

	// 4. the worlds themselves.
	fmt.Fprintf(w, "\n== worlds ==\n")
	wg := [][]string{{"world", "checks", "secs", "exit", "run.sh arguments"}}
	broken := 0
	for _, wr := range worlds {
		wg = append(wg, []string{wr.Label, fmt.Sprint(len(wr.Checks)), wr.Secs, wr.RC, wr.Args})
		if wr.Broken != "" {
			broken++
		}
	}
	printGrid(w, wg)
	for _, wr := range worlds {
		if wr.Broken != "" {
			fmt.Fprintf(w, "\nBROKEN WORLD %s: %s\n", wr.Label, wr.Broken)
		}
		if wr.Early != "" {
			fmt.Fprintf(w, "\nWORLD %s STOPPED EARLY at %s, before any client session: that check is red and is judged below (UNEXPECTED). The rig ran; this is a verdict on Daal.\n", wr.Label, wr.Early)
		}
	}

	v := Judge(ks, all)
	printVerdict(w, ks, v, broken)
	switch {
	case broken > 0:
		return 2
	case !v.OK():
		return 1
	}
	return 0
}
