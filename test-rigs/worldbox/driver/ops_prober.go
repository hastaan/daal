package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func init() { Ops["prober"] = opProber }

// opProber: the prober's-eye audit (W1-E). Findings: docs/prober-audit.md.
//
//	<family> capture.ja4    the ClientHello the engine sent for the route
//	                        (flow tap, censor-side) parses whole and has a
//	                        JA4; the evidence holds it, its raw form, and
//	                        how it compares with Chrome's (chromeJA4)
//	<family> ja4_vs_chrome  recorded, not judged: same, or which sections
//	                        differ
//	stranger.<port>         a stranger on the phone's network does a full
//	                        handshake to the port (no SNI, the cover name,
//	                        an unrelated name) and a plain GET: nothing it
//	                        gets back names Daal
//
// Evidence of every port: prober-stranger.json in the run directory.
func opProber(rc *RunCtx) {
	const phase = "op:prober"
	t0 := time.Now()
	if err := StartFlowTap(rc.Ctx, rc.P); err != nil {
		rc.R.Add("", phase, "flowtap", Pass, Fail, err.Error(), nil, t0)
		return
	}
	for _, f := range rc.activeFamilies() {
		if f.Name != "vless-reality" && f.Name != "websocket-tls" {
			continue
		}
		from := time.Now()
		outcome := rc.sub(f, phase, "capture", rc.Pack, Pass)
		rc.proberHello(f, phase, outcome, from)
	}
	rc.proberStranger(phase)
}

func (rc *RunCtx) proberHello(f Family, phase, outcome string, from time.Time) {
	t0 := time.Now()
	if outcome == Skipped || outcome == Refused {
		rc.R.Add(f.Name, phase, "capture.ja4", Skipped, Skipped, "the session did not dial ("+outcome+")", nil, t0)
		return
	}
	pkts, err := ReadFlowTap(rc.P)
	if err != nil {
		rc.R.Add(f.Name, phase, "capture.ja4", Pass, Fail, "flow tap: "+err.Error(), nil, t0)
		return
	}
	var why []string
	for _, fd := range firstData(pkts, f.Endpoint.Port, from, time.Now()) {
		h, err := helloFromFlow(fd)
		if err != nil {
			why = append(why, err.Error())
			continue
		}
		diff := ja4Diff(h.JA4, chromeJA4)
		ev := map[string]any{"hello": h, "chrome_ja4": chromeJA4, "chrome_source": "FoxIO-LLC/ja4 README examples (Chrome, TCP; version/platform not stated; Android unverified)", "differs_in": diff}
		rc.R.Add(f.Name, phase, "capture.ja4", Pass, Pass, h.JA4, ev, t0)
		note := "same JA4 as the reference Chrome"
		if len(diff) > 0 {
			note = fmt.Sprintf("%s differs from Chrome's %s in %s", h.JA4, chromeJA4, strings.Join(diff, ", "))
		}
		rc.R.Add(f.Name, phase, "ja4_vs_chrome", Skipped, Skipped, "recorded, not judged: "+note, ev, t0)
		return
	}
	rc.R.Add(f.Name, phase, "capture.ja4", Pass, Fail, "no flow to the route's port opened with a whole ClientHello: "+strings.Join(why, "; "),
		map[string]any{"port": f.Endpoint.Port}, t0)
}

// proberStranger looks at every TCP port of the relay a stranger could
// try: each served family's, the mgmt port, the provisioning health
// port, 22 and 80.
func (rc *RunCtx) proberStranger(phase string) {
	t0 := time.Now()
	owner := map[int]string{rc.Rec.MgmtPort: "(mgmt)", 9876: "(health)", 22: "(ssh)", 80: "(http)"}
	for _, n := range rc.Serve {
		if f := rc.Fams[n]; f.Endpoint.Proto == "tcp" {
			owner[f.Endpoint.Port] = n
		}
	}
	var targets []FaceTarget
	for port := range owner {
		if port > 0 {
			targets = append(targets, FaceTarget{Port: port, SNIs: []string{"", rc.Rec.CoverSNI, "www.example.org"}})
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Port < targets[j].Port })
	in, _ := json.Marshal(targets)
	argv := inNS(NSClient, filepath.Join(rc.P.Bin, "wb"), "tlsface", "--host", Relay1IP)
	cmd := exec.CommandContext(rc.Ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	runErr := cmd.Run()
	var res []FaceResult
	if err := json.Unmarshal(so.Bytes(), &res); err != nil {
		rc.R.Add("", phase, "stranger", Pass, Fail, fmt.Sprintf("tlsface: %v / %v: %s", runErr, err, strings.TrimSpace(se.String())), nil, t0)
		return
	}
	_ = os.WriteFile(filepath.Join(rc.P.Run, "prober-stranger.json"), append(so.Bytes(), '\n'), 0o644)
	for _, r := range res {
		fam := owner[r.Port]
		if strings.HasPrefix(fam, "(") {
			fam = ""
		}
		ev := map[string]any{"face": r, "port_of": owner[r.Port]}
		got, note := Pass, ""
		if len(r.Markers) > 0 {
			got, note = Fail, "a stranger's handshake shows "+strings.Join(r.Markers, ", ")
		}
		if !r.Open {
			note = "closed to a stranger"
		}
		rc.R.Add(fam, phase, fmt.Sprintf("stranger.%d", r.Port), Pass, got, note, ev, t0)
	}
}
