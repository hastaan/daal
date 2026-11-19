package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RunCtx is everything a phase or an op needs. Ops (ops_*.go) receive it
// and nothing else.
type RunCtx struct {
	Ctx   context.Context
	P     Paths
	R     *Results
	Pub   *Publisher
	Scn   Scenario
	Fams  map[string]Family // every declared family
	Want  []string          // families under test this run, in order
	Serve []string          // families the relay is provisioned to serve
	// ExplicitFamilies: Serve differs from the profile default, so
	// provisioning passes --families.
	ExplicitFamilies bool
	Rec              Record // the provisioned relay's OperatorRecord (read-only view)
	Pack             string // recipient r1's pack, as handed to the insider
	// PreL2 is set by op l2 for the ops that follow it: r1's file as it
	// was in the field BEFORE the cover host moved (mirror set in it),
	// and the cover host of that time. Op l3 uses it for the phone that
	// sits out BOTH rotations without being handed anything.
	PreL2 struct{ Pack, CoverSNI string }
	// FreshAnnounced is every pack id announced on the freshness channel
	// in this run, oldest first, across ops: the publisher keeps one
	// history per relay, and a document must name the ids it replaces.
	FreshAnnounced []string
	// identity is what the relay last said it is (`relay-identity`),
	// and signedPending the families the first signature had to leave
	// without an endpoint because the relay said their key was not made
	// yet. Both belong to the app's order of operations at mint.
	identity      RelayIdentityDoc
	signedPending []string
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	repo := fs.String("repo", "", "repository root")
	rig := fs.String("rig", "", "test-rigs/worldbox")
	bin := fs.String("bin", "", "built binaries")
	runDir := fs.String("run-dir", "", "evidence directory for this run")
	jsonMode := fs.Bool("json", false, "one JSON line per check on stdout (human progress → stderr)")
	opsFlag := fs.String("ops", "", "comma list of publisher ops to run after the matrix (see `wb list`)")
	artifacts := fs.String("artifacts", "", "release artefact directory the lab mirror serves")
	override := fs.String("override", "", "name=path[,…]: run a tree build of a box artefact instead of the pinned one")
	timescale := fs.String("timescale", "20", "divide cloud-init's 300 s provisioning window by this")
	relayFams := fs.String("relay-families", "", "comma list: families the relay is provisioned with (default: the profile's default-enabled families + any opt-in family under test)")
	shell := fs.Bool("shell", false, "after the run, open a shell inside the world (it dies when you exit)")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: run.sh [--json] [--ops a,b] <scenario> [family…]")
		return 2
	}
	p := Paths{Repo: *repo, Rig: *rig, Bin: *bin, Run: *runDir}
	for _, d := range []string{p.Logs(), filepath.Join(p.Run, "boxes"), filepath.Join(p.Run, "clients")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "wb:", err)
			return 2
		}
	}

	scn, err := LoadScenario(p.Rig, fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wb:", err)
		return 2
	}
	fams, all, err := LoadFamilies(p.Rig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wb:", err)
		return 2
	}
	resolveNeeds(p, fams)
	// What an operator who changes nothing gets: the toolbox profile's
	// default-enabled families. "@default" on the command line means
	// exactly those (the only set the pinned release artefacts can serve
	// until FINDINGS F-002 is released).
	_, defaults, err := ProfileFamilies(p.Repo, ToolboxProfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wb:", err)
		return 2
	}
	var want []string
	for _, a := range fs.Args()[1:] {
		if a == "@default" {
			want = append(want, defaults...)
		} else {
			want = append(want, a)
		}
	}
	if len(want) == 0 {
		want = all
	}
	for _, f := range want {
		if _, ok := fams[f]; !ok {
			fmt.Fprintf(os.Stderr, "wb: no families/%s.json (have: %s)\n", f, strings.Join(all, " "))
			return 2
		}
		if _, err := scn.ExpectFor(f); err != nil {
			fmt.Fprintln(os.Stderr, "wb:", err)
			return 2
		}
	}
	var ops []string
	if *opsFlag != "" {
		ops = strings.Split(*opsFlag, ",")
		for _, o := range ops {
			if _, ok := Ops[o]; !ok {
				fmt.Fprintf(os.Stderr, "wb: unknown op %q\n", o)
				return 2
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	// PID 1 gets no default signal dispositions; die on purpose. Exiting
	// is the teardown: the kernel kills every process in this pid
	// namespace and the network namespaces go with their last process.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\nwb: interrupted — tearing the world down")
		CollectEvidence(p)
		os.Exit(130)
	}()

	res, err := NewResults(p, filepath.Base(p.Run), scn.Name, got(*override == "", BoxPinned, BoxTree), *jsonMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wb:", err)
		return 2
	}
	// What the relay is provisioned to serve: the toolbox profile's
	// default-enabled families (what an operator who changes nothing
	// gets) plus any opt-in family under test. When that is exactly the
	// default set, --families is not passed at all, as in the app.
	serve := append([]string{}, defaults...)
	explicit := false
	if *relayFams != "" {
		serve, explicit = strings.Split(*relayFams, ","), true
	}
	for _, f := range want {
		if !contains(serve, f) {
			if *relayFams != "" {
				fmt.Fprintf(os.Stderr, "wb: family %s is under test but not in --relay-families\n", f)
				return 2
			}
			serve, explicit = append(serve, f), true
		}
	}
	for _, f := range serve {
		if _, ok := fams[f]; !ok {
			fmt.Fprintf(os.Stderr, "wb: the relay will serve %q but there is no families/%s.json — declare it (see README)\n", f, f)
			return 2
		}
	}
	rawPatience = time.Duration(scn.ProbePatienceMs) * time.Millisecond
	rc := &RunCtx{Ctx: ctx, P: p, R: res, Scn: scn, Fams: fams, Want: want, Serve: serve, ExplicitFamilies: explicit}
	t0 := time.Now()
	fmt.Fprintf(res.human, "worldbox: scenario=%s  under test: %s  relay serves: %s  ops: %s  box artefacts: %s\nworldbox: evidence in %s\n",
		scn.Name, strings.Join(want, ","), strings.Join(serve, ","), strings.Join(ops, ","), got(*override == "", "pinned release", "TREE BUILD "+*override), p.Run)

	if rc.world(*artifacts, *override, *timescale) && rc.provision() && rc.mint() {
		var served []Family
		for _, name := range serve {
			served = append(served, fams[name])
		}
		if err := InstallWireTap(ctx, served); err != nil {
			res.Add("", "world", "censor.wire_tap", Pass, Fail, err.Error(), nil, time.Now())
		} else if err := ApplyScenario(ctx, p, scn, scenarioVars(rc.Rec.CoverSNI)); err != nil {
			res.Add("", "world", "censor.apply", Pass, Fail, err.Error(), nil, time.Now())
		} else {
			res.Add("", "world", "censor.apply", Pass, Pass, "", map[string]any{"rules": len(scn.Censor.NFT) + len(scn.Censor.NFTRaw), "tc": len(scn.Censor.TC), "dpi": len(scn.Censor.DPI)}, time.Now())
			rc.ProveCensor() // raw, Daal-free: the censor does what the scenario says (censor.go)
			for _, name := range want {
				rc.family(fams[name])
			}
			for _, o := range ops {
				fmt.Fprintf(res.human, "op: %s\n", o)
				Ops[o](rc)
			}
		}
	}
	CollectEvidence(p)
	res.Matrix(res.human)
	fmt.Fprintf(res.human, "elapsed: %s   evidence: %s\n", time.Since(t0).Round(100*time.Millisecond), p.Run)
	if *shell {
		fmt.Fprintln(os.Stderr, "wb: shell inside the world (ip netns list; ip netns exec relay1 …). exit to tear down.")
		c := exec.Command("bash")
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		_ = c.Run()
	}
	if !res.Verdict().OK() {
		return 1
	}
	return 0
}

// ---- phase: world ----------------------------------------------------

func (rc *RunCtx) world(artifacts, override, timescale string) bool {
	p, r := rc.P, rc.R
	t0 := time.Now()
	fmt.Fprintln(r.human, "phase: world")
	if err := BringUp(rc.Ctx, p); err != nil {
		return r.Add("", "world", "namespaces", Pass, Fail, err.Error(), nil, t0)
	}
	r.Add("", "world", "namespaces", Pass, Pass, "", map[string]any{"netns": []string{NSClient, NSCensor, NSRelay1, NSInternet, NSPublisher}}, t0)

	t0 = time.Now()
	if err := MakeLabCA(p.Run, []string{"api.hetzner.cloud", "github.com"}, []string{CloudIP, MirrorIP}); err != nil {
		return r.Add("", "world", "internet.services", Pass, Fail, err.Error(), nil, t0)
	}
	pub, err := NewPublisher(p)
	if err != nil {
		return r.Add("", "world", "internet.services", Pass, Fail, err.Error(), nil, t0)
	}
	rc.Pub = pub
	wb := filepath.Join(p.Bin, "wb")
	if _, err := Spawn(p, "target", nil, inNS(NSInternet, wb, "target")...); err != nil {
		return r.Add("", "world", "internet.services", Pass, Fail, err.Error(), nil, t0)
	}
	cloudArgs := []string{wb, "fakecloud", "--repo", p.Repo, "--rig", p.Rig, "--bin", p.Bin, "--run-dir", p.Run,
		"--token-file", pub.Path("cloud.token"), "--artifacts", artifacts, "--timescale", timescale}
	if override != "" {
		cloudArgs = append(cloudArgs, "--override", override)
	}
	if _, err := Spawn(p, "fakecloud", nil, inNS(NSInternet, cloudArgs...)...); err != nil {
		return r.Add("", "world", "internet.services", Pass, Fail, err.Error(), nil, t0)
	}
	if _, err := Spawn(p, "inet", nil, inNS(NSInternet, wb, "inet", "--run-dir", p.Run)...); err != nil {
		return r.Add("", "world", "internet.services", Pass, Fail, err.Error(), nil, t0)
	}
	up := waitFor(rc.Ctx, 10*time.Second, func() bool {
		return rc.tcpFrom(NSInternet, TargetIP, 80) && rc.tcpFrom(NSInternet, CloudIP, 443) &&
			rc.tcpFrom(NSInternet, MirrorIP, 443) && rc.tcpFrom(NSInternet, CoverIP, 443)
	})
	if !up {
		return r.Add("", "world", "internet.services", Pass, Fail, "target / cloud API / mirror / cover site did not come up; see logs/", nil, t0)
	}
	r.Add("", "world", "internet.services", Pass, Pass, "", nil, t0)

	// The censor forwards between the client and the relay…
	t0 = time.Now()
	_, err = sh(rc.Ctx, inNS(NSClient, "ping", "-c1", "-W2", Relay1IP)...)
	if !r.Add("", "world", "client_reaches_relay_addr", Pass, got(err == nil, Pass, Blocked), errStr(err), nil, t0) {
		return false
	}
	// …the target is alive and reachable from where the relay sits…
	t0 = time.Now()
	pr := probeIn(rc.Ctx, p, NSRelay1, false, 5*time.Second)
	if !r.Add("", "world", "target_alive_from_relay", Pass, got(pr.OK && pr.Remote == Relay1EgressIP, Pass, Fail), pr.Error,
		map[string]any{"remote_seen_by_target": pr.Remote, "blob_bytes": pr.BlobBytes}, t0) {
		return false
	}
	// …and NOT reachable from the client. Without this, nothing later proves anything.
	t0 = time.Now()
	pr = Probe(rc.Ctx, p, false, 3*time.Second)
	return r.Add("", "world", "target_unreachable_from_client", Blocked, got(pr.OK, Pass, Blocked), pr.Error, nil, t0)
}

func got(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// tcpFrom reports whether a TCP connect from inside ns to ip:port succeeds.
func (rc *RunCtx) tcpFrom(ns, ip string, port int) bool {
	_, err := sh(rc.Ctx, inNS(ns, "timeout", "2", "bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", ip, port))...)
	return err == nil
}

func probeIn(ctx context.Context, p Paths, ns string, udp bool, timeout time.Duration) ProbeResult {
	// Same probe binary, different vantage point.
	args := []string{filepath.Join(p.Bin, "wb"), "probe", "--timeout", timeout.String()}
	if udp {
		args = append(args, "--udp")
	}
	return runProbeCmd(ctx, inNS(ns, args...))
}

// ---- phase: provision ------------------------------------------------

func (rc *RunCtx) provision() bool {
	p, r := rc.P, rc.R
	fmt.Fprintln(r.human, "phase: provision (real `daal-deploy provision` → lab cloud → real cloud-init on a real box)")

	t0 := time.Now()
	ctx, cancel := context.WithTimeout(rc.Ctx, 4*time.Minute)
	defer cancel()
	var famFlag []string
	if rc.ExplicitFamilies {
		famFlag = rc.Serve
	}
	v := rc.Pub.Provision(ctx, famFlag)
	if !r.Add("", "provision", "verb.provision", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"rc": v.RC, "serve": rc.Serve, "families_flag": famFlag}, t0) {
		return false
	}
	rec, err := rc.Pub.Record()
	if err != nil {
		return r.Add("", "provision", "record", Pass, Fail, err.Error(), nil, t0)
	}
	rc.Rec = rec
	fpOK := len(rec.MgmtTLSFingerprint) == 64
	var problems []string
	if rec.PublicIP != Relay1IP {
		problems = append(problems, "public_ip="+rec.PublicIP)
	}
	if !fpOK {
		problems = append(problems, "mgmt_tls_fingerprint missing")
	}
	if rec.MgmtPort == 0 {
		problems = append(problems, "mgmt_port missing")
	}
	if rec.CoverSNI == "" {
		problems = append(problems, "cover_sni missing")
	}
	candFam := map[string]int{}
	for _, c := range rec.Candidates {
		candFam[c.Family] = c.Port
	}
	for _, f := range rc.Serve {
		port, ok := candFam[f]
		if !ok {
			problems = append(problems, "no candidate for "+f)
		} else if port != rc.Fams[f].Endpoint.Port {
			problems = append(problems, fmt.Sprintf("%s: record says port %d, families/%s.json says %d", f, port, f, rc.Fams[f].Endpoint.Port))
		}
	}
	if len(candFam) != len(rc.Serve) {
		problems = append(problems, fmt.Sprintf("record has %d candidates, expected exactly the %d served families", len(candFam), len(rc.Serve)))
	}
	if !r.Add("", "provision", "record", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"server_id": rec.ServerID, "public_ip": rec.PublicIP, "mgmt_port": rec.MgmtPort, "cover_sni": rec.CoverSNI,
			"reality_public_key_in_record": rec.RealityPublicKey != "", "candidates": candFam}, t0) {
		return false
	}

	box := p.Box(rec.ServerID)
	// The one-shot SSH key must be gone from the cloud account.
	t0 = time.Now()
	created, deleted, notModelled := 0, 0, 0
	for _, q := range CloudRequests(p) {
		switch {
		case q.Method == "POST" && q.Path == "/v1/ssh_keys" && q.Status == 201:
			created++
		case q.Method == "DELETE" && strings.HasPrefix(q.Path, "/v1/ssh_keys/") && q.Status == 204:
			deleted++
		case q.Status == 501:
			notModelled++
		}
	}
	r.Add("", "provision", "cloud.ssh_key_removed", Pass, got(created > 0 && created == deleted, Pass, Fail),
		fmt.Sprintf("created=%d deleted=%d", created, deleted), nil, t0)
	r.Add("", "provision", "cloud.api_fully_modelled", Pass, got(notModelled == 0, Pass, Fail),
		fmt.Sprintf("%d cloud API calls hit an endpoint the lab does not model (grep 501 cloud-requests.jsonl)", notModelled), nil, t0)

	// What the box is actually running is what the release pins.
	t0 = time.Now()
	ev := map[string]any{}
	pinsOK := true
	for inst, art := range map[string]string{"sing-box": "sing-box-*-linux-amd64", "daal-relay-mgmt": "daal-relay-mgmt-*-linux-amd64", "daal-relay-health": "daal-relay-health-*-linux-amd64"} {
		installed := fileSum(filepath.Join(box, "rootfs", "usr", "local", "bin", inst))
		ev[inst] = installed
		matches, _ := filepath.Glob(filepath.Join(p.Repo, "dist-release", "relay-v1.5.1", art))
		same := false
		for _, m := range matches {
			same = same || (installed != "" && fileSum(m) == installed)
		}
		if _, err := os.Stat(filepath.Join(box, "state", "overrides", inst)); err == nil {
			ev[inst+"_override"] = "TREE BUILD (unpinned)"
			continue
		}
		pinsOK = pinsOK && same
	}
	r.Add("", "provision", "box.runs_pinned_artefacts", Pass, got(pinsOK, Pass, Fail), "", ev, t0)

	// Per family: do BOTH firewalls let it in? (Whether anything LISTENS
	// is checked after the first recipient exists — several inbounds are
	// only created by the mgmt daemon on the first /users/provision.)
	ufw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_ufw")...)
	cfw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_cloudfw")...)
	_ = os.WriteFile(filepath.Join(box, "state", "ufw.nft"), []byte(ufw), 0o644)
	allOK := true
	for _, name := range rc.Serve {
		f := rc.Fams[name]
		t0 = time.Now()
		rule := f.Endpoint.Proto + " dport " + strconv.Itoa(f.Endpoint.Port) + " accept"
		boxOpen, cloudOpen := nftAllows(ufw, f.Endpoint.Proto, f.Endpoint.Port), nftAllows(cfw, f.Endpoint.Proto, f.Endpoint.Port)
		allOK = r.Add(name, "provision", "firewalls.open", Pass, got(boxOpen && cloudOpen, Pass, Fail),
			fmt.Sprintf("want %q in both firewalls: box-side ufw=%v cloud firewall=%v", rule, boxOpen, cloudOpen),
			map[string]any{"box_ufw": boxOpen, "cloud_firewall": cloudOpen}, t0) && allOK
	}
	// The mgmt port must be SHUT to the client side of the world.
	t0 = time.Now()
	open := rc.tcpFrom(NSClient, Relay1IP, rec.MgmtPort)
	r.Add("", "provision", "mgmt_port_closed_to_strangers", Blocked, got(open, Pass, Blocked),
		"the cloud firewall should only open the mgmt port to the helper IP, and only during a verb", map[string]any{"port": rec.MgmtPort}, t0)
	_ = allOK // a shut firewall is that family's finding; the rest of the run still has value
	return true
}

// nftAllows reports whether an `nft list table` dump accepts proto/port.
func nftAllows(dump, proto string, port int) bool {
	p := strconv.Itoa(port)
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, "accept") || !strings.Contains(line, proto+" dport ") {
			continue
		}
		after := strings.TrimSuffix(strings.SplitN(line, proto+" dport ", 2)[1], " accept")
		after = strings.Trim(after, "{} ")
		for _, tok := range strings.Split(after, ",") {
			tok = strings.TrimSpace(tok)
			if tok == p {
				return true
			}
			if lo, hi, ok := strings.Cut(tok, "-"); ok {
				l, _ := strconv.Atoi(lo)
				h, _ := strconv.Atoi(hi)
				if l <= port && port <= h {
					return true
				}
			}
		}
	}
	return false
}

func fileSum(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(body)
	return hex.EncodeToString(s[:])
}

// ---- phase: mint -----------------------------------------------------

func (rc *RunCtx) mint() bool {
	r := rc.R
	// THE APP'S ORDER OF OPERATIONS. The wizard signs a relay's pack at
	// its Sign step, BEFORE any recipient exists, and every route in
	// that pack is committed to a signed endpoint — so the signature
	// needs the relay's keys with nobody on the relay. The record here
	// carries none of them (no sshd; the same record the Vultr adapter
	// writes on a real VPS). The app therefore asks the relay who it is
	// first, and signs from the answer (FINDINGS F-005).
	fmt.Fprintln(r.human, "phase: mint (relay-identity → bind-and-sign → users-provision → bind-and-sign again if the relay moved → users-pack-sbp)")
	if rc.askRelay("mint", "before-first-recipient") {
		if !rc.signBeforeAnyRecipient("mint") {
			return false
		}
		if !rc.provisionRecipient("r1", "mint") {
			return false
		}
		if !rc.resignIfRelayMoved("mint", "r1") {
			return false
		}
	} else {
		// A relay too old to state its identity. The app's fallback for
		// a record with no keys is to add a recipient and read the
		// relay's keys off the reply; the CLI spelling of that is
		// --endpoint-creds.
		if !rc.provisionRecipient("r1", "mint") {
			return false
		}
		if !rc.Resign("mint") {
			return false
		}
	}
	pack, _ := rc.packRecipient("r1", "mint")
	rc.Pack = pack
	// Not fatal: a family the relay does not serve is a finding about
	// that family, and the others still deserve their session.
	rc.relayListens()
	if pack != "" {
		rc.packChecks("mint", pack)
	}
	rc.MgmtWindowClosed("mint")
	return pack != ""
}

// askRelay runs `relay-identity` and reports whether the relay stated
// its identity. A relay that cannot say (exit 3) does not stop the
// world — the older order of operations is used, as the app does — and
// is recorded as what it is.
func (rc *RunCtx) askRelay(phase, when string) bool {
	t0 := time.Now()
	v, doc := rc.Pub.RelayIdentity(rc.Ctx)
	rc.identity = doc
	// Every relay must answer. A relay that cannot say (exit 3: its
	// management service predates the route) is still told apart from
	// one that failed — the app falls back on the first, and must not
	// guess about the second — but it is a red check either way: on the
	// box built from the pinned release it is FINDINGS F-005's
	// released-relay half, excused in known-findings.json until the pin
	// moves, and "did not reproduce" from that day on.
	want, gotV := "stated", "failed"
	switch {
	case v.OK():
		gotV = "stated"
	case v.RC == exitRelayCannotSay:
		gotV = "cannot-say"
	}
	rc.R.Add("", phase, "verb.relay-identity."+when, want, gotV, v.Tail(),
		map[string]any{"rc": v.RC, "pending_families": doc.PendingFamilies}, t0)
	return v.OK()
}

// signBeforeAnyRecipient is the app's Sign step: bind-and-sign with the
// relay's identity and NO recipient on the relay.
//
// One kind of route may legitimately be left without an endpoint here:
// a family whose key the relay has not made yet and SAID so
// (`pending_families` — shadowsocks, whose key is minted with the first
// recipient). Anything else uncommitted is a route the relay served and
// the signer could not commit, which is the defect this order of
// operations is here to catch.
func (rc *RunCtx) signBeforeAnyRecipient(phase string) bool {
	t0 := time.Now()
	v := rc.Pub.BindAndSign(rc.Ctx, "base.sbp")
	var ans struct {
		Uncommitted []string `json:"uncommitted_families"`
	}
	_ = json.Unmarshal([]byte(v.Stdout), &ans)
	ev := map[string]any{"uncommitted_families": ans.Uncommitted, "pending_families": rc.identity.PendingFamilies,
		"record_has_reality_key": rc.Rec.RealityPublicKey != ""}
	if !rc.R.Add("", phase, "verb.bind-and-sign.before-first-recipient", Pass, got(v.OK(), Pass, Fail), v.Tail(), ev, t0) {
		return false
	}
	pending := map[string]bool{}
	for _, f := range rc.identity.PendingFamilies {
		pending[f] = true
	}
	var unexplained []string
	for _, f := range ans.Uncommitted {
		if !pending[f] {
			unexplained = append(unexplained, f)
		}
	}
	rc.R.Add("", phase, "bind-and-sign.before-first-recipient.only_pending_families_uncommitted", Pass,
		got(len(unexplained) == 0, Pass, Fail),
		got(len(unexplained) == 0, "", "signed without an endpoint, and the relay did not say it was pending: "+strings.Join(unexplained, ", ")),
		ev, t0)
	rc.signedPending = ans.Uncommitted
	return true
}

// resignIfRelayMoved does what the app does with every reply the relay
// gives: compare the relay it describes with what the signed pack
// commits to, and sign again — from a fresh identity — when they
// differ. On a relay that serves shadowsocks the first recipient is
// exactly that case: its key did not exist when the pack was signed.
func (rc *RunCtx) resignIfRelayMoved(phase, recipient string) bool {
	t0 := time.Now()
	moved := rc.replyDisagreesWithSignedPack("creds-" + recipient + ".json")
	// What MUST have happened: a family signed as pending has its key
	// now, so the pack has to be signed again; with nothing pending the
	// relay is unchanged and a second signature would be churn.
	want := "not-needed"
	if len(rc.signedPending) > 0 {
		want = "signed-again"
	}
	gotV := "not-needed"
	if len(moved) > 0 {
		gotV = "signed-again"
	}
	rc.R.Add("", phase, "resign.after-first-recipient", want, gotV,
		got(want == gotV, "", "the reply disagreed with the signed pack on: "+strings.Join(moved, ", ")),
		map[string]any{"moved": moved, "signed_pending": rc.signedPending}, t0)
	if len(moved) == 0 {
		return true
	}
	return rc.Resign(phase)
}

// replyDisagreesWithSignedPack lists the relay-wide fields of a
// users-provision reply that are not what the signed pack commits to.
func (rc *RunCtx) replyDisagreesWithSignedPack(credsFile string) []string {
	body, err := os.ReadFile(rc.Pub.Path(credsFile))
	if err != nil {
		return nil
	}
	var reply struct {
		RealityPublicKey string `json:"reality_public_key"`
		TLSCertSHA256    string `json:"tls_cert_sha256"`
		CoverSNI         string `json:"cover_sni"`
		SSPassword       string `json:"ss_password"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return nil
	}
	c := rc.Pub.Committed
	var moved []string
	differs := func(said, signed string) bool { return said != "" && said != signed }
	if differs(reply.RealityPublicKey, c.RealityPublicKey) {
		moved = append(moved, "reality_public_key")
	} else if c.RealityPublicKey != "" && differs(reply.CoverSNI, c.CoverSNI) {
		moved = append(moved, "cover_sni")
	}
	if differs(reply.TLSCertSHA256, c.TLSCertSHA256) {
		moved = append(moved, "tls_cert_sha256")
	}
	if key, _, ok := strings.Cut(reply.SSPassword, ":"); ok && key != "" {
		sum := sha256.Sum256([]byte("daal/ss-server-key/v1\x00" + key))
		if hex.EncodeToString(sum[:]) != c.SSServerKeySHA256 {
			moved = append(moved, "ss_server_key")
		}
	}
	return moved
}

// relayListens checks, per served family, that something in the relay
// namespace is actually bound to the family's port. Run after the first
// recipient exists.
func (rc *RunCtx) relayListens() bool {
	listen, _ := sh(rc.Ctx, inNS(NSRelay1, "ss", "-Hltnu")...)
	_ = os.WriteFile(filepath.Join(rc.P.Box(rc.Rec.ServerID), "state", "listeners.txt"), []byte(listen), 0o644)
	allOK := true
	for _, name := range rc.Serve {
		f := rc.Fams[name]
		t0 := time.Now()
		port := strconv.Itoa(f.Endpoint.Port)
		listening := false
		for _, line := range strings.Split(listen, "\n") {
			fld := strings.Fields(line)
			if len(fld) >= 5 && fld[0] == f.Endpoint.Proto && strings.HasSuffix(fld[4], ":"+port) {
				listening = true
			}
		}
		allOK = rc.R.Add(name, "mint", "relay.listens", Pass, got(listening, Pass, Fail),
			got(listening, "", fmt.Sprintf("nothing listening on %s/%s in the relay namespace", port, f.Endpoint.Proto)),
			map[string]any{"port": f.Endpoint.Port, "proto": f.Endpoint.Proto}, t0) && allOK
	}
	return allOK
}

// MintRecipient provisions one recipient on the relay and mints their
// pack. Ops reuse it for extra recipients.
func (rc *RunCtx) MintRecipient(name, phase string) (string, bool) {
	if !rc.provisionRecipient(name, phase) {
		return "", false
	}
	return rc.packRecipient(name, phase)
}

// Resign runs bind-and-sign against record.json as it is now and
// replaces base.sbp. Called at mint and after every rotation that moves
// something the signed endpoints name (L2: the cover host; L3: the
// address) — the app re-signs after a rotation for the same reason.
//
// The app asks the relay who it is before it signs, so this does too —
// on a relay that can answer. After an L2 that is where the new cover
// host comes from.
func (rc *RunCtx) Resign(phase string) bool {
	if rc.Pub.identityFile != "" {
		rc.askRelay(phase, "before-resign")
	}
	t0 := time.Now()
	v := rc.Pub.BindAndSign(rc.Ctx, "base.sbp")
	var ans struct {
		Uncommitted []string `json:"uncommitted_families"`
	}
	_ = json.Unmarshal([]byte(v.Stdout), &ans)
	ok := rc.R.Add("", phase, "verb.bind-and-sign", Pass, got(v.OK(), Pass, Fail), v.Tail(),
		map[string]any{"uncommitted_families": ans.Uncommitted}, t0)
	// The verb exits 0 while signing a route WITHOUT an endpoint — a
	// route no recipient can use. Exit status alone would hide that.
	if ok && len(ans.Uncommitted) > 0 {
		rc.R.Add("", phase, "bind-and-sign.every_route_has_a_signed_endpoint", Pass, Fail,
			"signed without an endpoint: "+strings.Join(ans.Uncommitted, ", ")+" — "+oneLine(v.Tail(), 400), nil, t0)
	}
	return ok
}

func (rc *RunCtx) provisionRecipient(name, phase string) bool {
	r := rc.R
	t0 := time.Now()
	v := rc.Pub.UsersProvision(rc.Ctx, name)
	if !r.Add("", phase, "verb.users-provision."+name, Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
		return false
	}
	// The verb exits 0 while telling the operator a family it offers has
	// no credential. Exit status alone would hide that.
	if warn := strings.Count(v.Stderr, "warning:"); warn > 0 {
		r.Add("", phase, "users-provision."+name+".no_warnings", Pass, Fail, v.Tail(), nil, t0)
	}
	return true
}

func (rc *RunCtx) packRecipient(name, phase string) (string, bool) {
	r := rc.R
	t0 := time.Now()
	out := "pack-" + name + ".sbp"
	v := rc.Pub.PackSBP(rc.Ctx, "base.sbp", "creds-"+name+".json", out)
	ok := r.Add("", phase, "verb.users-pack-sbp."+name, Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"stdout": strings.TrimSpace(v.Stdout)}, t0)
	if ok && strings.Contains(v.Stderr, "NOT connectable") {
		// The verb exits 0 while dropping routes; that is a finding, not a pass.
		r.Add("", phase, "pack."+name+".no_dropped_routes", Pass, Fail, v.Tail(), nil, t0)
	}
	if !ok {
		return "", false
	}
	return rc.Pub.Path(out), true
}

// unconnectableNotListed: a route the pack cannot connect on — one the
// minter dropped (`_daal_unavailable`), or one with no outbound at all —
// must not be a route on the client. The engine's own route list is
// compared with the pack: nothing the pack marks unconnectable may be
// offered for selection (FINDINGS F-003).
func (rc *RunCtx) unconnectableNotListed(f Family, phase, pack string, routesEv map[string]any, t0 time.Time) {
	v, err := ReadPack(pack)
	if err != nil {
		return // packChecks reports an unreadable pack
	}
	listed := map[string]bool{}
	doc, _ := routesEv["routes"].(map[string]any)
	rows, _ := doc["routes"].([]any)
	for _, r := range rows {
		m, _ := r.(map[string]any)
		id, _ := m["route_id"].(string)
		listed[id] = true
	}
	var dead, offered []string
	for _, r := range v.Routes {
		if r.Unavailable == "" && r.Type != "" {
			continue
		}
		dead = append(dead, r.ID+":"+r.Family)
		if listed[r.ID] {
			offered = append(offered, r.ID+":"+r.Family)
		}
	}
	rc.R.Add(f.Name, phase, "import.unconnectable_not_listed", Pass, got(len(offered) == 0, Pass, Fail),
		got(len(offered) == 0, "", "the engine lists route(s) the pack cannot connect on: "+strings.Join(offered, ", ")),
		map[string]any{"unconnectable_in_pack": dead, "routes_listed": len(listed)}, t0)
}

// ---- phase: family ---------------------------------------------------

// family runs one family under the applied scenario with recipient r1.
func (rc *RunCtx) family(f Family) {
	expect, _ := rc.Scn.ExpectFor(f.Name)
	fmt.Fprintf(rc.R.human, "family: %s (scenario expects %s)\n", f.Name, expect)
	outcome := rc.Session(f, rc.Pack, "family", expect)
	rc.wrongCreds(f, "family", expect, outcome)
	rc.wrongServer(f, "family", expect, outcome)
}

// Session is one complete insider session for one family with one pack:
// control → import → connect → verified fetch → path proof → disconnect →
// control. It returns the observed tunnel outcome. Ops call it too.
//
// If the engine PROCESS dies mid-session (not: refuses, not: is blocked —
// dies), that is recorded as a red `engine.survived` with the crash
// signature, the dead VPN's routing is reaped as Android would, and the
// session is repeated once, so one crash costs one red check and not a
// cascade of misattributed ones (the first crash the rig saw read as "DNS
// blocked" on naive and "ip rule: File exists" on the next family).
func (rc *RunCtx) Session(f Family, pack, phase, expect string) string {
	outcome, died := rc.session(f, pack, phase, expect, true)
	if died {
		outcome, _ = rc.session(f, pack, phase, expect, false)
	}
	return outcome
}

// engineDied records the death. It returns true when the caller should
// abandon this attempt (a retry follows).
func (rc *RunCtx) engineDied(f Family, phase string, c *Client, retry bool, t0 time.Time) bool {
	if !c.Died() {
		return false
	}
	sig := c.CrashSignature()
	rc.R.Add(f.Name, phase, "engine.survived", Pass, Fail,
		"the engine process died mid-session: "+sig+got(retry, " — the session is repeated once", " — second death in a row; the checks below are what a user would see"),
		map[string]any{"client_dir": c.Dir, "stderr": filepath.Join(c.Dir, "stderr.log"), "signature": sig}, t0)
	ReapDeadVPN(rc.Ctx)
	return retry
}

func (rc *RunCtx) session(f Family, pack, phase, expect string, retry bool) (string, bool) {
	p, r := rc.P, rc.R
	if f.Skip != "" {
		r.Add(f.Name, phase, "tunnel", Skipped, Skipped, f.Skip, nil, time.Now())
		return Skipped, false
	}
	// A separate phone gets a link that carries nothing of the phone
	// before it (first_verdict.go: linkQuiet).
	t0 := time.Now()
	quietEv, quietErr := rc.linkQuiet()
	if quietErr != nil {
		r.Add(f.Name, phase, "link.quiet", Pass, Fail, quietErr.Error(), quietEv, t0)
	}
	// Negative control BEFORE: with no tunnel the target must be out of reach.
	t0 = time.Now()
	pre := Probe(rc.Ctx, p, false, 2*time.Second)
	r.Add(f.Name, phase, "control.before", Blocked, got(pre.OK, Pass, Blocked), pre.Error, quietEv, t0)

	t0 = time.Now()
	_, _ = WireReset(rc.Ctx) // the wire tap's window for this session starts here
	c, err := StartClient(p, f.Name, ClientOpts{Pack: pack, Family: f.Name, Experimental: f.Experimental})
	if err != nil {
		r.Add(f.Name, phase, "tunnel", expect, Fail, err.Error(), nil, t0)
		return Fail, false
	}
	ev, err := c.Wait(rc.Ctx, EngineConnectWait, "connected")
	if err != nil && rc.engineDied(f, phase, c, retry, t0) {
		return Fail, true
	}
	// The engine only reports a route connected once it has carried a
	// round trip through it (its connection proof), and gives up after a
	// bounded few seconds. Under a scenario that DEGRADES the path
	// (MustEstablish: 30% loss, a 56k cap) that proof can lose to the
	// same retransmissions the nonce round trip below is given 90 s for —
	// so, as there, a family that has not yet connected is asked again,
	// each time as a fresh phone, within the same budget, because
	// family/established and the wire check need a connected engine. A
	// family that is really dead costs the budget once and is then red.
	//
	// A fresh phone has forgotten the failure, so the retry answers "can
	// this family connect at all" and NOT "what was the person told":
	// every attempt is recorded, and the first is judged on its own
	// (engine.first_verdict, first_verdict.go).
	attempts := []ConnectAttempt{connectAttempt(1, c, ev, err)}
	if phase == "family" && expect == Blocked && rc.Scn.MustEstablish(f.Name) {
		deadline := time.Now().Add(EstablishBudget)
		for err != nil && ev != nil && ev["stage"] == StageProof && time.Now().Before(deadline) && rc.Ctx.Err() == nil {
			c.Stop()
			if c, err = StartClient(p, f.Name, ClientOpts{Pack: pack, Family: f.Name, Experimental: f.Experimental}); err != nil {
				r.Add(f.Name, phase, "tunnel", expect, Fail, err.Error(), nil, t0)
				return Fail, false
			}
			ev, err = c.Wait(rc.Ctx, EngineConnectWait, "connected")
			if err != nil && rc.engineDied(f, phase, c, retry, t0) {
				return Fail, true
			}
			attempts = append(attempts, connectAttempt(len(attempts)+1, c, ev, err))
		}
	}
	connects := len(attempts)
	importEv := c.Event("import")
	routesEv := c.Event("routes")
	if routesEv == nil {
		// Never got as far as a route list: the pack itself was not accepted.
		c.Stop()
		r.Add(f.Name, phase, "import", Pass, Refused, errStr(err), map[string]any{"import": importEv, "trust": c.Event("trust")}, t0)
		r.Add(f.Name, phase, "tunnel", expect, Refused, "pack not imported", nil, t0)
		rc.established(f, phase, expect, nil, ProbeResult{}, "the pack was not imported", false, t0)
		return Refused, false
	}
	r.Add(f.Name, phase, "import", Pass, Pass, "", map[string]any{"verdict": verdictKind(importEv), "trust": verdictKind(c.Event("trust"))}, t0)
	rc.unconnectableNotListed(f, phase, pack, routesEv, t0)
	if err != nil {
		c.Stop()
		outcome := Blocked
		stage, _ := ev["stage"].(string)
		if stage == "pick" || stage == "set_route" {
			outcome = Refused
		}
		r.Add(f.Name, phase, "tunnel", expect, outcome, "engine did not connect: "+err.Error(),
			map[string]any{"client_dir": c.Dir, "stage": stage, "connect_attempts": connects, "connects": attempts, "set_route_ms": ev["set_route_ms"]}, t0)
		rc.firstVerdictCheck(f, phase, expect, attempts, t0)
		if outcome == Blocked {
			// The bar is the payload a session ASKS for: the engine gave
			// the route up after its own round trip failed, so nothing
			// was fetched, and a completed TCP handshake before the
			// reset must not read as the family having carried anything.
			wire, werr := WireReset(rc.Ctx)
			rc.wireCheck(f, phase, expect, wire, werr, ProbeBlobBytes, false, t0)
		}
		rc.established(f, phase, expect, nil, ProbeResult{}, "the engine did not connect: "+err.Error(), false, t0)
		rc.EngineCategory(f, phase, c, nil)
		return outcome, false
	}

	// The fetch, through whatever the kernel routes it into.
	t0 = time.Now()
	budget := 10 * time.Second
	if expect == Blocked {
		budget = 5 * time.Second // long enough for any handshake that is going to happen
	}
	pr := ProbeApp(rc.Ctx, p, f.UDP != "", f.DNS != "", SessionBurst, budget)
	if rc.engineDied(f, phase, c, retry, t0) {
		return Fail, true
	}
	if !pr.OK {
		// Whatever is red from here to the end of this session carries
		// what the engine process itself said (Cronet logs to stderr and
		// nowhere else): the cause, not only the symptom.
		if said := c.StderrTail(); said != "" {
			r.note = " | engine stderr: " + said
			defer func() { r.note = "" }()
		}
	}
	wire, werr := WireReset(rc.Ctx)
	outcome := got(pr.OK, Pass, Blocked)
	detail := pr.Error
	if pr.OK && pr.Remote != Relay1EgressIP {
		outcome, detail = Fail, "fetch succeeded but the target saw "+pr.Remote+", not the relay ("+Relay1EgressIP+"): this is not the tunnel"
	}
	r.Add(f.Name, phase, "tunnel", expect, outcome, detail, map[string]any{
		"route_id": ev["route_id"], "target_saw": pr.Remote, "nonce_ok": pr.NonceOK,
		"blob_bytes": pr.BlobBytes, "blob_sha256_ok": pr.BlobOK, "upload_bytes": pr.UploadBytes, "upload_sha256_ok": pr.UploadOK,
		"burst_connections": pr.BurstN, "burst_ok": pr.BurstOK,
		"fetch_ms": pr.Ms, "client_dir": c.Dir, "connect_attempts": connects, "connects": attempts, "set_route_ms": ev["set_route_ms"]}, t0)
	rc.firstVerdictCheck(f, phase, expect, attempts, t0)
	// Where the bytes actually went: this family's endpoint, and nowhere else.
	// The bar is the payload the probe ASKED for, not what it got: a
	// censor that lets the TCP handshake through and kills the flow after
	// the ClientHello (sni-rst, sni-drop, tcp-reset-mid-handshake) returns
	// a few packets and zero payload, and "a SYN-ACK came back" must not
	// read as the family having carried the fetch.
	wantDown := int64(pr.BlobBytes)
	if !pr.OK {
		wantDown = ProbeBlobBytes
	}
	rc.wireCheck(f, phase, expect, wire, werr, wantDown, pr.OK, t0)
	if rc.established(f, phase, expect, c, pr, "", retry, t0) && rc.engineDied(f, phase, c, retry, t0) {
		return Fail, true
	}
	if outcome == Pass && f.UDP != "" {
		// Both sizes must make it: a tunnel that carries a DNS-sized
		// datagram and loses a 1400-byte one resolves names and then
		// cannot carry a single QUIC packet.
		udp, udpDetail := Pass, ""
		switch {
		case !pr.UDPOK:
			udp, udpDetail = Blocked, "small datagram: "+pr.UDPError
		case pr.UDPRemote != Relay1EgressIP:
			udp, udpDetail = Fail, "the datagram reached the target from "+pr.UDPRemote+", not from the relay: this is not the tunnel"
		case !pr.UDPBigOK:
			udp, udpDetail = Blocked, fmt.Sprintf("the small datagram round-tripped, the %d-byte one did not: %s", BigDatagram, pr.UDPBigError)
		}
		r.Add(f.Name, phase, "udp", f.UDP, udp, udpDetail, map[string]any{"target_saw": pr.UDPRemote, "small_ok": pr.UDPOK, "big_ok": pr.UDPBigOK, "big_bytes": BigDatagram}, t0)
	}
	if outcome == Pass && f.DNS != "" {
		// The phone's resolver: UDP/53 to the servers the VpnService set.
		dns, dnsDetail := Pass, ""
		switch {
		case !pr.DNSOK:
			dns, dnsDetail = Blocked, "UDP/53 lookup got no answer: "+pr.DNSError
		case pr.DNSAsker != Relay1EgressIP:
			dns, dnsDetail = Fail, "the resolver saw the query come from "+pr.DNSAsker+", not from the relay: the lookup did not go through the tunnel"
		case !pr.NameFetchOK:
			dns, dnsDetail = Blocked, "the name resolved but the fetch by name failed: "+pr.NameFetchErr
		}
		if dns != Pass && pr.DNSTCPOK {
			dnsDetail += " (the same lookup over TCP/53 succeeded)"
		}
		r.Add(f.Name, phase, "dns", f.DNS, dns, dnsDetail, map[string]any{"resolver_saw": pr.DNSAsker, "udp53_ok": pr.DNSOK,
			"tcp53_ok": pr.DNSTCPOK, "tcp53_error": pr.DNSTCPError, "fetch_by_name_ok": pr.NameFetchOK, "servers": []string{PublicDNS1, PublicDNS2}}, t0)
	}

	t0 = time.Now()
	bye := c.Stop()
	calls := 0
	if bye != nil {
		if n, ok := bye["protect_calls"].(float64); ok {
			calls = int(n)
		}
	}
	// Negative control AFTER: disconnecting must take the path away again.
	post := Probe(rc.Ctx, p, false, 2*time.Second)
	r.Add(f.Name, phase, "control.after", Blocked, got(post.OK, Pass, Blocked), post.Error,
		map[string]any{"engine_protect_calls": calls, "clean_disconnect": bye != nil}, t0)
	// What the ENGINE said happened, against what the censor did (censor.go).
	rc.EngineCategory(f, phase, c, bye)
	return outcome, false
}

// EstablishBudget is how long a family gets to show it connected at all
// under a scenario that degrades the path instead of cutting it.
// EstablishAttempt is one try. A healthy family answers the session's own
// probe and costs nothing here; only a family that has not yet answered
// (30% loss: a handshake that needed its third SYN) is asked again.
//
// The budget is sized for naive under heavy-loss, the worst case seen:
// its attempts fail fast with EOF (FINDINGS CEN-O4) about every other
// time, and at 20 s (five attempts) one full-matrix run in three had a
// naive that never got its nonce through. A family that is really dead
// costs the whole budget once, then is red.
//
// One attempt is 15 s, not 5: every attempt is a NEW connection, and
// under 30% loss in each direction a handshake needs TCP's own
// retransmissions (1 s, then 3 s, then 7 s) to finish. With 5 s attempts
// a slow machine — the 4-core CI runner, 15 worlds side by side — threw
// each connection away just before its retransmit landed, and the first
// CI run had a vless-reality that made 13 attempts and completed none.
const (
	EstablishBudget  = 90 * time.Second
	EstablishAttempt = 15 * time.Second
)

// established records family/established where the scenario demands it
// (Scenario.MustEstablish): expected "blocked" because the payload cannot
// finish in the probe's budget, NOT because the family is stopped. That
// expectation is satisfied by a family that is simply dead — no user on
// the relay, a wrong port, a broken config — so it needs this second,
// positive claim: one fresh nonce went out through the tunnel and came
// back, and the target saw it arrive from the relay's egress address.
// That takes a completed handshake AND an accepted credential.
//
// Its negative controls are the session's own: control.before (with no
// tunnel the same nonce round trip fails) and the source address (a
// reply from anywhere but the relay is not this tunnel).
//
// c is the live client (nil: the session never got one — why says so).
// It returns true, recording nothing, when the engine died while being
// asked again and the session is going to be repeated (retry).
func (rc *RunCtx) established(f Family, phase, expect string, c *Client, pr ProbeResult, why string, retry bool, t0 time.Time) (died bool) {
	if phase != "family" || expect != Blocked || !rc.Scn.MustEstablish(f.Name) {
		return false
	}
	attempts := 1
	if c != nil {
		deadline := time.Now().Add(EstablishBudget)
		for !establishedBy(pr) && pr.Remote == "" && time.Now().Before(deadline) && rc.Ctx.Err() == nil {
			started := time.Now()
			pr = ProbeWhoami(rc.Ctx, rc.P, EstablishAttempt)
			attempts++
			if d := time.Second - time.Since(started); d > 0 && !establishedBy(pr) {
				time.Sleep(d) // an instant refusal is not a reason to spin
			}
			if c.Died() {
				if retry {
					return true // the caller records the death and repeats the session
				}
				pr.Error = "the engine process died: " + c.CrashSignature()
				break
			}
		}
	}
	outcome, detail := Pass, ""
	switch {
	case c == nil:
		outcome, detail = Blocked, why
	case pr.NonceOK && pr.Remote != Relay1EgressIP:
		outcome, detail = Fail, "the nonce came back, but the target saw "+pr.Remote+", not the relay ("+Relay1EgressIP+"): this is not the tunnel"
	case !establishedBy(pr):
		outcome, detail = Blocked, fmt.Sprintf("the scenario says %s still connects and only then crawls, but in %d attempt(s) not one nonce made the round trip through it (%s): the family is dead here, not slow",
			f.Name, attempts, pr.Error)
	}
	ev := map[string]any{"nonce_ok": pr.NonceOK, "target_saw": pr.Remote, "attempts": attempts}
	if c != nil {
		ev["client_dir"] = c.Dir
	}
	rc.R.Add(f.Name, phase, "established", Pass, outcome, detail, ev, t0)
	return false
}

// establishedBy: the probe's nonce round trip succeeded, through the relay.
func establishedBy(pr ProbeResult) bool { return pr.NonceOK && pr.Remote == Relay1EgressIP }

func verdictKind(ev map[string]any) any {
	if ev == nil {
		return nil
	}
	return ev["kind"]
}

func runProbeCmd(ctx context.Context, argv []string) ProbeResult {
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	return parseProbe(out, err)
}

// activeFamilies are the families under test that the rig can exercise.
func (rc *RunCtx) activeFamilies() []Family {
	var out []Family
	for _, n := range rc.Want {
		if f := rc.Fams[n]; f.Skip == "" {
			out = append(out, f)
		}
	}
	return out
}

// sub runs a Session whose checks are namespaced "<label>.<check>", so an
// op can run several sessions per family without their rows colliding.
func (rc *RunCtx) sub(f Family, phase, label, pack, expect string) string {
	saved := rc.R.prefix
	rc.R.prefix = label + "."
	defer func() { rc.R.prefix = saved }()
	// Under a blocking scenario nothing an op expects to pass can pass;
	// the scenario's own expectation wins.
	if scn, _ := rc.Scn.ExpectFor(f.Name); scn == Blocked {
		expect = Blocked
	}
	return rc.Session(f, pack, phase, expect)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// MgmtWindowClosed asserts that no verb left its ephemeral cloud-firewall
// window behind: after a mgmt call returns, the cloud firewall must not
// accept the mgmt port from anyone. Ops should call it after their verbs.
func (rc *RunCtx) MgmtWindowClosed(phase string) bool {
	t0 := time.Now()
	cfw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_cloudfw")...)
	open := nftAllows(cfw, "tcp", rc.Rec.MgmtPort)
	return rc.R.Add("", phase, "cloud.mgmt_window_closed", Pass, got(!open, Pass, Fail),
		got(!open, "", "the cloud firewall still accepts the mgmt port after the verb returned"),
		map[string]any{"mgmt_port": rc.Rec.MgmtPort}, t0)
}
