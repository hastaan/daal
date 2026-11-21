package main

import (
	"crypto/rand"
	"regexp"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Add-on 3, the Google update channel (docs/optional-addons-plan.md §3,
// item G7), from both seats.
//
//	google-channel  the publisher's whole side against the lab's Google
//	                (fakegfe.go, fakegas_api.go): Path A with a one-shot
//	                token (the API turned off → the exact error the app
//	                branches on; a call that fails half way → resumed into
//	                the same project, the token revoked every time); the
//	                update POSTed and fetched back THROUGH THE FRONT (SNI
//	                www.google.com, authority script.google.com); a
//	                stranger's write key refused, an older update refused;
//	                Path B (the script pasted by hand) ending in the same
//	                state; a web app behind a sign-in wall named as such.
//	google-refresh  a phone CONNECTED when its relay's address is
//	                null-routed and the relay has moved (L3), under a
//	                censor that blocks the ordinary refresh hosts (the
//	                scenario's rules: refresh-google-*.json): the engine's
//	                walk reaches the Google mirror through the front and
//	                reconnects — or, under refresh-google-rst, ends
//	                cleanly after at most two connections to Google, or,
//	                under refresh-google-rollback, refuses the older
//	                update the script serves.
//
// The recipient half needs core/refresh and core/bootstrap code landing
// in this wave (L-fetch G4, G5): until it is in the tree that half is one
// SKIPPED line (addons_net.go Prereq).

func init() {
	Ops["google-channel"] = opGoogleChannel
	Ops["google-refresh"] = opGoogleRefresh
}

type googleChan struct {
	url, keyFile, pathToken string
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (rc *RunCtx) googleKnobs(k GoogleKnobs) {
	b, _ := json.Marshal(k)
	_ = os.WriteFile(filepath.Join(rc.P.Run, googleKnobsFile), b, 0o644)
}

// googleDeploy is Path A as the wizard drives it: appsscript-deploy with
// the sign-in's one-shot token on stdin.
func (rc *RunCtx) googleDeploy(phase, label, keyFile, pathToken, scriptID string) (map[string]any, Verb) {
	tok := "ya29.wb-" + randHex(24)
	_ = os.WriteFile(filepath.Join(rc.P.Run, googleTokenFile), []byte(tok), 0o600)
	args := []string{"appsscript-deploy", "--write-key-file", keyFile, "--path-token", pathToken, "--progress-json"}
	if scriptID != "" {
		args = append(args, "--script-id", scriptID)
	}
	stdin, _ := json.Marshal(map[string]string{"access_token": tok})
	t0 := time.Now()
	v := rc.Pub.deployStdin(rc.Ctx, stdin, args...)
	var out map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &out)
	leaked := strings.Contains(v.Stdout+v.Stderr, tok)
	rc.R.Add("", phase, label+".token_in_no_output", Pass, got(!leaked, Pass, Fail), got(!leaked, "", "appsscript-deploy printed the access token"), nil, t0)
	return out, v
}

// googleChannel sets the channel up by Path A and returns it.
func (rc *RunCtx) googleChannel(phase string) (*googleChan, bool) {
	t0 := time.Now()
	if err := rc.BringUpGoogle(); err != nil {
		return nil, rc.R.Add("", phase, "google.up", Pass, Fail, err.Error(), nil, t0)
	}
	g := &googleChan{keyFile: rc.Pub.Path("google-write.key"), pathToken: base64.RawURLEncoding.EncodeToString([]byte(randHex(8)))[:22]}
	if err := os.WriteFile(g.keyFile, []byte(randHex(32)+"\n"), 0o600); err != nil {
		return nil, rc.R.Add("", phase, "google.write_key", Pass, Fail, err.Error(), nil, t0)
	}
	rc.googleKnobs(GoogleKnobs{})
	out, v := rc.googleDeploy(phase, "deploy", g.keyFile, g.pathToken, "")
	g.url, _ = out["url"].(string)
	ok := rc.R.Add("", phase, "verb.appsscript-deploy", Pass, got(v.OK() && g.url != "", Pass, Fail), v.Tail(), map[string]any{"has_url": g.url != ""}, t0)
	return g, ok
}

// googlePost sends the container (document, the credential-less pack,
// and optionally a standby key) the way the app does after it publishes.
func (rc *RunCtx) googlePost(phase, label string, g *googleChan, docFile, packFile, keyFile, standbyKey string) (map[string]any, Verb) {
	args := []string{"appsscript-check", "--url", g.url, "--write-key-file", keyFile, "--freshness-file", docFile}
	if packFile != "" {
		args = append(args, "--pack-file", packFile)
	}
	if standbyKey != "" {
		kf := rc.Pub.Path("standby-key-" + label + ".txt")
		_ = os.WriteFile(kf, []byte(standbyKey), 0o600)
		defer os.Remove(kf)
		args = append(args, "--standby-key-file", kf)
	}
	v := rc.Pub.Deploy(rc.Ctx, args...)
	var out map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &out)
	return out, v
}

func opGoogleChannel(rc *RunCtx) {
	const phase = "op:google-channel"
	t0 := time.Now()
	if err := rc.BringUpGoogle(); err != nil {
		rc.R.Add("", phase, "google.up", Pass, Fail, err.Error(), nil, t0)
		return
	}
	keyFile := rc.Pub.Path("google-write.key")
	_ = os.WriteFile(keyFile, []byte(randHex(32)+"\n"), 0o600)
	pathToken := base64.RawURLEncoding.EncodeToString([]byte(randHex(8)))[:22]

	// 1. The Apps Script API is not turned on for the account.
	rc.googleKnobs(GoogleKnobs{APIDisabled: true})
	_, v := rc.googleDeploy(phase, "api-off", keyFile, pathToken, "")
	first := errorLine(v.Stderr)
	rc.R.Add("", phase, "api-off.named", Pass, got(!v.OK() && strings.HasPrefix(first, "E_GOOGLE_API_NOT_ENABLED"), Pass, Fail), first, map[string]any{"rc": v.RC}, t0)

	// 2. A call fails half way; the app resumes into the same project.
	t0 = time.Now()
	rc.googleKnobs(GoogleKnobs{FailStage: "version"})
	_, v = rc.googleDeploy(phase, "partial", keyFile, pathToken, "")
	first = errorLine(v.Stderr)
	scriptID := ""
	if i := strings.Index(first, "script_id="); i >= 0 {
		scriptID = strings.Fields(first[i+len("script_id="):])[0]
	}
	rc.R.Add("", phase, "partial.named_with_the_project", Pass, got(!v.OK() && strings.HasPrefix(first, "E_GOOGLE_PARTIAL") && scriptID != "", Pass, Fail), first, nil, t0)
	rc.googleKnobs(GoogleKnobs{})
	t0 = time.Now()
	out, v := rc.googleDeploy(phase, "resume", keyFile, pathToken, scriptID)
	url, _ := out["url"].(string)
	if !rc.R.Add("", phase, "verb.appsscript-deploy.resumed", Pass, got(v.OK() && url != "", Pass, Fail), v.Tail(), nil, t0) {
		return
	}
	creates, revokes := 0, 0
	for _, q := range GoogleRequests(rc.P.Run) {
		if q.Part == "api" && q.Detail == "create" && q.Status == 200 {
			creates++
		}
		if q.Part == "oauth" && q.Path == "/revoke" {
			revokes++
		}
	}
	rc.R.Add("", phase, "resume.one_project", Pass, got(creates == 1, Pass, Fail), fmt.Sprintf("projects created: %d (the resume must not make a second)", creates), nil, t0)
	rc.R.Add("", phase, "token_revoked_every_time", Pass, got(revokes >= 3, Pass, Fail), fmt.Sprintf("revocations: %d of 3 sign-ins", revokes), nil, t0)
	g := &googleChan{url: url, keyFile: keyFile, pathToken: pathToken}

	// 3. An update, posted and fetched back through the front.
	fc, ok := rc.freshChannel(phase)
	if !ok {
		return
	}
	mirrors := append(append([]string{}, freshMirrorFlags...), "--freshness-mirror", "appsscript="+g.url)
	t0 = time.Now()
	sv := rc.Pub.BindAndSign(rc.Ctx, "base-g1.sbp", mirrors...)
	var signed map[string]any
	_ = json.Unmarshal([]byte(sv.Stdout), &signed)
	n, _ := signed["freshness_mirrors"].(float64)
	if !rc.R.Add("", phase, "verb.bind-and-sign.with-google", Pass, got(sv.OK() && n == 3, Pass, Fail), sv.Tail(), map[string]any{"freshness_mirrors": n}, t0) {
		return
	}
	packID, _ := signed["relay_pack_id"].(string)
	sha, _ := signed["sbp_sha256"].(string)
	doc, ok := fc.publish("g1", packID, sha, rc.Pub.Path("publisher.priv"), nil)
	if !ok || len(doc) == 0 {
		return
	}
	docFile := rc.Pub.Path("freshness-g1.json")
	before := len(GoogleRequests(rc.P.Run))
	t0 = time.Now()
	res, v := rc.googlePost(phase, "g1", g, docFile, rc.Pub.Path("base-g1.sbp"), keyFile, "")
	okPost := v.OK() && res["ok"] == true && res["via_front"] == true && res["pack_included"] == true
	rc.R.Add("", phase, "update.posted_and_fetched_back_through_the_front", Pass, got(okPost, Pass, Fail), v.Tail()+" "+v.Stdout, res, t0)
	fronted, plain := 0, 0
	for _, q := range GoogleRequests(rc.P.Run)[before:] {
		if q.From != "" && !strings.HasPrefix(q.From, PublisherIP+":") {
			continue
		}
		switch {
		case q.SNI == "www.google.com" && (q.Host == "script.google.com" || q.Host == "script.googleusercontent.com"):
			fronted++
		case q.SNI == "script.google.com":
			plain++
		}
	}
	rc.R.Add("", phase, "update.front_routes_by_authority", Pass, got(fronted >= 2 && plain == 0, Pass, Fail),
		fmt.Sprintf("requests with SNI www.google.com for the script hosts: %d; with SNI script.google.com: %d", fronted, plain), nil, t0)

	// 4. A stranger's write key; an older update.
	t0 = time.Now()
	strange := rc.Pub.Path("google-write-stranger.key")
	_ = os.WriteFile(strange, []byte(randHex(32)+"\n"), 0o600)
	res, _ = rc.googlePost(phase, "stranger", g, docFile, "", strange, "")
	rc.R.Add("", phase, "stranger_key_refused", Pass, got(res["reason"] == "refused", Pass, Fail), fmt.Sprintf("reason=%v", res["reason"]), nil, t0)
	if older, ok := rc.olderDoc(phase, fc, packID, sha); ok {
		t0 = time.Now()
		res, _ = rc.googlePost(phase, "older", g, older, "", keyFile, "")
		rc.R.Add("", phase, "older_update_refused", Pass, got(res["reason"] == "stale", Pass, Fail), fmt.Sprintf("reason=%v", res["reason"]), nil, t0)
	}

	// 5. Path B: the same script, pasted and deployed by hand.
	t0 = time.Now()
	sv = rc.Pub.Deploy(rc.Ctx, "appsscript-script", "--write-key-file", keyFile, "--path-token", pathToken)
	var script struct {
		Code string `json:"code_gs"`
	}
	_ = json.Unmarshal([]byte(sv.Stdout), &script)
	depID := "AKfycbPathB" + randHex(16)
	_ = os.MkdirAll(filepath.Join(rc.P.Run, googlePasteDir), 0o755)
	if !rc.R.Add("", phase, "verb.appsscript-script", Pass, got(sv.OK() && script.Code != "", Pass, Fail), sv.Tail(), nil, t0) {
		return
	}
	_ = os.WriteFile(filepath.Join(rc.P.Run, googlePasteDir, depID+".gs"), []byte(script.Code), 0o644)
	gb := &googleChan{url: "https://script.google.com/macros/s/" + depID + "/exec?k=" + pathToken, keyFile: keyFile, pathToken: pathToken}
	res, v = rc.googlePost(phase, "path-b", gb, docFile, rc.Pub.Path("base-g1.sbp"), keyFile, "")
	rc.R.Add("", phase, "path-b.same_state", Pass, got(v.OK() && res["ok"] == true && res["via_front"] == true, Pass, Fail), v.Tail()+" "+v.Stdout, res, t0)

	// 6. A web app nobody anonymous may run (deployed with the wrong access).
	t0 = time.Now()
	rc.googleKnobs(GoogleKnobs{SignInWall: true})
	res, _ = rc.googlePost(phase, "wall", g, docFile, "", keyFile, "")
	rc.googleKnobs(GoogleKnobs{})
	rc.R.Add("", phase, "sign_in_wall_named", Pass, got(res["reason"] == "not_deployed", Pass, Fail), fmt.Sprintf("reason=%v", res["reason"]), nil, t0)

	// The token appears in nothing the run kept.
	t0 = time.Now()
	tok, _ := os.ReadFile(filepath.Join(rc.P.Run, googleTokenFile))
	var where []string
	for _, f := range []string{"publisher-verbs.jsonl", googleReqFile} {
		if b, _ := os.ReadFile(filepath.Join(rc.P.Run, f)); len(tok) > 0 && strings.Contains(string(b), strings.TrimSpace(string(tok))) {
			where = append(where, f)
		}
	}
	rc.R.Add("", phase, "token_in_no_log", Pass, got(len(where) == 0, Pass, Fail), strings.Join(where, ", "), nil, t0)
}

// errorLine is the first stderr line the app branches on: the first that
// is not a --progress-json line.
func errorLine(stderr string) string {
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "{") {
			return l
		}
	}
	return ""
}

// olderDoc signs a document with a sequence below the newest one.
func (rc *RunCtx) olderDoc(phase string, fc *freshChannel, packID, sha string) (string, bool) {
	if freshSeq < 2 {
		return "", false
	}
	out := rc.Pub.Path("freshness-older.json")
	pubRaw, _ := os.ReadFile(rc.Pub.Path("publisher.pub"))
	v := rc.Pub.Deploy(rc.Ctx, "publish-freshness", "--relay-pack-id", packID, "--current-bundle-sha256", sha,
		"--current-signed-url", freshPackURL, "--publisher-pub-hex", hex.EncodeToString(pubRaw), "--root-priv-file", rc.Pub.Path("publisher.priv"),
		"--mirror", "r2="+freshMirrorR2, "--mirror", "ghpages="+freshMirrorGH, "--sequence", fmt.Sprint(freshSeq-1), "--out-file", out)
	return out, rc.R.Add("", phase, "verb.publish-freshness.older", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, time.Now())
}

// googleRecovery: a phone connected on a file whose mirror set holds the
// Google channel; the relay moves (move); the publisher announces on every
// mirror; the ordinary ones are cut (cutMirrors: here; otherwise by the
// scenario); the old address is null-routed under the phone. The engine
// must find the new address through the Google front, or end the way the
// scenario says (google_expect).
func (rc *RunCtx) googleRecovery(phase, oldIP string, move func() bool, standbyKey string) {
	g, ok := rc.googleChannel(phase)
	if !ok {
		return
	}
	rc.googleKnobs(GoogleKnobs{})
	fc, ok := rc.freshChannel(phase)
	if !ok {
		return
	}
	mirrors := append(append([]string{}, freshMirrorFlags...), "--freshness-mirror", "appsscript="+g.url)
	// The app publishes to the Google channel as one more backend of
	// publish-freshness (--appsscript-*); appsscript-check is its
	// fetch-back check. Use the app's path when the verb has it.
	viaPublish := (Prereq{Dir: "publisher/deploy/cli", Files: "cli.go", Pattern: regexp.MustCompile(`fs\.String\("appsscript-url"`)}).Present(rc.P.Repo)
	keyFor := map[string]string{}
	fc.extra = func(label string) []string {
		if !viaPublish {
			return nil
		}
		x := []string{"--appsscript-url", g.url, "--appsscript-write-key-file", g.keyFile, "--appsscript-pack-file", rc.Pub.Path("base-" + label + ".sbp")}
		if k := keyFor[label]; k != "" {
			kf := rc.Pub.Path("standby-key-" + label + ".txt")
			_ = os.WriteFile(kf, []byte(k), 0o600)
			x = append(x, "--appsscript-standby-key-file", kf)
		}
		return x
	}
	defer func() { fc.extra = nil }()
	announce := func(tag, key string) bool {
		// publish-freshness gets the 26 symbols; the form as printed is
		// asked of the channel separately below.
		keyFor[tag] = strings.ReplaceAll(key, " ", "")
		out := "base-" + tag + ".sbp"
		t0 := time.Now()
		v := rc.Pub.BindAndSign(rc.Ctx, out, mirrors...)
		var ans map[string]any
		_ = json.Unmarshal([]byte(v.Stdout), &ans)
		if !rc.R.Add("", phase, "verb.bind-and-sign."+tag, Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
			return false
		}
		packID, _ := ans["relay_pack_id"].(string)
		sha, _ := ans["sbp_sha256"].(string)
		var supersedes []string
		for i := len(fc.announced) - 1; i >= 0; i-- {
			if fc.announced[i] != packID {
				supersedes = append(supersedes, fc.announced[i])
			}
		}
		doc, ok := fc.publish(tag, packID, sha, rc.Pub.Path("publisher.priv"), supersedes)
		if !ok {
			return false
		}
		body, _ := os.ReadFile(rc.Pub.Path(out))
		_ = firstErr(fc.serveDoc(doc), fc.put(freshPackURL, body))
		fc.announced = append(fc.announced, packID)
		rc.FreshAnnounced = append(rc.FreshAnnounced, packID)
		t0 = time.Now()
		// What the app holds the key as is what `standby promote` printed
		// (grouped, with spaces); the channel must take it as it is.
		res, pv := rc.googlePost(phase, tag, g, rc.Pub.Path("freshness-"+tag+".json"), rc.Pub.Path(out), g.keyFile, key)
		if key != "" {
			rc.R.Add("", phase, "google.standby_key_as_printed_accepted", Pass, got(pv.OK() && res["ok"] == true, Pass, Fail),
				got(pv.OK(), "", "the Google channel refuses the standby key in the form `standby promote` prints it: "+oneLine(pv.Tail(), 200)), nil, t0)
			if !pv.OK() {
				res, pv = rc.googlePost(phase, tag+"-compact", g, rc.Pub.Path("freshness-"+tag+".json"), rc.Pub.Path(out), g.keyFile, strings.ReplaceAll(key, " ", ""))
			}
		}
		return rc.R.Add("", phase, "google.posted."+tag, Pass, got(pv.OK() && res["ok"] == true, Pass, Fail), pv.Tail()+" "+pv.Stdout,
			map[string]any{"result": res, "also_by_publish_freshness": viaPublish}, t0)
	}
	if !announce("gr-before", "") {
		return
	}
	t0 := time.Now()
	v := rc.Pub.PackSBP(rc.Ctx, "base-gr-before.sbp", "creds-r1.json", "pack-r1-gr-before.sbp")
	if !rc.R.Add("", phase, "verb.users-pack-sbp.gr-before", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
		return
	}
	hosts, err := rc.phoneHostsWithGoogle(fc.hosts)
	if err != nil {
		rc.R.Add("", phase, "phone.hosts", Pass, Fail, err.Error(), nil, t0)
		return
	}
	a := &autoOp{rc: rc, phase: phase}
	p := c0Phone(a, "google", rc.Pub.Path("pack-r1-gr-before.sbp"), ClientOpts{LivenessS: c0Liveness, RecheckS: c0Recheck, Hosts: hosts, CAFile: rc.P.CA(), EngineLog: true})
	if p == nil {
		return
	}
	defer p.stop()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		return
	}
	if !move() {
		return
	}
	if rec, err := rc.Pub.Record(); err == nil {
		rc.Rec = rec
	}
	if !announce("gr-after", standbyKey) {
		return
	}
	if rc.Scn.GoogleKnobs != nil {
		rc.googleKnobs(*rc.Scn.GoogleKnobs)
	}
	// The ordinary refresh hosts and the plain script address cut, unless
	// the scenario cuts them by name already.
	if len(rc.Scn.Censor.DPI) == 0 {
		rule := "add table inet wb_op_gr; add chain inet wb_op_gr f { type filter hook forward priority -6; }; " +
			"add rule inet wb_op_gr f ip daddr { " + StorageIP + ", " + GoogleScriptIP + " } drop"
		if _, err := sh(rc.Ctx, inNS(NSCensor, "nft", rule)...); err != nil {
			rc.R.Add("", phase, "censor.cuts_mirrors", Pass, Fail, err.Error(), nil, t0)
			return
		}
		defer sh(rc.Ctx, inNS(NSCensor, "nft", "delete", "table", "inet", "wb_op_gr")...)
	}
	googleBefore := len(GoogleRequests(rc.P.Run))
	t0 = time.Now()
	if err := c0BlockWith(rc, oldIP, false); err != nil {
		rc.R.Add("", phase, "censor.blocks_old_address", Blocked, Fail, err.Error(), nil, t0)
		return
	}
	defer c0Unblock(rc)
	expect := rc.Scn.GoogleExpect
	if expect == "" {
		expect = "recovered"
	}
	d, states, done := c0WaitFor(p, "google", t0, func(diag, blk, rec map[string]any) bool {
		if expect == "recovered" {
			return blk["state"] == "connected" && rec["state"] == "updated" && diag["route_check"] == "ok"
		}
		return rec["state"] != "idle" && rec["state"] != "looking" && blk["state"] != "connected"
	})
	diag, _ := d["diag"].(map[string]any)
	rec := c0Recovery(diag)
	ev := map[string]any{"seen": strings.Join(states, " → "), "relay_recovery": rec, "expect": expect}
	switch expect {
	case "recovered":
		p.add("google", "", "found_the_new_address_through_google", Pass, got(done, Pass, Blocked), got(done, "", "not connected again (seen: "+strings.Join(states, " → ")+")"), ev, t0)
		if done {
			if fam, _ := autoBlock(diag)["family"].(string); fam != "" {
				if f, ok := rc.Fams[fam]; ok {
					p.sw.carries("google", f, t0)
				}
			}
		}
	default:
		ok := done && autoBlock(diag)["state"] != "connected"
		p.add("google", "", "ended_"+expect, Pass, got(ok, Pass, Fail), "seen: "+strings.Join(states, " → "), ev, t0)
	}
	var viaFront, plain, webapp int
	for _, q := range GoogleRequests(rc.P.Run)[googleBefore:] {
		if !strings.HasPrefix(q.From, ClientIP+":") {
			continue
		}
		if q.Part == "webapp" {
			webapp++
		}
		if q.SNI == "www.google.com" && (q.Host == "script.google.com" || q.Host == "script.googleusercontent.com") {
			viaFront++
		}
		if q.SNI == "script.google.com" {
			plain++
		}
	}
	gev := map[string]any{"via_front": viaFront, "plain": plain, "webapp_requests": webapp}
	if expect == "recovered" {
		p.add("google", "", "fetched_through_the_front", Pass, got(viaFront >= 2, Pass, Fail), fmt.Sprintf("%+v", gev), gev, t0)
	}
	p.add("google", "", "at_most_two_connections_per_walk", Pass, got(webapp <= 2, Pass, Fail), fmt.Sprintf("%+v", gev), gev, t0)
}

func opGoogleRefresh(rc *RunCtx) {
	const phase = "op:google-refresh"
	if caps, _, _, _ := rc.Health(); !contains(caps, "bind-address") {
		rc.R.Add("", phase, "google-refresh", Skipped, Skipped, "the relay cannot move to a new address (run with --mgmt=tree)", nil, time.Now())
		return
	}
	if (&autoOp{rc: rc}).scenarioBlocks() {
		rc.R.Add("", phase, "google-refresh", Skipped, Skipped, "the scenario blocks a family; this op needs a phone that can connect first", nil, time.Now())
		return
	}
	if rc.waitsOn(phase, "google-refresh", PreGoogleMirror, PreFrontFetch) {
		return
	}
	oldIP := rc.Rec.PublicIP
	moved := false
	defer func() {
		if moved {
			rc.standbyRestore(phase, oldIP)
		}
	}()
	rc.googleRecovery(phase, oldIP, func() bool {
		t0 := time.Now()
		v := rc.Pub.AssignFIP(rc.Ctx)
		moved = v.OK()
		rc.MgmtWindowClosed(phase)
		return rc.R.Add("", phase, "verb.assign-fip", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0)
	}, "")
}
