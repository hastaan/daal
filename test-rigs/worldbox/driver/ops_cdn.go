package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Add-on 2, the way in through Cloudflare (docs/optional-addons-plan.md
// §2, item B-8), from both seats.
//
//	cdn-provision  the publisher's whole side against the lab's Cloudflare
//	               (fakecf_api.go) and Hetzner: the token check's verdicts
//	               for exactly-right, too-broad (more permissions; more
//	               zones), short and dead tokens; a provision whose origin
//	               rule fails half way leaves nothing behind; a provision
//	               that works leaves exactly the zone state the edge needs
//	               (proxied record, Full (strict), WebSockets, origin pull
//	               with this front's own certificate, the port override)
//	               and the relay firewall open on the door's port to the
//	               published ranges only; the published ECH config is in
//	               the record; posture; a real WebSocket handshake through
//	               the edge with ECH (once the relay's door can be opened);
//	               removal leaves the zone as it was. The token is in no log.
//	cdn            a phone whose file carries the CDN route, under the
//	               scenario (scenarios/cdn-*.json): the route carries where
//	               the scenario says (`cdn.expect`), on an edge the scenario
//	               leaves open (`cdn.via`), and the zone's name never shows
//	               in a plain hello (owner decision D-2).
//
// The relay's door (daal-relay-mgmt /cdn) and everything on the
// recipient's side are being built in this wave (L-glue; L-ladder B-4,
// B-6, B-6b): what needs them records SKIPPED naming the missing piece
// (addons_net.go Prereq) and runs by itself once it is in the tree.

func init() {
	Ops["cdn-provision"] = opCDNProvision
	Ops["cdn"] = opCDN
}

// cdnTokens writes the account's tokens and returns the file holding each.
func (rc *RunCtx) cdnTokens() map[string]string {
	toks := []CFToken{
		{ID: "tokgood", Status: "active", Zones: []string{CDNZone}, Perms: CFFiveTokenPerms},
		{ID: "tokbroad", Status: "active", Zones: []string{CDNZone}, Perms: append(append([]string{}, CFFiveTokenPerms...), "workers_scripts", "user_details")},
		{ID: "toktwozones", Status: "active", Zones: []string{CDNZone, "otherzone.example"}, Perms: CFFiveTokenPerms},
		{ID: "tokshort", Status: "active", Zones: []string{CDNZone}, Perms: CFFiveTokenPerms[:4]},
		{ID: "tokdead", Status: "disabled", Zones: []string{CDNZone}, Perms: CFFiveTokenPerms},
	}
	files := map[string]string{}
	for i := range toks {
		toks[i].Token = "cfwb_" + randHex(20)
		f := rc.Pub.Path("cf-" + toks[i].ID + ".token")
		_ = os.WriteFile(f, []byte(toks[i].Token+"\n"), 0o600)
		files[toks[i].ID] = f
	}
	body, _ := json.MarshalIndent(toks, "", "  ")
	_ = os.WriteFile(filepath.Join(rc.P.Run, cfTokensFile), body, 0o600)
	return files
}

func (rc *RunCtx) cfFaults(fs []CFFault) {
	body, _ := json.Marshal(fs)
	_ = os.WriteFile(filepath.Join(rc.P.Run, cfFaultsFile), body, 0o644)
}

// relayFirewallID is the relay's own firewall, as provisioning made it.
func (rc *RunCtx) relayFirewallID() string {
	sid, _ := strconv.ParseInt(rc.Rec.ServerID, 10, 64)
	for _, f := range CloudFirewalls(rc.P) {
		for _, s := range f.Servers {
			if s == sid {
				return strconv.FormatInt(f.ID, 10)
			}
		}
	}
	return ""
}

// cdnDoor opens or closes the relay's door the way the app does:
// cdn-door through the relay's management, with the publisher's key.
func (rc *RunCtx) cdnDoor(recFile, action string) Verb {
	return rc.Pub.Deploy(rc.Ctx, "cdn-door", "--record-file", recFile, "--operator-record", rc.Pub.Path("record.json"),
		"--token-file", rc.Pub.Path("cloud.token"), "--action", action,
		"--priv-key", rc.Pub.Path("publisher.priv"), "--helper-ip", PublisherIP)
}

// cdnRemove is cdn-remove as the CLI takes it with the relay's door:
// the door is closed first, then Cloudflare and the firewall rule.
func (rc *RunCtx) cdnRemove(recFile, tokFile string) Verb {
	return rc.Pub.Deploy(rc.Ctx, "cdn-remove", "--record-file", recFile, "--token-file", tokFile,
		"--hetzner-token-file", rc.Pub.Path("cloud.token"), "--operator-record", rc.Pub.Path("record.json"),
		"--priv-key", rc.Pub.Path("publisher.priv"), "--helper-ip", PublisherIP)
}

// cdnZoneClean: nothing the add-on makes is left in the zone.
func cdnZoneClean(st *CFState) []string {
	var left []string
	if st == nil {
		return []string{"no state"}
	}
	z := st.ZoneFor(CDNHost)
	if z == nil {
		return []string{"zone gone"}
	}
	if len(z.Records) > 0 {
		left = append(left, fmt.Sprintf("%d dns record(s)", len(z.Records)))
	}
	if len(z.AOPCerts) > 0 {
		left = append(left, fmt.Sprintf("%d origin-pull certificate(s)", len(z.AOPCerts)))
	}
	if z.AOPEnabled {
		left = append(left, "origin pull still on")
	}
	if len(z.OriginRules) > 0 {
		left = append(left, fmt.Sprintf("%d origin rule(s)", len(z.OriginRules)))
	}
	if z.Settings["ssl"] != "flexible" {
		left = append(left, "ssl="+z.Settings["ssl"]+" (it was flexible)")
	}
	for _, c := range st.Certs {
		if !c.Revoked {
			left = append(left, "origin certificate "+c.ID+" not revoked")
		}
	}
	return left
}

// cdnProvision builds the front with the good token and returns the
// record file; the checks of what it left are recorded.
func (rc *RunCtx) cdnProvision(phase string, tok map[string]string) (string, bool) {
	fw := rc.relayFirewallID()
	t0 := time.Now()
	if !rc.R.Add("", phase, "relay_firewall_known", Pass, got(fw != "", Pass, Fail), "no firewall is applied to the relay's server", nil, t0) {
		return "", false
	}
	out := rc.Pub.Path("cdn-front")
	recFile := rc.Pub.Path("cdn-front.json")
	v := rc.Pub.Deploy(rc.Ctx, "cdn-provision", "--hostname", CDNHost, "--origin-ip", rc.Rec.PublicIP, "--out-dir", out,
		"--cf-token-file", tok["tokgood"], "--token-file", rc.Pub.Path("cloud.token"), "--firewall-id", fw, "--progress-json")
	if !rc.R.Add("", phase, "verb.cdn-provision", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
		return "", false
	}
	_ = os.WriteFile(recFile, []byte(v.Stdout), 0o600)
	var rec struct {
		Hostname, ZoneID, OriginPath string
		OriginPort                   int  `json:"origin_port"`
		AOPEnabled                   bool `json:"aop_enabled"`
		ECH                          struct {
			ZoneSetting   string `json:"zone_setting"`
			Published     bool   `json:"published"`
			ConfigListB64 string `json:"config_list_b64"`
		} `json:"ech"`
	}
	_ = json.Unmarshal([]byte(v.Stdout), &rec)
	st, _ := LoadCFState(rc.P.Run)
	var wrong []string
	if z := st.ZoneFor(CDNHost); z == nil {
		wrong = append(wrong, "no zone")
	} else {
		r, ok := z.Proxied(CDNHost)
		switch {
		case !ok:
			wrong = append(wrong, "no proxied A record for "+CDNHost)
		case r.Content != rc.Rec.PublicIP:
			wrong = append(wrong, "the record points at "+r.Content)
		}
		if z.Settings["ssl"] != "strict" {
			wrong = append(wrong, "ssl="+z.Settings["ssl"])
		}
		if z.Settings["websockets"] != "on" {
			wrong = append(wrong, "websockets off")
		}
		if !z.AOPEnabled || len(z.AOPCerts) != 1 {
			wrong = append(wrong, fmt.Sprintf("origin pull on=%v with %d certificate(s)", z.AOPEnabled, len(z.AOPCerts)))
		}
		if p := z.OriginPort(CDNHost); p != rec.OriginPort || p != 8448 {
			wrong = append(wrong, fmt.Sprintf("origin rule port %d (record says %d)", p, rec.OriginPort))
		}
	}
	rc.R.Add("", phase, "zone.as_the_edge_needs_it", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), nil, t0)
	list, _, _, _ := LabECH(rc.P.Run)
	gotECH := rec.ECH.ConfigListB64 == base64.StdEncoding.EncodeToString(list) && rec.ECH.Published
	rc.R.Add("", phase, "ech.published_config_read", Pass, got(gotECH, Pass, Fail),
		got(gotECH, "", fmt.Sprintf("the record's ECH config is not the one the zone publishes over DoH (published=%v setting=%q)", rec.ECH.Published, rec.ECH.ZoneSetting)), nil, t0)
	// The relay firewall: the door's port from the published ranges only.
	var srcs []string
	open := false
	for _, f := range CloudFirewalls(rc.P) {
		if strconv.FormatInt(f.ID, 10) != fw {
			continue
		}
		for _, r := range f.Rules {
			if r.Port != nil && *r.Port == "8448" {
				open = true
				for _, s := range r.SourceIPs {
					srcs = append(srcs, s)
					if s == "0.0.0.0/0" || s == "::/0" {
						open = false
					}
				}
			}
		}
	}
	want := append(append([]string{}, CDNPublishedV4...), "2001:db8:cf00::/40")
	same := open && len(srcs) == len(want)
	for _, s := range want {
		same = same && contains(srcs, s)
	}
	rc.R.Add("", phase, "firewall.door_open_to_published_ranges_only", Pass, got(same, Pass, Fail),
		fmt.Sprintf("8448/tcp sources: %v", srcs), nil, t0)

	// The relay's door, as the app opens it (cdn-door), once the verb
	// is in the tree.
	if PreCDNDoorCall.Present(rc.P.Repo) {
		t0 = time.Now()
		v := rc.cdnDoor(recFile, "enable")
		rc.R.Add("", phase, "verb.cdn-door.enable", Pass, got(v.OK(), Pass, Fail), v.Tail()+" "+oneLine(v.Stdout, 200), nil, t0)
		// The relay opened its own box firewall to the same ranges:
		// provisioning fetched none.
		ufw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_ufw")...)
		boxOK := true
		for _, s := range CDNPublishedV4 {
			boxOK = boxOK && strings.Contains(ufw, s)
		}
		rc.R.Add("", phase, "door.box_firewall_open_to_published_ranges", Pass, got(boxOK && nftAllows(ufw, "tcp", 8448), Pass, Fail),
			oneLine(ufw, 400), nil, t0)
	}
	return recFile, true
}

func opCDNProvision(rc *RunCtx) {
	const phase = "op:cdn-provision"
	t0 := time.Now()
	if err := rc.BringUpCDN(); err != nil {
		rc.R.Add("", phase, "cdn.up", Pass, Fail, err.Error(), nil, t0)
		return
	}
	tok := rc.cdnTokens()

	// 1. The token check (plan §2.3 step 3).
	for _, c := range []struct{ id, want string }{{"tokgood", "ok"}, {"tokbroad", "too_broad"}, {"toktwozones", "too_broad"},
		{"tokshort", "missing_permission"}, {"tokdead", "invalid"}} {
		t0 = time.Now()
		v := rc.Pub.Deploy(rc.Ctx, "cdn-token-check", "--token-file", tok[c.id], "--zone", CDNZone)
		var ans struct {
			Verdict string   `json:"verdict"`
			Extra   []string `json:"extra"`
			Missing []string `json:"missing"`
		}
		_ = json.Unmarshal([]byte(v.Stdout), &ans)
		rcWant := 0
		if c.want != "ok" {
			rcWant = 4
		}
		ok := ans.Verdict == c.want && v.RC == rcWant
		rc.R.Add("", phase, "token-check."+c.id, Pass, got(ok, Pass, Fail),
			got(ok, "", fmt.Sprintf("verdict %q rc %d, want %q rc %d: %s", ans.Verdict, v.RC, c.want, rcWant, v.Tail())),
			map[string]any{"verdict": ans.Verdict, "extra": ans.Extra, "missing": ans.Missing}, t0)
	}

	// 2. A provision that fails at the origin rule leaves nothing.
	t0 = time.Now()
	fw := rc.relayFirewallID()
	rc.cfFaults([]CFFault{{Method: "PUT", Path: `/rulesets/phases/http_request_origin/entrypoint$`, Status: 500, Times: 1}})
	v := rc.Pub.Deploy(rc.Ctx, "cdn-provision", "--hostname", CDNHost, "--origin-ip", rc.Rec.PublicIP, "--out-dir", rc.Pub.Path("cdn-front-failed"),
		"--cf-token-file", tok["tokgood"], "--token-file", rc.Pub.Path("cloud.token"), "--firewall-id", fw)
	rc.cfFaults(nil)
	st, _ := LoadCFState(rc.P.Run)
	left := cdnZoneClean(st)
	rc.R.Add("", phase, "rollback.failed_provision_left_nothing", Pass, got(!v.OK() && len(left) == 0, Pass, Fail),
		fmt.Sprintf("rc=%d left: %s — %s", v.RC, strings.Join(left, "; "), v.Tail()), nil, t0)

	// 3. The provision that works.
	recFile, ok := rc.cdnProvision(phase, tok)
	if !ok {
		return
	}
	// 4. Posture.
	t0 = time.Now()
	v = rc.Pub.Deploy(rc.Ctx, "cdn-posture", "--record-file", recFile, "--token-file", tok["tokgood"], "--hetzner-token-file", rc.Pub.Path("cloud.token"))
	var post map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &post)
	rc.R.Add("", phase, "posture.name_hidden_and_only_cloudflare", Pass, got(post["name_hidden"] == true && post["only_cloudflare"] == true, Pass, Fail),
		v.Tail(), map[string]any{"name_hidden": post["name_hidden"], "only_cloudflare": post["only_cloudflare"], "ssl_strict": post["ssl_strict"]}, t0)

	// 5. Through the edge, with ECH, to the relay's door.
	rc.cdnTest(phase, recFile)

	// 6. Removal.
	t0 = time.Now()
	v = rc.cdnRemove(recFile, tok["tokgood"])
	st, _ = LoadCFState(rc.P.Run)
	left = cdnZoneClean(st)
	rc.R.Add("", phase, "removed.zone_as_it_was", Pass, got(v.OK() && len(left) == 0, Pass, Fail), strings.Join(left, "; ")+" "+v.Tail(), nil, t0)
	if PreCDNDoorCall.Present(rc.P.Repo) {
		ufw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_ufw")...)
		rc.R.Add("", phase, "removed.door_closed", Pass, got(!rc.cdnDoorOpen() && !nftAllows(ufw, "tcp", 8448), Pass, Fail),
			fmt.Sprintf("ws-cdn-in served=%v, box firewall admits 8448=%v", rc.cdnDoorOpen(), nftAllows(ufw, "tcp", 8448)), nil, t0)
	}
	closed := true
	for _, f := range CloudFirewalls(rc.P) {
		for _, r := range f.Rules {
			if r.Port != nil && *r.Port == "8448" {
				closed = false
			}
		}
	}
	rc.R.Add("", phase, "removed.firewall_rule_closed", Pass, got(closed, Pass, Fail), "", nil, t0)

	// The token is in nothing the run kept.
	t0 = time.Now()
	var where []string
	for id, f := range tok {
		raw, _ := os.ReadFile(f)
		secret := strings.TrimSpace(string(raw))
		for _, logf := range []string{"publisher-verbs.jsonl", cfReqFile, cfStateFile, cdnReqFile} {
			if b, _ := os.ReadFile(filepath.Join(rc.P.Run, logf)); strings.Contains(string(b), secret) {
				where = append(where, id+" in "+logf)
			}
		}
	}
	rc.R.Add("", phase, "token_in_no_log", Pass, got(len(where) == 0, Pass, Fail), strings.Join(where, ", "), nil, t0)
}

// cdnDoorOpen: the relay serves ws-cdn-in.
func (rc *RunCtx) cdnDoorOpen() bool {
	return strings.Contains(rc.BoxSingboxConfig(), `"ws-cdn-in"`)
}

// cdnTest: one real WebSocket handshake through an edge with ECH, which
// needs the relay's door open.
func (rc *RunCtx) cdnTest(phase, recFile string) {
	t0 := time.Now()
	if !rc.cdnDoorOpen() {
		if rc.waitsOn(phase, "front-test", PreCDNDoorCall) {
			return
		}
		rc.R.Add("", phase, "front-test.door_open", Pass, Fail, "cdn-door ran and the relay serves no ws-cdn-in inbound", nil, t0)
		return
	}
	before := len(CDNRequests(rc.P.Run))
	v := rc.Pub.Deploy(rc.Ctx, "cdn-test", "--record-file", recFile, "--edge", CDNEdgeA+":443", "--require-ech")
	var res map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &res)
	rc.R.Add("", phase, "front-test.websocket_through_the_edge_with_ech", Pass, got(v.OK() && res["ech_accepted"] == true, Pass, Fail), v.Tail()+" "+v.Stdout, res, t0)
	var seen []string
	for _, q := range CDNRequests(rc.P.Run)[before:] {
		seen = append(seen, fmt.Sprintf("%s ech=%v %d %s", q.Edge, q.ECH, q.Status, q.OriginState))
	}
	rc.R.Add("", phase, "front-test.edge_pulled_with_origin_pull_cert", Pass, got(strings.Contains(strings.Join(seen, ","), "tls_strict+aop"), Pass, Fail),
		strings.Join(seen, "; "), nil, t0)
	// The door refuses anyone without this front's origin-pull
	// certificate, even from inside Cloudflare's ranges.
	t0 = time.Now()
	out, err := sh(rc.Ctx, inNS(NSCDN, "timeout", "5", "openssl", "s_client", "-connect", rc.Rec.PublicIP+":8448", "-bind", CDNOriginPull, "-brief")...)
	refused := err != nil || strings.Contains(out, "alert") || !strings.Contains(out, "CONNECTION ESTABLISHED")
	rc.R.Add("", phase, "door.refuses_without_origin_pull_cert", Pass, got(refused, Pass, Fail), oneLine(out, 300), nil, t0)
}

// opCDN: a recipient whose file carries the CDN route, under the scenario.
func opCDN(rc *RunCtx) {
	const phase = "op:cdn"
	t0 := time.Now()
	if err := rc.BringUpCDN(); err != nil {
		rc.R.Add("", phase, "cdn.up", Pass, Fail, err.Error(), nil, t0)
		return
	}
	if rc.waitsOn(phase, "cdn-route", PreCDNBind, PreCDNMint, PreCDNLabRoots, PreCDNDoorCall, PreEdgePick, PreCDNLadder) {
		return
	}
	tok := rc.cdnTokens()
	recFile, ok := rc.cdnProvision(phase, tok)
	if !ok {
		return
	}
	defer rc.cdnRemove(recFile, tok["tokgood"])
	if !rc.cdnDoorOpen() {
		rc.R.Add("", phase, "door_open", Pass, Fail, "the relay serves no ws-cdn-in inbound after cdn-door", nil, t0)
		return
	}
	t0 = time.Now()
	// The seeds are the published prefixes; the roots are the ones the
	// lab's edge chains to (the lab CA stands in for the public roots the
	// app ships, as it does for every other lab TLS server).
	cdnSign := []string{"--cdn-front", recFile, "--cdn-edge-seeds", strings.Join(CDNPublishedV4, ","), "--cdn-roots-file", rc.P.CA()}
	v := rc.Pub.BindAndSign(rc.Ctx, "base-cdn.sbp", cdnSign...)
	if !rc.R.Add("", phase, "verb.bind-and-sign.with-cdn", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
		return
	}
	_ = rc.Pub.UsersRevoke(rc.Ctx, "r1")
	if vp := rc.Pub.UsersProvision(rc.Ctx, "r1"); !rc.R.Add("", phase, "verb.users-provision.r1", Pass, got(vp.OK(), Pass, Fail), vp.Tail(), nil, t0) {
		return
	}
	// r1 is this relay's only recipient: the revoke took the shadowsocks
	// server key with it and the provision minted a new one. The app signs
	// again on such a reply before it builds a file (heal_after_reply), so
	// the rig does too — with the CDN flags, since that is the pack r1's
	// file is minted from.
	if !rc.healAfterReply(phase, "r1", "base-cdn.sbp", cdnSign...) {
		return
	}
	vp := rc.Pub.PackSBP(rc.Ctx, "base-cdn.sbp", "creds-r1.json", "pack-r1-cdn.sbp", "--cdn-roots-file", rc.P.CA(), "--cdn-front", recFile)
	if !rc.R.Add("", phase, "verb.users-pack-sbp.cdn", Pass, got(vp.OK(), Pass, Fail), vp.Tail(), nil, t0) {
		return
	}
	pack := rc.Pub.Path("pack-r1-cdn.sbp")
	cdnRouteInPack := false
	if routes, _, err := packManifest(pack); err == nil {
		for _, r := range routes {
			cdnRouteInPack = cdnRouteInPack || strings.Contains(string(r.FSC), `"_cdn_endpoint"`)
		}
	}
	if !rc.R.Add("", phase, "pack.carries_the_cdn_route", Pass, got(cdnRouteInPack, Pass, Fail), "", nil, t0) {
		return
	}
	want := Pass
	var via []string
	if rc.Scn.CDN != nil {
		if rc.Scn.CDN.Expect != "" {
			want = rc.Scn.CDN.Expect
		}
		via = rc.Scn.CDN.Via
	}
	// The CDN route is tried last (plan §4), so it can only be the one
	// that carries when the direct routes cannot. A scenario that models
	// only Cloudflare's side (edges, the zone's name) leaves the relay's
	// own address open: take it out of the way for this phone, the way
	// the burned address the add-on exists for would.
	if rc.tcpFromClient(rc.Rec.PublicIP, 443) {
		t0 = time.Now()
		err := c0BlockWith(rc, rc.Rec.PublicIP, false)
		ok := err == nil && !rc.tcpFromClient(rc.Rec.PublicIP, 443)
		if !rc.R.Add("", phase, "direct_routes_out_of_the_way", Pass, got(ok, Pass, Fail),
			fmt.Sprintf("the relay's own address null-routed for this phone (err %v)", err), nil, t0) {
			return
		}
		defer func() { _ = c0Unblock(rc) }()
	}
	a := &autoOp{rc: rc, phase: phase}
	saved := rc.Pack
	rc.Pack = pack
	p := a.start("cdn", ClientOpts{EngineLog: true})
	rc.Pack = saved
	if p == nil {
		return
	}
	defer p.stop()
	before := len(CDNRequests(rc.P.Run))
	dpiBefore := dpiEventsFor(rc.P, CDNHost)
	t0 = time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil {
		return
	}
	onCDN := x.connected && x.family == "websocket-tls" && len(CDNRequests(rc.P.Run)) > before
	p.add("connect", x.family, "cdn_route", want, got(onCDN, Pass, Blocked), "tried: "+x.triedText(), x.evidence(), t0)
	if onCDN {
		p.sw.viaEdge = true
		p.connectedOn("connect", x, t0)
		var edges []string
		okEdge := len(via) == 0
		for _, q := range CDNRequests(rc.P.Run)[before:] {
			if q.Status == 101 {
				edges = append(edges, q.Edge)
				for _, v := range via {
					if addrIn(q.Edge, substVars(v, scenarioVars(""))) {
						okEdge = true
					}
				}
				if !q.ECH {
					p.add("connect", x.family, "ech_used", Pass, Fail, "a session reached the edge without ECH", nil, t0)
				}
			}
		}
		p.add("connect", x.family, "carried_on_an_open_edge", Pass, got(okEdge, Pass, Fail), fmt.Sprintf("edges that carried: %v; open: %v", edges, via), nil, t0)
	}
	// D-2: the zone's name is never in a plain hello.
	shown := dpiEventsFor(rc.P, CDNHost) - dpiBefore
	p.add("connect", "", "zone_name_never_in_a_plain_hello", Pass, got(shown == 0, Pass, Fail), fmt.Sprintf("censor saw the zone name in %d hello(s)", shown), nil, t0)
}

// dpiEventsFor counts the censor's fired rules that read sni.
func dpiEventsFor(p Paths, sni string) int {
	body, _ := os.ReadFile(filepath.Join(p.Run, "dpi-events.jsonl"))
	return strings.Count(string(body), `"sni":"`+sni+`"`)
}

// addrIn: addr equals target, or lies in target when it is a prefix.
func addrIn(addr, target string) bool {
	var ip [4]byte
	parts := strings.Split(addr, ".")
	if len(parts) != 4 {
		return false
	}
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil {
			return false
		}
		ip[i] = byte(n)
	}
	return dstMatches(target, ip)
}
