package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// Add-on 1, the standby address (docs/optional-addons-plan.md §1,
// specs/optional-addons-v1.md §3), from both seats.
//
// The publisher's half is the real `daal-deploy standby add | promote |
// remove` against the lab cloud, which models Floating IPs as routing
// (fakecloud_fip.go), and the real box binding the address WITHOUT
// adopting it. The recipient's half is the real engine. Ops:
//
//	standby          rent → bind → sign: every eligible route carries a
//	                 sealed commitment, the address is nowhere in the
//	                 pack, the box answers on it, a phone imports and
//	                 connects; then remove: nothing left billing.
//	standby-promote  a phone CONNECTED on a file with a sealed standby;
//	                 the publisher taps "Switch to standby" (re-signed
//	                 with the standby as the endpoint, published through
//	                 freshness) and the censor null-routes the primary
//	                 under the phone: the engine walks the mirrors once
//	                 and reconnects on the standby, with no new file.
//	                 Needs nothing new in the engine (the C0 walk).
//	standby-sealed   the same phone, nobody switches: the primary dies
//	                 and NO key arrives — the phone never dials the
//	                 standby and the address is in nothing it says; then
//	                 the person types the 26-character key and the phone
//	                 reconnects on the standby (engine_standby_key; a
//	                 wrong key and a malformed one are refused).
//	standby-open     open mode: the primary dies under a connected phone
//	                 and the engine moves to the standby by itself with
//	                 zero fetches (the connect ladder's address variant).
//	standby-stale    open mode, the publisher released the address and
//	                 the provider gave it to a stranger: the variant must
//	                 fail closed, nothing carried.
//	standby-google   sealed; the ordinary refresh addresses are cut; the
//	                 publisher switches, and the Google channel carries
//	                 the re-signed pack and the standby key.
//
// The parts that need engine code still landing (add-ons wave 2: L-ladder
// S7 and SaveImport, L-fetch G4/G5) record one SKIPPED line each naming
// what they wait on (addons_net.go Prereq) and turn on by themselves when
// it is in the tree.

func init() {
	Ops["standby"] = opStandby
	Ops["standby-promote"] = opStandbyPromote
	Ops["standby-sealed"] = opStandbySealed
	Ops["standby-open"] = opStandbyOpen
	Ops["standby-stale"] = opStandbyStale
	Ops["standby-google"] = opStandbyGoogle
}

// standbyOut is the stdout of every `standby` verb.
type standbyOut struct {
	Record            json.RawMessage `json:"record"`
	FloatingIPID      string          `json:"floating_ip_id"`
	Mode              string          `json:"mode"`
	Created           bool            `json:"created"`
	Adopted           bool            `json:"adopted"`
	Key               string          `json:"key"`
	PriorFloatingIPID string          `json:"prior_floating_ip_id"`
	PriorAddress      string          `json:"prior_address"`
	Released          []string        `json:"released"`
	StillBilling      []any           `json:"still_billing"`
	Warnings          []string        `json:"warnings"`
}

type standbyRec struct {
	PublicIP     string `json:"public_ip"`
	FloatingIPID string `json:"floating_ip_id"`
	Standby      *struct {
		FloatingIPID string `json:"floating_ip_id"`
		IP           string `json:"ip"`
		Mode         string `json:"mode"`
	} `json:"standby"`
}

// standbyVerb runs one `standby <sub>` verb as the wizard does and, as
// the wizard does, keeps the record it answers with. The key it may
// carry stays in memory: it is never in a check's detail or evidence.
func (rc *RunCtx) standbyVerb(phase, sub string, extra ...string) (standbyOut, bool) {
	args := []string{"standby", sub, "--record-file", rc.Pub.Path("record.json"), "--token-file", rc.Pub.Path("cloud.token")}
	if sub == "add" || sub == "remove" {
		args = append(args, "--priv-key", rc.Pub.Path("publisher.priv"), "--helper-ip", PublisherIP)
	}
	t0 := time.Now()
	v := rc.Pub.Deploy(rc.Ctx, append(args, extra...)...)
	var out standbyOut
	_ = json.Unmarshal([]byte(v.Stdout), &out)
	ok := rc.R.Add("", phase, "verb.standby-"+sub, Pass, got(v.OK(), Pass, Fail), v.Tail(),
		map[string]any{"rc": v.RC, "mode": out.Mode, "created": out.Created, "adopted": out.Adopted, "key_chars": len(out.Key),
			"released": out.Released, "warnings": out.Warnings}, t0)
	if len(out.Record) > 2 {
		if err := os.WriteFile(rc.Pub.Path("record.json"), out.Record, 0o600); err != nil {
			rc.R.Add("", phase, "record.saved", Pass, Fail, err.Error(), nil, t0)
		}
		if rec, err := rc.Pub.Record(); err == nil {
			rc.Rec = rec
		}
	}
	rc.MgmtWindowClosed(phase)
	return out, ok
}

func (rc *RunCtx) standbyRecord() standbyRec {
	var r standbyRec
	body, _ := os.ReadFile(rc.Pub.Path("record.json"))
	_ = json.Unmarshal(body, &r)
	return r
}

// packRoute is one route of a signed pack's manifest.
type packRoute struct {
	ID     string          `json:"id"`
	Family string          `json:"transport_family"`
	FSC    json.RawMessage `json:"family_specific_config"`
}

func packManifest(path string) (routes []packRoute, files map[string][]byte, err error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, err
	}
	defer zr.Close()
	files = map[string][]byte{}
	for _, f := range zr.File {
		rd, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rd, 8<<20))
		rd.Close()
		files[f.Name] = b
	}
	var man struct {
		Routes []packRoute `json:"routes"`
	}
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		return nil, files, err
	}
	return man.Routes, files, nil
}

// standbyInPack asserts what a signed pack says about the standby:
// every route but shadowsocks carries `_standby` in the given mode; in
// sealed mode the commitment matches the key and the address is in no
// byte of the file.
func (rc *RunCtx) standbyInPack(phase, label, path, mode, addr string, key *bundle.StandbyKeyBytes) bool {
	t0 := time.Now()
	routes, files, err := packManifest(path)
	if err != nil {
		return rc.R.Add("", phase, label+".pack_readable", Pass, Fail, err.Error(), nil, t0)
	}
	var wrong []string
	carried := 0
	for _, r := range routes {
		sb, perr := bundle.ParseStandby(r.FSC)
		if r.Family == string(bundle.TransportShadowsocks) {
			if sb != nil {
				wrong = append(wrong, r.ID+" (shadowsocks) carries _standby: a stale one would hand the traffic to whoever holds the address")
			}
			continue
		}
		if perr != nil || sb == nil {
			wrong = append(wrong, fmt.Sprintf("%s (%s) carries no usable _standby (%v)", r.ID, r.Family, perr))
			continue
		}
		carried++
		if sb.Mode != mode {
			wrong = append(wrong, fmt.Sprintf("%s: mode %q, want %q", r.ID, sb.Mode, mode))
		}
		if mode == "sealed" && key != nil && !sb.Matches(*key) {
			wrong = append(wrong, r.ID+": the commitment does not match the key the verb printed")
		}
		if mode == "open" && sb.Server != addr {
			wrong = append(wrong, fmt.Sprintf("%s: open standby %q, want %q", r.ID, sb.Server, addr))
		}
	}
	ok := rc.R.Add("", phase, label+".every_route_carries_it", Pass, got(len(wrong) == 0 && carried > 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"routes": len(routes), "carrying": carried, "mode": mode}, t0)
	if mode == "sealed" {
		var where []string
		for name, b := range files {
			if bytes.Contains(b, []byte(addr)) {
				where = append(where, name)
			}
		}
		ok = rc.R.Add("", phase, label+".address_in_no_byte_of_the_pack", Pass, got(len(where) == 0, Pass, Fail),
			got(len(where) == 0, "", "a sealed standby's address is written in "+strings.Join(where, ", ")), map[string]any{"files": len(files)}, t0) && ok
	}
	return ok
}

var standbyKeyText = regexp.MustCompile(`^[0-9A-Z]{5,6}(-[0-9A-Z]{4,6}){3,5}$`)

// standbyAdd rents and binds a standby, checks the publisher's and the
// box's side of it, and returns its address and key.
func (rc *RunCtx) standbyAdd(phase, mode string) (addr string, key *bundle.StandbyKeyBytes, keyText string, ok bool) {
	before := rc.standbyRecord()
	out, ok := rc.standbyVerb(phase, "add", "--mode", mode)
	if !ok {
		return "", nil, "", false
	}
	after := rc.standbyRecord()
	t0 := time.Now()
	var wrong []string
	if after.Standby == nil {
		wrong = append(wrong, "the record names no standby")
	} else {
		addr = after.Standby.IP
		if !contains(FloatingIPPool, addr) {
			wrong = append(wrong, "standby "+addr+" is not a provider address")
		}
		if after.Standby.Mode != mode {
			wrong = append(wrong, "mode "+after.Standby.Mode)
		}
	}
	if after.PublicIP != before.PublicIP {
		wrong = append(wrong, fmt.Sprintf("public_ip moved %s → %s: a standby must not be adopted", before.PublicIP, after.PublicIP))
	}
	created, assigned := false, false
	for _, q := range CloudRequests(rc.P) {
		created = created || (q.Method == "POST" && q.Path == "/v1/floating_ips" && q.Status/100 == 2)
		assigned = assigned || (q.Method == "POST" && strings.HasSuffix(q.Path, "/actions/assign") && q.Status/100 == 2)
	}
	if !created || !assigned {
		wrong = append(wrong, fmt.Sprintf("cloud: floating IP created=%v assigned=%v", created, assigned))
	}
	rc.R.Add("", phase, "rented_and_kept_back", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"public_ip": after.PublicIP, "mode": mode}, t0)
	if addr == "" {
		return "", nil, "", false
	}
	keyText = out.Key
	if out.Key != "" {
		k, err := bundle.ParseStandbyKeyText(out.Key)
		good := err == nil && k.Address() == addr
		rc.R.Add("", phase, "key.names_the_standby", Pass, got(good, Pass, Fail), got(good, "", fmt.Sprintf("the printed key does not decode to the standby (%v)", err)),
			map[string]any{"key_chars": len(out.Key), "grouped": standbyKeyText.MatchString(out.Key)}, t0)
		if good {
			key = &k
		}
	} else if mode == "sealed" {
		rc.R.Add("", phase, "key.names_the_standby", Pass, Fail, "standby add printed no key for a sealed standby", nil, t0)
	}
	// The box answers on the standby (the data port, from the
	// recipients' side), and still on the primary.
	t0 = time.Now()
	both := rc.tcpFromClient(addr, 443) && rc.tcpFromClient(after.PublicIP, 443)
	rc.R.Add("", phase, "box.answers_on_both_addresses", Pass, got(both, Pass, Fail),
		got(both, "", "443/tcp does not answer on both the primary and the standby from the client's side"), map[string]any{"standby": addr}, t0)
	return addr, key, keyText, true
}

// standbyRemove takes the standby down in the app's order: sign without
// it first, then unbind and release.
func (rc *RunCtx) standbyRemove(phase string) {
	rec := rc.standbyRecord()
	if rec.Standby == nil {
		// Promoted, or never rented: still sweep strays (a killed run).
		rc.standbyVerb(phase, "remove")
		return
	}
	full, _ := os.ReadFile(rc.Pub.Path("record.json"))
	var m map[string]any
	_ = json.Unmarshal(full, &m)
	delete(m, "standby")
	stripped, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(rc.Pub.Path("record.json"), stripped, 0o600)
	rc.Resign(phase)
	_ = os.WriteFile(rc.Pub.Path("record.json"), full, 0o600)
	out, ok := rc.standbyVerb(phase, "remove")
	t0 := time.Now()
	after := rc.standbyRecord()
	clean := ok && after.Standby == nil && len(out.StillBilling) == 0 && contains(out.Released, rec.Standby.FloatingIPID)
	rc.R.Add("", phase, "removed.nothing_left_billing", Pass, got(clean, Pass, Fail),
		got(clean, "", fmt.Sprintf("released=%v still_billing=%v record standby=%v", out.Released, out.StillBilling, after.Standby != nil)), nil, t0)
	dead := !rc.tcpFromClient(rec.Standby.IP, 443)
	rc.R.Add("", phase, "removed.address_serves_nothing", Pass, got(dead, Pass, Fail), got(dead, "", "the released address still answers on 443"), nil, t0)
	rc.Resign(phase)
}

func (rc *RunCtx) standbyPrecheck(phase string) bool {
	if caps, _, _, _ := rc.Health(); !contains(caps, "bind-address") {
		rc.R.Add("", phase, "standby", Skipped, Skipped,
			"this relay's daal-relay-mgmt does not advertise bind-address, so it cannot hold a second address (run with --mgmt=tree)", nil, time.Now())
		return false
	}
	if (&autoOp{rc: rc}).scenarioBlocks() {
		rc.R.Add("", phase, "standby", Skipped, Skipped, "the scenario already blocks a family; this op needs a world where the phone can connect first", nil, time.Now())
		return false
	}
	return true
}

// mintR1 signs base.sbp against the record as it is and mints r1's file.
func (rc *RunCtx) mintR1(phase, tag string) (string, bool) {
	if !rc.Resign(phase) {
		return "", false
	}
	return rc.Rebuild("r1", phase, "base.sbp", tag)
}

// ---- dial watch: did the phone ever open anything to an address? -------

func (rc *RunCtx) watchDials(table, addr string) error {
	rule := fmt.Sprintf("add table inet %s; delete table inet %s; add table inet %s; add counter inet %s dials; "+
		"add chain inet %s f { type filter hook forward priority -20; }; add rule inet %s f ip saddr %s ip daddr %s ct state new counter name dials",
		table, table, table, table, table, table, ClientIP, addr)
	_, err := sh(rc.Ctx, inNS(NSCensor, "nft", rule)...)
	return err
}

var nftPackets = regexp.MustCompile(`packets (\d+)`)

func (rc *RunCtx) dialCount(table string) int {
	out, err := sh(rc.Ctx, inNS(NSCensor, "nft", "list", "counter", "inet", table, "dials")...)
	if err != nil {
		return -1
	}
	if m := nftPackets.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return -1
}

func (rc *RunCtx) unwatch(table string) {
	_, _ = sh(rc.Ctx, inNS(NSCensor, "nft", "delete", "table", "inet", table)...)
}

// ---- ops -----------------------------------------------------------------

func opStandby(rc *RunCtx) {
	const phase = "op:standby"
	if !rc.standbyPrecheck(phase) {
		return
	}
	addr, key, _, ok := rc.standbyAdd(phase, "sealed")
	if !ok {
		rc.standbyRemove(phase)
		return
	}
	defer rc.standbyRemove(phase)
	pack, ok := rc.mintR1(phase, "standby")
	if !ok {
		return
	}
	rc.standbyInPack(phase, "signed", rc.Pub.Path("base.sbp"), "sealed", addr, key)
	rc.standbyInPack(phase, "r1", pack, "sealed", addr, key)
	// A phone takes the file and connects as before: the new member
	// costs nothing (one family; the matrix covers the rest).
	if fams := rc.liveFamilies(phase); len(fams) > 0 {
		rc.sub(fams[0], phase, "with-standby", pack, Pass)
	}
	rc.Pack = pack
}

// opStandbyPromote: the switch, delivered by the ordinary freshness
// channel to a phone that is connected when the primary dies.
func opStandbyPromote(rc *RunCtx) {
	const phase = "op:standby-promote"
	if !rc.standbyPrecheck(phase) {
		return
	}
	oldIP := rc.Rec.PublicIP
	addr, _, _, ok := rc.standbyAdd(phase, "sealed")
	if !ok {
		rc.standbyRemove(phase)
		return
	}
	defer rc.standbyRestore(phase, oldIP)
	// The file in the field: signed WITH the standby commitment and the
	// mirror set, minted before anything went wrong.
	fc, heldPack, armed := rc.armNoNewFile(phase, "sbp")
	if !armed {
		return
	}
	a := &autoOp{rc: rc, phase: phase}
	p := c0Phone(a, "standby", heldPack, ClientOpts{LivenessS: c0Liveness, RecheckS: c0Recheck, Hosts: fc.hosts, CAFile: rc.P.CA(), EngineLog: true})
	if p == nil {
		return
	}
	defer p.stop()
	t0 := time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		return
	}
	tun, _ := x.ev["tun"].(string)
	// "Switch to standby": record → sign → publish. No provider call.
	if _, ok := rc.standbyVerb(phase, "promote"); !ok {
		return
	}
	t0 = time.Now()
	moved := rc.standbyRecord().PublicIP == addr
	rc.R.Add("", phase, "promoted.record_names_the_standby", Pass, got(moved, Pass, Fail), got(moved, "", "public_ip is "+rc.standbyRecord().PublicIP), nil, t0)
	if _, ok := fc.announce("sbp-after"); !ok {
		return
	}
	// The primary dies under the connected phone.
	t0 = time.Now()
	if err := c0BlockWith(rc, oldIP, false); err != nil {
		rc.R.Add("", phase, "censor.blocks_primary", Blocked, Fail, err.Error(), nil, t0)
		return
	}
	rc.R.Add("", phase, "censor.blocks_primary", Blocked, got(rc.tcpFromClient(oldIP, 443), Pass, Blocked), "", map[string]any{"address": oldIP}, t0)
	c0ExpectRecovery(rc, p, "recovered", tun, t0, len(StorageRequests(rc.P)))
}

// standbyRestore: block lifted; a promoted standby released (the relay
// back on its primary); any standby left removed; r1's file valid again.
func (rc *RunCtx) standbyRestore(phase, oldIP string) {
	_ = c0Unblock(rc)
	if rc.standbyRecord().PublicIP != oldIP {
		t0 := time.Now()
		v := rc.Pub.ReleaseFIP(rc.Ctx)
		rc.R.Add("", phase, "verb.floating-ip-release", Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0)
		rc.MgmtWindowClosed(phase)
		if rec, err := rc.Pub.Record(); err == nil {
			rc.Rec = rec
		}
	}
	rc.standbyRemove(phase)
	if p1, ok := rc.mintR1(phase, "after-"+strings.TrimPrefix(phase, "op:")); ok {
		rc.Pack = p1
	}
}

// standbyDeadPrimary: a phone connected on pack, the primary null-routed
// under it, and a watch on the standby address. It returns the phone
// once the engine has stopped claiming to be connected.
func (rc *RunCtx) standbyDeadPrimary(phase, label, pack, oldIP, standbyAddr string, o ClientOpts) (*autoPhone, string, bool) {
	a := &autoOp{rc: rc, phase: phase}
	o.LivenessS, o.RecheckS, o.EngineLog = c0Liveness, c0Recheck, true
	p := c0Phone(a, label, pack, o)
	if p == nil {
		return nil, "", false
	}
	t0 := time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		p.stop()
		return nil, "", false
	}
	tun, _ := x.ev["tun"].(string)
	if err := rc.watchDials("wb_sb_watch", standbyAddr); err != nil {
		rc.R.Add("", phase, label+".watch", Pass, Fail, err.Error(), nil, t0)
	}
	if err := c0BlockWith(rc, oldIP, false); err != nil {
		rc.R.Add("", phase, label+".censor.blocks_primary", Blocked, Fail, err.Error(), nil, t0)
		p.stop()
		return nil, "", false
	}
	return p, tun, true
}

// opStandbySealed: the sealed case end to end from the recipient's seat.
func opStandbySealed(rc *RunCtx) {
	const phase = "op:standby-sealed"
	if !rc.standbyPrecheck(phase) {
		return
	}
	oldIP := rc.Rec.PublicIP
	addr, key, keyText, ok := rc.standbyAdd(phase, "sealed")
	if !ok {
		rc.standbyRemove(phase)
		return
	}
	defer rc.standbyRestore(phase, oldIP)
	defer rc.unwatch("wb_sb_watch")
	pack, ok := rc.mintR1(phase, "sealed")
	if !ok || !rc.standbyInPack(phase, "r1", pack, "sealed", addr, key) {
		return
	}
	p, _, ok := rc.standbyDeadPrimary(phase, "sealed", pack, oldIP, addr, ClientOpts{})
	if !ok {
		return
	}
	defer p.stop()
	// 1. No key arrives: the engine gives up on the primary and must not
	// go looking for the standby — it does not know it, and must not act
	// as if it did.
	t0 := time.Now()
	d, states, ended := c0WaitFor(p, "no-key", t0, func(diag, blk, rec map[string]any) bool {
		return blk["state"] != "connected" && blk["state"] != "connecting" && blk["state"] != "trying"
	})
	diagText := ""
	if d != nil {
		b, _ := json.Marshal(d)
		diagText = string(b)
	}
	p.add("no-key", "", "not_connected", Pass, got(ended, Pass, Fail),
		got(ended, "", "the engine still says it is connected with its only address null-routed (seen: "+strings.Join(states, " → ")+")"),
		map[string]any{"seen": strings.Join(states, " → ")}, t0)
	n := rc.dialCount("wb_sb_watch")
	p.add("no-key", "", "never_dialled_the_standby", Pass, got(n == 0, Pass, Fail),
		got(n == 0, "", fmt.Sprintf("%d new flows from the phone to the sealed standby %s before any key", n, addr)), map[string]any{"flows": n}, t0)
	p.add("no-key", "", "address_in_nothing_it_says", Pass, got(!strings.Contains(diagText, addr), Pass, Fail),
		got(!strings.Contains(diagText, addr), "", "the engine's diagnostics name the sealed standby's address"), nil, t0)
	pr := Probe(rc.Ctx, rc.P, false, 4*time.Second)
	p.add("no-key", "", "no_traffic_around_the_tunnel", Blocked, got(pr.OK, Pass, Blocked), pr.Error, nil, t0)

	// 2. The person types the key.
	if rc.waitsOn(phase, "typed-key", PreStandbyKey, PreStandbyStore) {
		return
	}
	if !contains(rc.clientFeatures(), "standby_key") {
		rc.R.Add("", phase, "typed-key", Skipped, Skipped, "core/abi has StandbyKey but this wb-client was built without the wb_standby_key tag (rebuild: run.sh adds it)", nil, t0)
		return
	}
	// A wrong key (valid shape, another address) and a malformed one first.
	wrongKey, _ := bundle.NewStandbyKey("203.0.113.99", rand.Reader)
	for _, c := range []struct{ label, text, want string }{{"wrong-key", wrongKey.Text(), "no_match"}, {"malformed-key", "HELLO-WORLD", "malformed"}} {
		t0 = time.Now()
		ans := p.ask(c.label, "standby-key - "+c.text, "standby-key", 20*time.Second, t0)
		outcome := standbyOutcome(ans)
		p.add(c.label, "", "refused", Pass, got(outcome == c.want, Pass, Fail), got(outcome == c.want, "", fmt.Sprintf("outcome %q, want %q", outcome, c.want)), nil, t0)
	}
	n0 := rc.dialCount("wb_sb_watch")
	p.add("wrong-key", "", "still_never_dialled", Pass, got(n0 == 0, Pass, Fail), fmt.Sprintf("flows to the standby: %d", n0), nil, t0)
	t0 = time.Now()
	ans := p.ask("typed-key", "standby-key - "+keyText, "standby-key", 20*time.Second, t0)
	outcome := standbyOutcome(ans)
	if !p.add("typed-key", "", "accepted", Pass, got(outcome == "accepted", Pass, Fail), got(outcome == "accepted", "", fmt.Sprintf("outcome %q", outcome)), nil, t0) {
		return
	}
	if b, _ := json.Marshal(ans); strings.Contains(string(b), keyText) || strings.Contains(string(b), addr) {
		p.add("typed-key", "", "answer_echoes_nothing", Pass, Fail, "the engine's answer repeats the key or the address", nil, t0)
	}
	x := p.press("reconnect", "auto", t0)
	if x != nil && p.connectedOn("reconnect", x, t0) {
		n := rc.dialCount("wb_sb_watch")
		p.add("reconnect", x.family, "on_the_standby", Pass, got(n > 0, Pass, Fail), fmt.Sprintf("flows to the standby: %d", n), nil, t0)
	}
}

func standbyOutcome(ans map[string]any) string {
	if ans == nil {
		return "no_answer"
	}
	if e, _ := ans["error"].(string); strings.HasPrefix(e, "not_built") {
		return "not_built"
	}
	a, _ := ans["answer"].(map[string]any)
	o, _ := a["outcome"].(string)
	if o == "" {
		if e, _ := ans["error"].(string); e != "" {
			return "error: " + e
		}
	}
	return o
}

// opStandbyOpen: the address variant, zero fetches.
func opStandbyOpen(rc *RunCtx) {
	const phase = "op:standby-open"
	if !rc.standbyPrecheck(phase) {
		return
	}
	oldIP := rc.Rec.PublicIP
	addr, _, _, ok := rc.standbyAdd(phase, "open")
	if !ok {
		rc.standbyRemove(phase)
		return
	}
	defer rc.standbyRestore(phase, oldIP)
	defer rc.unwatch("wb_sb_watch")
	pack, ok := rc.mintR1(phase, "open")
	if !ok || !rc.standbyInPack(phase, "r1", pack, "open", addr, nil) {
		return
	}
	if rc.waitsOn(phase, "variant", PreStandbyVariant, PreStandbyStore) {
		return
	}
	p, tun, ok := rc.standbyDeadPrimary(phase, "open", pack, oldIP, addr, ClientOpts{})
	if !ok {
		return
	}
	defer p.stop()
	t0 := time.Now()
	reqBefore := len(StorageRequests(rc.P))
	// Connected again, on the standby variant (the engine's own word for
	// it, `a:standby`): until the liveness check notices, the engine is
	// still "connected" on the dead primary, which proves nothing.
	d, states, moved := c0WaitFor(p, "moved", t0, func(diag, blk, rec map[string]any) bool {
		return blk["state"] == "connected" && blk["variant"] == "a:standby" && diag["route_running"] == true && diag["route_check"] == "ok"
	})
	ev := map[string]any{"seen": strings.Join(states, " → ")}
	p.add("moved", "", "moved_to_the_standby_by_itself", Pass, got(moved, Pass, Blocked),
		got(moved, "", "the engine did not reconnect after its primary was null-routed (seen: "+strings.Join(states, " → ")+")"), ev, t0)
	if !moved {
		return
	}
	n := rc.dialCount("wb_sb_watch")
	fetches := len(StorageRequests(rc.P)) - reqBefore
	p.add("moved", "", "on_the_standby_with_zero_fetches", Pass, got(n > 0 && fetches == 0, Pass, Fail),
		fmt.Sprintf("flows to the standby=%d, refresh fetches=%d (want >0 and 0)", n, fetches), nil, t0)
	if d != nil && d["tun"] != tun {
		p.add("moved", "", "same_tun", Pass, Fail, fmt.Sprintf("TUN %q before, %v after", tun, d["tun"]), nil, t0)
	}
	diag, _ := d["diag"].(map[string]any)
	blk := autoBlock(diag)
	if fam, _ := blk["family"].(string); fam != "" {
		if f, known := rc.Fams[fam]; known {
			p.sw.carries("moved", f, t0)
		}
	}
}

// opStandbyStale: open mode, the address released and handed to a
// stranger; a phone that never refreshed must not carry anything there.
func opStandbyStale(rc *RunCtx) {
	const phase = "op:standby-stale"
	if !rc.standbyPrecheck(phase) {
		return
	}
	oldIP := rc.Rec.PublicIP
	addr, _, _, ok := rc.standbyAdd(phase, "open")
	if !ok {
		rc.standbyRemove(phase)
		return
	}
	pack, ok := rc.mintR1(phase, "stale")
	if !ok {
		rc.standbyRestore(phase, oldIP)
		return
	}
	// The publisher removes the standby; this phone never hears of it.
	rc.standbyRemove(phase)
	defer rc.standbyRestore(phase, oldIP)
	defer rc.unwatch("wb_sb_watch")
	if rc.waitsOn(phase, "variant", PreStandbyVariant, PreStandbyStore) {
		return
	}
	t0 := time.Now()
	if err := rc.BringUpStranger(addr); err != nil {
		rc.R.Add("", phase, "stranger.up", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer rc.RemoveStranger(addr)
	p, _, ok := rc.standbyDeadPrimary(phase, "stale", pack, oldIP, addr, ClientOpts{})
	if !ok {
		return
	}
	defer p.stop()
	t0 = time.Now()
	_, states, ended := c0WaitFor(p, "stranger", t0, func(diag, blk, rec map[string]any) bool {
		return blk["state"] == "failed" || blk["state"] == "idle"
	})
	tried := rc.dialCount("wb_sb_watch")
	diag := p.ask("stranger", "diag", "diag", 20*time.Second, t0)
	blk := autoBlock(diagOf(diag))
	connected := blk["state"] == "connected"
	p.add("stranger", "", "fails_closed", Pass, got(ended && !connected, Pass, Fail),
		fmt.Sprintf("seen: %s; flows to the stranger: %d", strings.Join(states, " → "), tried), map[string]any{"flows": tried}, t0)
	// …and that is because the variant was refused, not because it was
	// never tried: without a dial to the stranger the check above is empty.
	p.add("stranger", "", "variant_was_tried", Pass, got(tried > 0, Pass, Fail),
		got(tried > 0, "", "the engine never dialled the stale standby, so nothing here shows it fails closed"), map[string]any{"flows": tried}, t0)
	pr := Probe(rc.Ctx, rc.P, false, 4*time.Second)
	p.add("stranger", "", "nothing_carried", Blocked, got(pr.OK, Pass, Blocked), pr.Error, nil, t0)
}

// opStandbyGoogle: sealed; the ordinary mirrors are cut; the switch and
// the key reach the phone through the Google channel. Lives in
// ops_gfe.go's machinery (googleChannel).
func opStandbyGoogle(rc *RunCtx) {
	const phase = "op:standby-google"
	if !rc.standbyPrecheck(phase) {
		return
	}
	if rc.waitsOn(phase, "standby-google", PreGoogleMirror, PreFrontFetch) {
		return
	}
	oldIP := rc.Rec.PublicIP
	if _, _, keyText, ok := rc.standbyAdd(phase, "sealed"); ok {
		defer rc.standbyRestore(phase, oldIP)
		rc.googleRecovery(phase, oldIP, func() bool {
			_, ok := rc.standbyVerb(phase, "promote")
			return ok
		}, keyText)
	} else {
		rc.standbyRemove(phase)
	}
}
