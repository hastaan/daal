package main

import (
	"fmt"
	"strings"
	"time"
)

func init() { Ops["blocked-while-connected"] = opBlockedWhileConnected }

// opBlockedWhileConnected: the relay's address is null-routed WHILE THE
// PHONE IS CONNECTED (blackout plan §3, work item C0).
//
// scenarios/relay-ip-block.json blocks the address before the world
// starts, and op freshness ticks a phone whose VPN is off. Neither ever
// put the engine where a real recipient is when their relay is burned:
// connected, tunnel guard up, the automatic connect in charge, every
// route on the one dead address. This op does, and the host does nothing
// from the moment the block lands — it only reads diagnostics:
//
//  1. the publisher arms the freshness channel and mints r1 a file with
//     the mirror set in it (armNoNewFile); a phone that sees the mirrors
//     WITHOUT a tunnel (its own /etc/hosts, the lab CA) imports it and
//     presses Connect: connected, verified bytes through the relay;
//  2. the publisher moves the relay to a new address (`assign-fip`, the
//     L3 rung) and announces the re-signed, credential-less pack; the
//     phone is told nothing;
//  3. the censor null-routes the OLD address, both directions;
//  4. the engine by itself: the liveness check fails twice, a fall-over
//     pass finds nothing (every route is on the dead address), the
//     instance is stopped, ONE direct walk of the mirrors fetches the
//     document and the pack, the pack is applied, the route is put back
//     on its NEW address and checked → `auto.state` connected,
//     `relay_recovery.state` updated, verified bytes through the relay
//     again — with the old address still blocked;
//  5. the walk went out from the phone's OWN address (no tunnel was up:
//     the storage host saw the client, not the relay's egress).
//
// It also holds the walk to its promise of ONE bounded walk: no more
// document fetches than the pack names mirrors, at most one pack — a
// scheduled poll or a pointer walk going out beside it (review M2) would
// show up here.
//
// Then (6) the same move under a block that RESETS TCP instead of
// swallowing it (review H1: a reset is not "silence", so the pass charges
// the other routes' cooldowns): a second phone on the pre-move file must
// recover the same way. (A one-ROUTE file — a fall-over pass with no
// other candidate at all — is not reachable here: the relay serves every
// default family and r1's file holds them all whatever families are
// under test; core/abi TestC0_OneRouteFileWalksAndRetries covers it.)
//
// Then the control (7): the same, on a phone that CANNOT see the mirrors
// (no hosts file): the walk finds nothing, the engine says so
// (`relay_recovery.state` unreachable), keeps the route's instance
// running (failed) and does not pretend it is connected.
//
// The world is left as found: block lifted, address released, r1's file
// re-minted.
const (
	c0Phase    = "op:blocked-while-connected"
	c0Table    = "wb_op_c0"
	c0Liveness = 3
	c0Recheck  = 3
	// The move: two failed checks (≤ ~10 s), one pass over dead routes
	// (~4 s each), one walk (two fetches), one check.
	c0Wait = 150 * time.Second
)

// c0MaxMirrors bounds the document fetches of ONE walk: the mirrors
// armNoNewFile's pack names (freshMirrorFlags: a flag and a value each).
var c0MaxMirrors = len(freshMirrorFlags) / 2

func opBlockedWhileConnected(rc *RunCtx) {
	if caps, _, _, _ := rc.Health(); !contains(caps, "bind-address") {
		rc.R.Add("", c0Phase, "address_move", Skipped, Skipped,
			"this relay's daal-relay-mgmt does not advertise bind-address, so the relay cannot be moved to a new address (run with --mgmt=tree)", nil, time.Now())
		return
	}
	if blocks := (&autoOp{rc: rc}).scenarioBlocks(); blocks {
		rc.R.Add("", c0Phase, "blocked-while-connected", Skipped, Skipped, "the scenario already blocks a family; this op needs a world where the phone can connect first", nil, time.Now())
		return
	}
	fc, heldPack, armed := rc.armNoNewFile(c0Phase, "c0")
	if !armed {
		return
	}
	oldIP := rc.Rec.PublicIP
	a := &autoOp{rc: rc, phase: c0Phase}

	// 1. connected, on the file from before the move.
	p := c0Phone(a, "sees-mirrors", heldPack, ClientOpts{LivenessS: c0Liveness, RecheckS: c0Recheck,
		Hosts: fc.hosts, CAFile: rc.P.CA(), EngineLog: true})
	if p == nil {
		return
	}
	t0 := time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		p.stop()
		return
	}
	tun, _ := x.ev["tun"].(string)

	// 2. the relay moves; the publisher announces; the phone is not told.
	t0 = time.Now()
	v := rc.Pub.AssignFIP(rc.Ctx)
	okSwap := rc.R.Add("", c0Phase, "verb.assign-fip", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"rc": v.RC}, t0)
	rc.MgmtWindowClosed(c0Phase)
	if !okSwap {
		p.stop()
		rc.l3Leftovers(c0Phase, oldIP)
		return
	}
	defer rc.c0Restore(oldIP)
	if rec, err := rc.Pub.Record(); err == nil {
		rc.Rec = rec
	}
	if _, ok := fc.announce("c0-after"); !ok {
		p.stop()
		return
	}

	// 3. the censor null-routes the old address under the connected phone.
	t0 = time.Now()
	if err := c0BlockWith(rc, oldIP, false); err != nil {
		rc.R.Add("", c0Phase, "censor.blocks_old_address", Blocked, Fail, err.Error(), map[string]any{"address": oldIP}, t0)
		p.stop()
		return
	}
	rc.R.Add("", c0Phase, "censor.blocks_old_address", Blocked, got(rc.tcpFromClient(oldIP, 443), Pass, Blocked), "",
		map[string]any{"address": oldIP}, t0)
	reqBefore := len(StorageRequests(rc.P))

	// 4.–5. the engine, by itself, from the phone's own address.
	c0ExpectRecovery(rc, p, "recovered", tun, t0, reqBefore)
	p.stop()

	// 6. the same under a block that resets.
	_ = c0Unblock(rc)
	if p = c0Phone(a, "sees-mirrors-rst", heldPack, ClientOpts{LivenessS: c0Liveness, RecheckS: c0Recheck,
		Hosts: fc.hosts, CAFile: rc.P.CA(), EngineLog: true}); p != nil {
		t0 = time.Now()
		if x = p.press("connect", "auto", t0); x != nil && p.connectedOn("connect-rst", x, t0) {
			tun, _ = x.ev["tun"].(string)
			t0 = time.Now()
			if err := c0BlockWith(rc, oldIP, true); err != nil {
				rc.R.Add("", c0Phase, "censor.resets_old_address", Blocked, Fail, err.Error(), map[string]any{"address": oldIP}, t0)
			} else {
				c0ExpectRecovery(rc, p, "recovered-rst", tun, t0, len(StorageRequests(rc.P)))
			}
		}
		p.stop()
	}

	// 7. the control: a phone that cannot see the mirrors.
	rc.c0Control(heldPack, oldIP)
}

// c0ExpectRecovery: the engine, by itself, finds the new address and is
// connected again on it, in the same TUN, with one direct walk from the
// phone's own address.
func c0ExpectRecovery(rc *RunCtx, p *autoPhone, step, tun string, t0 time.Time, reqBefore int) {
	d, states, ok := c0WaitFor(p, step, t0, func(diag, blk, rec map[string]any) bool {
		return blk["state"] == "connected" && rec["state"] == "updated" && diag["route_running"] == true && diag["route_check"] == "ok"
	})
	if d == nil {
		return
	}
	diag, _ := d["diag"].(map[string]any)
	blk, rec := autoBlock(diag), c0Recovery(diag)
	ev := map[string]any{"seen": strings.Join(states, " → "), "relay_recovery": rec, "auto_state": blk["state"], "verdict": blk["verdict"],
		"route_check": diag["route_check"], "waited_ms": time.Since(t0).Milliseconds(), "client_dir": p.c.Dir}
	p.add(step, "", "found_the_new_address_by_itself", Pass, got(ok, Pass, Blocked),
		got(ok, "", fmt.Sprintf("%s after the censor null-routed the relay's old address under a connected phone, the engine is not connected again (seen: %s)",
			time.Since(t0).Round(time.Second), strings.Join(states, " → "))), ev, t0)
	if ok {
		var wrong []string
		if rec["trigger"] != "failure" {
			wrong = append(wrong, fmt.Sprintf("relay_recovery.trigger=%v, want failure (nobody pressed anything)", rec["trigger"]))
		}
		if blk["mode"] != true {
			wrong = append(wrong, "auto.mode is false")
		}
		if d["tun"] != tun || tun == "" {
			wrong = append(wrong, fmt.Sprintf("the phone held TUN %q before and %q after", tun, d["tun"]))
		}
		if bad := anyStrings(d["sentinels_bad"]); len(bad) > 0 {
			wrong = append(wrong, "fds: "+strings.Join(bad, "; "))
		}
		p.add(step, "", "says_what_happened", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "), ev, t0)
		fam, _ := blk["family"].(string)
		if f, known := rc.Fams[fam]; known {
			p.sw.carries(step, f, t0)
		}
	}
	// The walk was direct, from the phone's own address — and it was ONE
	// walk: no more document fetches than there are mirrors, one pack.
	docs, packs, fromClient := 0, 0, true
	for _, q := range StorageRequests(rc.P)[reqBefore:] {
		if q.From != ClientIP {
			fromClient = false
		}
		switch {
		case strings.HasSuffix(q.Path, ".json"):
			docs++
		case strings.HasSuffix(q.Path, ".sbp") && q.Status == 200:
			packs++
		}
	}
	p.add(step, "", "walked_the_mirrors_directly", Pass, got(docs > 0 && packs > 0 && fromClient, Pass, Fail),
		fmt.Sprintf("document fetches=%d pack fetches=%d, all from the phone's own address=%v", docs, packs, fromClient),
		map[string]any{"document_fetches": docs, "pack_fetches": packs}, t0)
	p.add(step, "", "one_walk_nothing_beside_it", Pass, got(docs <= c0MaxMirrors && packs <= 1, Pass, Fail),
		fmt.Sprintf("document fetches=%d (at most %d) pack fetches=%d (at most 1)", docs, c0MaxMirrors, packs),
		map[string]any{"document_fetches": docs, "pack_fetches": packs}, t0)
}

// c0Control: connected on the file from before the move, the old
// address null-routed, the mirrors out of sight. The walk finds nothing
// and the engine must say exactly that.
func (rc *RunCtx) c0Control(heldPack, oldIP string) {
	_ = c0Unblock(rc)
	a := &autoOp{rc: rc, phase: c0Phase}
	p := c0Phone(a, "no-mirrors", heldPack, ClientOpts{LivenessS: c0Liveness, RecheckS: c0Recheck, EngineLog: true})
	if p == nil {
		return
	}
	defer p.stop()
	t0 := time.Now()
	x := p.press("connect", "auto", t0)
	if x == nil || !p.connectedOn("connect", x, t0) {
		return
	}
	if err := c0BlockWith(rc, oldIP, false); err != nil {
		rc.R.Add("", c0Phase, "control.censor", Blocked, Fail, err.Error(), nil, t0)
		return
	}
	t0 = time.Now()
	d, states, ok := c0WaitFor(p, "honest", t0, func(diag, blk, rec map[string]any) bool {
		return rec["state"] != "idle" && rec["state"] != "looking" && blk["state"] == "failed"
	})
	if d == nil {
		return
	}
	diag, _ := d["diag"].(map[string]any)
	blk, rec := autoBlock(diag), c0Recovery(diag)
	var wrong []string
	if !ok {
		wrong = append(wrong, "the walk never ended (seen: "+strings.Join(states, " → ")+")")
	}
	if rec["state"] != "unreachable" {
		wrong = append(wrong, fmt.Sprintf("relay_recovery.state=%v, want unreachable", rec["state"]))
	}
	if diag["route_running"] != true || diag["route_check"] != "failed" {
		wrong = append(wrong, fmt.Sprintf("route_running=%v route_check=%v: the dead route's instance should be back, failed", diag["route_running"], diag["route_check"]))
	}
	if v, _ := blk["verdict"].(string); v == "" {
		wrong = append(wrong, "auto.verdict is empty: a failed pass must say why")
	}
	p.add("honest", "", "nothing_new_is_said_plainly", Pass, got(len(wrong) == 0, Pass, Fail), strings.Join(wrong, "; "),
		map[string]any{"seen": strings.Join(states, " → "), "relay_recovery": rec, "auto": blk["state"], "verdict": blk["verdict"]}, t0)
	pr := Probe(rc.Ctx, rc.P, false, 4*time.Second)
	p.add("honest", "", "no_traffic_around_the_tunnel", Blocked, got(pr.OK, Pass, Blocked), pr.Error, nil, t0)
}

// c0Phone starts an auto phone holding `pack` (autoOp.start uses the
// run's current r1 file; this op needs the one from before the move).
func c0Phone(a *autoOp, label, pack string, o ClientOpts) *autoPhone {
	saved := a.rc.Pack
	a.rc.Pack = pack
	defer func() { a.rc.Pack = saved }()
	return a.start("c0-"+label, o)
}

func c0Recovery(diag map[string]any) map[string]any {
	b, _ := diag["relay_recovery"].(map[string]any)
	if b == nil {
		return map[string]any{}
	}
	return b
}

// c0WaitFor polls diagnostics (the host only LOOKS) until done says so or
// c0Wait runs out.
func c0WaitFor(p *autoPhone, step string, t0 time.Time, done func(diag, blk, rec map[string]any) bool) (map[string]any, []string, bool) {
	rc := p.op.rc
	var d map[string]any
	var states []string
	deadline := time.Now().Add(c0Wait)
	for time.Now().Before(deadline) && rc.Ctx.Err() == nil {
		d = p.ask(step, "diag", "diag", 20*time.Second, t0)
		if d == nil {
			return nil, states, false
		}
		diag, _ := d["diag"].(map[string]any)
		blk, rec := autoBlock(diag), c0Recovery(diag)
		s := fmt.Sprintf("%v/%v/%v", blk["state"], diag["route_check"], rec["state"])
		if len(states) == 0 || states[len(states)-1] != s {
			states = append(states, s)
		}
		if done(diag, blk, rec) {
			return d, states, true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return d, states, false
}

// c0BlockWith null-routes addr both ways; reset: TCP to it is answered
// with a reset instead (UDP still swallowed) — a block that is not
// silence, so the pass charges the routes it tries.
func c0BlockWith(rc *RunCtx, addr string, reset bool) error {
	rule := "add table inet " + c0Table + "; add chain inet " + c0Table + " forward { type filter hook forward priority -5; }; "
	if reset {
		rule += "add rule inet " + c0Table + " forward ip daddr " + addr + " meta l4proto tcp reject with tcp reset; "
	}
	rule += "add rule inet " + c0Table + " forward ip daddr " + addr + " drop; add rule inet " + c0Table + " forward ip saddr " + addr + " drop"
	_, err := sh(rc.Ctx, inNS(NSCensor, "nft", rule)...)
	return err
}

func c0Unblock(rc *RunCtx) error {
	_, err := sh(rc.Ctx, inNS(NSCensor, "nft", "delete", "table", "inet", c0Table)...)
	return err
}

// c0Restore leaves the world as op l3 does: block lifted, address given
// back, r1's file valid against the record as it is.
func (rc *RunCtx) c0Restore(oldIP string) {
	_ = c0Unblock(rc)
	t0 := time.Now()
	rv := rc.Pub.ReleaseFIP(rc.Ctx)
	rc.R.Add("", c0Phase, "verb.floating-ip-release", Pass, got(rv.OK(), Pass, Fail), rv.Tail(), map[string]any{"rc": rv.RC}, t0)
	rc.MgmtWindowClosed(c0Phase)
	if rec, err := rc.Pub.Record(); err == nil {
		rc.Rec = rec
	}
	if rc.Rec.PublicIP != oldIP {
		rc.l3Leftovers(c0Phase, oldIP)
	}
	if rc.Resign(c0Phase) {
		if p1, ok := rc.Rebuild("r1", c0Phase, "base.sbp", "after-c0"); ok {
			rc.Pack = p1
		}
	}
	rc.MgmtWindowClosed(c0Phase)
}
