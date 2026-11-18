package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() { Ops["revoke"] = opRevoke }

// opRevoke: a revoked recipient is refused; nobody else is affected.
//
//  1. provision a second recipient r2 and mint their pack
//  2. r2 connects and fetches                         → pass   (positive: the pack was good)
//  3. `users-revoke --name r2`
//  4. r2's same pack, fresh session                   → blocked (the control that gives 2 meaning)
//  5. r1's pack, fresh session                        → pass   (no collateral damage)
//
// Runs once per family under test, because revocation is implemented per
// inbound on the box and a family whose user row survives is exactly the
// kind of seam this rig exists for.
func opRevoke(rc *RunCtx) {
	const phase = "op:revoke"
	pack2, ok := rc.MintRecipient("r2", phase)
	if !ok {
		return
	}
	fams := rc.activeFamilies()
	for _, f := range fams {
		rc.sub(f, phase, "before", pack2, Pass)
	}
	t0 := time.Now()
	v := rc.Pub.UsersRevoke(rc.Ctx, "r2")
	if !rc.R.Add("", phase, "verb.users-revoke.r2", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"stdout": strings.TrimSpace(v.Stdout)}, t0) {
		return
	}
	t0 = time.Now()
	lv := rc.Pub.UsersList(rc.Ctx)
	rc.R.Add("", phase, "users-list.r2_absent", Pass, got(lv.OK() && !strings.Contains(lv.Stdout, `"r2"`) && strings.Contains(lv.Stdout, `"r1"`), Pass, Fail),
		strings.TrimSpace(lv.Stdout)+" "+lv.Tail(), nil, t0)
	rc.MgmtWindowClosed(phase)
	for _, f := range fams {
		revoked := rc.sub(f, phase, "revoked", pack2, Blocked)
		bystander := rc.sub(f, phase, "bystander", rc.Pack, Pass)
		rc.revokedAttributable(f, phase, revoked, bystander)
	}
}

// revokedAttributable: "the revoked recipient is blocked" is evidence of
// revocation only if the family was serving at that moment. Once (FINDINGS
// INT-2) naive refused every TLS handshake for one sing-box instance's
// life: the revoked session was blocked, green — and so was the bystander
// a second later. That green cell proved nothing. So the pair is judged
// together: if the never-revoked recipient cannot get through on the same
// family right after, the revoked cell is not attributable to the revoke,
// and this check is red. It is deliberately NOT matched by any
// known-findings entry: a run in which revocation went unproven on a
// family must not exit 0.
//
// Under a scenario that blocks the family nothing can be attributed (both
// sessions are expected blocked) and the check is not recorded.
func (rc *RunCtx) revokedAttributable(f Family, phase, revoked, bystander string) {
	if scn, _ := rc.Scn.ExpectFor(f.Name); scn == Blocked {
		return
	}
	if revoked != Blocked {
		return // revoked.tunnel is already red for the plain reason
	}
	t0 := time.Now()
	if bystander == Pass {
		rc.R.Add(f.Name, phase, "revoked.attributable", Pass, Pass, "", nil, t0)
		return
	}
	rc.R.Add(f.Name, phase, "revoked.attributable", Pass, Fail,
		"the never-revoked bystander was "+bystander+" on the same family right after: the revoked recipient's `blocked` is not evidence of revocation in this run (the family was not serving anyone; FINDINGS INT-2)",
		rc.relayLifecycleEvidence(), t0)
}

// relayLifecycleEvidence is what tells a relay defect from a lab one after
// a restart: the systemctl shim's journal of the sing-box unit (which pid
// was stopped, how, what it still held; which pid was started) and what
// is listening in the relay's namespace right now, by pid.
func (rc *RunCtx) relayLifecycleEvidence() map[string]any {
	ev := map[string]any{}
	journal := filepath.Join(rc.P.Box(rc.Rec.ServerID), "rootfs", "var", "log", "wb-units", "sing-box.service.lifecycle.log")
	ev["shim_journal"] = journal
	if body, err := os.ReadFile(journal); err == nil {
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if len(lines) > 8 {
			lines = lines[len(lines)-8:]
		}
		ev["shim_journal_tail"] = lines
	} else {
		ev["shim_journal_error"] = err.Error()
	}
	out, err := sh(rc.Ctx, inNS(NSRelay1, "ss", "-Hlntup")...)
	if err != nil {
		ev["relay_listeners_error"] = err.Error()
	} else {
		ev["relay_listeners"] = strings.Split(strings.TrimSpace(out), "\n")
	}
	return ev
}
