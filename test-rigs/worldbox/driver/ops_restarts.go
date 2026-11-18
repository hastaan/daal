package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func init() { Ops["restarts"] = opRestarts }

// opRestarts: the relay must come back serving EVERY family after every
// restart of its data plane.
//
// Each mgmt verb that changes the user table restarts sing-box on the box
// (the kick wrapper: SIGUSR2, sleep 2, `systemctl reload || restart`;
// revoke and rotate do it twice). An operator with a dozen recipients
// restarts the relay a dozen times in an afternoon, and every existing
// recipient reconnects into whatever came up. The other ops cross a
// restart once or twice each and look at the recipient the verb was
// about; this one crosses many and looks at the bystander:
//
//	repeat N times (WB_RESTART_CYCLES, default 6):
//	  users-provision r9<i>    one restart
//	  users-revoke   r9<i>     two restarts, 2 s apart
//	  r1's pack, fresh session, each family   → pass
//
// It exists because the full matrix, run repeatedly, saw naive refuse
// every TLS handshake for the whole life of one sing-box instance while
// the six other inbounds of the same process served normally (FINDINGS
// INT-2: sing-box's start-up ALPN race on the naive inbound, fixed in the
// tree daemon by writing alpn into naive-in; a released relay still has
// it). One crossing per run finds that one run in N; this finds it in
// one.
func opRestarts(rc *RunCtx) {
	const phase = "op:restarts"
	cycles := 6
	if n, err := strconv.Atoi(os.Getenv("WB_RESTART_CYCLES")); err == nil && n > 0 {
		cycles = n
	}
	fams := rc.liveFamilies(phase)
	for i := 1; i <= cycles; i++ {
		name := fmt.Sprintf("r9%02d", i) // the box accepts r[0-9]{1,12} only
		t0 := time.Now()
		v := rc.Pub.UsersProvision(rc.Ctx, name)
		if !rc.R.Add("", phase, fmt.Sprintf("cycle%02d.verb.users-provision", i), Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
			return
		}
		t0 = time.Now()
		v = rc.Pub.UsersRevoke(rc.Ctx, name)
		if !rc.R.Add("", phase, fmt.Sprintf("cycle%02d.verb.users-revoke", i), Pass, got(v.OK(), Pass, Fail), v.Tail(), nil, t0) {
			return
		}
		for _, f := range fams {
			rc.sub(f, phase, fmt.Sprintf("cycle%02d", i), rc.Pack, Pass)
		}
	}
	rc.MgmtWindowClosed(phase)
}
