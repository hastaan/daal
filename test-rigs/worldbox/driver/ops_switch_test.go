package main

import "testing"

// switch-all must visit every ordered pair of families exactly once, and
// end where it started (one session, no reconnect in between).
func TestEulerCircuitVisitsEveryOrderedPairOnce(t *testing.T) {
	for n := 2; n <= 8; n++ {
		walk := eulerCircuit(n)
		if len(walk) != n*(n-1)+1 || walk[0] != walk[len(walk)-1] {
			t.Fatalf("n=%d: walk of %d vertices from %d to %d, want a closed walk of %d", n, len(walk), walk[0], walk[len(walk)-1], n*(n-1)+1)
		}
		seen := map[[2]int]int{}
		for i := 1; i < len(walk); i++ {
			if walk[i-1] == walk[i] {
				t.Fatalf("n=%d: a switch from %d to itself", n, walk[i])
			}
			seen[[2]int{walk[i-1], walk[i]}]++
		}
		for a := 0; a < n; a++ {
			for b := 0; b < n; b++ {
				if a != b && seen[[2]int{a, b}] != 1 {
					t.Errorf("n=%d: pair %d>%d switched %d times, want once", n, a, b, seen[[2]int{a, b}])
				}
			}
		}
	}
}

// The open switch finding (SW-1) excuses exactly its own cell. In
// particular nothing in known-findings.json may excuse the checks that
// pin the phone bug (FINDINGS SW-0): a file closed underneath its owner,
// a store that stopped answering, a wrong active route — in any order —
// or lost connections in an order that does not share a TUN.
func TestSwitchFindingsExcuseOnlyTheirOwnCells(t *testing.T) {
	ks, err := LoadKnown(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	red := func(phase, family, check, expect, gotV string) Check {
		return chk("clean", BoxTree, phase, family, check, expect, gotV)
	}
	for _, c := range []Check{
		red("op:switch", "hysteria2", "rotate.vless-reality>hysteria2.fds_intact", Pass, Fail),
		red("op:switch", "hysteria2", "keep.vless-reality>hysteria2.fds_intact", Pass, Fail),
		red("op:switch", "vless-reality", "rotate.disconnect.fds_intact", Pass, Fail),
		red("op:switch", "hysteria2", "rotate.vless-reality>hysteria2.store_survives", Pass, Fail),
		red("op:switch", "hysteria2", "keep.vless-reality>hysteria2.store_survives", Pass, Fail),
		red("op:switch", "hysteria2", "keep.vless-reality>hysteria2.active_route", Pass, Fail),
		red("op:switch", "hysteria2", "rotate.vless-reality>hysteria2.tunnel", Pass, Blocked),
		red("op:switch-all", "naive", "rotate.tuic>naive.tunnel", Pass, Blocked),
		red("op:switch", "vless-reality", "check-rotate.restore.vless-reality.tunnel", Pass, Blocked),
		red("op:switch", "vless-reality", "keep.connect.tunnel", Pass, Blocked),
		red("op:switch", "hysteria2", "keep.vless-reality>hysteria2.tunnel", Pass, Fail),
		// SW-2 (a closed instance's packet reader was never stopped) is
		// fixed in the engine: what it used to excuse is an unexpected
		// red again.
		red("op:switch", "hysteria2", "keep.vless-reality>hysteria2.tunnel", Pass, Blocked),
		red("op:switch-all", "", "rotate.session.old_tuns_released", Pass, "held"),
		red("op:switch", "", "check-rotate.session.old_tuns_released", Pass, "held"),
		red("op:switch", "", "rotate.session.fd_trap_armed", Pass, Fail),
		red("op:switch", "vless-reality", "check-rotate.refused.vless-reality>hysteria2.old_route_still_connected", Pass, "disconnected"),
		red("op:switch", "hysteria2", "check-rotate.unreachable.vless-reality>hysteria2.dead_route_not_connected", Blocked, Pass),
	} {
		if id := knownFor(ks, c); id != "" {
			t.Errorf("%s %s got=%s is excused by %s; it must be an unexpected red", c.Phase, c.Check, c.Got, id)
		}
	}
	for want, c := range map[string]Check{
		"SW-1": red("op:switch", "vless-reality", "check-rotate.unreachable.vless-reality>hysteria2.old_route_still_connected", Pass, "disconnected"),
	} {
		if id := knownFor(ks, c); id != want {
			t.Errorf("%s got=%s: excused by %q, want %s (fixed? then delete this case with the entry)", c.Check, c.Got, id, want)
		}
	}
}
