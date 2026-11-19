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
		// SW-1 (a failed switch left nothing connected) is fixed in the
		// engine: the same.
		red("op:switch", "vless-reality", "check-rotate.unreachable.vless-reality>hysteria2.old_route_still_connected", Pass, "disconnected"),
		red("op:switch", "vless-reality", "check-rotate.unreachable.vless-reality>hysteria2.switch_back_recorded", Pass, Fail),
		// The automatic connect: what is open is two cells (below), and
		// nothing beside them.
		red("op:auto", "hysteria2", "memory.udp.refined", "udp_blocked_here", "none"),
		red("op:auto", "hysteria2", "memory.udp.refined", "udp_blocked_here", "relay_unreachable"),
		red("op:auto", "hysteria2", "all-blocked.connect.refined", "relay_unreachable", "udp_blocked_here"),
		red("op:auto", "hysteria2", "quic-only.connect.refined", AutoRefinedQUICOnly, "none"),
		red("op:auto", "hysteria2", "quic-only.connect.refined", AutoRefinedQUICOnly, "relay_unreachable"),
		red("op:auto", "", "all-blocked.connect.verdict", "relay_unreachable", "all_failed"),
		red("op:auto", "", "all-blocked.connect.verdict", "relay_unreachable", "network_down"),
		red("op:auto", "vless-reality", "fall-over.moved.engine_moved_by_itself", Pass, Blocked),
		red("op:auto", "websocket-tls", "blocked.again.remembered_route_first", Pass, Fail),
		chk("total-blackout", BoxTree, "op:auto", "", "scenario.connect.verdict", "network_down", "all_failed"),
		chk("total-blackout", BoxTree, "op:auto", "", "scenario.connect.not_connected", Blocked, Pass),
		chk("relay-ip-block", BoxTree, "op:auto", "", "scenario.connect.verdict", "relay_unreachable", "all_failed"),
		chk("relay-ip-block", BoxTree, "op:auto", "", "scenario.connect.verdict", "relay_unreachable", "network_down"),
		// The second slice: what is open is two cells (below). A race
		// that is not faster than one after the other, a third route in
		// flight, a side instance that leaves something, a move that
		// does not happen or does not hold — none is excused.
		red("op:auto", "naive", "race.connect.faster_than_one_after_another", Pass, Fail),
		red("op:auto", "", "race.connect.at_most_two_routes_in_flight", Pass, Fail),
		red("op:auto", "", "race.connect.both_dropped_routes_checked_together", Pass, Fail),
		red("op:auto", "naive", "race.again.remembered_route_alone", Pass, Fail),
		red("op:auto", "vless-reality", "first.connect.measured", Pass, Fail),
		red("op:auto-deep", "", "leak-stopped.race.a_side_instance_leaves_nothing", Pass, Fail),
		red("op:auto-deep", "", "leak-cancel.race.a_side_instance_leaves_nothing", Pass, Fail),
		red("op:auto-deep", "", "leak-cancel.cycle.a_connect_and_a_disconnect_leave_nothing", Pass, Fail),
		red("op:auto-deep", "vless-reality", "speed.moved.engine_moved_for_speed", Pass, Blocked),
		red("op:auto-deep", "websocket-tls", "speed.hold.stays_after_a_move_for_speed", Pass, Fail),
		red("op:auto-deep", "vless-reality", "metered.slow.no_probe_on_a_metered_network", Pass, Fail),
		red("op:auto-deep", "", "networks.down.verdict", "network_down", "relay_unreachable"),
		// A network the platform has not validated is not "no internet":
		// calling a dead relay on it network_down is an unexpected red.
		red("op:auto-deep", "", "networks.unvalidated.verdict", "relay_unreachable", "network_down"),
		red("op:auto-deep", "", "networks.dead-relay.verdict", "relay_unreachable", "network_down"),
		red("op:auto-deep", "", "networks.ids.the_clear_id_is_in_no_file", Pass, Fail),
	} {
		if id := knownFor(ks, c); id != "" {
			t.Errorf("%s %s got=%s is excused by %s; it must be an unexpected red", c.Phase, c.Check, c.Got, id)
		}
	}
	for want, c := range map[string]Check{
		// CEN-4, what is left of it in a pass: a QUIC-only filter gets the
		// answer all-UDP-dropped gets.
		"CEN-4": red("op:auto", "hysteria2", "quic-only.connect.refined", AutoRefinedQUICOnly, "udp_blocked_here"),
		// AUTO-1 (a border that forwards nothing, the link up, read as
		// one relay): open. Only a host that says "no network at all" gets
		// network_down; "not validated" is not taken for it.
		"AUTO-1": chk("total-blackout", BoxTree, "op:auto", "", "scenario.connect.verdict", "network_down", "relay_unreachable"),
		// AUTO-2: a silent address costs two attempt budgets, not one.
		"AUTO-2": red("op:auto", "naive", "race.connect.a_silent_address_costs_one_attempt", Pass, Fail),
		// SW-3: a connect and a disconnect leave one open file behind.
		"SW-3": red("op:auto-deep", "", "leak-stopped.cycle.a_connect_and_a_disconnect_leave_nothing", Pass, Fail),
	} {
		if id := knownFor(ks, c); id != want {
			t.Errorf("%s got=%s: excused by %q, want %s (fixed? then delete this case with the entry)", c.Check, c.Got, id, want)
		}
	}
}
