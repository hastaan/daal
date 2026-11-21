package abi

import "daal/core/diagnostics"

// What an automatic pass can SAY — `verdict` for the pass, `refined`
// for a route — derived from the set of its results.
//
// One route sees one thing. A UDP route that hears nothing cannot tell
// a network without UDP from a dead address; a reset after the first
// flight cannot tell a filter keyed on the name from one keyed on the
// address (the end-to-end rig's finding CEN-4). A second route of the
// same pass, to the same server, sometimes can — and when it cannot,
// nothing is added. Every rule below names the two observations it
// rests on. A route's own `category` is never rewritten.

// `verdict`: a closed set. The UI turns each into one plain sentence;
// a code it does not know gets the generic one.
const (
	// Connected on the first route tried.
	AutoVerdictNone = ""
	// Connected, after one or more routes did not carry.
	AutoVerdictMovedOn = "moved_on"
	// Nothing has been imported.
	AutoVerdictNoRoutes = "no_routes"
	// No route could be tried, and every one of them needs a new file:
	// made before files carried signed server addresses, or revoked or
	// expired beside others that were.
	AutoVerdictAllNeedNewFile = "all_need_new_file"
	// No route could be tried: every one is revoked or expired.
	AutoVerdictAllExpiredOrRevoked = "all_expired_or_revoked"
	// No route could be tried now, and at least one is only waiting out
	// a cooldown: trying again later can work.
	AutoVerdictAllCoolingDown = "all_cooling_down"
	// Every route tried was told by the device itself that there is no
	// network (network_offline) — or nothing at all answered and the
	// HOST has said the device is on no network at all (kind "none",
	// engine_network_facts). The engine has no reachability probe of its
	// own, so silence alone is never called this — and neither is a
	// network the platform merely has not validated.
	AutoVerdictNetworkDown = "network_down"
	// Every UDP route tried heard nothing while a TCP route to the same
	// server was answered. (The TCP routes failed too, each for the
	// reason in its own entry.)
	//
	// The code's name is the contract's and says more than is proved.
	// What the two observations prove is: THIS route's UDP port was
	// silent from here while the server's address was alive. A network
	// that drops UDP gives that — and so does a relay whose UDP service
	// has stopped or whose provider firewall closes the port (the rig
	// cannot tell the three apart either). Nothing downstream may read
	// it as "this network blocks UDP": the UI's sentence says "one of
	// the ways did not get through here", and no route of another
	// server is ordered or refused on the strength of it.
	AutoVerdictUDPBlockedHere = "udp_blocked_here"
	// Every route tried failed at the server's address: no answer to a
	// TCP connect, and any UDP route to the same address silent. The
	// address is dead or blocked — or the network has no way out at
	// all, which silence cannot be told from.
	AutoVerdictRelayUnreachable = "relay_unreachable"
	// A first flight carrying one name was stopped where another name
	// to the same address and port got through.
	AutoVerdictNameBlocked = "name_blocked"
	// First flights carrying different names to the same address and
	// port were all stopped at the same point.
	AutoVerdictAddressBlocked = "address_blocked"
	// Routes were tried, none carried, and nothing narrower is proved.
	AutoVerdictAllFailed = "all_failed"

	// Four codes beyond the contract's set, for outcomes it has no
	// word for (a UI that does not know them shows its generic line):
	//
	// No route could be tried and none of the reasons above covers them
	// all (an experimental family that is not turned on, a route the
	// mode forbids, a stored profile that cannot be used).
	AutoVerdictNoneUsable = "none_usable"
	// The pass was abandoned: a disconnect, a route picked by hand, a
	// newer pass.
	AutoVerdictCancelled = "cancelled"
	// This build cannot tunnel.
	AutoVerdictNoDataPlane = "no_data_plane"
	// The list of routes could not be read (a store that is locked,
	// busy or damaged). Nothing was tried and nothing is known about
	// what the person holds — in particular NOT that they hold nothing.
	AutoVerdictStoreUnreadable = "store_unreadable"
	// Nothing else carried and the engine has paused the dead route for
	// one direct walk of its pack's freshness mirrors, looking for the
	// publisher's new address (relaypack_recover.go). `auto.state` is
	// "trying" for as long as it says this; when the walk ends empty the
	// verdict of the pass comes back.
	AutoVerdictLookingForAddress = "looking_for_address"
)

// `refined` on one route: what a second observation added.
const (
	// See AutoVerdictUDPBlockedHere for what this does and does not
	// prove.
	AutoRefinedUDPBlockedHere   = "udp_blocked_here"
	AutoRefinedRelayUnreachable = "relay_unreachable"
	AutoRefinedNameBlocked      = "name_blocked"
	AutoRefinedAddressBlocked   = "address_blocked"
)

// autoObs is one tried route as deriveAuto sees it. host / port / name
// say which routes share a server; they never leave the pass.
type autoObs struct {
	result   string
	category diagnostics.Category
	obs      diagnostics.Observation
	udp      bool
	host     string
	port     int
	name     string
	// unplaced: nothing is known about where the route goes or how it
	// failed beyond its category (the route that was connected before a
	// fall-over pass). It is never a second observation for another
	// route.
	unplaced bool
	// id / racedWith / second: the route, the route it was checked
	// beside, and whether it was the SECOND of that pair (the partner
	// picked to go beside the pass's next route).
	id, racedWith string
	second        bool
	// sideOnly: "carried" in a side instance only — it proved a moment
	// after the route the tunnel was started on. It is an observation
	// (the address answered) and never "the pass connected".
	sideOnly bool
}

func (a autoObs) failed() bool {
	return a.result == AutoResultNotCarrying || a.result == AutoResultStartFailed
}

// tcpReached: the server's address answered this TCP route — its SYN
// was accepted, whatever became of the connection afterwards.
func (a autoObs) tcpReached() bool {
	if a.udp || a.unplaced {
		return false
	}
	return a.result == AutoResultCarried ||
		(a.result == AutoResultNotCarrying && (a.obs.Phase == diagnostics.PhaseHandshake || a.obs.Phase == diagnostics.PhaseCarry))
}

// pastHandshake: the relay answered this route's own first flight.
func (a autoObs) pastHandshake() bool {
	if a.udp || a.unplaced {
		return false
	}
	return a.result == AutoResultCarried || (a.result == AutoResultNotCarrying && a.obs.Phase == diagnostics.PhaseCarry)
}

// stoppedAtHello: a TLS first flight went out on an open TCP connection
// and was reset, closed or left unanswered, on a path not seen moving.
func (a autoObs) stoppedAtHello() bool {
	return !a.udp && !a.unplaced && a.result == AutoResultNotCarrying &&
		a.obs.Phase == diagnostics.PhaseHandshake && a.obs.TLS && !a.obs.Progress &&
		(a.obs.Reset || a.obs.Timeout || a.obs.Closed)
}

// synUnanswered: a TCP connect to the server's address timed out.
func (a autoObs) synUnanswered() bool {
	return !a.udp && !a.unplaced && a.result == AutoResultNotCarrying && a.category == diagnostics.TCPConnectTimeout
}

// deriveAuto returns the verdict of a pass in which at least one route
// was tried, and the refinement of each tried route (parallel to tried).
func deriveAuto(tried []autoObs) (verdict string, refined []string) {
	refined = make([]string, len(tried))
	for i, a := range tried {
		if a.result != AutoResultNotCarrying || a.unplaced || a.host == "" {
			continue
		}
		switch {
		case a.udp && a.category == diagnostics.UDPNoReply:
			// Silent UDP + the SAME address answering TCP: the address
			// is alive, so the silence is about UDP to it from here.
			// Silent UDP + the same address not answering a SYN either:
			// the address, not UDP.
			for j, b := range tried {
				if j == i || b.host != a.host {
					continue
				}
				if b.tcpReached() {
					refined[i] = AutoRefinedUDPBlockedHere
					break
				}
				if b.synUnanswered() {
					refined[i] = AutoRefinedRelayUnreachable
				}
			}
		case a.stoppedAtHello() && a.name != "":
			// Same address AND port, a different name. If that one got
			// through, what stopped this one is its name. If that one
			// was stopped at the same point, the name is not what the
			// filter reads. A different port proves neither (the filter
			// may be keyed on the port, or one service may be down), so
			// it is not used.
			for j, b := range tried {
				if j == i || b.udp || b.host != a.host || b.port != a.port || b.name == "" || b.name == a.name {
					continue
				}
				if b.pastHandshake() {
					refined[i] = AutoRefinedNameBlocked
					break
				}
				if b.stoppedAtHello() {
					refined[i] = AutoRefinedAddressBlocked
				}
			}
		}
	}

	fails := 0
	for _, a := range tried {
		if a.failed() {
			fails++
		}
	}
	for _, c := range tried {
		if c.result != AutoResultCarried || c.sideOnly {
			continue
		}
		// Connected on c. "Moved on" is said when a route the pass came
		// to BEFORE c did not carry. The partner picked to be checked
		// beside c is not that: c is the route the pass meant to try,
		// it worked at its first attempt, and the partner failing
		// beside it is not something the engine moved on from.
		for _, a := range tried {
			if a.failed() && !(a.second && a.racedWith != "" && a.racedWith == c.id) {
				return AutoVerdictMovedOn, refined
			}
		}
		return AutoVerdictNone, refined
	}
	if fails == 0 {
		// Every candidate was refused between the listing and its turn
		// (a family cooldown tripped by an earlier candidate).
		return AutoVerdictAllFailed, refined
	}

	all := func(pred func(i int, a autoObs) bool) bool {
		for i, a := range tried {
			if a.failed() && !pred(i, a) {
				return false
			}
		}
		return true
	}
	count := func(pred func(i int, a autoObs) bool) int {
		n := 0
		for i, a := range tried {
			if a.failed() && pred(i, a) {
				n++
			}
		}
		return n
	}
	switch {
	case all(func(_ int, a autoObs) bool { return a.category == diagnostics.NetworkOffline }):
		return AutoVerdictNetworkDown, refined
	case all(func(i int, a autoObs) bool { return a.synUnanswered() || refined[i] == AutoRefinedRelayUnreachable }):
		return AutoVerdictRelayUnreachable, refined
	case all(func(i int, _ autoObs) bool { return refined[i] == AutoRefinedAddressBlocked }):
		return AutoVerdictAddressBlocked, refined
	case count(func(i int, _ autoObs) bool { return refined[i] == AutoRefinedNameBlocked }) > 0 &&
		all(func(i int, a autoObs) bool { return refined[i] == AutoRefinedNameBlocked || a.pastHandshake() }):
		return AutoVerdictNameBlocked, refined
	case count(func(_ int, a autoObs) bool { return a.udp }) > 0 &&
		all(func(i int, a autoObs) bool {
			if a.udp {
				return refined[i] == AutoRefinedUDPBlockedHere
			}
			return a.tcpReached()
		}):
		return AutoVerdictUDPBlockedHere, refined
	}
	return AutoVerdictAllFailed, refined
}

// verdictWithoutCandidates is the verdict of a pass that had nothing to
// try: routes is how many routes the person holds, left the ones that
// were refused.
func verdictWithoutCandidates(routes int, left []AutoTried) string {
	if routes == 0 {
		return AutoVerdictNoRoutes
	}
	var needNew, dead, cooling, other int
	for _, l := range left {
		switch l.Refused {
		case ConnectRefusedNeedsNewFile:
			needNew++
		case ConnectRefusedRevoked, ConnectRefusedExpired:
			dead++
		case ConnectRefusedCooldown:
			cooling++
		default:
			other++
		}
	}
	switch {
	case cooling > 0:
		// Waiting helps, whatever the others are.
		return AutoVerdictAllCoolingDown
	case other > 0 || needNew+dead == 0:
		return AutoVerdictNoneUsable
	case needNew == 0:
		return AutoVerdictAllExpiredOrRevoked
	}
	// Only a new file helps: every route needs one, or is revoked or
	// expired beside ones that do.
	return AutoVerdictAllNeedNewFile
}
