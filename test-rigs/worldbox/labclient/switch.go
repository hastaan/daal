//go:build singbox && cgo && linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"daal/core/abi"
)

// switch.go is the phone's ROUTE SWITCH: one tap on another route's
// Connect while a route is up. The first real-phone pass (2026-11-19)
// did exactly that and ended with the tunnel carrying traffic and every
// store-backed screen dead; nothing in the rig had ever switched a route
// on a real TUN, so nothing here could have seen it.
//
// What the phone did then, and what the engine did with it:
//
//	Builder.establish()        a second TUN (fd N2) while route A runs on N
//	engine_set_tun_fd(N2)      the engine closed N — with A's sing-box
//	                           instance still reading it
//	  … the app's next open() gets the free number N …
//	engine_set_route(B)        tearing A's instance down closed N AGAIN:
//	                           somebody else's file
//
// and the same pair of closes on every disconnect (clear_route through
// the instance, then clear_tun_fd). The engine now gives each sing-box
// instance its own duplicate (core/engine/platform.go, "ONE OWNER PER
// COPY"); this file is the check that it stays that way, on a real TUN,
// through the same abi calls in the same order.
//
// Three orders, because the Android service has had two and the rig
// found a reason for a third:
//
//	rotate        establish a new TUN → SetTunFD(new) → SetRoute(B), no
//	              ClearRoute first. The order of the phone pass, and the
//	              harshest for fds: the only one in which the engine
//	              closes a TUN fd while an instance is up.
//	keep          RouteConnectPrecheck(B) → (refused: touch nothing) →
//	              SetRoute(B) on the TUN already held. The order
//	              vpn/StartSequence.kt settled on after that pass — and
//	              the one in which the old instance's packet reader and
//	              the new one share a TUN (FINDINGS SW-2).
//	check-rotate  RouteConnectPrecheck(B) → (refused: touch nothing) →
//	              new TUN → SetTunFD(new) → SetRoute(B): a refused switch
//	              costs nothing, and no two instances ever read one TUN.
//
// The trap for the double close is a handful of SENTINEL files: plain
// fds the "app" opens at the moments the phone's own files were opened
// (before the switch, between the rotate and the switch, between
// clear_route and clear_tun_fd) and then checks — still open, still the
// same file, still writable. In the rotate order one of them is made to
// land on the old TUN's number, which is where the phone's database file
// landed.

// sentinel is one fd the app owns and the engine has no business with.
type sentinel struct {
	fd       int
	dev, ino uint64
	when     string
}

type sentinels struct {
	dir  string
	seq  int
	open []*sentinel
}

func newSentinels(stateDir string) *sentinels {
	// Beside the engine's state directory, never inside it.
	return &sentinels{dir: filepath.Join(filepath.Dir(stateDir), filepath.Base(stateDir)+".sentinels")}
}

// add opens n sentinel files. With wantFD >= 0 it keeps opening (up to
// 64) until one of them has that number, and reports whether one did:
// open() returns the lowest free number, so a number the engine has just
// closed is taken within a few opens unless something else took it first.
func (s *sentinels) add(when string, n, wantFD int) (landed bool) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return false
	}
	for i := 0; i < n || (wantFD >= 0 && !landed && i < 64); i++ {
		s.seq++
		fd, err := syscall.Open(filepath.Join(s.dir, fmt.Sprintf("s%04d", s.seq)), syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC, 0o600)
		if err != nil {
			return landed
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			syscall.Close(fd)
			return landed
		}
		s.open = append(s.open, &sentinel{fd: fd, dev: uint64(st.Dev), ino: st.Ino, when: when})
		landed = landed || fd == wantFD
	}
	return landed
}

// verify checks every sentinel still open and returns one line per
// casualty. Order matters: identity first, and a write only to an fd
// that is still OUR file — a number closed underneath us may by now be
// the engine's database, and writing a test token into that would be the
// rig damaging what it is checking.
func (s *sentinels) verify() (bad []string) {
	alive := s.open[:0]
	defer func() { s.open = alive }()
	for _, x := range s.open {
		// A casualty is reported once and then forgotten: its number is
		// no longer ours to look at, let alone close.
		var st syscall.Stat_t
		if err := syscall.Fstat(x.fd, &st); err != nil {
			bad = append(bad, fmt.Sprintf("fd %d (opened %s) was closed underneath its owner: fstat: %v", x.fd, x.when, err))
			continue
		}
		if uint64(st.Dev) != x.dev || st.Ino != x.ino {
			bad = append(bad, fmt.Sprintf("fd %d (opened %s) is no longer the file its owner opened: it was closed underneath them and the number reused", x.fd, x.when))
			continue
		}
		alive = append(alive, x)
		token := []byte(fmt.Sprintf("sentinel %d %d", x.fd, time.Now().UnixNano()))
		back := make([]byte, len(token))
		if _, err := syscall.Pwrite(x.fd, token, 0); err != nil {
			bad = append(bad, fmt.Sprintf("fd %d (opened %s): write: %v", x.fd, x.when, err))
		} else if n, err := syscall.Pread(x.fd, back, 0); err != nil || n != len(token) || string(back) != string(token) {
			bad = append(bad, fmt.Sprintf("fd %d (opened %s): read back %d bytes (%v), not what was written", x.fd, x.when, n, err))
		}
	}
	return bad
}

// release closes the sentinels that are still verifiably ours and
// forgets all of them (a casualty's number is not ours to close).
func (s *sentinels) release() {
	for _, x := range s.open {
		var st syscall.Stat_t
		if syscall.Fstat(x.fd, &st) == nil && uint64(st.Dev) == x.dev && st.Ino == x.ino {
			syscall.Close(x.fd)
		}
	}
	s.open = nil
	_ = os.RemoveAll(s.dir)
}

// storeChecks is what the app's pages ask the engine after a switch —
// every call below reads the route store, except ExportDiagnostics'
// active_route, which must not. A store that died under a double close
// fails them; the tunnel does not notice.
func storeChecks(routeID string) map[string]any {
	res := map[string]any{}
	var failed []string
	note := func(call string, err error) {
		if err != nil {
			res[call] = err.Error()
			failed = append(failed, call)
		}
	}
	_, err := abi.SubscriptionList()
	note("subscription_list", err)
	routes, err := abi.AvailableRoutes()
	note("available_routes", err)
	var doc struct {
		Routes []map[string]any `json:"routes"`
	}
	_ = json.Unmarshal([]byte(routes), &doc)
	res["routes_listed"] = len(doc.Routes)
	if routeID != "" {
		_, err = abi.RouteSummary(routeID)
		note("route_summary", err)
	}
	explain, err := abi.DiagnosticsExplain()
	note("diagnostics_explain", err)
	res["explain"] = rawJSON(explain)
	diag, err := abi.ExportDiagnostics()
	note("export_diagnostics", err)
	res["diag"] = rawJSON(diag)
	res["failed"] = failed
	return res
}

// poller is the app's pages polling while the switch is in flight: the
// same four calls, every 25 ms, from another thread. On the phone these
// were the calls that started failing; a single error here is a red
// check.
type poller struct {
	stop  chan struct{}
	done  chan struct{}
	mu    sync.Mutex
	calls int
	errs  int
	first string
}

func startPoller() *poller {
	p := &poller{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		t := time.NewTicker(25 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
			}
			for name, call := range map[string]func() (string, error){
				"diagnostics_explain": abi.DiagnosticsExplain, "export_diagnostics": abi.ExportDiagnostics,
				"available_routes": abi.AvailableRoutes, "subscription_list": abi.SubscriptionList,
			} {
				_, err := call()
				p.mu.Lock()
				p.calls++
				if err != nil {
					p.errs++
					if p.first == "" {
						p.first = name + ": " + err.Error()
					}
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}

func (p *poller) finish() map[string]any {
	close(p.stop)
	<-p.done
	return map[string]any{"calls": p.calls, "errors": p.errs, "first_error": p.first}
}

// session is the VPN the lab client currently holds.
type session struct {
	vpn     *vpn
	routeID string
	tunSeq  int
	tunBase string
	sent    *sentinels
}

// doSwitch performs one route switch and emits one "switched" event,
// whatever happened: a switch that does not take is an outcome the
// driver judges, not the end of the process.
func (s *session) doSwitch(mode, family string) {
	ev := map[string]any{"mode": mode, "family": family, "from": s.routeID, "attempted": false}
	fail := func(stage string, err error) {
		ev["stage"], ev["error"] = stage, err.Error()
		ev["store"] = storeChecks(s.routeID)
		ev["sentinels_bad"] = s.sent.verify()
		emit("switched", ev)
	}
	routesJSON, err := abi.AvailableRoutes()
	if err != nil {
		fail("routes", err)
		return
	}
	to, err := pickRoute(routesJSON, family)
	if err != nil {
		fail("pick", err)
		return
	}
	ev["to"] = to

	// Files the app already had open when the person tapped.
	s.sent.add("before the switch", 4, -1)

	armed := false
	if mode == "keep" || mode == "check-rotate" {
		pre, err := abi.RouteConnectPrecheck(to)
		if err != nil {
			fail("precheck", err)
			return
		}
		ev["precheck"] = rawJSON(pre)
		var ans struct {
			Refused string `json:"refused"`
		}
		_ = json.Unmarshal([]byte(pre), &ans)
		if ans.Refused != "" {
			// Refused before anything was touched: the route that was
			// connected is left exactly as it was.
			ev["refused"] = ans.Refused
			ev["stage"] = "precheck"
			ev["store"] = storeChecks(s.routeID)
			ev["sentinels_bad"] = s.sent.verify()
			emit("switched", ev)
			return
		}
	}
	oldTun := ""
	switch mode {
	case "rotate", "check-rotate":
		s.tunSeq++
		next, err := establishReplacing(fmt.Sprintf("%s%d", s.tunBase, s.tunSeq))
		if err != nil {
			fail("tun", err)
			return
		}
		old := s.vpn.fd
		oldTun = s.vpn.name
		if _, err := abi.SetTunFD(next.fd); err != nil {
			syscall.Close(next.fd)
			_ = ip("route", "replace", "default", "dev", s.vpn.name, "table", vpnTable)
			fail("set_tun_fd", err)
			return
		}
		s.vpn = next
		ev["old_tun_fd"], ev["new_tun_fd"] = old, next.fd
		// The window the phone's database file was opened in: the engine
		// has let go of the old TUN's number, route A's instance is still
		// up, and route B has not been asked for yet.
		armed = s.sent.add("between the TUN rotate and the switch", 4, old)
	case "keep":
		s.sent.add("between the pre-check and the switch", 4, -1)
	default:
		fail("mode", fmt.Errorf("unknown switch mode %q (rotate | keep | check-rotate)", mode))
		return
	}
	ev["fd_trap_armed"] = armed

	ev["attempted"] = true
	poll := startPoller()
	t0 := time.Now()
	serr := abi.SetRoute(to)
	ev["set_route_ms"] = time.Since(t0).Milliseconds()
	ev["poll"] = poll.finish()
	after := to
	if serr != nil {
		// "proof": the engine started B, could not carry a round trip
		// through it and stopped it. Anything else: it refused B without
		// starting anything.
		ev["stage"] = "set_route"
		if errors.Is(serr, abi.ErrRouteNotCarrying) {
			ev["stage"] = "proof"
		}
		ev["error"] = serr.Error()
		after = s.routeID
	} else {
		s.routeID = to
	}
	ev["sentinels_bad"] = s.sent.verify()
	ev["store"] = storeChecks(after)
	if oldTun != "" {
		// The interface the switch replaced lives exactly as long as
		// something in this process still holds it open.
		// (Unregistering a device is not instant; half a second is.)
		gone := false
		for i := 0; i < 10 && !gone; i++ {
			if gone = ip("link", "show", "dev", oldTun) != nil; !gone {
				time.Sleep(50 * time.Millisecond)
			}
		}
		ev["old_tun"], ev["old_tun_gone"] = oldTun, gone
	}
	emit("switched", ev)
}

// disconnect is the service's teardown — clear_route, clear_tun_fd, the
// routing — with the same trap between the two engine calls, and the
// app's pages asked once more afterwards: the store must have survived
// the disconnect as well as the switch.
func (s *session) disconnect() (cerr error, after map[string]any) {
	last := s.routeID
	cerr = abi.ClearRoute()
	s.sent.add("between clear_route and clear_tun_fd", 4, -1)
	_, _ = abi.ClearTunFD()
	s.sent.add("after clear_tun_fd", 2, -1)
	s.vpn.teardown()
	after = storeChecks(last)
	after["sentinels_bad"] = s.sent.verify()
	s.sent.release()
	return cerr, after
}
