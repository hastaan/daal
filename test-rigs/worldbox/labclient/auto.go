//go:build singbox && cgo && linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"daal/core/abi"
)

// auto.go is the phone whose person presses the one button: "connect",
// no route named (engine_connect_auto). The second real-phone pass
// (2026-11-19) had a file with four routes on the phone and a main
// screen whose button did not connect; picking among protocol names by
// hand was the only way in. The engine now picks, tries, moves on and
// remembers, and this file is the host half of that, in the order the
// Android service uses (vpn/StartSequence.kt runAuto):
//
//	protect            registered once, before anything
//	TUN                built only when none is held
//	engine_connect_auto   blocking; the engine tries route after route
//	                   in the SAME TUN
//	connected          stay; the engine is in charge of moving on
//	not connected,
//	nothing running    clear_route, clear_tun_fd, routing removed
//
// Unlike every other session of this rig the process stays up across
// connects and disconnects (--auto, commands on stdin), because what the
// engine remembers about this network and what it leaves running after a
// failed pass are exactly the things under test:
//
//	auto                press Connect
//	auto-cancel <ms>    press Connect, and Cancel <ms> later: the
//	                    service's clearRoute, repeated every 100 ms while
//	                    the call is in flight (DaalVpnService.cancelInFlight)
//	auto-net <kind> <id|-> <validated> <metered>
//	                    press Connect while the service's network callback
//	                    reports the network: engine_network_facts on ANOTHER
//	                    thread at the moment the connect starts, which is
//	                    how DaalVpnService does it (startNetworkWatch in
//	                    beginStart, its own thread `daal-vpn-network`)
//	net <kind> <id|-> <validated> <metered>
//	                    the callback alone: the phone moved to another
//	                    network, or the platform changed its mind about this
//	                    one. `-` is the empty id
//	connect <family>    pick one route by hand (engine_set_route)
//	listing             what the Connections page reads: the route list and
//	                    the connected route's summary (the `measured` block)
//	res                 what the process holds: open files and goroutines
//	disconnect          the person disconnects; the process stays
//	diag                the engine's diagnostics and the app's open files,
//	                    with NO other call into the engine: what a phone
//	                    lying on a table does
//	stop                disconnect if up, and exit
//
// Every answer carries the same store and fd checks a switch does
// (switch.go): a pass starts and stops up to one engine instance per
// route on one TUN, which is the SW-0 situation several times over.

type phone struct {
	tunBase string
	tunSeq  int
	vpn     *vpn // nil: no TUN held
	routeID string
	sent    *sentinels
}

// tun builds the TUN if none is held and hands it to the engine.
func (p *phone) tun() (built bool, err error) {
	if p.vpn != nil {
		return false, nil
	}
	p.tunSeq++
	v, err := establish(fmt.Sprintf("%s%d", p.tunBase, p.tunSeq))
	if err != nil {
		return false, err
	}
	if _, err := abi.SetTunFD(v.fd); err != nil {
		v.teardown()
		return false, err
	}
	p.vpn = v
	return true, nil
}

// down is the service's teardown: clear_route, clear_tun_fd, routing.
func (p *phone) down() error {
	cerr := abi.ClearRoute()
	p.sent.add("between clear_route and clear_tun_fd", 4, -1)
	if p.vpn != nil {
		_, _ = abi.ClearTunFD()
		p.vpn.teardown()
		p.vpn = nil
	}
	p.sent.add("after clear_tun_fd", 2, -1)
	p.routeID = ""
	return cerr
}

// autoProgress polls the `auto` block of the diagnostics while a pass is
// in flight and keeps every distinct (state, trying, index, total) it
// saw, in order: what a page polling the engine would have had to show.
type autoProgress struct {
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	seen []map[string]any
}

func startAutoProgress() *autoProgress {
	p := &autoProgress{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		t := time.NewTicker(40 * time.Millisecond)
		defer t.Stop()
		last, t0 := "", time.Now()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
			}
			d, err := abi.ExportDiagnostics()
			if err != nil {
				continue
			}
			var doc struct {
				Auto map[string]any `json:"auto"`
			}
			if json.Unmarshal([]byte(d), &doc) != nil || doc.Auto == nil {
				continue
			}
			key := fmt.Sprintf("%v|%v|%v|%v|%v", doc.Auto["state"], doc.Auto["trying"], doc.Auto["index"], doc.Auto["total"], doc.Auto["racing"])
			if key == last {
				continue
			}
			last = key
			p.mu.Lock()
			p.seen = append(p.seen, map[string]any{"state": doc.Auto["state"], "trying": doc.Auto["trying"],
				"index": doc.Auto["index"], "total": doc.Auto["total"], "mode": doc.Auto["mode"], "racing": doc.Auto["racing"],
				"ms": time.Since(t0).Milliseconds()})
			p.mu.Unlock()
		}
	}()
	return p
}

func (p *autoProgress) finish() []map[string]any {
	close(p.stop)
	<-p.done
	return p.seen
}

// hostNet is one report of the service's network callback.
type hostNet struct {
	kind, id           string
	validated, metered int
}

// parseHostNet reads `<kind> <id|-> <validated> <metered>`.
func parseHostNet(f []string) (*hostNet, error) {
	if len(f) != 4 {
		return nil, errors.New("want <kind> <id|-> <validated> <metered>")
	}
	n := &hostNet{kind: f[0], id: f[1]}
	if n.id == "-" {
		n.id = ""
	}
	var err error
	if n.validated, err = strconv.Atoi(f[2]); err != nil {
		return nil, err
	}
	if n.metered, err = strconv.Atoi(f[3]); err != nil {
		return nil, err
	}
	return n, nil
}

// report is the engine call. The answer goes into the event as the
// engine gave it; the id that was sent does NOT (the driver greps
// everything this process wrote for it).
func (n *hostNet) report() map[string]any {
	t0 := time.Now()
	body, err := abi.NetworkFacts(n.kind, n.id, n.validated, n.metered)
	return map[string]any{"kind": n.kind, "id_set": n.id != "", "validated": n.validated, "metered": n.metered,
		"answer": rawJSON(body), "error": errString(err), "ms": time.Since(t0).Milliseconds()}
}

// held is what the process holds right now: its open files (the
// sentinels, which are the lab's own, taken off) and its goroutines —
// all of them, and those with a sing-box frame on their stack. A side
// instance that was not torn down shows in both.
func (p *phone) held() map[string]any {
	kinds := map[string]int{}
	total := 0
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		for _, e := range ents {
			target, err := os.Readlink("/proc/self/fd/" + e.Name())
			if err != nil {
				continue // the directory handle of this very listing
			}
			total++
			k := "file"
			switch {
			case strings.HasPrefix(target, "socket:"):
				k = "socket"
			case strings.HasPrefix(target, "pipe:"):
				k = "pipe"
			case strings.HasPrefix(target, "anon_inode:"):
				k = strings.TrimPrefix(target, "anon_inode:")
			case strings.HasPrefix(target, "/dev/net/tun"):
				k = "tun"
			}
			kinds[k]++
		}
	}
	buf := make([]byte, 4<<20)
	buf = buf[:runtime.Stack(buf, true)]
	box := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "github.com/sagernet/") {
			box++
		}
	}
	return map[string]any{"fds": total - len(p.sent.open), "fd_kinds": kinds, "sentinels": len(p.sent.open),
		"goroutines": runtime.NumGoroutine(), "goroutines_box": box}
}

// auto is one press of Connect. cancelAfter >= 0: Cancel is pressed that
// long after it. net != nil: the service's network callback reports at
// the same moment, on its own thread.
func (p *phone) auto(cancelAfter time.Duration, net *hostNet) {
	ev := map[string]any{"cancel_after_ms": cancelAfter.Milliseconds()}
	p.sent.add("before the connect", 4, -1)
	built, err := p.tun()
	if err != nil {
		ev["stage"], ev["error"] = "tun", err.Error()
		ev["sentinels_bad"] = p.sent.verify()
		emit("auto", ev)
		return
	}
	ev["tun_built"] = built
	p.sent.add("between the TUN and the connect", 4, -1)

	poll, progress := startPoller(), startAutoProgress()
	t0 := time.Now()
	type answer struct {
		body string
		err  error
		at   time.Time
	}
	ch := make(chan answer, 1)
	netDone := make(chan map[string]any, 1)
	if net != nil {
		go func() { netDone <- net.report() }()
	}
	go func() {
		body, err := abi.ConnectAuto()
		ch <- answer{body, err, time.Now()}
	}()
	var ans answer
	if cancelAfter < 0 {
		ans = <-ch
	} else {
		select {
		case ans = <-ch: // it was over before the person reached the button
			ev["cancelled_in_flight"] = false
		case <-time.After(cancelAfter):
			ev["cancelled_in_flight"] = true
			tCancel := time.Now()
			clears := 0
			tick := time.NewTicker(100 * time.Millisecond)
		waiting:
			for {
				clears++
				_ = abi.ClearRoute()
				select {
				case ans = <-ch:
					break waiting
				case <-tick.C:
				}
			}
			tick.Stop()
			ev["cancel_to_return_ms"], ev["clear_route_calls"] = ans.at.Sub(tCancel).Milliseconds(), clears
		}
	}
	ev["auto_ms"] = time.Since(t0).Milliseconds()
	if net != nil {
		ev["net"] = <-netDone
	}
	ev["progress"] = progress.finish()
	ev["poll"] = poll.finish()
	var res struct {
		Connected bool   `json:"connected"`
		RouteID   string `json:"route_id"`
	}
	if ans.err != nil {
		ev["error"] = ans.err.Error()
	} else {
		ev["result"] = rawJSON(ans.body)
		_ = json.Unmarshal([]byte(ans.body), &res)
	}
	p.routeID = ""
	if res.Connected {
		p.routeID = res.RouteID
	}
	ev["sentinels_bad"] = p.sent.verify()
	ev["store"] = storeChecks(res.RouteID)
	// What the service does with a connect that did not come up: if the
	// engine still has a route running it stays on it (SwitchPolicy
	// afterFailedAuto "Keep"); otherwise the plumbing goes.
	running := false
	if d, _ := abi.ExportDiagnostics(); d != "" {
		var doc struct {
			Running bool   `json:"route_running"`
			Active  string `json:"active_route"`
		}
		_ = json.Unmarshal([]byte(d), &doc)
		running = doc.Running
		if !res.Connected && running {
			p.routeID = doc.Active
		}
	}
	ev["torn_down"] = false
	if !res.Connected && !running {
		cerr := p.down()
		ev["torn_down"], ev["teardown_error"] = true, errString(cerr)
		after := storeChecks("")
		after["sentinels_bad"] = p.sent.verify()
		ev["after_teardown"] = after
	}
	ev["tun"] = p.tunName()
	emit("auto", ev)
}

func (p *phone) tunName() string {
	if p.vpn == nil {
		return ""
	}
	return p.vpn.name
}

// byHand is the person picking one route themselves: engine_set_route on
// a TUN built for it when none is held.
func (p *phone) byHand(family string) {
	ev := map[string]any{"family": family}
	fail := func(stage string, err error) {
		ev["stage"], ev["error"] = stage, err.Error()
		ev["store"] = storeChecks("")
		ev["sentinels_bad"] = p.sent.verify()
		emit("set", ev)
	}
	routesJSON, err := abi.AvailableRoutes()
	if err != nil {
		fail("routes", err)
		return
	}
	id, err := pickRoute(routesJSON, family)
	if err != nil {
		fail("pick", err)
		return
	}
	ev["route_id"] = id
	if _, err := p.tun(); err != nil {
		fail("tun", err)
		return
	}
	t0 := time.Now()
	if err := abi.SetRoute(id); err != nil {
		stage := "set_route"
		if errors.Is(err, abi.ErrRouteNotCarrying) {
			stage = "proof"
		}
		_ = p.down()
		fail(stage, err)
		return
	}
	p.routeID = id
	ev["set_route_ms"] = time.Since(t0).Milliseconds()
	ev["store"] = storeChecks(id)
	ev["sentinels_bad"] = p.sent.verify()
	emit("set", ev)
}

func autoLoop(sc *bufio.Scanner, stateDir, tunBase string, protectCalls func() int) {
	p := &phone{tunBase: tunBase, sent: newSentinels(stateDir)}
	emit("ready", nil)
	why := "eof"
loop:
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "auto":
			p.auto(-1, nil)
		case "auto-cancel":
			ms := 1000
			if len(f) > 1 {
				ms, _ = strconv.Atoi(f[1])
			}
			p.auto(time.Duration(ms)*time.Millisecond, nil)
		case "auto-net":
			n, err := parseHostNet(f[1:])
			if err != nil {
				emit("auto", map[string]any{"stage": "net", "error": err.Error()})
				continue
			}
			p.auto(-1, n)
		case "net":
			n, err := parseHostNet(f[1:])
			if err != nil {
				emit("net", map[string]any{"error": err.Error()})
				continue
			}
			emit("net", n.report())
		case "listing":
			routes, rerr := abi.AvailableRoutes()
			ev := map[string]any{"routes": rawJSON(routes), "error": errString(rerr), "active": p.routeID}
			if p.routeID != "" {
				sum, serr := abi.RouteSummary(p.routeID)
				ev["summary"], ev["summary_error"] = rawJSON(sum), errString(serr)
			}
			d, _ := abi.ExportDiagnostics()
			ev["diag"] = rawJSON(d)
			emit("listing", ev)
		case "res":
			emit("res", p.held())
		case "standby-key":
			// The person types the 26 characters they were sent
			// (engine_standby_key; standby_key.go). "-" = every held file.
			emit("standby-key", standbyKeyCmd(f[1:]))
		case "connect":
			if len(f) < 2 {
				emit("set", map[string]any{"stage": "pick", "error": "connect needs a family"})
				continue
			}
			p.byHand(f[1])
		case "disconnect":
			last := p.routeID
			cerr := p.down()
			after := storeChecks(last)
			after["sentinels_bad"] = p.sent.verify()
			emit("down", map[string]any{"error": errString(cerr), "after": after})
		case "diag":
			d, _ := abi.ExportDiagnostics()
			emit("diag", map[string]any{"diag": rawJSON(d), "tun": p.tunName(), "sentinels_bad": p.sent.verify(), "protect_calls": protectCalls(), "held": p.held()})
		case "stop":
			why = "stop"
			break loop
		}
	}
	diag, _ := abi.ExportDiagnostics()
	explain, _ := abi.DiagnosticsExplain()
	last := p.routeID
	cerr := p.down()
	after := storeChecks(last)
	after["sentinels_bad"] = p.sent.verify()
	p.sent.release()
	routesAfter, _ := abi.AvailableRoutes()
	emit("disconnected", map[string]any{"after": after, "explain": rawJSON(explain), "routes_after": rawJSON(routesAfter),
		"why": why, "error": errString(cerr), "protect_calls": protectCalls(), "diag": rawJSON(diag)})
	abi.Shutdown()
}
