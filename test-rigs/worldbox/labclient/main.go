//go:build singbox && cgo && linux

package main

/*
#include <stdint.h>
#include <sys/socket.h>

// The lab's VpnService.protect(), registered because the phone registers
// one (DaalVpnService step 1). It tags the socket the way Android's does
// and counts calls. Nothing in the lab's routing depends on the tag: see
// vpnservice.go for what actually keeps the engine out of its own tunnel.
static volatile int wb_protect_calls = 0;

static int wb_protect(int fd) {
	unsigned int mark = 0xDAA1;
	__sync_fetch_and_add(&wb_protect_calls, 1);
	return setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0 ? 1 : 0;
}

static uintptr_t wb_protect_ptr(void) { return (uintptr_t)wb_protect; }
static int wb_protect_count(void) { return wb_protect_calls; }
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"daal/core/abi"
	"daal/core/desync"
	"daal/core/diagnostics"
	"daal/core/engine"
)

var out = json.NewEncoder(os.Stdout)

// emit writes one event line. The driver reads these; nothing else is
// printed on stdout.
func emit(event string, kv map[string]any) {
	if kv == nil {
		kv = map[string]any{}
	}
	kv["event"] = event
	kv["t"] = time.Now().UTC().Format(time.RFC3339Nano)
	_ = out.Encode(kv)
}

func fatal(stage string, err error) {
	kv := map[string]any{"stage": stage, "error": err.Error()}
	if stage == "set_route" || stage == "proof" {
		// What the engine itself says about the attempt it just refused
		// or failed (the driver's engine.category check reads this).
		exp, _ := abi.DiagnosticsExplain()
		diag, _ := abi.ExportDiagnostics()
		kv["explain"], kv["diag"] = rawJSON(exp), rawJSON(diag)
	}
	emit("error", kv)
	abi.Shutdown()
	os.Exit(1)
}

func rawJSON(s string) any {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	return v
}

func main() {
	stateDir := flag.String("state-dir", "", "engine state directory (fresh per attempt)")
	pack := flag.String("pack", "", "signed pack (.sbp) to import")
	family := flag.String("family", "", "transport family to activate (matched against the engine's own route list)")
	routeID := flag.String("route-id", "", "activate this exact route instead of matching --family")
	tunName := flag.String("tun", "daal-tun", "TUN interface name")
	experimental := flag.Bool("experimental", false, "turn on the engine's experimental-families gate, as the user would in Settings")
	importOnly := flag.Bool("import-only", false, "import, list routes, exit")
	idle := flag.Bool("idle", false, "after import, do NOT connect: wait for commands on stdin (tick | routes | connect <family> | stop). A phone that holds a pack and is not connected")
	proofTargets := flag.String("proof-targets", "", "comma list of host:port: what the engine's connection check reaches through the tunnel. Written to the engine's own configuration file (engine-config.json, connection_check.targets) before engine_init, as an operator would; empty leaves the engine on its production default")
	auto := flag.Bool("auto", false, "after import, wait for commands on stdin and connect the way the main screen's one button does: `auto` is engine_connect_auto, no route named (auto.go)")
	livenessS := flag.Int("liveness-s", 0, "connection_check.liveness_interval_s in the engine's configuration file: how often the engine re-checks the connected route. 0 leaves the production default (180 s)")
	recheckS := flag.Int("recheck-s", 0, "connection_check.recheck_interval_s in the engine's configuration file. 0 leaves the production default (30 s)")
	desyncJSON := flag.String("desync", "", "a core/desync strategy (JSON, e.g. {\"preset\":\"sni-cut\"}) turned on for the route before it connects — what the selection ladder does for a network (engine.SetRouteDesync). Empty: off")
	classify := flag.Bool("classify", false, "read error texts on stdin, one per line; print the product classifier's category for each (core/diagnostics.Classify) and exit")
	features := flag.Bool("features", false, "print the build-tag-gated host calls this binary has (standby_key.go) and exit")
	flag.Parse()
	if *features {
		fmt.Println(strings.Join(clientFeatures, " "))
		return
	}
	if *classify {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			_ = out.Encode(map[string]any{"text": sc.Text(), "category": string(diagnostics.Classify(sc.Text()))})
		}
		return
	}
	if *stateDir == "" || *pack == "" {
		fmt.Fprintln(os.Stderr, "usage: wb-client --state-dir D --pack P (--family F | --route-id R)")
		os.Exit(2)
	}

	// The engine's connection check needs a host on the far side of the
	// relay. Its production default is a set of public sites, which do
	// not exist in the lab; the lab names its own through the engine's
	// ordinary configuration file. Nothing else about the check changes.
	if *proofTargets != "" || *livenessS > 0 || *recheckS > 0 {
		cc := map[string]any{}
		if *proofTargets != "" {
			cc["targets"] = strings.Split(*proofTargets, ",")
		}
		// The two clocks of the engine's own liveness loop, through the
		// same file an operator would use. Nothing else about the loop
		// changes: a rig that waited the production three minutes for
		// every "the route stopped carrying" would not be run.
		if *livenessS > 0 {
			cc["liveness_interval_s"] = *livenessS
		}
		if *recheckS > 0 {
			cc["recheck_interval_s"] = *recheckS
		}
		cfg, _ := json.Marshal(map[string]any{"connection_check": cc})
		if err := os.WriteFile(filepath.Join(*stateDir, abi.EngineConfigFile), cfg, 0o600); err != nil {
			emit("error", map[string]any{"stage": "init", "error": err.Error()})
			os.Exit(1)
		}
	}
	if err := abi.Init(*stateDir, "warn"); err != nil {
		emit("error", map[string]any{"stage": "init", "error": err.Error()})
		os.Exit(1)
	}
	emit("init", map[string]any{"version": abi.VersionString(), "data_plane": abi.DataPlaneKind()})

	// --- import, exactly as the app does: verdict, then the trust prompt.
	verdictJSON, err := abi.ImportSBP(*pack)
	verdict := parseVerdict(verdictJSON)
	emit("import", map[string]any{"kind": verdict.kind(), "reason": verdict.Reason, "route_count": verdict.RouteCount,
		"verdict": rawJSON(verdictJSON), "error": errString(err)})
	switch verdict.Kind {
	case 1: // first-seen publisher: the user reads the fingerprint words and taps Trust
		resJSON, rerr := abi.ResolveTrustPrompt(verdict.Fingerprint, 0)
		res := parseVerdict(resJSON)
		emit("trust", map[string]any{"kind": res.kind(), "reason": res.Reason, "verdict": rawJSON(resJSON), "error": errString(rerr)})
		if rerr != nil || res.Kind == 3 {
			fatal("trust", fmt.Errorf("%s %s", res.Reason, errString(rerr)))
		}
	case 3:
		fatal("import", fmt.Errorf("rejected: %s %s", verdict.Reason, errString(err)))
	default:
		if err != nil {
			fatal("import", err)
		}
	}

	if *experimental {
		abi.SetExperimentalFamiliesEnabled(true)
	}

	routesJSON, err := abi.AvailableRoutes()
	if err != nil {
		fatal("routes", err)
	}
	emit("routes", map[string]any{"routes": rawJSON(routesJSON)})
	if *importOnly {
		abi.Shutdown()
		return
	}

	// One reader for stdin for the whole life of the process: a second
	// bufio.Scanner would lose whatever the first had buffered.
	stdin := bufio.NewScanner(os.Stdin)
	if *idle {
		fam, ok := idleLoop(stdin)
		if !ok {
			abi.Shutdown()
			return
		}
		*family = fam
		if routesJSON, err = abi.AvailableRoutes(); err != nil {
			fatal("routes", err)
		}
	}

	if *auto {
		if _, err := abi.RegisterProtectCallback(uintptr(C.wb_protect_ptr())); err != nil {
			fatal("protect", err)
		}
		autoLoop(stdin, *stateDir, *tunName, func() int { return int(C.wb_protect_count()) })
		return
	}

	id := *routeID
	if id == "" {
		id, err = pickRoute(routesJSON, *family)
		if err != nil {
			fatal("pick", err)
		}
	}

	// --- the VpnService half.
	if _, err := abi.RegisterProtectCallback(uintptr(C.wb_protect_ptr())); err != nil {
		fatal("protect", err)
	}
	vpn, err := establish(*tunName)
	if err != nil {
		fatal("tun", err)
	}
	if _, err := abi.SetTunFD(vpn.fd); err != nil {
		vpn.teardown()
		fatal("set_tun_fd", err)
	}

	// The selection ladder's half of hello desync: a strategy for THIS
	// route, set before it connects. The engine builds the route's
	// config with the daal-desync detour from it (core/engine desync.go).
	// A strategy the engine refuses is a refused route, not a blocked one.
	if *desyncJSON != "" {
		s, err := desync.ParseStrategy([]byte(*desyncJSON))
		if err == nil {
			err = engine.SetRouteDesync(id, s)
		}
		if err != nil {
			_, _ = abi.ClearTunFD()
			vpn.teardown()
			fatal("set_route", fmt.Errorf("desync strategy refused: %w", err))
		}
		emit("desync", map[string]any{"route_id": id, "strategy": rawJSON(*desyncJSON)})
	}

	events := abi.Subscribe()
	go func() {
		for ev := range events {
			emit("engine", map[string]any{"engine_event": ev})
		}
	}()

	t0 := time.Now()
	if err := abi.SetRoute(id); err != nil {
		_, _ = abi.ClearTunFD()
		vpn.teardown()
		// "proof": the engine started the route, tried to carry a round
		// trip through it and could not — it DIALLED, and was stopped.
		// "set_route": it refused the route without dialling anything.
		stage := "set_route"
		if errors.Is(err, abi.ErrRouteNotCarrying) {
			stage = "proof"
		}
		kv := map[string]any{"stage": stage, "error": err.Error(), "route_id": id, "set_route_ms": time.Since(t0).Milliseconds()}
		exp, _ := abi.DiagnosticsExplain()
		diag, _ := abi.ExportDiagnostics()
		routes, _ := abi.AvailableRoutes()
		kv["explain"], kv["diag"], kv["routes_after"] = rawJSON(exp), rawJSON(diag), rawJSON(routes)
		emit("error", kv)
		abi.Shutdown()
		os.Exit(1)
	}
	emit("connected", map[string]any{"route_id": id, "family": *family, "set_route_ms": time.Since(t0).Milliseconds()})
	sess := &session{vpn: vpn, routeID: id, tunBase: *tunName, sent: newSentinels(*stateDir)}

	// --- stay up until the driver says stop (a line on stdin, EOF, or a signal).
	stop := make(chan string, 2)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; stop <- "signal" }()
	go func() {
		sc := stdin
		for sc.Scan() {
			switch strings.TrimSpace(sc.Text()) {
			case "stop":
				stop <- "stop"
				return
			case "diag":
				d, _ := abi.ExportDiagnostics()
				emit("diag", map[string]any{"diag": rawJSON(d), "protect_calls": int(C.wb_protect_count())})
			default:
				// switch <rotate|keep> <family>: the person taps another
				// route's Connect while this one is up (switch.go). Runs
				// here, so commands are strictly one after another.
				if f := strings.Fields(sc.Text()); len(f) == 3 && f[0] == "switch" {
					sess.doSwitch(f[1], f[2])
				}
			}
		}
		stop <- "eof"
	}()
	why := <-stop

	diag, _ := abi.ExportDiagnostics()
	// The engine's own account of this route, taken while it is still the
	// active one: failures[] is where a classified failure would appear.
	explain, _ := abi.DiagnosticsExplain()
	cerr, after := sess.disconnect()
	routesAfter, _ := abi.AvailableRoutes()
	emit("disconnected", map[string]any{
		"after":        after,
		"explain":      rawJSON(explain),
		"routes_after": rawJSON(routesAfter),
		"why":          why, "error": errString(cerr),
		"protect_calls": int(C.wb_protect_count()),
		"diag":          rawJSON(diag),
	})
	abi.Shutdown()
}

// idleLoop is the phone sitting in a pocket with a pack imported and no
// VPN up. The only thing that happens to the engine in that state is the
// app's periodic scheduler tick — the product's own entry point
// (abi.SchedulerTick), which is what drives every background refresh,
// the freshness poll included. The lab adds nothing to the engine here;
// it calls the tick when told to instead of on a timer.
//
//	tick              one scheduler tick at the current time; reports the
//	                  tick's error, the scheduler's status, and the route
//	                  list afterwards
//	routes            the engine's route list
//	import <file>     the phone is handed ANOTHER file while it already
//	                  holds a pack (the app's own import call); reports
//	                  the verdict and the route list afterwards
//	connect <family>  leave the loop and bring the VPN up on that family
//	stop              exit
func idleLoop(sc *bufio.Scanner) (family string, connect bool) {
	emit("idle", nil)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "tick":
			terr := abi.SchedulerTick(time.Now())
			st, _ := abi.SchedulerStatus()
			routes, _ := abi.AvailableRoutes()
			explain, _ := abi.DiagnosticsExplain()
			emit("tick", map[string]any{"error": errString(terr), "scheduler": rawJSON(st), "routes": rawJSON(routes), "explain": rawJSON(explain)})
		case "routes":
			routes, err := abi.AvailableRoutes()
			emit("routes", map[string]any{"routes": rawJSON(routes), "error": errString(err)})
		case "standby-key":
			emit("standby-key", standbyKeyCmd(f[1:]))
		case "import":
			if len(f) < 2 {
				emit("error", map[string]any{"stage": "idle", "error": "import needs a file"})
				continue
			}
			verdictJSON, ierr := abi.ImportSBP(f[1])
			v := parseVerdict(verdictJSON)
			routes, _ := abi.AvailableRoutes()
			emit("reimport", map[string]any{"kind": v.kind(), "reason": v.Reason, "route_count": v.RouteCount,
				"verdict": rawJSON(verdictJSON), "error": errString(ierr), "routes": rawJSON(routes)})
		case "connect":
			if len(f) < 2 {
				emit("error", map[string]any{"stage": "idle", "error": "connect needs a family"})
				continue
			}
			return f[1], true
		case "stop":
			emit("stopped", map[string]any{"why": "stop"})
			return "", false
		}
	}
	emit("stopped", map[string]any{"why": "eof"})
	return "", false
}

// importVerdict mirrors bundle/go/importer.Verdict as the ABI serialises
// it (Go field names, Kind as an integer).
type importVerdict struct {
	Kind        int
	Fingerprint string
	Reason      string
	RouteCount  int
}

func parseVerdict(s string) importVerdict {
	v := importVerdict{Kind: -1}
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func (v importVerdict) kind() string {
	switch v.Kind {
	case 0:
		return "imported"
	case 1:
		return "trust_prompt"
	case 2:
		return "rotation_accepted"
	case 3:
		return "rejected"
	}
	return "unparsed"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// pickRoute finds the route for one family in the engine's OWN list.
// This is test addressing ("exercise this family"), not route selection:
// it never ranks, and it fails when the family is absent or ambiguous
// rather than choosing.
func pickRoute(routesJSON, family string) (string, error) {
	if family == "" {
		return "", fmt.Errorf("no --family and no --route-id")
	}
	var doc struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal([]byte(routesJSON), &doc); err != nil {
		return "", err
	}
	var hits, seen []string
	for _, r := range doc.Routes {
		fam, _ := r["transport_family"].(string)
		if fam == "" {
			fam, _ = r["family"].(string)
		}
		id, _ := r["route_id"].(string)
		seen = append(seen, fam)
		if fam == family {
			hits = append(hits, id)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("pack has no route of family %q (it has: %s)", family, strings.Join(seen, ", "))
	default:
		return "", fmt.Errorf("pack has %d routes of family %q; pass --route-id", len(hits), family)
	}
}
