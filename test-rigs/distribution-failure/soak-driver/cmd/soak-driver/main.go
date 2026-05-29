// soak-driver is the Phase 1.5C blackout + accelerated 30-day soak
// runner. See ../../README.md for usage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"daal/soak-driver/internal/artifacts"
	"daal/soak-driver/internal/censor"
	"daal/soak-driver/internal/client"
	"daal/soak-driver/internal/clock"
	"daal/soak-driver/internal/origin"
	"daal/soak-driver/internal/soak"
	"daal/soak-driver/internal/wallclock"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run-7d":
		os.Exit(runSoak(os.Args[2:], 7))
	case "run-30d":
		os.Exit(runSoak(os.Args[2:], 30))
	case "run":
		os.Exit(runSoak(os.Args[2:], 0))
	case "run-wallclock":
		os.Exit(runWallclock(os.Args[2:]))
	case "run-burn":
		os.Exit(runBurn(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "verify-burn":
		os.Exit(runVerifyBurn(os.Args[2:]))
	case "redact":
		os.Exit(runRedact(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: soak-driver <run-7d|run-30d|run|run-wallclock|verify|redact> [flags]")
	fmt.Fprintln(os.Stderr, "  run-7d         --engine-lib PATH --out DIR [--scenarios csv] [--clients csv] [--mode rig|in-engine]")
	fmt.Fprintln(os.Stderr, "  run-30d        --engine-lib PATH --out DIR [--scenarios csv] [--clients csv] [--mode rig|in-engine]")
	fmt.Fprintln(os.Stderr, "  run            --engine-lib PATH --out DIR --simulated-days N --lift-day N [--mode rig|in-engine]")
	fmt.Fprintln(os.Stderr, "  run-wallclock  --engine PATH --out DIR --duration 7d --tick 1m [--max-fd-growth 50]")
	fmt.Fprintln(os.Stderr, "  run-burn       --engine PATH --out DIR --clients N --duration 30d --pool-size 50 --directory-refresh 48h [--burn-rate-per-route-per-hour 0.014] [--seed 42]")
	fmt.Fprintln(os.Stderr, "  verify         --in DIR")
	fmt.Fprintln(os.Stderr, "  verify-burn    --in DIR")
	fmt.Fprintln(os.Stderr, "  redact         --in DIR")
}

func runSoak(args []string, presetDays int) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	enginePath := fs.String("engine", findEngineBinary(), "soak-engine binary")
	out := fs.String("out", "", "output directory (required)")
	scnDir := fs.String("scenarios-dir", filepath.Join("..", "scenarios"), "scenarios directory")
	scenarios := fs.String("scenarios", "", "comma-separated scenario IDs (default: all)")
	clientsFlag := fs.String("clients", "linux-cli-A,linux-cli-B", "comma-separated client names")
	days := fs.Int("simulated-days", presetDays, "number of simulated days")
	liftDay := fs.Int("lift-day", presetDays/2, "day on which to lift the censor (0 = never)")
	modeFlag := fs.String("mode", "rig", "scheduler driver: rig | in-engine (V2 parity)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *days <= 0 || *out == "" || *enginePath == "" {
		usage()
		return 2
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "out:", err)
		return 1
	}
	scenariosToRun, err := loadScenarios(*scnDir, *scenarios)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scenarios:", err)
		return 1
	}
	srv, err := origin.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "origin:", err)
		return 1
	}
	defer srv.Close()
	// Seed each origin with a minimal valid body. The point of the
	// soak is failure-mode behavior, not bundle-content variation.
	srv.SetBody(origin.ChannelSubscription, []byte("vless://soak@example/?type=tcp&security=tls#soak"))
	srv.SetBody(origin.ChannelRevocation, []byte(`{"v":1,"issued_at":"2026-04-26T00:00:00Z","reason":"soak","revoked_publishers":[],"revoked_routes":[]}`))
	srv.SetBody(origin.ChannelDirectory, []byte(`(stub directory bundle)`))
	srv.SetBody(origin.ChannelIPFS, []byte(`(stub directory bundle)`))
	srv.SetBody(origin.ChannelTelegram, []byte(`(stub telegram listing)`))
	srv.SetBody(origin.ChannelGitHub, []byte(`(stub github releases)`))

	clk := clock.Default()
	clientNames := strings.Split(*clientsFlag, ",")

	manifest := artifacts.Manifest{
		RunID:         filepath.Base(*out),
		StartedAt:     time.Now().UTC().Format(time.RFC3339),
		SimulatedDays: *days,
		EngineLib:     *enginePath,
		Clients:       clientNames,
	}

	// Spawn one client per name. Each gets its own state dir.
	clients := make([]*client.Client, 0, len(clientNames))
	for _, name := range clientNames {
		stateDir := filepath.Join(*out, "state", name)
		c, err := client.Spawn(name, *enginePath, stateDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "spawn", name, ":", err)
			return 1
		}
		v, err := c.Version()
		if err == nil && manifest.EngineVersion == "" {
			manifest.EngineVersion = v
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	scNames := []string{}
	for _, s := range scenariosToRun {
		scNames = append(scNames, s.ID)
	}
	manifest.Scenarios = scNames
	if err := artifacts.WriteManifest(*out, manifest); err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
	}

	overallFailed := false
	for _, sc := range scenariosToRun {
		fmt.Println("scenario:", sc.ID)
		// Phase 2E: scenarios may declare engine_env to constrain
		// the soak engine subprocess (e.g., GOMEMLIMIT=50MiB for
		// ios-extension-memory). When present, we respawn the
		// client fleet for THIS scenario and tear them back down
		// after, so the rest of the run is unaffected.
		runClients := clients
		var perScenarioCleanup func()
		if len(sc.EngineEnv) > 0 {
			perScenario := make([]*client.Client, 0, len(clientNames))
			for _, name := range clientNames {
				stateDir := filepath.Join(*out, "state-"+sc.ID, name)
				c, err := client.SpawnWithEnv(name, *enginePath, stateDir, sc.EngineEnv)
				if err != nil {
					fmt.Fprintln(os.Stderr, "  ERR per-scenario spawn:", err)
					for _, prev := range perScenario {
						_ = prev.Close()
					}
					overallFailed = true
					perScenario = nil
					break
				}
				perScenario = append(perScenario, c)
			}
			if perScenario == nil {
				continue
			}
			runClients = perScenario
			perScenarioCleanup = func() {
				for _, c := range perScenario {
					_ = c.Close()
				}
			}
		}
		runRes, err := soak.Run(soak.Config{
			Scenario:      sc,
			SimulatedDays: *days,
			LiftDay:       *liftDay,
			OutDir:        filepath.Join(*out, sc.ID),
			Clients:       runClients,
			Origins:       srv,
			Clock:         clk,
			Mode:          soak.Mode(*modeFlag),
		})
		if perScenarioCleanup != nil {
			perScenarioCleanup()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "  ERR:", err)
			overallFailed = true
			continue
		}
		body, _ := json.MarshalIndent(runRes, "", "  ")
		_ = os.WriteFile(filepath.Join(*out, sc.ID, "invariants.json"), body, 0o644)
		if runRes.Failed {
			overallFailed = true
			fmt.Println("  FAIL")
		} else {
			fmt.Println("  PASS")
		}
	}

	if overallFailed {
		return 1
	}
	fmt.Println("ALL SCENARIOS PASSED")
	return 0
}

func loadScenarios(dir, ids string) ([]censor.Scenario, error) {
	all, err := censor.Load(dir)
	if err != nil {
		return nil, err
	}
	if ids == "" {
		// Default whitelist is the 2D V2-superset (10 scenarios).
		ids = "v2-superset"
	}
	// Phase 2G: named whitelists for the parity sub-gates.
	switch ids {
	case "legacy":
		// The 1.5C-locked regression gate. CI-gated since 1.5C and
		// MUST stay green through every V2 sub-phase.
		want := map[string]bool{
			"github-unreachable":                     true, // primary-blocked
			"bootstrap-directory-mirror-unreachable": true, // primary+fallback
			"telegram-unreachable":                   true, // all-bootstrap
			"subscription-url-unreachable":           true,
			"publisher-revocation-url-unreachable":   true,
		}
		var out []censor.Scenario
		for _, s := range all {
			if want[s.ID] {
				out = append(out, s)
			}
		}
		return out, nil
	case "v2-superset":
		// Legacy + 3 from 2C + 2 from 2D + 2 from 2E + 2 from 3A
		//   + 3 from 3B + 2 from 3C + 2 from 3D + 2 from 3E
		//   + 3 from 3F = 26 scenarios. The 2G ship-gate parity
		// tier widened at 2E, 3A, 3B, 3C, 3D, 3E, and now 3F
		// (the one-tap delegate-share surface).
		want := map[string]bool{
			"github-unreachable":                     true,
			"bootstrap-directory-mirror-unreachable": true,
			"telegram-unreachable":                   true,
			"subscription-url-unreachable":           true,
			"publisher-revocation-url-unreachable":   true,
			"network-roam":                           true,
			"mode-bulk-unlock":                       true,
			"posture-recovery-cycle":                 true,
			"lifeline-strict-policy":                 true,
			"lifeline-strict-roam":                   true,
			// Phase 2E:
			"ios-extension-memory":  true,
			"ios-wireguard-handoff": true,
			// Phase 3A:
			"experimental-gate-respected": true,
			"webtunnel-handshake":         true,
			// Phase 3B:
			"snowflake-rendezvous-fallback": true,
			"snowflake-broker-burn":         true,
			"push-rendezvous-opt-in":        true,
			// Phase 3C:
			"masque-udp-failover":  true,
			"masque-lifeline-rung": true,
			// Phase 3D:
			"psiphon-blob-rotation": true,
			"conjure-phantom-pool":  true,
			// Phase 3E:
			"wasm-hello-transport": true,
			"wasm-kill-switch":     true,
			// Phase 3F:
			"delegate-share-cap":              true,
			"delegate-share-policy-respected": true,
			"delegate-share-chain-depth-5":    true,
		}
		var out []censor.Scenario
		for _, s := range all {
			if want[s.ID] {
				out = append(out, s)
			}
		}
		return out, nil
	case "v1-5-superset":
		// Phase FRP-7 (V1.5 pilot soak): the V1.5-shaped pilot
		// evidence selector. Six scenarios driving the supplement
		// §22.1 success metric + §14.1 L3 wall-clock pin. The
		// selector is **additive**: v2-superset (26) and
		// v3-superset (31) remain locked and untouched. See
		// specs/v1-5-closure-v1.md §pilot-evidence-target.
		want := map[string]bool{
			"v1-5-provisioning-under-10min":     true,
			"v1-5-family-online-under-60s":      true,
			"v1-5-7-day-stay-online":            true,
			"v1-5-1-rotation-under-60s":         true,
			"v1-5-mode-aware-schema-end-to-end": true,
			"v1-5-l3-fast-path":                 true,
		}
		var out []censor.Scenario
		for _, s := range all {
			if want[s.ID] {
				out = append(out, s)
			}
		}
		return out, nil
	case "v1-6-superset":
		// Phase FRP-9 (V1.6 CDN alpha soak): seven synthetic
		// scenarios covering the supplement §22.2 CDN-fronted
		// alpha gate. This selector is additive: v1-5-superset
		// stays 6, v2-superset stays 26, and v3-superset stays 31.
		want := map[string]bool{
			"v1-6-cdn-dominant-route":           true,
			"v1-6-dns-only-a-leak-detected":     true,
			"v1-6-origin-ip-scan-rejected":      true,
			"v1-6-cf-hostname-blocked-fallback": true,
			"v1-6-public-surface-rotation":      true,
			"v1-6-origin-only-rotation":         true,
			"v1-6-freshness-atomic-swap":        true,
		}
		var out []censor.Scenario
		for _, s := range all {
			if want[s.ID] {
				out = append(out, s)
			}
		}
		return out, nil
	case "v3-superset":
		// Phase 3-Soak: the v3-superset subsumes the v2-superset
		// (26 scenarios) and adds the 5 new V3 scenarios for a
		// total of **31**. The 3-Soak verifier (internal/v3verifier)
		// computes the 5-metric V3 aggregate over this selector.
		// See `phases of development/27-phase-3-soak-success-metric.md`
		// §4 sub-task 7.
		want := map[string]bool{
			// All of v2-superset:
			"github-unreachable":                     true,
			"bootstrap-directory-mirror-unreachable": true,
			"telegram-unreachable":                   true,
			"subscription-url-unreachable":           true,
			"publisher-revocation-url-unreachable":   true,
			"network-roam":                           true,
			"mode-bulk-unlock":                       true,
			"posture-recovery-cycle":                 true,
			"lifeline-strict-policy":                 true,
			"lifeline-strict-roam":                   true,
			"ios-extension-memory":                   true,
			"ios-wireguard-handoff":                  true,
			"experimental-gate-respected":            true,
			"webtunnel-handshake":                    true,
			"snowflake-rendezvous-fallback":          true,
			"snowflake-broker-burn":                  true,
			"push-rendezvous-opt-in":                 true,
			"masque-udp-failover":                    true,
			"masque-lifeline-rung":                   true,
			"psiphon-blob-rotation":                  true,
			"conjure-phantom-pool":                   true,
			"wasm-hello-transport":                   true,
			"wasm-kill-switch":                       true,
			"delegate-share-cap":                     true,
			"delegate-share-policy-respected":        true,
			"delegate-share-chain-depth-5":           true,
			// Plus the 5 new V3 scenarios:
			"v3-cross-platform-pickup":           true,
			"v3-experimental-gate-cross-product": true,
			"v3-bulk-capable-cross-product":      true,
			"v3-auto-promotion-threshold-A-vs-B": true,
			"v3-mixed-family-directory":          true,
		}
		var out []censor.Scenario
		for _, s := range all {
			if want[s.ID] {
				out = append(out, s)
			}
		}
		return out, nil
	}
	wantList := strings.Split(ids, ",")
	want := map[string]bool{}
	for _, id := range wantList {
		want[strings.TrimSpace(id)] = true
	}
	var out []censor.Scenario
	for _, s := range all {
		if want[s.ID] {
			out = append(out, s)
		}
	}
	return out, nil
}

// runWallclock implements `soak-driver run-wallclock`. One client, one
// scenario, real time.Now, bounded fd growth check. See
// internal/wallclock for the loop body.
//
// Default `--duration 7d --tick 1m --max-fd-growth 50` matches the
// 1.5C-Polish exit gate; small durations (e.g. `--duration 3s
// --tick 500ms`) keep the unit test fast. The subcommand is also the
// long-running smoke procedure recorded in the 1.5C-Polish handover.
func runWallclock(args []string) int {
	fs := flag.NewFlagSet("run-wallclock", flag.ExitOnError)
	enginePath := fs.String("engine", findEngineBinary(), "soak-engine binary")
	out := fs.String("out", "", "output directory (required)")
	durStr := fs.String("duration", "7d", "wall-clock duration (Go duration; 'd' is treated as 24h)")
	tickStr := fs.String("tick", "1m", "tick interval (Go duration)")
	maxFDGrowth := fs.Int("max-fd-growth", 50, "max(fd) - min(fd) above which the run fails")
	clientName := fs.String("client", "wallclock-cli", "client name (artifact subdir)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *enginePath == "" {
		usage()
		return 2
	}
	dur, err := parseDayDuration(*durStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "duration:", err)
		return 2
	}
	tick, err := time.ParseDuration(*tickStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tick:", err)
		return 2
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "out:", err)
		return 1
	}

	stateDir := filepath.Join(*out, "state", *clientName)
	c, err := client.Spawn(*clientName, *enginePath, stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spawn:", err)
		return 1
	}
	defer c.Close()
	if v, err := c.Version(); err == nil {
		fmt.Println("engine:", v)
	}

	res, err := wallclock.Run(wallclock.Config{
		Client:      c,
		OutDir:      *out,
		Duration:    dur,
		TickEvery:   tick,
		MaxFDGrowth: *maxFDGrowth,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wallclock:", err)
		return 1
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(body))
	if res.Failed {
		return 1
	}
	return 0
}

// parseDayDuration accepts Go duration syntax plus a 'd' suffix for
// whole days (e.g. "7d" → 7×24h, "1d12h" is rejected; for sub-day
// resolution use 's', 'm', 'h' as usual).
func parseDayDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		base := strings.TrimSuffix(s, "d")
		n, err := time.ParseDuration(base + "h")
		if err != nil {
			return 0, err
		}
		return n * 24, nil
	}
	return time.ParseDuration(s)
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "", "run directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" {
		usage()
		return 2
	}
	if err := artifacts.VerifyShape(*in); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	fmt.Println("verify: ok")
	return 0
}

func runRedact(args []string) int {
	fs := flag.NewFlagSet("redact", flag.ExitOnError)
	in := fs.String("in", "", "run directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" {
		usage()
		return 2
	}
	out, err := artifacts.Redact(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "redact:", err)
		return 1
	}
	fmt.Println("wrote", out)
	return 0
}

func findEngineBinary() string {
	// Sensible default for local invocation.
	for _, p := range []string{
		"/tmp/daal-soak-engine-soak",
		"./daal-soak-engine",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
