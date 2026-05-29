// Command explanation-fixtures regenerates the 7 deterministic
// Explanation golden fixtures at specs/test-vectors/explanation/.
//
// Run from the repo root:
//
//	cd core && go run ./cmd/explanation-fixtures
//
// The generator is itself a pure function of the seven hard-coded
// scenarios below. Each scenario invokes the FRP-3 selector pipeline
// with a fixed Now timestamp and a synthetic []RouteRow, then emits
// the resulting *Explanation as canonical JSON.
//
// This command is the canonical source of truth for the wire shape of
// Explanation. The golden walker (selection/explain_test.go) validates
// that every file at specs/test-vectors/explanation/ round-trips through
// MarshalCanonical; this generator GUARANTEES round-trip equality by
// using MarshalCanonical itself.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"daal/core/internal/selection"
	"daal/core/netmem"
	"daal/core/routestore"
)

// pinTime is fixed for byte-stable expires_at_unix / last_seen_unix.
var pinTime = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

type fixture struct {
	filename string
	build    func() *selection.Explanation
}

func main() {
	out := flag.String("out", "", "output dir (defaults to specs/test-vectors/explanation/ relative to repo root)")
	flag.Parse()

	dir := *out
	if dir == "" {
		// Resolve repo root from cwd: this command is run from
		// `core/`, so the repo root is one level up.
		cwd, err := os.Getwd()
		if err != nil {
			die(err)
		}
		dir = filepath.Join(cwd, "..", "specs", "test-vectors", "explanation")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		die(err)
	}

	fixtures := []fixture{
		{"empty-decision.json", buildEmptyDecision},
		{"single-vps-pick.json", buildSingleVPSPick},
		{"cooldown-propagation.json", buildCooldownPropagation},
		{"origin-unhealthy-isolated.json", buildOriginUnhealthyIsolated},
		{"single-vps-with-sni.json", buildSingleVPSWithSNI},
		{"mixed-mode-v16.json", buildMixedModeV16},
		{"udp-collapsed.json", buildUDPCollapsed},
	}
	for _, f := range fixtures {
		exp := f.build()
		body, err := exp.MarshalCanonical()
		if err != nil {
			die(err)
		}
		// Trailing newline for POSIX-friendly fixtures.
		body = append(body, '\n')
		path := filepath.Join(dir, f.filename)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			die(err)
		}
		fmt.Println("wrote", path)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "explanation-fixtures:", err)
	os.Exit(1)
}

// 1. empty-decision: no candidates available.
func buildEmptyDecision() *selection.Explanation {
	out := selection.Decide(selection.Input{
		Phase: selection.PhaseV15, Mode: selection.ModeNormal,
		Now: pinTime, DecisionID: "frp3-fixture-empty-decision-001",
	})
	return out.Explanation
}

// 2. single-vps-pick: 3 direct_vps candidates sharing one public_ip;
// V1.5 single-VPS shortlist via secondary axes.
func buildSingleVPSPick() *selection.Explanation {
	rows := []routestore.RouteRow{
		mkRow("r1", "vless-reality", "direct_vps", "low",
			[]string{"public_ip:5.75.0.1", "public_port:tcp443"}, nil),
		mkRow("r2", "naive", "direct_vps", "low",
			[]string{"public_ip:5.75.0.1", "public_port:tcp443"}, nil),
		mkRow("r3", "websocket-tls", "direct_vps", "low",
			[]string{"public_ip:5.75.0.1", "public_port:tcp443"}, nil),
	}
	snap := &netmem.Snapshot{
		LastSeen: pinTime,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {
				Successes: 3,
				ByRelayPack: []netmem.RelayPackStat{{
					Key: netmem.RelayPackKey{
						Family:                 "vless-reality",
						ExposureMode:           "direct_vps",
						PublicRiskTagSignature: "public_ip:5.75.0.1,public_port:tcp443",
						Outcome:                selection.OutcomeSuccess,
					},
					Successes: 3,
				}},
			},
		},
	}
	out := selection.Decide(selection.Input{
		Routes: rows, NetMem: snap, Phase: selection.PhaseV15,
		Mode: selection.ModeNormal, Now: pinTime,
		DecisionID: "frp3-fixture-single-vps-001",
	})
	return out.Explanation
}

// 3. cooldown-propagation: 3 vps; the leader's TCP RST cooled
// public_ip + public_asn; runner-up r2 picks. We model the
// post-failure decision: the failed candidate is absent from rows
// (caller would have filtered it), and the active_cooldowns list
// reflects the cooled tags.
func buildCooldownPropagation() *selection.Explanation {
	rows := []routestore.RouteRow{
		mkRow("r2", "naive", "direct_vps", "low",
			[]string{"public_ip:5.75.0.2"}, nil),
	}
	out := selection.Decide(selection.Input{
		Routes: rows, Phase: selection.PhaseV15,
		Mode: selection.ModeNormal, Now: pinTime,
		DecisionID: "frp3-fixture-cooldown-propagation-001",
	})
	// Hand-augment with the cooldowns the caller would have
	// computed via PropagateCooldown for the failed leader:
	out.Explanation.Failures = []selection.FailureRecord{{
		RouteID:        "r1",
		Classification: "tcp_reset",
		Tag:            "public_ip:5.75.0.1",
	}}
	out.Explanation.ActiveCooldowns = []selection.CooldownEntry{
		{Tag: "public_asn:24940", ExpiresAtUnix: pinTime.Add(30 * time.Minute).Unix(), Reason: "tcp_rst"},
		{Tag: "public_ip:5.75.0.1", ExpiresAtUnix: pinTime.Add(5 * time.Minute).Unix(), Reason: "tcp_rst"},
	}
	return out.Explanation
}

// 4. origin-unhealthy-isolated: cdn_fronted; rA failed
// origin_unhealthy; rB picks (sibling on same origin NOT cooled).
func buildOriginUnhealthyIsolated() *selection.Explanation {
	rB := mkRow("rB", "websocket-tls", "cdn_fronted", "low",
		[]string{"cdn:cloudflare", "public_domain:b.example"},
		[]string{"origin_ip:5.75.0.1"})
	out := selection.Decide(selection.Input{
		Routes: []routestore.RouteRow{rB}, Phase: selection.PhaseV16,
		Mode: selection.ModeNormal, Now: pinTime,
		NetworkSignals: []selection.NetworkSignal{selection.SignalOriginUnhealthy},
		DecisionID:     "frp3-fixture-origin-unhealthy-001",
	})
	out.Explanation.Failures = []selection.FailureRecord{{
		RouteID:        "rA",
		Classification: "origin_unhealthy",
		Tag:            "origin_ip:5.75.0.1",
	}}
	out.Explanation.ActiveCooldowns = []selection.CooldownEntry{
		{Tag: "origin_ip:5.75.0.1", ExpiresAtUnix: pinTime.Add(60 * time.Minute).Unix(), Reason: "origin_unhealthy"},
	}
	return out.Explanation
}

// 5. single-vps-with-sni: same as single-vps but candidates differ
// on sni:* — the SNI diversity axis dominates.
func buildSingleVPSWithSNI() *selection.Explanation {
	rows := []routestore.RouteRow{
		mkRow("r1", "vless-reality", "direct_vps", "low",
			[]string{"public_ip:1.2.3.4", "sni:www.bing.com"}, nil),
		mkRow("r2", "vless-reality", "direct_vps", "low",
			[]string{"public_ip:1.2.3.4", "sni:www.example.com"}, nil),
	}
	out := selection.Decide(selection.Input{
		Routes: rows, Phase: selection.PhaseV15, Mode: selection.ModeNormal,
		Now: pinTime, DecisionID: "frp3-fixture-single-vps-sni-001",
	})
	return out.Explanation
}

// 6. mixed-mode-v16: V1.6 with one direct_vps + one cdn_fronted;
// mode-mixing bonus drives shortlist ordering.
func buildMixedModeV16() *selection.Explanation {
	rows := []routestore.RouteRow{
		mkRow("rA", "vless-reality", "direct_vps", "low",
			[]string{"public_ip:5.75.0.1"}, nil),
		mkRow("rB", "websocket-tls", "cdn_fronted", "low",
			[]string{"cdn:cloudflare", "public_domain:e.example"}, nil),
	}
	out := selection.Decide(selection.Input{
		Routes: rows, Phase: selection.PhaseV16, Mode: selection.ModeNormal,
		Now: pinTime, DecisionID: "frp3-fixture-mixed-mode-v16-001",
	})
	return out.Explanation
}

// 7. udp-collapsed: all-UDP-gated; the udp_collapsed signal is
// surfaced via Explanation.NetworkSignals; race plan is degraded
// (caller would have cooled udp_gated:true).
func buildUDPCollapsed() *selection.Explanation {
	rows := []routestore.RouteRow{
		mkRow("rTCP", "naive", "direct_vps", "low",
			[]string{"public_ip:5.75.0.1"}, nil),
	}
	out := selection.Decide(selection.Input{
		Routes: rows, Phase: selection.PhaseV15, Mode: selection.ModeNormal,
		Now:            pinTime,
		NetworkSignals: []selection.NetworkSignal{selection.SignalUDPCollapsed},
		DecisionID:     "frp3-fixture-udp-collapsed-001",
	})
	return out.Explanation
}

func mkRow(id, family, mode, probing string, pub, origin []string) routestore.RouteRow {
	r := routestore.RouteRow{
		RouteID:             id,
		TransportFamily:     family,
		ExposureMode:        mode,
		FamilyClass:         "vps-native",
		ProbingRiskClass:    probing,
		PublicRiskTags:      pub,
		SharedRiskGraphJSON: "[]",
	}
	if origin != nil {
		r.OriginRiskTags = origin
	}
	return r
}
