// Package censor maps a distribution-failure scenario to a set of
// channel-state changes on the origin server. It is the rig's
// "what does the censor do this hour" knob.
//
// We deliberately stay in user-space: the simplest faithful simulation
// is to flip our own origin servers between Allow and Drop. This avoids
// needing CAP_NET_ADMIN and avoids tearing down real networking.
package censor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"daal/soak-driver/internal/origin"
)

// EngineAction is a single engine-side action the soak driver runs
// at a given simulated day. Phase 2C: introduced to support the
// engine-driven scenarios (`mode-bulk-unlock`,
// `posture-recovery-cycle`, `network-roam`) without breaking the
// byte-for-byte 30-day in-engine parity ledger of the legacy 7
// scenarios — those carry no `engine_actions` and behave identically
// to pre-2C.
//
// Action names recognised by the soak driver's dispatcher:
//   - "set_mode"          args: {"mode": "lifeline"|"normal"|"bulk"}
//   - "set_route_budget"  args: {"route_id": "...", "budget_tag": "..."}
//   - "network_changed"   args: {"kind": "wifi"|"cell"|"eth"|"unknown",
//     "carrier": "...", "ssid": "..."}
type EngineAction struct {
	Day  int            `json:"day"`  // simulated day (1-indexed)
	Name string         `json:"name"` // action name (see above)
	Args map[string]any `json:"args"`
}

// Scenario is the on-disk JSON shape under
// test-rigs/distribution-failure/scenarios/.
type Scenario struct {
	ID          string   `json:"id"`
	Channel     string   `json:"channel"`
	Description string   `json:"description"`
	Blocks      []string `json:"blocks"`

	// EngineActions is Phase 2C. Optional, nil for legacy
	// scenarios. Each action runs after the day's normal refresh
	// sweep on the day specified by EngineAction.Day.
	EngineActions []EngineAction `json:"engine_actions,omitempty"`

	// EngineEnv is Phase 2E. Optional, nil for legacy scenarios.
	// Key/value entries are exported into the soak engine
	// subprocess environment at spawn time. Used by
	// `ios-extension-memory` to set `GOMEMLIMIT=50MiB`. The driver
	// MUST treat unknown keys as opaque environment overrides; no
	// magic is applied to the value.
	EngineEnv map[string]string `json:"engine_env,omitempty"`
}

// Load reads a scenarios directory.
func Load(dir string) ([]Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Scenario
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var s Scenario
		if err := json.Unmarshal(body, &s); err != nil {
			return nil, fmt.Errorf("censor: parse %s: %w", e.Name(), err)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// blockToChannel maps a scenario "blocks" entry to one or more origin
// channels. The scenario language was frozen in Phase 0C; we honor it
// even where a single block string maps to multiple channels.
func blockToChannel(block string) []origin.Channel {
	switch block {
	case "subscription-url":
		return []origin.Channel{origin.ChannelSubscription}
	case "publisher-revocation":
		return []origin.Channel{origin.ChannelRevocation}
	case "directory-primary":
		return []origin.Channel{origin.ChannelDirectory}
	case "ipfs-gateway":
		return []origin.Channel{origin.ChannelIPFS}
	case "telegram":
		return []origin.Channel{origin.ChannelTelegram}
	case "github-raw", "github-releases", "github-api":
		return []origin.Channel{origin.ChannelGitHub}
	case "project-domain", "app-store", "cdn-primary":
		// These map to the directory channel: blocking the project's
		// primary domain is, in practice, blocking the directory it
		// hosts. The scenario semantics are preserved at the soak
		// level via per-day invariant assertions.
		return []origin.Channel{origin.ChannelDirectory}
	}
	return nil
}

// Apply translates a scenario into channel-state changes on the
// supplied origin server. Channels not mentioned in `blocks` are reset
// to StateAllow. If `lifted` is true, every channel is set to
// StateAllow regardless of the scenario.
func Apply(s Scenario, srv *origin.Server, lifted bool) {
	if lifted {
		srv.SetAll(origin.StateAllow)
		return
	}
	srv.SetAll(origin.StateAllow)
	for _, b := range s.Blocks {
		for _, ch := range blockToChannel(b) {
			srv.Set(ch, origin.StateDrop)
		}
	}
}
