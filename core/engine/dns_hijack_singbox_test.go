//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"testing"

	"daal/core/routestore"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// TestHijackedDNSConfigIsAcceptedBySingBox is the half of FAM-1 that
// TestBuildSingBoxConfigHijacksDNSForUDPLessOutbounds cannot see. That
// test checks the shape of a Go map; this one hands the same config to
// the sing-box this module links and asks it to build a router from it.
//
// Two things are load-bearing for every name lookup on a UDP-less route
// (naive, http) and neither is ours to define:
//
//   - the route rule {network:udp, port:53, action:hijack-dns}, and
//   - the dns block Start adds (defaultDNSBlock), which is written in
//     the legacy server format sing-box deprecated in 1.12.
//
// If a sing-box bump removes the legacy format, renames the action or
// rejects the pair, the engine fails at "option parse"/"box.New" on the
// phone — or worse, starts and resolves nothing. The end-to-end rig
// catches that (check `family/naive dns`), but the rig is skipped on a
// machine without user namespaces. This is the gate that cannot skip.
//
// An `http` outbound stands in for naive: it is in the same
// udpLessOutboundTypes set, so it takes the identical rule, and it
// needs no Cronet library to construct.
//
// What this does NOT prove: that a query is answered. That needs a TUN
// and a relay — the rig, and the phone retest FINDINGS.md lists for
// FAM-1 (Private DNS off, naive route, open a site by name).
func TestHijackedDNSConfigIsAcceptedBySingBox(t *testing.T) {
	cfg, err := BuildSingBoxConfig(
		routestore.RouteRow{RouteID: "r1", TransportFamily: "naive"},
		[]byte(`{"type":"http","server":"192.0.2.1","server_port":8444,"username":"u","password":"p"}`),
	)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	// BuildSingBoxConfig stages a refresh inlet as a side effect; do not
	// leave it behind for the tests that assert on that state.
	t.Cleanup(retireRefreshInlet)

	blob, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The same two edits singBox.Start makes, minus the TUN inbound
	// (which needs the VpnService's fd): the real dns block, and the
	// daal-only marker stripped.
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["dns"]; has {
		t.Fatal("BuildSingBoxConfig now emits its own dns block; this test must follow whatever Start really sends")
	}
	raw["dns"] = defaultDNSBlock()
	if route, ok := raw["route"].(map[string]any); ok {
		delete(route, "udp_gated")
	}
	merged, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	defer cancel()
	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, merged)
	if err != nil {
		t.Fatalf("sing-box rejects the hijack-dns config at option parse: %v\n%s", err, merged)
	}

	// The decoder must have understood the rule as a DNS hijack on
	// exactly UDP/53 — not merely tolerated the keys.
	if options.Route == nil || len(options.Route.Rules) != 1 {
		t.Fatalf("want exactly one route rule, got %+v", options.Route)
	}
	rule := options.Route.Rules[0].DefaultOptions
	if rule.Action != C.RuleActionTypeHijackDNS {
		t.Errorf("rule action = %q, want %q", rule.Action, C.RuleActionTypeHijackDNS)
	}
	if len(rule.Network) != 1 || rule.Network[0] != "udp" {
		t.Errorf("rule network = %v, want [udp]", rule.Network)
	}
	if len(rule.Port) != 1 || rule.Port[0] != 53 {
		t.Errorf("rule port = %v, want [53]", rule.Port)
	}
	// And the dns block must have produced a server the hijack can use.
	if options.DNS == nil || len(options.DNS.Servers) != 1 || options.DNS.Servers[0].Tag != "remote" {
		t.Fatalf("dns servers = %+v, want the single \"remote\" server", options.DNS)
	}
	if options.DNS.Final != "remote" {
		t.Errorf("dns.final = %q, want \"remote\"", options.DNS.Final)
	}

	// box.New builds the router, the rule actions and the DNS servers;
	// Start is where sing-box resolves the server's detour against the
	// outbounds and brings the DNS transports up (box.New alone accepts
	// a detour naming an outbound that does not exist). Start binds only
	// the loopback refresh inlet on its ephemeral port and dials
	// nothing: no query is made until traffic arrives.
	inst, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("sing-box cannot build a box from the hijack-dns config: %v\n%s", err, merged)
	}
	defer inst.Close()
	if err := inst.Start(); err != nil {
		t.Fatalf("sing-box cannot start a box from the hijack-dns config: %v\n%s", err, merged)
	}
}
