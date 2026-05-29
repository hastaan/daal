package selection

import (
	"testing"
	"time"
)

// helper: fixed instant for byte-stable cooldown expiries.
var fixedT = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

// candWithGraph builds a Candidate with a small SharedRiskGraph for
// propagation tests.
func candWithGraph(id, mode string, pub []string, origin []string, edges []SharedRiskEdge) Candidate {
	return Candidate{
		RouteID:         id,
		ExposureMode:    mode,
		PublicRiskTags:  pub,
		OriginRiskTags:  origin,
		SharedRiskGraph: edges,
	}
}

// TestCooldown_DirectVPS_TCPRSTCoolsPublicIP — the implicit
// "tcp_rst" path (signal == "") for direct_vps cools public_ip:*,
// public_asn:*, public_provider:*.
func TestCooldown_DirectVPS_TCPRSTCoolsPublicIP(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:5.75.0.1", "public_asn:24940", "public_provider:hetzner"},
		nil, nil)
	plan := PropagateCooldown(c, "", nil, fixedT)
	if len(plan.OnCandidate) != 3 {
		t.Fatalf("expected 3 cooldowns on candidate; got %d: %+v", len(plan.OnCandidate), plan.OnCandidate)
	}
}

// TestCooldown_DirectVPS_TCPRSTPropagatesToSiblings — sibling
// sharing public_ip is cooled too.
func TestCooldown_DirectVPS_TCPRSTPropagatesToSiblings(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:5.75.0.1"}, nil, nil)
	sibling := candWithGraph("rB", "direct_vps",
		[]string{"public_ip:5.75.0.1"}, nil, nil)
	plan := PropagateCooldown(c, "", []Candidate{sibling}, fixedT)
	if len(plan.OnSiblings["rB"]) == 0 {
		t.Errorf("rB must be cooled (shares public_ip); got %+v", plan.OnSiblings)
	}
}

func TestCooldown_UsesSharedRiskGraphWhenPresent(t *testing.T) {
	edges := []SharedRiskEdge{{
		Tag:     "public_ip:5.75.0.1",
		Members: []string{"rA", "rC"},
	}}
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:5.75.0.1"}, nil, edges)
	inGraph := candWithGraph("rC", "direct_vps",
		[]string{"public_ip:5.75.0.1"}, nil, nil)
	outOfGraph := candWithGraph("rB", "direct_vps",
		[]string{"public_ip:5.75.0.1"}, nil, nil)
	plan := PropagateCooldown(c, "", []Candidate{inGraph, outOfGraph}, fixedT)
	if len(plan.OnSiblings["rC"]) == 0 {
		t.Errorf("rC must be cooled because the signed graph includes it")
	}
	if len(plan.OnSiblings["rB"]) != 0 {
		t.Errorf("rB must not be cooled because the signed graph excludes it: %+v", plan.OnSiblings["rB"])
	}
}

// TestCooldown_SNIRst_DirectMode_CoolsSNI.
func TestCooldown_SNIRst_DirectMode_CoolsSNI(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"sni:www.bing.com", "public_ip:1.2.3.4"}, nil, nil)
	plan := PropagateCooldown(c, SignalSNIRst, nil, fixedT)
	if !hasTag(plan.OnCandidate, "sni:www.bing.com") {
		t.Errorf("expected sni:* cooldown on direct_vps SNIRst; got %+v", plan.OnCandidate)
	}
	if hasTag(plan.OnCandidate, "public_ip:1.2.3.4") {
		t.Errorf("public_ip must NOT be cooled by SNIRst on direct_vps")
	}
}

// TestCooldown_SNIRst_CDNFronted_CoolsSNIAndPublicDomainAndHostNotCDN.
func TestCooldown_SNIRst_CDNFronted_CoolsSNIAndPublicDomainAndHostNotCDN(t *testing.T) {
	c := candWithGraph("rA", "cdn_fronted",
		[]string{"cdn:cloudflare", "sni:e.example", "public_domain:e.example", "host:e.example"},
		nil, nil)
	plan := PropagateCooldown(c, SignalSNIRst, nil, fixedT)
	if !hasTag(plan.OnCandidate, "sni:e.example") ||
		!hasTag(plan.OnCandidate, "public_domain:e.example") ||
		!hasTag(plan.OnCandidate, "host:e.example") {
		t.Errorf("expected sni/public_domain/host cooldowns; got %+v", plan.OnCandidate)
	}
	if hasTag(plan.OnCandidate, "cdn:cloudflare") {
		t.Errorf("cdn:* must NOT be cooled by SNIRst on cdn_fronted (asymmetry)")
	}
}

// TestCooldown_OriginUnhealthy_DoesNotPropagate — invariant 20
// (asymmetry pin).
func TestCooldown_OriginUnhealthy_DoesNotPropagate(t *testing.T) {
	c := candWithGraph("rA", "cdn_fronted",
		[]string{"cdn:cloudflare", "public_domain:e.example"},
		[]string{"origin_ip:5.75.0.1", "origin_asn:24940"},
		nil)
	sibling := candWithGraph("rB", "cdn_fronted",
		[]string{"cdn:cloudflare", "public_domain:b.example"},
		[]string{"origin_ip:5.75.0.1"}, // shares origin
		nil)
	plan := PropagateCooldown(c, SignalOriginUnhealthy, []Candidate{sibling}, fixedT)
	// Cool ONLY origin_* on the failing candidate.
	if !hasTag(plan.OnCandidate, "origin_ip:5.75.0.1") {
		t.Errorf("expected origin_ip cooldown on candidate; got %+v", plan.OnCandidate)
	}
	for _, e := range plan.OnCandidate {
		if e.Tag == "cdn:cloudflare" || e.Tag == "public_domain:e.example" {
			t.Errorf("origin_unhealthy must NOT cool any public_risk_tag; got %s", e.Tag)
		}
	}
	// Sibling MUST NOT be cooled at all.
	if len(plan.OnSiblings) != 0 {
		t.Errorf("invariant 20 broken: origin_unhealthy propagated to siblings: %+v", plan.OnSiblings)
	}
}

// TestCooldown_CDNWideFailure_DoesPropagate — invariant 20 (the
// other half).
func TestCooldown_CDNWideFailure_DoesPropagate(t *testing.T) {
	c := candWithGraph("rA", "cdn_fronted",
		[]string{"cdn:cloudflare", "public_domain:a.example"}, nil, nil)
	sibling := candWithGraph("rB", "cdn_fronted",
		[]string{"cdn:cloudflare", "public_domain:b.example"}, nil, nil)
	other := candWithGraph("rC", "direct_vps",
		[]string{"public_ip:1.2.3.4"}, nil, nil)
	plan := PropagateCooldown(c, SignalCDNWideFailure, []Candidate{sibling, other}, fixedT)
	if !hasTag(plan.OnCandidate, "cdn:cloudflare") {
		t.Errorf("expected cdn:cloudflare cooldown on candidate; got %+v", plan.OnCandidate)
	}
	if !tagPresent(plan.OnSiblings["rB"], "cdn:cloudflare") {
		t.Errorf("rB must be cooled (shares cdn:cloudflare); got %+v", plan.OnSiblings)
	}
	if len(plan.OnSiblings["rC"]) != 0 {
		t.Errorf("rC must NOT be cooled (no cdn:cloudflare tag); got %+v", plan.OnSiblings["rC"])
	}
}

// TestCooldown_CDNHostnameBlocked_CDNFronted_CoolsHostnameNotCDN.
func TestCooldown_CDNHostnameBlocked_CDNFronted_CoolsHostnameNotCDN(t *testing.T) {
	c := candWithGraph("rA", "cdn_fronted",
		[]string{"cdn:cloudflare", "public_domain:e.example", "host:e.example", "sni:e.example"},
		nil, nil)
	plan := PropagateCooldown(c, SignalCDNHostnameBlocked, nil, fixedT)
	if !hasTag(plan.OnCandidate, "public_domain:e.example") {
		t.Errorf("expected public_domain cooldown; got %+v", plan.OnCandidate)
	}
	if hasTag(plan.OnCandidate, "cdn:cloudflare") {
		t.Errorf("cdn:* must NOT be cooled by CDNHostnameBlocked")
	}
}

// TestCooldown_UDPCollapsed_AnyMode_CoolsUDPGated.
func TestCooldown_UDPCollapsed_AnyMode_CoolsUDPGated(t *testing.T) {
	c := candWithGraph("rUDP", "direct_vps",
		[]string{"public_ip:1.1.1.1", "udp_gated:true"}, nil, nil)
	c.UDPGated = true
	sibling := candWithGraph("rTCP", "direct_vps",
		[]string{"public_ip:2.2.2.2"}, nil, nil)
	siblingUDP := candWithGraph("rUDP2", "direct_vps",
		[]string{"public_ip:3.3.3.3", "udp_gated:true"}, nil, nil)
	siblingUDP.UDPGated = true
	plan := PropagateCooldown(c, SignalUDPCollapsed, []Candidate{sibling, siblingUDP}, fixedT)
	if !hasTag(plan.OnCandidate, "udp_gated:true") {
		t.Errorf("expected udp_gated cooldown; got %+v", plan.OnCandidate)
	}
	if len(plan.OnSiblings["rTCP"]) != 0 {
		t.Errorf("non-UDP sibling must NOT be cooled; got %+v", plan.OnSiblings["rTCP"])
	}
	if !tagPresent(plan.OnSiblings["rUDP2"], "udp_gated:true") {
		t.Errorf("UDP-gated sibling must be cooled; got %+v", plan.OnSiblings["rUDP2"])
	}
}

// TestCooldown_DefaultPreferenceShifts_NoCooldowns — DNSBogon,
// QUICCollapsed, ProtocolWhitelistMode, StatefulReassemblyPresent
// are preference shifts per §13.4 — they emit no cooldowns from
// PropagateCooldown directly.
func TestCooldown_DefaultPreferenceShifts_NoCooldowns(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:1.1.1.1"}, nil, nil)
	for _, sig := range []NetworkSignal{
		SignalDNSBogonDetected,
		SignalQUICCollapsed,
		SignalProtocolWhitelistMode,
		SignalStatefulReassemblyPresent,
	} {
		plan := PropagateCooldown(c, sig, nil, fixedT)
		if len(plan.OnCandidate) != 0 || len(plan.OnSiblings) != 0 {
			t.Errorf("signal %s should be preference-shift only; got %+v", sig, plan)
		}
	}
}

// TestCooldown_Determinism — pure function: same input, same output.
func TestCooldown_Determinism(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:5.75.0.1", "public_asn:24940"}, nil, nil)
	sibling := candWithGraph("rB", "direct_vps",
		[]string{"public_ip:5.75.0.1"}, nil, nil)
	for i := 0; i < 100; i++ {
		p1 := PropagateCooldown(c, "", []Candidate{sibling}, fixedT)
		p2 := PropagateCooldown(c, "", []Candidate{sibling}, fixedT)
		if len(p1.OnCandidate) != len(p2.OnCandidate) {
			t.Fatalf("non-determinism on candidate cooldowns")
		}
		if len(p1.OnSiblings["rB"]) != len(p2.OnSiblings["rB"]) {
			t.Fatalf("non-determinism on sibling cooldowns")
		}
	}
}

// TestCooldown_DirectVPS_CooldownDurations — pin the per-prefix
// durations: public_ip 5min, public_asn 30min, public_provider
// 30min.
func TestCooldown_DirectVPS_CooldownDurations(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:5.75.0.1", "public_asn:24940", "public_provider:hetzner"},
		nil, nil)
	plan := PropagateCooldown(c, "", nil, fixedT)
	durs := map[string]int64{}
	for _, e := range plan.OnCandidate {
		durs[e.Tag] = e.ExpiresAtUnix - fixedT.Unix()
	}
	if durs["public_ip:5.75.0.1"] != int64(5*time.Minute/time.Second) {
		t.Errorf("public_ip cooldown = %d s; want 300", durs["public_ip:5.75.0.1"])
	}
	if durs["public_asn:24940"] != int64(30*time.Minute/time.Second) {
		t.Errorf("public_asn cooldown = %d s; want 1800", durs["public_asn:24940"])
	}
	if durs["public_provider:hetzner"] != int64(30*time.Minute/time.Second) {
		t.Errorf("public_provider cooldown = %d s; want 1800", durs["public_provider:hetzner"])
	}
}

// TestCooldown_NotCDNFronted_OriginUnhealthy_NoOp — origin_unhealthy
// only applies to cdn_fronted candidates; for direct_vps it is
// a no-op (operator-hygiene path doesn't apply).
func TestCooldown_NotCDNFronted_OriginUnhealthy_NoOp(t *testing.T) {
	c := candWithGraph("rA", "direct_vps",
		[]string{"public_ip:1.2.3.4"}, []string{"origin_ip:1.2.3.4"}, nil)
	plan := PropagateCooldown(c, SignalOriginUnhealthy, nil, fixedT)
	if len(plan.OnCandidate) != 0 || len(plan.OnSiblings) != 0 {
		t.Errorf("origin_unhealthy on direct_vps must be no-op; got %+v", plan)
	}
}

// helpers.
func hasTag(entries []CooldownEntry, tag string) bool {
	for _, e := range entries {
		if e.Tag == tag {
			return true
		}
	}
	return false
}

func tagPresent(entries []CooldownEntry, tag string) bool {
	return hasTag(entries, tag)
}
