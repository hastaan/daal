// Package relayconf renders the three things that must agree about
// which transport families a relay serves: the candidate metadata the
// binder signs, the sing-box inbounds cloud-init installs, and the
// family list the two firewalls (cloud-side and box-side ufw) are
// derived from.
//
// WHY IT IS A PACKAGE AND NOT A METHOD ON EACH ADAPTER. It lived
// inside providers/hetzner until Wave 6, and providers/vultr carried a
// hand-written imitation of it: a switch over profile names that
// returned families ("trojan-tls", "shadowsocks-2022") which are not in
// any profile this repo ships, ports that were always 443, and — worst
// — no error when the profile name did not resolve. A Vultr relay built
// from that imitation would boot a placeholder sing-box config, serve
// nothing, and still mint a signed pack full of routes.
//
// That is exactly the failure L5 is supposed to be an answer to. A
// second provider is only a rotation target if the relay it builds is
// the same relay; two renderers guarantee it eventually is not. So the
// renderer is one package, and an adapter that wants to host a Daal
// relay calls it rather than approximating it.
package relayconf

import (
	"fmt"
	"net"

	"daal/publisher/deploy/profiles"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
	"daal/publisher/deploy/sni"
)

// CandidatesForProfile produces the unsigned []CandidateMeta the
// FRP-4b binder folds into the per-route _relaypack sub-object.
//
// At V1.5 every candidate is direct_vps. publicIP supplies the
// public_ip:* tag; relayports supplies port + protocol; the profile
// supplies probing_risk_class.
//
// IT RETURNS AN ERROR, and that is the entire fix for L6.
//
// This function used to swallow a profile load error and return nil.
// The caller could not tell that apart from "this profile enables no
// families", so a typo'd or missing profile slug produced an
// OperatorRecord with zero candidates: a record that provisions
// happily, signs happily, and yields a pack with no routes in it. L6 —
// the rung whose whole content is "move to a different toolbox
// profile" — is the one operation that passes a NEW profile name here,
// so it is the operation the silent nil was guaranteed to hit. A wrong
// profile name must be an error at the moment it is read, not a shape
// that looks like an empty choice three layers downstream.
func CandidatesForProfile(profileName string, publicIP net.IP, enabledFamilies []string) ([]provider.CandidateMeta, error) {
	p, err := profiles.ByName(profileName)
	if err != nil {
		return nil, fmt.Errorf("toolbox profile %q: %w", profileName, err)
	}
	selected := map[string]bool{}
	for _, family := range enabledFamilies {
		selected[family] = true
	}
	tags := []string{}
	if publicIP != nil {
		tags = append(tags, fmt.Sprintf("public_ip:%s", publicIP.String()))
	}

	out := make([]provider.CandidateMeta, 0, len(p.Candidates))
	for _, pc := range p.Candidates {
		if len(selected) == 0 && !pc.DefaultEnabled {
			continue
		}
		if len(selected) > 0 && !selected[pc.Family] {
			continue
		}
		port := DefaultPortForFamily(pc.Family)
		candidateTags := append([]string{}, tags...)
		candidateTags = append(candidateTags, fmt.Sprintf("public_port:%s%d", portProto(pc.Family), port))
		out = append(out, provider.CandidateMeta{
			Family:           pc.Family,
			ExposureMode:     "direct_vps", // V1.5 invariant
			FamilyClass:      "vps-native",
			ProbingRiskClass: pc.ProbingRiskClass,
			Port:             port,
			PublicRiskTags:   candidateTags,
			OriginRiskTags:   []string{}, // empty at V1.5
		})
	}
	// A profile that loaded but selects nothing is also a record with
	// no routes, just arrived at by a different path — an
	// enabled-families list naming a family this profile does not
	// carry. Same outcome for the recipient, same refusal here.
	if len(out) == 0 {
		return nil, fmt.Errorf("toolbox profile %q yields no candidates for families %v", profileName, enabledFamilies)
	}
	return out, nil
}

// ServedFamilies resolves the family set this relay will actually
// serve, applying the same profile + enabled-families rules the
// candidate renderer does. One resolver, so the sing-box inbounds, the
// box-side ufw rules and the cloud-provider firewall cannot disagree
// about which families exist on a box — a disagreement between any two
// of those three is a route that mints and cannot be dialled.
func ServedFamilies(profileName string, enabledFamilies []string) ([]string, error) {
	cands, err := CandidatesForProfile(profileName, nil, enabledFamilies)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Family)
	}
	return out, nil
}

// DefaultSingBoxConfig produces the sing-box config embedded in
// cloud-init for a profile's own default-enabled family set. See
// SingBoxConfigForFamilies for what is in it and why.
//
// A profile that will not load is not a reason to refuse here — the
// caller (CandidatesForProfile) already errors on that, loudly — so
// this falls back to the always-present families.
func DefaultSingBoxConfig(profileName, coverSNI string) string {
	fams, err := ServedFamilies(profileName, nil)
	if err != nil {
		fams = nil
	}
	return SingBoxConfigForFamilies(coverSNI, fams)
}

// SingBoxConfigForFamilies is DefaultSingBoxConfig with the served
// family set supplied explicitly, which is what the provisioner has
// after it applies the wizard's enabled-families override.
//
// vless-in and hy2-in are unconditional: they are the two tiers every
// Daal relay has, and both start with an empty users[]. naive-in (8444)
// and ws-in (8445) are absent because sing-box will not start a naive
// inbound with no users, and the mgmt service creates them with their
// first recipient.
//
// tuic-in is the first inbound that is CONDITIONAL on the profile, and
// it is written here rather than created on first use for one reason:
// binding 8443/udp is a visible, permanent property of the relay, and
// the box-side ufw rule that has to accompany it is baked by cloud-init
// at first boot and cannot be changed afterwards. Deciding the family
// set once, at provision time, is the only way the inbound, the two
// firewalls and the minted pack can all agree. Turning tuic on for an
// existing relay is a reprovision.
//
// coverSNI is substituted into BOTH tls.server_name — the name the
// client advertises and the censor sees — AND
// reality.handshake.server, the dest this box completes a stolen
// handshake against. Those two must be the same string: when they
// disagree, an active prober gets a certificate from one site while the
// SNI claimed another, which is precisely the mismatch REALITY exists
// to prevent.
//
// An empty coverSNI is a caller bug, not a config option: sing-box's
// REALITY inbound needs a name, and an empty server_name is a box that
// does not start. Every provider resolves the value before calling
// here, so the fallback only fires on a programming error — and it
// fails loudly-wrong-but-working rather than silently broken.
func SingBoxConfigForFamilies(coverSNI string, families []string) string {
	if coverSNI == "" {
		coverSNI = sni.LegacyCoverSNI
	}
	extra := ""
	for _, f := range families {
		if f != "tuic" {
			continue
		}
		ep := relayports.For("tuic")
		// alpn IS REQUIRED, and its absence is not a degradation.
		// sing-quic defaults hysteria2's NextProtos to "h3" when the
		// config omits it; its tuic service does not, and quic-go
		// refuses a TLS config with no application protocol. An
		// alpn-less tuic inbound fails every handshake. The client
		// outbound sets the same single-element list — see
		// relaypack/client_outbound.go tuicTLS.
		//
		// congestion_control must also match the client's ("bbr"): a
		// mismatch does not fail, it stalls, which is harder to
		// diagnose than a refusal.
		extra = fmt.Sprintf(`,
    {"type": "tuic", "tag": "tuic-in", "listen": "0.0.0.0", "listen_port": %d,
     "users": [],
     "congestion_control": "bbr",
     "tls": {"enabled": true, "alpn": ["h3"],
             "certificate_path": "/etc/daal/tls-cert.pem", "key_path": "/etc/daal/tls-key.pem"}}`, ep.Port)
		break
	}
	// %[1]q, twice: one value, two required sites.
	return fmt.Sprintf(`{
  "log": {"level": "info"},
  "inbounds": [
    {"type": "vless", "tag": "vless-in", "listen": "0.0.0.0", "listen_port": 443,
     "users": [],
     "tls": {"enabled": true, "server_name": %[1]q,
             "reality": {"enabled": true, "private_key": "", "short_id": [],
                         "handshake": {"server": %[1]q, "server_port": 443}}}},
    {"type": "hysteria2", "tag": "hy2-in", "listen": "0.0.0.0", "listen_port": 443,
     "users": [],
     "tls": {"enabled": true,
             "certificate_path": "/etc/daal/tls-cert.pem", "key_path": "/etc/daal/tls-key.pem"}}%[2]s
  ],
  "outbounds": [{"type": "direct"}]
}`, coverSNI, extra)
}

// DefaultPortForFamily is the relayports lookup, re-exported so
// adapters have one import for "what does this relay listen on".
func DefaultPortForFamily(family string) int {
	return relayports.For(family).Port
}

func portProto(family string) string {
	if relayports.For(family).UDP {
		return "udp"
	}
	return "tcp"
}
