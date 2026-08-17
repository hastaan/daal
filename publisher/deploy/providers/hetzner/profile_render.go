package hetzner

import (
	"fmt"
	"net"

	"daal/publisher/deploy/profiles"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
	"daal/publisher/deploy/sni"
)

// candidatesForProfile produces the unsigned []CandidateMeta the
// FRP-4b binder will fold into the per-route _relaypack sub-object.
//
// At V1.5 every candidate is direct_vps. The PublicIP supplies the
// public_ip:* tag; family-specific defaults supply port +
// probing_risk_class + udp_gated.
//
// FRP-8 will widen this to include cdn_fronted candidates.
//
// IT RETURNS AN ERROR NOW, and that is the entire fix for L6.
//
// This function used to swallow a profile load error and return nil.
// The caller could not tell that apart from "this profile enables no
// families", so a typo'd or missing profile slug produced an
// OperatorRecord with zero candidates: a record that provisions
// happily, signs happily, and yields a pack with no routes in it. L6 —
// the rung whose whole content is "move to a different toolbox
// profile" — is the one operation that passes a NEW profile name here,
// so it is the operation the silent nil was guaranteed to hit, and it
// is why L6 has been invisible. A wrong profile name must be an error
// at the moment it is read, not a shape that looks like an empty
// choice three layers downstream.
func candidatesForProfile(profileName string, publicIP net.IP, enabledFamilies []string) ([]provider.CandidateMeta, error) {
	p, err := loadProfile(profileName)
	if err != nil {
		return nil, fmt.Errorf("hetzner: toolbox profile %q: %w", profileName, err)
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
		port := defaultPortForFamily(pc.Family)
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
		return nil, fmt.Errorf("hetzner: toolbox profile %q yields no candidates for families %v", profileName, enabledFamilies)
	}
	return out, nil
}

// defaultSingBoxConfig produces a sing-box config skeleton
// embedded in cloud-init. At FRP-14 the V2 boxes ship with the
// vless-in inbound (the REALITY-fronted port-443 transport that
// every recipient uses) carrying empty users[]; cloud-init injects
// a real REALITY private_key on first boot (see v2.yaml.tmpl) and
// the on-box mgmt service appends per-recipient user rows via
// /users/provision, including a row on the single shared ws-in inbound.
//
// The hy2-in inbound ships alongside it (hysteria2 starts fine with an
// empty users[]). Unlike REALITY, it needs a real certificate: cloud-init
// generates a self-signed data-plane leaf at /etc/daal/tls-cert.pem (+ key)
// before sing-box first starts, and the client pins it by SPKI SHA-256
// rather than name-validating it (see relaypack/client_outbound.go
// pinnedTLS). vless and hy2 share 443 on different L4 sockets (tcp vs udp).
//
// naive-in is NOT shipped here: sing-box's naive inbound FATALs with
// "missing users" if users[] is empty (protocol/naive/inbound.go), so it
// can't exist until it has a user. The mgmt service creates it — with its
// first recipient — in appendNaiveUser (8444/tcp), the same way it creates
// the single shared ws-in inbound (8445/tcp) that ALL recipients use.
// Ports come from relayports (the canonical map).
//
// coverSNI is the per-relay REALITY cover host chosen at provision time
// (publisher/deploy/sni). It is substituted into BOTH tls.server_name —
// the name the client advertises and the censor sees — AND
// reality.handshake.server — the dest this box actually completes a
// stolen handshake against. Those two must be the same string. When they
// disagree, an active prober gets a certificate from one site while the
// SNI claimed another, which is precisely the mismatch REALITY exists to
// prevent; both were hard-coded to "www.cloudflare.com" until Wave 2,
// which also made the entire fleet blockable with one SNI rule.
//
// An empty coverSNI is a caller bug, not a config option: sing-box's
// REALITY inbound needs a name, and an empty server_name is a box that
// does not start. The provider resolves the value before calling here,
// so this only ever falls back on a programming error — and it falls
// back loudly-wrong-but-working rather than silently broken.
func defaultSingBoxConfig(profileName, coverSNI string) string {
	if coverSNI == "" {
		coverSNI = sni.LegacyCoverSNI
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
             "certificate_path": "/etc/daal/tls-cert.pem", "key_path": "/etc/daal/tls-key.pem"}}
  ],
  "outbounds": [{"type": "direct"}]
}`, coverSNI)
}

// loadProfile dispatches on the profile name.
//
// The dispatch lives in the profiles package now rather than here, so
// a profile added to the registry is reachable from every adapter at
// once. A per-adapter switch is how "the wizard offers a slug the
// provisioner cannot resolve" gets introduced, and on L6 that costs
// the relay: Reprovision has already deleted the box by the time an
// unresolvable slug is noticed.
func loadProfile(name string) (*profiles.Profile, error) {
	return profiles.ByName(name)
}

func defaultPortForFamily(family string) int {
	return relayports.For(family).Port
}

func portProto(family string) string {
	if relayports.For(family).UDP {
		return "udp"
	}
	return "tcp"
}
