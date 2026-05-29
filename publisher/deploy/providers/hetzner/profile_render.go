package hetzner

import (
	"fmt"
	"net"

	"daal/publisher/deploy/profiles"
	"daal/publisher/deploy/provider"
)

// candidatesForProfile produces the unsigned []CandidateMeta the
// FRP-4b binder will fold into the per-route _relaypack sub-object.
//
// At V1.5 every candidate is direct_vps. The PublicIP supplies the
// public_ip:* tag; family-specific defaults supply port +
// probing_risk_class + udp_gated.
//
// FRP-8 will widen this to include cdn_fronted candidates.
func candidatesForProfile(profileName string, publicIP net.IP, enabledFamilies []string) []provider.CandidateMeta {
	p, err := loadProfile(profileName)
	if err != nil {
		return nil
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
	return out
}

// defaultSingBoxConfig produces a sing-box config skeleton
// embedded in cloud-init. At FRP-14 the V2 boxes ship with the
// vless-in inbound (the REALITY-fronted port-443 transport that
// every recipient uses) carrying empty users[]; cloud-init injects
// a real REALITY private_key on first boot (see v2.yaml.tmpl) and
// the on-box mgmt service appends per-recipient user rows via
// /users/provision and a fresh ws-r<id> inbound per recipient.
//
// Hysteria2 and Naive inbounds are intentionally NOT shipped in
// the default config: sing-box refuses to start either without a
// TLS block, and the per-user appenders in singbox_users.go are
// no-ops when those inbounds aren't present. They'll be added
// later when we ship the toolbox-profile-driven UDP/TCP-multi-
// transport story. See specs/per-recipient-credentials-v1.md.
func defaultSingBoxConfig(profileName string) string {
	return `{
  "log": {"level": "info"},
  "inbounds": [
    {"type": "vless", "tag": "vless-in", "listen": "0.0.0.0", "listen_port": 443,
     "users": [],
     "tls": {"enabled": true, "server_name": "www.cloudflare.com",
             "reality": {"enabled": true, "private_key": "", "short_id": [],
                         "handshake": {"server": "www.cloudflare.com", "server_port": 443}}}}
  ],
  "outbounds": [{"type": "direct"}]
}`
}

// loadProfile dispatches on the profile name. iran-default is the
// only supported profile at V1.5.
func loadProfile(name string) (*profiles.Profile, error) {
	if name == "iran-default" {
		return profiles.IranDefault()
	}
	return nil, fmt.Errorf("unknown toolbox profile %q", name)
}

func defaultPortForFamily(family string) int {
	switch family {
	case "hysteria2", "tuic":
		return 443 // UDP
	case "wireguard", "amnezia-wg":
		return 51820
	default:
		return 443 // TCP
	}
}

func portProto(family string) string {
	switch family {
	case "hysteria2", "tuic", "wireguard", "amnezia-wg":
		return "udp"
	default:
		return "tcp"
	}
}
