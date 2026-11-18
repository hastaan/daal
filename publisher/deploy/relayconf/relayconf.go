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
	"strings"

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
// this falls back to the legacy family set.
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
// EVERY INBOUND IS CONDITIONAL ON THE FAMILY SET. The box binds what the
// relay was provisioned to serve and nothing else:
//
//	vless-reality → vless-in   (443/tcp, REALITY, empty users[])
//	hysteria2     → hy2-in     (443/udp, empty users[])
//	tuic          → tuic-in    (8443/udp, empty users[])
//
// vless-in and hy2-in used to be unconditional — "the two tiers every
// Daal relay has" — which stopped being true the day `--families` could
// name a set without them: a relay provisioned with
// `shadowsocks,anytls` still listened on 443/tcp and 443/udp, with
// credentials for every recipient, behind two firewalls that were also
// unconditionally open (finding FAM-4, backlog W5-1).
//
// naive-in (8444), ws-in (8445), ss-in (8446) and anytls-in (8447) are
// never written here, whatever the family set: sing-box will not start a
// naive inbound with no users, and an empty shadowsocks inbound is an
// open relay (see cmd/daal-relay-mgmt/singbox_shadowsocks.go). The mgmt
// service creates each with its first recipient — and only for the
// families cloud-init lists in /etc/daal/families, which is this same
// list. A config with no inbounds at all is therefore legitimate (a
// relay serving only on-first-use families) and sing-box starts on it.
//
// The three written here are decided at provision time for one reason:
// binding a port is a visible, permanent property of the relay, and the
// box-side ufw rule that has to accompany it is baked by cloud-init at
// first boot and cannot be changed afterwards. Deciding the family set
// once is the only way the inbounds, the two firewalls and the minted
// pack can all agree. Changing it for an existing relay is a reprovision.
//
// A nil or empty family list means relayports.LegacyFamilies(): the
// caller could not say, so the relay is the one every relay used to be.
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
	if len(families) == 0 {
		families = relayports.LegacyFamilies()
	}
	served := map[string]bool{}
	for _, f := range families {
		served[f] = true
	}
	var inbounds []string
	if served["vless-reality"] {
		// %[1]q, twice: one value, two required sites.
		inbounds = append(inbounds, fmt.Sprintf(`    {"type": "vless", "tag": "vless-in", "listen": "0.0.0.0", "listen_port": %[2]d,
     "users": [],
     "tls": {"enabled": true, "server_name": %[1]q,
             "reality": {"enabled": true, "private_key": "", "short_id": [],
                         "handshake": {"server": %[1]q, "server_port": 443}}}}`,
			coverSNI, relayports.For("vless-reality").Port))
	}
	if served["hysteria2"] {
		inbounds = append(inbounds, fmt.Sprintf(`    {"type": "hysteria2", "tag": "hy2-in", "listen": "0.0.0.0", "listen_port": %d,
     "users": [],
     "tls": {"enabled": true,
             "certificate_path": "/etc/daal/tls-cert.pem", "key_path": "/etc/daal/tls-key.pem"}}`,
			relayports.For("hysteria2").Port))
	}
	if served["tuic"] {
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
		inbounds = append(inbounds, fmt.Sprintf(`    {"type": "tuic", "tag": "tuic-in", "listen": "0.0.0.0", "listen_port": %d,
     "users": [],
     "congestion_control": "bbr",
     "tls": {"enabled": true, "alpn": ["h3"],
             "certificate_path": "/etc/daal/tls-cert.pem", "key_path": "/etc/daal/tls-key.pem"}}`,
			relayports.For("tuic").Port))
	}
	body := ""
	if len(inbounds) > 0 {
		body = "\n" + strings.Join(inbounds, ",\n") + "\n  "
	}
	return fmt.Sprintf(`{
  "log": {"level": "info"},
  "inbounds": [%s],
  "outbounds": [{"type": "direct"}]
}`, body)
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
