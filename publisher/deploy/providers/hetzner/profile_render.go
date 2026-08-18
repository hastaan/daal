package hetzner

import (
	"fmt"
	"net"

	"daal/publisher/deploy/profiles"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayconf"
	"daal/publisher/deploy/relayports"
)

// This file used to BE the renderer. It is now four thin adapters onto
// publisher/deploy/relayconf, which holds the one copy.
//
// The move happened in Wave 6, when Vultr became a real rotation target
// for L5. Vultr had its own imitation of these functions — different
// family names, no profile errors, a placeholder sing-box config — so
// "rotate provider" would have moved the operator onto a box that was
// not the same relay. Two renderers is how that happens; one renderer
// is how it cannot. See relayconf's package comment.
//
// The wrappers stay because the error text an operator reads should
// name the cloud they are on, and because everything in this package
// already calls these names.

// candidatesForProfile produces the unsigned []CandidateMeta the
// FRP-4b binder will fold into the per-route _relaypack sub-object.
// See relayconf.CandidatesForProfile, including why an unresolvable
// profile is an error rather than an empty slice (the L6 fix).
func candidatesForProfile(profileName string, publicIP net.IP, enabledFamilies []string) ([]provider.CandidateMeta, error) {
	out, err := relayconf.CandidatesForProfile(profileName, publicIP, enabledFamilies)
	if err != nil {
		return nil, fmt.Errorf("hetzner: %w", err)
	}
	return out, nil
}

// servedFamilies resolves the family set this relay will actually
// serve. One resolver for the sing-box inbounds, the box-side ufw rules
// and the cloud firewall — see relayconf.ServedFamilies.
func servedFamilies(profileName string, enabledFamilies []string) ([]string, error) {
	out, err := relayconf.ServedFamilies(profileName, enabledFamilies)
	if err != nil {
		return nil, fmt.Errorf("hetzner: %w", err)
	}
	return out, nil
}

// defaultSingBoxConfig produces the sing-box config skeleton embedded
// in cloud-init for the profile's default-enabled families.
func defaultSingBoxConfig(profileName, coverSNI string) string {
	return relayconf.DefaultSingBoxConfig(profileName, coverSNI)
}

// singBoxConfigForFamilies is defaultSingBoxConfig with the served
// family set supplied explicitly.
func singBoxConfigForFamilies(coverSNI string, families []string) string {
	return relayconf.SingBoxConfigForFamilies(coverSNI, families)
}

// loadProfile dispatches on the profile name.
//
// The dispatch lives in the profiles package rather than here, so a
// profile added to the registry is reachable from every adapter at
// once. A per-adapter switch is how "the wizard offers a slug the
// provisioner cannot resolve" gets introduced, and on L6 that costs the
// relay: Reprovision has already deleted the box by the time an
// unresolvable slug is noticed.
func loadProfile(name string) (*profiles.Profile, error) {
	return profiles.ByName(name)
}

func defaultPortForFamily(family string) int {
	return relayconf.DefaultPortForFamily(family)
}

func portProto(family string) string {
	if relayports.For(family).UDP {
		return "udp"
	}
	return "tcp"
}
