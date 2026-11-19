package abi

import (
	"encoding/json"
	"errors"
	"fmt"

	"daal/core/engine"
	"daal/core/netmem"
)

// Network facts from the host — engine_network_facts.
//
// The engine sees the world only through its routes. It cannot tell
// "this phone has no internet" from "the relay is dead" (the rig's
// AUTO-1), it learns that the network changed only when a page happens
// to be open to say so, and until now its whole idea of WHICH network
// it is on was the word "wifi" or "mobile". The host knows all three,
// for free: on Android a ConnectivityManager.NetworkCallback registered
// by the VPN service. This call is how it says so.
//
//	kind       "wifi" | "cellular" | "ethernet" | "vpn" | "other" | "none"
//	           — the underlying (non-VPN) default network. "none": the
//	           device is on no network at all.
//	id         an opaque string that is the same every time the device is
//	           on this network and different on another one. It is hashed
//	           on entry (netmem.HashID, the hash engine_network_changed
//	           uses) and never stored, logged or returned in clear; only
//	           the hash is the key of this network's memory. "" is
//	           allowed: the kind is then the whole identity.
//	validated  1: the platform found the network to reach the internet
//	           (Android NET_CAPABILITY_VALIDATED); 0: it did not; -1: not
//	           known.
//	metered    1 / 0 / -1 likewise.
//
// WHAT THE ENGINE DOES WITH THEM.
//
//   - The hashed id is the key of the per-network route memory. The
//     first time a network of a kind is named, it takes over what was
//     remembered under the old kind-only record (the page's
//     engine_network_changed("wifi","","") bucket, then the record of an
//     engine that was never told anything), which is then deleted: see
//     netmem.AdoptRouteMemory.
//   - A change — another network, a network after none, a network that
//     has just become validated — asks the liveness loop to check the
//     connected route NOW (kickLiveness) instead of at its 3-minute
//     tick.
//   - kind "none" turns the verdict of a pass in which nothing at all
//     answered into `network_down`. No traffic is added to learn it.
//   - validated is REPORTED (the `network` block of the diagnostics
//     blob, for Details) and used for one thing: a network that has just
//     become validated is worth a check now. It is NOT evidence that the
//     device has no internet: a network that filters the platform's own
//     connectivity check — ordinary inside the country this is built
//     for — is never validated and carries traffic all the same. A pass
//     in which nothing answered on such a network keeps the verdict the
//     observations give (relay_unreachable: "this network, or the
//     server"), and nothing is stopped from being tried.
//   - kind "none" keeps the engine from starting a fall-over pass by
//     itself (autoFallOver): there is nothing to move to.
//   - metered 1 keeps the engine from starting side probes by itself
//     (connect_race.go, connect_speed.go).
//
// Once a host has called this, engine_network_changed is answered and
// changes nothing (NetworkChanged): two callers naming one network two
// ways would split its memory.
const (
	NetKindWiFi     = "wifi"
	NetKindCellular = "cellular"
	NetKindEthernet = "ethernet"
	NetKindVPN      = "vpn"
	NetKindOther    = "other"
	NetKindNone     = "none"
)

// netFactsDomain separates the ids a host reports here from the
// (carrier, ssid) pairs engine_network_changed hashes: it goes where
// that call puts the carrier.
const netFactsDomain = "host-network"

// netFacts is what the host last said. The zero value: nothing.
type netFacts struct {
	seen               bool
	kind               string
	validated, metered int
}

// hostFacts returns the host's last report.
func hostFacts() netFacts {
	globalNetmem.mu.Lock()
	defer globalNetmem.mu.Unlock()
	return globalNetmem.facts
}

// noNetwork: the host says the device is on no network at all.
func (f netFacts) noNetwork() bool { return f.seen && f.kind == NetKindNone }

func (f netFacts) block() map[string]any {
	if !f.seen {
		return map[string]any{"from_host": false, "kind": "", "validated": -1, "metered": -1}
	}
	return map[string]any{"from_host": true, "kind": f.kind, "validated": f.validated, "metered": f.metered}
}

func triState(v int) int {
	switch v {
	case 0, 1:
		return v
	}
	return -1
}

// legacyBuckets are the hashed ids of the records a network of this
// kind was remembered under before the host named networks: the kind
// alone, as the page reports it, then the record of an engine nobody
// told anything.
func legacyBuckets(kind string) []string {
	var out []string
	switch kind {
	case NetKindWiFi:
		out = append(out, netmem.HashID(netmem.KindWiFi, "", ""))
	case NetKindCellular:
		out = append(out, netmem.HashID(netmem.KindCell, "", ""))
	case NetKindEthernet:
		out = append(out, netmem.HashID(netmem.KindEth, "", ""))
	}
	return append(out, netmem.SentinelUnset)
}

// NetworkFacts is engine_network_facts. See the top of this file.
//
// Returns {"network_id","kind","validated","metered","changed","fresh"}:
// network_id is the HASHED id the engine is on now (unchanged by kind
// "none"), changed whether this report differs from the last in a way
// the engine acted on, fresh whether the network was never seen before.
// The error is non-nil for an unknown kind or an engine that is not
// initialised.
func NetworkFacts(kind, id string, validated, metered int) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	switch kind {
	case NetKindWiFi, NetKindCellular, NetKindEthernet, NetKindVPN, NetKindOther, NetKindNone:
	default:
		return "", errors.New("abi: invalid network kind")
	}
	next := netFacts{seen: true, kind: kind, validated: triState(validated), metered: triState(metered)}
	prev := hostFacts()

	fresh, netChanged := false, false
	if kind == NetKindNone {
		// No network is not A network: what is remembered stays filed
		// under the one the device was last on.
		next.validated = 0
	} else {
		incoming := netmem.HashID(netmem.Kind(kind), netFactsDomain, id)
		// The clear id goes no further than the line above.
		id = ""
		_ = id
		var err error
		fresh, _, netChanged, err = c.switchNetwork(incoming, legacyBuckets(kind))
		if err != nil {
			return "", err
		}
	}
	globalNetmem.mu.Lock()
	globalNetmem.facts = next
	globalNetmem.mu.Unlock()

	// Worth a check of the connected route right now: another network,
	// a network where there was none, or one the platform has just found
	// to work. Going DOWN is not: there is nothing to check with.
	kick := kind != NetKindNone && (netChanged || !prev.seen || prev.kind == NetKindNone || (prev.validated != 1 && next.validated == 1))
	changed := netChanged || prev != next
	if changed {
		engine.LogInfo(fmt.Sprintf("network facts kind=%s validated=%d metered=%d network_changed=%t check_now=%t",
			kind, next.validated, next.metered, netChanged, kick))
	}
	if kick {
		if netChanged {
			c.resetDriverNetwork()
		}
		c.kickLiveness()
	}
	body, _ := json.Marshal(map[string]any{
		"network_id": activeNetworkID(),
		"kind":       kind,
		"validated":  next.validated,
		"metered":    next.metered,
		"changed":    changed,
		"fresh":      fresh,
	})
	return string(body), nil
}
