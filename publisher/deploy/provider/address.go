package provider

import (
	"fmt"
	"net"
	"strings"

	"daal/publisher/deploy/sni"
)

// THE RECORD HAS TWO COPIES OF THE DIALED ADDRESS, AND BOTH MUST MOVE.
//
// This file is provider-agnostic on purpose. It was born inside the
// Hetzner adapter, where L3 rotated nothing for a whole wave because
// AssignFloatingIP set FloatingIPID — a field nothing on the wire reads
// — and left rec.PublicIP and every candidate's public_ip:* tag naming
// the burned address. The provider call succeeded, the pack was
// re-signed, the UI said the rotation worked, and every recipient's
// pack pointed at exactly the address that had been blocked.
//
// Wave 6 adds a second cloud. Two adapters each carrying their own copy
// of that fix is how one of them silently loses it, so the fix lives
// once, here, where every adapter and the rotation code can reach it.

// PublicIPTagPrefix is the candidate-tag vocabulary item that carries
// the dialed address. The rotation recommender keys its L3
// recommendation off the same prefix, so the two must not drift.
const PublicIPTagPrefix = "public_ip:"

// AdoptPublicIP writes one address into every place the record claims a
// dialed address: the PublicIP field the client outbound is built from,
// and the public_ip:* tag on every candidate, which is what the risk
// graph groups on and what the recommender reads back when deciding
// whether an address is in cooldown.
//
// Both, always. A record where they disagree produces a signed pack
// that dials one address and declares another, so a burned-address
// cooldown would keep firing against a relay that had already moved.
func AdoptPublicIP(rec *OperatorRecord, ip net.IP) {
	if rec == nil || len(ip) == 0 {
		return
	}
	rec.PublicIP = ip
	for i := range rec.Candidates {
		rec.Candidates[i].PublicRiskTags = RetagPublicIP(rec.Candidates[i].PublicRiskTags, ip)
	}
}

// RetagPublicIP replaces the public_ip:* tag in one candidate's tag
// list, preserving the position and the order of everything else.
//
// Rewrite-in-place rather than append-and-move-on: the tags are a set
// the recipient-side selector reasons over, and a candidate carrying
// two public_ip:* tags is a candidate that is simultaneously in and out
// of an address cooldown. Duplicates that were already there are
// collapsed onto the first slot for the same reason.
func RetagPublicIP(tags []string, ip net.IP) []string {
	want := PublicIPTagPrefix + ip.String()
	out := make([]string, 0, len(tags)+1)
	replaced := false
	for _, t := range tags {
		if !strings.HasPrefix(t, PublicIPTagPrefix) {
			out = append(out, t)
			continue
		}
		if replaced {
			continue // collapse pre-existing duplicates
		}
		out = append(out, want)
		replaced = true
	}
	if !replaced {
		out = append(out, want)
	}
	return out
}

// CoverSNIPlausibleForAddress is the Wave-2 interaction, and the reason
// L3 is not simply "swap the address". fipID and homeRegion describe
// the address about to be attached.
//
// THE DECISION: an L3 swap does NOT re-pick the cover SNI, and refuses
// the swap outright when the new address makes the current cover host
// implausible. Both halves need the justification.
//
// Why not re-pick. The rule in publisher/deploy/sni/rule.go admits a
// host on properties of the ADDRESS CLASS, not of the specific address:
// R5 wants the cover host served from hosting/colo AS space like the
// relay itself, and R6 wants it in the relay's peering neighbourhood.
// A floating address homed in the relay's own region is announced from
// the same provider's AS out of that same region, so every property the
// pick was made on is unchanged — while re-picking costs plenty: the
// cover host is baked into the box's sing-box config in two places
// (tls.server_name and reality.handshake.server), so moving it means an
// in-place rotate-tls call, a different and capability-gated operation
// on a relay whose pinned mgmt binary may not support it at all. An L3
// that silently performs an L2 is also a rotation the operator did not
// ask for and cannot see.
//
// Why refuse instead of proceeding. Both clouds permit attaching an
// address homed in region A to a machine in region B. Then the packet's
// destination sits in a neighbourhood the cover host was never picked
// for, and the (address, SNI) pair a censor sees for free becomes
// exactly the obviously-implausible IP-to-SNI mapping the corpus's
// avoid-list ends on. Since L3 must not fix it by re-picking, the only
// honest move left is to stop and say so. The operator's options are
// both cheap: reserve the address in the relay's own region, or run an
// L2 rotate-tls afterwards to move the cover host deliberately.
//
// Not judgeable ⇒ allowed. A record with no cover SNI predates Wave 2,
// an address with no home region cannot be placed, and a cover host
// that is not in the pool was either operator-supplied or dropped by an
// audit. Guessing in any of those cases would block rotations that are
// fine.
func CoverSNIPlausibleForAddress(rec *OperatorRecord, fipID, homeRegion string) error {
	if rec == nil || rec.CoverSNI == "" || homeRegion == "" {
		return nil
	}
	if !sni.ZoneMismatch(rec.CoverSNI, homeRegion) {
		return nil
	}
	hostZone, _ := sni.ZoneOfHost(rec.CoverSNI)
	return fmt.Errorf(
		"floating ip %s is homed in %s (%s) but this relay advertises cover host %q, which is a %s host: "+
			"attaching it would leave the relay claiming a TLS destination that does not belong near its own address. "+
			"Reserve an address in %s instead, or rotate the cover host (L2 rotate-tls) into %s first",
		fipID, homeRegion, sni.ZoneFor(homeRegion), rec.CoverSNI, hostZone,
		rec.Region, sni.ZoneFor(homeRegion))
}
