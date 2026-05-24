package selection

import (
	"sort"
	"strings"
	"time"
)

// CooldownPlan is the output of the cooldown propagation step.
// `OnCandidate` is the cooldowns applied to the failed candidate
// itself; `OnSiblings` maps RouteID → []CooldownEntry to apply
// per sibling. The split exists so the pipeline writes the failed
// candidate's cooldown unconditionally and the sibling cooldowns
// only if the propagation rule says so.
type CooldownPlan struct {
	OnCandidate []CooldownEntry
	OnSiblings  map[string][]CooldownEntry
}

// PropagateCooldown computes the mode-aware cooldown propagation
// per supplement §13.4 / phase doc §6. Pure function: same inputs
// → same output. No mutation of input slices.
//
// The asymmetry pin (invariant 20):
//   - public_risk_tag failure on direct_vps OR cdn_fronted
//     propagates to siblings sharing the tag.
//   - origin_* failure on cdn_fronted does NOT propagate; only the
//     failing candidate's origin_* tags are cooled.
//   - cdn:cloudflare wide failure propagates to every sibling
//     carrying that cdn tag.
func PropagateCooldown(failed Candidate, signal NetworkSignal, peers []Candidate, now time.Time) CooldownPlan {
	plan := CooldownPlan{OnSiblings: map[string][]CooldownEntry{}}
	switch signal {
	case SignalSNIRst:
		propagateSNIRst(failed, peers, now, &plan)
	case SignalCDNHostnameBlocked:
		// Only meaningful on cdn_fronted. Cool public_domain:* and
		// host:* and sni:* but NOT cdn:*.
		if failed.ExposureMode == "cdn_fronted" {
			coolFailed(&plan, failed, now, []prefixDur{
				{"public_domain:", 30 * time.Minute},
				{"host:", 30 * time.Minute},
				{"sni:", 30 * time.Minute},
			}, signal)
			propagateOnPrefixes(&plan, failed, peers, now,
				[]string{"public_domain:"}, 30*time.Minute, signal)
		}
	case SignalOriginUnhealthy:
		// Operator-hygiene per §13.4: cool ONLY origin_* on the
		// failing candidate; do NOT propagate to siblings.
		if failed.ExposureMode == "cdn_fronted" {
			coolFailed(&plan, failed, now, []prefixDur{
				{"origin_", 60 * time.Minute},
			}, signal)
			// Explicitly NO sibling propagation. Asymmetry pin.
		}
	case SignalCDNWideFailure:
		// Cool cdn:cloudflare for 60 min on the failing candidate
		// AND every sibling carrying that cdn:* tag.
		if failed.ExposureMode == "cdn_fronted" {
			coolFailed(&plan, failed, now, []prefixDur{
				{"cdn:", 60 * time.Minute},
			}, signal)
			propagateOnPrefixes(&plan, failed, peers, now,
				[]string{"cdn:"}, 60*time.Minute, signal)
		}
	case SignalUDPCollapsed:
		// Any-mode: cool all udp_gated:true candidates for 30 min.
		if failed.UDPGated {
			plan.OnCandidate = append(plan.OnCandidate, CooldownEntry{
				Tag: "udp_gated:true", ExpiresAtUnix: now.Add(30 * time.Minute).Unix(),
				Reason: string(signal),
			})
		}
		for _, p := range peers {
			if p.RouteID == failed.RouteID {
				continue
			}
			if p.UDPGated {
				plan.OnSiblings[p.RouteID] = append(plan.OnSiblings[p.RouteID], CooldownEntry{
					Tag: "udp_gated:true", ExpiresAtUnix: now.Add(30 * time.Minute).Unix(),
					Reason: string(signal),
				})
			}
		}
	default:
		// Other signals (DNSBogon, ProtocolWhitelistMode,
		// QUICCollapsed, StatefulReassemblyPresent) are preference
		// shifts, not cooldown sources, per §13.4. Pipeline.go
		// surfaces them via Explanation.NetworkSignals; no
		// cooldowns emitted here.
	}

	// Direct-mode TCP/IP-burn rule: any "TCP RST on connect"-class
	// failure (treated upstream as caller of this function with the
	// implicit signal "tcp_rst") cools the failed candidate's
	// public_ip / public_asn / public_provider and propagates on
	// public_ip / public_asn / public_provider to siblings sharing
	// those tags. We model this by inspecting the candidate's
	// exposure_mode and the absence of any cdn-specific signal.
	if signal == "" && failed.ExposureMode == "direct_vps" {
		coolFailed(&plan, failed, now, []prefixDur{
			{"public_ip:", 5 * time.Minute},
			{"public_asn:", 30 * time.Minute},
			{"public_provider:", 30 * time.Minute},
		}, "tcp_rst")
		propagateOnPrefixes(&plan, failed, peers, now,
			[]string{"public_ip:", "public_asn:", "public_provider:"},
			0, "tcp_rst")
	}

	// Sort cooldowns by tag for byte-stable Explanation.
	sort.SliceStable(plan.OnCandidate, func(i, j int) bool {
		return plan.OnCandidate[i].Tag < plan.OnCandidate[j].Tag
	})
	for k, v := range plan.OnSiblings {
		sort.SliceStable(v, func(i, j int) bool { return v[i].Tag < v[j].Tag })
		plan.OnSiblings[k] = v
	}
	return plan
}

type prefixDur struct {
	prefix string
	dur    time.Duration
}

func propagateSNIRst(failed Candidate, peers []Candidate, now time.Time, plan *CooldownPlan) {
	// Cool sni:* always 30 min. For cdn_fronted, also cool
	// public_domain:* and host:*; for direct_vps, cool sni:* only
	// + demote probing_risk_class:high (preference shift, not a
	// cooldown — pipeline.go handles).
	switch failed.ExposureMode {
	case "cdn_fronted":
		coolFailed(plan, failed, now, []prefixDur{
			{"sni:", 30 * time.Minute},
			{"public_domain:", 30 * time.Minute},
			{"host:", 30 * time.Minute},
		}, SignalSNIRst)
		propagateOnPrefixes(plan, failed, peers, now,
			[]string{"public_domain:"}, 30*time.Minute, SignalSNIRst)
	default: // direct_vps or "" legacy
		coolFailed(plan, failed, now, []prefixDur{
			{"sni:", 30 * time.Minute},
		}, SignalSNIRst)
		propagateOnPrefixes(plan, failed, peers, now,
			[]string{"sni:"}, 30*time.Minute, SignalSNIRst)
	}
}

func coolFailed(plan *CooldownPlan, c Candidate, now time.Time, prefixes []prefixDur, signal NetworkSignal) {
	// On origin_*, the prefix is a multi-tag bag — cool every
	// origin_* tag on the candidate. On other prefixes we cool
	// every matching public_risk_tag.
	tags := c.PublicRiskTags
	if strings.HasPrefix(prefixes[0].prefix, "origin_") {
		tags = c.OriginRiskTags
	}
	for _, pd := range prefixes {
		for _, t := range tags {
			if !strings.HasPrefix(t, pd.prefix) {
				continue
			}
			plan.OnCandidate = append(plan.OnCandidate, CooldownEntry{
				Tag:           t,
				ExpiresAtUnix: now.Add(pd.dur).Unix(),
				Reason:        string(signal),
			})
		}
	}
}

// propagateOnPrefixes cools every sibling sharing any of the given
// prefix-matched public_risk_tags with `failed`. Cooldown duration
// per-prefix uses `dur`; if `dur == 0`, falls back to the prefix-
// specific duration table (used by direct-mode TCP RST rule).
func propagateOnPrefixes(plan *CooldownPlan, failed Candidate, peers []Candidate, now time.Time, prefixes []string, dur time.Duration, signal NetworkSignal) {
	defaultDur := func(tag string) time.Duration {
		if dur > 0 {
			return dur
		}
		switch {
		case strings.HasPrefix(tag, "public_ip:"):
			return 5 * time.Minute
		case strings.HasPrefix(tag, "public_asn:"):
			return 30 * time.Minute
		case strings.HasPrefix(tag, "public_provider:"):
			return 30 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	for _, prefix := range prefixes {
		failedTags := tagsWithPrefix(failed.PublicRiskTags, prefix)
		if len(failedTags) == 0 {
			continue
		}
		for _, p := range peers {
			if p.RouteID == failed.RouteID {
				continue
			}
			for _, ft := range failedTags {
				for _, pt := range p.PublicRiskTags {
					if pt != ft {
						continue
					}
					if !sharedRiskAllowsPropagation(failed, p, ft) {
						continue
					}
					plan.OnSiblings[p.RouteID] = append(plan.OnSiblings[p.RouteID], CooldownEntry{
						Tag:           ft,
						ExpiresAtUnix: now.Add(defaultDur(ft)).Unix(),
						Reason:        string(signal),
					})
				}
			}
		}
	}
}

func sharedRiskAllowsPropagation(failed, peer Candidate, tag string) bool {
	members, ok := failed.SharedRiskMembers(tag)
	if !ok {
		return true
	}
	for _, m := range members {
		if m == peer.RouteID {
			return true
		}
	}
	return false
}
