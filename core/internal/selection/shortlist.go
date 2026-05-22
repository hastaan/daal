package selection

import (
	"sort"
	"strings"
)

// Shortlist computes the up-to-`size` race-shortlist from `cands`,
// applying:
//
//   - Hard rule: never include two candidates that share a `cdn:*`
//     tag (supplement v2.3.5 §13.1).
//   - Soft preference: prefer public-risk diversity on
//     `public_ip:*` and `public_domain:*` tags.
//   - Single-VPS V1.5 fallback: when all remaining candidates share
//     the same `public_ip:*` (the dominant V1.5 case), select on
//     secondary axes — protocol family, SNI tag, probing_risk_class,
//     port — maximising secondary-axis distance.
//   - Mode mixing (V1.6+): always prefer mixing direct_vps and
//     cdn_fronted candidates when both are available and the
//     phase allows it.
//
// Ties are broken lexicographically by RouteID for byte-stable
// shortlists across runs.
//
// Pure function: never mutates `cands` or any sub-slice; returns a
// fresh slice.
func Shortlist(cands []Candidate, size int, phase Phase) []Candidate {
	if size <= 0 || len(cands) == 0 {
		return []Candidate{}
	}
	// Defensive copy + stable rank order so the leader pick is the
	// highest-ranked candidate. RouteID remains the deterministic
	// tie-break when callers do not provide RankScore.
	pool := make([]Candidate, len(cands))
	copy(pool, cands)
	sort.SliceStable(pool, func(i, j int) bool {
		if pool[i].RankScore != pool[j].RankScore {
			return pool[i].RankScore > pool[j].RankScore
		}
		return pool[i].RouteID < pool[j].RouteID
	})

	// Cap requested size to pool size.
	if size > len(pool) {
		size = len(pool)
	}

	out := make([]Candidate, 0, size)
	out = append(out, pool[0])

	for len(out) < size {
		next := pickNext(out, pool, phase)
		if next == nil {
			break
		}
		out = append(out, *next)
	}
	return out
}

// pickNext selects the next shortlist member from the pool given
// what's already been picked. Returns nil if no eligible candidate
// remains.
func pickNext(picked, pool []Candidate, phase Phase) *Candidate {
	type scored struct {
		idx   int
		score int
	}
	var ranked []scored
	for i, c := range pool {
		if alreadyPicked(c, picked) {
			continue
		}
		// Hard rule: skip when cdn:* tag overlap with any picked.
		if hasCDNOverlap(c, picked) {
			continue
		}
		ranked = append(ranked, scored{idx: i, score: c.RankScore + diversityScore(c, picked, phase)})
	}
	if len(ranked) == 0 {
		return nil
	}
	// Highest score wins; tie-break by RouteID lex order (already
	// enforced by pool's stable sort above; ranked preserves index
	// order which is RouteID order).
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return pool[ranked[i].idx].RouteID < pool[ranked[j].idx].RouteID
	})
	c := pool[ranked[0].idx]
	return &c
}

func alreadyPicked(c Candidate, picked []Candidate) bool {
	for _, p := range picked {
		if p.RouteID == c.RouteID {
			return true
		}
	}
	return false
}

// hasCDNOverlap reports whether c shares any cdn:* tag with any
// candidate in picked. Hard prohibition per supplement v2.3.5 §13.1.
func hasCDNOverlap(c Candidate, picked []Candidate) bool {
	cdnsC := tagsWithPrefix(c.PublicRiskTags, "cdn:")
	if len(cdnsC) == 0 {
		return false
	}
	for _, p := range picked {
		for _, pc := range tagsWithPrefix(p.PublicRiskTags, "cdn:") {
			for _, cc := range cdnsC {
				if pc == cc {
					return true
				}
			}
		}
	}
	return false
}

// diversityScore is a heuristic ranking. Higher = more preferred.
// Each diversity dimension contributes a fixed weight; the leader
// selection is implicit (we always start with pool[0]).
//
// Weights (inversely proportional to ease of achieving diversity
// in V1.5): mode mixing > public_ip diversity > public_domain >
// protocol family > SNI > probing_risk_class > port.
func diversityScore(c Candidate, picked []Candidate, phase Phase) int {
	score := 0

	// Mode mixing (V1.6+). At V1.5 there are no cdn_fronted
	// candidates so this rule is inert — invariant 19 — but the
	// scoring code path is exercised.
	if phase != PhaseV15 {
		hasDirect := false
		hasCDN := false
		for _, p := range picked {
			if p.ExposureMode == "direct_vps" {
				hasDirect = true
			}
			if p.ExposureMode == "cdn_fronted" {
				hasCDN = true
			}
		}
		if c.ExposureMode == "cdn_fronted" && hasDirect && !hasCDN {
			score += 1000
		}
		if c.ExposureMode == "direct_vps" && hasCDN && !hasDirect {
			score += 1000
		}
	}

	// Soft public_ip diversity.
	if !sharesAnyTag(c.PublicRiskTags, picked, "public_ip:") {
		score += 500
	}
	// Soft public_domain diversity.
	if !sharesAnyTag(c.PublicRiskTags, picked, "public_domain:") {
		score += 250
	}

	// Secondary axes (single-VPS V1.5 fallback). These dominate when
	// the public-IP rule is forced to a single value.
	if !samesAsAny(c.TransportFamily, picked, func(p Candidate) string { return p.TransportFamily }) {
		score += 100
	}
	if !sharesAnyTag(c.PublicRiskTags, picked, "sni:") {
		score += 60
	}
	if !samesAsAny(c.ProbingRiskClass, picked, func(p Candidate) string { return p.ProbingRiskClass }) {
		score += 30
	}
	if !sharesAnyTag(c.PublicRiskTags, picked, "public_port:") {
		score += 10
	}
	return score
}

// tagsWithPrefix returns the subset of tags starting with prefix.
func tagsWithPrefix(tags []string, prefix string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			out = append(out, t)
		}
	}
	return out
}

// sharesAnyTag reports whether c's tags-with-prefix overlap with
// the same-prefix tags of any candidate in picked. "Sharing" means
// equal tag value (e.g. "public_ip:5.75.0.1").
func sharesAnyTag(tags []string, picked []Candidate, prefix string) bool {
	for _, t := range tagsWithPrefix(tags, prefix) {
		for _, p := range picked {
			for _, pt := range tagsWithPrefix(p.PublicRiskTags, prefix) {
				if pt == t {
					return true
				}
			}
		}
	}
	return false
}

// samesAsAny reports whether key(c) equals key(p) for some p in
// picked. Used for protocol family / probing_risk_class diversity.
func samesAsAny(value string, picked []Candidate, key func(Candidate) string) bool {
	if value == "" {
		return false
	}
	for _, p := range picked {
		if key(p) == value {
			return true
		}
	}
	return false
}
