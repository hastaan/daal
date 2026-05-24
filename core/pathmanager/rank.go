package pathmanager

import (
	"sort"
)

// Route is the minimal projection that Rank operates on. Pathmanager
// knows about route_id, family, modes_allowed, and consumed/cap
// fractions; nothing else. The caller (the engine layer) is
// responsible for assembling this slice from the routestore + the
// budget engine snapshot.
//
// `BudgetTag` is informative for diagnostics and for the
// `bulk-capable` deprefer step; rank does not consult the cap table
// directly.
type Route struct {
	RouteID      string
	Family       string
	ModesAllowed []string
	HourlyCap    uint64 // 0 == unlimited
	Consumed     uint64
	BudgetTag    string
}

// Rank is the pure mode-aware filter+sort for V2.2's mode budgets.
// It does NOT mutate input; it returns a fresh slice.
//
// Behaviour (locked at 2B):
//
//  1. Filter — keep only routes whose ModesAllowed contains `mode`.
//     In `bulk` mode this leaves bulk-capable routes only (per V2.2
//     "Bulk — explicit opt-in, only on bulk-capable routes").
//
//  2. In `lifeline` and `normal` modes, push `bulk-capable`-tagged
//     routes to the END of the result (deprefer). The user opted
//     into a budget-conscious mode; burning a paid bulk route on
//     chat-class traffic is the wrong default.
//
//  3. Within each rank class (non-bulk-capable, then bulk-capable
//     in non-bulk modes), sort ascending by `Consumed/Cap`. Cap=0
//     (unlimited) is treated as 0% consumed (always first within
//     class) — the deprefer step in (2) already handles bulk-capable
//     in non-bulk modes, so this only affects routes whose tag
//     legitimately allows the mode but happens to have an unlimited
//     hourly cap (`normal` and `experimental` in fact have
//     finite-hourly caps; `bulk-capable` is the only unlimited tag,
//     and it's already deprefered or filter-only).
//
//  4. Stable tie-break by `RouteID`.
//
// At 2B Rank is exercised by tests + diagnostics; the connect path
// (engine_set_route) still accepts a user-chosen route_id verbatim.
// 2C wires Rank into a richer "next route" picker.
//
// Phase 2D: `lifeline-strict` mode dispatches to RankWithView with a
// zero view. Callers that have a real per-network view (active
// network's failure rates + the engine's bulk-capable opt-in flag)
// should call RankWithView directly to get the stability bias and
// the per-session bulk opt-in.
func Rank(rs []Route, mode string) []Route {
	return RankWithView(rs, mode, zeroNetworkView{})
}

// RankWithView is the 2D extension of Rank. For mode == "lifeline-strict"
// it filters bulk-capable routes (unless view.AllowsBulkCapableThisSession())
// and sorts ascending by view.FailureRate, tie-breaking by consumed-fraction
// and route_id.
//
// For modes other than "lifeline-strict" the view is ignored and the
// result is byte-identical to 2B's Rank — i.e., the modes_allowed
// filter, the bulk-capable deprefer in non-bulk modes, the
// consumed-fraction sort, the route_id tie-break.
func RankWithView(rs []Route, mode string, view NetworkView) []Route {
	if view == nil {
		view = zeroNetworkView{}
	}
	out := make([]Route, 0, len(rs))
	// Filter step. lifeline-strict shares the lifeline modes_allowed
	// set (a route allowed in lifeline is allowed in lifeline-strict)
	// and additionally refuses bulk-capable unless the per-session
	// opt-in is set.
	filterMode := mode
	if mode == "lifeline-strict" {
		filterMode = "lifeline"
	}
	for _, r := range rs {
		if !contains(r.ModesAllowed, filterMode) {
			continue
		}
		if mode == "lifeline-strict" && isBulkCapable(r) && !view.AllowsBulkCapableThisSession() {
			continue
		}
		out = append(out, r)
	}
	if mode == "lifeline-strict" {
		// Stability bias: ascending failure rate, then ascending
		// consumed-fraction, then route_id.
		sort.SliceStable(out, func(i, j int) bool {
			fi := view.FailureRate(out[i].RouteID)
			fj := view.FailureRate(out[j].RouteID)
			if fi != fj {
				return fi < fj
			}
			ci := consumedFraction(out[i])
			cj := consumedFraction(out[j])
			if ci != cj {
				return ci < cj
			}
			return out[i].RouteID < out[j].RouteID
		})
		return out
	}
	// 2B sort: bulk-capable last in non-bulk modes; otherwise
	// ascending by consumed-fraction; tie-break by route_id.
	depreferBulk := mode != "bulk"
	sort.SliceStable(out, func(i, j int) bool {
		ai := isBulkCapable(out[i])
		aj := isBulkCapable(out[j])
		if depreferBulk && ai != aj {
			return aj
		}
		fi := consumedFraction(out[i])
		fj := consumedFraction(out[j])
		if fi != fj {
			return fi < fj
		}
		return out[i].RouteID < out[j].RouteID
	})
	return out
}

// contains reports whether s contains v. Pure helper.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func isBulkCapable(r Route) bool {
	return r.BudgetTag == "bulk-capable"
}

// consumedFraction is Consumed/HourlyCap with cap=0 (unlimited)
// treated as 0% (the route has unbounded headroom).
func consumedFraction(r Route) float64 {
	if r.HourlyCap == 0 {
		return 0
	}
	return float64(r.Consumed) / float64(r.HourlyCap)
}
