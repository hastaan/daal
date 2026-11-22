package fieldprobe

import "time"

// The run allowance (specs/field-probe-v2.md §2): one run per network
// per 6 hours, three per day in all. The engine enforces it, not the
// page. The history is the engine's own (encrypted at rest beside the
// result); network keys are the engine's hashed network ids.

const (
	PerNetworkGap = 6 * time.Hour
	PerDay        = 3
	ResultTTL     = 7 * 24 * time.Hour
)

// History is the record of past runs.
type History struct {
	Runs []HistoryRun `json:"runs"`
}

// HistoryRun is one past run: the hashed network and the hour it began,
// rounded UP to the hour (no second-precision time sits beside a
// network id, even encrypted; rounding up keeps the allowance at least
// as strict as stated).
type HistoryRun struct {
	Net string `json:"net"`
	At  int64  `json:"at"`
}

// Allow says whether a run may start now on net, and if not, when.
func (h History) Allow(net string, now time.Time) (bool, time.Duration) {
	var day int
	var wait time.Duration
	for _, r := range h.Runs {
		at := time.Unix(r.At, 0)
		age := now.Sub(at)
		if age < 0 {
			age = 0
		}
		if age < 24*time.Hour {
			day++
			if w := 24*time.Hour - age; day >= PerDay && (wait == 0 || w < wait) {
				wait = w
			}
		}
		if r.Net == net && age < PerNetworkGap {
			if w := PerNetworkGap - age; w > wait {
				wait = w
			}
		}
	}
	if day >= PerDay || wait > 0 {
		return false, wait
	}
	return true, 0
}

// Note records a run and forgets those older than a day.
func (h *History) Note(net string, now time.Time) {
	kept := h.Runs[:0]
	for _, r := range h.Runs {
		if now.Sub(time.Unix(r.At, 0)) < 24*time.Hour {
			kept = append(kept, r)
		}
	}
	h.Runs = append(kept, HistoryRun{Net: net, At: CeilHour(now).Unix()})
}

// CeilHour rounds t up to the next whole hour (t itself if it is one).
func CeilHour(t time.Time) time.Time {
	f := t.Truncate(time.Hour)
	if f.Equal(t) {
		return f
	}
	return f.Add(time.Hour)
}
