package threshold_compare

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

func TestLockedThresholds(t *testing.T) {
	// Lock-down test for the 2G defaults carried into 3-Soak.
	if LockedA.DistinctFamilyMinimum != 3 {
		t.Errorf("LockedA.DistinctFamilyMinimum = %d, want 3", LockedA.DistinctFamilyMinimum)
	}
	if LockedA.WindowDuration != 30*time.Minute {
		t.Errorf("LockedA.WindowDuration = %s, want 30m", LockedA.WindowDuration)
	}
	if LockedA.LadderStepMinimum != 3 {
		t.Errorf("LockedA.LadderStepMinimum = %d, want 3", LockedA.LadderStepMinimum)
	}
	// Lock-down for the tightened candidate.
	if LockedB.DistinctFamilyMinimum != 4 {
		t.Errorf("LockedB.DistinctFamilyMinimum = %d, want 4", LockedB.DistinctFamilyMinimum)
	}
	if LockedB.WindowDuration != 20*time.Minute {
		t.Errorf("LockedB.WindowDuration = %s, want 20m", LockedB.WindowDuration)
	}
	if LockedB.LadderStepMinimum != 4 {
		t.Errorf("LockedB.LadderStepMinimum = %d, want 4", LockedB.LadderStepMinimum)
	}
}

func TestCompare_NoTicks_NoFires(t *testing.T) {
	a, b := Compare(nil)
	if a.Fires != 0 || b.Fires != 0 {
		t.Errorf("empty input: A.Fires=%d B.Fires=%d, want 0/0", a.Fires, b.Fires)
	}
	if a.TickCount != 0 || b.TickCount != 0 {
		t.Errorf("empty input: A.TickCount=%d B.TickCount=%d, want 0/0", a.TickCount, b.TickCount)
	}
}

func TestCompare_AFires_BDoesNot(t *testing.T) {
	// 3 families, ladder ≥ 3 → A fires; B requires 4 families → no fire.
	tick := Tick{
		Now: t0,
		Skipped: []Skipped{
			{Family: "vless", Until: t0.Add(15 * time.Minute), LadderStep: 3},
			{Family: "hysteria2", Until: t0.Add(15 * time.Minute), LadderStep: 3},
			{Family: "snowflake", Until: t0.Add(15 * time.Minute), LadderStep: 3},
		},
	}
	a, b := Compare([]Tick{tick})
	if a.Fires != 1 {
		t.Errorf("A.Fires = %d, want 1", a.Fires)
	}
	if b.Fires != 0 {
		t.Errorf("B.Fires = %d, want 0 (only 3 families; B needs 4)", b.Fires)
	}
}

func TestCompare_BothFire(t *testing.T) {
	// 4 families, ladder ≥ 4 → both A and B fire.
	tick := Tick{
		Now: t0,
		Skipped: []Skipped{
			{Family: "vless", Until: t0.Add(15 * time.Minute), LadderStep: 4},
			{Family: "hysteria2", Until: t0.Add(15 * time.Minute), LadderStep: 4},
			{Family: "snowflake", Until: t0.Add(15 * time.Minute), LadderStep: 4},
			{Family: "masque", Until: t0.Add(15 * time.Minute), LadderStep: 4},
		},
	}
	a, b := Compare([]Tick{tick})
	if a.Fires != 1 || b.Fires != 1 {
		t.Errorf("both should fire: A=%d B=%d", a.Fires, b.Fires)
	}
}

func TestCompare_NeitherFires_LadderTooShallow(t *testing.T) {
	tick := Tick{
		Now: t0,
		Skipped: []Skipped{
			{Family: "vless", Until: t0.Add(15 * time.Minute), LadderStep: 1},
			{Family: "hysteria2", Until: t0.Add(15 * time.Minute), LadderStep: 1},
			{Family: "snowflake", Until: t0.Add(15 * time.Minute), LadderStep: 1},
			{Family: "masque", Until: t0.Add(15 * time.Minute), LadderStep: 1},
		},
	}
	a, b := Compare([]Tick{tick})
	if a.Fires != 0 || b.Fires != 0 {
		t.Errorf("neither should fire (ladder=1): A=%d B=%d", a.Fires, b.Fires)
	}
}

func TestCompare_ExpiredCooldownsIgnored(t *testing.T) {
	// Cooldown Until is in the past → does not count.
	tick := Tick{
		Now: t0,
		Skipped: []Skipped{
			{Family: "vless", Until: t0.Add(-15 * time.Minute), LadderStep: 5},
			{Family: "hysteria2", Until: t0.Add(-15 * time.Minute), LadderStep: 5},
			{Family: "snowflake", Until: t0.Add(-15 * time.Minute), LadderStep: 5},
		},
	}
	a, b := Compare([]Tick{tick})
	if a.Fires != 0 || b.Fires != 0 {
		t.Errorf("expired cooldowns should not fire: A=%d B=%d", a.Fires, b.Fires)
	}
}

func TestCompare_FirstAndLastFireRecorded(t *testing.T) {
	t1 := t0
	t2 := t0.Add(1 * time.Hour)
	t3 := t0.Add(2 * time.Hour)
	mkTick := func(now time.Time) Tick {
		return Tick{
			Now: now,
			Skipped: []Skipped{
				{Family: "vless", Until: now.Add(15 * time.Minute), LadderStep: 3},
				{Family: "hysteria2", Until: now.Add(15 * time.Minute), LadderStep: 3},
				{Family: "snowflake", Until: now.Add(15 * time.Minute), LadderStep: 3},
			},
		}
	}
	a, _ := Compare([]Tick{mkTick(t1), mkTick(t2), mkTick(t3)})
	if !a.FirstFire.Equal(t1) {
		t.Errorf("FirstFire = %s, want %s", a.FirstFire, t1)
	}
	if !a.LastFire.Equal(t3) {
		t.Errorf("LastFire = %s, want %s", a.LastFire, t3)
	}
	if a.Fires != 3 {
		t.Errorf("A.Fires = %d, want 3", a.Fires)
	}
}

func TestRenderMemo_StableShape(t *testing.T) {
	a := Comparison{Set: LockedA, TickCount: 100, Fires: 5,
		FirstFire: t0, LastFire: t0.Add(1 * time.Hour)}
	b := Comparison{Set: LockedB, TickCount: 100, Fires: 1,
		FirstFire: t0.Add(30 * time.Minute), LastFire: t0.Add(30 * time.Minute)}
	memo := RenderMemo("run-test-001", a, b)
	wants := []string{
		"# Phase 3-Soak — Auto-Promotion Threshold Comparison Memo",
		"**Run ID:** `run-test-001`",
		"locked-A (2G default)",
		"locked-B (tightened candidate)",
		"DistinctFamilyMinimum = 3",
		"DistinctFamilyMinimum = 4",
		"WindowDuration        = 30m",
		"WindowDuration        = 20m",
		"LadderStepMinimum     = 3",
		"LadderStepMinimum     = 4",
		"Fires: **5**",
		"Fires: **1**",
		"## Delta",
		"## Recommendation",
		"informs V4 freeze",
	}
	for _, w := range wants {
		if !strings.Contains(memo, w) {
			t.Errorf("memo missing %q\n--- memo ---\n%s", w, memo)
		}
	}
}

func TestRenderMemo_EmptyFiresFormatted(t *testing.T) {
	a := Comparison{Set: LockedA, TickCount: 100, Fires: 0}
	b := Comparison{Set: LockedB, TickCount: 100, Fires: 0}
	memo := RenderMemo("run-empty", a, b)
	if !strings.Contains(memo, "First fire: —") {
		t.Errorf("zero-fire run should render em-dash; memo=%s", memo)
	}
}
