package modifiers

import (
	"strings"
	"testing"
)

const samplePending = `# Modifier: client_desync

## Identity
- **kind**: ` + "`client_desync`" + `
- **sing-box reference**: n/a (raw-socket modifier)

## Pass record
- **status**: PENDING
- **methodology**: TBD
- **observed**: TBD
- **reviewer**: TBD
- **date**: TBD

## Phase gating
- **min_phase**: PostV2

## Platform gating
- **platforms**: ["linux-desktop"]
`

const sampleSyntheticPass = `# Modifier: synthetic_pass

## Identity
- **kind**: ` + "`synthetic_pass`" + `
- **sing-box reference**: n/a

## Pass record
- **status**: PASS
- **methodology**: synthetic test fixture
- **observed**: synthetic
- **reviewer**: test-only
- **date**: 2026-05-05

## Phase gating
- **min_phase**: PostV2

## Platform gating
- **platforms**: ["linux-desktop", "windows-desktop"]
`

func TestParse_PendingClientDesync(t *testing.T) {
	m, err := Parse(strings.NewReader(samplePending))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Kind != "client_desync" {
		t.Errorf("Kind = %q, want client_desync", m.Kind)
	}
	if m.Status != StatusPending {
		t.Errorf("Status = %q, want PENDING", m.Status)
	}
	if m.MinPhase != PhasePostV2 {
		t.Errorf("MinPhase = %q, want PostV2", m.MinPhase)
	}
	if len(m.Platforms) != 1 || m.Platforms[0] != PlatformLinuxDesktop {
		t.Errorf("Platforms = %v, want [linux-desktop]", m.Platforms)
	}
	if m.Reviewer != "" {
		t.Errorf("Reviewer should be empty (TBD elided), got %q", m.Reviewer)
	}
	if m.Date != "" {
		t.Errorf("Date should be empty (TBD elided), got %q", m.Date)
	}
	if err := m.validate(); err != nil {
		t.Errorf("validate(): %v", err)
	}
}

func TestParse_SyntheticPass(t *testing.T) {
	m, err := Parse(strings.NewReader(sampleSyntheticPass))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Status != StatusPass {
		t.Errorf("Status = %q, want PASS", m.Status)
	}
	if m.Reviewer != "test-only" {
		t.Errorf("Reviewer = %q, want test-only", m.Reviewer)
	}
	if m.Date != "2026-05-05" {
		t.Errorf("Date = %q, want 2026-05-05", m.Date)
	}
	if len(m.Platforms) != 2 {
		t.Errorf("Platforms = %v, want 2 entries", m.Platforms)
	}
	if err := m.validate(); err != nil {
		t.Errorf("validate(): %v", err)
	}
}

func TestParse_EmptyPlatforms(t *testing.T) {
	in := `## Identity
- **kind**: ` + "`tls_fragment`" + `
## Pass record
- **status**: PENDING
## Phase gating
- **min_phase**: PostV2
## Platform gating
- **platforms**: []
`
	m, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Platforms) != 0 {
		t.Errorf("Platforms should be nil/empty for `[]`, got %v", m.Platforms)
	}
}

func TestParse_ValidateRejectsBadStatus(t *testing.T) {
	m := Meta{Kind: "x", Status: "BOGUS", MinPhase: PhasePostV2}
	if err := m.validate(); err == nil {
		t.Error("validate() should reject status=BOGUS")
	}
}

func TestParse_ValidateRejectsBadKind(t *testing.T) {
	m := Meta{Kind: "Bad-Kind!", Status: StatusPending, MinPhase: PhasePostV2}
	if err := m.validate(); err == nil {
		t.Error("validate() should reject kind with uppercase / dashes")
	}
}

func TestParse_ValidateRejectsBadPlatform(t *testing.T) {
	m := Meta{Kind: "x", Status: StatusPending, MinPhase: PhasePostV2,
		Platforms: []Platform{Platform("bsd-desktop")}}
	if err := m.validate(); err == nil {
		t.Error("validate() should reject unrecognised platform")
	}
}

func TestParse_ValidateRejectsBadPhase(t *testing.T) {
	m := Meta{Kind: "x", Status: StatusPending, MinPhase: Phase("V99")}
	if err := m.validate(); err == nil {
		t.Error("validate() should reject min_phase=V99")
	}
}

func TestParse_ValidateRejectsPassWithoutReviewer(t *testing.T) {
	m := Meta{Kind: "x", Status: StatusPass, MinPhase: PhasePostV2,
		Reviewer: "TBD", Date: "2026-01-01"}
	if err := m.validate(); err == nil {
		t.Error("validate() should reject PASS with reviewer=TBD")
	}
}

func TestParse_ValidateRejectsPassWithoutDate(t *testing.T) {
	m := Meta{Kind: "x", Status: StatusPass, MinPhase: PhasePostV2,
		Reviewer: "alice", Date: ""}
	if err := m.validate(); err == nil {
		t.Error("validate() should reject PASS with empty date")
	}
}

func TestPhaseOrdinal(t *testing.T) {
	if phaseOrdinal(PhaseV15) >= phaseOrdinal(PhaseV16) {
		t.Error("V1.5 < V1.6 expected")
	}
	if phaseOrdinal(PhaseV16) >= phaseOrdinal(PhasePostV2) {
		t.Error("V1.6 < PostV2 expected")
	}
	if phaseOrdinal(Phase("nope")) != -1 {
		t.Error("unknown phase should ordinal=-1")
	}
}
