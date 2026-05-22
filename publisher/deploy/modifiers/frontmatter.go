package modifiers

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Status is the pass_record.status enum.
type Status string

const (
	StatusPending    Status = "PENDING"
	StatusPass       Status = "PASS"
	StatusRejected   Status = "REJECTED"
	StatusDeprecated Status = "DEPRECATED"
)

// Phase is the min_phase enum. Mirrors relaypackvalidate.Phase
// exactly; we duplicate the constants here so the modifiers package
// can be consumed without pulling in the validator package (asymmetric
// guard preserved).
type Phase string

const (
	PhaseV15    Phase = "V1.5"
	PhaseV16    Phase = "V1.6"
	PhasePostV2 Phase = "PostV2"
)

// phaseOrdinal returns the comparison ordinal for a phase. Higher
// number means a later phase. Returns -1 for unknown.
func phaseOrdinal(p Phase) int {
	switch p {
	case PhaseV15:
		return 0
	case PhaseV16:
		return 1
	case PhasePostV2:
		return 2
	default:
		return -1
	}
}

// Platform is one allowed-platform string.
type Platform string

const (
	PlatformLinuxDesktop   Platform = "linux-desktop"
	PlatformWindowsDesktop Platform = "windows-desktop"
	PlatformMacOSDesktop   Platform = "macos-desktop"
	PlatformAndroid        Platform = "android"
	PlatformIOS            Platform = "ios"
)

var validPlatforms = map[Platform]bool{
	PlatformLinuxDesktop:   true,
	PlatformWindowsDesktop: true,
	PlatformMacOSDesktop:   true,
	PlatformAndroid:        true,
	PlatformIOS:            true,
}

// Meta is one parsed modifier spec record. The genregistry binary
// emits a Go literal of these into registry_gen.go.
type Meta struct {
	Kind       string
	Status     Status
	MinPhase   Phase
	Platforms  []Platform
	SingboxRef string
	Reviewer   string
	Date       string
}

// ValidateExported is the exported alias of validate, used by the
// genregistry binary which lives in a separate package.
func (m Meta) ValidateExported() error { return m.validate() }

// validate sanity-checks the parsed record. Callers (genregistry
// binary; tests) MUST call this after Parse and refuse to ship
// malformed records (locked invariant 43).
func (m Meta) validate() error {
	if m.Kind == "" {
		return fmt.Errorf("kind is empty")
	}
	if !isValidKind(m.Kind) {
		return fmt.Errorf("kind %q must match [a-z][a-z0-9_]*", m.Kind)
	}
	switch m.Status {
	case StatusPending, StatusPass, StatusRejected, StatusDeprecated:
	default:
		return fmt.Errorf("status %q must be one of PENDING|PASS|REJECTED|DEPRECATED", m.Status)
	}
	if phaseOrdinal(m.MinPhase) < 0 {
		return fmt.Errorf("min_phase %q must be one of V1.5|V1.6|PostV2", m.MinPhase)
	}
	for _, p := range m.Platforms {
		if !validPlatforms[p] {
			return fmt.Errorf("platform %q is not a recognised value", p)
		}
	}
	// PASS records have stricter requirements.
	if m.Status == StatusPass {
		if m.Reviewer == "" || strings.EqualFold(m.Reviewer, "TBD") {
			return fmt.Errorf("PASS record requires a non-empty reviewer (got %q)", m.Reviewer)
		}
		if m.Date == "" || strings.EqualFold(m.Date, "TBD") {
			return fmt.Errorf("PASS record requires a non-empty date (got %q)", m.Date)
		}
	}
	return nil
}

var kindRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func isValidKind(s string) bool { return kindRe.MatchString(s) }

// Parse reads one modifier markdown file and extracts its
// front-matter into a Meta. The format is intentionally strict:
// section headers ("## Identity", "## Pass record", "## Phase
// gating", "## Platform gating") and `- **field**: value` bullets.
// Free-form description / risk-notes / references sections are
// ignored.
//
// Lines that cannot be parsed are silently skipped — the validate()
// method is the gatekeeper that rejects malformed records.
func Parse(r io.Reader) (Meta, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	var m Meta
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := parseBullet(line)
		if !ok {
			continue
		}
		switch key {
		case "kind":
			m.Kind = val
		case "sing-box reference":
			if val != "n/a" && !strings.EqualFold(val, "tbd") {
				m.SingboxRef = val
			}
		case "status":
			m.Status = Status(val)
		case "methodology", "observed":
			// Captured in spec text only; the registry doesn't
			// surface methodology / observed as searchable
			// fields. Skipped.
		case "reviewer":
			if !strings.EqualFold(val, "tbd") {
				m.Reviewer = val
			}
		case "date":
			if !strings.EqualFold(val, "tbd") {
				m.Date = val
			}
		case "min_phase":
			m.MinPhase = Phase(val)
		case "platforms":
			m.Platforms = parsePlatformList(val)
		}
	}
	if err := scanner.Err(); err != nil {
		return Meta{}, fmt.Errorf("scan: %w", err)
	}
	return m, nil
}

// bulletRe matches "- **<key>**: <value>" with optional trailing
// inline comments / backticks; also accepts leading whitespace.
var bulletRe = regexp.MustCompile("^\\s*-\\s+\\*\\*([^*]+?)\\*\\*\\s*:\\s*(.*?)\\s*$")

func parseBullet(line string) (key, val string, ok bool) {
	matches := bulletRe.FindStringSubmatch(line)
	if matches == nil {
		return "", "", false
	}
	key = strings.TrimSpace(matches[1])
	val = strings.TrimSpace(matches[2])
	val = strings.Trim(val, "`")
	val = strings.TrimSpace(val)
	return key, val, true
}

// parsePlatformList accepts JSON-style arrays (`["a", "b"]`),
// bracket-only empty (`[]`), or a bare comma-separated list.
func parsePlatformList(val string) []Platform {
	val = strings.TrimSpace(val)
	if val == "" || val == "[]" {
		return nil
	}
	val = strings.TrimPrefix(val, "[")
	val = strings.TrimSuffix(val, "]")
	parts := strings.Split(val, ",")
	out := make([]Platform, 0, len(parts))
	seen := map[Platform]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"")
		p = strings.Trim(p, "'")
		p = strings.Trim(p, "`")
		if p == "" {
			continue
		}
		pp := Platform(p)
		if seen[pp] {
			continue
		}
		seen[pp] = true
		out = append(out, pp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
