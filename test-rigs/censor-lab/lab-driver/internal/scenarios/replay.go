package scenarios

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Fixture is the JSON shape written under fixtures/failures/<category>/<scenario>.json.
type Fixture struct {
	ScenarioID string         `json:"scenario_id"`
	Category   string         `json:"category"`
	Outcome    string         `json:"outcome"`
	HourBucket string         `json:"hour_bucket"`
	Notes      string         `json:"notes,omitempty"`
	Flow       string         `json:"flow,omitempty"`
	Asserts    []FixtureAsser `json:"asserts,omitempty"`
}

type FixtureAsser struct {
	Rule     string `json:"rule"`
	Category string `json:"category,omitempty"`
}

// HourBucket renders an RFC3339-style hour bucket from t in UTC.
func HourBucket(t time.Time) string {
	t = t.UTC().Truncate(time.Hour)
	return t.Format("2006-01-02T15:00Z")
}

// Replay produces fixtures for a scenario, one per (category, expectation)
// pair where the expectation outcome is a recognized failure category outcome.
// Fixtures contain no real timestamps finer than the hour bucket and no
// network secrets.
func (s *Scenario) Replay(now time.Time) []Fixture {
	bucket := HourBucket(now)
	var out []Fixture
	for _, cat := range s.V0FailureCategories {
		for _, exp := range s.Expectations {
			if exp.Outcome == "ok" {
				continue
			}
			out = append(out, Fixture{
				ScenarioID: s.ID,
				Category:   cat,
				Outcome:    exp.Outcome,
				HourBucket: bucket,
				Flow:       exp.Flow,
				Asserts:    cloneAsserts(s.Asserts),
			})
		}
	}
	return out
}

func cloneAsserts(in []Assert) []FixtureAsser {
	if len(in) == 0 {
		return nil
	}
	out := make([]FixtureAsser, 0, len(in))
	for _, a := range in {
		out = append(out, FixtureAsser{Rule: a.Rule, Category: a.Category})
	}
	return out
}

// WriteFixtures writes fixtures into outDir/<category>/<scenario>-<n>.json.
// outDir is created if missing.
func WriteFixtures(outDir string, fixtures []Fixture) ([]string, error) {
	var written []string
	counts := map[string]int{}
	for _, f := range fixtures {
		dir := filepath.Join(outDir, f.Category)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return written, err
		}
		key := f.Category + "/" + f.ScenarioID
		counts[key]++
		name := fmt.Sprintf("%s-%d.json", f.ScenarioID, counts[key])
		path := filepath.Join(dir, name)
		body, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return written, err
		}
		body = append(body, '\n')
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}
