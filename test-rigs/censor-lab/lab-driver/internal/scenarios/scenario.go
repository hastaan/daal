package scenarios

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AllowedCategories mirrors specs/failure-taxonomy-v1.md. Adding a category
// requires a spec revision before code accepts it.
var AllowedCategories = map[string]bool{
	"dns_poisoned":                    true,
	"dns_timeout":                     true,
	"tcp_connect_timeout":             true,
	"tcp_reset":                       true,
	"tls_handshake_failed":            true,
	"tls_sni_or_cert_block_suspected": true,
	"udp_unavailable":                 true,
	"quic_unavailable":                true,
	"auth_failed":                     true,
	"route_expired":                   true,
	"publisher_revoked":               true,
	"publisher_key_changed":           true,
	"subscription_unreachable":        true,
	"engine_crash":                    true,
	"bundle_signature_invalid":        true,
	"bundle_corrupted":                true,
	"network_offline":                 true,
	"unknown":                         true,
}

// AllowedOutcomes are coarse, fixture-friendly expected outcomes.
var AllowedOutcomes = map[string]bool{
	"ok":                              true,
	"blocked":                         true,
	"tcp_reset":                       true,
	"tcp_connect_timeout":             true,
	"tls_handshake_failed":            true,
	"tls_sni_or_cert_block_suspected": true,
	"bogon":                           true,
	"timeout":                         true,
	"loss":                            true,
	"auth_failed":                     true,
	"route_expired":                   true,
	"bundle_corrupted":                true,
	"bundle_signature_invalid":        true,
}

type Scenario struct {
	ID                  string          `json:"id"`
	V0FailureCategories []string        `json:"v0_failure_categories"`
	Description         string          `json:"description"`
	Network             json.RawMessage `json:"network"`
	Censor              json.RawMessage `json:"censor"`
	Expectations        []Expectation   `json:"expectations"`
	Asserts             []Assert        `json:"asserts,omitempty"`
}

type Expectation struct {
	Flow    string `json:"flow"`
	Outcome string `json:"outcome"`
}

type Assert struct {
	Rule     string `json:"rule"`
	Category string `json:"category,omitempty"`
}

// Load parses a scenario JSON file from disk.
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses scenario JSON bytes.
func Parse(data []byte) (*Scenario, error) {
	var s Scenario
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse scenario: %w", err)
	}
	return &s, nil
}

// Validate enforces taxonomy invariants.
func (s *Scenario) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("scenario id is required")
	}
	if len(s.V0FailureCategories) == 0 {
		return fmt.Errorf("scenario %q must declare at least one v0_failure_category", s.ID)
	}
	for _, cat := range s.V0FailureCategories {
		if !AllowedCategories[cat] {
			return fmt.Errorf("scenario %q references unknown failure category %q", s.ID, cat)
		}
	}
	if len(s.Expectations) == 0 {
		return fmt.Errorf("scenario %q must declare at least one expectation", s.ID)
	}
	for _, e := range s.Expectations {
		if !AllowedOutcomes[e.Outcome] {
			return fmt.Errorf("scenario %q expectation %q has unknown outcome %q", s.ID, e.Flow, e.Outcome)
		}
	}
	for _, a := range s.Asserts {
		if a.Rule == "no_cooldown_on" && !AllowedCategories[a.Category] {
			return fmt.Errorf("scenario %q assert references unknown category %q", s.ID, a.Category)
		}
	}
	return nil
}

// LoadDir loads and validates every *.json scenario in a directory, sorted by ID.
func LoadDir(dir string) ([]*Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Scenario
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		s, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if err := s.Validate(); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
