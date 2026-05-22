package scenarios

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseValidScenario(t *testing.T) {
	body := []byte(`{
        "id": "x",
        "v0_failure_categories": ["tcp_reset"],
        "description": "test",
        "expectations": [{"flow":"a","outcome":"tcp_reset"}]
    }`)
	s, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRejectUnknownCategory(t *testing.T) {
	body := []byte(`{
        "id": "x",
        "v0_failure_categories": ["does_not_exist"],
        "expectations": [{"flow":"a","outcome":"ok"}]
    }`)
	s, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "unknown failure category") {
		t.Fatalf("expected unknown category error, got %v", err)
	}
}

func TestRejectUnknownOutcome(t *testing.T) {
	body := []byte(`{
        "id": "x",
        "v0_failure_categories": ["tcp_reset"],
        "expectations": [{"flow":"a","outcome":"frobnicated"}]
    }`)
	s, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "unknown outcome") {
		t.Fatalf("expected unknown outcome error, got %v", err)
	}
}

func TestLoadAllScenariosValid(t *testing.T) {
	dir := scenariosDir(t)
	all, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("load dir: %v", err)
	}
	if len(all) < 10 {
		t.Fatalf("expected at least 10 scenarios, got %d", len(all))
	}
	seen := map[string]bool{}
	for _, s := range all {
		seen[s.ID] = true
		for _, cat := range s.V0FailureCategories {
			if !AllowedCategories[cat] {
				t.Fatalf("scenario %q references unknown category %q", s.ID, cat)
			}
		}
	}
	required := []string{
		"stateless-sni-rst",
		"iran-protocol-whitelist",
		"udp-blackhole",
		"dns-bogon",
		"doh-dot-sni-block",
		"ech-bootstrap-fail",
		"tcp-reset-mid-handshake",
		"wireguard-signature",
		"auth-failed",
		"bundle-tampering",
		"stateful-reassembly",
	}
	for _, r := range required {
		if !seen[r] {
			t.Fatalf("missing required scenario %q", r)
		}
	}
}

func TestReplayProducesFixtures(t *testing.T) {
	dir := scenariosDir(t)
	all, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	now := time.Date(2026, 4, 26, 19, 17, 30, 0, time.UTC)
	out := t.TempDir()
	total := 0
	for _, s := range all {
		fixtures := s.Replay(now)
		written, err := WriteFixtures(out, fixtures)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		for _, p := range written {
			body, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if !strings.Contains(string(body), "T19:00Z") {
				t.Fatalf("fixture %s missing hour bucket: %s", p, string(body))
			}
		}
		total += len(written)
	}
	if total == 0 {
		t.Fatal("no fixtures produced")
	}
}

func TestEveryTaxonomyCategoryHasAFixture(t *testing.T) {
	dir := scenariosDir(t)
	all, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	covered := map[string]bool{}
	now := time.Now()
	for _, s := range all {
		for _, f := range s.Replay(now) {
			covered[f.Category] = true
		}
	}
	// network_offline / publisher_revoked / publisher_key_changed / engine_crash
	// / unknown / subscription_unreachable / quic_unavailable / dns_timeout are
	// out of scope for direct executable replay in V0; they are covered via
	// distribution-failure fixtures and bundle-go tests instead. The required
	// set below is the categories the lab MUST cover end-to-end.
	required := []string{
		"dns_poisoned",
		"tcp_connect_timeout",
		"tcp_reset",
		"tls_handshake_failed",
		"tls_sni_or_cert_block_suspected",
		"udp_unavailable",
		"auth_failed",
		"route_expired",
		"bundle_signature_invalid",
		"bundle_corrupted",
	}
	for _, r := range required {
		if !covered[r] {
			t.Fatalf("required category %q not covered by any replayable scenario", r)
		}
	}
}

func scenariosDir(t *testing.T) string {
	t.Helper()
	// scenario_test.go lives at:
	//   test-rigs/censor-lab/lab-driver/internal/scenarios/
	// scenarios live at:
	//   test-rigs/censor-lab/scenarios/
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", "..", "..", "scenarios"))
}
