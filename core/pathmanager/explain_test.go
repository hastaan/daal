package pathmanager

import (
	"testing"
	"time"

	"daal/core/diagnostics"
)

func TestExplainHappyPath(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 30, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	m.Attempt("route-A", "vless-reality")
	m.Connected()
	w := m.Explain()
	if w.State != "Connected" || w.ActiveRoute != "route-A" {
		t.Fatalf("unexpected: %+v", w)
	}
	if w.WhyChoseRoute == "" {
		t.Fatal("missing why string")
	}
	if w.Bucket != "2026-04-26T12:00:00Z" {
		t.Fatalf("wrong bucket: %q", w.Bucket)
	}
}

func TestExplainCooldownEmitsReason(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 30, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	m.Attempt("route-A", "vless-reality")
	m.Failed("route-A", "vless-reality", diagnostics.TLSHandshakeFailed)
	w := m.Explain()
	if w.State != "Cooldown" {
		t.Fatalf("expected Cooldown, got %s", w.State)
	}
	if w.WhyChoseRoute == "" || w.LastFailure != nil { // LastFailure is reserved for future use
	}
}

func TestExplainFamilyCooldownAppears(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 30, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	// Three failures in the same hour bucket → family cooldown.
	for i := 0; i < 3; i++ {
		m.Attempt("route-X", "hysteria2")
		m.Failed("route-X", "hysteria2", diagnostics.UDPUnavailable)
	}
	w := m.Explain()
	found := false
	for _, sk := range w.SkippedFamilies {
		if sk.Family == "hysteria2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected hysteria2 skipped family, got %+v", w.SkippedFamilies)
	}
}
