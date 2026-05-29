package hetzner

import (
	"context"
	"errors"
	"testing"

	"daal/publisher/deploy/cloudflare"
)

func TestCloudflareFirewallApplier_CreatesNewRule(t *testing.T) {
	fc := newFake()
	a := NewCloudflareFirewallApplier(fc)
	id, err := a.ApplyCloudflareRule(context.Background(), "", &cloudflare.EdgeRanges{
		V4: []string{"173.245.48.0/20"},
		V6: []string{"2400:cb00::/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Error("expected non-empty firewall ID")
	}
	if rule, ok := fc.firewalls[id]; !ok {
		t.Errorf("rule not stored under id %q", id)
	} else {
		if len(rule.V4) != 1 || rule.V4[0] != "173.245.48.0/20" {
			t.Errorf("v4 = %v", rule.V4)
		}
		if len(rule.V6) != 1 || rule.V6[0] != "2400:cb00::/32" {
			t.Errorf("v6 = %v", rule.V6)
		}
	}
}

func TestCloudflareFirewallApplier_UpdatesExistingRule(t *testing.T) {
	fc := newFake()
	a := NewCloudflareFirewallApplier(fc)
	id1, _ := a.ApplyCloudflareRule(context.Background(), "", &cloudflare.EdgeRanges{V4: []string{"1.0.0.0/24"}})
	id2, err := a.ApplyCloudflareRule(context.Background(), id1, &cloudflare.EdgeRanges{V4: []string{"2.0.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id1 {
		t.Errorf("update should return same id; got %q vs %q", id2, id1)
	}
	if got := fc.firewalls[id1].V4; len(got) != 1 || got[0] != "2.0.0.0/24" {
		t.Errorf("v4 not updated: %v", got)
	}
}

func TestCloudflareFirewallApplier_RejectsNilRanges(t *testing.T) {
	fc := newFake()
	a := NewCloudflareFirewallApplier(fc)
	_, err := a.ApplyCloudflareRule(context.Background(), "", nil)
	if !errors.Is(err, errEmptyRanges) {
		t.Errorf("want errEmptyRanges, got %v", err)
	}
}
