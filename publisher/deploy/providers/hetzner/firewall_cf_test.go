package hetzner

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/relayports"
)

func TestCloudflareFirewallApplier_WritesToTheGivenFirewall(t *testing.T) {
	fc := newFake()
	a := NewCloudflareFirewallApplier(fc)
	id, err := a.ApplyCloudflareRule(context.Background(), "fw-relay", &cloudflare.EdgeRanges{
		V4: []string{"173.245.48.0/20"},
		V6: []string{"2400:cb00::/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "fw-relay" {
		t.Errorf("id = %q, want the relay firewall", id)
	}
	rule, ok := fc.firewalls[id]
	if !ok {
		t.Fatalf("rule not stored under id %q", id)
	}
	if len(rule.V4) != 1 || rule.V4[0] != "173.245.48.0/20" || len(rule.V6) != 1 {
		t.Errorf("rule = %+v", rule)
	}
}

// Defect 3: an empty id used to create a firewall attached to nothing.
func TestCloudflareFirewallApplier_RefusesNoFirewall(t *testing.T) {
	fc := newFake()
	a := NewCloudflareFirewallApplier(fc)
	_, err := a.ApplyCloudflareRule(context.Background(), "", &cloudflare.EdgeRanges{V4: []string{"1.0.0.0/24"}})
	if !errors.Is(err, errNoRelayFirewall) {
		t.Fatalf("want errNoRelayFirewall, got %v", err)
	}
	if len(fc.firewalls) != 0 {
		t.Errorf("a refused call created %v", fc.firewalls)
	}
}

func TestCloudflareFirewallApplier_RejectsNilRanges(t *testing.T) {
	fc := newFake()
	a := NewCloudflareFirewallApplier(fc)
	_, err := a.ApplyCloudflareRule(context.Background(), "fw-1", nil)
	if !errors.Is(err, errEmptyRanges) {
		t.Errorf("want errEmptyRanges, got %v", err)
	}
}

// A client without the port-aware call can only open the CDN door.
func TestCloudflareFirewallApplier_OtherPortNeedsLiveClient(t *testing.T) {
	fc := newFake()
	a := &CloudflareFirewallApplier{c: fc, Port: 2053}
	if _, err := a.ApplyCloudflareRule(context.Background(), "fw-1", &cloudflare.EdgeRanges{V4: []string{"1.0.0.0/24"}}); err == nil {
		t.Fatal("want a refusal")
	}
}

// The live client opens the CDN door's port, through the applier, and
// the posture read sees exactly that rule; removal takes it off and
// keeps every other rule.
func TestCloudflareFirewallApplier_LiveApplyReadRemove(t *testing.T) {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	l := newFakeLive(t, f)
	a := NewCloudflareFirewallApplier(l)
	ctx := context.Background()
	fw := strconv.Itoa(fakeFirewallID)
	if _, err := a.ApplyCloudflareRule(ctx, fw, &cloudflare.EdgeRanges{V4: []string{"173.245.48.0/20"}, V6: []string{"2400:cb00::/32"}}); err != nil {
		t.Fatal(err)
	}
	st, err := a.CloudflareRule(ctx, fw)
	if err != nil {
		t.Fatal(err)
	}
	if !a.DoorPortOpenToCloudflareOnly(st) || st.Port != strconv.Itoa(relayports.CDNOrigin.Port) || st.Sources != 2 {
		t.Fatalf("rule state = %+v", st)
	}
	if err := a.RemoveCloudflareRule(ctx, fw); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(f.descriptions(), " "), strings.Join(baselineDescriptions(), " "); got != want {
		t.Fatalf("after removal:\n got  %v\n want %v", got, want)
	}
	if st, _ := a.CloudflareRule(ctx, fw); st.Present {
		t.Error("rule still present after removal")
	}
	// Idempotent.
	before := f.setCalls
	if err := a.RemoveCloudflareRule(ctx, fw); err != nil || f.setCalls != before {
		t.Errorf("second removal: err=%v writes %d->%d", err, before, f.setCalls)
	}
}

func baselineDescriptions() []string {
	f := &fakeHcloudAPI{rules: relayBaseline()}
	return f.descriptions()
}

func TestPortCovers(t *testing.T) {
	cases := []struct {
		spec, port string
		want       bool
	}{
		{"8448", "8448", true}, {"443", "8448", false}, {"8000-9000", "8448", true},
		{"8449-9000", "8448", false}, {"x", "8448", false},
	}
	for _, c := range cases {
		if got := portCovers(c.spec, c.port); got != c.want {
			t.Errorf("portCovers(%q,%q) = %v", c.spec, c.port, got)
		}
	}
}
