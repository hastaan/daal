package soak

import (
	"encoding/json"
	"testing"

	"daal/soak-driver/internal/censor"
)

func TestV16EngineActionsDispatchWithoutUnknown(t *testing.T) {
	sc := censor.Scenario{
		ID: "v1-6-test",
		EngineActions: []censor.EngineAction{
			{Day: 1, Name: "soak_cdn_provision_attestation", Args: map[string]any{"relay_pack_id": "rp", "connected_within_seconds": 42, "cdn_fronted_share_percent": 68}},
			{Day: 1, Name: "soak_simulate_dns_only_leak", Args: map[string]any{"expected_code": "RP023", "recipient_affected": false}},
			{Day: 1, Name: "soak_simulate_origin_ip_scan", Args: map[string]any{"aop_rejected": true, "family_visible_event": false}},
			{Day: 1, Name: "soak_simulate_cf_hostname_block", Args: map[string]any{"classification": "cdn_hostname_blocked", "fallback_family": "direct_vps"}},
			{Day: 1, Name: "soak_rotate_public_surface", Args: map[string]any{"rotation_kind": "cdn_path", "duration_seconds": 24, "freshness_republished": true, "qr_rescan": false, "re_tofu": false}},
			{Day: 1, Name: "soak_rotate_origin_only", Args: map[string]any{"rotation_kind": "cdn_origin", "relaypack_republished": false, "freshness_republished": false, "family_visible_event": false}},
			{Day: 1, Name: "soak_freshness_atomic_swap", Args: map[string]any{"recovery_seconds": 96, "qr_rescan": false, "re_tofu": false, "same_publisher": true}},
		},
	}
	got := runEngineActions(nil, sc, 1)
	if len(got) != len(sc.EngineActions) {
		t.Fatalf("outcomes = %d, want %d", len(got), len(sc.EngineActions))
	}
	for _, rec := range got {
		if rec.Kind == "engine_action_unknown" {
			t.Fatalf("unexpected unknown action: %+v", rec)
		}
		var body struct {
			Metric string `json:"metric"`
			Pass   bool   `json:"pass"`
		}
		if err := json.Unmarshal(rec.Body, &body); err != nil {
			t.Fatalf("%s body is not JSON: %v", rec.Kind, err)
		}
		if body.Metric == "" {
			t.Errorf("%s missing metric in %s", rec.Kind, string(rec.Body))
		}
		if !body.Pass {
			t.Errorf("%s did not pass: %s", rec.Kind, string(rec.Body))
		}
	}
}
