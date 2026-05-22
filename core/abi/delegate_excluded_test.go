//go:build no_delegate_share

package abi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExcluded_3FFlagFlipped — the diagnostics flag flips
// false; the redistribute path returns identity_unavailable.
func TestExcluded_3FFlagFlipped(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal([]byte(body), &m)
	if v, _ := m["delegate_share_compiled_in"].(bool); v {
		t.Errorf("delegate_share_compiled_in: expected false")
	}

	envelope := RedistributeRoute("any", "rcp")
	if !strings.Contains(envelope, `"error":"identity_unavailable"`) {
		t.Errorf("excluded redistribute: %s", envelope)
	}
}
