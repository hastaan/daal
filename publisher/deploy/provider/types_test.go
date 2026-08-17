package provider

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// TestOperatorRecord_RoundTrip pins the JSON wire shape FRP-5 will
// persist to SQLite and FRP-4b will read for signing.
func TestOperatorRecord_RoundTrip(t *testing.T) {
	rec := OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "12345",
		ServerType:      "cx22",
		Region:          "fsn1",
		PublicIP:        net.ParseIP("5.75.0.1"),
		ToolboxProfile:  "iran-default",
		PublisherPubKey: []byte{0x01, 0x02, 0x03},
		Candidates: []CandidateMeta{
			{
				Family:           "vless-reality",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:tcp443"},
				OriginRiskTags:   []string{},
			},
		},
		ProvisionedAt: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var got OperatorRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Provider != rec.Provider {
		t.Errorf("Provider lost")
	}
	if got.PublicIP.String() != "5.75.0.1" {
		t.Errorf("PublicIP lost: %v", got.PublicIP)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].Family != "vless-reality" {
		t.Errorf("Candidates lost: %+v", got.Candidates)
	}
	if !bytes.Equal(got.PublisherPubKey, rec.PublisherPubKey) {
		t.Errorf("PublisherPubKey lost")
	}
}

// TestProvisionOpts_PrivateKeyNotSerialised pins that the ephemeral
// SSH private key is excluded from JSON output (json:"-"). FRP-5
// uses this to safely log ProvisionOpts without leaking key
// material.
func TestProvisionOpts_PrivateKeyNotSerialised(t *testing.T) {
	opts := ProvisionOpts{
		Region:          "fsn1",
		ServerType:      "cx22",
		ToolboxProfile:  "iran-default",
		HelperIP:        net.ParseIP("1.2.3.4"),
		EphemeralSSHKey: make([]byte, 64),
	}
	for i := range opts.EphemeralSSHKey {
		opts.EphemeralSSHKey[i] = 0xAB
	}
	body, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("ABABAB")) || bytes.Contains(body, []byte{0xAB}) {
		t.Errorf("ephemeral SSH key leaked into JSON: %s", body)
	}
}

// TestOperatorRecord_MgmtFieldsRoundTripCanonicalJSON pins the
// V2 mgmt-plane additions (FRP-10 invariants 26 + 27): MgmtPort
// and MgmtTLSFingerprint round-trip through canonical-JSON. Empty
// values omit cleanly so V1.5 records stay byte-identical.
func TestOperatorRecord_MgmtFieldsRoundTripCanonicalJSON(t *testing.T) {
	rec := OperatorRecord{
		Provider:           "hetzner",
		ServerID:           "12345",
		ServerType:         "cx22",
		Region:             "fsn1",
		PublicIP:           net.ParseIP("5.75.0.1"),
		ToolboxProfile:     "iran-default",
		PublisherPubKey:    []byte{0x01},
		ProvisionedAt:      time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC),
		MgmtPort:           42424,
		MgmtTLSFingerprint: "deadbeef0102030405060708090a0b0c0d0e0f10111213141516171819aabbcc",
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"mgmt_port":42424`)) {
		t.Errorf("mgmt_port not serialised: %s", body)
	}
	if !bytes.Contains(body, []byte(`"mgmt_tls_fingerprint":"deadbeef`)) {
		t.Errorf("mgmt_tls_fingerprint not serialised: %s", body)
	}
	var got OperatorRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.MgmtPort != 42424 {
		t.Errorf("MgmtPort lost; got %d", got.MgmtPort)
	}
	if got.MgmtTLSFingerprint != rec.MgmtTLSFingerprint {
		t.Errorf("MgmtTLSFingerprint lost; got %q", got.MgmtTLSFingerprint)
	}

	// V1.5 records (zero values) must omit both fields entirely.
	v15 := OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "1",
		ServerType:      "cx22",
		Region:          "fsn1",
		PublicIP:        net.ParseIP("5.75.0.1"),
		ToolboxProfile:  "iran-default",
		PublisherPubKey: []byte{0x01},
		ProvisionedAt:   time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC),
	}
	v15Body, _ := json.Marshal(v15)
	if bytes.Contains(v15Body, []byte(`"mgmt_port"`)) {
		t.Errorf("V1.5 record must omit mgmt_port; got %s", v15Body)
	}
	if bytes.Contains(v15Body, []byte(`"mgmt_tls_fingerprint"`)) {
		t.Errorf("V1.5 record must omit mgmt_tls_fingerprint; got %s", v15Body)
	}
}

func TestResolveMgmtPort_GeneratesInRange(t *testing.T) {
	for i := 0; i < 32; i++ {
		p, err := ResolveMgmtPort(0)
		if err != nil {
			t.Fatal(err)
		}
		if p < MinMgmtPort || p > MaxMgmtPort {
			t.Fatalf("generated port %d outside [%d,%d]", p, MinMgmtPort, MaxMgmtPort)
		}
	}
}

func TestResolveMgmtPort_RejectsOutOfRange(t *testing.T) {
	for _, p := range []int{1, 8443, 9999, 65001, 65535} {
		if _, err := ResolveMgmtPort(p); err == nil {
			t.Fatalf("ResolveMgmtPort(%d) must reject", p)
		}
		if err := ValidateMgmtPort(p); err == nil {
			t.Fatalf("ValidateMgmtPort(%d) must reject", p)
		}
	}
	if err := ValidateMgmtPort(42424); err != nil {
		t.Fatalf("ValidateMgmtPort(42424): %v", err)
	}
}

// TestCandidateMeta_OmitEmptyParams pins that an empty Params slice
// does not emit "params": null — relaypack-v1 expects either a JSON
// object or absence.
func TestCandidateMeta_OmitEmptyParams(t *testing.T) {
	m := CandidateMeta{
		Family:           "vless-reality",
		ExposureMode:     "direct_vps",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		Port:             443,
		PublicRiskTags:   []string{},
		OriginRiskTags:   []string{},
	}
	body, _ := json.Marshal(m)
	if bytes.Contains(body, []byte(`"params":null`)) {
		t.Errorf(`empty Params must omit; got %s`, body)
	}
}

// TestDecommissionReport_WireShape locks the JSON contract
// `daal-deploy decommission` prints and the wizard's DestroyReport
// reads. Renaming a field here silently breaks the Rust shim, which
// deserialises by name.
func TestDecommissionReport_WireShape(t *testing.T) {
	rep := NewDecommissionReport("hetzner", "12345")
	rep.ServerDeleted = true
	rep.FirewallDeleted = true
	rep.FirewallID = "910"
	rep.DeletedSSHKeyIDs = []string{"678"}
	rep.Warnf("floating IP %s stays reserved", "fip-9")
	rep.Preserve("floating-ip:fip-9")

	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{
		"provider", "server_id", "server_deleted", "ssh_key_deleted",
		"firewall_deleted", "deleted_ssh_key_ids", "firewall_id",
		"preserved", "warnings",
	} {
		if _, ok := wire[k]; !ok {
			t.Errorf("missing field %q in %s", k, body)
		}
	}
	if wire["ssh_key_deleted"] != false {
		t.Errorf("an untouched leg must serialise as false, not be omitted: %s", body)
	}
	if w, ok := wire["warnings"].([]any); !ok || len(w) != 1 {
		t.Errorf("warnings = %v; want a one-element array", wire["warnings"])
	}
}

// TestDecommissionReport_WarningsNeverNull: the Rust side reads
// warnings into a Vec<String>, and a JSON null there is a
// deserialisation error rather than an empty list.
func TestDecommissionReport_WarningsNeverNull(t *testing.T) {
	body, err := json.Marshal(NewDecommissionReport("vultr", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"warnings":[]`) {
		t.Errorf("warnings must marshal as [] on a fresh report; got %s", body)
	}
}

func TestDecommissionReport_CleanRequiresEveryLeg(t *testing.T) {
	cases := []struct {
		name  string
		build func() *DecommissionReport
		want  bool
	}{
		{"all three legs, nothing preserved", func() *DecommissionReport {
			r := NewDecommissionReport("hetzner", "1")
			r.ServerDeleted, r.SSHKeyDeleted, r.FirewallDeleted = true, true, true
			return r
		}, true},
		{"a preserved resource is not clean", func() *DecommissionReport {
			r := NewDecommissionReport("hetzner", "1")
			r.ServerDeleted, r.SSHKeyDeleted, r.FirewallDeleted = true, true, true
			r.Preserve("firewall:daal-relay-1")
			return r
		}, false},
		{"a false leg is not clean", func() *DecommissionReport {
			r := NewDecommissionReport("hetzner", "1")
			r.ServerDeleted, r.FirewallDeleted = true, true
			return r
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.build().Clean(); got != tc.want {
				t.Errorf("Clean() = %v want %v", got, tc.want)
			}
		})
	}
}
