package abi

import (
	"os"
	"strings"
	"testing"

	"daal/core/routestore"
)

func rdzPub() routestore.PublisherRow {
	return routestore.PublisherRow{
		PublisherID: "fp-3b", DisplayName: "SF", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T13:00:00Z", LastSeenBundle: "2026-04-28T13:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}
}

func rdzRoute() routestore.RouteRow {
	return routestore.RouteRow{
		RouteID: "r-sf", TransportFamily: "snowflake", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "fp-3b",
		PublisherLabel: "SF", TrustState: "tofu", ScarcityClass: "experimental",
		ModesAllowed: []string{"normal"}, ExpiresAt: "2026-05-28T13:00:00Z",
		ImportedAt: "2026-04-28T13:00:00Z",
	}
}

// Phase 3B. Rendezvous-priority + push opt-in ABI tests.
//
// Canonical regressions called out in
// specs/engine-abi-v1.md "Phase 3B" and
// specs/push-rendezvous-v1.md:
//
//   - TestRendezvousPriority_DefaultsToBundle (no override)
//   - TestSetRendezvousPriority_RejectsUnknownChannel
//   - TestRendezvousOverrideSurvivesSessionEpoch
//   - TestPushOptIn_DefaultsOff
//   - TestPushOptIn_RejectedByVaultProfile (-2)
//   - TestPushOptIn_AcceptedByKeystoreProfile
//   - TestRecordRendezvousWinner_PersistsThroughLayers
//   - TestVersionStringIncludesV3Transport (regression on
//     `0.7.1+v3-transport` after the 3B bump)

func TestRendezvousPriority_DefaultsToBundle(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if RendezvousPriority() != nil {
		t.Errorf("default override should be nil, got %v", RendezvousPriority())
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"rendezvous_priority": null`) {
		t.Errorf("diagnostics did not show null priority:\n%s", body)
	}
}

func TestSetRendezvousPriority_AcceptsKnownChannels(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetRendezvousPriority([]string{"sqs", "domain_fronted_broker"}); rc != 0 {
		t.Fatalf("set with known channels: rc=%d", rc)
	}
	got := RendezvousPriority()
	if len(got) != 2 || got[0] != "sqs" || got[1] != "domain_fronted_broker" {
		t.Errorf("priority round-trip: got %v", got)
	}
}

func TestSetRendezvousPriority_RejectsUnknownChannel(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetRendezvousPriority([]string{"sqs", "telepathy"}); rc != -3 {
		t.Errorf("expected rc=-3 (unknown channel), got rc=%d", rc)
	}
	if RendezvousPriority() != nil {
		t.Error("rejected setter must not mutate state")
	}
}

func TestRendezvousOverrideSurvivesSessionEpoch(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	if rc := SetRendezvousPriority([]string{"amp_cache", "sqs"}); rc != 0 {
		t.Fatalf("set: rc=%d", rc)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	// Re-Init the same state-dir.
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	got := RendezvousPriority()
	if len(got) != 2 || got[0] != "amp_cache" || got[1] != "sqs" {
		t.Errorf("override did not survive session epoch: got %v", got)
	}
}

func TestPushOptIn_DefaultsOff(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if PushRendezvousEnabled() {
		t.Error("push opt-in must default OFF")
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"push_rendezvous_enabled": false`) {
		t.Errorf("diagnostics missing push_rendezvous_enabled=false:\n%s", body)
	}
}

func TestPushOptIn_RejectedByVaultProfile(t *testing.T) {
	dir := t.TempDir()
	// Mark the state-dir as a vault profile BEFORE Init.
	if err := os.WriteFile(dir+"/.use_vault", []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetPushRendezvousEnabled(true); rc != -2 {
		t.Errorf("vault rejection: expected rc=-2, got %d", rc)
	}
	if PushRendezvousEnabled() {
		t.Error("vault profile must remain push-OFF even after a setter call")
	}
}

func TestPushOptIn_AcceptedByKeystoreProfile(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetPushRendezvousEnabled(true); rc != 0 {
		t.Fatalf("keystore opt-in: rc=%d", rc)
	}
	if !PushRendezvousEnabled() {
		t.Error("opt-in did not flip the flag")
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"push_rendezvous_enabled": true`) {
		t.Errorf("diagnostics did not reflect opt-in:\n%s", body)
	}
}

func TestPushDeviceToken_RejectedByVaultProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/.use_vault", []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetPushDeviceToken("fcm", "tok-abc"); rc != -2 {
		t.Errorf("vault rejection of token: expected rc=-2, got %d", rc)
	}
	pd := PushDeviceToken()
	if pd.Platform != "" || pd.Token != "" {
		t.Errorf("vault profile must hold empty token; got (%q,%q)", pd.Platform, pd.Token)
	}
}

func TestPushDeviceToken_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetPushDeviceToken("fcm", "tok-abc"); rc != 0 {
		t.Fatalf("set: rc=%d", rc)
	}
	pd := PushDeviceToken()
	if pd.Platform != "fcm" || pd.Token != "tok-abc" {
		t.Errorf("token round-trip: got (%q,%q)", pd.Platform, pd.Token)
	}
}

func TestRecordRendezvousWinner_PersistsThroughLayers(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	c := mustCore()
	if err := c.store.UpsertPublisher(rdzPub()); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertRoute(rdzRoute()); err != nil {
		t.Fatal(err)
	}

	if err := RecordRendezvousWinner("r-sf", "sqs", "net-1"); err != nil {
		t.Fatalf("RecordRendezvousWinner: %v", err)
	}

	// Routestore: per-route persistence.
	row, _ := c.store.GetRoute("r-sf")
	if row.LastWinningRendezvousChannel != "sqs" {
		t.Errorf("routestore: got %q want sqs", row.LastWinningRendezvousChannel)
	}
	// Netmem: per-network persistence.
	if got := netmemStore().LookupWinningRendezvousChannel("net-1"); got != "sqs" {
		t.Errorf("netmem: got %q want sqs", got)
	}
	// Diagnostics: in-memory snapshot.
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"rendezvous_channel": "sqs"`) {
		t.Errorf("diagnostics missing rendezvous_channel=sqs:\n%s", body)
	}
	if !strings.Contains(body, `"last_winning_rendezvous_channel": "sqs"`) {
		t.Errorf("diagnostics missing last_winning_rendezvous_channel=sqs:\n%s", body)
	}
}

func TestRecordRendezvousWinner_RejectsUnknownChannel(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	err := RecordRendezvousWinner("r-x", "telepathy", "net-1")
	if err == nil {
		t.Error("unknown channel must be rejected")
	}
}

func TestVersionStringIncludesV3Transport(t *testing.T) {
	// Phase 3F: version moves from 0.8.0+v3-wasm to
	// 0.9.0+v3-share to mark the one-tap delegate-share
	// milestone.
	if !strings.Contains(Version, "0.9.0+v3-share") {
		t.Errorf("Version did not bump for 3F: %q", Version)
	}
}

func TestEngineDeliverPushPayload_RequiresOptIn(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := EngineDeliverPushPayload([]byte(`{"x":1}`)); rc != -2 {
		t.Errorf("default-off must return -2, got %d", rc)
	}
}

func TestEngineDeliverPushPayload_RejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := SetPushRendezvousEnabled(true); rc != 0 {
		t.Fatal(rc)
	}
	if rc := EngineDeliverPushPayload([]byte("garbage")); rc != -6 {
		t.Errorf("malformed must return -6, got %d", rc)
	}
}

func TestEngineDeliverPushPayload_VaultRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/.use_vault", []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if rc := EngineDeliverPushPayload([]byte(`{"hint_version":1}`)); rc != -2 {
		t.Errorf("vault must return -2, got %d", rc)
	}
}
