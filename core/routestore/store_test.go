package routestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndCRUD(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp1", DisplayName: "Pub 1", TrustLevel: "tofu_friend",
		FirstSeen: "2026-04-26T19:00:00Z", LastSeenBundle: "2026-04-26T19:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 26, 19, 30, 0, 0, time.UTC)
	if err := s.AppendTrustAudit("fp1", "unknown", "tofu", "first import", now); err != nil {
		t.Fatal(err)
	}

	if err := s.UpsertRoute(RouteRow{
		RouteID: "r1", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "fp1",
		PublisherLabel: "Pub 1", TrustState: "tofu", ScarcityClass: "normal",
		ModesAllowed: []string{"normal"}, ExpiresAt: "2026-05-26T19:00:00Z",
		ImportedAt: HourBucket(now),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRoute("r1")
	if err != nil {
		t.Fatalf("get route: %v", err)
	}
	if got.PublisherID != "fp1" || got.TrustState != "tofu" {
		t.Fatalf("unexpected route row: %+v", got)
	}

	all, err := s.ListRoutes()
	if err != nil || len(all) != 1 {
		t.Fatalf("list routes: %v %v", all, err)
	}

	if err := s.MarkRouteRevoked("r1"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRoute("r1")
	if got.TrustState != "revoked" {
		t.Fatalf("trust_state: want revoked got %s", got.TrustState)
	}
}

func TestSecretsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pt := []byte(`{"type":"vless","tag":"r-1"}`)
	cp := append([]byte(nil), pt...)
	if err := s.PutSecret("route:r-1", cp); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSecret("route:r-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("decrypted mismatch: %q != %q", got, pt)
	}
}

func TestSecretCiphertextDoesNotContainPlaintext(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pt := []byte("topsecret-route-marker-XYZ987")
	if err := s.PutSecret("k", append([]byte(nil), pt...)); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "daal.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, pt) {
		t.Fatal("plaintext appears verbatim in sqlite file")
	}
}

func TestPanicWipeRemovesEverything(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutSecret("k", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := s.PanicWipe(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"daal.db", "secrets.key"} {
		if _, err := os.Stat(filepath.Join(dir, p)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists: %v", p, err)
		}
	}
}

func TestHourBucketIsTruncated(t *testing.T) {
	in := time.Date(2026, 4, 26, 19, 47, 23, 555, time.UTC)
	got := HourBucket(in)
	if got != "2026-04-26T19:00:00Z" {
		t.Fatalf("hour bucket %q", got)
	}
}

// Phase 3A. The three new SBP-v1 widening fields round-trip through
// UpsertRoute / GetRoute / ListRoutes.
func TestUpsertRoute_3AFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-3a", DisplayName: "WT Provider", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T13:00:00Z", LastSeenBundle: "2026-04-28T13:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 28, 13, 30, 0, 0, time.UTC)
	want := RouteRow{
		RouteID:                      "r-wt-1",
		TransportFamily:              "webtunnel",
		Engine:                       "sing-box",
		SourceType:                   "trusted_provider",
		PublisherID:                  "fp-3a",
		PublisherLabel:               "WT Provider",
		TrustState:                   "tofu",
		ScarcityClass:                "experimental",
		ModesAllowed:                 []string{"normal"},
		ExpiresAt:                    "2026-05-28T13:00:00Z",
		ImportedAt:                   HourBucket(now),
		FamilySpecificConfigJSON:     `{"webtunnel_secret_path":"abc","webtunnel_alpn":["http/1.1"]}`,
		CaveatFAIR:                   "custom caveat",
		ExperimentalMinEngineVersion: "0.7.0",
	}
	if err := s.UpsertRoute(want); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRoute("r-wt-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.FamilySpecificConfigJSON != want.FamilySpecificConfigJSON {
		t.Errorf("family_specific_config_json: got %q want %q", got.FamilySpecificConfigJSON, want.FamilySpecificConfigJSON)
	}
	if got.CaveatFAIR != want.CaveatFAIR {
		t.Errorf("caveat_fa_ir: got %q want %q", got.CaveatFAIR, want.CaveatFAIR)
	}
	if got.ExperimentalMinEngineVersion != want.ExperimentalMinEngineVersion {
		t.Errorf("experimental_min_engine_version: got %q want %q", got.ExperimentalMinEngineVersion, want.ExperimentalMinEngineVersion)
	}

	all, err := s.ListRoutes()
	if err != nil || len(all) != 1 {
		t.Fatalf("list routes: %v %v", all, err)
	}
	if all[0].FamilySpecificConfigJSON != want.FamilySpecificConfigJSON {
		t.Errorf("list family_specific_config_json: got %q", all[0].FamilySpecificConfigJSON)
	}
}

// Phase 3B. The two new SBP-v1 + engine-recorded fields
// round-trip through UpsertRoute / GetRoute / ListRoutes; the
// per-route winning channel persists across UpsertRoute calls
// (UpsertRoute MUST NOT overwrite the engine-recorded value).
func TestUpsertRoute_3BFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-3b", DisplayName: "SF Provider", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T13:00:00Z", LastSeenBundle: "2026-04-28T13:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 28, 13, 30, 0, 0, time.UTC)
	want := RouteRow{
		RouteID:                "r-sf-1",
		TransportFamily:        "snowflake",
		Engine:                 "sing-box",
		SourceType:             "trusted_provider",
		PublisherID:            "fp-3b",
		PublisherLabel:         "SF Provider",
		TrustState:             "tofu",
		ScarcityClass:          "experimental",
		ModesAllowed:           []string{"normal"},
		ExpiresAt:              "2026-05-28T13:00:00Z",
		ImportedAt:             HourBucket(now),
		RendezvousPriorityJSON: `["sqs","domain_fronted_broker","offline_hint"]`,
	}
	if err := s.UpsertRoute(want); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRoute("r-sf-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RendezvousPriorityJSON != want.RendezvousPriorityJSON {
		t.Errorf("rendezvous_priority_json: got %q want %q",
			got.RendezvousPriorityJSON, want.RendezvousPriorityJSON)
	}
	if got.LastWinningRendezvousChannel != "" {
		t.Errorf("winning channel: got %q want empty (no winner yet)",
			got.LastWinningRendezvousChannel)
	}

	// Engine records a winner.
	if err := s.RecordRendezvousWinner("r-sf-1", "sqs"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRoute("r-sf-1")
	if got.LastWinningRendezvousChannel != "sqs" {
		t.Errorf("after RecordRendezvousWinner: got %q want sqs",
			got.LastWinningRendezvousChannel)
	}

	// Subsequent UpsertRoute (e.g., bundle re-import) MUST NOT
	// clobber the recorded winner.
	want.RendezvousPriorityJSON = `["amp_cache"]`
	if err := s.UpsertRoute(want); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRoute("r-sf-1")
	if got.LastWinningRendezvousChannel != "sqs" {
		t.Errorf("UpsertRoute clobbered the winner: got %q",
			got.LastWinningRendezvousChannel)
	}
	if got.RendezvousPriorityJSON != `["amp_cache"]` {
		t.Errorf("UpsertRoute did not update priority: got %q",
			got.RendezvousPriorityJSON)
	}
}

// A pre-3A caller that leaves the widening fields zeroed must
// continue to round-trip without surfacing nil/invalid JSON.
func TestUpsertRoute_PreserveBackwardCompatibility(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-old", DisplayName: "Old", TrustLevel: "tofu_friend",
		FirstSeen: "2026-04-28T13:00:00Z", LastSeenBundle: "2026-04-28T13:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoute(RouteRow{
		RouteID: "r-old", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "fp-old",
		TrustState: "tofu", ScarcityClass: "normal",
		ModesAllowed: []string{"normal"}, ExpiresAt: "2026-05-28T13:00:00Z",
		ImportedAt: "2026-04-28T13:00:00Z",
		// 3A fields left zero.
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRoute("r-old")
	if err != nil {
		t.Fatal(err)
	}
	if got.FamilySpecificConfigJSON != "{}" {
		t.Errorf("family_specific_config_json default: got %q want {}", got.FamilySpecificConfigJSON)
	}
	if got.CaveatFAIR != "" {
		t.Errorf("caveat_fa_ir default: got %q", got.CaveatFAIR)
	}
	if got.ExperimentalMinEngineVersion != "" {
		t.Errorf("experimental_min_engine_version default: got %q", got.ExperimentalMinEngineVersion)
	}
	// Phase 3B defaults.
	if got.RendezvousPriorityJSON != "[]" {
		t.Errorf("rendezvous_priority_json default: got %q want []",
			got.RendezvousPriorityJSON)
	}
	if got.LastWinningRendezvousChannel != "" {
		t.Errorf("last_winning_rendezvous_channel default: got %q",
			got.LastWinningRendezvousChannel)
	}
	// Phase 3C default.
	if got.MasqueEndpoint != "" {
		t.Errorf("masque_endpoint default: got %q want empty",
			got.MasqueEndpoint)
	}
}

// TestUpsertRoute_3CFieldsRoundTrip — Phase 3C MASQUE
// endpoint round-trips through Upsert + Get + Upsert without
// drift. Pre-3C callers that leave MasqueEndpoint zeroed
// continue to round-trip via the additive-ALTER default.
func TestUpsertRoute_3CFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-3c", DisplayName: "MASQUE Provider", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T13:00:00Z", LastSeenBundle: "2026-04-28T13:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 28, 13, 30, 0, 0, time.UTC)
	want := RouteRow{
		RouteID:         "r-mq-1",
		TransportFamily: "masque",
		Engine:          "sing-box",
		SourceType:      "trusted_provider",
		PublisherID:     "fp-3c",
		PublisherLabel:  "MASQUE Provider",
		TrustState:      "tofu",
		ScarcityClass:   "experimental",
		ModesAllowed:    []string{"normal"},
		ExpiresAt:       "2026-05-28T13:00:00Z",
		ImportedAt:      HourBucket(now),
		MasqueEndpoint:  "https://m.example.com/.well-known/masque/udp",
	}
	if err := s.UpsertRoute(want); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRoute("r-mq-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MasqueEndpoint != want.MasqueEndpoint {
		t.Errorf("masque_endpoint: got %q want %q",
			got.MasqueEndpoint, want.MasqueEndpoint)
	}

	// Subsequent UpsertRoute (e.g., bundle re-import) updates
	// the endpoint deterministically.
	want.MasqueEndpoint = "https://m.example.com/v2/m"
	if err := s.UpsertRoute(want); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRoute("r-mq-1")
	if got.MasqueEndpoint != "https://m.example.com/v2/m" {
		t.Errorf("UpsertRoute did not update endpoint: got %q", got.MasqueEndpoint)
	}

	// Listing returns the field too.
	all, err := s.ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range all {
		if r.RouteID == "r-mq-1" {
			found = true
			if r.MasqueEndpoint != "https://m.example.com/v2/m" {
				t.Errorf("ListRoutes endpoint: got %q", r.MasqueEndpoint)
			}
		}
	}
	if !found {
		t.Error("r-mq-1 missing from ListRoutes")
	}
}

// TestUpsertRoute_3DFieldsRoundTrip — Phase 3D refraction
// fields (Psiphon opaque blob + Conjure phantom subnets +
// station pubkey + decoy pool) round-trip through Upsert +
// Get + Upsert without drift. Pre-3D callers that leave the
// fields zeroed round-trip via the additive-ALTER defaults.
func TestUpsertRoute_3DFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-3d", DisplayName: "Refraction Provider", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T16:00:00Z", LastSeenBundle: "2026-04-28T16:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 28, 16, 30, 0, 0, time.UTC)

	// --- Psiphon route ---
	psiBlob := bytes.Repeat([]byte{0xAB}, 4096)
	psiWant := RouteRow{
		RouteID:           "r-ps-1",
		TransportFamily:   "psiphon",
		Engine:            "psiphon",
		SourceType:        "trusted_provider",
		PublisherID:       "fp-3d",
		PublisherLabel:    "Refraction Provider",
		TrustState:        "tofu",
		ScarcityClass:     "normal",
		ModesAllowed:      []string{"normal"},
		ExpiresAt:         "2026-05-28T16:00:00Z",
		ImportedAt:        HourBucket(now),
		PsiphonBundleBlob: psiBlob,
	}
	if err := s.UpsertRoute(psiWant); err != nil {
		t.Fatal(err)
	}
	psiGot, err := s.GetRoute("r-ps-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(psiGot.PsiphonBundleBlob, psiBlob) {
		t.Errorf("psiphon_bundle_blob: got %d bytes want %d bytes",
			len(psiGot.PsiphonBundleBlob), len(psiBlob))
	}

	// --- Conjure route ---
	cjWant := RouteRow{
		RouteID:                   "r-cj-1",
		TransportFamily:           "conjure",
		Engine:                    "gotapdance",
		SourceType:                "trusted_provider",
		PublisherID:               "fp-3d",
		PublisherLabel:            "Refraction Provider",
		TrustState:                "tofu",
		ScarcityClass:             "experimental",
		ModesAllowed:              []string{"normal"},
		ExpiresAt:                 "2026-05-28T16:00:00Z",
		ImportedAt:                HourBucket(now),
		ConjurePhantomSubnetsJSON: `["192.122.190.0/24","2001:48a8:687f::/48"]`,
		ConjureStationPubkeyHex:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ConjureDecoyPoolJSON:      `["www.example.com","static.example.org"]`,
	}
	if err := s.UpsertRoute(cjWant); err != nil {
		t.Fatal(err)
	}
	cjGot, err := s.GetRoute("r-cj-1")
	if err != nil {
		t.Fatal(err)
	}
	if cjGot.ConjurePhantomSubnetsJSON != cjWant.ConjurePhantomSubnetsJSON {
		t.Errorf("phantom_subnets: got %q want %q",
			cjGot.ConjurePhantomSubnetsJSON, cjWant.ConjurePhantomSubnetsJSON)
	}
	if cjGot.ConjureStationPubkeyHex != cjWant.ConjureStationPubkeyHex {
		t.Errorf("station_pubkey: got %q", cjGot.ConjureStationPubkeyHex)
	}
	if cjGot.ConjureDecoyPoolJSON != cjWant.ConjureDecoyPoolJSON {
		t.Errorf("decoy_pool: got %q", cjGot.ConjureDecoyPoolJSON)
	}

	// --- Pre-3D defaults round-trip ---
	preWant := RouteRow{
		RouteID:         "r-pre-3d",
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "trusted_provider",
		PublisherID:     "fp-3d",
		PublisherLabel:  "Refraction Provider",
		TrustState:      "tofu",
		ScarcityClass:   "normal",
		ModesAllowed:    []string{"normal"},
		ExpiresAt:       "2026-05-28T16:00:00Z",
		ImportedAt:      HourBucket(now),
		// All 3D fields left zeroed.
	}
	if err := s.UpsertRoute(preWant); err != nil {
		t.Fatal(err)
	}
	preGot, err := s.GetRoute("r-pre-3d")
	if err != nil {
		t.Fatal(err)
	}
	if len(preGot.PsiphonBundleBlob) != 0 {
		t.Errorf("pre-3D psiphon_bundle_blob default: got %d bytes",
			len(preGot.PsiphonBundleBlob))
	}
	if preGot.ConjurePhantomSubnetsJSON != "[]" {
		t.Errorf("pre-3D conjure_phantom_subnets default: got %q",
			preGot.ConjurePhantomSubnetsJSON)
	}
	if preGot.ConjureStationPubkeyHex != "" {
		t.Errorf("pre-3D station_pubkey default: got %q",
			preGot.ConjureStationPubkeyHex)
	}
	if preGot.ConjureDecoyPoolJSON != "[]" {
		t.Errorf("pre-3D decoy_pool default: got %q",
			preGot.ConjureDecoyPoolJSON)
	}
}

// TestUpsertRoute_3EFieldsRoundTrip — Phase 3E
// `transport_module_slug` round-trips through Upsert + Get
// without drift, and pre-3E callers that leave the field
// zeroed round-trip via the additive-ALTER default empty
// string. Also exercises the 3E non-clobber discipline for
// engine-recorded kill-switch entries: `wasm_killed:` keys
// in `secrets_kv` must persist across an UpsertRoute that
// does NOT touch them.
func TestUpsertRoute_3EFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-3e", DisplayName: "WASM Provider", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T17:00:00Z", LastSeenBundle: "2026-04-28T17:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 28, 17, 30, 0, 0, time.UTC)

	// --- WASM transport_module route ---
	wmWant := RouteRow{
		RouteID:             "r-wm-1",
		TransportFamily:     "transport_module",
		Engine:              "wasm",
		SourceType:          "trusted_provider",
		PublisherID:         "fp-3e",
		PublisherLabel:      "WASM Provider",
		TrustState:          "tofu",
		ScarcityClass:       "experimental",
		ModesAllowed:        []string{"normal"},
		ExpiresAt:           "2026-05-28T17:00:00Z",
		ImportedAt:          HourBucket(now),
		TransportModuleSlug: "hello-https",
	}
	if err := s.UpsertRoute(wmWant); err != nil {
		t.Fatal(err)
	}
	wmGot, err := s.GetRoute("r-wm-1")
	if err != nil {
		t.Fatal(err)
	}
	if wmGot.TransportModuleSlug != "hello-https" {
		t.Errorf("transport_module_slug: got %q want %q", wmGot.TransportModuleSlug, "hello-https")
	}

	// --- Pre-3E defaults round-trip ---
	preWant := RouteRow{
		RouteID:         "r-pre-3e",
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "trusted_provider",
		PublisherID:     "fp-3e",
		PublisherLabel:  "WASM Provider",
		TrustState:      "tofu",
		ScarcityClass:   "normal",
		ModesAllowed:    []string{"normal"},
		ExpiresAt:       "2026-05-28T17:00:00Z",
		ImportedAt:      HourBucket(now),
	}
	if err := s.UpsertRoute(preWant); err != nil {
		t.Fatal(err)
	}
	preGot, err := s.GetRoute("r-pre-3e")
	if err != nil {
		t.Fatal(err)
	}
	if preGot.TransportModuleSlug != "" {
		t.Errorf("pre-3E transport_module_slug default: got %q", preGot.TransportModuleSlug)
	}

	// --- Non-clobber: kill-switch entries persist across
	// re-import. The engine writes wasm_killed:<sha> into
	// secrets_kv; an UpsertRoute MUST NOT clear them.
	const killedSHA = "deadbeef" + // 64 hex chars
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := s.PutSecret("wasm_killed:"+killedSHA, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Re-import the route; secrets_kv must be untouched.
	if err := s.UpsertRoute(wmWant); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecret("wasm_killed:" + killedSHA); err != nil {
		t.Errorf("wasm_killed entry was clobbered by UpsertRoute: %v", err)
	}
}

// TestUpsertRoute_3FFieldsRoundTrip — Phase 3F. The
// (RedistributionPolicy, RedistributionCap) pair round-trips
// through the single TEXT column with the on-disk encoding
// `<policy>` or `<policy>:<cap>` for delegated_n.
func TestUpsertRoute_3FFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp-3f", DisplayName: "Share Publisher", TrustLevel: "trusted_provider",
		FirstSeen: "2026-04-28T18:00:00Z", LastSeenBundle: "2026-04-28T18:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 28, 18, 30, 0, 0, time.UTC)

	cases := []struct {
		id     string
		policy string
		cap    uint8
	}{
		{"r-3f-none", "none", 0},
		{"r-3f-deln", "delegated_n", 10},
		{"r-3f-trans", "transitive", 0},
		{"r-3f-empty", "", 0},
	}
	for _, c := range cases {
		want := RouteRow{
			RouteID: c.id, TransportFamily: "vless-reality", Engine: "sing-box",
			SourceType: "trusted_provider", PublisherID: "fp-3f",
			PublisherLabel: "Share Publisher", TrustState: "tofu",
			ScarcityClass: "normal", ModesAllowed: []string{"normal"},
			ExpiresAt: "2026-05-28T18:00:00Z", ImportedAt: HourBucket(now),
			RedistributionPolicy: c.policy, RedistributionCap: c.cap,
		}
		if err := s.UpsertRoute(want); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetRoute(c.id)
		if err != nil {
			t.Fatal(err)
		}
		if got.RedistributionPolicy != c.policy || got.RedistributionCap != c.cap {
			t.Errorf("%s: got (%q,%d) want (%q,%d)",
				c.id, got.RedistributionPolicy, got.RedistributionCap, c.policy, c.cap)
		}
	}

	// Non-clobber: the device-local re-share counter under
	// `secrets_kv:delegate_share_counter:<route_id>` must NOT
	// be touched by an UpsertRoute that updates the
	// publisher-declared policy. Pre-seed the counter, then
	// re-import the route with a new cap and confirm the
	// counter survives.
	const counterKey = "delegate_share_counter:r-3f-deln"
	if err := s.PutSecret(counterKey, []byte("3")); err != nil {
		t.Fatal(err)
	}
	updated := RouteRow{
		RouteID: "r-3f-deln", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "fp-3f",
		PublisherLabel: "Share Publisher", TrustState: "tofu",
		ScarcityClass: "normal", ModesAllowed: []string{"normal"},
		ExpiresAt: "2026-05-28T18:00:00Z", ImportedAt: HourBucket(now),
		RedistributionPolicy: "delegated_n", RedistributionCap: 25,
	}
	if err := s.UpsertRoute(updated); err != nil {
		t.Fatal(err)
	}
	body, err := s.GetSecret(counterKey)
	if err != nil {
		t.Fatalf("delegate_share_counter clobbered: %v", err)
	}
	if string(body) != "3" {
		t.Errorf("delegate_share_counter body: got %q want %q", body, "3")
	}
	// And the policy is now the new value.
	got, _ := s.GetRoute("r-3f-deln")
	if got.RedistributionCap != 25 {
		t.Errorf("re-import cap: got %d want 25", got.RedistributionCap)
	}
}

// TestEncodeDecodeRedistributionPolicy locks the on-disk shape.
func TestEncodeDecodeRedistributionPolicy(t *testing.T) {
	cases := []struct {
		policy  string
		cap     uint8
		encoded string
	}{
		{"", 0, ""},
		{"none", 0, "none"},
		{"transitive", 0, "transitive"},
		{"delegated_n", 10, "delegated_n:10"},
		{"delegated_n", 255, "delegated_n:255"},
	}
	for _, c := range cases {
		got := EncodeRedistributionPolicy(c.policy, c.cap)
		if got != c.encoded {
			t.Errorf("Encode(%q,%d) = %q want %q", c.policy, c.cap, got, c.encoded)
		}
		gp, gc := DecodeRedistributionPolicy(c.encoded)
		if gp != c.policy || gc != c.cap {
			t.Errorf("Decode(%q) = (%q,%d) want (%q,%d)", c.encoded, gp, gc, c.policy, c.cap)
		}
	}
	// Malformed → fail closed.
	for _, s := range []string{"yolo", "delegated_n:abc", "delegated_n:", "delegated_n:300"} {
		gp, gc := DecodeRedistributionPolicy(s)
		if gp != "none" || gc != 0 {
			t.Errorf("Decode(%q) = (%q,%d) want (none,0)", s, gp, gc)
		}
	}
}

// FRP-2 (Phase 30): RelayPack RouteRow widening tests.

// frp2SetupPublisher creates a minimal publisher row so RouteRow's
// FK to publishers is satisfied.
func frp2SetupPublisher(t *testing.T, s *Store) {
	t.Helper()
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "pub-frp2", DisplayName: "FRP-2 test publisher",
		TrustLevel: "tofu_friend", FirstSeen: HourBucket(now),
		LastSeenBundle: HourBucket(now), KeyStatus: "active",
		RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatalf("seed publisher: %v", err)
	}
}

// frp2RouteRowRP returns a fully-populated RouteRow with all 9
// RelayPack fields set to non-default values. Used across the
// FRP-2 RouteRow widening tests.
func frp2RouteRowRP(routeID string) RouteRow {
	return RouteRow{
		RouteID:         routeID,
		TransportFamily: "vless-reality",
		Engine:          "sing-box",
		SourceType:      "trusted_provider",
		PublisherID:     "pub-frp2",
		PublisherLabel:  "FRP-2 test publisher",
		TrustState:      "tofu",
		ScarcityClass:   "normal",
		ModesAllowed:    []string{"normal"},
		ExpiresAt:       "2026-06-02T12:00:00Z",
		ImportedAt:      "2026-05-02T12:00:00Z",
		// RelayPack fields:
		ExposureMode:        "direct_vps",
		FamilyClass:         "vps-native",
		ProbingRiskClass:    "low",
		PublicRiskTags:      []string{"public_asn:24940", "public_ip:5.75.0.1", "public_provider:hetzner"},
		OriginRiskTags:      []string{},
		ModifiersJSON:       "",
		RelayPackID:         "rp-frp2-test-001",
		FreshnessURL:        "",
		SharedRiskGraphJSON: `[{"tag":"public_ip:5.75.0.1","members":["` + routeID + `"]}]`,
	}
}

// TestRouteRow_RelayPackFields_RoundTrip verifies that all 9
// RelayPack columns survive UpsertRoute → GetRoute (and ListRoutes)
// byte-equal.
func TestRouteRow_RelayPackFields_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	frp2SetupPublisher(t, s)

	want := frp2RouteRowRP("r1-rp")
	if err := s.UpsertRoute(want); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetRoute("r1-rp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExposureMode != want.ExposureMode {
		t.Errorf("ExposureMode = %q want %q", got.ExposureMode, want.ExposureMode)
	}
	if got.FamilyClass != want.FamilyClass {
		t.Errorf("FamilyClass = %q want %q", got.FamilyClass, want.FamilyClass)
	}
	if got.ProbingRiskClass != want.ProbingRiskClass {
		t.Errorf("ProbingRiskClass = %q want %q", got.ProbingRiskClass, want.ProbingRiskClass)
	}
	if !equalStrSlice(got.PublicRiskTags, want.PublicRiskTags) {
		t.Errorf("PublicRiskTags = %v want %v", got.PublicRiskTags, want.PublicRiskTags)
	}
	if got.OriginRiskTags == nil {
		// JSON unmarshal of "[]" yields a non-nil empty slice.
		t.Errorf("OriginRiskTags must round-trip as non-nil empty slice")
	}
	if len(got.OriginRiskTags) != 0 {
		t.Errorf("OriginRiskTags = %v want empty", got.OriginRiskTags)
	}
	if got.ModifiersJSON != want.ModifiersJSON {
		t.Errorf("ModifiersJSON = %q want %q", got.ModifiersJSON, want.ModifiersJSON)
	}
	if got.RelayPackID != want.RelayPackID {
		t.Errorf("RelayPackID = %q want %q", got.RelayPackID, want.RelayPackID)
	}
	if got.FreshnessURL != want.FreshnessURL {
		t.Errorf("FreshnessURL = %q want %q (must be empty at V1.5 per RP021)", got.FreshnessURL, want.FreshnessURL)
	}
	if got.SharedRiskGraphJSON != want.SharedRiskGraphJSON {
		t.Errorf("SharedRiskGraphJSON = %q want %q", got.SharedRiskGraphJSON, want.SharedRiskGraphJSON)
	}

	// Confirm ListRoutes scanner returns the same values.
	all, err := s.ListRoutes()
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %v %v", all, err)
	}
	if all[0].ExposureMode != want.ExposureMode || all[0].RelayPackID != want.RelayPackID {
		t.Errorf("ListRoutes scanner inconsistent with GetRoute: %+v", all[0])
	}
}

// TestRouteRow_LegacyRowsHaveSentinelRelayPackFields verifies that
// a route inserted without any RelayPack fields scans back with
// sentinel-empty values matching the schema defaults.
func TestRouteRow_LegacyRowsHaveSentinelRelayPackFields(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	frp2SetupPublisher(t, s)

	legacy := RouteRow{
		RouteID: "r1-legacy", TransportFamily: "vless-reality", Engine: "sing-box",
		SourceType: "trusted_provider", PublisherID: "pub-frp2",
		PublisherLabel: "FRP-2 test publisher", TrustState: "tofu",
		ScarcityClass: "normal", ModesAllowed: []string{"normal"},
		ExpiresAt: "2026-06-02T12:00:00Z", ImportedAt: "2026-05-02T12:00:00Z",
		// All 9 RelayPack fields zero-valued.
	}
	if err := s.UpsertRoute(legacy); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetRoute("r1-legacy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExposureMode != "" || got.FamilyClass != "" || got.ProbingRiskClass != "" {
		t.Errorf("legacy row scalar RelayPack fields not sentinel-empty: %+v", got)
	}
	// JSON-array TEXT defaults '[]' decode to non-nil empty []string.
	if got.PublicRiskTags == nil || len(got.PublicRiskTags) != 0 {
		t.Errorf("PublicRiskTags must decode as empty slice; got %v", got.PublicRiskTags)
	}
	if got.OriginRiskTags == nil || len(got.OriginRiskTags) != 0 {
		t.Errorf("OriginRiskTags must decode as empty slice; got %v", got.OriginRiskTags)
	}
	if got.ModifiersJSON != "" {
		t.Errorf("ModifiersJSON must default to empty string; got %q", got.ModifiersJSON)
	}
	if got.RelayPackID != "" || got.FreshnessURL != "" {
		t.Errorf("bundle-level RelayPack fields not empty: id=%q url=%q", got.RelayPackID, got.FreshnessURL)
	}
	if got.SharedRiskGraphJSON != "[]" {
		t.Errorf("SharedRiskGraphJSON default = %q want '[]'", got.SharedRiskGraphJSON)
	}
}

// TestRouteRow_RelayPackReimportIdempotent verifies that
// re-upserting the same RouteRow twice (re-import scenario) yields
// the same row count and the same field values across all 9
// RelayPack columns.
func TestRouteRow_RelayPackReimportIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	frp2SetupPublisher(t, s)

	row := frp2RouteRowRP("r1-idemp")
	if err := s.UpsertRoute(row); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	first, err := s.GetRoute("r1-idemp")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoute(row); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	second, err := s.GetRoute("r1-idemp")
	if err != nil {
		t.Fatal(err)
	}

	all, err := s.ListRoutes()
	if err != nil || len(all) != 1 {
		t.Fatalf("ListRoutes after re-import: %d rows want 1 (err=%v)", len(all), err)
	}

	if first.ExposureMode != second.ExposureMode ||
		first.FamilyClass != second.FamilyClass ||
		first.ProbingRiskClass != second.ProbingRiskClass ||
		!equalStrSlice(first.PublicRiskTags, second.PublicRiskTags) ||
		!equalStrSlice(first.OriginRiskTags, second.OriginRiskTags) ||
		first.ModifiersJSON != second.ModifiersJSON ||
		first.RelayPackID != second.RelayPackID ||
		first.FreshnessURL != second.FreshnessURL ||
		first.SharedRiskGraphJSON != second.SharedRiskGraphJSON {
		t.Errorf("re-import not idempotent:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}

// TestSchemaMigration_RelayPackColumnsExistOnSecondOpen verifies
// that the FRP-2 schema migration:
//  1. Runs on first open (the columns get added by ALTER ADD COLUMN).
//  2. Is idempotent on re-open (the existing migrations slice
//     pattern swallows ALTER errors when the column already exists,
//     so re-opening the same DB does not double-add or fail).
func TestSchemaMigration_RelayPackColumnsExistOnSecondOpen(t *testing.T) {
	dir := t.TempDir()

	s1, err := Open(dir)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	frp2SetupPublisher(t, s1)
	row := frp2RouteRowRP("r1-mig")
	if err := s1.UpsertRoute(row); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-open the same DB. Migration must be idempotent (the existing
	// `_, _ = db.Exec(m)` pattern swallows the "column already exists"
	// error from sqlite). RouteRow round-trips byte-equal on the
	// second open.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("open 2 (re-open): %v", err)
	}
	defer s2.Close()
	got, err := s2.GetRoute("r1-mig")
	if err != nil {
		t.Fatalf("get after re-open: %v", err)
	}
	if got.ExposureMode != row.ExposureMode || got.RelayPackID != row.RelayPackID {
		t.Errorf("RouteRow not preserved across re-open: got %+v", got)
	}
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
