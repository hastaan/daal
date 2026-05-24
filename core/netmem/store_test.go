package netmem

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeKV is an in-memory SecretsKV for tests. Round-trips bytes
// without encryption — encryption is the caller's contract.
type fakeKV struct {
	m map[string][]byte
}

func newFakeKV() *fakeKV { return &fakeKV{m: map[string][]byte{}} }

func (f *fakeKV) PutSecret(key string, plaintext []byte) error {
	f.m[key] = append([]byte(nil), plaintext...)
	return nil
}

func (f *fakeKV) GetSecret(key string) ([]byte, error) {
	b, ok := f.m[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), b...), nil
}

func (f *fakeKV) DeleteSecret(key string) error {
	delete(f.m, key)
	return nil
}

func (f *fakeKV) ListSecretKeys(prefix string) ([]string, error) {
	out := []string{}
	for k := range f.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func TestStorePutGetForget(t *testing.T) {
	kv := newFakeKV()
	st := New(kv)
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	id := HashID(KindWiFi, "", "Home")

	snap := Snapshot{
		Mode: "normal",
		RouteFamilyStats: map[string]FamilyStats{
			"vless-reality": {Successes: 12, Failures: 1},
		},
		BudgetUsage:  map[string]uint64{"r1": 5_000_000},
		BudgetBucket: now.Truncate(time.Hour),
		UDPProbeOK:   true,
		UDPProbeAt:   now.Add(-30 * time.Minute),
	}
	if err := st.Put(id, snap, now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Mode != "normal" {
		t.Fatalf("Mode roundtrip: %q", got.Mode)
	}
	if got.RouteFamilyStats["vless-reality"].Successes != 12 {
		t.Fatalf("FamilyStats roundtrip: %+v", got.RouteFamilyStats)
	}
	if got.BudgetUsage["r1"] != 5_000_000 {
		t.Fatalf("BudgetUsage roundtrip: %+v", got.BudgetUsage)
	}
	if !got.UDPProbeOK {
		t.Fatalf("UDPProbeOK roundtrip: %v", got.UDPProbeOK)
	}
	if got.LastSeen.IsZero() {
		t.Fatalf("LastSeen should be stamped by Put")
	}

	if err := st.Forget(id); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, err := st.Get(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Forget: %v", err)
	}
}

func TestStoreGetMissReturnsErrNotFound(t *testing.T) {
	st := New(newFakeKV())
	if _, err := st.Get("nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreAllListsAllNetworks(t *testing.T) {
	kv := newFakeKV()
	st := New(kv)
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	for _, ssid := range []string{"Home", "Cafe", "Office"} {
		id := HashID(KindWiFi, "", ssid)
		_ = st.Put(id, Snapshot{Mode: "normal"}, now)
	}
	ids, err := st.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("All count: %d", len(ids))
	}
	// Sorted.
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("All not sorted: %v", ids)
	}
}

func TestStoreSweepDeletesStale(t *testing.T) {
	kv := newFakeKV()
	st := New(kv)
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-31 * 24 * time.Hour)
	fresh := now.Add(-1 * time.Hour)

	idStale := HashID(KindWiFi, "", "OldHotel")
	idFresh := HashID(KindWiFi, "", "Home")

	_ = st.Put(idStale, Snapshot{Mode: "normal"}, stale)
	_ = st.Put(idFresh, Snapshot{Mode: "normal"}, fresh)

	deleted, err := st.Sweep(now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != idStale {
		t.Fatalf("Sweep deleted: %v", deleted)
	}
	if _, err := st.Get(idStale); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale not deleted")
	}
	if _, err := st.Get(idFresh); err != nil {
		t.Fatalf("fresh deleted: %v", err)
	}
}

func TestStoreEmptyNetworkIDRejected(t *testing.T) {
	st := New(newFakeKV())
	if err := st.Put("", Snapshot{}, time.Now()); err == nil {
		t.Fatalf("Put with empty networkID should error")
	}
	if _, err := st.Get(""); err == nil {
		t.Fatalf("Get with empty networkID should error")
	}
	if err := st.Forget(""); err == nil {
		t.Fatalf("Forget with empty networkID should error")
	}
}

func TestSnapshotEmpty(t *testing.T) {
	if !(Snapshot{}).Empty() {
		t.Fatalf("zero Snapshot should be Empty")
	}
	if (Snapshot{Mode: "normal"}).Empty() {
		t.Fatalf("Snapshot with Mode is not empty")
	}
}

func TestSnapshotMarshalIsCanonical(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	s := Snapshot{
		Mode:     "lifeline",
		LastSeen: now,
		RouteFamilyStats: map[string]FamilyStats{
			"b": {Successes: 1},
			"a": {Successes: 2},
		},
	}
	b1, _ := s.MarshalCanonical()
	b2, _ := s.MarshalCanonical()
	if string(b1) != string(b2) {
		t.Fatalf("marshal not canonical: %s vs %s", b1, b2)
	}
	// Keys "a" must come before "b" in canonical output.
	if !strings.Contains(string(b1), `"a"`) || !strings.Contains(string(b1), `"b"`) {
		t.Fatalf("expected family keys in output: %s", b1)
	}
	if i, j := strings.Index(string(b1), `"a"`), strings.Index(string(b1), `"b"`); i > j {
		t.Fatalf("canonical order broken: a at %d, b at %d", i, j)
	}
}

// Phase 3B. RecordWinningRendezvousChannel writes a focused
// hint without rewriting the rest of the snapshot, and
// LookupWinningRendezvousChannel reads it back. The hint
// participates in the empty-snapshot check so a fresh write
// does not bypass Sweep.
func TestRecordWinningRendezvousChannel(t *testing.T) {
	st := New(newFakeKV())
	now := time.Date(2026, 4, 28, 14, 0, 0, 0, time.UTC)

	// Net with no prior snapshot.
	if got := st.LookupWinningRendezvousChannel("net-1"); got != "" {
		t.Errorf("fresh: got %q want empty", got)
	}
	if err := st.RecordWinningRendezvousChannel("net-1", "sqs", now); err != nil {
		t.Fatal(err)
	}
	if got := st.LookupWinningRendezvousChannel("net-1"); got != "sqs" {
		t.Errorf("after record: got %q want sqs", got)
	}

	// Add additional snapshot data, then update the hint.
	snap, err := st.Get("net-1")
	if err != nil {
		t.Fatal(err)
	}
	snap.Mode = "normal"
	snap.RouteFamilyStats = map[string]FamilyStats{"snowflake": {Successes: 1}}
	if err := st.Put("net-1", snap, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordWinningRendezvousChannel("net-1", "amp_cache", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("net-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastWinningRendezvousChannel != "amp_cache" {
		t.Errorf("hint update: got %q want amp_cache", got.LastWinningRendezvousChannel)
	}
	if got.Mode != "normal" {
		t.Errorf("RecordWinning clobbered Mode: got %q want normal", got.Mode)
	}
	if got.RouteFamilyStats["snowflake"].Successes != 1 {
		t.Errorf("RecordWinning clobbered RouteFamilyStats")
	}

	// Empty hint participates in Empty().
	var empty Snapshot
	if !empty.Empty() {
		t.Error("zero-value snapshot must be Empty()")
	}
	empty.LastWinningRendezvousChannel = "sqs"
	if empty.Empty() {
		t.Error("snapshot with rendezvous hint MUST NOT be Empty()")
	}
}

// Phase 3C. RecordLastUsedMasqueSubmode writes a focused
// hint without rewriting the rest of the snapshot, and
// LookupLastUsedMasqueSubmode reads it back. The hint
// participates in the empty-snapshot check so a fresh write
// does not bypass Sweep.
func TestRecordLastUsedMasqueSubmode(t *testing.T) {
	st := New(newFakeKV())
	now := time.Date(2026, 4, 28, 14, 0, 0, 0, time.UTC)

	// Net with no prior snapshot.
	if got := st.LookupLastUsedMasqueSubmode("net-1"); got != "" {
		t.Errorf("fresh: got %q want empty", got)
	}
	if err := st.RecordLastUsedMasqueSubmode("net-1", "masque_h3_quic", now); err != nil {
		t.Fatal(err)
	}
	if got := st.LookupLastUsedMasqueSubmode("net-1"); got != "masque_h3_quic" {
		t.Errorf("after record: got %q want masque_h3_quic", got)
	}

	// Adding more snapshot data + updating the hint preserves
	// the rest of the row.
	snap, err := st.Get("net-1")
	if err != nil {
		t.Fatal(err)
	}
	snap.Mode = "normal"
	snap.RouteFamilyStats = map[string]FamilyStats{"masque": {Successes: 1}}
	if err := st.Put("net-1", snap, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordLastUsedMasqueSubmode("net-1", "masque_h2_connect", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("net-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedMasqueSubmode != "masque_h2_connect" {
		t.Errorf("hint update: got %q want masque_h2_connect", got.LastUsedMasqueSubmode)
	}
	if got.Mode != "normal" {
		t.Errorf("RecordLastUsedMasqueSubmode clobbered Mode: got %q", got.Mode)
	}
	if got.RouteFamilyStats["masque"].Successes != 1 {
		t.Errorf("RecordLastUsedMasqueSubmode clobbered RouteFamilyStats")
	}
	// 3B hint must coexist with 3C hint on the same network row.
	if err := st.RecordWinningRendezvousChannel("net-1", "sqs", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ = st.Get("net-1")
	if got.LastWinningRendezvousChannel != "sqs" {
		t.Errorf("3B hint after 3C write: got %q want sqs", got.LastWinningRendezvousChannel)
	}
	if got.LastUsedMasqueSubmode != "masque_h2_connect" {
		t.Errorf("3C hint clobbered by 3B write: got %q", got.LastUsedMasqueSubmode)
	}

	// Empty() must include the 3C hint.
	var empty Snapshot
	if !empty.Empty() {
		t.Error("zero-value snapshot must be Empty()")
	}
	empty.LastUsedMasqueSubmode = "masque_h3_quic"
	if empty.Empty() {
		t.Error("snapshot with masque sub-mode hint MUST NOT be Empty()")
	}
}

// FRP-2 (Phase 30): RelayPack-aware netmem entry-value tests.
//
// The widening adds optional sparse `ByRelayPack` sub-counters on
// FamilyStats. Wire-compat invariant: pre-FRP-2 canonical JSON
// (without `by_relay_pack`) must round-trip byte-identical, and
// new fixtures with non-empty `by_relay_pack` must round-trip
// cleanly through MarshalCanonical / UnmarshalSnapshot. FRP-3 is
// the writer; FRP-2 only delivers the schema.

func TestSnapshot_LegacyDecodeStillWorks(t *testing.T) {
	// Pre-FRP-2 canonical JSON. No `by_relay_pack` field on
	// FamilyStats; no `last_winning_rendezvous_channel` /
	// `last_used_masque_submode` either (those came at 3B/3C).
	legacy := []byte(`{
"mode":"normal",
"last_seen":"2026-04-27T12:00:00Z",
"route_family_stats":{"vless-reality":{"successes":5,"failures":1}},
"udp_probe_ok":true,
"udp_probe_at":"2026-04-27T11:30:00Z"
}`)
	snap, err := UnmarshalSnapshot(legacy)
	if err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if snap.Mode != "normal" {
		t.Errorf("Mode = %q want normal", snap.Mode)
	}
	fs, ok := snap.RouteFamilyStats["vless-reality"]
	if !ok {
		t.Fatalf("vless-reality family missing")
	}
	if fs.Successes != 5 || fs.Failures != 1 {
		t.Errorf("FamilyStats = %+v want {5,1}", fs)
	}
	if fs.ByRelayPack != nil {
		t.Errorf("ByRelayPack must be nil for legacy entry; got %v", fs.ByRelayPack)
	}
}

func TestSnapshot_RelayPackStatRoundTrip(t *testing.T) {
	kv := newFakeKV()
	st := New(kv)
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)

	want := Snapshot{
		Mode: "normal",
		RouteFamilyStats: map[string]FamilyStats{
			"vless-reality": {
				Successes: 7, Failures: 2,
				ByRelayPack: []RelayPackStat{
					{
						Key: RelayPackKey{
							Family:                 "vless-reality",
							ExposureMode:           "direct_vps",
							PublicRiskTagSignature: "public_asn:24940,public_ip:5.75.0.1",
							Outcome:                "success",
						},
						Successes: 5, Failures: 0,
					},
					{
						Key: RelayPackKey{
							Family:                 "vless-reality",
							ExposureMode:           "direct_vps",
							PublicRiskTagSignature: "public_asn:24940,public_ip:5.75.0.2",
							Outcome:                "classified_failure",
						},
						Successes: 0, Failures: 2,
					},
				},
			},
		},
	}
	if err := st.Put("net-frp2-rt", want, now); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get("net-frp2-rt")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	gfs := got.RouteFamilyStats["vless-reality"]
	if gfs.Successes != 7 || gfs.Failures != 2 {
		t.Errorf("outer counts = %+v want {7,2}", gfs)
	}
	if len(gfs.ByRelayPack) != 2 {
		t.Fatalf("ByRelayPack len = %d want 2", len(gfs.ByRelayPack))
	}
	if gfs.ByRelayPack[0].Key.PublicRiskTagSignature != "public_asn:24940,public_ip:5.75.0.1" {
		t.Errorf("ByRelayPack[0] key = %+v", gfs.ByRelayPack[0].Key)
	}
	if gfs.ByRelayPack[0].Successes != 5 || gfs.ByRelayPack[1].Failures != 2 {
		t.Errorf("ByRelayPack counts wrong: %+v", gfs.ByRelayPack)
	}
}

func TestSnapshot_MixedLegacyAndRelayPack(t *testing.T) {
	// One family with only outer counters (legacy shape); another
	// with full ByRelayPack. Canonical JSON round-trip must include
	// the full structure for the FRP-2 family and OMIT
	// `by_relay_pack` for the legacy family (omitempty preserves
	// wire-compat).
	snap := Snapshot{
		Mode: "normal",
		RouteFamilyStats: map[string]FamilyStats{
			"hysteria2": {Successes: 3, Failures: 1}, // legacy shape
			"vless-reality": {
				Successes: 5, Failures: 0,
				ByRelayPack: []RelayPackStat{
					{
						Key:       RelayPackKey{Family: "vless-reality", ExposureMode: "direct_vps"},
						Successes: 5, Failures: 0,
					},
				},
			},
		},
	}
	body, err := snap.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The legacy family's serialised form must NOT contain
	// `by_relay_pack` thanks to omitempty.
	if !contains(body, []byte(`"hysteria2":{"successes":3,"failures":1}`)) {
		t.Errorf("legacy family entry missing or has unexpected shape: %s", body)
	}
	// The FRP-2 family must contain `by_relay_pack`.
	if !contains(body, []byte(`"by_relay_pack"`)) {
		t.Errorf("FRP-2 family entry must include by_relay_pack: %s", body)
	}
	// Round-trip.
	restored, err := UnmarshalSnapshot(body)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.RouteFamilyStats["hysteria2"].ByRelayPack != nil {
		t.Errorf("legacy family must round-trip with nil ByRelayPack")
	}
	if len(restored.RouteFamilyStats["vless-reality"].ByRelayPack) != 1 {
		t.Errorf("FRP-2 family ByRelayPack lost on round-trip")
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
