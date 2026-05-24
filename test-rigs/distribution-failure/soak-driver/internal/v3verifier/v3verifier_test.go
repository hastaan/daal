package v3verifier

import (
	"testing"
	"time"
)

// helper — base time for tests.
var t0 = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

func TestVerify_Empty_AllPass(t *testing.T) {
	got := Verify("run-empty", 24*time.Hour, 48*time.Hour,
		nil, nil, nil, nil, true)
	if !got.AllPass() {
		t.Fatalf("empty inputs should AllPass; got %+v", got)
	}
}

func TestVerify_Primary_CrossPlatformPickupOK(t *testing.T) {
	publish := t0
	pickups := []PickupObservation{
		{ClientID: "c1", Platform: PlatformLinux, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(2 * time.Hour)},
		{ClientID: "c2", Platform: PlatformAndroid, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(10 * time.Hour)},
		{ClientID: "c3", Platform: PlatformIOS, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(23 * time.Hour)},
	}
	got := Verify("run-primary-ok", 24*time.Hour, 48*time.Hour,
		pickups, nil, nil, nil, true)
	if !got.CrossPlatformPickupPass {
		t.Fatalf("primary should PASS; failures=%v", got.Failures)
	}
}

func TestVerify_Primary_PlatformMissed(t *testing.T) {
	publish := t0
	// iOS never observed.
	pickups := []PickupObservation{
		{ClientID: "c1", Platform: PlatformLinux, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(2 * time.Hour)},
		{ClientID: "c2", Platform: PlatformAndroid, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(5 * time.Hour)},
	}
	got := Verify("run-primary-miss", 24*time.Hour, 48*time.Hour,
		pickups, nil, nil, nil, true)
	if got.CrossPlatformPickupPass {
		t.Fatalf("primary should FAIL on missed platform")
	}
	if len(got.Failures) == 0 {
		t.Fatalf("expected a failure detail line")
	}
}

func TestVerify_Primary_OverCadence(t *testing.T) {
	publish := t0
	pickups := []PickupObservation{
		{ClientID: "c1", Platform: PlatformLinux, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(2 * time.Hour)},
		{ClientID: "c2", Platform: PlatformAndroid, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(5 * time.Hour)},
		{ClientID: "c3", Platform: PlatformIOS, ModuleSlug: "hello-tm", PublishedAt: publish, ObservedAt: publish.Add(25 * time.Hour)}, // > 24h
	}
	got := Verify("run-primary-late", 24*time.Hour, 48*time.Hour,
		pickups, nil, nil, nil, true)
	if got.CrossPlatformPickupPass {
		t.Fatalf("primary should FAIL on late pickup")
	}
}

func TestVerify_Secondary1_GateOFFViolation(t *testing.T) {
	acts := []Activation{
		// Gate-OFF client activates an experimental family.
		{ClientID: "c-off-1", Platform: PlatformLinux, GateOn: false, Family: "webtunnel", OccurredAt: t0},
	}
	got := Verify("run-gate-off-violation", 24*time.Hour, 48*time.Hour,
		nil, acts, nil, nil, true)
	if got.ExperimentalGateCrossProductPass {
		t.Fatalf("secondary-1 should FAIL when gate-OFF activates experimental")
	}
}

func TestVerify_Secondary1_GateONNoExperimental(t *testing.T) {
	acts := []Activation{
		// Gate-ON client never activates an experimental family.
		{ClientID: "c-on-1", Platform: PlatformLinux, GateOn: true, Family: "vless", OccurredAt: t0},
	}
	got := Verify("run-gate-on-empty", 24*time.Hour, 48*time.Hour,
		nil, acts, nil, nil, true)
	if got.ExperimentalGateCrossProductPass {
		t.Fatalf("secondary-1 should FAIL when gate-ON never activates experimental")
	}
}

func TestVerify_Secondary1_GateCrossProductOK(t *testing.T) {
	acts := []Activation{
		{ClientID: "c-off-1", Platform: PlatformLinux, GateOn: false, Family: "vless", OccurredAt: t0},
		{ClientID: "c-on-1", Platform: PlatformLinux, GateOn: true, Family: "webtunnel", OccurredAt: t0},
	}
	got := Verify("run-gate-ok", 24*time.Hour, 48*time.Hour,
		nil, acts, nil, nil, true)
	if !got.ExperimentalGateCrossProductPass {
		t.Fatalf("secondary-1 should PASS; failures=%v", got.Failures)
	}
}

func TestVerify_Secondary2_TrustUIParity(t *testing.T) {
	good := []TrustUIObservation{
		{ClientID: "c1", Family: "vless", Badge: MaturityGA},
		{ClientID: "c1", Family: "webtunnel", Badge: MaturityExperimental},
		{ClientID: "c2", Family: "transport_module", Badge: MaturityExperimental},
	}
	got := Verify("run-tu-ok", 24*time.Hour, 48*time.Hour, nil, nil, good, nil, true)
	if !got.TrustUIParityPass {
		t.Fatalf("secondary-2 should PASS; failures=%v", got.Failures)
	}
	bad := []TrustUIObservation{
		{ClientID: "c1", Family: "webtunnel", Badge: MaturityGA}, // wrong: webtunnel is Experimental
	}
	got = Verify("run-tu-bad", 24*time.Hour, 48*time.Hour, nil, nil, bad, nil, true)
	if got.TrustUIParityPass {
		t.Fatalf("secondary-2 should FAIL on wrong badge")
	}
	unknown := []TrustUIObservation{
		{ClientID: "c1", Family: "made-up-family", Badge: MaturityGA},
	}
	got = Verify("run-tu-unknown", 24*time.Hour, 48*time.Hour, nil, nil, unknown, nil, true)
	if got.TrustUIParityPass {
		t.Fatalf("secondary-2 should FAIL on unknown family")
	}
}

func TestVerify_Secondary3_RegressionPropagates(t *testing.T) {
	got := Verify("run-regress", 24*time.Hour, 48*time.Hour, nil, nil, nil, nil, false)
	if got.NoV1V2RegressionPass {
		t.Fatalf("secondary-3 should FAIL when caller signals regression")
	}
	if got.AllPass() {
		t.Fatalf("AllPass should be false")
	}
}

func TestVerify_Secondary4_PerFamilyBurnRate(t *testing.T) {
	// 50 h interval > 48 h cadence: passes.
	good := []FamilyBurn{
		{Family: "vless", FirstPublishAt: t0, FirstBurnAt: t0.Add(50 * time.Hour),
			BurnInterval: 50 * time.Hour, Burned: true},
	}
	got := Verify("run-burn-ok", 24*time.Hour, 48*time.Hour, nil, nil, nil, good, true)
	if !got.PerFamilyBurnRatePass {
		t.Fatalf("secondary-4 should PASS; failures=%v", got.Failures)
	}
	// 24 h interval < 48 h cadence: fails.
	bad := []FamilyBurn{
		{Family: "snowflake", FirstPublishAt: t0, FirstBurnAt: t0.Add(24 * time.Hour),
			BurnInterval: 24 * time.Hour, Burned: true},
	}
	got = Verify("run-burn-bad", 24*time.Hour, 48*time.Hour, nil, nil, nil, bad, true)
	if got.PerFamilyBurnRatePass {
		t.Fatalf("secondary-4 should FAIL on fast burn")
	}
}

func TestVerify_AllPassSetsFlag(t *testing.T) {
	publish := t0
	pickups := []PickupObservation{
		{ClientID: "c1", Platform: PlatformLinux, ModuleSlug: "tm", PublishedAt: publish, ObservedAt: publish.Add(1 * time.Hour)},
		{ClientID: "c2", Platform: PlatformAndroid, ModuleSlug: "tm", PublishedAt: publish, ObservedAt: publish.Add(1 * time.Hour)},
		{ClientID: "c3", Platform: PlatformIOS, ModuleSlug: "tm", PublishedAt: publish, ObservedAt: publish.Add(1 * time.Hour)},
	}
	acts := []Activation{
		{ClientID: "c-off", GateOn: false, Family: "vless", OccurredAt: t0},
		{ClientID: "c-on", GateOn: true, Family: "webtunnel", OccurredAt: t0},
	}
	tu := []TrustUIObservation{
		{ClientID: "c1", Family: "vless", Badge: MaturityGA},
		{ClientID: "c1", Family: "transport_module", Badge: MaturityExperimental},
	}
	burns := []FamilyBurn{
		{Family: "vless", FirstPublishAt: t0, FirstBurnAt: t0.Add(72 * time.Hour),
			BurnInterval: 72 * time.Hour, Burned: true},
	}
	got := Verify("run-all-pass", 24*time.Hour, 48*time.Hour, pickups, acts, tu, burns, true)
	if !got.AllPass() {
		t.Fatalf("expected all-pass; got %+v", got)
	}
	if len(got.Failures) != 0 {
		t.Errorf("expected no failures; got %v", got.Failures)
	}
}

func TestVerify_FailuresAreSorted(t *testing.T) {
	// Stable sort eases diffing across runs. Force two failures
	// that would come out in non-sorted order without the sort.
	bad := []TrustUIObservation{
		{ClientID: "z", Family: "webtunnel", Badge: MaturityGA},
		{ClientID: "a", Family: "vless", Badge: MaturityExperimental},
	}
	got := Verify("run-sort", 24*time.Hour, 48*time.Hour, nil, nil, bad, nil, true)
	for i := 1; i < len(got.Failures); i++ {
		if got.Failures[i] < got.Failures[i-1] {
			t.Errorf("Failures not sorted: %v", got.Failures)
			break
		}
	}
}

func TestLockedFamilyMaturity(t *testing.T) {
	// Lock-down test: the V3 family-maturity table is locked at
	// 3-Soak and any change requires a roadmap amendment.
	want := map[string]Maturity{
		"vless":            MaturityGA,
		"hysteria2":        MaturityGA,
		"wireguard":        MaturityGA,
		"webtunnel":        MaturityExperimental,
		"snowflake":        MaturityExperimental,
		"masque":           MaturityExperimental,
		"psiphon":          MaturityExperimental,
		"conjure":          MaturityExperimental,
		"transport_module": MaturityExperimental,
	}
	if len(LockedFamilyMaturity) != len(want) {
		t.Fatalf("LockedFamilyMaturity size = %d, want %d", len(LockedFamilyMaturity), len(want))
	}
	for k, v := range want {
		if LockedFamilyMaturity[k] != v {
			t.Errorf("LockedFamilyMaturity[%q] = %s, want %s", k, LockedFamilyMaturity[k], v)
		}
	}
}
