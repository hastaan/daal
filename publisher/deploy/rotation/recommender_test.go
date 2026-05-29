package rotation

import (
	"net"
	"reflect"
	"testing"

	"daal/publisher/deploy/provider"
)

// fakeRecord returns an OperatorRecord that a unit test can mutate.
// Default has FloatingIPID set so L3 is reachable.
func fakeRecord(withFloatingIP bool) *provider.OperatorRecord {
	rec := &provider.OperatorRecord{
		Provider:   "hetzner",
		ServerID:   "test-1",
		ServerType: "cpx21",
		Region:     "fsn1",
		PublicIP:   net.ParseIP("198.51.100.10"),
	}
	if withFloatingIP {
		rec.FloatingIPID = "fip-1"
	}
	return rec
}

// --- FromExplanation cases ------------------------------------------

func TestFromExplanation_TCPResetWithPublicIP_FastPathL3(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{RouteID: "vless-1", Classification: "tcp_reset", Tag: "public_ip:198.51.100.10"},
		},
		ActiveCooldowns: []ExplCooldown{
			{Tag: "public_ip:198.51.100.10", Reason: "tcp_reset"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L3 {
		t.Errorf("level = %s, want L3", got.Level)
	}
	if got.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %s, want high", got.Confidence)
	}
	if got.EstWallClock != "~10s" {
		t.Errorf("wallclock = %s, want ~10s", got.EstWallClock)
	}
}

func TestFromExplanation_TCPResetNoFloatingIP_FallbackL4(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "tcp_reset", Tag: "public_ip:198.51.100.10"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(false))
	if got.Level != L4 {
		t.Errorf("level = %s, want L4 (no floating IP attached)", got.Level)
	}
	if got.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %s, want high", got.Confidence)
	}
}

func TestFromExplanation_PublicASNCooldown_L4(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		ActiveCooldowns: []ExplCooldown{
			{Tag: "public_asn:24940", Reason: "tcp_reset"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L4 {
		t.Errorf("level = %s, want L4", got.Level)
	}
	if got.EstWallClock != "~3min" {
		t.Errorf("wallclock = %s, want ~3min", got.EstWallClock)
	}
}

func TestFromExplanation_PublicProviderCooldown_L4(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		ActiveCooldowns: []ExplCooldown{
			{Tag: "public_provider:hetzner", Reason: "origin_unhealthy"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L4 {
		t.Errorf("level = %s, want L4", got.Level)
	}
}

func TestFromExplanation_ProviderSuspended_L5(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "provider_suspended"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L5 {
		t.Errorf("level = %s, want L5", got.Level)
	}
	if got.EstWallClock != "~2min" {
		t.Errorf("wallclock = %s, want ~2min", got.EstWallClock)
	}
}

func TestFromExplanation_SNIRst_L2(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "sni_rst", Tag: "sni:example.com"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L2 {
		t.Errorf("level = %s, want L2", got.Level)
	}
	if got.EstWallClock != "~90s" {
		t.Errorf("wallclock = %s, want ~90s", got.EstWallClock)
	}
}

func TestFromExplanation_CredentialLeak_L1Medium(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "credential_leak"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L1 {
		t.Errorf("level = %s, want L1", got.Level)
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium (credential_leak is intrinsically medium)", got.Confidence)
	}
}

func TestFromExplanation_UDPCollapsed_L6(t *testing.T) {
	exp := Explanation{
		Pick:           ExplPicked{ExposureMode: "direct_vps"},
		NetworkSignals: []string{"udp_collapsed"},
		Phase:          "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L6 {
		t.Errorf("level = %s, want L6", got.Level)
	}
}

func TestFromExplanation_ProtocolWhitelistMode_L6(t *testing.T) {
	exp := Explanation{
		Pick:           ExplPicked{ExposureMode: "direct_vps"},
		NetworkSignals: []string{"protocol_whitelist_mode"},
		Phase:          "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L6 {
		t.Errorf("level = %s, want L6", got.Level)
	}
}

func TestFromExplanation_TwoFamilyClassesBurned_L6(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		ActiveCooldowns: []ExplCooldown{
			{Tag: "family:vless-reality"},
			{Tag: "family:hysteria2"},
		},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L6 {
		t.Errorf("level = %s, want L6 (two families burned)", got.Level)
	}
}

func TestFromExplanation_CDNFrontedAtV15_L3WithReason(t *testing.T) {
	exp := Explanation{
		Pick:  ExplPicked{ExposureMode: "cdn_fronted"},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L3 {
		t.Errorf("level = %s, want L3 (V1.5 has no cdn_fronted candidates)", got.Level)
	}
	if !contains(got.Reason, "no cdn_fronted candidates") {
		t.Errorf("reason missing the no-cdn note: %s", got.Reason)
	}
}

func TestFromExplanation_EmptyExplanation_LowConfidenceL1(t *testing.T) {
	exp := Explanation{
		Pick:  ExplPicked{ExposureMode: "direct_vps"},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L1 {
		t.Errorf("level = %s, want L1 (default)", got.Level)
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("confidence = %s, want low", got.Confidence)
	}
}

// --- FromContext cases ----------------------------------------------

func TestFromContext_OperatorAssertedCredentialLeak_L1Medium(t *testing.T) {
	ctx := RotationContext{
		ExposureMode:            "direct_vps",
		OperatorRecord:          fakeRecord(true),
		CredentialLeakSuspected: true,
	}
	got := FromContext(ctx)
	if got.Level != L1 {
		t.Errorf("level = %s, want L1", got.Level)
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium (context-source cap)", got.Confidence)
	}
}

func TestFromContext_TCPResetCappedAtMedium(t *testing.T) {
	ctx := RotationContext{
		FailureClassifications: []string{"tcp_reset"},
		ExposureMode:           "direct_vps",
		OperatorRecord:         fakeRecord(true),
	}
	// Without an active cooldown tag, the recommender doesn't have
	// enough to call L3 — it falls through to L1 default.
	got := FromContext(ctx)
	if got.Level != L1 {
		t.Errorf("level = %s, want L1 (tcp_reset alone with no public_ip:* cooldown)", got.Level)
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium", got.Confidence)
	}
}

func TestFromContext_SNIRstCappedAtMedium(t *testing.T) {
	ctx := RotationContext{
		FailureClassifications: []string{"sni_rst"},
		ExposureMode:           "direct_vps",
		OperatorRecord:         fakeRecord(true),
	}
	got := FromContext(ctx)
	if got.Level != L2 {
		t.Errorf("level = %s, want L2", got.Level)
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium (context cap)", got.Confidence)
	}
}

func TestFromContext_UDPCollapsed_L6Medium(t *testing.T) {
	ctx := RotationContext{
		NetworkSignals: []string{"udp_collapsed"},
		ExposureMode:   "direct_vps",
		OperatorRecord: fakeRecord(true),
	}
	got := FromContext(ctx)
	if got.Level != L6 {
		t.Errorf("level = %s, want L6", got.Level)
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium", got.Confidence)
	}
}

func TestFromContext_EmptyContext_LowConfidenceL1(t *testing.T) {
	ctx := RotationContext{
		ExposureMode:   "direct_vps",
		OperatorRecord: fakeRecord(true),
	}
	got := FromContext(ctx)
	if got.Level != L1 {
		t.Errorf("level = %s, want L1", got.Level)
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("confidence = %s, want low", got.Confidence)
	}
}

func TestFromContext_DefaultExposureMode(t *testing.T) {
	// ExposureMode unset ⇒ recommender defaults to direct_vps.
	ctx := RotationContext{
		FailureClassifications: []string{"sni_rst"},
		OperatorRecord:         fakeRecord(true),
	}
	got := FromContext(ctx)
	if got.Level != L2 {
		t.Errorf("level = %s, want L2 (default exposure_mode)", got.Level)
	}
}

// --- Wallclock pin --------------------------------------------------

func TestEstWallClockV15Pinned(t *testing.T) {
	want := map[Level]string{
		L1: "~90s",
		L2: "~90s",
		L3: "~10s",
		L4: "~3min",
		L5: "~2min",
		L6: "~3min",
	}
	if !reflect.DeepEqual(estWallClockV15, want) {
		t.Errorf("V1.5 wallclock table drift: %+v", estWallClockV15)
	}
}

// --- AllLevels + SortedLevels --------------------------------------

func TestAllLevelsCanonicalOrder(t *testing.T) {
	got := AllLevels()
	want := []Level{L1, L2, L3, L4, L5, L6}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllLevels = %v, want %v", got, want)
	}
}

func TestSortedLevelsStable(t *testing.T) {
	got := SortedLevels([]Level{L4, L1, L3, L2})
	want := []Level{L1, L2, L3, L4}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SortedLevels = %v, want %v", got, want)
	}
}

// --- Override list dedupe ------------------------------------------

func TestOverrideListsAreDeduped(t *testing.T) {
	exp := Explanation{
		Pick:  ExplPicked{ExposureMode: "direct_vps"},
		Phase: "V1.5",
	}
	got := FromExplanation(exp, fakeRecord(true))
	seen := map[Level]bool{}
	for _, l := range got.Override {
		if seen[l] {
			t.Errorf("override list has duplicate: %s", l)
		}
		seen[l] = true
	}
}

// --- helper ---------------------------------------------------------

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) &&
		(haystack == needle ||
			indexOf(haystack, needle) >= 0))
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
