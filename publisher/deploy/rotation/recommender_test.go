package rotation

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/phase"
	"daal/publisher/deploy/provider"
)

// currentPhase is what the recipient selector stamps on an Explanation
// today. The recommender never reads Explanation.Phase — it decides
// from Pick.ExposureMode, the failure classifications, and the record
// — so this is fixture furniture; it is spelled from the canonical
// constant rather than as a literal so tools/check-phase.sh stays able
// to assert that no phase literal exists outside its declaration.
var currentPhase = string(phase.Current)

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
		Phase: currentPhase,
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

// REPLACES TestFromExplanation_TCPResetNoFloatingIP_FallbackL4, which
// pinned behaviour that had become wrong and dangerous.
//
// That test asserted "no floating IP attached ⇒ recommend L4", i.e.
// destroy the server and rebuild it in another datacenter. It was
// written before the Hetzner adapter could RESERVE an address, when an
// empty FloatingIPID really did mean "L3 is impossible". Since then an
// empty id means "L3 will mint one" — and since no relay provisioned
// before that step has a floating IP, the old rule pointed every relay
// in the field at a rebuild for a problem a ten-second address swap
// fixes. Provisioning has no rollback, so being wrong in that direction
// can leave a second billing server behind.
//
// Whether L3 is possible is now asked of ActionForProvider, which
// weighs the adapter AND the relay's mgmt vintage.
func TestFromExplanation_TCPResetNoFloatingIP_StillL3(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "tcp_reset", Tag: "public_ip:198.51.100.10"},
		},
		Phase: currentPhase,
	}
	got := FromExplanation(exp, fakeRecord(false))
	if got.Level != L3 {
		t.Errorf("level = %s, want L3 (the adapter reserves an address; nothing needs rebuilding)", got.Level)
	}
	if got.Action.DestroysServer {
		t.Error("recommended action destroys the server for an address-level block")
	}
}

// The rebuild is still recommended when the address swap is KNOWN to be
// impossible — which is a property of the adapter, not of whether an
// address happens to be attached today. Stark attaches a reserved IP
// without moving the record onto it, so an L3 there would re-sign a
// pack aimed at the address being rotated away from. (Vultr was in this
// case until Wave 6 finished its adapter.)
func TestFromExplanation_TCPResetOnAdapterThatCannotSwap_FallsToL4(t *testing.T) {
	rec := fakeRecord(false)
	rec.Provider = "stark"
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "tcp_reset", Tag: "public_ip:198.51.100.10"},
		},
		Phase: currentPhase,
	}
	got := FromExplanation(exp, rec)
	if got.Level != L4 {
		t.Fatalf("level = %s, want L4 (this adapter cannot move the record onto a new address)", got.Level)
	}
	if !got.Action.DestroysServer {
		t.Error("L4 action does not report that it destroys the server")
	}
}

func TestFromExplanation_PublicASNCooldown_L4(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		ActiveCooldowns: []ExplCooldown{
			{Tag: "public_asn:24940", Reason: "tcp_reset"},
		},
		Phase: currentPhase,
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
		Phase: currentPhase,
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
		Phase: currentPhase,
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L5 {
		t.Errorf("level = %s, want L5", got.Level)
	}
	// L5 is quoted at L4's figure, not below it. It deletes a server
	// and builds another on a SECOND cloud with a cold account, so it
	// strictly contains L4's work; the old "~2min" made the bigger rung
	// look like the cheaper one on the panel that renders this verbatim.
	if got.EstWallClock != "~3min" {
		t.Errorf("wallclock = %s, want ~3min", got.EstWallClock)
	}
}

func TestFromExplanation_SNIRst_L2(t *testing.T) {
	exp := Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{Classification: "sni_rst", Tag: "sni:example.com"},
		},
		Phase: currentPhase,
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
		Phase: currentPhase,
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
		Phase:          currentPhase,
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
		Phase:          currentPhase,
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
		Phase: currentPhase,
	}
	got := FromExplanation(exp, fakeRecord(true))
	if got.Level != L6 {
		t.Errorf("level = %s, want L6 (two families burned)", got.Level)
	}
}

func TestFromExplanation_CDNFrontedAtV15_L3WithReason(t *testing.T) {
	exp := Explanation{
		Pick:  ExplPicked{ExposureMode: "cdn_fronted"},
		Phase: currentPhase,
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
		Phase: currentPhase,
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

// REPLACES TestFromContext_TCPResetCappedAtMedium, which pinned "a
// reset with no public_ip:* cooldown tag falls through to the L1
// default".
//
// The tag it waited for has no producer anywhere in the tree:
// selection.PropagateCooldown, the only thing that would attribute a
// cooldown to a shared risk tag, has no production caller, so
// Explanation.ActiveCooldowns is `[]` in every real blob. The rule was
// therefore unreachable from measured data, and the ladder's cheapest
// and most common rung could only be reached by an operator typing the
// tag in by hand.
//
// A reset is address-level evidence on its own. What the missing tag
// costs is the ATTRIBUTION, and that is paid in confidence and in a
// reason that says which half is missing — not by recommending a
// different rung.
func TestFromContext_TCPResetAloneReachesL3(t *testing.T) {
	ctx := RotationContext{
		FailureClassifications: []string{"tcp_reset"},
		ExposureMode:           "direct_vps",
		OperatorRecord:         fakeRecord(true),
	}
	got := FromContext(ctx)
	if got.Level != L3 {
		t.Errorf("level = %s, want L3", got.Level)
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium", got.Confidence)
	}
	if !got.Grounded {
		t.Error("grounded = false; a recorded reset IS evidence")
	}
	if !strings.Contains(got.Reason, "no address-level attribution") {
		t.Errorf("reason does not say the attribution is missing: %q", got.Reason)
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
		L5: "~3min",
		L6: "~3min",
	}
	if !reflect.DeepEqual(estWallClockV15, want) {
		t.Errorf("V1.5 wallclock table drift: %+v", estWallClockV15)
	}
}

// A rung must never be quoted as cheaper than a rung whose work it
// strictly contains. L5 deletes a server and builds another — L4's
// whole job — and additionally does the build on a different cloud
// against a cold account. The table said "~2min" for L5 and "~3min"
// for L4, so the panel that renders these verbatim offered the larger
// outage as the shorter one.
//
// Compared as parsed durations rather than strings: the point is the
// ordering, and a future table that writes "180s" must not pass by
// being textually different.
func TestDestroyingRungsAreNotQuotedBelowTheRungTheyContain(t *testing.T) {
	// The table writes "min" where Go's duration grammar wants "m";
	// normalise rather than change the table, because the strings are
	// rendered to operators and "~3m" reads as a typo.
	parse := func(t *testing.T, s string) time.Duration {
		t.Helper()
		norm := strings.Replace(strings.TrimPrefix(s, "~"), "min", "m", 1)
		d, err := time.ParseDuration(norm)
		if err != nil {
			t.Fatalf("wallclock %q is not a parseable duration: %v", s, err)
		}
		return d
	}
	l4 := parse(t, estWallClockV15[L4])
	l5 := parse(t, estWallClockV15[L5])
	if l5 < l4 {
		t.Errorf("L5 (%s) is quoted below L4 (%s), but L5 does L4's work on a second cloud",
			estWallClockV15[L5], estWallClockV15[L4])
	}
	// And every destroying rung must be quoted above every in-place
	// one: the cheapest thing a rebuild can do is still a rebuild.
	for _, inPlace := range []Level{L1, L2, L3} {
		ip := parse(t, estWallClockV15[inPlace])
		for _, d := range []Level{L4, L5, L6} {
			if parse(t, estWallClockV15[d]) < ip {
				t.Errorf("%s (destroys the relay, %s) is quoted below in-place %s (%s)",
					d, estWallClockV15[d], inPlace, estWallClockV15[inPlace])
			}
		}
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
		Phase: currentPhase,
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
