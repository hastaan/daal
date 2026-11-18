package rotation

import (
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// Wave 6. The recommender existed, had no caller, and — because its
// three Explanation inputs had no producer — answered "L1, confidence
// low" on every real run. Two of those three still have no producer,
// which is the point of these tests: the fix is not to make the answer
// louder, it is to make the silence legible.

// A fresh relay has nothing recorded against it. The honest answer is
// "there is no evidence", NOT a rung.
func TestFreshRelay_IsUngroundedNotAConfidentL1(t *testing.T) {
	got := FromExplanation(Explanation{
		Pick:  ExplPicked{ExposureMode: "direct_vps"},
		Phase: currentPhase,
	}, fakeRecord(false))

	if got.Grounded {
		t.Fatal("grounded = true with nothing recorded")
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("confidence = %s, want low", got.Confidence)
	}
	if !strings.Contains(got.Reason, "Nothing has been recorded about this relay yet") {
		t.Errorf("reason does not name the absence: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "not a recommendation") {
		t.Errorf("reason reads as advice rather than a refusal: %q", got.Reason)
	}
	if len(got.Evidence.Absent) == 0 {
		t.Error("no named absences on a recommendation made from nothing")
	}
}

// The worse silence: inputs ARE present, and none of them is something
// the ladder fixes. Before this pass that returned L1 at HIGH
// confidence off the Explanation path, because confidenceFor asked only
// "was any input non-empty".
func TestUnrecognisedFailure_IsUngroundedAndLow(t *testing.T) {
	got := FromExplanation(Explanation{
		Pick: ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{
			{RouteID: "r-1", Classification: "route_expired"},
		},
		Phase: currentPhase,
	}, fakeRecord(true))

	if got.Grounded {
		t.Fatal("grounded = true for a failure no rung addresses")
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("confidence = %s, want low", got.Confidence)
	}
	if !strings.Contains(got.Reason, "route_expired") {
		t.Errorf("reason does not name what was seen: %q", got.Reason)
	}
	found := false
	for _, u := range got.Evidence.Unrecognised {
		if u == "classification route_expired" {
			found = true
		}
	}
	if !found {
		t.Errorf("unrecognised = %v, want the route_expired entry", got.Evidence.Unrecognised)
	}
}

// A recorded failure category picks the matching rung. These are the
// categories core/diagnostics actually stamps on a route row, which is
// what now reaches here through Explanation.Failures.
func TestRecordedCategoryPicksTheMatchingRung(t *testing.T) {
	cases := []struct {
		category string
		want     Level
	}{
		{"tcp_reset", L3},
		{"tcp_connect_timeout", L3},
		{"tls_sni_or_cert_block_suspected", L2},
		{"sni_rst", L2},
	}
	for _, tc := range cases {
		t.Run(tc.category, func(t *testing.T) {
			got := FromExplanation(Explanation{
				Pick:     ExplPicked{ExposureMode: "direct_vps"},
				Failures: []ExplFailure{{RouteID: "r-1", Classification: tc.category}},
				Phase:    currentPhase,
			}, fakeRecord(true))
			if got.Level != tc.want {
				t.Fatalf("level = %s, want %s", got.Level, tc.want)
			}
			if !got.Grounded {
				t.Error("grounded = false for a recognised category")
			}
		})
	}
}

// udp_collapsed is one of the five signals that DO have a producer, and
// it is the only measured input that reaches a destroy-and-rebuild rung.
// It is recommended — and capped at medium, because "one route on one
// device saw UDP fail" is not "this network has no UDP, rebuild the
// relay".
func TestMeasuredUDPCollapse_RecommendsL6AtMedium(t *testing.T) {
	got := FromExplanation(Explanation{
		Pick:           ExplPicked{ExposureMode: "direct_vps"},
		NetworkSignals: []string{"udp_collapsed"},
		Phase:          currentPhase,
	}, fakeRecord(true))

	if got.Level != L6 {
		t.Fatalf("level = %s, want L6", got.Level)
	}
	if !got.Grounded {
		t.Error("grounded = false for a measured signal")
	}
	if got.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %s, want medium — a destroy on one route's evidence", got.Confidence)
	}
}

// THE REFUSAL. The four probe-derived signals have no prober, and the
// recommendation must say they were unmeasured rather than let their
// absence read as "checked, and fine". Nothing may turn an absent
// signal into a present one.
func TestProbeDerivedSignalsAreReportedAbsentNeverPresent(t *testing.T) {
	got := FromExplanation(Explanation{
		Pick:           ExplPicked{ExposureMode: "direct_vps"},
		NetworkSignals: []string{"udp_collapsed"},
		Phase:          currentPhase,
	}, fakeRecord(true))

	for _, s := range got.Evidence.Signals {
		for _, probe := range probeDerivedSignals {
			if s == probe {
				t.Fatalf("signal %s was reported present; no prober produces it", s)
			}
		}
	}
	joined := strings.Join(got.Evidence.Absent, "\n")
	for _, probe := range probeDerivedSignals {
		if !strings.Contains(joined, probe) {
			t.Errorf("absent list does not name %s", probe)
		}
	}
	if !strings.Contains(joined, "UNMEASURED") {
		t.Errorf("absent list does not distinguish unmeasured from measured-negative: %q", joined)
	}
}

// The cooldown-tag vocabulary has no producer either, so a rung that
// needs one must never fire off measured data — and the recommendation
// must say the absence is not a clean bill of health for the ASN.
func TestCooldownTagAbsenceIsNamed(t *testing.T) {
	got := FromExplanation(Explanation{
		Pick:     ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{{RouteID: "r-1", Classification: "tcp_reset"}},
		Phase:    currentPhase,
	}, fakeRecord(true))

	joined := strings.Join(got.Evidence.Absent, "\n")
	if !strings.Contains(joined, "no producer") {
		t.Errorf("absent list does not say the cooldown tags have no producer: %q", joined)
	}
	if !strings.Contains(joined, "not evidence") {
		t.Errorf("absent list lets a missing ASN cooldown read as 'the ASN is fine': %q", joined)
	}
}

// recommender.go's honesty rule — never quote the in-place figure for a
// relay that can only get there by destroy-and-rebuild — has to survive
// to the string a screen renders, or it protects nothing.
func TestDestroysServerWallClockOverrideSurvivesToTheString(t *testing.T) {
	// Probed, and the relay is too old for the in-place verb.
	caps := RelayCapabilities{Known: true}
	got := FromExplanationWithCapabilities(Explanation{
		Pick:     ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{{RouteID: "r-1", Classification: "tls_sni_or_cert_block_suspected"}},
		Phase:    currentPhase,
	}, fakeRecord(true), caps)

	if got.Level != L2 {
		t.Fatalf("level = %s, want L2", got.Level)
	}
	if !got.Action.DestroysServer {
		t.Fatal("precondition: an unprobed-capable relay should degrade to reprovision")
	}
	if strings.Contains(got.EstWallClock, "90s") {
		t.Errorf("est_wallclock quotes the in-place figure for a rebuild: %q", got.EstWallClock)
	}
	if !strings.Contains(got.EstWallClock, "reprovision fallback") {
		t.Errorf("est_wallclock = %q, want the reprovision-fallback override", got.EstWallClock)
	}
	// And the same string is what WallClockFor gives a renderer, so a
	// UI cannot get the optimistic number by asking again.
	if WallClockFor(got.Level, got.Action) != got.EstWallClock {
		t.Error("WallClockFor disagrees with the recommendation it came from")
	}
}

// A rung that is known-unsupported with no rebuild attached must not
// carry a duration at all: an L3 on an adapter that would leave every
// pack pointing at the burned address is going to refuse.
func TestUnsupportedRungHasNoDuration(t *testing.T) {
	rec := fakeRecord(true)
	rec.Provider = "stark"
	got := WallClockFor(L3, ActionForProvider(L3, RelayCapabilities{Known: true, BindAddress: true}, rec.Provider))
	if strings.Contains(got, "10s") {
		t.Errorf("est_wallclock = %q for a rung that will refuse", got)
	}
	if got != "not available on this relay" {
		t.Errorf("est_wallclock = %q, want the unavailable string", got)
	}
}

// Evidence.Source is the confidence ceiling, and it has to reach the
// screen: "the operator typed this" and "the recipient's selector
// recorded this" are not the same claim.
func TestEvidenceNamesItsSource(t *testing.T) {
	fromCtx := FromContext(RotationContext{
		FailureClassifications: []string{"tcp_reset"},
		OperatorRecord:         fakeRecord(true),
	})
	if fromCtx.Evidence.Source != "context" {
		t.Errorf("source = %q, want context", fromCtx.Evidence.Source)
	}
	if !strings.Contains(strings.Join(fromCtx.Evidence.Absent, "\n"), "cannot exceed medium") {
		t.Error("context-sourced advice does not say why its confidence is capped")
	}

	fromExp := FromExplanation(Explanation{
		Pick:     ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{{RouteID: "r-1", Classification: "tcp_reset"}},
		Phase:    currentPhase,
	}, fakeRecord(true))
	if fromExp.Evidence.Source != "explanation" {
		t.Errorf("source = %q, want explanation", fromExp.Evidence.Source)
	}
}

// AbsentCodes must stay in lockstep with Absent: same length, same
// order, and every code drawn from the closed vocabulary.
//
// The panel renders a translated sentence per code and falls back to
// the English prose when a catalog does not carry one. If the two
// slices can drift, the fallback pairs a code with the wrong sentence —
// which on this screen means telling an operator that something was
// measured and clean when it was never measured at all.
func TestAbsentCodesParallelAbsentProse(t *testing.T) {
	known := map[string]bool{
		AbsentNoFailures:         true,
		AbsentNoCooldownProducer: true,
		AbsentNoProber:           true,
		AbsentOperatorSupplied:   true,
	}
	for _, tc := range []struct {
		name string
		exp  Explanation
	}{
		{"empty", Explanation{Phase: currentPhase}},
		{"one failure", Explanation{
			Phase:    currentPhase,
			Pick:     ExplPicked{ExposureMode: "direct_vps"},
			Failures: []ExplFailure{{Classification: "tcp_reset"}},
		}},
		{"a real signal", Explanation{
			Phase:          currentPhase,
			Pick:           ExplPicked{ExposureMode: "direct_vps"},
			NetworkSignals: []string{"udp_collapsed"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FromExplanation(tc.exp, fakeRecord(true))
			ev := got.Evidence
			if len(ev.Absent) != len(ev.AbsentCodes) {
				t.Fatalf("Absent has %d entries and AbsentCodes %d — a renderer pairing them by index "+
					"would attach the wrong sentence to a code:\n  prose=%q\n  codes=%q",
					len(ev.Absent), len(ev.AbsentCodes), ev.Absent, ev.AbsentCodes)
			}
			for _, c := range ev.AbsentCodes {
				if !known[c] {
					t.Errorf("AbsentCodes contains %q, which is not in the closed vocabulary — the UI "+
						"cannot key it and it must be added to both the constants and the catalogs", c)
				}
			}
		})
	}
}

// Every arm of recommend() must name itself with a ReasonCode from the
// closed vocabulary, and the vocabulary must be fully reachable.
//
// Reason is the most decisive sentence the advice panel renders — it is
// the whole substance of the answer, and three of the six rungs it can
// point at DESTROY the relay. It is built here in English, so the panel
// keys ReasonCode to render it in the operator's own language and falls
// back to the prose when a catalog does not carry the code yet.
//
// The exhaustiveness half is the half that will actually catch
// something: a rule added without a code still compiles, still returns
// prose, and silently drops every Farsi reader back to English on the
// one sentence they most need. The table below has to grow with the
// ladder, and this test is what makes that non-optional.
func TestEveryReasonIsNamedByACodeFromTheClosedVocabulary(t *testing.T) {
	known := map[string]bool{
		ReasonCredentialLeakSuspected:    true,
		ReasonNoCDNCandidates:            true,
		ReasonProviderSuspended:          true,
		ReasonUDPCollapsed:               true,
		ReasonProtocolFamiliesBurned:     true,
		ReasonSharedRiskCooldown:         true,
		ReasonAddressResetAttributed:     true,
		ReasonAddressResetUnattributed:   true,
		ReasonAddressTimeoutAttributed:   true,
		ReasonAddressTimeoutUnattributed: true,
		ReasonAddressBlockNoSwap:         true,
		ReasonSNIBlock:                   true,
		ReasonCredentialLeakObserved:     true,
		ReasonNoEvidenceAtAll:            true,
		ReasonNothingMatchedLadder:       true,
	}

	// A relay whose provider adapter is known NOT to move the record
	// onto the new address, so L3 is refused and rule 7 falls to the
	// rebuild arm. See action.go's "stark" case.
	noSwapRecord := func() *provider.OperatorRecord {
		rec := fakeRecord(true)
		rec.Provider = "stark"
		return rec
	}

	direct := ExplPicked{ExposureMode: "direct_vps"}
	seen := map[string]bool{}

	for _, tc := range []struct {
		name string
		got  RotationRecommendation
		want string
	}{
		{"operator-asserted leak", FromContext(RotationContext{
			CredentialLeakSuspected: true,
			OperatorRecord:          fakeRecord(true),
		}), ReasonCredentialLeakSuspected},

		{"cdn_fronted at V1.5", FromExplanation(Explanation{
			Pick: ExplPicked{ExposureMode: "cdn_fronted"}, Phase: currentPhase,
		}, fakeRecord(true)), ReasonNoCDNCandidates},

		{"provider suspended", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "provider_suspended"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonProviderSuspended},

		{"udp collapsed", FromExplanation(Explanation{
			Pick: direct, NetworkSignals: []string{"udp_collapsed"}, Phase: currentPhase,
		}, fakeRecord(true)), ReasonUDPCollapsed},

		{"protocol families burned", FromExplanation(Explanation{
			Pick: direct, NetworkSignals: []string{"protocol_whitelist_mode"}, Phase: currentPhase,
		}, fakeRecord(true)), ReasonProtocolFamiliesBurned},

		{"asn-level cooldown", FromExplanation(Explanation{
			Pick:            direct,
			ActiveCooldowns: []ExplCooldown{{Tag: "public_asn:24940"}},
			Phase:           currentPhase,
		}, fakeRecord(true)), ReasonSharedRiskCooldown},

		{"reset, attributed", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "tcp_reset", Tag: "public_ip:198.51.100.10"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonAddressResetAttributed},

		{"reset, unattributed", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "tcp_reset"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonAddressResetUnattributed},

		{"timeout, attributed", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "tcp_connect_timeout", Tag: "public_ip:198.51.100.10"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonAddressTimeoutAttributed},

		{"timeout, unattributed", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "tcp_connect_timeout"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonAddressTimeoutUnattributed},

		{"blocked address this relay cannot swap", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "tcp_reset"}},
			Phase:    currentPhase,
		}, noSwapRecord()), ReasonAddressBlockNoSwap},

		{"sni block", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "tls_sni_or_cert_block_suspected"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonSNIBlock},

		{"observed credential leak", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "credential_leak"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonCredentialLeakObserved},

		{"nothing recorded at all", FromExplanation(Explanation{
			Pick: direct, Phase: currentPhase,
		}, fakeRecord(true)), ReasonNoEvidenceAtAll},

		{"recorded, but no rung addresses it", FromExplanation(Explanation{
			Pick:     direct,
			Failures: []ExplFailure{{Classification: "route_expired"}},
			Phase:    currentPhase,
		}, fakeRecord(true)), ReasonNothingMatchedLadder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.ReasonCode != tc.want {
				t.Fatalf("ReasonCode = %q, want %q (reason was %q)",
					tc.got.ReasonCode, tc.want, tc.got.Reason)
			}
			if !known[tc.got.ReasonCode] {
				t.Fatalf("ReasonCode %q is outside the closed vocabulary — the UI cannot key it",
					tc.got.ReasonCode)
			}
			if tc.got.Reason == "" {
				t.Error("no English prose behind the code; a catalog miss would render nothing")
			}
			seen[tc.got.ReasonCode] = true
		})
	}

	for code := range known {
		if !seen[code] {
			t.Errorf("ReasonCode %q is declared but no case above reaches it — either the rule "+
				"is dead or this table is stale; both hide an untranslatable sentence", code)
		}
	}
}

// The two codes that interpolate machine text must actually carry it,
// and the ones that do not must stay empty.
//
// A catalog string for these reads "…cannot swap its address ({detail})".
// If ReasonDetail were empty the Farsi reader would get an empty
// parenthesis where the concrete blocker should be — which is the
// difference between "this relay's software is too old" and no
// explanation at all.
func TestReasonDetailCarriesTheInterpolatedFragment(t *testing.T) {
	noSwap := fakeRecord(true)
	noSwap.Provider = "stark"
	got := FromExplanation(Explanation{
		Pick:     ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{{Classification: "tcp_reset"}},
		Phase:    currentPhase,
	}, noSwap)
	if got.ReasonCode != ReasonAddressBlockNoSwap {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, ReasonAddressBlockNoSwap)
	}
	if got.ReasonDetail == "" {
		t.Error("no blocker in ReasonDetail; a translated sentence would name no cause")
	}
	if !strings.Contains(got.Reason, got.ReasonDetail) {
		t.Errorf("ReasonDetail %q is not the fragment the English prose interpolates (%q) — the "+
			"two renderings would disagree", got.ReasonDetail, got.Reason)
	}

	unmatched := FromExplanation(Explanation{
		Pick:     ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{{Classification: "route_expired"}},
		Phase:    currentPhase,
	}, fakeRecord(true))
	if !strings.Contains(unmatched.ReasonDetail, "route_expired") {
		t.Errorf("ReasonDetail = %q, want it to name what was recorded", unmatched.ReasonDetail)
	}

	plain := FromExplanation(Explanation{
		Pick:     ExplPicked{ExposureMode: "direct_vps"},
		Failures: []ExplFailure{{Classification: "tcp_reset"}},
		Phase:    currentPhase,
	}, fakeRecord(true))
	if plain.ReasonDetail != "" {
		t.Errorf("ReasonDetail = %q on a code that interpolates nothing; a catalog string with no "+
			"{detail} would silently drop it", plain.ReasonDetail)
	}
}
