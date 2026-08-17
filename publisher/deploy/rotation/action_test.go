package rotation

import (
	"encoding/json"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// Before Step 7 the recommender's two cheapest rungs were advice with
// no machine behind them: the only way to execute L1 or L2 was
// `reprovision`, which deletes the server. These tests pin that L1 and
// L2 now name the in-place verbs — and, just as importantly, that they
// stop naming them on a relay that cannot run them.

func TestActionFor_L1IsTheTargetedPerRecipientRevocation(t *testing.T) {
	a := ActionFor(L1, RelayCapabilities{Known: true, RotateCredentialsInPlace: true})
	if a.Kind != ActionRotateCredentials || a.CLIVerb != "rotate-credentials" {
		t.Fatalf("L1 action = %+v", a)
	}
	if !a.InPlace || a.DestroysServer {
		t.Errorf("L1 must not destroy the server: %+v", a)
	}
	if a.Scope != "recipient" || !a.NeedsRecipientName {
		t.Errorf("L1 must be scoped to one named recipient: %+v", a)
	}
	// The whole point of splitting the endpoint: revoking one recipient
	// must not strand everybody else's pack.
	if a.InvalidatesEveryPack {
		t.Errorf("a targeted revocation must not invalidate every pack: %+v", a)
	}
	if a.Availability != AvailabilityReady {
		t.Errorf("availability = %q", a.Availability)
	}
}

func TestActionFor_L2IsRelayWideAndAdmitsItStrandsPacks(t *testing.T) {
	a := ActionFor(L2, RelayCapabilities{Known: true, RotateTLSInPlace: true})
	if a.Kind != ActionRotateTLS || a.CLIVerb != "rotate-tls" {
		t.Fatalf("L2 action = %+v", a)
	}
	if a.Scope != "relay" || a.NeedsRecipientName {
		t.Errorf("L2 is relay-wide, not per-recipient: %+v", a)
	}
	if !a.InPlace || a.DestroysServer {
		t.Errorf("L2 must not destroy the server: %+v", a)
	}
	// The cover host is pinned in every distributed pack. Moving it on
	// the box strands all of them until each is re-minted, and the UI
	// must be able to say so before the operator taps.
	if !a.InvalidatesEveryPack {
		t.Errorf("L2 must declare that every pack needs re-minting: %+v", a)
	}
}

// Not probed is not "probably fine". The recommender is offline and
// cannot see the relay's vintage, so it must say unknown.
func TestActionFor_UnprobedRelayIsUnknownNotReady(t *testing.T) {
	for _, l := range []Level{L1, L2} {
		a := ActionFor(l, RelayCapabilities{})
		if a.Availability != AvailabilityUnknown {
			t.Errorf("%s availability = %q, want unknown", l, a.Availability)
		}
		if a.DestroysServer {
			t.Errorf("%s: unprobed must not pre-emptively fall back to a rebuild: %+v", l, a)
		}
		if !strings.Contains(a.Note, "probed") {
			t.Errorf("%s: note does not tell the caller to probe: %q", l, a.Note)
		}
	}
}

// A relay whose pinned mgmt artifact predates the split degrades to the
// only route that still works, labelled honestly.
func TestActionFor_KnownIncapableRelayDegradesToReprovision(t *testing.T) {
	caps := RelayCapabilities{Known: true} // probed; supports neither
	for _, l := range []Level{L1, L2} {
		a := ActionFor(l, caps)
		if a.Kind != ActionReprovision {
			t.Errorf("%s: kind = %q, want reprovision fallback", l, a.Kind)
		}
		if a.Availability != AvailabilityUnsupported {
			t.Errorf("%s: availability = %q", l, a.Availability)
		}
		if !a.DestroysServer || a.InPlace {
			t.Errorf("%s: fallback must admit it rebuilds the box: %+v", l, a)
		}
		if !strings.Contains(a.Note, "re-release") {
			t.Errorf("%s: note gives the operator no remedy: %q", l, a.Note)
		}
	}
}

// Per-capability, not all-or-nothing: a box that can rotate credentials
// but not TLS must offer exactly the one it can do.
func TestActionFor_CapabilitiesAreIndependent(t *testing.T) {
	caps := RelayCapabilities{Known: true, RotateCredentialsInPlace: true}
	if got := ActionFor(L1, caps); got.Kind != ActionRotateCredentials {
		t.Errorf("L1 = %q, want the in-place verb", got.Kind)
	}
	if got := ActionFor(L2, caps); got.Kind != ActionReprovision {
		t.Errorf("L2 = %q, want the fallback", got.Kind)
	}
}

func TestActionFor_HeavyRungsAreUnchanged(t *testing.T) {
	a := ActionFor(L3, RelayCapabilities{})
	if a.Kind != ActionFloatingIPSwap || a.DestroysServer {
		t.Errorf("L3 = %+v", a)
	}
	// L3 must not claim to be ready while it rotates nothing:
	// AssignFloatingIP updates rec.FloatingIPID only, so the dialled
	// address and the candidate tags still name the burned IP. A
	// consumer reading availability:"ready" would offer the cheapest
	// rung as a working one-tap action.
	if a.Availability == AvailabilityReady {
		t.Error(`L3 is stamped "ready" while the swap does not move rec.PublicIP or the public_ip:* candidate tags`)
	}
	if a.Note == "" {
		t.Error("L3 carries no note saying what is missing")
	}
	for _, l := range []Level{L4, L5, L6} {
		a := ActionFor(l, RelayCapabilities{Known: true, RotateCredentialsInPlace: true, RotateTLSInPlace: true})
		if a.Kind != ActionReprovision || !a.DestroysServer {
			t.Errorf("%s = %+v, want a destroying reprovision regardless of capabilities", l, a)
		}
	}
}

// --- the recommendation carries the action ---

func TestRecommendation_CarriesAReachableActionForCredentialLeak(t *testing.T) {
	rec := FromContext(RotationContext{
		CredentialLeakSuspected: true,
		RelayCapabilities:       RelayCapabilities{Known: true, RotateCredentialsInPlace: true},
	})
	if rec.Level != L1 {
		t.Fatalf("level = %s", rec.Level)
	}
	if rec.Action.CLIVerb != "rotate-credentials" {
		t.Errorf("recommender named a rung with no runnable verb: %+v", rec.Action)
	}
	if rec.EstWallClock != "~90s" {
		t.Errorf("in-place wall clock = %q", rec.EstWallClock)
	}
}

// The dial must not lie. ~90s is the in-place figure; on a relay that
// can only be rebuilt, quoting it is the class of false instrumentation
// this project spent a step removing.
func TestRecommendation_WallClockFollowsTheFallback(t *testing.T) {
	rec := FromContext(RotationContext{
		FailureClassifications: []string{"sni_rst"},
		RelayCapabilities:      RelayCapabilities{Known: true},
	})
	if rec.Level != L2 {
		t.Fatalf("level = %s", rec.Level)
	}
	if rec.EstWallClock == "~90s" {
		t.Errorf("quoted the in-place wall clock for a destroy-and-rebuild: %q", rec.EstWallClock)
	}
	if !strings.Contains(rec.EstWallClock, estWallClockV15[L4]) {
		t.Errorf("wall clock %q does not reflect the reprovision cost", rec.EstWallClock)
	}
}

// FromExplanation keeps its signature and its meaning: a caller that
// has not been taught about capabilities gets "unknown", never a false
// "ready".
func TestFromExplanation_DefaultsToUnprobed(t *testing.T) {
	got := FromExplanation(Explanation{
		Failures: []ExplFailure{{Classification: "credential_leak"}},
	}, &provider.OperatorRecord{ServerID: "1", Region: "fsn1"})
	if got.Action.Availability != AvailabilityUnknown {
		t.Errorf("availability = %q, want unknown", got.Action.Availability)
	}
	withCaps := FromExplanationWithCapabilities(Explanation{
		Failures: []ExplFailure{{Classification: "credential_leak"}},
	}, &provider.OperatorRecord{ServerID: "1", Region: "fsn1"},
		RelayCapabilities{Known: true, RotateCredentialsInPlace: true})
	if withCaps.Action.Availability != AvailabilityReady {
		t.Errorf("availability = %q, want ready", withCaps.Action.Availability)
	}
	// Only the action changes; the ladder decision itself is unaffected.
	if got.Level != withCaps.Level || got.Confidence != withCaps.Confidence {
		t.Errorf("capabilities changed the recommendation itself: %+v vs %+v", got, withCaps)
	}
}

// The wizard reads this over the CLI's stdout JSON, so the wire keys
// are a contract with another owner.
func TestRecommendation_ActionJSONKeys(t *testing.T) {
	body, err := json.Marshal(FromContext(RotationContext{CredentialLeakSuspected: true}))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"action"`, `"kind"`, `"cli_verb"`, `"scope"`, `"in_place"`,
		`"needs_recipient_name"`, `"destroys_server"`,
		`"invalidates_every_pack"`, `"availability"`,
	} {
		if !strings.Contains(string(body), key) {
			t.Errorf("missing %s in %s", key, body)
		}
	}
}
