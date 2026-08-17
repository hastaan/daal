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
	// Without a provider name there is nothing to be confident about:
	// whether a swap moves the record's dialled address is a property
	// of the adapter, so "we were not told which" is its own state and
	// must never round up to ready.
	if a.Availability != AvailabilityUnknown {
		t.Errorf(`L3 with no provider = %q, want unknown`, a.Availability)
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

// L3's availability now differs by cloud adapter, because the adapters
// differ: Hetzner moves the record's dialled address, Vultr and Stark
// record the id and stop. Reporting one answer for both would either
// hide a working rung or offer a broken one.
func TestActionForProvider_L3DiffersByAdapter(t *testing.T) {
	// A relay probed and able to bind: the only combination that is
	// genuinely ready. The adapter half and the box half both have to
	// be known good — see TestActionForProvider_L3DependsOnTheBoxToo.
	canBind := RelayCapabilities{Known: true, BindAddress: true}
	ready := ActionForProvider(L3, canBind, "hetzner")
	if ready.Availability != AvailabilityReady {
		t.Errorf("hetzner L3 = %q, want ready", ready.Availability)
	}
	if !ready.InPlace || ready.DestroysServer {
		t.Errorf("hetzner L3 should keep the server: %+v", ready)
	}
	if !ready.InvalidatesEveryPack {
		t.Error("an address swap invalidates every distributed pack; the flag must say so")
	}

	for _, p := range []string{"vultr", "stark"} {
		a := ActionForProvider(L3, RelayCapabilities{}, p)
		if a.Availability != AvailabilityUnsupported {
			t.Errorf("%s L3 = %q, want unsupported (the adapter attaches an address without moving the record onto it)", p, a.Availability)
		}
		if a.Note == "" {
			t.Errorf("%s L3 carries no remediation note", p)
		}
	}

	if got := ActionForProvider(L3, canBind, "  HETZNER  ").Availability; got != AvailabilityReady {
		t.Errorf("provider name matching should be case- and space-insensitive; got %q", got)
	}
	if got := ActionForProvider(L3, canBind, "digitalocean").Availability; got != AvailabilityUnknown {
		t.Errorf("unrecognised provider = %q, want unknown", got)
	}
}

// L3's availability USED to be a pure property of the cloud adapter, and
// this test asserted that the box's capabilities could not move it. Real
// hardware falsified that on 2026-08-17: a floating IP is routed to the
// server by the provider and never answered by the guest OS until the
// relay configures it on its interface, so a relay whose mgmt binary
// predates the bind endpoint cannot complete an L3 at all.
//
// Both halves therefore have to be known good, and "not asked" must not
// round up to "ready" — an operator who presses a one-tap button that
// then refuses has been told something false about their relay.
func TestActionForProvider_L3DependsOnTheBoxToo(t *testing.T) {
	unprobed := ActionForProvider(L3, RelayCapabilities{}, "hetzner")
	if unprobed.Availability != AvailabilityUnknown {
		t.Errorf("unprobed hetzner L3 = %q, want unknown — the relay's ability to bind the address has not been asked about", unprobed.Availability)
	}
	if !strings.Contains(unprobed.Note, "probe") && !strings.Contains(unprobed.Note, "Probe") {
		t.Errorf("the unknown note must tell the caller to probe: %q", unprobed.Note)
	}

	tooOld := RelayCapabilities{Known: true, RotateCredentialsInPlace: true, RotateTLSInPlace: true}
	old := ActionForProvider(L3, tooOld, "hetzner")
	if old.Availability != AvailabilityUnsupported {
		t.Errorf("a relay that cannot bind an address = %q, want unsupported", old.Availability)
	}
	if !strings.Contains(old.Note, "interface") {
		t.Errorf("the refusal must name the guest-OS cause: %q", old.Note)
	}

	// The adapter's failure comes first: a box that can bind does not
	// make an adapter that never moves the record work.
	full := RelayCapabilities{Known: true, BindAddress: true, RotateCredentialsInPlace: true, RotateTLSInPlace: true}
	if a := ActionForProvider(L3, full, "vultr"); a.Availability != AvailabilityUnsupported {
		t.Errorf("a fully-capable box does not make a Vultr address swap work: %q", a.Availability)
	}
}
