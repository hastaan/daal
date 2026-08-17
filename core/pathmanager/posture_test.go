package pathmanager

import (
	"testing"
)

// TestAllPosturesUnique guards against typos in the constant block.
func TestAllPosturesUnique(t *testing.T) {
	seen := map[Posture]bool{}
	for _, p := range AllPostures {
		if seen[p] {
			t.Errorf("duplicate posture in AllPostures: %q", p)
		}
		seen[p] = true
	}
	if len(AllPostures) != 8 {
		t.Errorf("V2.3 specifies 8 postures, got %d", len(AllPostures))
	}
}

// TestLegalTransitionsAreClosed asserts every entry in
// LegalTransitions references a known Posture and a known
// PostureEvent, and From/To are not equal (no self-loops in the
// table — Manager.SetPosture never has to no-op).
func TestLegalTransitionsAreClosed(t *testing.T) {
	allPosture := map[Posture]bool{}
	for _, p := range AllPostures {
		allPosture[p] = true
	}
	knownEvents := map[PostureEvent]bool{
		EventBootstrapStart:       true,
		EventDirectoryFetched:     true,
		EventImportedSelected:     true,
		EventSharedSelected:       true,
		EventActiveFailed:         true,
		EventRecoverySelected:     true,
		EventLifelineModeOn:       true,
		EventLifelineModeOff:      true,
		EventOfflineShareStart:    true,
		EventOfflineShareEnd:      true,
		EventExperimentalSelected: true,
		EventDisconnected:         true,
	}
	for _, tr := range LegalTransitions {
		if !allPosture[tr.From] {
			t.Errorf("unknown From posture %q in transition %+v", tr.From, tr)
		}
		if !allPosture[tr.To] {
			t.Errorf("unknown To posture %q in transition %+v", tr.To, tr)
		}
		if !knownEvents[tr.Event] {
			t.Errorf("unknown event %q in transition %+v", tr.Event, tr)
		}
		if tr.From == tr.To {
			t.Errorf("self-loop transition %+v", tr)
		}
	}
}

// TestEveryActivePostureCanReachNoRoute asserts every non-terminal
// posture has at least one path to NoRoute (via Disconnected). This
// is the V2.3 invariant that the user can always disconnect.
func TestEveryActivePostureCanReachNoRoute(t *testing.T) {
	hasDisconnect := map[Posture]bool{
		PostureNoRoute: true, // already there
	}
	for _, tr := range LegalTransitions {
		if tr.Event == EventDisconnected && tr.To == PostureNoRoute {
			hasDisconnect[tr.From] = true
		}
	}
	for _, p := range AllPostures {
		if !hasDisconnect[p] {
			t.Errorf("posture %q has no disconnect → NoRoute path", p)
		}
	}
}

func TestIsLegalTrueForKnownTransitions(t *testing.T) {
	for _, tr := range LegalTransitions {
		if !IsLegal(tr.From, tr.Event, tr.To) {
			t.Errorf("IsLegal returned false for known transition %+v", tr)
		}
	}
}

func TestIsLegalFalseForUnknownTransition(t *testing.T) {
	if IsLegal(PostureNoRoute, EventActiveFailed, PostureLifeline) {
		t.Error("expected illegal: NoRoute --active_failed--> Lifeline")
	}
	if IsLegal(PostureBootstrapDiscovery, EventLifelineModeOn, PostureLifeline) {
		t.Error("expected illegal: BootstrapDiscovery --lifeline_mode_on--> Lifeline")
	}
}

// TestExperimentalHasTheSameExitsAsAnyActivePosture: PostureExperimental
// became reachable on a live connection when tuic/shadowsocks were
// demoted from Stable, so it must be able to LEAVE. A user who connects
// on a tuic route and then picks a vless-reality one fires
// `imported_selected`; burn-pressure auto-promotion fires
// `lifeline_mode_on`. When either is illegal, abi swallows the error
// (`_ =`), the posture sticks at Experimental while a stable route is
// active, and Manager.SetPosture overwrites lastReason with the FSM
// violation — which ExportDiagnostics then publishes as `why`.
func TestExperimentalHasTheSameExitsAsAnyActivePosture(t *testing.T) {
	for _, tc := range []struct {
		event PostureEvent
		to    Posture
	}{
		{EventImportedSelected, PostureImportedActive},
		{EventSharedSelected, PostureSharedActive},
		{EventLifelineModeOn, PostureLifeline},
		{EventOfflineShareStart, PostureOfflineSharing},
		{EventActiveFailed, PostureRecovery},
		{EventDisconnected, PostureNoRoute},
	} {
		if !IsLegal(PostureExperimental, tc.event, tc.to) {
			t.Errorf("Experimental --%s--> %s must be legal", tc.event, tc.to)
		}
		m := New()
		if err := m.SetPosture(EventExperimentalSelected, PostureExperimental); err != nil {
			t.Fatalf("entering Experimental: %v", err)
		}
		if err := m.SetPosture(tc.event, tc.to); err != nil {
			t.Errorf("SetPosture(%s → %s) from Experimental: %v", tc.event, tc.to, err)
		}
		if got := m.Posture(); got != tc.to {
			t.Errorf("posture stuck at %q after %s", got, tc.event)
		}
	}
}

// === Manager posture-axis tests ===

func TestPostureDefaultIsNoRoute(t *testing.T) {
	m := New()
	if got := m.Posture(); got != PostureNoRoute {
		t.Errorf("default posture = %q, want %q", got, PostureNoRoute)
	}
}

func TestSetPostureLegalAdvances(t *testing.T) {
	m := New()
	if err := m.SetPosture(EventBootstrapStart, PostureBootstrapDiscovery); err != nil {
		t.Fatalf("legal transition rejected: %v", err)
	}
	if got := m.Posture(); got != PostureBootstrapDiscovery {
		t.Errorf("posture not advanced: got %q", got)
	}
}

func TestSetPostureIllegalReturnsErrorAndDoesNotAdvance(t *testing.T) {
	m := New()
	err := m.SetPosture(EventActiveFailed, PostureLifeline)
	if err == nil {
		t.Fatal("expected error on illegal transition")
	}
	if got := m.Posture(); got != PostureNoRoute {
		t.Errorf("posture changed despite illegal transition: got %q", got)
	}
}

func TestPostureRecoveryCycle(t *testing.T) {
	m := New()
	// NoRoute → ImportedActive
	if err := m.SetPosture(EventImportedSelected, PostureImportedActive); err != nil {
		t.Fatal(err)
	}
	// ImportedActive → Recovery (active failed)
	if err := m.SetPosture(EventActiveFailed, PostureRecovery); err != nil {
		t.Fatal(err)
	}
	// Recovery → ImportedActive (recovery selected next-best)
	if err := m.SetPosture(EventRecoverySelected, PostureImportedActive); err != nil {
		t.Fatal(err)
	}
	if got := m.Posture(); got != PostureImportedActive {
		t.Errorf("posture after recovery cycle = %q, want ImportedActive", got)
	}
}
