package pathmanager

// Posture is the V2.3 application-posture axis. Orthogonal to State
// (which remains the legacy connection-lifecycle axis preserved
// since 1B). Both are surfaced in `engine_export_diagnostics`; the
// desktop's mode picker and route-health table read Posture.
//
// Removal of the legacy `State` enum is deferred to V3; at V2 both
// axes live side by side on Manager.
type Posture string

const (
	PostureNoRoute            Posture = "NoRoute"
	PostureBootstrapDiscovery Posture = "BootstrapDiscovery"
	PostureImportedActive     Posture = "ImportedActive"
	PostureSharedActive       Posture = "SharedActive"
	PostureRecovery           Posture = "Recovery"
	PostureLifeline           Posture = "Lifeline"
	PostureOfflineSharing     Posture = "OfflineSharing"
	PostureExperimental       Posture = "Experimental"
)

// AllPostures is the closed set of V2.3 posture names verbatim.
// Tests assert exhaustive transition coverage against this list.
var AllPostures = []Posture{
	PostureNoRoute,
	PostureBootstrapDiscovery,
	PostureImportedActive,
	PostureSharedActive,
	PostureRecovery,
	PostureLifeline,
	PostureOfflineSharing,
	PostureExperimental,
}

// PostureEvent is the closed event vocabulary that drives the
// transition table. The set is small by design — the FSM is
// deterministic and human-auditable.
type PostureEvent string

const (
	EventBootstrapStart       PostureEvent = "bootstrap_start"
	EventDirectoryFetched     PostureEvent = "directory_fetched"
	EventImportedSelected     PostureEvent = "imported_selected"
	EventSharedSelected       PostureEvent = "shared_selected"
	EventActiveFailed         PostureEvent = "active_failed"
	EventRecoverySelected     PostureEvent = "recovery_selected"
	EventLifelineModeOn       PostureEvent = "lifeline_mode_on"
	EventLifelineModeOff      PostureEvent = "lifeline_mode_off"
	EventOfflineShareStart    PostureEvent = "offline_share_start"
	EventOfflineShareEnd      PostureEvent = "offline_share_end"
	EventExperimentalSelected PostureEvent = "experimental_selected"
	EventDisconnected         PostureEvent = "disconnected"
)

// PostureTransition is one row of the legal-edge table.
type PostureTransition struct {
	From  Posture
	Event PostureEvent
	To    Posture
}

// LegalTransitions is the closed transition table. Anything not in
// it is illegal; Manager.SetPosture rejects illegal transitions.
//
// Ordering: outgoing edges grouped by From for readability; tests do
// not depend on slice order.
var LegalTransitions = []PostureTransition{
	// From NoRoute
	{PostureNoRoute, EventBootstrapStart, PostureBootstrapDiscovery},
	{PostureNoRoute, EventImportedSelected, PostureImportedActive},
	{PostureNoRoute, EventSharedSelected, PostureSharedActive},
	{PostureNoRoute, EventOfflineShareStart, PostureOfflineSharing},
	// Gap 5 — Experimental from NoRoute. A user can pick an
	// experimental-family route as their first connection without
	// having transited through ImportedActive first.
	{PostureNoRoute, EventExperimentalSelected, PostureExperimental},
	// Gap 5 — A cold-start `engine_bootstrap_refresh` that lands a
	// directory before any user-selected route should advance the
	// posture directly to ImportedActive (the directory IS the import
	// source). Without this edge the call at refresh time is silently
	// illegal-no-op when the posture is still NoRoute.
	{PostureNoRoute, EventDirectoryFetched, PostureImportedActive},
	// Gap 5 — A first-attempt SetRoute that fails (driver.Start
	// error) was firing EventActiveFailed → Recovery from NoRoute,
	// which the table did not allow. The error was swallowed and
	// the posture stayed at NoRoute — leaving the GUI without the
	// recovery affordance. Allow it explicitly.
	{PostureNoRoute, EventActiveFailed, PostureRecovery},

	// From BootstrapDiscovery
	{PostureBootstrapDiscovery, EventDirectoryFetched, PostureImportedActive},
	{PostureBootstrapDiscovery, EventActiveFailed, PostureRecovery},
	{PostureBootstrapDiscovery, EventDisconnected, PostureNoRoute},

	// From ImportedActive
	{PostureImportedActive, EventActiveFailed, PostureRecovery},
	{PostureImportedActive, EventLifelineModeOn, PostureLifeline},
	{PostureImportedActive, EventOfflineShareStart, PostureOfflineSharing},
	{PostureImportedActive, EventExperimentalSelected, PostureExperimental},
	{PostureImportedActive, EventDisconnected, PostureNoRoute},

	// From SharedActive
	{PostureSharedActive, EventActiveFailed, PostureRecovery},
	{PostureSharedActive, EventLifelineModeOn, PostureLifeline},
	{PostureSharedActive, EventDisconnected, PostureNoRoute},

	// From Recovery
	{PostureRecovery, EventRecoverySelected, PostureImportedActive},
	{PostureRecovery, EventRecoverySelected, PostureSharedActive},
	{PostureRecovery, EventActiveFailed, PostureNoRoute},
	{PostureRecovery, EventDisconnected, PostureNoRoute},

	// From Lifeline
	{PostureLifeline, EventLifelineModeOff, PostureImportedActive},
	{PostureLifeline, EventActiveFailed, PostureRecovery},
	{PostureLifeline, EventDisconnected, PostureNoRoute},

	// From OfflineSharing
	{PostureOfflineSharing, EventOfflineShareEnd, PostureImportedActive},
	{PostureOfflineSharing, EventDisconnected, PostureNoRoute},

	// From Experimental
	{PostureExperimental, EventActiveFailed, PostureRecovery},
	{PostureExperimental, EventDisconnected, PostureNoRoute},
}

// IsLegal reports whether (from, event) → to is in the table. Order
// of the slice is irrelevant; this is a linear scan over the closed
// table (≤ 30 entries) and is fast enough for the FSM.
func IsLegal(from Posture, event PostureEvent, to Posture) bool {
	for _, tr := range LegalTransitions {
		if tr.From == from && tr.Event == event && tr.To == to {
			return true
		}
	}
	return false
}
