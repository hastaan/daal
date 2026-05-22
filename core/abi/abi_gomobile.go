//go:build gomobile

// DaalCore is the gomobile-friendly facade. gomobile bind exports the
// DaalCore type plus its methods to Java/Kotlin and Objective-C/Swift.
//
// Strings cross the bridge by value; complex objects cross as JSON.
package abi

// DaalCore is the receiver gomobile bind exposes.
type DaalCore struct{}

// New returns a new DaalCore. (gomobile bind does not export package-level
// functions cleanly, so we wrap them on a struct.)
func New() *DaalCore { return &DaalCore{} }

func (h *DaalCore) Init(stateDir, logLevel string) error   { return Init(stateDir, logLevel) }
func (h *DaalCore) Shutdown() error                        { return Shutdown() }
func (h *DaalCore) Version() string                        { return VersionString() }
func (h *DaalCore) SetRoute(routeID string) error          { return SetRoute(routeID) }
func (h *DaalCore) ClearRoute() error                      { return ClearRoute() }
func (h *DaalCore) SetMode(mode string) error              { return SetMode(mode) }
func (h *DaalCore) ApplyCooldown(id string, sec int) error { return ApplyCooldown(id, sec) }
func (h *DaalCore) ProbeUDP(timeoutMs int) int             { return ProbeUDP(timeoutMs) }
func (h *DaalCore) ProbeDNS(timeoutMs int) int             { return ProbeDNS(timeoutMs) }
func (h *DaalCore) ProbeTCP443(timeoutMs int) int          { return ProbeTCP443(timeoutMs) }
func (h *DaalCore) StatsRedacted() (string, error)         { return StatsRedacted() }
func (h *DaalCore) ExportDiagnostics() (string, error)     { return ExportDiagnostics() }

// ImportSBP returns a JSON string of the importer.Verdict.
func (h *DaalCore) ImportSBP(path string) (string, error) { return ImportSBP(path) }

// ResolveTrustPrompt accepts decision: 0=trust, 1=once, 2=cancel.
func (h *DaalCore) ResolveTrustPrompt(fingerprint string, decision int) (string, error) {
	return ResolveTrustPrompt(fingerprint, decision)
}
