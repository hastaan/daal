package engine

// PublishRefreshInletForTest publishes `in` as the live refresh inlet
// without a driver having started one, and returns a function that
// retires it again.
//
// IT EXISTS ONLY FOR TESTS IN OTHER PACKAGES. core/abi proves the
// engine → abi → refresh round trip against a real SOCKS5 listener
// without booting sing-box, and Go has no cross-package export_test.go.
//
// NOTHING IN PRODUCTION MAY CALL THIS. The live slot's contract is "a
// driver is listening on this address right now"; publishing an inlet
// nobody serves hands the refresher a dialer aimed at a dead port, which
// converts a correct fail-closed refusal into a connection error once
// per scheduler cadence. The production publisher is
// promoteRefreshInlet, called by the driver only after its instance —
// and therefore every inbound in its config — is up.
func PublishRefreshInletForTest(in *RefreshInlet) func() {
	inletMu.Lock()
	inletLive = in
	inletMu.Unlock()
	return retireRefreshInlet
}
