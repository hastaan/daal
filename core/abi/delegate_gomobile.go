//go:build gomobile

package abi

// Phase 3F. Gomobile-side wrapper for the new release ABI
// symbol. The Java/Swift sides see it as an instance method on
// `DaalCore`.

// RedistributeRoute returns serialized `.sbp.share` envelope
// bytes (a JSON envelope; see specs/delegate-keys-v1.md "Wire
// format") on success, or a JSON error envelope on failure.
// Always valid JSON.
func (h *DaalCore) RedistributeRoute(routeID, recipientFPHex string) string {
	return RedistributeRoute(routeID, recipientFPHex)
}
