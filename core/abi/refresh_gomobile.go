//go:build gomobile

package abi

// Phase 1.5A extensions to the DaalCore gomobile facade. All return JSON.

func (h *DaalCore) SubscriptionAdd(publisherFP, url, displayName string) (string, error) {
	return SubscriptionAdd(publisherFP, url, displayName)
}

func (h *DaalCore) SubscriptionRefresh(subscriptionID string, timeoutMs int) (string, error) {
	return SubscriptionRefresh(subscriptionID, timeoutMs)
}

func (h *DaalCore) SubscriptionRemove(subscriptionID string) error {
	return SubscriptionRemove(subscriptionID)
}

func (h *DaalCore) SubscriptionList() (string, error) { return SubscriptionList() }

func (h *DaalCore) RevocationRefreshAll(timeoutMs int) (string, error) {
	return RevocationRefreshAll(timeoutMs)
}

func (h *DaalCore) PointerRotationStatus() (string, error) { return PointerRotationStatus() }

func (h *DaalCore) DiagnosticsExplain() (string, error) { return DiagnosticsExplain() }
