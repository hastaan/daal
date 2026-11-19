//go:build gomobile

package abi

// gomobile facade for engine_network_facts.

func (h *DaalCore) NetworkFacts(kind, id string, validated, metered int) (string, error) {
	return NetworkFacts(kind, id, validated, metered)
}
