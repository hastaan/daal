//go:build gomobile

package abi

// gomobile facade for the network test (fieldprobe.go).

func (h *DaalCore) FieldProbeStart(optsJSON string) (string, error) { return FieldProbeStart(optsJSON) }

func (h *DaalCore) FieldProbeStatus() (string, error) { return FieldProbeStatus() }

func (h *DaalCore) FieldProbeCancel(reason string) bool { return FieldProbeCancel(reason) }

func (h *DaalCore) FieldProbeSeal(optsJSON string) (string, error) { return FieldProbeSeal(optsJSON) }

func (h *DaalCore) FieldProbeDiscard() (int, error) { return FieldProbeDiscard() }
