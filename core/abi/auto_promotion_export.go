//go:build cshared

package abi

import "C"

// engine_set_auto_promotion is the Phase 2G release ABI symbol
// (release surface 39 → 40). Sets the engine's auto-promotion
// preference for entry into `lifeline-strict` on burn pressure.
//
// The flag is enabled by default at engine_init and survives
// session epochs (it is a user preference). Pass 1 to enable,
// 0 to disable. Always returns 0.
//
// The detector itself is consulted by the scheduler on every Tick
// (see core/burnpressure for the locked v1 thresholds). Manual
// `engine_set_mode` calls within the same hour-bucket suppress
// auto-promotion for that bucket — the user's choice always wins.

//export engine_set_auto_promotion
func engine_set_auto_promotion(enabled C.int) C.int {
	SetAutoPromotion(enabled != 0)
	return 0
}
