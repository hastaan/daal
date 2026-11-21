//go:build singbox && cgo && linux && !wb_standby_key

package main

// clientFeatures: built without the engine's standby-key call (the
// engine does not export it yet: add-ons wave 2, lane L-ladder S7).
var clientFeatures = []string{}

func standbyKeyCmd(args []string) map[string]any {
	return map[string]any{"error": "not_built: this engine has no StandbyKey (engine_standby_key); WAITS ON L-ladder S7"}
}
