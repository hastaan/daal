//go:build singbox && cgo && linux && wb_standby_key

package main

import (
	"strings"

	"daal/core/abi"
)

// clientFeatures: this build has the engine's standby-key call
// (specs/optional-addons-v1.md §3.4, engine_standby_key). run.sh adds
// the wb_standby_key tag when core/abi exports StandbyKey.
var clientFeatures = []string{"standby_key"}

// standbyKeyCmd is the recipient's "I was sent a code" field:
// `standby-key <relay pack id | -> <key text>`. The engine's answer is
// passed through whole; the key is never echoed back.
func standbyKeyCmd(args []string) map[string]any {
	if len(args) < 2 {
		return map[string]any{"error": "standby-key needs <relay pack id|-> <key>"}
	}
	pack := args[0]
	if pack == "-" {
		pack = ""
	}
	// The key is typed in groups with spaces; the field passes it whole.
	out, err := abi.StandbyKey(pack, strings.Join(args[1:], " "))
	routes, _ := abi.AvailableRoutes()
	return map[string]any{"answer": rawJSON(out), "error": errString(err), "routes": rawJSON(routes)}
}
