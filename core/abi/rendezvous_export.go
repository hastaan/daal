//go:build cshared

package abi

import (
	"C"
	"encoding/json"
)

// engine_set_rendezvous_priority is the Phase 3B release ABI
// symbol (release surface 42 → 43). Sets the per-engine
// rendezvous priority override.
//
// `priority_json` is a UTF-8 JSON-encoded string array of
// channel IDs. NULL is invalid (use "[]" to reset). Returns:
//
//	 0 success
//	-1 engine not initialised
//	-3 priority list contains an unknown channel ID
//	-4 priority_json is NULL or malformed
//
// See specs/engine-abi-v1.md "Phase 3B" and
// specs/rendezvous-channels-v1.md.

//export engine_set_rendezvous_priority
func engine_set_rendezvous_priority(priorityJSON *C.char) C.int {
	if globalCore == nil {
		return -1
	}
	if priorityJSON == nil {
		return -4
	}
	body := C.GoString(priorityJSON)
	var list []string
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		return -4
	}
	return C.int(SetRendezvousPriority(list))
}

// engine_set_push_rendezvous_enabled is the Phase 3B release
// ABI symbol (release surface 43 → 44). Sets the user opt-in
// for the `push` rendezvous channel.
//
// Pass 1 to enable, 0 to disable. Default OFF at engine_init.
// Returns:
//
//	 0 success
//	-1 engine not initialised
//	-2 storage profile is "vault" — push is rejected
//
// See specs/push-rendezvous-v1.md.

//export engine_set_push_rendezvous_enabled
func engine_set_push_rendezvous_enabled(enabled C.int) C.int {
	if globalCore == nil {
		return -1
	}
	return C.int(SetPushRendezvousEnabled(enabled != 0))
}
