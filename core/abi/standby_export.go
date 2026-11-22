//go:build cshared

package abi

import "C"

import "unsafe"

// engine_standby_key (optional add-ons S7, specs/optional-addons-v1.md
// §3.4): a recipient's standby key, checked against the sealed
// `_standby` of the held routes and kept on each it opens. JSON
// {"outcome":"accepted|no_match|malformed|no_standby","routes":<n>} via
// copyOut. Never echoes the key or the address. -1 when the engine is
// not initialised or the store cannot be written.
//
//export engine_standby_key
func engine_standby_key(relayPackID *C.char, key *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := StandbyKey(C.GoString(relayPackID), C.GoString(key))
	if err != nil {
		return exportFail("engine_standby_key", err)
	}
	return copyOut(body, out, outLen)
}
