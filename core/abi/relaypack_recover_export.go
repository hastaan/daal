//go:build cshared

package abi

import "C"

import "unsafe"

// engine_relaypack_refresh looks for a newer signed pack NOW: one walk
// of the publisher's freshness mirrors for one pack, or for every pack
// the device holds (relay_pack_id "" — at most three). See
// RelayPackRefresh (relaypack_recover.go).
//
// The tunnel guard decides how it dials, as for every fetch: with a
// route that carries, through the tunnel or not at all
// (outcome "tunnel_required"); with nothing running, direct. With a
// route that is running and carries NOTHING, the engine stops that
// instance for the walk, dials direct (every other fetch stays refused
// meanwhile), and puts it back after — re-checked at once when a new
// pack was applied to it. Works in lifeline-strict.
//
// Per pack at most one walk a minute, then 2 and 5 minutes for presses
// in a row that found nothing new; a press inside it dials nothing
// ("rate_limited", retry_after_s). "in_progress" while a walk or an
// automatic pass is in flight; "cancelled" when a disconnect or a
// connect cut the walk off.
//
// Blocking, bounded by the walk (≈ 55 s per pack at worst): call it off
// the UI thread. Writes to `out`:
//
//	{"outcome":"updated|unchanged|unreachable|rejected|tunnel_required|
//	            rate_limited|no_endpoints|unknown_pack|in_progress|cancelled",
//	 "retry_after_s":0,"route_paused":false,"rechecking":false,
//	 "packs":[{"relay_pack_id":"rp-…","outcome":"<core/refresh code>",
//	           "kind":"on_demand","applied":false,"changed":false,
//	           "via_tunnel":false,"endpoints_tried":2,"providers":2, …}]}
//
// Returns the number of bytes written, or -1 if the engine is not
// initialised. Finding nothing is NOT an error: the answer is in the
// JSON. No URL, address or host is ever in it.
//
//export engine_relaypack_refresh
func engine_relaypack_refresh(relayPackID *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := RelayPackRefresh(C.GoString(relayPackID))
	if err != nil {
		return exportFail("engine_relaypack_refresh", err)
	}
	return copyOut(body, out, outLen)
}
