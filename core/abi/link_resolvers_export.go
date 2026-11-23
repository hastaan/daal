//go:build cshared

package abi

import "C"

// engine_set_link_resolvers: the DNS servers of the network under any
// VPN, as a JSON list of strings ("addr" or "addr:port"); "[]" when that
// network is lost. Returns 1 when the update ladder's DNS reader has a
// resolver to ask now, 0 when it has none, -1 for input that is not a
// JSON list of strings. Optional for the hosts (added 2026-11-22); the
// addresses are never stored or logged.
//
//	int engine_set_link_resolvers(const char* servers_json);
//
//export engine_set_link_resolvers
func engine_set_link_resolvers(serversJSON *C.char) C.int {
	n, err := SetLinkResolvers(C.GoString(serversJSON))
	if err != nil {
		return exportFailCode("engine_set_link_resolvers", -1, "not a JSON list of strings")
	}
	return C.int(n)
}
