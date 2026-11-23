package abi

// link_resolvers.go — engine_set_link_resolvers: the host tells the
// engine the DNS servers of the network UNDER any VPN (Android:
// LinkProperties.getDnsServers of the non-VPN network NetworkWatch
// follows), on every change, and an empty list when that network is
// lost. Go on Android cannot read them itself, and the update ladder's
// DNS reader (core/refresh/carrier_dns.go) asks only the network's own
// resolver: without this call it is never usable on a phone.
//
// The addresses live in memory only (bootstrap.SetLinkResolvers); they
// are never stored or logged.

import (
	"encoding/json"
	"errors"
	"strings"

	"daal/core/bootstrap"
)

// maxLinkResolvers bounds what one call keeps (a link has two or three).
const maxLinkResolvers = 8

var errLinkResolversJSON = errors.New("abi: link resolvers: not a JSON list of strings")

// SetLinkResolvers takes `["<addr>", "<addr:port>", …]` ("" or "[]" = the
// network is gone) and returns how many servers the DNS reader may ask
// now: 1 when one usable resolver is known, 0 when none (an empty list,
// only public resolvers, nothing that parses).
func SetLinkResolvers(serversJSON string) (int, error) {
	var servers []string
	if s := strings.TrimSpace(serversJSON); s != "" {
		if len(s) > 4096 {
			return -1, errLinkResolversJSON
		}
		if err := json.Unmarshal([]byte(s), &servers); err != nil {
			return -1, errLinkResolversJSON
		}
	}
	if len(servers) > maxLinkResolvers {
		servers = servers[:maxLinkResolvers]
	}
	bootstrap.SetLinkResolvers(servers)
	if _, ok := bootstrap.LinkResolver(); ok {
		return 1, nil
	}
	return 0, nil
}
