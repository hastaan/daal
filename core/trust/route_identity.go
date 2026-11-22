package trust

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
)

// A ROUTE ID IS NOT A SERVER.
//
// Route ids are the manifest's (r1, r2, …), and a publisher's every
// RelayPack numbers its routes the same way. A file for a NEW relay —
// one that replaces a relay the publisher deleted — is saved over the
// rows of the old one, and before this every record of how the route
// did stayed on the row: the route list said "worked before" (proven:
// the success hour), showed the old relay's health_pct, and this
// network's memory ordered and graded the route by what the OLD server
// did (seen on the Sony, 2026-11-21: a fresh relay's VLESS at 100 % the
// moment its file was opened).
//
// So SaveImport compares what the route id names before and after the
// save — routeIdentity — and when the two are known and differ, the
// route's history is reset: the row's history columns
// (routestore.ResetRouteHistory) and, through OnRouteRebound, what the
// engine keeps beside it (core/abi: every network's memory of the route
// and its variants, the path manager's cooldown).
//
// WHAT NAMES A SERVER: the RelayPack id, and the signed
// commitment's address and keys — server, port, the TLS key pin, the
// REALITY key and cover name, the shadowsocks method and box key digest;
// for a CDN-fronted route its host name, port and CDN. Without a
// commitment (a pasted link, a subscription), the outbound's type,
// server and port. NOT part of it: anything a freshness refresh of the
// SAME relay changes without moving it — the signing date, the expiry,
// the credentials inside the profile, the standby address, a CDN zone's
// rotated ECH config, its edge seeds and roots. A refresh of the same
// relay therefore keeps its history; a new address, a new relay key or
// a new relay does not.

// routeID is what names the server a route id points at. ok false:
// nothing readable to go by — no comparison is made, nothing is reset.
type routeID struct {
	ok bool
	// pack: the RelayPack id ("" for a route of none).
	pack string
	// kind: "ep" (a signed endpoint), "cdn" (a signed CDN endpoint) or
	// "ob" (no commitment: the outbound itself).
	kind string
	// addr: where it dials — host and port.
	addr string
	// keys: the rest of what names the server, for its kind.
	keys string
}

// otherServer: do a and b name different servers? Unknown is never
// different. Two kinds (a route that gained a commitment) are compared
// by the pack and the address alone: the same relay at the same address
// that now has its endpoint signed is the same server.
func (a routeID) otherServer(b routeID) bool {
	if !a.ok || !b.ok {
		return false
	}
	if a.pack != b.pack || a.addr != b.addr {
		return true
	}
	return a.kind == b.kind && a.keys != b.keys
}

func routeIdentity(relayPackID string, endpoint, profile []byte) routeID {
	id := routeID{pack: relayPackID}
	addr := func(host string, port int) string { return strings.ToLower(host) + "|" + strconv.Itoa(port) }
	switch {
	case len(endpoint) > 0 && bundle.IsCDNCommitment(endpoint):
		var ep bundle.CDNEndpoint
		if json.Unmarshal(endpoint, &ep) != nil || ep.Server == "" {
			return routeID{}
		}
		id.kind, id.addr, id.keys = "cdn", addr(ep.Server, ep.Port), ep.CDN
	case len(endpoint) > 0:
		var ep bundle.Endpoint
		if json.Unmarshal(endpoint, &ep) != nil || ep.Server == "" {
			return routeID{}
		}
		id.kind, id.addr = "ep", addr(ep.Server, ep.Port)
		id.keys = strings.Join([]string{ep.ServerName, ep.TLSSPKISHA256, ep.RealityPublicKey, ep.SSMethod, ep.SSServerKeySHA256}, "|")
	case len(profile) > 0:
		typ, server, port := profileServer(profile)
		if server == "" {
			return routeID{}
		}
		id.kind, id.addr, id.keys = "ob", addr(server, port), typ
	default:
		return routeID{}
	}
	id.ok = true
	return id
}

// profileServer reads where an outbound goes: its type, server and port
// (a wireguard outbound's first peer).
func profileServer(profile []byte) (typ, server string, port int) {
	var p struct {
		Type   string `json:"type"`
		Server string `json:"server"`
		Port   int    `json:"server_port"`
		Peers  []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
		} `json:"peers"`
	}
	if json.Unmarshal(profile, &p) != nil {
		return "", "", 0
	}
	if p.Server == "" && len(p.Peers) > 0 {
		return p.Type, p.Peers[0].Address, p.Peers[0].Port
	}
	return p.Type, p.Server, p.Port
}

// heldIdentity is routeIdentity of what the device holds under id now
// (not ok when it holds no such route, or cannot tell).
func (a *StoreAdapter) heldIdentity(id string) (routeID, error) {
	row, err := a.S.GetRoute(id)
	if errors.Is(err, sql.ErrNoRows) {
		return routeID{}, nil
	}
	if err != nil {
		return routeID{}, err
	}
	endpoint, _ := a.S.GetSecret(RouteEndpointKey(id))
	profile, _ := a.S.GetSecret("route:" + id)
	return routeIdentity(row.RelayPackID, endpoint, profile), nil
}

// savedIdentity is routeIdentity of what SaveImport is about to hold
// under r.RouteID. heldProfile: the profile kept when r carries none (a
// file without credentials for a route this device already holds).
func savedIdentity(r importer.RouteInput, heldProfile []byte) routeID {
	packID := ""
	if r.RelayPack != nil {
		packID = r.RelayPack.RelayPackID
	}
	profile := r.Profile
	if len(profile) == 0 {
		profile = heldProfile
	}
	return routeIdentity(packID, r.Endpoint, profile)
}
