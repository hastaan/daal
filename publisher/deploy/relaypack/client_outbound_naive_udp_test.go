package relaypack

import (
	"encoding/json"
	"reflect"
	"testing"

	"daal/bundle-go/bundle"
)

// TestClientOutbound_NaiveCarriesUDP: a naive route minted without
// udp_over_tcp is built by sing-box with networks=[tcp], and every app
// datagram that is not a name lookup is refused inside the engine while
// the route says Connected (the end-to-end rig's finding FAM-6). The
// minted outbound must ask for UDP-over-TCP, version 2 — the shape the
// relay's naive inbound accepts with no configuration
// (sing-box 1.13.12 protocol/naive/inbound.go wraps its router in
// uot.NewRouter) and the engine reads to know the route carries
// datagrams (core/engine.outboundCarriesUDP).
func TestClientOutbound_NaiveCarriesUDP(t *testing.T) {
	certPEM, pin := boxCert(t, "5.75.0.1", "cover.example-host.net")
	p := fullParams()
	p.Server = "5.75.0.1"
	p.TLSCertPEM, p.TLSCertSHA256 = certPEM, pin

	raw, err := ClientOutboundForFamily("naive", 8444, p)
	if err != nil {
		t.Fatal(err)
	}
	var ob map[string]any
	if err := json.Unmarshal(raw, &ob); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"enabled": true, "version": float64(2)}
	if !reflect.DeepEqual(ob["udp_over_tcp"], want) {
		t.Fatalf("naive outbound udp_over_tcp = %v, want %v: without it the route carries no app UDP", ob["udp_over_tcp"], want)
	}

	// The signed endpoint accepts it: UDP-over-TCP changes what the
	// stream carries, not where it goes or what proves who answered.
	ep, why := endpointFor("naive", 8444, EndpointMaterialFromParams(p))
	if ep == nil {
		t.Fatal(why)
	}
	if err := bundle.CheckOutbound("naive", ep, raw); err != nil {
		t.Fatalf("the commitment check refuses the minted naive outbound: %v", err)
	}

	// And it survives the freshness merge: a phone that follows the
	// relay to a new address without a new file keeps its UDP.
	moved := *ep
	moved.Server = "203.0.113.200"
	merged, err := bundle.MergeEndpoint("naive", &moved, raw)
	if err != nil {
		t.Fatal(err)
	}
	var mob map[string]any
	_ = json.Unmarshal(merged, &mob)
	if !reflect.DeepEqual(mob["udp_over_tcp"], want) {
		t.Errorf("after a merge to a new address udp_over_tcp = %v, want %v", mob["udp_over_tcp"], want)
	}
	if mob["server"] != "203.0.113.200" {
		t.Errorf("merge did not move the server: %v", mob["server"])
	}
}
