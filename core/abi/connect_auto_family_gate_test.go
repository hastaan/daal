package abi

import (
	"errors"
	"strings"
	"testing"
)

// Families the path manager never selects are never raced, gate open
// or closed: `other` (a pasted link to someone else's server) is left
// for the person to pick, and `amneziawg` (a config this build's
// WireGuard cannot speak) is refused even when picked, because every
// attempt is a plain WireGuard handshake from the person's address.
func TestConnectAuto_UnselectableFamiliesAreNeverRaced(t *testing.T) {
	rig := newAutoRig(t, autoFourRoutes[:1])
	seedAutoRoute(t, rig.c, "r-other", "other",
		`{"type":"vless","server":"stranger.example","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"stranger.example"}}`)
	seedAutoRoute(t, rig.c, "r-awg", "amneziawg",
		`{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"a","peers":[{"address":"vpn.example","port":51820,"public_key":"b","allowed_ips":["0.0.0.0/0"]}]}`)
	// The experimental gate does not open these.
	rig.c.mu.Lock()
	rig.c.experimentalFamiliesEnabled = true
	rig.c.mu.Unlock()

	rig.fail("r1", deadSYN())
	res := rig.connectAuto()
	if got := rig.provedRoutes(); !eq(got, []string{"r1"}) {
		t.Fatalf("started %v; only r1 may be started", got)
	}
	if res.Connected || res.Candidates != 1 {
		t.Fatalf("got %+v", res)
	}
	want := map[string]string{"r-awg": AutoRefusedFamilyUnsupported, "r-other": AutoRefusedManualOnly}
	for _, tr := range res.Tried {
		if code, ok := want[tr.RouteID]; ok {
			if tr.Result != AutoResultRefused || tr.Refused != code {
				t.Errorf("%s: %+v, want refused %s", tr.RouteID, tr, code)
			}
			delete(want, tr.RouteID)
		}
	}
	if len(want) != 0 {
		t.Errorf("not listed as refused: %v (tried %+v)", want, res.Tried)
	}

	// An explicit pick: amneziawg is refused before anything starts,
	// with its own code; `other` is the person's choice and connects.
	clearCooldowns(rig.c)
	before := len(rig.provedRoutes())
	if err := SetRoute("r-awg"); !errors.Is(err, errRouteFamilyUnsupported) {
		t.Fatalf("SetRoute(amneziawg) = %v", err)
	}
	if got := diagField(t, "connect_refused"); got != ConnectRefusedFamilyUnsupported {
		t.Fatalf("connect_refused = %v", got)
	}
	if len(rig.provedRoutes()) != before {
		t.Fatal("the amneziawg route was started")
	}
	if out, err := RouteConnectPrecheck("r-awg"); err != nil || !strings.Contains(out, `"refused":"`+ConnectRefusedFamilyUnsupported+`"`) {
		t.Fatalf("precheck = %s, %v", out, err)
	}
	if err := SetRoute("r-other"); err != nil {
		t.Fatalf("SetRoute(other) = %v", err)
	}
}
