//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// familyMatrixFile is the publisher's generated record of what
// ClientOutboundForFamily ACTUALLY emits for every family a Daal relay
// serves. It is written by
// publisher/deploy/relaypack TestClientOutboundMatrixIsCurrent and lives
// in another Go module, which is why this is a path and not an import:
// daal/core cannot depend on daal/publisher (the dependency runs the
// other way), so a file on disk is the only seam available.
const familyMatrixFile = "../../publisher/deploy/relaypack/testdata/client_outbounds.json"

type familyMatrixEntry struct {
	Port     int             `json:"port"`
	UDP      bool            `json:"udp"`
	Outbound json.RawMessage `json:"outbound"`
}

// TestEveryMintedOutboundParses is the "the configs are real" gate.
//
// TestAssembledClientOutboundsParse above proves that hand-written
// samples parse, and its own doc comment admits they are "kept in sync
// by hand". That is exactly the seam a family dies in: the samples were
// written from the renderer once, and nothing makes them follow it. Two
// concrete drifts were live in this file until this test was added —
// websocket-tls was sampled on port 443 while relayports has served it
// on 8445 for two waves, and naive, a STABLE shipped family, had no
// sample at all.
//
// This test takes the publisher's real output instead. If the renderer
// emits a field sing-box 1.13.12 does not have, or the wrong nesting, or
// a duration where an int belongs, the recipient engine cannot build the
// route — the pack imports, the route appears in the UI, the user
// selects it, and it fails at connect with no way to tell why. That is
// the failure this wave forbids outright, and it is cheap to catch here:
// the decoder below is the same strict parser the shipped engine runs.
//
// Note this does NOT need -tags with_quic / with_naive_outbound. Those
// tags decide whether the outbound can DIAL; sing-box registers the
// option types either way (include/naive_outbound_stub.go,
// include/quic_stub.go), so decoding is a faithful shape check for
// every family regardless of how this test binary was built.
func TestEveryMintedOutboundParses(t *testing.T) {
	families := loadFamilyMatrix(t)

	// A silently empty matrix would make this test pass forever.
	for _, must := range []string{"vless-reality", "hysteria2", "naive", "websocket-tls", "shadowsocks", "anytls", "tuic"} {
		if _, ok := families[must]; !ok {
			t.Fatalf("%s: family missing from %s — either the relay stopped serving it or the matrix is stale",
				must, familyMatrixFile)
		}
	}

	ctx := include.Context(context.Background())
	for family, e := range families {
		t.Run(family, func(t *testing.T) {
			cfg, err := BuildSingBoxConfig(sampleRowForFamily(family), []byte(e.Outbound))
			if err != nil {
				t.Fatalf("BuildSingBoxConfig: %v", err)
			}
			// Mirror singBox.Start's preprocessing: the daal-internal
			// route.udp_gated marker is stripped before sing-box sees it.
			delete(cfg.Route, "udp_gated")
			raw, err := MarshalSingBox(cfg)
			if err != nil {
				t.Fatalf("MarshalSingBox: %v", err)
			}
			if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, raw); err != nil {
				t.Fatalf("sing-box 1.13.12 rejected the outbound the publisher really mints for %s: %v\n\noutbound: %s",
					family, err, e.Outbound)
			}
		})
	}
}

// TestMintedOutboundsCarryTheDialTag pins the one property BuildSingBoxConfig
// cannot supply for itself: route.final resolves the tag "active", so an
// outbound minted under any other tag builds fine and is never selected.
func TestMintedOutboundsCarryTheDialTag(t *testing.T) {
	for family, e := range loadFamilyMatrix(t) {
		var ob map[string]any
		if err := json.Unmarshal(e.Outbound, &ob); err != nil {
			t.Fatalf("%s: %v", family, err)
		}
		if tag, _ := ob["tag"].(string); tag != "active" {
			t.Errorf("%s: tag = %q, want \"active\"", family, tag)
		}
		if typ, _ := ob["type"].(string); typ == "" {
			t.Errorf("%s: outbound has no type", family)
		}
	}
}

func loadFamilyMatrix(t *testing.T) map[string]familyMatrixEntry {
	t.Helper()
	raw, err := os.ReadFile(familyMatrixFile)
	if err != nil {
		t.Fatalf("read %s: %v\n\nRegenerate it from the publisher module:\n"+
			"  cd publisher && go test ./deploy/relaypack -run TestClientOutboundMatrixIsCurrent -update-family-matrix",
			familyMatrixFile, err)
	}
	var doc struct {
		Families map[string]familyMatrixEntry `json:"families"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", familyMatrixFile, err)
	}
	if len(doc.Families) == 0 {
		t.Fatalf("%s lists no families", familyMatrixFile)
	}
	return doc.Families
}
