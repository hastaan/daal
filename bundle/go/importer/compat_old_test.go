package importer_test

// Today's add-on packs, fed to the rules phones in the field already
// run (internal/oldrules: frozen from 079ef96, the last build before the
// add-ons put anything new into a pack).
//
// The owner's requirement: a family inside Iran may stay on an older
// build for a long time. A pack that carries a standby commitment or a
// CDN route must therefore cost such a phone NOTHING it had before: the
// direct routes import, the freshness merge of the signed skeleton still
// moves them, and the new members are simply not seen. The last test
// shows why the carrier the plan first proposed (CDN members inside
// `_endpoint`) was not used: the old rules refuse the whole pack for it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer/internal/oldrules"
	relaypack "daal/bundle-go/relaypackvalidate"
)

// oldDevice is the store as the old importer saw it.
type oldDevice struct {
	routes map[string]oldrules.DeviceRoute
}

func (d *oldDevice) DeviceRoute(id string) (oldrules.DeviceRoute, bool, error) {
	r, ok := d.routes[id]
	return r, ok, nil
}

// oldImport is the old build's import of a pack: signature, expiry and
// revocation (bundle.VerifyBundle — what proves the new members are
// SIGNED: they sit in family_specific_config, which the manifest
// signature covers), RelayPack validation at the phase it ships, then
// its route plan.
func oldImport(t *testing.T, body []byte, st oldrules.State, continuity bool) (*bundle.Bundle, oldrules.Outcome) {
	t.Helper()
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundleAt(parsed, time.Now().UTC()); err != nil {
		t.Fatalf("the pack does not verify: %v", err)
	}
	if _, err := relaypack.Validate(parsed, relaypack.ValidateOpts{Phase: relaypack.CurrentPhase}); err != nil {
		t.Fatalf("an old build's RelayPack validator refuses the pack: %v", err)
	}
	return parsed, oldrules.Plan(parsed, st, bundle.PublisherFingerprint(parsed.PublisherPub).Hex, continuity)
}

func TestOldBuild_ImportsAnAddonPack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	body := defaultAddonPack(t, pub, priv, root)

	_, out := oldImport(t, body, &oldDevice{routes: map[string]oldrules.DeviceRoute{}}, false)
	if out.Refused {
		t.Fatalf("the old rules refused the whole pack: %s %v", out.Reason, out.Err)
	}
	if len(out.Stored) != 2 || out.Stored[0].RouteID != "rA" || out.Stored[1].RouteID != "rB" {
		t.Fatalf("the direct routes must import: %+v", out.Stored)
	}
	for _, r := range out.Stored {
		// `_standby` never reaches the old engine's row, and the old
		// commitment it stores is the unchanged `_endpoint`.
		if strings.Contains(r.EngineConfig, "_standby") || strings.Contains(string(r.Endpoint), "_standby") {
			t.Fatalf("%s: standby leaked into %q / %s", r.RouteID, r.EngineConfig, r.Endpoint)
		}
		if !strings.Contains(r.EngineConfig, "_desync") {
			t.Fatalf("%s: the old engine config lost what it reads: %q", r.RouteID, r.EngineConfig)
		}
	}
	// The CDN route: no commitment, no outbound the old rules can see.
	// One line on the import screen ("not included in this file …
	// nothing is wrong with your phone"), not a refusal.
	if len(out.Unavailable) != 1 || out.Unavailable[0].RouteID != "rC" ||
		out.Unavailable[0].Reason != oldrules.UnavailableNotOffered {
		t.Fatalf("rC: %+v", out.Unavailable)
	}
}

// The freshness path on an old build: the signed skeleton of a moved
// relay, carrying `_standby` and the CDN route, still merges into the
// direct routes the phone holds.
func TestOldBuild_FreshnessMergeSurvivesAddonPack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	first := defaultAddonPack(t, pub, priv, root)
	fp := bundle.PublisherFingerprint(pub).Hex

	dev := &oldDevice{routes: map[string]oldrules.DeviceRoute{}}
	_, out := oldImport(t, first, dev, false)
	for _, r := range out.Stored {
		dev.routes[r.RouteID] = oldrules.DeviceRoute{
			PublisherFingerprint: fp, RelayPackID: "rp-addons-001", TransportFamily: r.Family,
			Profile: r.Profile, Endpoint: r.Endpoint, SignedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	moved := fixtureEndpoint()
	moved.Server = "198.51.100.200"
	moved.ServerName = "new-cover.example"
	next := buildAddonPack(t, pub, priv, root, addonPackOpts{packID: "rp-addons-002",
		endpoint: moved, standby: bundle.OpenStandby("203.0.113.20"),
		cdn: cdnFixtureEndpoint(root, "edge9.example.com")})
	_, out = oldImport(t, skeletonOf(t, next, nil), dev, true)
	if out.Refused {
		t.Fatalf("the old freshness merge refused the pack: %s %v", out.Reason, out.Err)
	}
	if out.Merged != 2 {
		t.Fatalf("both direct routes must merge: %+v", out)
	}
	for _, r := range out.Stored {
		if !strings.Contains(string(r.Profile), `"198.51.100.200"`) || !strings.Contains(string(r.Profile), "new-cover.example") {
			t.Fatalf("%s did not move: %s", r.RouteID, r.Profile)
		}
	}
	if len(out.Unavailable) != 1 || out.Unavailable[0].RouteID != "rC" ||
		out.Unavailable[0].Reason != oldrules.UnavailableNoCredentials {
		t.Fatalf("rC: %+v", out.Unavailable)
	}
}

// A future `_cdn_endpoint` (v2, new members) and a future `_standby`
// are as invisible to the old rules as today's.
func TestOldBuild_IgnoresFutureAddonMembers(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	wrapped, _ := bundle.WrapCDNOutbound(cdnFixtureOutbound(t, cdnFixtureEndpoint(root, "edge7.example.com"), root))
	body := buildAddonPack(t, pub, priv, root, addonPackOpts{
		endpoint:   fixtureEndpoint(),
		standby:    map[string]any{"v": 2, "mode": "rotating", "commits": []string{"x"}},
		cdn:        map[string]any{"v": 2, "anything": true},
		cdnProfile: wrapped,
	})
	_, out := oldImport(t, body, &oldDevice{routes: map[string]oldrules.DeviceRoute{}}, false)
	if out.Refused || len(out.Stored) != 2 {
		t.Fatalf("%+v", out)
	}
}

// Why the CDN commitment is NOT in `_endpoint`: the old rules decode it
// strictly, and one unknown member there refuses the WHOLE pack — the
// direct routes and the freshness merge with it.
func TestOldBuild_RefusesCDNMembersInsideEndpoint(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	wrapped, _ := bundle.WrapCDNOutbound(cdnFixtureOutbound(t, cdnFixtureEndpoint(root, "edge7.example.com"), root))
	body := buildAddonPack(t, pub, priv, root, addonPackOpts{
		endpoint: fixtureEndpoint(), cdn: cdnFixtureEndpoint(root, "edge7.example.com"),
		cdnProfile: wrapped, cdnInEndpoint: true,
	})
	_, out := oldImport(t, body, &oldDevice{routes: map[string]oldrules.DeviceRoute{}}, false)
	if !out.Refused || out.Reason != oldrules.ReasonEndpointMalformed {
		t.Fatalf("expected the old rules to refuse the whole pack: %+v", out)
	}
	_, out = oldImport(t, skeletonOf(t, body, nil), &oldDevice{routes: map[string]oldrules.DeviceRoute{}}, true)
	if !out.Refused || out.Reason != oldrules.ReasonEndpointMalformed {
		t.Fatalf("expected the old freshness merge to refuse too: %+v", out)
	}
}
