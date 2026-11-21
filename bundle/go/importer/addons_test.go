package importer_test

// This build's import rules for the optional add-ons' members:
// `_standby` (S2) and the CDN-fronted endpoint (B-4).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
)

func savedByID(t *testing.T, st *deviceState) map[string]importer.RouteInput {
	t.Helper()
	if len(st.saved) == 0 {
		t.Fatal("nothing saved")
	}
	out := map[string]importer.RouteInput{}
	for _, r := range st.saved[len(st.saved)-1] {
		out[r.RouteID] = r
	}
	return out
}

func TestImport_AddonPack_StoresEveryRoute(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	body := defaultAddonPack(t, pub, priv, root)
	st := newDeviceState()
	mustImport(t, st, body)
	got := savedByID(t, st)
	if len(got) != 3 {
		t.Fatalf("want rA, rB, rC stored; got %d", len(got))
	}
	// The direct routes keep their `_standby`, beside the commitment and
	// NOT on the row (EngineConfig).
	for _, id := range []string{"rA", "rB"} {
		r := got[id]
		sb, err := bundle.ParseStandbyJSON(r.Standby)
		if err != nil || !sb.Matches(addonStandbyKey()) {
			t.Fatalf("%s: standby not carried: %s %v", id, r.Standby, err)
		}
		if strings.Contains(r.EngineConfig, "_standby") || !strings.Contains(r.EngineConfig, "_desync") {
			t.Fatalf("%s: engine row config %q", id, r.EngineConfig)
		}
	}
	// The CDN route is stored UNWRAPPED, held to its CDN commitment.
	c := got["rC"]
	if bundle.ProfileOutboundType(c.Profile) != "vless" || !bundle.IsCDNCommitment(c.Endpoint) || c.Standby != nil {
		t.Fatalf("rC stored as %s / %s / standby %s", c.Profile, c.Endpoint, c.Standby)
	}
	cep, err := bundle.ParseCDNEndpointJSON("websocket-tls", c.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.CheckCDNOutbound(cep, c.Profile); err != nil {
		t.Fatalf("stored CDN outbound does not match its commitment: %v", err)
	}
	if c.RelayPack == nil || c.RelayPack.ExposureMode != "cdn_fronted" {
		t.Fatalf("rC relay pack meta: %+v", c.RelayPack)
	}
}

// A CDN outbound rewritten in transit refuses the whole pack, as for any
// direct route: it is evidence the file was altered.
func TestImport_TamperedCDNOutboundIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	genuine := defaultAddonPack(t, pub, priv, root)
	for name, edit := range map[string]func(ob map[string]any){
		"edge outside the seeds": func(ob map[string]any) { ob["server"] = "198.51.100.66" },
		"tls name":               func(ob map[string]any) { ob["tls"].(map[string]any)["server_name"] = "attacker.example" },
		"ECH dropped":            func(ob map[string]any) { delete(ob["tls"].(map[string]any), "ech") },
		"insecure":               func(ob map[string]any) { ob["tls"].(map[string]any)["insecure"] = true },
	} {
		tampered := repack(t, genuine, func(p map[string][]byte) {
			var w map[string]json.RawMessage
			_ = json.Unmarshal(p["profiles/rC.json"], &w)
			var ob map[string]any
			_ = json.Unmarshal(w[bundle.CDNOutboundKey], &ob)
			edit(ob)
			w[bundle.CDNOutboundKey], _ = json.Marshal(ob)
			p["profiles/rC.json"], _ = json.Marshal(w)
		})
		st := newDeviceState()
		v, err := importer.ImportBytes(tampered, st, wordlists(), time.Now().UTC())
		if err == nil || v.Reason != importer.ReasonEndpointMismatch || st.saveCalls != 0 {
			t.Fatalf("%s: verdict=%+v err=%v", name, v, err)
		}
	}
}

// A `_cdn_endpoint` this build cannot read costs that route, not the
// pack: it is signed, so it is a newer publisher.
func TestImport_NewerCDNEndpointCostsOneRoute(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	ep := cdnFixtureEndpoint(root, "edge7.example.com")
	future := map[string]any{}
	raw, _ := json.Marshal(ep)
	_ = json.Unmarshal(raw, &future)
	future["v"] = 2
	future["edge_pick"] = "probe-first"
	wrapped, _ := bundle.WrapCDNOutbound(cdnFixtureOutbound(t, ep, root))
	body := buildAddonPack(t, pub, priv, root, addonPackOpts{
		endpoint: fixtureEndpoint(), cdn: future, cdnProfile: wrapped,
	})
	st := newDeviceState()
	mustImport(t, st, body)
	got := savedByID(t, st)
	if len(got) != 2 || got["rC"].RouteID != "" {
		t.Fatalf("want rA, rB only; got %v", got)
	}
	v, err := importer.ImportBytes(body, st, wordlists(), time.Now().UTC())
	if err != nil || len(v.Unavailable) != 1 || v.Unavailable[0].Reason != importer.UnavailableNeedsNewerApp {
		t.Fatalf("verdict %+v %v", v, err)
	}
}

// A route with both carriers is a publisher error; it is refused rather
// than guessed at.
func TestImport_BothCarriersIsMalformed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	body := buildAddonPack(t, pub, priv, root, addonPackOpts{endpoint: fixtureEndpoint(),
		cdn: cdnFixtureEndpoint(root, "edge7.example.com")})
	// Re-sign with rC carrying a valid direct `_endpoint` too.
	parsed, _ := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	m := parsed.Manifest
	for i := range m.Routes {
		if m.Routes[i].ID == "rC" {
			var fc map[string]any
			_ = json.Unmarshal(m.Routes[i].FamilySpecificConfig, &fc)
			fc[bundle.EndpointKey] = bundle.Endpoint{V: 1, Server: "5.75.0.1", Port: 443, TLSSPKISHA256: root.Digest}
			m.Routes[i].FamilySpecificConfig, _ = json.Marshal(fc)
		}
	}
	both, err := bundle.BuildSignedBundle(m, parsed.Profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := importer.ImportBytes(both, newDeviceState(), wordlists(), time.Now().UTC())
	if err == nil || v.Reason != importer.ReasonEndpointMalformed {
		t.Fatalf("verdict %+v %v", v, err)
	}
}

// The freshness path: a signed skeleton that moves the CDN route to a
// new name merges into the device's CDN outbound and keeps its
// credentials; the direct routes merge as before.
func TestApplyVerifiedRefresh_MergesCDNEndpoint(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	st := newDeviceState()
	mustImport(t, st, defaultAddonPack(t, pub, priv, root))

	moved := fixtureEndpoint()
	moved.Server = "198.51.100.200"
	newCDN := cdnFixtureEndpoint(root, "edge9.example.com")
	next := buildAddonPack(t, pub, priv, root, addonPackOpts{packID: "rp-addons-002",
		endpoint: moved, standby: bundle.OpenStandby("203.0.113.20"), cdn: newCDN})
	skeleton := skeletonOf(t, next, nil)
	sum := sha256.Sum256(skeleton)
	v, err := importer.ApplyVerifiedRefresh(skeleton, hex.EncodeToString(sum[:]), st, wordlists(), time.Now().UTC())
	if err != nil || v.Kind != importer.VerdictImported || v.Merged != 3 {
		t.Fatalf("refresh: %+v %v", v, err)
	}
	got := savedByID(t, st)
	c := got["rC"]
	cep, _ := bundle.ParseCDNEndpointJSON("websocket-tls", c.Endpoint)
	if cep == nil || cep.Server != "edge9.example.com" || bundle.CheckCDNOutbound(cep, c.Profile) != nil {
		t.Fatalf("rC not merged to the new name: %s", c.Profile)
	}
	if !strings.Contains(string(c.Profile), "77777777-2222-3333-4444-555555555555") {
		t.Fatal("rC credentials lost")
	}
	// The newer commitment's open standby replaced the sealed one.
	if sb, err := bundle.ParseStandbyJSON(got["rA"].Standby); err != nil || sb.Mode != bundle.StandbyModeOpen {
		t.Fatalf("rA standby: %s %v", got["rA"].Standby, err)
	}
	// A newer commitment with no `_standby` leaves none.
	third := buildAddonPack(t, pub, priv, root, addonPackOpts{packID: "rp-addons-003", endpoint: moved, cdn: newCDN})
	skeleton = skeletonOf(t, third, nil)
	sum = sha256.Sum256(skeleton)
	if v, err := importer.ApplyVerifiedRefresh(skeleton, hex.EncodeToString(sum[:]), st, wordlists(), time.Now().UTC()); err != nil || v.Merged != 3 {
		t.Fatalf("third: %+v %v", v, err)
	}
	if s := savedByID(t, st)["rA"].Standby; s != nil {
		t.Fatalf("a commitment without _standby must store none: %s", s)
	}
}

// The amended endpoint rule on import: an outbound may sit at the open
// standby; at any other address the pack is refused. Shadowsocks never
// gets a standby.
func TestImport_OutboundAtOpenStandby(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := newTestRoot(t)
	open := buildAddonPack(t, pub, priv, root, addonPackOpts{endpoint: fixtureEndpoint(),
		standby: bundle.OpenStandby("203.0.113.20")})
	atStandby := repack(t, open, func(p map[string][]byte) {
		p["profiles/rA.json"] = setField(t, p["profiles/rA.json"], "server", "203.0.113.20")
	})
	st := newDeviceState()
	mustImport(t, st, atStandby)
	elsewhere := repack(t, open, func(p map[string][]byte) {
		p["profiles/rA.json"] = setField(t, p["profiles/rA.json"], "server", "203.0.113.99")
	})
	if v, err := importer.ImportBytes(elsewhere, newDeviceState(), wordlists(), time.Now().UTC()); err == nil || v.Reason != importer.ReasonEndpointMismatch {
		t.Fatalf("third address: %+v %v", v, err)
	}
	// Sealed: no key is held at import, so the standby address is refused.
	sealed := buildAddonPack(t, pub, priv, root, addonPackOpts{endpoint: fixtureEndpoint(),
		standby: bundle.SealedStandby(addonStandbyKey())})
	atSealed := repack(t, sealed, func(p map[string][]byte) {
		p["profiles/rA.json"] = setField(t, p["profiles/rA.json"], "server", "203.0.113.20")
	})
	if v, err := importer.ImportBytes(atSealed, newDeviceState(), wordlists(), time.Now().UTC()); err == nil || v.Reason != importer.ReasonEndpointMismatch {
		t.Fatalf("sealed standby without a key: %+v %v", v, err)
	}
	// A malformed `_standby` is absent: the pack imports, no standby.
	broken := buildAddonPack(t, pub, priv, root, addonPackOpts{endpoint: fixtureEndpoint(),
		standby: map[string]any{"v": 9, "mode": "open", "server": "203.0.113.20"}})
	st = newDeviceState()
	mustImport(t, st, broken)
	if s := savedByID(t, st)["rA"].Standby; s != nil {
		t.Fatalf("malformed standby kept: %s", s)
	}
	if !errors.Is(func() error { _, e := bundle.ParseStandbyJSON([]byte(`{"v":9}`)); return e }(), bundle.ErrStandbyMalformed) {
		t.Fatal("sanity")
	}
}
