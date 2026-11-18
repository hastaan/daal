package abi

// The recipient side of the signed endpoint commitment, on the
// production ABI: ImportSBP, ResolveTrustPrompt, AvailableRoutes,
// SetRoute. The fixture is real publisher output (freshness_wire_test.go
// says how it is minted); every alteration below is a plain zip rewrite
// with no key, manifest.sig copied through untouched — what somebody who
// intercepted the file can do.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/routestore"
	"daal/core/trust"
)

func fixturePack(t *testing.T) (*bundle.Bundle, []byte) {
	t.Helper()
	body, err := os.ReadFile(freshnessFixture)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	return parsed, body
}

func rewriteProfileField(t *testing.T, profile []byte, path string, value any) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(profile, &doc); err != nil {
		t.Fatal(err)
	}
	cur := doc
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			t.Fatalf("profile has no %q", p)
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
	out, _ := json.Marshal(doc)
	return string(out)
}

func routeOf(t *testing.T, parsed *bundle.Bundle, family string) bundle.RouteManifestEntry {
	t.Helper()
	for _, r := range parsed.Manifest.Routes {
		if r.TransportFamily == family {
			return r
		}
	}
	t.Fatalf("fixture has no %s route", family)
	return bundle.RouteManifestEntry{}
}

// F-004 through the ABI. A pack whose outbound was rewritten after
// signing is REJECTED by ImportSBP — not turned into a trust prompt —
// and leaves nothing behind: no pending prompt, no route.
func TestImportSBP_RefusesAPackWhoseEndpointWasRewritten(t *testing.T) {
	parsed, body := fixturePack(t)
	reality := routeOf(t, parsed, "vless-reality")
	ws := routeOf(t, parsed, "websocket-tls")
	cases := []struct {
		name  string
		route bundle.RouteManifestEntry
		path  string
		value any
	}{
		{"server", reality, "server", "198.51.100.66"},
		{"port", reality, "server_port", 8443},
		{"REALITY public key", reality, "tls.reality.public_key", "YXR0YWNrZXItcmVhbGl0eS1wdWJsaWMta2V5LTMyYg"},
		{"TLS key pin", ws, "tls.certificate_public_key_sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := Init(dir, "warn"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { Shutdown() })
			tampered := rewriteArchiveEntry(t, body, tc.route.ConfigPath,
				rewriteProfileField(t, parsed.Profiles[tc.route.ConfigPath], tc.path, tc.value))
			path := dir + "/tampered.sbp"
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := ImportSBP(path)
			var v importer.Verdict
			_ = json.Unmarshal([]byte(out), &v)
			if err == nil || v.Kind != importer.VerdictRejected || v.Reason != importer.ReasonEndpointMismatch {
				t.Fatalf("a pack with a rewritten %s was not refused: err=%v verdict=%s", tc.name, err, out)
			}
			if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err == nil {
				t.Fatal("the refused pack left a trust prompt that could still be answered")
			}
			routes, _ := mustCore().store.ListRoutes()
			if len(routes) != 0 {
				t.Fatalf("the refused pack left %d route(s) behind", len(routes))
			}
		})
	}
}

// F-003 through the ABI. A route the minter marked as dropped is not a
// route on the device: AvailableRoutes does not list it and SetRoute
// cannot activate it. The import verdict names it with a reason.
func TestDroppedRouteIsNeitherListedNorActivatable(t *testing.T) {
	parsed, body := fixturePack(t)
	dropped := routeOf(t, parsed, "hysteria2")
	marker := `{"port":443,"_relaypack":{},"_daal_unavailable":{"family":"hysteria2","reason":"hysteria2 needs hy2_password"}}`
	pack := rewriteArchiveEntry(t, body, dropped.ConfigPath, marker)

	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	path := dir + "/pack.sbp"
	if err := os.WriteFile(path, pack, 0o600); err != nil {
		t.Fatal(err)
	}
	v := importFixture(t, path)
	if v.Kind != importer.VerdictTrustPromptNeeded || v.RouteCount != len(parsed.Manifest.Routes)-1 {
		t.Fatalf("prompt verdict: %+v", v)
	}
	out, err := ResolveTrustPrompt(v.Fingerprint, 0)
	if err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}
	var done importer.Verdict
	_ = json.Unmarshal([]byte(out), &done)
	if len(done.Unavailable) != 1 || done.Unavailable[0].RouteID != dropped.ID ||
		done.Unavailable[0].Reason != importer.UnavailableNotOffered {
		t.Fatalf("the verdict must name the dropped route: %s", out)
	}

	listed, err := AvailableRoutes()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal([]byte(listed), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Routes) != len(parsed.Manifest.Routes)-1 {
		t.Fatalf("AvailableRoutes lists %d routes, want %d: %s", len(doc.Routes), len(parsed.Manifest.Routes)-1, listed)
	}
	if strings.Contains(listed, `"`+dropped.ID+`"`) || strings.Contains(listed, "hysteria2") {
		t.Fatalf("the dropped route is offered for selection: %s", listed)
	}
	if err := SetRoute(dropped.ID); err == nil {
		t.Fatal("the dropped route could be activated")
	}
}

type fakeSecrets map[string][]byte

func (f fakeSecrets) GetSecret(k string) ([]byte, error) {
	v, ok := f[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

// The last gate before the engine dials: whatever wrote the profile,
// it must match the endpoint the import stored.
func TestRouteEndpointGuard(t *testing.T) {
	parsed, _ := fixturePack(t)
	r := routeOf(t, parsed, "vless-reality")
	profile := parsed.Profiles[r.ConfigPath]
	ep, err := bundle.ParseEndpoint(r.FamilySpecificConfig)
	if err != nil {
		t.Fatal(err)
	}
	epJSON, _ := json.Marshal(ep)
	row := routestore.RouteRow{RouteID: r.ID, TransportFamily: r.TransportFamily, RelayPackID: "rp-x"}
	stored := fakeSecrets{trust.RouteEndpointKey(r.ID): epJSON}

	if err := routeEndpointGuard(stored, row, profile); err != nil {
		t.Fatalf("genuine route refused: %v", err)
	}
	// The stored profile was changed behind the importer's back.
	moved := []byte(rewriteProfileField(t, profile, "server", "198.51.100.66"))
	if err := routeEndpointGuard(stored, row, moved); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("a profile pointing somewhere else was not refused: %v", err)
	}
	// A RelayPack route with no stored commitment cannot say where it
	// points.
	if err := routeEndpointGuard(fakeSecrets{}, row, profile); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("a RelayPack route with no signed endpoint was not refused: %v", err)
	}
	// An unreadable commitment is not "no commitment".
	if err := routeEndpointGuard(fakeSecrets{trust.RouteEndpointKey(r.ID): []byte("{")}, row, profile); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("garbage commitment: %v", err)
	}
	// A route that is not part of a RelayPack (a pasted URI, a
	// subscription) has no commitment and is not this gate's business.
	plain := routestore.RouteRow{RouteID: "uri-1", TransportFamily: "vless-reality"}
	if err := routeEndpointGuard(fakeSecrets{}, plain, moved); err != nil {
		t.Fatalf("non-RelayPack route refused: %v", err)
	}
}

// SetRoute itself applies the gate, and a refusal is not recorded as a
// failure of the route (it is not the network's doing).
func TestSetRoute_RefusesAProfileThatNoLongerMatchesItsSignedEndpoint(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	v := importFixture(t, freshnessFixture)
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatal(err)
	}
	c := mustCore()
	rows, _ := c.store.ListRoutes()
	var target routestore.RouteRow
	for _, row := range rows {
		if row.TransportFamily == "vless-reality" {
			target = row
		}
	}
	profile, err := c.store.GetSecret("route:" + target.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.PutSecret("route:"+target.RouteID,
		[]byte(rewriteProfileField(t, profile, "server", "198.51.100.66"))); err != nil {
		t.Fatal(err)
	}
	err = SetRoute(target.RouteID)
	if !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("SetRoute dialled a profile that does not match its signed endpoint: err=%v", err)
	}
	after, _ := c.store.GetRoute(target.RouteID)
	if after.ConsecutiveFailures != 0 || after.LastFailureCategory != "" {
		t.Fatalf("the refusal was recorded as a route failure: %+v", after)
	}
}
