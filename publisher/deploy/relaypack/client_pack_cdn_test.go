package relaypack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

const cdnMintECH = "AAT+DQAA" // a 2-byte length (4) and four bytes

func cdnMintEndpoint(roots []string, ech string, plain bool) *bundle.CDNEndpoint {
	return &bundle.CDNEndpoint{
		V: bundle.CDNEndpointVersion, Server: "w7.example.com", Port: 443, ServerName: "w7.example.com",
		CDN: bundle.CDNCloudflare, EdgeSeeds: []string{"104.16.0.0/13", "2606:4700::/32"},
		ECHConfig: ech, TLSRootsSHA256: roots, PlainFallback: plain,
	}
}

// buildCDNPack signs a pack with one direct vless-reality route and one
// CDN-fronted websocket-tls route committed by ep.
func buildCDNPack(t *testing.T, ep *bundle.CDNEndpoint) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	from := now.Add(-time.Hour).Format(time.RFC3339)
	until := now.Add(30 * 24 * time.Hour).Format(time.RFC3339)
	direct := map[string]any{"port": 443, "_relaypack": map[string]any{"exposure_mode": "direct_vps"}}
	dep, _ := endpointFor("vless-reality", 443, EndpointMaterialFromParams(fullParams()))
	direct[bundle.EndpointKey] = dep
	cdn := map[string]any{"port": 443, "_relaypack": map[string]any{"exposure_mode": "cdn_fronted"}, bundle.CDNEndpointKey: ep}
	var routes []bundle.RouteManifestEntry
	profiles := map[string][]byte{}
	for i, x := range []struct {
		fam string
		fsc map[string]any
	}{{"vless-reality", direct}, {"websocket-tls", cdn}} {
		id := "r" + string(rune('1'+i))
		cp := "profiles/" + id + ".json"
		b, _ := json.Marshal(x.fsc)
		profiles[cp] = b
		routes = append(routes, bundle.RouteManifestEntry{
			ID: id, ScarcityClass: "normal", TransportFamily: x.fam, ConfigPath: cp,
			ValidFrom: from, ValidUntil: until, FamilySpecificConfig: b,
		})
	}
	m := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{Name: "Test", KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt: from, TrustClass: "community"},
		Bundle: bundle.BundleInfo{ID: "rp-cdn", Type: "provider", CreatedAt: from, ExpiresAt: until},
		Routes: routes,
	}
	sbp, err := bundle.BuildSignedBundle(m, profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return sbp
}

func mintedProfiles(t *testing.T, out []byte) map[string][]byte {
	t.Helper()
	b, err := bundle.ParseSBP(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	return b.Profiles
}

// The shipped root set is what a commitment may list: eight roots at
// most, each a CA, each digest distinct.
func TestCDNShippedRoots(t *testing.T) {
	pems, digests := CDNShippedRoots(), CDNShippedRootDigests()
	if len(pems) == 0 || len(pems) > bundle.MaxTLSRoots || len(pems) != len(digests) {
		t.Fatalf("%d roots, %d digests", len(pems), len(digests))
	}
	seen := map[string]bool{}
	for _, d := range digests {
		if seen[d] {
			t.Fatalf("repeated digest %s", d)
		}
		seen[d] = true
	}
	if got, err := CDNRootDigests([]byte(strings.Join(pems, "\n"))); err != nil || strings.Join(got, ",") != strings.Join(digests, ",") {
		t.Fatalf("the binder's digest of the shipped roots differs: %v %v", got, err)
	}
}

// A CDN-fronted route is minted as a WRAPPED outbound: roots inline,
// the ws Host, the committed ECH configuration; held to its commitment
// by CheckCDNOutbound; and the direct route beside it is minted as
// before.
func TestRewriteProfiles_MintsTheWayInThroughCloudflare(t *testing.T) {
	digests := CDNShippedRootDigests()
	ep := cdnMintEndpoint(digests[:3], cdnMintECH, false)
	p := fullParams()
	p.CDNWSPath = "/c0ffee00112233445566778899aabbcc"
	out, skipped, err := RewriteProfilesForRecipient(buildCDNPack(t, ep), p)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("err=%v skipped=%+v", err, skipped)
	}
	profiles := mintedProfiles(t, out)
	prof := profiles["profiles/r2.json"]
	if bundle.ProfileOutboundType(prof) != "" {
		t.Fatal("the CDN outbound is at the top of the profile: an older build would dial it")
	}
	if !bundle.ProfileUnavailable(prof) {
		t.Fatal("the CDN profile carries no unavailable marker for older builds")
	}
	ob, ok := bundle.CDNProfileOutbound(prof)
	if !ok {
		t.Fatal("no wrapped outbound")
	}
	if err := bundle.CheckCDNOutbound(ep, ob); err != nil {
		t.Fatalf("minted outbound refused by its commitment: %v", err)
	}
	var got struct {
		Server    string `json:"server"`
		UUID      string `json:"uuid"`
		Transport struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"transport"`
		TLS struct {
			Certificate []string `json:"certificate"`
			ECH         struct {
				Enabled bool     `json:"enabled"`
				Config  []string `json:"config"`
			} `json:"ech"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(ob, &got); err != nil {
		t.Fatal(err)
	}
	if got.Server != ep.FirstEdgeAddress() || got.UUID != p.VLESSUUID || got.Transport.Path != p.CDNWSPath ||
		got.Transport.Headers["Host"] != ep.ServerName || len(got.TLS.Certificate) != 3 || !got.TLS.ECH.Enabled ||
		len(got.TLS.ECH.Config) == 0 {
		t.Fatalf("minted outbound: %s", ob)
	}
	if bundle.ProfileOutboundType(profiles["profiles/r1.json"]) != "vless" {
		t.Fatal("the direct route beside it was not minted")
	}
}

// What cannot be minted costs that one route, never the pack: no door
// path, roots this app does not ship, a commitment that is not one.
func TestRewriteProfiles_CDNRouteDegradesAlone(t *testing.T) {
	digests := CDNShippedRootDigests()
	sum := sha256.Sum256([]byte("not a shipped root"))
	unshipped := base64.StdEncoding.EncodeToString(sum[:])
	cases := map[string]struct {
		ep   *bundle.CDNEndpoint
		path string
	}{
		"no door path":    {cdnMintEndpoint(digests[:1], cdnMintECH, false), ""},
		"unshipped roots": {cdnMintEndpoint([]string{unshipped}, cdnMintECH, false), "/p"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := fullParams()
			p.CDNWSPath = c.path
			out, skipped, err := RewriteProfilesForRecipient(buildCDNPack(t, c.ep), p)
			if err != nil {
				t.Fatal(err)
			}
			if len(skipped) != 1 || skipped[0].RouteID != "r2" {
				t.Fatalf("skipped=%+v", skipped)
			}
			profiles := mintedProfiles(t, out)
			if _, ok := bundle.CDNProfileOutbound(profiles["profiles/r2.json"]); ok {
				t.Fatal("a route that could not be minted carries an outbound")
			}
			if bundle.ProfileOutboundType(profiles["profiles/r1.json"]) != "vless" {
				t.Fatal("the direct route was lost with the CDN one")
			}
		})
	}
}

// A commitment signed without ECH (only with plain_fallback) is minted
// without it; one with ECH always carries exactly the committed config.
func TestCDNClientOutbound_PlainOnlyWhenSigned(t *testing.T) {
	digests := CDNShippedRootDigests()
	p := fullParams()
	p.CDNWSPath = "/p"
	ob, err := CDNClientOutbound(cdnMintEndpoint(digests[:1], "", true), p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ob), `"ech"`) {
		t.Fatalf("an ECH block with no committed config: %s", ob)
	}
	if _, err := CDNClientOutbound(cdnMintEndpoint(digests[:1], cdnMintECH, false), ClientConnParams{Server: "x", CDNWSPath: "/p"}); err == nil {
		t.Fatal("minted without the recipient's uuid")
	}
}
