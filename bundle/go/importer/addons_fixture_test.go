package importer_test

// Fixtures for the optional add-ons' pack members (`_standby`,
// `_cdn_endpoint`): one relay, two direct vless-reality routes carrying
// a sealed standby, and one CDN-fronted websocket-tls route. Used by
// addons_test.go (this build) and compat_old_test.go (the rules phones
// already run).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// addonStandbyKey is the vector key of specs/relaypack-v1.md: salt
// 00..0b, address 203.0.113.20.
func addonStandbyKey() bundle.StandbyKeyBytes {
	var k bundle.StandbyKeyBytes
	for i := 0; i < bundle.StandbySaltLen; i++ {
		k[i] = byte(i)
	}
	copy(k[bundle.StandbySaltLen:], []byte{203, 0, 113, 20})
	return k
}

// testRoot is a self-signed certificate standing in for a root the app
// ships; its SPKI digest is what the CDN commitment lists.
type testRoot struct {
	PEM    string
	Digest string
}

func newTestRoot(t *testing.T) testRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pin, err := bundle.SPKIPinFromCertPEM(pemText)
	if err != nil {
		t.Fatal(err)
	}
	return testRoot{PEM: pemText, Digest: pin}
}

func cdnFixtureEndpoint(root testRoot, name string) bundle.CDNEndpoint {
	return bundle.CDNEndpoint{
		V: 1, Server: name, Port: 443, ServerName: name, CDN: bundle.CDNCloudflare,
		EdgeSeeds:      []string{"104.16.0.0/13"},
		ECHConfig:      base64.StdEncoding.EncodeToString([]byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00}),
		TLSRootsSHA256: []string{root.Digest},
	}
}

func cdnFixtureOutbound(t *testing.T, ep bundle.CDNEndpoint, root testRoot) []byte {
	t.Helper()
	ob := map[string]any{
		"type": "vless", "tag": "active", "server": "104.16.1.2", "server_port": ep.Port,
		"uuid":      "77777777-2222-3333-4444-555555555555",
		"transport": map[string]any{"type": "ws", "path": "/fedcba9876543210", "headers": map[string]any{"Host": ep.ServerName}},
		"tls": map[string]any{"enabled": true, "server_name": ep.ServerName,
			"certificate": []string{root.PEM},
			"ech":         map[string]any{"enabled": true, "config": ep.ECHConfigPEM()}},
	}
	raw, err := json.Marshal(ob)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// addonPackOpts says what goes into one fixture pack.
type addonPackOpts struct {
	packID   string
	endpoint bundle.Endpoint // the direct routes' commitment
	standby  any             // the direct routes' `_standby`; nil = none
	cdn      any             // rC's `_cdn_endpoint`; nil = no rC at all
	// cdnProfile is rC's profile; nil = the wrapped outbound for cdn.
	cdnProfile []byte
	// cdnInEndpoint puts the CDN members INSIDE `_endpoint` instead —
	// the carrier the plan first proposed — to show what older builds
	// do with it.
	cdnInEndpoint bool
}

// buildAddonPack signs a RelayPack of one relay: rA and rB are direct
// vless-reality routes (fixtureEndpoint, fixtureOutbound), rC is a
// CDN-fronted websocket-tls route.
func buildAddonPack(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, root testRoot, o addonPackOpts) []byte {
	t.Helper()
	now := time.Now().UTC()
	if o.packID == "" {
		o.packID = "rp-addons-001"
	}
	m := bundle.Manifest{
		SpecVersion: 3,
		Publisher: bundle.PublisherInfo{
			Name: "Add-ons Test", KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt: now.Format(time.RFC3339), TrustClass: "unknown",
		},
		Bundle: bundle.BundleInfo{
			ID: "bundle-addons", Type: "provider", CreatedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), SupersedesKeys: []string{},
		},
		RelayPack: &bundle.RelayPack{RelayPackID: o.packID},
	}
	direct := bundle.RelayPackEntry{
		ExposureMode: "direct_vps", FamilyClass: "vps-native", ProbingRiskClass: "low",
		PublicRiskTags: []string{"public_ip:5.75.0.1", "public_asn:24940"}, OriginRiskTags: []string{},
	}
	profiles := map[string][]byte{}
	members := []string{}
	for _, id := range []string{"rA", "rB"} {
		fc := map[string]any{"_relaypack": direct, bundle.EndpointKey: o.endpoint,
			"_desync": map[string]any{"v": 1}}
		if o.standby != nil {
			fc[bundle.StandbyKey] = o.standby
		}
		raw, _ := json.Marshal(fc)
		m.Routes = append(m.Routes, bundle.RouteManifestEntry{
			ID: id, ScarcityClass: "normal", TransportFamily: "vless-reality",
			ConfigPath: "profiles/" + id + ".json", ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339),
			FamilySpecificConfig: raw,
		})
		profiles["profiles/"+id+".json"] = fixtureOutbound()
		members = append(members, id)
	}
	if o.cdn != nil {
		cdnEntry := bundle.RelayPackEntry{
			ExposureMode: "cdn_fronted", FamilyClass: "vps-native", ProbingRiskClass: "low",
			PublicRiskTags: []string{"cdn:cloudflare"}, OriginRiskTags: []string{"origin_ip:5.75.0.1"},
		}
		fc := map[string]any{"_relaypack": cdnEntry,
			"_cdn_attestation": map[string]any{"origin_ca_fingerprint": "ab12cd34", "aop_enabled": true,
				"firewall_id": "fw-1", "dns_only_present": false}}
		if o.cdnInEndpoint {
			fc[bundle.EndpointKey] = o.cdn
		} else {
			fc[bundle.CDNEndpointKey] = o.cdn
		}
		raw, _ := json.Marshal(fc)
		m.Routes = append(m.Routes, bundle.RouteManifestEntry{
			ID: "rC", ScarcityClass: "normal", TransportFamily: "websocket-tls",
			ConfigPath: "profiles/rC.json", ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339),
			FamilySpecificConfig: raw,
		})
		prof := o.cdnProfile
		if prof == nil {
			ep, ok := o.cdn.(bundle.CDNEndpoint)
			if !ok {
				t.Fatal("cdnProfile must be given for a non-CDNEndpoint cdn member")
			}
			w, err := bundle.WrapCDNOutbound(cdnFixtureOutbound(t, ep, root))
			if err != nil {
				t.Fatal(err)
			}
			prof = w
		}
		profiles["profiles/rC.json"] = prof
		members = append(members, "rC")
	}
	m.RelayPack.SharedRiskGraph = []bundle.SharedRiskEdge{{Tag: "public_ip:5.75.0.1", Members: members}}
	body, err := bundle.BuildSignedBundle(m, profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// defaultAddonPack is the pack every add-on test starts from: sealed
// standby on the direct routes, a CDN route named edge7.example.com.
func defaultAddonPack(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, root testRoot) []byte {
	return buildAddonPack(t, pub, priv, root, addonPackOpts{
		endpoint: fixtureEndpoint(),
		standby:  bundle.SealedStandby(addonStandbyKey()),
		cdn:      cdnFixtureEndpoint(root, "edge7.example.com"),
	})
}
