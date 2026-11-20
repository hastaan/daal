package abi

// The set-route gate for the optional add-ons' commitments: a direct
// route may be dialled at its standby (open, or sealed with a matching
// key the device holds) and nowhere else; a CDN-fronted route is held
// to its CDN commitment.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/routestore"
	"daal/core/trust"
)

func guardRealityOutbound(server string) []byte {
	return []byte(`{"type":"vless","server":"` + server + `","server_port":443,"uuid":"u",` +
		`"tls":{"enabled":true,"server_name":"cover.example","reality":{"enabled":true,"public_key":"rpk","short_id":"ab"}}}`)
}

func TestRouteEndpointGuard_Standby(t *testing.T) {
	ep := bundle.Endpoint{V: 1, Server: "198.51.100.10", Port: 443, ServerName: "cover.example", RealityPublicKey: "rpk"}
	epJSON, _ := json.Marshal(ep)
	var key bundle.StandbyKeyBytes
	copy(key[bundle.StandbySaltLen:], []byte{203, 0, 113, 20})
	sealed, _ := json.Marshal(bundle.SealedStandby(key))
	open, _ := json.Marshal(bundle.OpenStandby("203.0.113.20"))
	row := routestore.RouteRow{RouteID: "rA", TransportFamily: "vless-reality", RelayPackID: "rp-x"}
	base := func(extra map[string][]byte) fakeSecrets {
		s := fakeSecrets{trust.RouteEndpointKey("rA"): epJSON}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	atStandby := guardRealityOutbound("203.0.113.20")

	// Committed server: always fine.
	if err := routeEndpointGuard(base(nil), row, guardRealityOutbound("198.51.100.10")); err != nil {
		t.Fatal(err)
	}
	// Open standby.
	if err := routeEndpointGuard(base(map[string][]byte{bundle.StandbyStoreKey("rA"): open}), row, atStandby); err != nil {
		t.Fatalf("open standby: %v", err)
	}
	if a, ok := routeStandbyAddress(base(map[string][]byte{bundle.StandbyStoreKey("rA"): open}), row); !ok || a != "203.0.113.20" {
		t.Fatalf("open standby address: %q %v", a, ok)
	}
	// Sealed, no key: refused; with the matching key: fine.
	sealedOnly := base(map[string][]byte{bundle.StandbyStoreKey("rA"): sealed})
	if err := routeEndpointGuard(sealedOnly, row, atStandby); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("sealed without a key: %v", err)
	}
	if _, ok := routeStandbyAddress(sealedOnly, row); ok {
		t.Fatal("sealed without a key gave an address")
	}
	withKey := base(map[string][]byte{bundle.StandbyStoreKey("rA"): sealed, bundle.StandbyKeyStoreKey("rA"): key[:]})
	if err := routeEndpointGuard(withKey, row, atStandby); err != nil {
		t.Fatalf("sealed with its key: %v", err)
	}
	if a, ok := routeStandbyAddress(withKey, row); !ok || a != "203.0.113.20" {
		t.Fatalf("sealed standby address: %q %v", a, ok)
	}
	// A key for another address cannot open it.
	forged := key
	forged[15] = 99
	forgedStore := base(map[string][]byte{bundle.StandbyStoreKey("rA"): sealed, bundle.StandbyKeyStoreKey("rA"): forged[:]})
	if err := routeEndpointGuard(forgedStore, row, guardRealityOutbound("203.0.113.99")); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("forged key: %v", err)
	}
	// Any third address, and a garbage standby, are refused.
	if err := routeEndpointGuard(base(map[string][]byte{bundle.StandbyStoreKey("rA"): open}), row, guardRealityOutbound("203.0.113.99")); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("third address: %v", err)
	}
	if err := routeEndpointGuard(base(map[string][]byte{bundle.StandbyStoreKey("rA"): []byte("{")}), row, atStandby); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("garbage standby: %v", err)
	}
	// Never for shadowsocks.
	ssEP, _ := json.Marshal(bundle.Endpoint{V: 1, Server: "198.51.100.10", Port: 8388,
		SSMethod: "2022-blake3-aes-128-gcm", SSServerKeySHA256: bundle.SSServerKeyDigest("ipsk")})
	ssRow := routestore.RouteRow{RouteID: "rS", TransportFamily: "shadowsocks", RelayPackID: "rp-x"}
	ssStore := fakeSecrets{trust.RouteEndpointKey("rS"): ssEP, bundle.StandbyStoreKey("rS"): open}
	ss := []byte(`{"type":"shadowsocks","server":"203.0.113.20","server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"ipsk:upsk"}`)
	if err := routeEndpointGuard(ssStore, ssRow, ss); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("shadowsocks at the standby: %v", err)
	}
	if _, ok := routeStandbyAddress(ssStore, ssRow); ok {
		t.Fatal("shadowsocks got a standby address")
	}
}

func guardRoot(t *testing.T) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pin, _ := bundle.SPKIPinFromCertPEM(p)
	return p, pin
}

func TestRouteEndpointGuard_CDN(t *testing.T) {
	rootPEM, pin := guardRoot(t)
	cep := bundle.CDNEndpoint{V: 1, Server: "edge7.example.com", Port: 443, ServerName: "edge7.example.com",
		CDN: bundle.CDNCloudflare, EdgeSeeds: []string{"104.16.0.0/13"},
		ECHConfig:      base64.StdEncoding.EncodeToString([]byte{0, 2, 1, 2}),
		TLSRootsSHA256: []string{pin}}
	cepJSON, _ := json.Marshal(cep)
	mk := func(server, name string) []byte {
		raw, _ := json.Marshal(map[string]any{"type": "vless", "server": server, "server_port": 443, "uuid": "u",
			"transport": map[string]any{"type": "ws", "path": "/p", "headers": map[string]any{"Host": "edge7.example.com"}},
			"tls": map[string]any{"enabled": true, "server_name": name, "certificate": []string{rootPEM},
				"ech": map[string]any{"enabled": true, "config": cep.ECHConfigPEM()}}})
		return raw
	}
	row := routestore.RouteRow{RouteID: "rC", TransportFamily: "websocket-tls", RelayPackID: "rp-x"}
	st := fakeSecrets{trust.RouteEndpointKey("rC"): cepJSON}
	if err := routeEndpointGuard(st, row, mk("104.16.1.2", "edge7.example.com")); err != nil {
		t.Fatalf("genuine CDN outbound: %v", err)
	}
	if err := routeEndpointGuard(st, row, mk("198.51.100.66", "edge7.example.com")); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("edge outside the seeds: %v", err)
	}
	if err := routeEndpointGuard(st, row, mk("104.16.1.2", "other.example.com")); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("other name: %v", err)
	}
	// A stored CDN commitment on a row of another family, or one this
	// build cannot read, is refused, not treated as absent.
	if err := routeEndpointGuard(st, routestore.RouteRow{RouteID: "rC", TransportFamily: "vless-reality", RelayPackID: "rp-x"}, mk("104.16.1.2", "edge7.example.com")); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("wrong family: %v", err)
	}
	bad := fakeSecrets{trust.RouteEndpointKey("rC"): []byte(`{"v":2,"cdn":"cloudflare"}`)}
	if err := routeEndpointGuard(bad, row, mk("104.16.1.2", "edge7.example.com")); !errors.Is(err, ErrRouteEndpoint) {
		t.Fatalf("unreadable CDN commitment: %v", err)
	}
	if _, ok := routeStandbyAddress(st, row); ok {
		t.Fatal("a CDN route has no standby")
	}
}
