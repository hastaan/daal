package relaypack

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/provider"
)

// cdnTestECH is a well-formed ECHConfigList for the commitment's shape
// check: a 2-byte length (4) and four bytes.
const cdnTestECH = "AAT+DQAA"

const cdnTestAppsScriptURL = "https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA"

func cdnTestRec(pub ed25519.PublicKey) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "12345", ServerType: "cx22", Region: "fsn1",
		ToolboxProfile: "iran-default",
		PublicIP:       net.ParseIP("5.75.0.1"), RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin,
		PublisherPubKey: pub,
		Candidates: []provider.CandidateMeta{{
			Family: "vless-reality", ExposureMode: "direct_vps", FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 443,
			PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:tcp443"}, OriginRiskTags: []string{},
		}},
	}
}

func cdnTestRootPEM(t *testing.T) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test edge root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func cdnTestFront(t *testing.T) *CDNFront {
	t.Helper()
	roots, err := CDNRootDigests(cdnTestRootPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	return &CDNFront{
		Front: &cloudflare.FrontRecord{
			Hostname:            "Door.Example.org",
			OriginPath:          "/0123456789abcdef0123456789abcdef",
			FirewallID:          "fw-1234",
			OriginCAFingerprint: "ababababababababababababababababababababababababababababababab",
			AOPEnabled:          true,
			ECH:                 cloudflare.ECHPosture{ZoneSetting: "on", Published: true, ConfigListB64: cdnTestECH, PublicName: "cloudflare-ech.com"},
		},
		EdgeSeeds:      []string{"104.16.0.1/13", "2606:4700::/32"},
		TLSRootsSHA256: roots,
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
