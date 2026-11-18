package relaypack

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
)

var servedFamilies = []string{"vless-reality", "websocket-tls", "naive", "hysteria2", "tuic", "shadowsocks", "anytls"}

// boxCert is a relay's data-plane certificate as cloud-init mints it:
// the first-boot address as an iPAddress SAN, and one stable DNS name.
func boxCert(t *testing.T, ip, dnsName string) (pemText, pin string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "daal-relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP(ip)},
	}
	if dnsName != "" {
		tmpl.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pin, err = bundle.SPKIPinFromCertPEM(pemText)
	if err != nil {
		t.Fatal(err)
	}
	return pemText, pin
}

// allFamilyRelay is one relay serving every family, and one recipient's
// reply from it.
func allFamilyRelay(t *testing.T, pub []byte) (*provider.OperatorRecord, ClientConnParams) {
	t.Helper()
	const ip = "5.75.0.1"
	certPEM, pin := boxCert(t, ip, "cover.example-host.net")
	rec := &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "12345", Region: "fsn1", ServerType: "cx22",
		PublicIP: net.ParseIP(ip), ToolboxProfile: "iran-default",
		PublisherPubKey: append([]byte(nil), pub...),
		CoverSNI:        "cover.example-host.net",
		ProvisionedAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	for _, fam := range servedFamilies {
		pp := relayports.For(fam)
		rec.Candidates = append(rec.Candidates, provider.CandidateMeta{
			Family: fam, ExposureMode: "direct_vps", FamilyClass: "vps-native", ProbingRiskClass: "low",
			Port:           pp.Port,
			PublicRiskTags: []string{"public_ip:" + ip, "public_port:" + fam},
			OriginRiskTags: []string{},
		})
	}
	p := fullParams()
	p.Server = ip
	p.CoverSNI = rec.CoverSNI
	p.TLSCertPEM, p.TLSCertSHA256 = certPEM, pin
	p.SSMethod = "2022-blake3-aes-128-gcm"
	p.SSPassword = "aVBTS2lQU0tpUFNLaVBTSw==:dVBTS3VQU0t1UFNLdVBTSw=="
	p.AnyTLSPassword = "anytlssecretpassword2"
	p.Multiplex = nil
	return rec, p
}

func bindAll(t *testing.T, rec *provider.OperatorRecord, priv []byte, m *EndpointMaterial) *BindResult {
	t.Helper()
	res, err := BindAndSign(rec, priv, BindOpts{
		Now: time.Now().UTC(), Phase: relaypackvalidate.CurrentPhase, Endpoint: m,
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	return res
}

// The contract between the two halves of the publisher: for EVERY
// family, the outbound the minter renders matches the endpoint the
// binder signed. If these ever disagree the minter refuses its own
// pack, so this is the test that has to move with either side.
func TestBindAndSign_CommitsEveryFamilyAndTheMinterMatchesIt(t *testing.T) {
	pub, priv := fixedKey(t, 0x51)
	rec, params := allFamilyRelay(t, pub)
	live := EndpointMaterialFromParams(params)
	res := bindAll(t, rec, priv, &live)
	if len(res.Uncommitted) != 0 {
		t.Fatalf("every family has its material; uncommitted = %+v", res.Uncommitted)
	}

	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("signed pack does not verify: %v", err)
	}
	for _, r := range parsed.Manifest.Routes {
		ep, err := bundle.ParseEndpoint(r.FamilySpecificConfig)
		if err != nil {
			t.Fatalf("route %s (%s): no signed endpoint: %v", r.ID, r.TransportFamily, err)
		}
		if err := ep.Validate(r.TransportFamily); err != nil {
			t.Fatalf("route %s: %v", r.ID, err)
		}
		if ep.Server != "5.75.0.1" || ep.Port != relayports.For(r.TransportFamily).Port {
			t.Errorf("route %s commits to %s:%d", r.ID, ep.Server, ep.Port)
		}
		// The skeleton's own profile holds no outbound and no secret.
		if typ := bundle.ProfileOutboundType(parsed.Profiles[r.ConfigPath]); typ != "" {
			t.Errorf("signed skeleton route %s carries an outbound (%s)", r.ID, typ)
		}
	}
	// Nothing recipient-specific, and no shadowsocks key, in the file
	// that goes on the freshness mirrors.
	for _, secret := range []string{params.VLESSUUID, params.Hy2Password, params.NaivePassword, params.TUICPassword,
		params.AnyTLSPassword, "aVBTS2lQU0tpUFNLaVBTSw==", "dVBTS3VQU0t1UFNLdVBTSw==", params.RealityShortID} {
		for name, body := range parsed.Profiles {
			if bytes.Contains(body, []byte(secret)) {
				t.Errorf("signed skeleton %s contains a secret (%s…)", name, secret[:6])
			}
		}
		raw, _ := json.Marshal(parsed.Manifest)
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("signed manifest contains a secret (%s…)", secret[:6])
		}
	}

	minted, skipped, err := RewriteProfilesForRecipient(res.SBPBytes, params)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("mint: err=%v skipped=%+v", err, skipped)
	}
	got, _ := bundle.ParseSBP(bytes.NewReader(minted), int64(len(minted)))
	for _, r := range got.Manifest.Routes {
		ep, _ := bundle.ParseEndpoint(r.FamilySpecificConfig)
		if err := bundle.CheckOutbound(r.TransportFamily, ep, got.Profiles[r.ConfigPath]); err != nil {
			t.Errorf("route %s (%s): minted outbound does not match the signed endpoint: %v", r.ID, r.TransportFamily, err)
		}
	}
}

// A record that carries no connection material and no live reply
// cannot commit to anything; the pack is not signed.
func TestBindAndSign_RefusesToSignAPackNobodyCouldUse(t *testing.T) {
	pub, priv := fixedKey(t, 0x52)
	rec, _ := allFamilyRelay(t, pub)
	_, err := BindAndSign(rec, priv, BindOpts{Now: time.Now().UTC(), Phase: relaypackvalidate.CurrentPhase})
	if !errors.Is(err, ErrNoEndpointMaterial) {
		t.Fatalf("err=%v, want ErrNoEndpointMaterial", err)
	}
}

// One family's material missing (a relay whose mgmt binary predates
// shadowsocks reports no key) costs that route and only that route —
// and the caller is told.
func TestBindAndSign_DegradesPerRouteWhenMaterialIsMissing(t *testing.T) {
	pub, priv := fixedKey(t, 0x53)
	rec, params := allFamilyRelay(t, pub)
	params.SSPassword, params.SSMethod = "", ""
	live := EndpointMaterialFromParams(params)
	res := bindAll(t, rec, priv, &live)
	if len(res.Uncommitted) != 1 || res.Uncommitted[0].Family != "shadowsocks" || res.Uncommitted[0].Reason == "" {
		t.Fatalf("uncommitted = %+v, want exactly shadowsocks with a reason", res.Uncommitted)
	}
	minted, skipped, err := RewriteProfilesForRecipient(res.SBPBytes, params)
	if err != nil || len(skipped) != 1 || skipped[0].Family != "shadowsocks" {
		t.Fatalf("mint: err=%v skipped=%+v", err, skipped)
	}
	if len(minted) == 0 {
		t.Fatal("no pack")
	}
}

// The record wins wherever it speaks — it is what every rotation verb
// rewrites, while a saved reply is a snapshot that goes stale (a reply
// from before an L2 still names the old cover host). The reply only
// fills what the record has no field for.
func TestEndpointMaterial_Overlay(t *testing.T) {
	rec := EndpointMaterial{Server: "5.75.0.1", CoverSNI: "current.example", RealityPublicKey: "REC", TLSSPKISHA256: ""}
	saved := EndpointMaterial{Server: "9.9.9.9", CoverSNI: "before-l2.example", RealityPublicKey: "LIVE", TLSSPKISHA256: "PIN", SSMethod: "m", SSServerKey: "k"}
	got := rec.Overlay(saved)
	want := EndpointMaterial{Server: "5.75.0.1", CoverSNI: "current.example", RealityPublicKey: "REC", TLSSPKISHA256: "PIN", SSMethod: "m", SSServerKey: "k"}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if rec.CoverSNI = ""; rec.Overlay(saved).CoverSNI != "before-l2.example" {
		t.Fatal("a record with no cover host must take the reply's")
	}
}

// LC-3. After an address move the minted naive outbound dials the new
// address and verifies the relay's certificate against the name that
// does not depend on the address; before one, against the address.
func TestClientOutbound_NaiveVerificationNameFollowsTheCertificate(t *testing.T) {
	certPEM, pin := boxCert(t, "5.75.0.1", "cover.example-host.net")
	p := fullParams()
	p.TLSCertPEM, p.TLSCertSHA256 = certPEM, pin

	render := func() map[string]any {
		raw, err := ClientOutboundForFamily("naive", 8444, p)
		if err != nil {
			t.Fatal(err)
		}
		var ob map[string]any
		if err := json.Unmarshal(raw, &ob); err != nil {
			t.Fatal(err)
		}
		return ob
	}
	p.Server = "5.75.0.1"
	if got := render()["tls"].(map[string]any)["server_name"]; got != "5.75.0.1" {
		t.Fatalf("on the certificate's own address the name must stay the address (nothing new on the wire); got %v", got)
	}
	p.Server = "203.0.113.200" // the floating address
	ob := render()
	if ob["server"] != "203.0.113.200" {
		t.Fatalf("server = %v", ob["server"])
	}
	if got := ob["tls"].(map[string]any)["server_name"]; got != "cover.example-host.net" {
		t.Fatalf("after an address move naive must verify against the certificate's DNS name; got %v", got)
	}
	// And that outbound matches what bind-and-sign commits for the new
	// address, so the minter accepts it.
	ep, why := endpointFor("naive", 8444, EndpointMaterialFromParams(p))
	if ep == nil {
		t.Fatal(why)
	}
	raw, _ := json.Marshal(ob)
	if err := bundle.CheckOutbound("naive", ep, raw); err != nil {
		t.Fatal(err)
	}
}
