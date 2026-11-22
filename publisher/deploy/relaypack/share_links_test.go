package relaypack

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/uri"
)

// shareCert is a self-signed leaf standing in for the relay's data-plane
// certificate: hysteria2's link pin is computed from it.
func shareCert(t *testing.T) (pemText string, der []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("78.47.152.16")},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der
}

// shareParams is one person's material with values every importer
// accepts: a real 32-byte base64url REALITY key, a hex short id, a real
// certificate whose SPKI is the pin.
func shareParams(t *testing.T) (ClientConnParams, []byte) {
	t.Helper()
	certPEM, der := shareCert(t)
	pin, err := bundle.SPKIPinFromCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	return ClientConnParams{
		Server:           "78.47.152.16",
		Name:             "r1",
		VLESSUUID:        "11111111-2222-3333-4444-555555555555",
		RealityShortID:   "deadbeef",
		RealityPublicKey: base64.RawURLEncoding.EncodeToString(key),
		Hy2Password:      "hy2+secret/pass=word",
		NaivePassword:    "naivesecretpassword22",
		WSPath:           "/r1/cafebabe",
		TLSCertSHA256:    pin,
		TLSCertPEM:       certPEM,
		CoverSNI:         "cdn.example-host.net",
		SSPassword:       "bW9jay1ib3gtaXBzay0xNg==:bW9jay11c2VyLXVwc2sxNg==",
		SSMethod:         "2022-blake3-aes-128-gcm",
		CDNWSPath:        "/0123456789abcdef0123456789abcdef",
	}, der
}

type shareRoute struct {
	fam  string
	port int
	cdn  *bundle.CDNEndpoint
}

// buildSharePack signs a pack whose endpoints describe `signedFor`.
func buildSharePack(t *testing.T, signedFor ClientConnParams, rs []shareRoute) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	from := now.Add(-time.Hour).Format(time.RFC3339)
	until := now.Add(30 * 24 * time.Hour).Format(time.RFC3339)
	var routes []bundle.RouteManifestEntry
	profiles := map[string][]byte{}
	for i, r := range rs {
		id := "r" + string(rune('1'+i))
		cp := "profiles/" + id + ".json"
		fsc := map[string]any{"port": r.port, "_relaypack": map[string]any{"exposure_mode": "direct_vps"}}
		if r.cdn != nil {
			fsc["_relaypack"] = map[string]any{"exposure_mode": "cdn_fronted"}
			fsc[bundle.CDNEndpointKey] = r.cdn
		} else if ep, _ := endpointFor(r.fam, r.port, EndpointMaterialFromParams(signedFor)); ep != nil {
			fsc[bundle.EndpointKey] = ep
		}
		b, _ := json.Marshal(fsc)
		profiles[cp] = b
		routes = append(routes, bundle.RouteManifestEntry{
			ID: id, ScarcityClass: "normal", TransportFamily: r.fam, ConfigPath: cp,
			ValidFrom: from, ValidUntil: until, FamilySpecificConfig: b,
		})
	}
	m := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{Name: "Test", KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt: from, TrustClass: "community"},
		Bundle: bundle.BundleInfo{ID: "rp-share", Type: "provider", CreatedAt: from, ExpiresAt: until},
		Routes: routes,
	}
	sbp, err := bundle.BuildSignedBundle(m, profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return sbp
}

func allDirectRoutes() []shareRoute {
	return []shareRoute{
		{fam: "vless-reality", port: 443},
		{fam: "hysteria2", port: 443},
		{fam: "shadowsocks", port: 8446},
		{fam: "websocket-tls", port: 8444},
		{fam: "naive", port: 8445},
		{fam: "tuic", port: 8443},
		{fam: "anytls", port: 8447},
	}
}

func linksByWay(links []ShareLink) map[string]ShareLink {
	m := map[string]ShareLink{}
	for _, l := range links {
		m[l.Way] = l
	}
	return m
}

func leftByWay(left []LeftOutWay) map[string]LeftOutWay {
	m := map[string]LeftOutWay{}
	for _, l := range left {
		m[l.Way] = l
	}
	return m
}

// importLink runs a link through Daal's own importer (bundle/go/uri) —
// the strictest reader of the grammar this repo has.
func importLink(t *testing.T, link string) map[string]any {
	t.Helper()
	prof, _, err := uri.ParseURI(link)
	if err != nil {
		t.Fatalf("the importer refused our own link (%s): %v", uri.RefusalCode(err), err)
	}
	return prof.Outbound
}

func tlsOf(t *testing.T, ob map[string]any) map[string]any {
	t.Helper()
	tls, ok := ob["tls"].(map[string]any)
	if !ok {
		t.Fatalf("imported outbound has no tls block: %v", ob)
	}
	return tls
}

func TestShareLinks_RendersOnlyTheSafeWaysAndSaysWhyTheRestAreOut(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	links, left, err := ShareLinksForRecipient(sbp, p, "")
	if err != nil {
		t.Fatal(err)
	}
	got := linksByWay(links)
	for _, w := range []string{ShareWayReality, ShareWayShadowsocks} {
		if _, ok := got[w]; !ok {
			t.Errorf("no link for %s; left out: %v", w, left)
		}
	}
	if len(links) != 2 {
		t.Errorf("want exactly 2 links, got %d", len(links))
	}
	out := leftByWay(left)
	for _, w := range []string{"hysteria2", "websocket-tls", "naive", "tuic", "anytls"} {
		if out[w].Reason != LeftOutNeedsInsecure {
			t.Errorf("%s: reason = %q, want %q", w, out[w].Reason, LeftOutNeedsInsecure)
		}
	}
}

// THE RULE: no link may switch certificate checks off, in any spelling a
// client in the list accepts.
func TestShareLinks_NeverCarryInsecure(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	links, _, err := ShareLinksForRecipient(sbp, p, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		u, err := url.Parse(l.Link)
		if err != nil {
			t.Fatalf("%s: not a URL: %v", l.Way, err)
		}
		for k := range u.Query() {
			switch strings.ToLower(k) {
			case "insecure", "allowinsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify":
				t.Errorf("%s link carries %q", l.Way, k)
			}
		}
	}
}

func TestShareLinks_RealityRoundTripsThroughTheImporterAndTheSignedEndpoint(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	links, _, err := ShareLinksForRecipient(sbp, p, "Home")
	if err != nil {
		t.Fatal(err)
	}
	l := linksByWay(links)[ShareWayReality]
	if l.Label != "Home · REALITY" {
		t.Errorf("label = %q", l.Label)
	}
	ob := importLink(t, l.Link)
	if ob["server"] != p.Server || ob["server_port"] != 443 || ob["uuid"] != p.VLESSUUID ||
		ob["flow"] != "xtls-rprx-vision" {
		t.Errorf("imported outbound: %v", ob)
	}
	tls := tlsOf(t, ob)
	if tls["server_name"] != p.CoverSNI {
		t.Errorf("sni = %v", tls["server_name"])
	}
	r, _ := tls["reality"].(map[string]any)
	if r["public_key"] != p.RealityPublicKey || r["short_id"] != p.RealityShortID {
		t.Errorf("reality = %v", r)
	}
	if u, _ := tls["utls"].(map[string]any); u["fingerprint"] != "chrome" {
		t.Errorf("utls = %v", tls["utls"])
	}
	// What the importer makes of the link is something the SIGNED
	// endpoint accepts — the same check Daal's own file passes.
	ep, _ := endpointFor("vless-reality", 443, EndpointMaterialFromParams(p))
	b, _ := json.Marshal(ob)
	if err := bundle.CheckOutbound("vless-reality", ep, b); err != nil {
		t.Errorf("imported link disagrees with the signed endpoint: %v", err)
	}
	if u, _ := url.Parse(l.Link); u.Fragment != "Home · REALITY" {
		t.Errorf("fragment = %q", u.Fragment)
	}
}

// Hysteria 2 is left out until a client is shown to connect with the
// pin alone (share_links.go header): a pinned link against a self-signed
// leaf most likely fails chain verification before the pin is read.
func TestShareLinks_Hysteria2IsLeftOutEvenWithTheCertificate(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	links, left, err := ShareLinksForRecipient(sbp, p, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := linksByWay(links)[ShareWayHysteria2]; ok {
		t.Fatal("a hysteria2 link was rendered")
	}
	if leftByWay(left)[ShareWayHysteria2].Reason != LeftOutNeedsInsecure {
		t.Errorf("left out: %v", left)
	}
}

// The pin kept for later is the SHA-256 of the whole certificate, and
// only of one whose key is the signed one.
func TestShareLinks_Hysteria2PinIsTheWholeSignedCertificate(t *testing.T) {
	p, der := shareParams(t)
	ep, why := endpointFor("hysteria2", 443, EndpointMaterialFromParams(p))
	if ep == nil {
		t.Fatal(why)
	}
	sum := sha256.Sum256(der)
	if got, ok := hy2CertPin(p.TLSCertPEM, ep.TLSSPKISHA256); !ok || got != hex.EncodeToString(sum[:]) {
		t.Errorf("pin = %q %v, want the certificate's SHA-256", got, ok)
	}
	if _, ok := hy2CertPin("", ep.TLSSPKISHA256); ok {
		t.Error("a pin without a certificate")
	}
	other, _ := shareCert(t)
	if _, ok := hy2CertPin(other, ep.TLSSPKISHA256); ok {
		t.Error("a pin for a certificate the pack did not sign")
	}
}

func TestShareLinks_ShadowsocksRoundTripsTheTwoPartKey(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	links, _, err := ShareLinksForRecipient(sbp, p, "")
	if err != nil {
		t.Fatal(err)
	}
	l := linksByWay(links)[ShareWayShadowsocks]
	if strings.Contains(strings.SplitN(strings.TrimPrefix(l.Link, "ss://"), "@", 2)[0], "==:") {
		t.Errorf("password not percent-encoded: the ':' between the keys would split userinfo")
	}
	ob := importLink(t, l.Link)
	if ob["method"] != p.SSMethod || ob["password"] != p.SSPassword || ob["server_port"] != 8446 {
		t.Errorf("imported outbound: %v", ob)
	}
}

func TestShareLinks_ShadowsocksWithoutThisPersonsKeyIsLeftOut(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	q := p
	q.SSPassword, q.SSMethod = "", ""
	links, left, err := ShareLinksForRecipient(sbp, q, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := linksByWay(links)[ShareWayShadowsocks]; ok {
		t.Fatal("shadowsocks link without a key")
	}
	if leftByWay(left)[ShareWayShadowsocks].Reason != LeftOutMissingMaterial {
		t.Errorf("left out: %v", left)
	}
}

func TestShareLinks_ARelayThatMovedIsAnErrorNotAWrongLink(t *testing.T) {
	p, _ := shareParams(t)
	sbp := buildSharePack(t, p, allDirectRoutes())
	q := p
	q.Server = "203.0.113.9"
	_, _, err := ShareLinksForRecipient(sbp, q, "")
	if !errors.Is(err, ErrStaleSignedPack) {
		t.Fatalf("err = %v, want ErrStaleSignedPack", err)
	}
	if err != nil && (strings.Contains(err.Error(), q.VLESSUUID) || strings.Contains(err.Error(), q.Hy2Password)) {
		t.Error("the error carries a credential")
	}
}

func TestShareLinks_UnsignedRouteIsLeftOut(t *testing.T) {
	p, _ := shareParams(t)
	signed := p
	signed.RealityPublicKey = "" // bind-and-sign had no key: no endpoint
	sbp := buildSharePack(t, signed, []shareRoute{{fam: "vless-reality", port: 443}})
	links, left, err := ShareLinksForRecipient(sbp, p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 || leftByWay(left)[ShareWayReality].Reason != LeftOutNotSigned {
		t.Errorf("links=%d left=%v", len(links), left)
	}
}

func shareCDNEndpoint(plain bool) *bundle.CDNEndpoint {
	return cdnMintEndpoint(CDNShippedRootDigests()[:2], cdnMintECH, plain)
}

func TestShareLinks_CDNOnlyWhenTheSignedCommitmentAllowsAPlainHello(t *testing.T) {
	p, _ := shareParams(t)
	for _, plain := range []bool{false, true} {
		sbp := buildSharePack(t, p, []shareRoute{
			{fam: "vless-reality", port: 443},
			{fam: "websocket-tls", port: 443, cdn: shareCDNEndpoint(plain)},
		})
		links, left, err := ShareLinksForRecipient(sbp, p, "")
		if err != nil {
			t.Fatal(err)
		}
		l, ok := linksByWay(links)[ShareWayCDN]
		if !plain {
			if ok || leftByWay(left)[ShareWayCDN].Reason != LeftOutShowsCDNName {
				t.Errorf("no plain fallback: link=%v left=%v", ok, left)
			}
			continue
		}
		if !ok {
			t.Fatalf("plain fallback allowed but no CDN link: %v", left)
		}
		if l.Label != "WebSocket TLS · Cloudflare" {
			t.Errorf("label = %q", l.Label)
		}
		ob := importLink(t, l.Link)
		tls := tlsOf(t, ob)
		if tls["server_name"] != "w7.example.com" || ob["server_port"] != 443 || ob["uuid"] != p.VLESSUUID {
			t.Errorf("imported outbound: %v", ob)
		}
		if ob["server"] != shareCDNEndpoint(true).FirstEdgeAddress() {
			t.Errorf("server = %v", ob["server"])
		}
		tr, _ := ob["transport"].(map[string]any)
		h, _ := tr["headers"].(map[string]any)
		if tr["type"] != "ws" || tr["path"] != p.CDNWSPath || h["Host"] != "w7.example.com" {
			t.Errorf("transport = %v", tr)
		}
	}
}

func TestShareLinks_CDNWithoutTheDoorPathIsLeftOut(t *testing.T) {
	p, _ := shareParams(t)
	q := p
	q.CDNWSPath = ""
	sbp := buildSharePack(t, p, []shareRoute{
		{fam: "vless-reality", port: 443},
		{fam: "websocket-tls", port: 443, cdn: shareCDNEndpoint(true)},
	})
	_, left, err := ShareLinksForRecipient(sbp, q, "")
	if err != nil {
		t.Fatal(err)
	}
	if leftByWay(left)[ShareWayCDN].Reason != LeftOutMissingMaterial {
		t.Errorf("left = %v", left)
	}
}

func TestShareLinks_IPv6ServerIsBracketed(t *testing.T) {
	if got := hostPort("2001:db8::1", 443); got != "[2001:db8::1]:443" {
		t.Errorf("hostPort = %q", got)
	}
}
