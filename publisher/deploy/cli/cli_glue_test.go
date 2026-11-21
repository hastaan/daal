package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/freshness/backends/appsscript"
	"daal/publisher/deploy/provider"
)

// publish-freshness takes the Google update channel as one more
// target: one call signs, uploads to the script, and reports it beside
// the other mirrors. Alone it satisfies the floor (D-3).
func TestPublishFreshness_GoogleChannelIsATarget(t *testing.T) {
	f := withFakeGoogle(t)
	keyPath, _ := gKeyFile(t)
	rc, out, errs := runG(t, "appsscript-script", "--write-key-file", keyPath, "--path-token", gToken)
	if rc != 0 {
		t.Fatalf("script rc=%d %s", rc, errs)
	}
	var s struct {
		Code string `json:"code_gs"`
	}
	_ = json.Unmarshal([]byte(out), &s)
	shown, err := f.DeployByHand(s.Code)
	if err != nil {
		t.Fatal(err)
	}
	url, err := appsscript.NormalizeExecURL(shown, gToken)
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := writeTemp(t, "root.key", priv)
	pack := []byte("signed credential-less pack")
	packPath := writeTemp(t, "rp.sbp", pack)
	sum := sha256.Sum256(pack)
	docPath := filepath.Join(t.TempDir(), "doc.json")
	base := []string{"publish-freshness",
		"--relay-pack-id", "rp-google-2",
		"--current-bundle-sha256", hex.EncodeToString(sum[:]),
		"--current-signed-url", "https://packs.example.com/rp.sbp",
		"--publisher-pub-hex", hex.EncodeToString(pub),
		"--root-priv-file", privPath,
		"--mirror", "appsscript=" + url,
		"--out-file", docPath}

	// Half a group is refused, like the other providers.
	if rc, _, errs := runG(t, append(base, "--appsscript-url", url)...); rc != 2 || !strings.Contains(errs, "--appsscript-write-key-file") {
		t.Fatalf("url without key: rc=%d %s", rc, errs)
	}

	rc, out, errs = runG(t, append(base, "--appsscript-url", url, "--appsscript-write-key-file", keyPath,
		"--appsscript-pack-file", packPath)...)
	if rc != 0 {
		t.Fatalf("publish rc=%d %s", rc, errs)
	}
	if strings.Contains(errs, "NOT published") {
		t.Fatalf("signed only: %s", errs)
	}
	var res publishFreshnessResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Published) != 1 || res.Published[0].Provider != freshness.ProviderAppsScript || !res.Published[0].OK {
		t.Fatalf("published = %+v", res.Published)
	}
	id, _, _ := freshness.ValidateAppsScriptURL(url)
	_, blob, ok := f.Stored(id)
	if !ok {
		t.Fatal("nothing stored at the script")
	}
	parts, err := appsscript.Parse([]byte(blob))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := os.ReadFile(docPath)
	if !bytes.Equal(parts.Freshness, doc) || !bytes.Equal(parts.Pack, pack) {
		t.Fatal("the script holds something other than the signed document and its pack")
	}
	if strings.Contains(errs, hex.EncodeToString(doc[:8])) {
		t.Fatal("unexpected document bytes on stderr")
	}
}

// --cdn-edge-ranges fetches Cloudflare's list through the seam and
// hands it to the provider; a failed fetch builds the relay anyway and
// says so; without the flag nothing is fetched.
func TestProvision_CDNEdgeRanges(t *testing.T) {
	var got [][]string
	fp := &captureProvisionProvider{onProvision: func(o provider.ProvisionOpts) { got = append(got, o.CDNEdgeRanges) }}
	withFakeProvider(t, fp)
	fetches := 0
	old := newEdgeFetcher
	t.Cleanup(func() { newEdgeFetcher = old })
	fail := false
	newEdgeFetcher = func() cloudflare.EdgeRangeFetcher {
		fetches++
		if fail {
			return failingEdgeFetcher{}
		}
		return fakeEdgeFetcher{}
	}
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	pubFile := filepath.Join(dir, "pub")
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	argv := []string{"provision", "--pubkey-file", pubFile, "--region", "fsn1",
		"--toolbox-profile", "iran-default", "--helper-ip", "1.2.3.4", "--token-file", filepath.Join(dir, "tok")}

	if rc, _, errs := runG(t, argv...); rc != 0 {
		t.Fatalf("plain provision rc=%d %s", rc, errs)
	}
	if fetches != 0 || len(got[0]) != 0 {
		t.Fatalf("fetched without the flag: %d %v", fetches, got)
	}
	if rc, _, errs := runG(t, append(argv, "--cdn-edge-ranges")...); rc != 0 {
		t.Fatalf("provision rc=%d %s", rc, errs)
	}
	if want := []string{"173.245.48.0/20", "2400:cb00::/32"}; strings.Join(got[1], ",") != strings.Join(want, ",") {
		t.Fatalf("ranges = %v, want %v", got[1], want)
	}
	fail = true
	rc, _, errs := runG(t, append(argv, "--cdn-edge-ranges")...)
	if rc != 0 {
		t.Fatalf("a failed range fetch failed the provision: rc=%d %s", rc, errs)
	}
	if len(got[2]) != 0 || !strings.Contains(errs, "rebuild") {
		t.Fatalf("failed fetch: ranges %v, stderr %q", got[2], errs)
	}
	// A dry run fetches nothing.
	before := fetches
	if rc, _, errs := runG(t, append(argv, "--cdn-edge-ranges", "--dry-run")...); rc != 0 || fetches != before {
		t.Fatalf("dry run: rc=%d fetches %d→%d %s", rc, before, fetches, errs)
	}
}

func TestCheckEdgeRanges(t *testing.T) {
	if err := checkEdgeRanges([]string{"104.16.0.0/13", "2606:4700::/32"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"not a cidr"}, {"1.2.3.4; rm -rf /"}} {
		if checkEdgeRanges(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

type failingEdgeFetcher struct{}

func (failingEdgeFetcher) FetchV4(context.Context) ([]string, error) {
	return nil, errors.New("unreachable")
}
func (failingEdgeFetcher) FetchV6(context.Context) ([]string, error) {
	return nil, errors.New("unreachable")
}

// captureProvisionProvider records what Provision was asked for and
// returns a minimal record.
type captureProvisionProvider struct {
	providerFace
	onProvision func(provider.ProvisionOpts)
}

func (c *captureProvisionProvider) Provision(_ context.Context, o provider.ProvisionOpts) (*provider.OperatorRecord, error) {
	c.onProvision(o)
	return &provider.OperatorRecord{Provider: "hetzner", ServerID: "1", Region: o.Region, PublisherPubKey: o.PublisherPubKey}, nil
}

// bind-and-sign --cdn-front adds the way in through Cloudflare as one
// more route committed by _cdn_endpoint (and never _endpoint), with the
// ECH configuration from the front record.
func TestBindAndSign_CDNFront(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	dir := t.TempDir()
	front := cloudflare.FrontRecord{
		Hostname: "door.example.org", Zone: "example.org", ZoneID: "z1",
		OriginPath: "/0123456789abcdef0123456789abcdef", FirewallID: "4711",
		OriginCAFingerprint: strings.Repeat("ab", 32), AOPEnabled: true,
		ECH: cloudflare.ECHPosture{ZoneSetting: "on", Published: true, ConfigListB64: "AAT+DQAA", PublicName: "cloudflare-ech.com"},
	}
	fb, _ := json.Marshal(front)
	frontPath := writeTemp(t, "front.json", fb)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "edge root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	rootsPath := writeTemp(t, "roots.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	out := filepath.Join(dir, "rp.sbp")
	argv := []string{"bind-and-sign", "--operator-record", recPath, "--priv-key", privPath, "--output", out,
		"--phase", string(relaypackvalidate.PhaseV16), "--now-unix", "1746115200", "--cdn-front", frontPath}

	if rc, _, errs := runG(t, argv...); rc != 2 || !strings.Contains(errs, "--cdn-edge-seeds") {
		t.Fatalf("front without seeds: rc=%d %s", rc, errs)
	}
	rc, _, errs := runG(t, append(argv, "--cdn-edge-seeds", "104.16.0.0/13,2606:4700::/32", "--cdn-roots-file", rootsPath)...)
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errs)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	last := b.Manifest.Routes[len(b.Manifest.Routes)-1]
	ep, err := bundle.ParseCDNEndpoint(last.TransportFamily, last.FamilySpecificConfig)
	if err != nil {
		t.Fatalf("last route is not the CDN one: %v (%s)", err, last.FamilySpecificConfig)
	}
	if ep.Server != "door.example.org" || ep.ECHConfig != "AAT+DQAA" || len(ep.TLSRootsSHA256) != 1 {
		t.Fatalf("endpoint = %+v", ep)
	}
	if _, err := bundle.ParseEndpoint(last.FamilySpecificConfig); !errors.Is(err, bundle.ErrNoEndpoint) {
		t.Fatalf("CDN route carries _endpoint (%v)", err)
	}
	if rc, _, _ := runG(t, "bind-and-sign", "--operator-record", recPath, "--priv-key", privPath, "--output", out,
		"--cdn-plain-fallback"); rc != 2 {
		t.Fatal("a --cdn-* flag without --cdn-front was accepted")
	}
}
