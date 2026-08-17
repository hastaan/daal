package abi

// The cross-module wire test for FRP-8's freshness mirror set.
//
// WHY THIS FILE EXISTS. The mirror set crosses three separately
// compiled things: the publisher CLI writes it into an .sbp archive
// entry, the importer (bundle module) ferries it to the store, and the
// recipient's refresher verifies it and turns it into the endpoints it
// will poll. Every one of those has thorough unit tests, and none of
// them can see the seam. When this test was first written the seam was
// BROKEN in the field-relevant direction: a pack signing three mirrors
// across three providers imported into a device that would poll ONE
// host — the manifest's legacy scalar — because the persisted mirror
// set was only ever written by a SUCCESSFUL refresh, and a recipient
// whose one host is blocked never gets one. The spare endpoints sat
// unread inside the signed file already in the user's hands, in exactly
// the scenario they were added for, and both sides' tests were green.
// That is the same failure shape that made Wave 2's multiplex inert.
//
// So: testdata/freshness-3mirrors.sbp is REAL OUTPUT of the real
// publisher path, minted by
//
//	daal-deploy provision --dry-run --pubkey-file pub.bin --region fsn1 \
//	    --toolbox-profile iran-default --helper-ip 203.0.113.9 -o rec.json
//	daal-deploy bind-and-sign --operator-record rec.json --priv-key priv.bin \
//	    --output fixture.sbp --expiry-days 3650 \
//	    --freshness-mirror ghpages=https://freshness.pages.invalid/f/abc.json \
//	    --freshness-mirror r2=https://cdn-r2.invalid/daal/f/abc.json \
//	    --freshness-mirror bunny=https://b-cdn.invalid/daal/freshness/abc.json \
//	    --revocation-url https://revoke.invalid/daal/rev.json \
//	    --revocation-pub-hex <32-byte hex>
//
// It is a byte fixture and not a builder because a builder written in
// this module would re-implement the publisher's encoder, and then the
// test would prove the two copies agree with each other rather than
// that this client can read that publisher's output. When the publisher
// changes the wire shape, this must fail — that is the point. Re-mint
// with the command above; do not edit the bytes.
//
// The endpoint hosts are .invalid on purpose: a fixture must never name
// a resolvable host, and nothing here dials.
//
// The 10-year expiry is a fixture concession, so the test does not
// start failing on a date rather than on a change.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/bootstrap"
	"daal/core/trust"
)

const freshnessFixture = "testdata/freshness-3mirrors.sbp"

// The set the fixture was signed with, in publisher-canonical order
// (sorted by provider, then url — the binder sorts so a pack is
// byte-identical regardless of flag order).
var fixtureMirrors = []string{
	"https://b-cdn.invalid/daal/freshness/abc.json", // bunny
	"https://freshness.pages.invalid/f/abc.json",    // ghpages
	"https://cdn-r2.invalid/daal/f/abc.json",        // r2
}

// The manifest's scalar slot carries ONE of them (the lowest-sorting
// member) so that a recipient minted before FRP-8 reads a valid single
// URL instead of something it will reject. Pinned here because it is
// the compatibility promise: if the publisher ever starts writing the
// whole set into this field, every already-distributed client silently
// loses its freshness path.
const fixtureScalar = "https://b-cdn.invalid/daal/freshness/abc.json"

func TestImportedPackYieldsEveryMirror(t *testing.T) {
	if _, err := os.Stat(freshnessFixture); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	// The production import path, prompt and all: a first-seen
	// publisher is TOFU-prompted, and the mirror set must survive the
	// prompt round trip (the bytes are re-parsed from the persisted
	// pending blob, which is a second place they can be dropped).
	v := importFixture(t, freshnessFixture)
	if v.Fingerprint == "" {
		t.Fatalf("no fingerprint in verdict: %+v", v)
	}
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}

	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := rp.Targets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected exactly one refreshable pack, got %d (%+v)", len(targets), targets)
	}
	got := targets[0]

	// N endpoints, not one. This is the assertion the whole file is
	// for; everything else is diagnosis.
	if len(got.Endpoints) != len(fixtureMirrors) {
		t.Fatalf("pack signs %d mirrors, client would poll %d: %v\n"+
			"the spare endpoints are inside the pack the device already holds; "+
			"a client that polls one host has no recovery path when that host is blocked",
			len(fixtureMirrors), len(got.Endpoints), got.Endpoints)
	}
	for _, want := range fixtureMirrors {
		if !containsStr(got.Endpoints, want) {
			t.Errorf("signed mirror %q is not in the client's endpoint set %v", want, got.Endpoints)
		}
	}
	// DISTINCT providers is the property that makes N mirrors worth
	// anything: three URLs on one host is one block away from zero.
	if got.Providers != len(fixtureMirrors) {
		t.Errorf("Providers=%d, want %d — the UI reads this to tell the user "+
			"whether their pack can repair itself", got.Providers, len(fixtureMirrors))
	}
}

// The legacy scalar slot is a single URL, and stays one. An old client
// reading a space- or JSON-joined list here would reject it and lose
// the only freshness path it can understand.
func TestManifestScalarSlotStaysSingleURL(t *testing.T) {
	body, err := os.ReadFile(freshnessFixture)
	if err != nil {
		t.Fatal(err)
	}
	scalar := manifestFreshnessScalar(t, body)
	if scalar != fixtureScalar {
		t.Fatalf("manifest scalar = %q, want %q", scalar, fixtureScalar)
	}
	if strings.ContainsAny(scalar, " ,\n[") {
		t.Fatalf("manifest scalar %q carries more than one URL: every client "+
			"minted before FRP-8 parses this field as a single URL", scalar)
	}
}

// A pack whose mirror entry was rewritten in transit must not steer the
// device: the entry is not covered by manifest.sig, so the only thing
// standing between a courier and a list of hosts this device will poll
// is the entry's own publisher signature.
func TestTamperedMirrorEntryIsIgnoredButPackStillImports(t *testing.T) {
	body, err := os.ReadFile(freshnessFixture)
	if err != nil {
		t.Fatal(err)
	}
	tampered := rewriteArchiveEntry(t, body, "trust/freshness-mirrors.json",
		strings.Replace(string(mirrorEntry(t, body)),
			"https://cdn-r2.invalid/daal/f/abc.json",
			"https://attacker.invalid/beacon.json", 1))

	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	path := dir + "/tampered.sbp"
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	v := importFixture(t, path)
	if v.Fingerprint == "" {
		t.Fatalf("the pack itself must still import — manifest.sig is intact "+
			"and the routes are what the user asked for: %+v", v)
	}
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}

	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := rp.Targets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected one pack, got %d", len(targets))
	}
	for _, ep := range targets[0].Endpoints {
		if strings.Contains(ep, "attacker.invalid") {
			t.Fatalf("a rewritten mirror entry reached the poll list: %v\n"+
				"that is a beacon — it tells whoever wrote it which devices hold "+
				"this publisher's pack and when they wake up", targets[0].Endpoints)
		}
	}
	// The whole set is dropped, not partially trusted: what remains is
	// the scalar that arrived under manifest.sig.
	if len(targets[0].Endpoints) != 1 || targets[0].Endpoints[0] != fixtureScalar {
		t.Fatalf("endpoints after tamper = %v, want just the signed scalar %q",
			targets[0].Endpoints, fixtureScalar)
	}
}

// An oversized mirror entry must not be carried into the device's
// secrets table. The entry is not covered by manifest.sig and it
// survives import, so an unbounded one turns "here is a relay pack"
// into "store this blob forever".
func TestOversizedMirrorEntryIsDropped(t *testing.T) {
	body, err := os.ReadFile(freshnessFixture)
	if err != nil {
		t.Fatal(err)
	}
	huge := `{"kind":"daal/freshness-mirrors-v1","pad":"` +
		strings.Repeat("A", bundle.MaxFreshnessMirrorsBytes+1) + `"}`
	fat := rewriteArchiveEntry(t, body, bundle.FreshnessMirrorsPath, huge)

	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	path := dir + "/fat.sbp"
	if err := os.WriteFile(path, fat, 0o600); err != nil {
		t.Fatal(err)
	}
	v := importFixture(t, path)
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}
	stored, err := loadedCore().store.GetSecret(trust.FreshnessMirrorsKey(v.BundleID))
	if err == nil && len(stored) > bundle.MaxFreshnessMirrorsBytes {
		t.Fatalf("stored %d bytes of attacker-chosen padding", len(stored))
	}
	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := rp.Targets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(targets[0].Endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want just the signed scalar", targets)
	}
}

// ---- helpers ------------------------------------------------------

func importFixture(t *testing.T, path string) importer.Verdict {
	t.Helper()
	out, err := ImportSBP(path)
	if err != nil {
		t.Fatalf("ImportSBP(%s): %v (%s)", path, err, out)
	}
	var v importer.Verdict
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("verdict %q: %v", out, err)
	}
	return v
}

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func manifestFreshnessScalar(t *testing.T, body []byte) string {
	t.Helper()
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if parsed.Manifest.RelayPack == nil {
		t.Fatal("fixture carries no relay_pack slot")
	}
	return parsed.Manifest.RelayPack.FreshnessURL
}

func mirrorEntry(t *testing.T, body []byte) []byte {
	t.Helper()
	raw, ok := bootstrap.ArchiveEntry(body, bundle.FreshnessMirrorsPath)
	if !ok {
		t.Fatalf("fixture carries no %s", bundle.FreshnessMirrorsPath)
	}
	return raw
}

// rewriteArchiveEntry rebuilds the zip with one entry replaced,
// touching nothing else — the manifest and its signature are copied
// verbatim, which is precisely why the tampered pack still verifies.
func rewriteArchiveEntry(t *testing.T, body []byte, name, content string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if f.Name == name {
			if _, err := w.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
