package cli

// THE APP'S ORDER OF OPERATIONS, ON THE VERBS THE APP RUNS.
//
// The wizard signs a relay's pack before any recipient exists. Since a
// pack's routes are committed to signed endpoints, that signature needs
// the relay's keys — and the OperatorRecord has them only where a
// provider adapter happened to read them over SSH (finding F-005: on
// Vultr it has none, and the Sign step failed outright; on Hetzner
// shadowsocks was never committed). These tests hold the replacement
// path down: relay-identity → bind-and-sign --relay-identity, on a
// record that knows nothing.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
)

const fixtureSSDigest = "fcdbdca159bd5651a33cf17ba64d6bcda8b6fb65929529933faf309ab580eae2"

// bareRecord is mkBindFixture's record with everything a provisioning
// SSH read would have added stripped out again, plus a shadowsocks
// route: the record a provider adapter that reads nothing produces.
func bareRecord(t *testing.T) (barePath, privPath, server, coverSNI string) {
	t.Helper()
	recPath, privPath, _, _ := mkBindFixture(t)
	body, _ := os.ReadFile(recPath)
	var rec map[string]any
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	delete(rec, "reality_public_key")
	delete(rec, "tls_cert_sha256")
	cands, _ := rec["candidates"].([]any)
	if len(cands) == 0 {
		t.Fatal("fixture record has no candidates")
	}
	// A shadowsocks route, shaped like its siblings.
	first, _ := cands[0].(map[string]any)
	ss := map[string]any{}
	for k, v := range first {
		ss[k] = v
	}
	ss["family"], ss["port"] = "shadowsocks", 8446
	delete(ss, "params")
	rec["candidates"] = append(cands, ss)
	bare, _ := json.Marshal(rec)
	barePath = filepath.Join(t.TempDir(), "bare.json")
	if err := os.WriteFile(barePath, bare, 0o600); err != nil {
		t.Fatal(err)
	}
	server, _ = rec["public_ip"].(string)
	coverSNI, _ = rec["cover_sni"].(string)
	return
}

func writeIdentity(t *testing.T, id mgmt.RelayIdentity) string {
	t.Helper()
	id.IdentityVersion = mgmt.IdentityVersion
	body, _ := json.Marshal(id)
	p := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type bindSummary struct {
	Uncommitted []string `json:"uncommitted_families"`
	Committed   struct {
		Server            string   `json:"server"`
		CoverSNI          string   `json:"cover_sni"`
		RealityPublicKey  string   `json:"reality_public_key"`
		TLSCertSHA256     string   `json:"tls_cert_sha256"`
		SSMethod          string   `json:"ss_method"`
		SSServerKeySHA256 string   `json:"ss_server_key_sha256"`
		Families          []string `json:"families"`
	} `json:"committed_identity"`
	IdentityWarnings []string `json:"identity_warnings"`
}

func bindWith(t *testing.T, recPath, privPath, out string, extra ...string) (int, bindSummary, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rc := Run(append([]string{"bind-and-sign", "--operator-record", recPath, "--priv-key", privPath,
		"--output", out, "--phase", testPhase}, extra...), &stdout, &stderr)
	var s bindSummary
	if rc == 0 {
		if err := json.Unmarshal(stdout.Bytes(), &s); err != nil {
			t.Fatalf("summary: %v\n%s", err, stdout.String())
		}
	}
	return rc, s, stderr.String()
}

func endpointsOf(t *testing.T, sbpPath string) map[string]*bundle.Endpoint {
	t.Helper()
	signed, err := os.ReadFile(sbpPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*bundle.Endpoint{}
	for _, r := range parsed.Manifest.Routes {
		ep, err := bundle.ParseEndpoint(r.FamilySpecificConfig)
		if err == nil {
			out[r.TransportFamily] = ep
		}
	}
	return out
}

// F-005, first half. A record with no connection material at all (what
// the Vultr adapter writes) cannot be signed alone — and CAN be signed
// from the relay's own identity, with no recipient in existence.
func TestBindAndSign_RelayIdentity_SignsARecordThatKnowsNothing(t *testing.T) {
	barePath, privPath, server, cover := bareRecord(t)
	out := filepath.Join(t.TempDir(), "rp.sbp")

	if rc, _, stderr := bindWith(t, barePath, privPath, out); rc == 0 || !strings.Contains(stderr, "--relay-identity") {
		t.Fatalf("the bare record must not sign, and the refusal must name the remedy: rc=%d stderr=%s", rc, stderr)
	}

	// The relay before its first recipient: everything except the
	// shadowsocks key, which does not exist yet.
	idPath := writeIdentity(t, mgmt.RelayIdentity{
		RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin, CoverSNI: cover,
		Families: []mgmt.RelayIdentityFamily{
			{Family: "vless-reality", Port: 443, Listening: true},
			{Family: "hysteria2", Port: 443, Listening: true},
			{Family: "shadowsocks", Port: 8446, Listening: false},
		},
		PendingFamilies: []string{"shadowsocks"},
	})
	rc, sum, stderr := bindWith(t, barePath, privPath, out, "--relay-identity", idPath)
	if rc != 0 {
		t.Fatalf("bind with --relay-identity: rc=%d stderr=%s", rc, stderr)
	}
	if fmt.Sprint(sum.Uncommitted) != "[shadowsocks]" {
		t.Errorf("uncommitted_families = %v, want [shadowsocks] (its key does not exist yet)", sum.Uncommitted)
	}
	if !strings.Contains(stderr, "first recipient") {
		t.Errorf("the shadowsocks warning must say what to do about it; stderr=%s", stderr)
	}
	eps := endpointsOf(t, out)
	if ep := eps["vless-reality"]; ep == nil || ep.RealityPublicKey != fixtureRealityPub || ep.ServerName != cover || ep.Server != server {
		t.Errorf("vless-reality endpoint = %+v", ep)
	}
	if ep := eps["hysteria2"]; ep == nil || ep.TLSSPKISHA256 != fixtureTLSPin || ep.Server != server {
		t.Errorf("hysteria2 endpoint = %+v", ep)
	}
	if eps["shadowsocks"] != nil {
		t.Errorf("shadowsocks was committed with no key: %+v", eps["shadowsocks"])
	}
	if sum.Committed.Server != server || sum.Committed.RealityPublicKey != fixtureRealityPub ||
		sum.Committed.TLSCertSHA256 != fixtureTLSPin || sum.Committed.CoverSNI != cover ||
		sum.Committed.SSServerKeySHA256 != "" ||
		fmt.Sprint(sum.Committed.Families) != "[hysteria2 vless-reality]" {
		t.Errorf("committed_identity = %+v", sum.Committed)
	}

	// F-005, second half. After the first recipient the relay has a
	// shadowsocks key; signing again from its identity commits the
	// route — with the key's DIGEST, the key itself having never left
	// the relay on this path.
	idPath = writeIdentity(t, mgmt.RelayIdentity{
		RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin, CoverSNI: cover,
		SSMethod: "2022-blake3-aes-128-gcm", SSServerKeySHA256: fixtureSSDigest,
		PendingFamilies: []string{},
	})
	rc, sum, stderr = bindWith(t, barePath, privPath, out, "--relay-identity", idPath)
	if rc != 0 || len(sum.Uncommitted) != 0 {
		t.Fatalf("re-sign: rc=%d uncommitted=%v stderr=%s", rc, sum.Uncommitted, stderr)
	}
	ep := endpointsOf(t, out)["shadowsocks"]
	if ep == nil || ep.SSServerKeySHA256 != fixtureSSDigest || ep.SSMethod != "2022-blake3-aes-128-gcm" || ep.Port != 8446 {
		t.Fatalf("shadowsocks endpoint = %+v", ep)
	}
	if sum.Committed.SSServerKeySHA256 != fixtureSSDigest {
		t.Errorf("committed_identity.ss_server_key_sha256 = %q", sum.Committed.SSServerKeySHA256)
	}

	// And a recipient minted from that relay's reply fits the pack: the
	// digest the relay stated is the digest of the key it hands out.
	creds := map[string]any{
		"name": "r1", "vless_uuid": "11111111-2222-3333-4444-555555555555", "reality_short_id": "deadbeef",
		"hy2_password": "hy2secretpassword22ch", "reality_public_key": fixtureRealityPub,
		"tls_cert_sha256": fixtureTLSPin, "cover_sni": cover,
		"ss_method": "2022-blake3-aes-128-gcm", "ss_password": "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
	}
	cb, _ := json.Marshal(creds)
	credsPath := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(credsPath, cb, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, errb bytes.Buffer
	if rc := Run([]string{"users-pack-sbp", "--in", out, "--out", filepath.Join(t.TempDir(), "r1.sbp"),
		"--creds-file", credsPath, "--server", server}, &stdout, &errb); rc != 0 {
		t.Fatalf("users-pack-sbp against the identity-signed pack: rc=%d stderr=%s", rc, errb.String())
	}
	if strings.Contains(errb.String(), "shadowsocks") {
		t.Errorf("the shadowsocks route was dropped at mint: %s", errb.String())
	}
}

// The pin of the cross-module contract from this side: the digest the
// relay computes (cmd/daal-relay-mgmt ssServerKeyDigest, pinned there
// to the same vector) is the one a signed endpoint carries.
func TestSSServerKeyDigestVector(t *testing.T) {
	if got := bundle.SSServerKeyDigest("AAECAwQFBgcICQoLDA0ODw=="); got != fixtureSSDigest {
		t.Fatalf("bundle.SSServerKeyDigest = %s, want %s", got, fixtureSSDigest)
	}
}

// After rotate-tls the relay serves a new cover host. If the record
// write was lost, the record still names the old one — and the relay,
// asked just before the signature, is the one that is right.
func TestBindAndSign_RelayIdentityOutranksAStaleRecord(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t) // a record WITH material
	out := filepath.Join(t.TempDir(), "rp.sbp")
	const now = 1_780_000_000
	idPath := writeIdentity(t, mgmt.RelayIdentity{
		RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin, CoverSNI: "moved.example.org",
		Families:        []mgmt.RelayIdentityFamily{{Family: "hysteria2", Port: 8443, Listening: true}},
		GeneratedAtUnix: now - 2, // asked just before the signature
	})
	rc, sum, stderr := bindWith(t, recPath, privPath, out, "--relay-identity", idPath, "--now-unix", fmt.Sprint(now))
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr)
	}
	if ep := endpointsOf(t, out)["vless-reality"]; ep == nil || ep.ServerName != "moved.example.org" {
		t.Fatalf("vless-reality endpoint = %+v, want the relay's cover host", ep)
	}
	joined := strings.Join(sum.IdentityWarnings, "\n")
	if !strings.Contains(joined, "moved.example.org") || !strings.Contains(stderr, "moved.example.org") {
		t.Errorf("the disagreement was silent: warnings=%v stderr=%s", sum.IdentityWarnings, stderr)
	}
	// A port the relay does not serve the family on is reported, and
	// the record's port is what stays signed.
	if !strings.Contains(joined, "hysteria2") {
		t.Errorf("the port disagreement was silent: %v", sum.IdentityWarnings)
	}
}

// An identity read a while ago does not know about a rotate-tls that
// happened since; the record does, because rotate-tls rewrites it. Seen
// in the end-to-end rig: an identity saved before an L2 and reused
// after it signed the OLD cover host, and every phone that took the
// refreshed pack failed REALITY verification.
func TestBindAndSign_AnOldIdentityDoesNotOutrankTheRecordOnTheCoverHost(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	body, _ := os.ReadFile(recPath)
	var rec map[string]any
	_ = json.Unmarshal(body, &rec)
	recordCover, _ := rec["cover_sni"].(string)
	if recordCover == "" {
		t.Fatal("fixture record has no cover host")
	}
	out := filepath.Join(t.TempDir(), "rp.sbp")
	const now = 1_780_000_000
	sign := func(generatedAt int64) (bindSummary, string) {
		idPath := writeIdentity(t, mgmt.RelayIdentity{
			RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin,
			CoverSNI: "before-the-rotation.example.org", GeneratedAtUnix: generatedAt,
		})
		rc, sum, stderr := bindWith(t, recPath, privPath, out, "--relay-identity", idPath,
			"--now-unix", fmt.Sprint(now))
		if rc != 0 {
			t.Fatalf("rc=%d stderr=%s", rc, stderr)
		}
		return sum, stderr
	}

	// Read an hour ago: the record's cover host is signed, and the
	// operator is told to ask the relay again.
	sum, stderr := sign(now - 3600)
	if ep := endpointsOf(t, out)["vless-reality"]; ep == nil || ep.ServerName != recordCover {
		t.Fatalf("vless-reality endpoint = %+v, want the record's cover host %s", ep, recordCover)
	}
	if len(sum.IdentityWarnings) != 1 || !strings.Contains(sum.IdentityWarnings[0], "relay-identity again") ||
		!strings.Contains(stderr, "relay-identity again") {
		t.Errorf("a stale identity was overruled silently: %v / %s", sum.IdentityWarnings, stderr)
	}
	// Its keys are still the relay's keys.
	if sum.Committed.RealityPublicKey != fixtureRealityPub {
		t.Errorf("committed REALITY key = %q", sum.Committed.RealityPublicKey)
	}

	// Read just now: the relay is contradicting a stale record.
	sign(now - 5)
	if ep := endpointsOf(t, out)["vless-reality"]; ep == nil || ep.ServerName != "before-the-rotation.example.org" {
		t.Fatalf("vless-reality endpoint = %+v, want the relay's cover host", ep)
	}
}

func TestBindAndSign_RefusesAnIdentityItCannotRead(t *testing.T) {
	barePath, privPath, _, _ := bareRecord(t)
	bad := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(bad, []byte(`{"identity_version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, _, stderr := bindWith(t, barePath, privPath, filepath.Join(t.TempDir(), "rp.sbp"), "--relay-identity", bad)
	if rc != 2 || !strings.Contains(stderr, "--relay-identity") {
		t.Fatalf("rc=%d stderr=%s", rc, stderr)
	}
}

// --- the verb ---

func TestRun_DispatchesRelayIdentity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"relay-identity"}, &stdout, &stderr); rc != 2 ||
		strings.Contains(stderr.String(), "unknown subcommand") || !strings.Contains(stderr.String(), "--record-file") {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	stdout.Reset()
	_ = Run([]string{"--help"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "relay-identity") {
		t.Error("usage does not mention relay-identity")
	}
}

func withRelayIdentity(t *testing.T, id *mgmt.RelayIdentity, err error) *int {
	t.Helper()
	calls := 0
	prev := relayIdentityFn
	relayIdentityFn = func(_ context.Context, _ provider.Provider, _ *provider.OperatorRecord, _ ed25519.PrivateKey, _ string) (*mgmt.RelayIdentity, error) {
		calls++
		return id, err
	}
	t.Cleanup(func() { relayIdentityFn = prev })
	return &calls
}

func TestRelayIdentity_PrintsAndSavesWhatTheRelaySaid(t *testing.T) {
	withFakeProvider(t, &fakeFIPProvider{})
	calls := withRelayIdentity(t, &mgmt.RelayIdentity{
		IdentityVersion: mgmt.IdentityVersion, RealityPublicKey: fixtureRealityPub, TLSCertSHA256: fixtureTLSPin,
		PendingFamilies: []string{"shadowsocks"},
	}, nil)
	recordFile, tokenFile, keyFile := l3Fixture(t)
	outPath := filepath.Join(t.TempDir(), "identity.json")

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"relay-identity", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4", "--output", outPath}, &stdout, &stderr)
	if rc != 0 || *calls != 1 {
		t.Fatalf("rc=%d calls=%d stderr=%s", rc, *calls, stderr.String())
	}
	saved, err := readRelayIdentityFile(outPath)
	if err != nil || saved.RealityPublicKey != fixtureRealityPub || !saved.Pending("shadowsocks") {
		t.Fatalf("saved identity = %+v err=%v", saved, err)
	}
	if st, _ := os.Stat(outPath); st == nil || st.Mode().Perm() != 0o600 {
		t.Errorf("identity file mode = %v, want 0600", st.Mode())
	}
	printed, err := mgmt.ParseRelayIdentity(stdout.Bytes())
	if err != nil || printed.TLSCertSHA256 != fixtureTLSPin {
		t.Errorf("stdout is not the identity: %s (%v)", stdout.String(), err)
	}
	if !strings.Contains(stderr.String(), "first recipient") {
		t.Errorf("a pending family must be said out loud; stderr=%s", stderr.String())
	}
}

// Exit 3 is "this relay cannot say", distinct from "the call failed":
// the wizard falls back on the first and reports the second.
func TestRelayIdentity_ExitCodesTellAnOlderRelayFromAFailure(t *testing.T) {
	withFakeProvider(t, &fakeFIPProvider{})
	recordFile, tokenFile, keyFile := l3Fixture(t)
	args := []string{"relay-identity", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}

	withRelayIdentity(t, nil, fmt.Errorf("%w (status 404)", mgmt.ErrIdentityUnsupported))
	var stdout, stderr bytes.Buffer
	if rc := Run(args, &stdout, &stderr); rc != exitCapabilityUnsupported || stdout.Len() != 0 {
		t.Fatalf("older relay: rc=%d stdout=%q", rc, stdout.String())
	}
	withRelayIdentity(t, nil, fmt.Errorf("mgmt: identity: dial tcp: i/o timeout"))
	stdout.Reset()
	stderr.Reset()
	if rc := Run(args, &stdout, &stderr); rc != 1 {
		t.Fatalf("network failure: rc=%d", rc)
	}
}

// LC-O1. rotate-tls used to end by telling the operator that every
// recipient needs a re-minted pack. Six of seven families never put the
// cover host on the wire, and a phone that checks for updates heals the
// seventh by itself once the pack is signed again.
func TestRotateTLS_DoesNotClaimEveryoneNeedsANewFile(t *testing.T) {
	withFakeProvider(t, &fakeFIPProvider{})
	prev := rotateTLSFn
	rotateTLSFn = func(_ context.Context, _ provider.Provider, rec *provider.OperatorRecord, _ ed25519.PrivateKey, _ string, _ mgmt.TLSProfile) (*mgmt.RotateTLSResp, error) {
		rec.CoverSNI = "moved.example.org"
		return &mgmt.RotateTLSResp{AppliedAtUnix: 1780000000, AppliedSNI: "moved.example.org"}, nil
	}
	t.Cleanup(func() { rotateTLSFn = prev })
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	rc := Run([]string{"rotate-tls", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	// stdout is the rewritten record's path echo plus the result JSON;
	// the result is the last line.
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var out struct {
		CoverSNI string   `json:"cover_sni"`
		Warnings []string `json:"warnings"`
		NextStep string   `json:"next_step"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &out); err != nil {
		t.Fatalf("result JSON: %v\n%s", err, stdout.String())
	}
	if out.CoverSNI != "moved.example.org" {
		t.Fatalf("cover_sni = %q", out.CoverSNI)
	}
	// A clean rotation has NO warning. The standing one was false.
	if len(out.Warnings) != 0 {
		t.Errorf("warnings = %v, want none after a clean rotation", out.Warnings)
	}
	for _, text := range []string{strings.Join(out.Warnings, " "), out.NextStep, stderr.String()} {
		low := strings.ToLower(text)
		if strings.Contains(low, "every recipient needs") || strings.Contains(low, "everyone needs") {
			t.Errorf("rotate-tls still claims every recipient needs a new file: %q", text)
		}
	}
	// What is true is still said: which route is affected, and that
	// signing again and publishing is what heals it.
	if !strings.Contains(out.NextStep, "vless-reality") || !strings.Contains(out.NextStep, "bind-and-sign") ||
		!strings.Contains(out.NextStep, "publish-freshness") {
		t.Errorf("next_step = %q", out.NextStep)
	}
}
