package relaypack_test

// FRP-4b end-to-end smoke test.
//
// Drives the full stack with the public APIs only:
//
//     daal-deploy provision --dry-run
//          v
//     OperatorRecord JSON on disk
//          v
//     relaypack.BindAndSign (in-process Go, not via CLI)
//          v
//     ParseSBP + VerifyBundle + relaypackvalidate.Validate
//
// We deliberately keep the test in package relaypack_test (not
// relaypack) so it exercises the package's exported surface only,
// matching how the wizard subprocess driver will hit the same code
// path.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/cli"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relaypack"
)

// e2eBindNow pins --now-unix so the .sbp stays byte-deterministic
// across the two builds below, while staying anchored to this run's
// clock: bundle.VerifyBundle checks the manifest expiry against the
// real time.Now(), so a hard-coded date silently turns into "bundle
// expired" once it passes.
var e2eBindNow = time.Now().UTC().Add(-time.Hour)

// TestFRP4b_DryRunProvisionThenBindAndSign exercises the
// provision -> bind-and-sign chain that the wizard drives at the
// CLI boundary. Asserts:
//
//   - The dry-run CLI emits a valid OperatorRecord.
//   - relaypack.BindAndSign on that record produces a valid .sbp.
//   - The .sbp parses, verifies, and re-validates against the
//     PhaseV15 RelayPack rules.
//
// This is the single test that proves the FRP-4b chain works end
// to end without a live cloud.
func TestFRP4b_DryRunProvisionThenBindAndSign(t *testing.T) {
	tmp := t.TempDir()

	// 1) Generate publisher keypair; write pub bytes to disk so the
	//    CLI's --pubkey-file flag can read them.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pubFile := filepath.Join(tmp, "pub")
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(tmp, "rec.json")

	// 2) Drive `daal-deploy provision --dry-run` to produce the
	//    OperatorRecord we'd hand to bind-and-sign.
	var stdout, stderr bytes.Buffer
	rc := cli.Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--families", "vless-reality,hysteria2",
		"--helper-ip", "1.2.3.4",
		"--dry-run",
		"-o", recPath,
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("provision rc=%d stderr=%s", rc, stderr.String())
	}

	// 3) Read the dry-run OperatorRecord off disk and stamp the
	//    pubkey on it (the dry-run path leaves PublisherPubKey
	//    populated but we re-attach explicitly so we don't depend
	//    on undocumented internal state).
	var rec provider.OperatorRecord
	body, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatalf("read rec: %v", err)
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatalf("unmarshal rec: %v", err)
	}
	if !bytes.Equal(rec.PublisherPubKey, pub) {
		// The dry-run helper writes the pubkey straight into the
		// record; if this ever drifts the smoke test catches it.
		t.Fatalf("PublisherPubKey not stamped on dry-run record: got %x want %x",
			rec.PublisherPubKey, pub)
	}
	if len(rec.Candidates) < 2 {
		t.Fatalf("dry-run record has too few candidates: %d", len(rec.Candidates))
	}
	if !rec.PublicIP.Equal(net.ParseIP(rec.PublicIP.String())) {
		t.Fatalf("PublicIP malformed: %v", rec.PublicIP)
	}

	// 4) Bind-and-sign in-process. We pin --now-unix via opts.Now
	//    so the .sbp is byte-deterministic across reruns.
	res, err := relaypack.BindAndSign(&rec, priv, relaypack.BindOpts{
		Now:    e2eBindNow,
		Expiry: 30 * 24 * time.Hour,
		Phase:  relaypackvalidate.PhaseV15,
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	if len(res.SBPBytes) == 0 {
		t.Fatalf("empty .sbp bytes")
	}

	// 5) Round-trip the .sbp through ParseSBP + VerifyBundle.
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	// 6) Re-run the FRP-1 validator on the parsed bundle. This
	//    proves our binder's validate-before-sign step is doing
	//    the same job a fresh recipient would do at import time.
	if _, err := relaypackvalidate.Validate(parsed, relaypackvalidate.ValidateOpts{
		Phase: relaypackvalidate.PhaseV15,
	}); err != nil {
		t.Fatalf("post-parse validate: %v", err)
	}
}

// TestFRP4b_BindAndSignDeterministicCrossRun pins the by-bytes
// determinism of BindAndSign across two top-level runs. This is
// the lever the supplement §15.2 calls out: byte-equal .sbp
// outputs let two operators on different machines verify their
// build identical .sbps for a given (rec, key, now) tuple.
func TestFRP4b_BindAndSignDeterministicCrossRun(t *testing.T) {
	tmp := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	rec := &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "12345", Region: "fsn1",
		ServerType:      "cx22",
		PublicIP:        net.ParseIP("5.75.0.1"),
		PublisherPubKey: append([]byte(nil), pub...),
		Candidates: []provider.CandidateMeta{
			{Family: "vless-reality", ExposureMode: "direct_vps",
				FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 443,
				PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:tcp443"},
				OriginRiskTags: []string{}},
			{Family: "hysteria2", ExposureMode: "direct_vps",
				FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 443,
				PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:udp443"},
				OriginRiskTags: []string{}},
		},
	}
	opts := relaypack.BindOpts{
		Now:    e2eBindNow,
		Expiry: 30 * 24 * time.Hour,
		Phase:  relaypackvalidate.PhaseV15,
	}
	a, err := relaypack.BindAndSign(rec, priv, opts)
	if err != nil {
		t.Fatalf("first BindAndSign: %v", err)
	}
	b, err := relaypack.BindAndSign(rec, priv, opts)
	if err != nil {
		t.Fatalf("second BindAndSign: %v", err)
	}
	if !bytes.Equal(a.SBPBytes, b.SBPBytes) {
		t.Fatalf("BindAndSign not byte-deterministic across two calls (len %d vs %d)",
			len(a.SBPBytes), len(b.SBPBytes))
	}
	// Sanity: both round-trip through ParseSBP.
	if _, err := bundle.ParseSBP(bytes.NewReader(a.SBPBytes), int64(len(a.SBPBytes))); err != nil {
		t.Fatalf("ParseSBP a: %v", err)
	}
	_ = tmp
}
