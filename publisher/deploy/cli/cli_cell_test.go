package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bundle "daal/bundle-go/bundle"
)

// 1. cell-create produces a JSON whose pub_b64 + priv_b64 form a
// matching ed25519 keypair.
func TestCellCreate_HappyPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := runCellCreate(context.Background(),
		[]string{"--cell-id", "cell-test", "--admin-idx", "0"},
		&stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	var out struct {
		CellID   string `json:"cell_id"`
		PubB64   string `json:"pub_b64"`
		PrivB64  string `json:"priv_b64"`
		AdminIdx int    `json:"admin_idx"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &out); err != nil {
		t.Fatal(err)
	}
	priv, _ := base64.RawStdEncoding.DecodeString(out.PrivB64)
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv len = %d", len(priv))
	}
	derivedPub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	pub, _ := base64.RawStdEncoding.DecodeString(out.PubB64)
	if !bytes.Equal(derivedPub, pub) {
		t.Fatal("derived pub != emitted pub")
	}
}

// 2. cell-create rejects empty --cell-id and out-of-range --admin-idx.
func TestCellCreate_FlagValidation(t *testing.T) {
	var sout, serr bytes.Buffer
	if rc := runCellCreate(context.Background(), []string{}, &sout, &serr); rc == 0 {
		t.Fatal("want non-zero rc for missing --cell-id")
	}
	sout.Reset()
	serr.Reset()
	if rc := runCellCreate(context.Background(),
		[]string{"--cell-id", "c1", "--admin-idx", "99"}, &sout, &serr); rc == 0 {
		t.Fatal("want non-zero rc for admin-idx=99")
	}
}

// helper: build a quorum-valid membership doc on disk + return
// path plus a mode-0600 admin private-key file suitable for
// cell-sign.
func writeMembership(t *testing.T) (string, string) {
	t.Helper()
	pubs := make([]string, 3)
	privs := make([]ed25519.PrivateKey, 3)
	for i := 0; i < 3; i++ {
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pubs[i] = base64.RawStdEncoding.EncodeToString(pk)
		privs[i] = sk
	}
	doc := bundle.CellMembershipDoc{
		CellID:       "cell-test",
		AdminPubkeys: pubs,
		QuorumM:      2,
		Members: []bundle.CellMember{
			{PublisherFPHex: "9f3a", SubkeyFPHex: "1c2b", JoinedAtUnix: 1},
		},
		RuleSet: bundle.CellRuleSet{CellMaxDepth: 1, AbuseRoute: "cell-internal", ValidUntilUnix: 1893456000},
	}
	for _, i := range []int{0, 2} {
		s, _ := bundle.SignCellMembership(doc, i, privs[i])
		doc.AdminSignatures = append(doc.AdminSignatures, s)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "membership.json")
	bytes, _ := json.Marshal(doc)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "admin0.key")
	priv0 := []byte(base64.RawStdEncoding.EncodeToString(privs[0]))
	if err := os.WriteFile(privPath, priv0, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, privPath
}

// 3. cell-invite wraps a quorum-valid doc into a cellInviteJSON
// envelope on stdout.
func TestCellInvite_HappyPath(t *testing.T) {
	memPath, _ := writeMembership(t)
	var sout, serr bytes.Buffer
	rc := runCellInvite(context.Background(), []string{
		"--membership-file", memPath,
		"--directory-url", "https://r2.example.com/cell/cell-test/directory.json",
		"--trust-label-hint", "family",
	}, &sout, &serr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, serr.String())
	}
	var inv cellInviteJSON
	if err := json.Unmarshal(sout.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.CellID != "cell-test" || inv.TrustLabelHint != "family" {
		t.Fatalf("envelope mismatch: %+v", inv)
	}
}

// 4. cell-invite rejects non-HTTPS directory URL.
func TestCellInvite_RejectsNonHTTPS(t *testing.T) {
	memPath, _ := writeMembership(t)
	var sout, serr bytes.Buffer
	rc := runCellInvite(context.Background(), []string{
		"--membership-file", memPath,
		"--directory-url", "http://insecure.example.com",
	}, &sout, &serr)
	if rc == 0 {
		t.Fatal("want non-zero for http:// URL")
	}
}

// 5. cell-sign reads the long-lived admin key from a mode-0600
// file, not argv, and emits one admin signature JSON.
func TestCellSign_HappyPathPrivFile(t *testing.T) {
	memPath, privPath := writeMembership(t)
	var sout, serr bytes.Buffer
	rc := runCellSign(context.Background(), []string{
		"--doc-file", memPath,
		"--priv-file", privPath,
		"--idx", "0",
		"--type", "membership",
	}, &sout, &serr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, serr.String())
	}
	var sig bundle.CellAdminSignature
	if err := json.Unmarshal(sout.Bytes(), &sig); err != nil {
		t.Fatal(err)
	}
	if sig.AdminPubkeyIdx != 0 || sig.SignatureB64 == "" {
		t.Fatalf("bad signature output: %+v", sig)
	}
}

// 6. cell-sign refuses group/world-readable admin key files.
func TestCellSign_RejectsLoosePrivFileMode(t *testing.T) {
	memPath, privPath := writeMembership(t)
	loosePath := filepath.Join(t.TempDir(), "loose.key")
	raw, _ := os.ReadFile(privPath)
	if err := os.WriteFile(loosePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	var sout, serr bytes.Buffer
	rc := runCellSign(context.Background(), []string{
		"--doc-file", memPath,
		"--priv-file", loosePath,
		"--idx", "0",
	}, &sout, &serr)
	if rc == 0 {
		t.Fatal("want non-zero for loose key file mode")
	}
	if !strings.Contains(serr.String(), "mode 0600") {
		t.Fatalf("stderr %q missing mode guidance", serr.String())
	}
}

// 5. cell-verify happy path on quorum-valid membership + delegation.
func TestCellVerify_HappyPath(t *testing.T) {
	memPath, _ := writeMembership(t)
	// Build a quorum-valid delegation against this membership.
	memBytes, _ := os.ReadFile(memPath)
	var memb bundle.CellMembershipDoc
	json.Unmarshal(memBytes, &memb)
	// Re-derive privs is not possible from on-disk; simulate by
	// generating a fresh triple and writing both docs.
	pubs := make([]string, 3)
	privs := make([]ed25519.PrivateKey, 3)
	for i := 0; i < 3; i++ {
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pubs[i] = base64.RawStdEncoding.EncodeToString(pk)
		privs[i] = sk
	}
	memb2 := bundle.CellMembershipDoc{
		CellID:       "cell-test",
		AdminPubkeys: pubs,
		QuorumM:      2,
		RuleSet:      bundle.CellRuleSet{CellMaxDepth: 1, AbuseRoute: "cell-internal", ValidUntilUnix: 1893456000},
	}
	for _, i := range []int{0, 2} {
		s, _ := bundle.SignCellMembership(memb2, i, privs[i])
		memb2.AdminSignatures = append(memb2.AdminSignatures, s)
	}
	bsPub, _, _ := ed25519.GenerateKey(rand.Reader)
	deleg := bundle.CellDelegationDoc{
		CellID:             "cell-test",
		BundleSignerPubkey: base64.RawStdEncoding.EncodeToString(bsPub),
		ValidFromUnix:      1735689600,
		ValidUntilUnix:     1893456000,
	}
	for _, i := range []int{0, 1} {
		s, _ := bundle.SignCellDelegation(deleg, i, privs[i])
		deleg.AdminSignatures = append(deleg.AdminSignatures, s)
	}
	dir := t.TempDir()
	mp := filepath.Join(dir, "memb.json")
	dp := filepath.Join(dir, "deleg.json")
	mb2, _ := json.Marshal(memb2)
	db2, _ := json.Marshal(deleg)
	os.WriteFile(mp, mb2, 0o600)
	os.WriteFile(dp, db2, 0o600)

	var sout, serr bytes.Buffer
	rc := runCellVerify(context.Background(), []string{
		"--membership-file", mp,
		"--delegation-file", dp,
	}, &sout, &serr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, serr.String())
	}
	if !strings.Contains(sout.String(), "OK") {
		t.Fatalf("stdout %q missing OK", sout.String())
	}
}

// 6. cell-status emits JSON with quorate=true on a valid membership.
func TestCellStatus_HappyPath(t *testing.T) {
	memPath, _ := writeMembership(t)
	var sout, serr bytes.Buffer
	rc := runCellStatus(context.Background(), []string{"--membership-file", memPath}, &sout, &serr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, serr.String())
	}
	var out struct {
		CellID     string `json:"cell_id"`
		Quorate    bool   `json:"quorate"`
		QuorumM    int    `json:"quorum_m"`
		AdminCount int    `json:"admin_count"`
	}
	if err := json.Unmarshal(sout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.CellID != "cell-test" || !out.Quorate || out.QuorumM != 2 {
		t.Fatalf("status mismatch: %+v", out)
	}
}
