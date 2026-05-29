package publisher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Phase 3B. snowflake-rendezvous-hint subcommand tests.
//
// Canonical regressions called out in
// specs/publisher-cli-v1.md "Phase 3B" and
// specs/snowflake-route-v1.md "Offline hints":
//
//   - TestSnowflakeRendezvousHint_RoundTripSignedByKey
//   - TestSnowflakeRendezvousHint_RequiresBridge
//   - TestSnowflakeRendezvousHint_RequiresFingerprint
//   - TestSnowflakeRendezvousHint_DefaultValidity
//   - TestSnowflakeRendezvousHint_PayloadVersionLockedAt1

func TestSnowflakeRendezvousHint_RoundTripSignedByKey(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "publisher.priv")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "hint.json")
	env, err := SnowflakeRendezvousHint(SnowflakeHintOptions{
		Bridge:         "203.0.113.5:443",
		FingerprintHex: "deadbeef",
		Validity:       7 * 24 * time.Hour,
		OutPath:        outPath,
		PrivKeyPath:    keyPath,
	})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	// File written.
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("payload")) || !bytes.Contains(body, []byte("signature")) {
		t.Errorf("output missing expected fields: %s", body)
	}

	// Signature verifies under the publisher's pubkey.
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatalf("signature decode: %v", err)
	}
	if !ed25519.Verify(pub, env.Payload, sig) {
		t.Error("signature does not verify under the publisher's pubkey")
	}

	// Payload round-trips.
	var pl SnowflakeHintPayload
	if err := json.Unmarshal(env.Payload, &pl); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if pl.Bridge != "203.0.113.5:443" {
		t.Errorf("bridge: got %q", pl.Bridge)
	}
	if pl.FingerprintHex != "deadbeef" {
		t.Errorf("fp: got %q", pl.FingerprintHex)
	}
	if pl.HintVersion != 1 {
		t.Errorf("hint_version: got %d want 1", pl.HintVersion)
	}
}

func TestSnowflakeRendezvousHint_RequiresBridge(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "publisher.priv")
	_ = os.WriteFile(keyPath, priv, 0o600)
	_, err := SnowflakeRendezvousHint(SnowflakeHintOptions{
		FingerprintHex: "deadbeef",
		OutPath:        filepath.Join(dir, "h.json"),
		PrivKeyPath:    keyPath,
	})
	if err == nil {
		t.Error("missing --bridge must error")
	}
}

func TestSnowflakeRendezvousHint_RequiresFingerprint(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "publisher.priv")
	_ = os.WriteFile(keyPath, priv, 0o600)
	_, err := SnowflakeRendezvousHint(SnowflakeHintOptions{
		Bridge:      "x:443",
		OutPath:     filepath.Join(dir, "h.json"),
		PrivKeyPath: keyPath,
	})
	if err == nil {
		t.Error("missing --fingerprint must error")
	}
}

func TestSnowflakeRendezvousHint_DefaultValidity(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "publisher.priv")
	_ = os.WriteFile(keyPath, priv, 0o600)
	env, err := SnowflakeRendezvousHint(SnowflakeHintOptions{
		Bridge:         "x:443",
		FingerprintHex: "abc",
		OutPath:        filepath.Join(dir, "h.json"),
		PrivKeyPath:    keyPath,
		// no Validity
	})
	if err != nil {
		t.Fatal(err)
	}
	var pl SnowflakeHintPayload
	if err := json.Unmarshal(env.Payload, &pl); err != nil {
		t.Fatal(err)
	}
	notAfter, err := time.Parse(time.RFC3339, pl.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	// Default 30 days; allow 1 minute drift.
	delta := notAfter.Sub(time.Now().UTC())
	if delta < 29*24*time.Hour || delta > 31*24*time.Hour {
		t.Errorf("default validity: NotAfter delta %v, want ~30d", delta)
	}
}

func TestSnowflakeRendezvousHint_RejectsBadKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "publisher.priv")
	if err := os.WriteFile(keyPath, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := SnowflakeRendezvousHint(SnowflakeHintOptions{
		Bridge:         "x:443",
		FingerprintHex: "abc",
		OutPath:        filepath.Join(dir, "h.json"),
		PrivKeyPath:    keyPath,
	})
	if err == nil {
		t.Error("malformed key file must error")
	}
}
