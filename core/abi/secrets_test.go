package abi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/core/keyvault"
)

// TestUnlockSecretsRejectedForKeystoreProfile — keystore profile
// returns ErrVaultProfileNotEnabled so the desktop knows the call
// was a no-op.
func TestUnlockSecretsRejectedForKeystoreProfile(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if got := StorageProfile(); got != "keystore" {
		t.Fatalf("storage_profile = %q, want keystore", got)
	}
	if !SecretsUnlocked() {
		t.Error("keystore profile should be unlocked at Init")
	}
	if err := UnlockSecrets("anything"); !errors.Is(err, ErrVaultProfileNotEnabled) {
		t.Errorf("UnlockSecrets on keystore profile = %v, want ErrVaultProfileNotEnabled", err)
	}
}

// TestUnlockSecretsRoundTripVault — seal a blob via keyvault.Seal,
// enable the vault profile, init, and unlock with the right PIN.
func TestUnlockSecretsRoundTripVault(t *testing.T) {
	dir := t.TempDir()
	pt := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	blob, err := keyvault.Seal(pt, "correct")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, vaultBlobName), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	// Enable the vault storage profile.
	if err := os.WriteFile(filepath.Join(dir, ".use_vault"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if got := StorageProfile(); got != "vault" {
		t.Fatalf("storage_profile = %q, want vault", got)
	}
	if SecretsUnlocked() {
		t.Error("vault profile must NOT be unlocked at Init")
	}
	if err := UnlockSecrets(""); err != keyvault.ErrEmptyPIN {
		t.Errorf("UnlockSecrets(\"\") = %v, want ErrEmptyPIN", err)
	}
	if err := UnlockSecrets("wrong"); err != keyvault.ErrWrongPIN {
		t.Errorf("UnlockSecrets(wrong) = %v, want ErrWrongPIN", err)
	}
	if SecretsUnlocked() {
		t.Error("wrong PIN must not flip the unlocked flag")
	}
	if err := UnlockSecrets("correct"); err != nil {
		t.Fatalf("UnlockSecrets(correct) = %v", err)
	}
	if !SecretsUnlocked() {
		t.Error("right PIN should flip the unlocked flag")
	}
}

// TestPINDoesNotLeakIntoDiagnostics — the 2D canonical V0.1 + CC.6
// privacy regression. Drives UnlockSecrets with a distinctive PIN,
// then exports diagnostics, and asserts the PIN string never
// appears anywhere in the output. Mirrors 2C's
// TestSSIDDoesNotLeakIntoDiagnostics.
func TestPINDoesNotLeakIntoDiagnostics(t *testing.T) {
	dir := t.TempDir()
	pt := []byte("AGE-SECRET-KEY-1XXX")
	pin := "DISTINCTIVE-PIN-SHOULD-NEVER-APPEAR-IN-DIAG-7E2A"
	blob, _ := keyvault.Seal(pt, pin)
	_ = os.WriteFile(filepath.Join(dir, vaultBlobName), blob, 0o600)
	_ = os.WriteFile(filepath.Join(dir, ".use_vault"), nil, 0o600)

	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := UnlockSecrets(pin); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, pin) {
		t.Fatalf("raw PIN leaked into diagnostics:\n%s", body)
	}
}

// TestExportDiagnosticsCarries2DFields — the 2D additive widening:
// secrets_unlocked, storage_profile, session_allows_bulk_capable.
func TestExportDiagnosticsCarries2DFields(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"secrets_unlocked"`,
		`"storage_profile"`,
		`"session_allows_bulk_capable"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing 2D field %s in:\n%s", want, body)
		}
	}
}

// TestLifelineStrictActiveSinceAppearsOnlyWhenActive — the
// lifeline_strict_active_since field must NOT be rendered when the
// mode is not lifeline-strict.
func TestLifelineStrictActiveSinceAppearsOnlyWhenActive(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "lifeline_strict_active_since") {
		t.Error("field present despite not being in lifeline-strict")
	}
	if err := SetMode("lifeline-strict"); err != nil {
		t.Fatal(err)
	}
	body, _ = ExportDiagnostics()
	if !strings.Contains(body, "lifeline_strict_active_since") {
		t.Error("field missing while in lifeline-strict")
	}
}
