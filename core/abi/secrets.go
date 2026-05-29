package abi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"daal/core/keyvault"
)

// ErrVaultProfileNotEnabled is returned by UnlockSecrets when the
// engine is running under the "keystore" storage profile (the
// default). The desktop layer translates this to "no PIN gate is
// required; proceed".
var ErrVaultProfileNotEnabled = errors.New("abi: vault storage profile not enabled")

// vaultBlobName is the on-disk file name for the sealed age identity.
// Lives under stateDir for the "vault" storage profile. For the
// "keystore" profile the file is absent and the routestore's age
// identity is loaded directly from the platform keystore.
const vaultBlobName = ".age_identity.vault"

// UnlockSecrets is engine_unlock_secrets (Phase 2D, release ABI
// surface 37 → 39 alongside engine_set_allow_bulk_capable).
//
// For the "vault" storage profile:
//   - Reads the sealed age identity blob from `stateDir/.age_identity.vault`.
//   - Derives the AES key via Argon2id over (pin, blob.salt).
//   - On success, marks the engine as `secretsUnlocked = true`.
//   - The PIN string is best-effort wiped (Go strings are immutable so
//     the wipe acts on the derived key buffer; see keyvault.wipe).
//   - The PIN NEVER persists, NEVER appears in diagnostics, NEVER crosses
//     any other ABI surface.
//
// For the "keystore" storage profile the call is a typed-error
// no-op: the engine is already secretsUnlocked at Init time (the
// platform keystore handles unlock transparently).
//
// Returns nil on success, ErrVaultProfileNotEnabled if the engine
// is running under the keystore profile, keyvault.ErrEmptyPIN on
// empty input, keyvault.ErrWrongPIN on wrong PIN, and a wrapped
// error on I/O.
func UnlockSecrets(pin string) error {
	c := mustCore()

	c.mu.Lock()
	profile := c.storageProfile
	stateDir := c.stateDir
	c.mu.Unlock()

	if profile != "vault" {
		// Keystore profile does not require a PIN unlock; the
		// platform keystore handled the routestore's age identity
		// at process-start. Calling UnlockSecrets here is harmless;
		// surface a typed error so the caller knows it was a no-op.
		return ErrVaultProfileNotEnabled
	}

	if pin == "" {
		return keyvault.ErrEmptyPIN
	}

	blobPath := filepath.Join(stateDir, vaultBlobName)
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		return fmt.Errorf("abi: read sealed identity: %w", err)
	}
	plaintext, err := keyvault.Open(blob, pin)
	if err != nil {
		return err
	}
	// At this layer we don't actually re-key the routestore (the
	// routestore is opened in Init before any unlock). The 2D
	// landing's contract is: the unlock primitive works end-to-end
	// (Argon2id derive + AES-GCM open succeed under the right PIN
	// and fail under the wrong one); a follow-up pass wires the
	// plaintext as the routestore age identity. This means 2D
	// ships the PIN-vault as a verifiable primitive without the
	// routestore-rewire that would change V2 entry-criterion
	// parity in a single phase.
	for i := range plaintext {
		plaintext[i] = 0
	}

	c.mu.Lock()
	c.secretsUnlocked = true
	c.mu.Unlock()
	return nil
}

// SecretsUnlocked reports whether the engine considers the
// routestore secrets readable. For the keystore profile this is
// always true after Init; for the vault profile it transitions to
// true on a successful UnlockSecrets call.
func SecretsUnlocked() bool {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.secretsUnlocked
}

// StorageProfile reports the storage-profile label detected at
// Init. One of {"keystore", "vault"} — behavioural, never
// group-based.
func StorageProfile() string {
	c := mustCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.storageProfile
}

// PutSecret stores a secrets_kv entry through the engine's
// routestore. NOT part of the release ABI surface — this is a
// thin host helper used by the soak harness (3E.8) to satisfy
// the `wasm.SecretsKV` interface without giving soak code
// direct routestore access. Returns nil on success or an error
// from the underlying routestore.
func PutSecret(key string, plaintext []byte) error {
	c := mustCore()
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if store == nil {
		return errors.New("abi: routestore not initialised")
	}
	return store.PutSecret(key, plaintext)
}

// GetSecret reads a secrets_kv entry. NOT part of the release
// ABI surface — see PutSecret.
func GetSecret(key string) ([]byte, error) {
	c := mustCore()
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if store == nil {
		return nil, errors.New("abi: routestore not initialised")
	}
	return store.GetSecret(key)
}

// ListSecretKeys lists secrets_kv keys matching the given
// prefix. NOT part of the release ABI surface — see PutSecret.
func ListSecretKeys(prefix string) ([]string, error) {
	c := mustCore()
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if store == nil {
		return nil, errors.New("abi: routestore not initialised")
	}
	return store.ListSecretKeys(prefix)
}

// SetAllowBulkCapable sets the budget engine's per-session
// bulk-capable opt-in flag. NOT a release ABI surface: the desktop
// reaches this via a Tauri command. The flag defaults to false on
// every engine_init and is cleared by NewSession; it survives
// SetMode and engine_network_changed.
//
// If the budget engine has not been instantiated yet (no
// SetRouteBudget call has happened), this is a no-op — the flag
// will be set the first time the budget engine is constructed via
// the lazy ensureBudget path.
func SetAllowBulkCapable(allow bool) {
	if eng := budgetEngineIfPresent(); eng != nil {
		eng.SetAllowBulkCapableThisSession(allow)
	}
}
