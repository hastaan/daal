//go:build no_wasm

package wasm

import (
	"crypto/ed25519"
	"errors"
)

// Phase 3E. Kill-switch shims under `-tags no_wasm`. The engine
// still surfaces the kill-switch ABI (`engine_wasm_kill_switch_pubkey`),
// which returns an empty string under this build; deltas are
// silently ignored at refresh time.

var (
	ErrKillSwitchPubkeyMissing  = errors.New("wasm: kill-switch pubkey not configured")
	ErrKillSwitchSignature      = errors.New("wasm: kill-switch signature invalid")
	ErrKillSwitchEntryMalformed = errors.New("wasm: kill-switch entry malformed")
	ErrKillSwitchGenerationGoes = errors.New("wasm: kill-switch generation must increase")
)

type KillSwitchEntry struct {
	Slug         string `json:"slug"`
	SHA256Hex    string `json:"sha256"`
	Generation   uint64 `json:"generation"`
	SignatureB64 string `json:"signature"`
}

type SecretsKV interface {
	PutSecret(key string, plaintext []byte) error
	GetSecret(key string) ([]byte, error)
	ListSecretKeys(prefix string) ([]string, error)
}

type KillSwitchVerifier struct{}

func NewKillSwitchVerifier(_ ed25519.PublicKey, _ *Loader, _ SecretsKV) *KillSwitchVerifier {
	return &KillSwitchVerifier{}
}

func (v *KillSwitchVerifier) PubkeyHex() string                           { return "" }
func (v *KillSwitchVerifier) Apply(_ []KillSwitchEntry) (int, int, error) { return 0, 0, nil }
func (v *KillSwitchVerifier) DaalteFromKV() (int, error)                  { return 0, nil }
func (v *KillSwitchVerifier) KillSwitchedCount() (int, error)             { return 0, nil }

func VerifyEntry(_ ed25519.PublicKey, _ KillSwitchEntry) error { return ErrCompiledOut }
