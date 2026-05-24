// Phase 3E. Soak-side kill-switch delta application. Lives in
// a separate file so the build tag (`!soak` would still compile
// without it) and the imports are scoped narrowly.
//
// The soak harness owns a single in-memory Ed25519 keypair for
// the WASM kill-switch surface — the production CC.4 hardware-
// token-protected key is NOT available to the soak driver.
// The harness:
//
//   1. Lazily generates the keypair on first call.
//   2. Wires the verifier into the engine ABI on first call,
//      using the engine's WASM Loader and a thin in-memory
//      SecretsKV adapter that delegates to the routestore the
//      engine already opened at `engine_init`.
//   3. Signs the (slug, sha256, generation) tuple with the
//      lazily-generated private key.
//   4. Hands the signed entry to the engine's verifier
//      `Apply` method.
//
// The harness keeps the keypair in process memory only; soak
// runs are ephemeral and the keypair never escapes.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"

	"daal/core/abi"
	"daal/core/wasm"
)

var (
	soakWasmKSMu      sync.Mutex
	soakWasmKSPub     ed25519.PublicKey
	soakWasmKSPriv    ed25519.PrivateKey
	soakWasmLoader    *wasm.Loader
	soakWasmVerifier  *wasm.KillSwitchVerifier
	soakWasmKVAdapter *abiSecretsKV
)

// abiSecretsKV is a tiny SecretsKV adapter that satisfies
// `wasm.SecretsKV` by delegating into the engine's
// per-process secrets-KV surface. The engine's routestore
// already implements the same interface; we keep the adapter
// so soak builds do not have to import routestore directly.
type abiSecretsKV struct{}

func (a *abiSecretsKV) PutSecret(k string, b []byte) error {
	return abi.PutSecret(k, b)
}
func (a *abiSecretsKV) GetSecret(k string) ([]byte, error) {
	return abi.GetSecret(k)
}
func (a *abiSecretsKV) ListSecretKeys(prefix string) ([]string, error) {
	return abi.ListSecretKeys(prefix)
}

// soakApplyWasmKillswitchDelta is the soak harness's entry
// point for `soak-publish-wasm-killswitch-delta`. Lazy-wires
// the verifier on first call, signs the tuple, and runs Apply.
func soakApplyWasmKillswitchDelta(slug, sha256Hex string, generation uint64) error {
	soakWasmKSMu.Lock()
	if soakWasmKSPub == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			soakWasmKSMu.Unlock()
			return err
		}
		soakWasmKSPub = pub
		soakWasmKSPriv = priv
		soakWasmLoader = wasm.NewLoader()
		soakWasmKVAdapter = &abiSecretsKV{}
		soakWasmVerifier = wasm.NewKillSwitchVerifier(pub, soakWasmLoader, soakWasmKVAdapter)
		// Wire into the engine ABI surface. SetWASMLoader /
		// SetWASMKillSwitchVerifier reject re-wiring; if the
		// engine_init host caller already wired them, the
		// soak harness silently keeps its own pair (the
		// engine surface still reflects the host caller's
		// pubkey). In a clean soak boot the host caller has
		// not wired them, so the soak harness's wiring wins.
		_ = abi.SetWASMLoader(soakWasmLoader)
		_ = abi.SetWASMKillSwitchVerifier(soakWasmVerifier)
	}
	priv := soakWasmKSPriv
	verifier := soakWasmVerifier
	soakWasmKSMu.Unlock()

	if priv == nil || verifier == nil {
		return errors.New("soak: wasm kill-switch harness not initialised")
	}
	payload := canonicalKillswitchPayload(slug, sha256Hex, generation)
	sig := ed25519.Sign(priv, payload)
	entry := wasm.KillSwitchEntry{
		Slug:         slug,
		SHA256Hex:    sha256Hex,
		Generation:   generation,
		SignatureB64: base64.RawStdEncoding.EncodeToString(sig),
	}
	_, _, err := verifier.Apply([]wasm.KillSwitchEntry{entry})
	return err
}

// canonicalKillswitchPayload mirrors the engine's helper.
// Inlined here so the soak harness does not import any
// engine-package-private function.
func canonicalKillswitchPayload(slug, sha256Hex string, gen uint64) []byte {
	// {"slug":"…","sha256":"…","generation":N}
	const tplSlug = `{"slug":"`
	out := append([]byte{}, tplSlug...)
	out = append(out, escape(slug)...)
	out = append(out, `","sha256":"`...)
	out = append(out, escape(sha256Hex)...)
	out = append(out, `","generation":`...)
	out = appendUint(out, gen)
	out = append(out, '}')
	return out
}

// escape is a minimal JSON string escaper: only handles the
// characters that can appear in a slug or hex sha256 (which is
// none — slugs are [a-z0-9_-] and sha256 hex is [0-9a-f]).
// We keep the function here as a defensive layer in case a
// future test fixture uses unusual characters.
func escape(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch c {
		case '\\', '"':
			out = append(out, '\\', c)
		default:
			out = append(out, c)
		}
	}
	return out
}

func appendUint(out []byte, n uint64) []byte {
	if n == 0 {
		return append(out, '0')
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return append(out, buf[i:]...)
}
