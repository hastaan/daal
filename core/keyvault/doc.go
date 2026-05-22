// Package keyvault is the V0.1 PIN-vault encryption-key derivation
// primitive. Phase 2D wires it into the routestore's secrets layer
// so the age identity used to encrypt the per-network memory and
// the URL-secret KV is itself encrypted at rest under a PIN-derived
// key.
//
// The user PIN never leaves this package. It is used as Argon2id
// input, the resulting 32-byte key seals/unseals the age identity,
// and the PIN string is best-effort wiped after the derive call. No
// ABI surface, no diagnostics field, no log line ever sees the PIN.
//
// Argon2id parameters (locked at v1):
//   - time = 3
//   - memory = 64 MiB
//   - parallelism = 4
//   - salt length = 16 bytes
//   - output length = 32 bytes
//
// These are the OWASP 2024 Argon2id "moderate-resource" defaults
// and target the threat model of an adversary in possession of the
// device: each guess pays roughly 100 ms of CPU + 64 MiB. Adjusting
// any of them is a v2 spec change.
//
// Two storage profiles exist:
//   - "vault"    — the PIN-encrypted on-disk identity blob this
//     package operates on; selected when the engine state
//     directory contains the file `.use_vault`.
//   - "keystore" — the platform keystore handles unlock
//     transparently (Android Keystore / Keychain / DPAPI /
//     libsecret); keyvault is bypassed entirely.
//
// The "vault" / "keystore" labels are deliberately behavioural;
// they describe the storage path, not the user. No
// surveillance-targetable group label appears anywhere in the
// engine, in line with the V0.1 + CC.6 opsec posture.
package keyvault
