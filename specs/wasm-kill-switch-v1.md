
**Phase:** 3E
**Status:** Locked at 3E. Experimental.
**Roadmap line:** V3.5 — "WASM transport slot."
**Engine version:** `daal-core 0.8.0+v3-wasm`.
**ABI release surface:** Reuses release symbol 46
(`engine_wasm_kill_switch_pubkey`).

---

## Scope

Defines the project-controlled signed-delta channel that lets
the project rescind a WASM transport module without an engine
release. The kill-switch is **per-module**, not blanket
(rescinding `slug=A` does NOT affect `slug=B`).

The publisher private key is held under **CC.4 hardware-token
custody** (a separate offline air-gapped Ed25519 key from the
publisher manifest-signing key). The corresponding public key
is engine-immutable: it ships embedded in the engine binary at
3E and is exposed via `engine_wasm_kill_switch_pubkey()`. A
key rotation is a new spec phase.

---

## Locked invariants

1. **Single project-controlled key (3E).** Exactly one
   Ed25519 pubkey is recognised at v1. Multi-key federation
   is reserved for a future spec.

2. **Append-only generation watermark.** Every signed delta
   carries a monotonically-increasing `generation` (uint64).
   The engine rejects any delta whose generation is ≤ the
   watermark cached in `secrets_kv:wasm_killed:_generation`.
   This prevents replay of stale deltas.

3. **Canonical signing payload (locked byte-for-byte):**

   ```
   {"slug":"<slug>","sha256":"<64-hex>","generation":<N>}
   ```

   No whitespace, no trailing newline, JSON-string-escaped
   per RFC 8259. Both the publisher CLI
   (`bundle/go/publisher/wasm.go`) and the engine verifier
   (`core/wasm/killswitch.go`) MUST emit byte-identical
   bytes; a regression test
   (`TestPublisherCanonicalPayload_RoundTrips`) locks this.

4. **Kill-switch entry shape (locked):**

   ```json
   {
     "slug":       "evil-mod",
     "sha256":     "<64-hex>",
     "generation": 7,
     "signature":  "<base64-raw-std Ed25519 sig>"
   }
   ```

5. **Per-module sha256 keying.** The cache namespace is
   `secrets_kv:wasm_killed:<sha256-hex>`. Two modules with
   different blobs but the same slug are independent; killing
   one does NOT kill the other (different sha256 → different
   key).

6. **Daalte-on-boot.** At engine boot, the verifier daaltes
   the killed-set from `secrets_kv:wasm_killed:*`. A killed
   sha256 NEVER loads even after a process restart, even if
   the publishing channel is unreachable.

7. **No rescinds at v1.** The 3E surface only **adds**
   killed modules. To unblock a kill-switched module, the
   project MUST reissue it with a different sha256 (i.e.
   recompile and re-publish under a new blob). Rescind /
   un-kill is reserved for v2.

8. **Fuel exhaustion is NOT a kill-switch.** Modules that
   exhaust their fuel budget surface
   `last_wasm_module_dial_outcome = fuel_exhausted` and are
   unloaded for the rest of the session, but
   `wasm_kill_switched_count` does NOT increment. The
   `fuel_exhausted` outcome is a per-module budget signal,
   not a publisher-mediated kill.

9. **`no_unloaded_module_appears_in_diagnostics` invariant
   (canonical regression).** A killed module's slug or
   sha256 prefix MUST NOT surface in
   `loaded_wasm_modules` after the verifier applies the
   delta. The soak rig's `wasm-kill-switch` scenario asserts
   this.

10. **Soft-validation discipline.** A malformed kill-switch
    delta (bad signature, bad slug regex, generation ≤
    watermark) is rejected per-entry; other entries in the
    same delta-batch continue to apply.

---

## Refresh path

The kill-switch reuses the existing **pointer-rotation
refresh** path (see
[pointer-rotation-v1.md](pointer-rotation-v1.md)). The
publisher embeds new deltas in subsequent published bundles
under a top-level `wasm_kill_switch_deltas[]` array (locked
shape). Each delta is verified individually; the engine
applies accepted entries to the loader and persists them in
`secrets_kv`.

There is no separate "kill-switch URL" — running deltas
through the same channel that ships the bundles guarantees
that a network position which can deliver bundles can also
deliver kills.

## Custody

- **Publisher key (3E):** Ed25519, generated offline on a
  hardware token (CC.4); the seed never touches a networked
  machine. Signing is done air-gapped using
  `daal-publish wasm-killswitch` against an exported key
  file (or, in the project's runbook, a HSM-backed signer).

- **Engine pubkey:** ships embedded in the binary at build
  time (NOT from the bundle, NOT from the network). Rotation
  requires a new release. Surfaced to host UIs via release
  symbol 46 (`engine_wasm_kill_switch_pubkey()`).

## Diagnostics

The kill-switch surface contributes to two diagnostics
fields defined in
[wasm-transport-v1.md](wasm-transport-v1.md):

- `wasm_kill_switched_count` (int)
- `loaded_wasm_modules` (array; killed modules are absent)

## Cross-references

- [wasm-transport-v1.md](wasm-transport-v1.md)
- [pointer-rotation-v1.md](pointer-rotation-v1.md)
- [sbp-v1.md](sbp-v1.md)
- [routestore-v1.md](routestore-v1.md)
- [engine-abi-v1.md](engine-abi-v1.md)
- [publisher-cli-v1.md](publisher-cli-v1.md)
- [publisher-keys-v1.md](publisher-keys-v1.md)
