# Phase 1A — Publisher CLI: Handover

**Status:** Complete (implementation, tests, sample artifacts generated)
**Module:** `daal/bundle-go` (added `publisher/` and `cmd/daal-publish/`)
**Binary:** `daal-publish 0.1.0`
**Spec:** `specs/publisher-cli-v1.md`

---

## What was built

Phase 1A delivers the operator-facing CLI that turns a route manifest plus
profile bytes into a signed, deterministic `.sbp` bundle, and provides the
sub-key, revocation, and root-rotation flows that Phase 1B and beyond
consume. The CLI never opens a network socket; this is enforced by the
`opsec_test.go` source grep.

### Code

- `bundle/go/bundle/build_deterministic.go` — `BuildSignedBundleDeterministic`
  produces byte-identical output for identical inputs (sorted entries, zeroed
  `mtime`, deflate `Store`). Tested in `build_deterministic_test.go`.
- `bundle/go/publisher/`:
  - `duration.go` — `ParseDuration` accepting Go syntax extended with `d`/`w`.
  - `keystore.go` — `Keygen`, `LoadPub`, `LoadPriv`, `DefaultWordlists`,
    atomic writes, POSIX modes (`0700` keystore dir, `0600` priv, `0644`
    pub/meta), error sanitiser that never echoes private bytes.
  - `subkey.go` — `Subkey` issuance, `SubkeyCert` canonical-JSON, validity
    window enforcement in `VerifySubkeyCert`.
  - `canonical_sign.go` — canonical-JSON helpers (`signCanonical`,
    `verifyCanonical`) reusing the same RFC8785-ish ordering as bundle-go.
  - `lint.go` — 10 lint codes (`REALITY_COVER_SNI_IMPLAUSIBLE`,
    `PUBLISHER_KEY_REUSE`, `EXPIRY_TOO_LONG_BOOTSTRAP`,
    `EXPIRY_TOO_LONG_FRIEND_SHARE`, `UDP_ONLY_NO_TCP_FALLBACK`,
    `UDP_GATED_NOT_MARKED`, `EMPTY_PROFILES`, `PROFILE_OUTSIDE_DIR`,
    `BUNDLE_TYPE_MISMATCH_SCARCITY`, `MANIFEST_TIME_SKEW`). Pure metadata
    heuristics; no DNS, no fs traversal beyond the supplied profile bytes.
  - `bundle_cmd.go` — manifest policy enforcement, lint integration,
    `BuildSignedBundleDeterministic` invocation, self-verify before write,
    refusal to overwrite production-named outputs in `--unsafe-unsigned`
    mode.
  - `verify_cmd.go` — operator-side policy flags
    (`--require-trust-class`, `--max-route-count`, `--reject-on-warn`),
    redacted summary printer.
  - `revoke.go` — `SignedRevocation` with audit fields and root-key
    signature; round-trip `VerifyRevocation`.
  - `rotate.go` — `RotationChain` signed by old root; round-trip
    `VerifyRotationChain` enforcing the transition window.
  - Tests: `keystore_test.go`, `bundle_cmd_test.go`, `revoke_rotate_test.go`,
    `opsec_test.go` (forbidden network call sites and no-private-bytes-in-
    errors).
- `bundle/go/cmd/daal-publish/main.go` — dispatcher with subcommands
  `keygen`, `subkey`, `bundle`, `verify`, `revoke`, `rotate-key`,
  `fingerprint`, `version`. `--hsm` and signing-with-a-subkey are reserved
  and explicitly fail with a "not yet implemented" message so callers do not
  rely on them.

### Tests

- `go test ./bundle/... ./publisher/...` passes (10+ tests).
- Deterministic round-trip: identical inputs yield byte-identical `.sbp`.
- Round-trip end-to-end: manifest -> bundle -> parse -> verify (validates
  the deterministic builder did not regress bundle-go's verifier).
- Lint blocking: `UDP_GATED_NOT_MARKED` blocks build on UDP-first
  transports without `udp_gated`.
- Error policy: bundle expiry in the past is rejected with the documented
  message; manifest fingerprint mismatch is rejected.
- Sub-key, revocation, rotation: all signed, all round-trip verified, all
  reject tampering or out-of-window timestamps.
- OPSEC grep: forbidden network call sites do not appear outside the test's
  denylist; private-key bytes never appear in error strings.

### Sample artifacts (Phase 1B input)

Under `/home/daal/specs/test-vectors/bundles/samples/`:

```
keys-A/                       publisher root A (label "sample-publisher-A")
keys-B/                       publisher root B (label "sample-publisher-B")
profiles/route-1.json         minimal vless-reality profile
signed-A.sbp                  good signed sample, A
unknown-publisher-B.sbp       same shape, signed by a different publisher
valid-rotation-B.sbp          B-signed bundle bundling a rotation chain
rotation-A-to-B.json          rotation chain (A -> B), signed by A
revoked-A.sbp                 follow-on A bundle whose archive embeds an
                              in-archive RevocationList revoking route-1
revocation-A.json             standalone signed revocation (A)
work/                         intermediate manifests (ignore)
```

The bundle file lengths are stable across runs for any given `--Now`. The
samples were generated with the runtime clock; if Phase 1B requires a
fixed-clock corpus, regenerate with a wrapper that pins `time.Now()`.

---

## Decisions worth carrying forward

1. **Sub-key signing on bundles is staged.** `bundle.VerifyBundle` in
   `bundle-go` currently checks the bundle signature against the
   `publisher.pub` shipped inside the archive. Embedding a sub-key cert in
   `trust/subkey-cert.json` is supported, but `Bundle()` refuses to sign
   the manifest itself with a sub-key until bundle-go's verifier learns the
   cert chain. This is the right ordering — the chain is a Phase 1.5 trust
   feature — but Phase 1B should plan to implement the verifier-side cert
   chain so journalists can actually rotate sub-keys without a root touch.

2. **`--unsafe-unsigned` is hard-walled.** The CLI requires the output to
   end in `.UNSIGNED.sbp`, prints a stderr warning, and the bundle library's
   `VerifyBundle` will refuse the result anyway. Operators have to opt in,
   rename the file, and accept that no client will trust it.

3. **Lint heuristics are deliberately metadata-only.** No DNS, no IP
   geolocation, no ASN lookup, no profile-content interpretation beyond
   trivial substring matching. This keeps the publisher offline and keeps
   the failure modes explainable. The cost is that some real-world
   misconfigurations (e.g., a perfectly valid REALITY cover SNI) will not
   trigger findings; that is acceptable for V1.

4. **Default wordlists are placeholders.** `DefaultWordlists()` ships 16
   English and 16 Persian tokens — enough to render a fingerprint, not the
   full BIP-39 / curated Persian list a V0 deliverable will provide. The
   helper is exported so the CLI can use it consistently and so a future
   patch can swap in the real lists in one place.

5. **No telemetry of any kind.** `--quiet`, `--json`, and `--verbose` are
   reserved for stdout shape only. No counters, no event sinks, no opt-in
   reporting. The OPSEC test enforces that the CLI does not link `net/http`
   or call `net.Dial`.

6. **Group-based labels are absent.** No "activist", "journalist",
   "ordinary user", "high-risk", "device-seizure" strings appear in the
   spec, the CLI, or the publisher package. Trust class is the operator
   tag; route scarcity is the route tag; nothing else.

---

## Known follow-ups

- **bundle-go cert chain** (Phase 1.5 candidate): teach `VerifyBundle` to
  accept a manifest signed by a sub-key whose cert is embedded in
  `trust/subkey-cert.json` and signed by the bundle's `publisher.pub`. Once
  this lands, drop the "staged" guard in `publisher.Bundle`.
- **Inline revocation shape**: the in-archive `RevocationList` from bundle-
  go is unsigned, while `SignedRevocation` is signed. The split is
  intentional (the archive's outer signature already covers the inline
  list) but the field names differ. Phase 1B should decide whether the
  client honours both shapes or only the in-archive list, and we should
  document the canonical migration path in `specs/sbp-v1.md`.
- **Time-skew clamp on `bundle.created_at`**: today the lint warns at >24h
  forward or >90d backward. Phase 1B might prefer a hard block, especially
  for `friend_share` bundles that sit in a USB stick for weeks.
- **`--hsm`**: reserved flag exists; concrete integration (PKCS#11, age-
  plugin-yubikey) is a Phase 1.5 deliverable.
- **CLI smoke tests**: the `cmd/daal-publish` entry point is exercised
  manually here. A `cmd/daal-publish/main_test.go` that runs the binary
  against the sample artifacts would harden the CI matrix.

---

## Where Phase 1B picks up

Phase 1B (Android bootstrap MVP) consumes:

- `signed-A.sbp` for the happy-path "valid bundle, valid signature" test.
- `unknown-publisher-B.sbp` for the "publisher you have not pinned" UI.
- `valid-rotation-B.sbp` + `rotation-A-to-B.json` for the rotation-chain
  acceptance flow.
- `revoked-A.sbp` + `revocation-A.json` for the route-revocation surface.
- `keys-A/publisher.pub` and `keys-B/publisher.pub` for the trust pin
  store.

Concretely, the Android client should be able to:

1. Pin `publisher-A` via its hex fingerprint (or the EN/FA renderings).
2. Accept `signed-A.sbp` and surface the route count + expiry.
3. Reject `unknown-publisher-B.sbp` with a "you have not pinned this
   publisher" UI before any handshake bytes are sent.
4. Accept `valid-rotation-B.sbp` only after the bundled rotation chain is
   verified against the pinned `publisher-A`, then pin `publisher-B`.
5. Honour the revocation embedded in `revoked-A.sbp` and stop offering
   route `sample-route-1`.

If any of those flows requires fields the CLI does not yet emit, file a
Phase 1B issue against `specs/publisher-cli-v1.md` rather than working
around it client-side.

---

## Validation snapshot

```
$ cd /home/daal/bundle/go
$ gofmt -l ./bundle ./publisher ./cmd
(no output)
$ go build ./bundle/... ./publisher/... ./cmd/...
$ go test ./bundle/... ./publisher/...
ok      daal/bundle-go/bundle
ok      daal/bundle-go/publisher
$ go build -o /tmp/daal-publish ./cmd/daal-publish
$ /tmp/daal-publish version
daal-publish 0.1.0
$ /tmp/daal-publish fingerprint specs/test-vectors/bundles/samples/keys-A/publisher.pub
hex: baf7fd3808058a8575c46473a0ef60dd38639bda92caf42550a4449995c001c9
 en: hotel-papa-alpha-alpha
 fa: هشت-شانزده-یک-یک
```

OPSEC grep: no `net/http` / `net.Dial` / `http.Client` references outside
`opsec_test.go`'s denylist constant.

---

## Files changed

```
bundle/go/bundle/build_deterministic.go         (new)
bundle/go/bundle/build_deterministic_test.go    (new)
bundle/go/publisher/canonical_sign.go           (new)
bundle/go/publisher/duration.go                 (new)
bundle/go/publisher/keystore.go                 (new, exports DefaultWordlists)
bundle/go/publisher/lint.go                     (new)
bundle/go/publisher/bundle_cmd.go               (new)
bundle/go/publisher/verify_cmd.go               (new)
bundle/go/publisher/revoke.go                   (new)
bundle/go/publisher/rotate.go                   (new)
bundle/go/publisher/subkey.go                   (new)
bundle/go/publisher/keystore_test.go            (new)
bundle/go/publisher/bundle_cmd_test.go          (new)
bundle/go/publisher/revoke_rotate_test.go       (new)
bundle/go/publisher/opsec_test.go               (new)
bundle/go/cmd/daal-publish/main.go             (new)
specs/publisher-cli-v1.md                       (new)
specs/test-vectors/bundles/samples/             (new corpus)
phases of development/04-phase-1a-publisher-cli.handover.md  (this file)
```

Phase 1A is ready for the Phase 1B working session.
