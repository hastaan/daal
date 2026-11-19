# Relay artefact releases

`relay-v1.5.1.sh` builds the three binaries a relay downloads at first boot
(`sing-box`, `daal-relay-health`, `daal-relay-mgmt`), signs each with the
release key (`release-keys/release.key`, never committed) and stages them
under `dist-release/relay-v1.5.1/` together with `artifacts.snippet.go` —
the pins to paste into `publisher/deploy/cloudinit/artifacts.go`.

```
bash tools/release/relay-v1.5.1.sh            # build + sign + stage. Nothing leaves the machine.
bash tools/release/relay-v1.5.1.sh --upload   # …and create/upload the GitHub releases. See the order below.
```

`keygen.sh` makes a release key pair. Its public half is
`cloudinit.DaalReleasePubKeyPEM`; changing it orphans every artefact ever
signed.

## Rules

* **A tag that is pinned anywhere is never uploaded to again.** A pin is
  (URL, sha256, signature). New bytes under an old URL break every build
  that pins the old hash (CI stages the published artefacts by those
  URLs) and let a cache answer a new pin with the old bytes — which the
  box refuses, on a server somebody is already paying for. A release that
  changes bytes gets a new tag (copy the script, bump `TAG`). That is why
  the script is `relay-v1.5.1.sh` although the artefact file names still
  say `0.1.0`; `relay-v1.5.0` and `relay-v1.5.0-mirror` stay published.
* **The build is reproducible, for one toolchain.** `-trimpath
  -buildvcs=false -ldflags="-s -w"`, `CGO_ENABLED=0`: the same tree under
  the same `go version` gives the same bytes at any path, and Ed25519
  signatures are deterministic, so running the script twice — or once to
  prove and once to upload — gives the same pins. A different Go patch
  release gives different bytes (relay-v1.5.0 was go1.26.0; the same
  `daal-relay-health` source under go1.26.8 hashes differently). The
  toolchain is written to `toolchain.txt` beside the artefacts.
* **`daal-relay-mgmt` must be built from the tree the publisher is built
  from.** The two halves of the management API are released on opposite
  sides of this pin (see RELEASE COUPLING in `artifacts.go`). Any change
  under `cmd/daal-relay-mgmt/` after the script ran means: run it again.
* **So must `daal-relay-health`.** It is the box half of the
  authenticated bootstrap (`publisher/deploy/health/bootstrap.go`, spec
  `daal-relay-mgmt-v1.md` §2.1): the publisher refuses a management
  fingerprint the health reply does not authenticate, and a health binary
  from before that (relay-v1.5.0, **and any relay-v1.5.1 candidate staged
  before 2026-11-19**) cannot. Any change under `cmd/daal-relay-health/`
  or `publisher/deploy/health/` after the script ran means: run it again.
  A relay provisioned with the older health binary fails at provisioning
  (`the relay's health endpoint does not recognise this provisioning
  secret`), never later.

## The pin bump

One commit. Everything below moves together; a test or the end-to-end rig
fails on any half alone. `python3 tools/release/pin-bump.py` makes the
edits of steps 1–4 from the staged snippet (it asserts every edit and
uploads, commits and tests nothing); 5–9 are by hand.

1. `publisher/deploy/cloudinit/artifacts.go`
   * replace `V15Artifacts` and `V2Artifacts` with `artifacts.snippet.go`
     (new `Sha256`/`SigHex`, new mirror URLs for all three artefacts);
   * `PinnedMgmtServesOptInFamilies = true`
     (`TestPinnedMgmtOptInGateMatchesThePin` fails on a bump without the
     flip and on a flip without the bump);
   * the RELEASE COUPLING notes: OPT-IN FAMILIES is resolved.
2. `client-ui/src/publisher/extraFamilies.ts`
   * `RELEASED_RELAY_SERVES_EXTRA_FAMILIES = true`
     (`tools/check-toolbox-profiles.mjs` and `extraFamilies.test.tsx` fail
     while it disagrees with the Go constant).
3. `test-rigs/worldbox/known-findings.json` — delete the entries that say
   "fixed in the tree, not on a released relay", all `box=pinned`:
   **`F-002`, `LC-1`, `INT-2`, `F-005`** (the last is "a relay built from
   the pinned release cannot say who it is": `GET /identity` rides this
   release). The run fails with "did not reproduce"
   until they go. Mark them **and `REL-1`** fixed in
   `test-rigs/worldbox/FINDINGS.md` (index rows and sections). REL-1 has
   no entry to delete: it is the unexcused red `mint
   verb.users-provision.r1` (401) that every pinned world stops at until
   this commit.
4. Everything that names the tag / staging directory of the **pinned**
   artefacts, `relay-v1.5.0` → `relay-v1.5.1`:
   * `test-rigs/worldbox/run.sh` (`ART` default, the preflight message)
   * `test-rigs/worldbox/driver/run.go` (`box.runs_pinned_artefacts`)
   * `test-rigs/worldbox/README.md`, `test-rigs/worldbox/repro/int2-naive-alpn-race.sh`
   * `cmd/daal-relay-mgmt/singbox_mux_test.go` (the sing-box binary it runs)
   * `publisher/deploy/cloudinit/template_test.go`
     (`TestArtifacts_AllSigsVerifyAgainstPubkey` reads the staged files)
   * `publisher/deploy/providers/hetzner/cover_sni_singbox_test.go`
   * `.github/workflows/gate.yml` (the release CI downloads)
5. The golden that embeds the pins:
   `publisher/deploy/cloudinit/template_test.go`, `TestRender_GoldenSHA256`
   — run `(cd publisher/deploy && go test ./cloudinit/)` and set `want` to
   the hash it prints, with a dated line saying why.
6. **Prove it before uploading.** With 1–5 applied, the rig's "pinned" box
   downloads from `dist-release/relay-v1.5.1/` (the lab mirror serves that
   directory under the pinned URLs; the box verifies the real hashes and
   the real signature):

   ```
   ./daal test                     # every module
   ./daal e2e full                 # 18 worlds
   ```

   Acceptance: worlds `release` (quick), `release.lifecycle` and
   `release.all-families` all green — 7 families in the last; no
   `KNOWN [F-002|LC-1|INT-2|F-005]` line in the report; the only reds are the
   open findings that have nothing to do with the release.
7. Then, and only then, `bash tools/release/relay-v1.5.1.sh --upload` from
   the same tree with the same toolchain (same bytes — compare
   `artifacts.snippet.go` before and after), and push the commit.
   **Upload before push**: CI stages the artefacts from the published tag.
8. Rebuild everything that EMBEDS the pins: `daal-deploy`, and the
   publisher library the apps load (`libdaal_deploy.so` for Android —
   `tools/build-deploy-android.sh` — and the desktop build). An app built
   before the commit provisions relays from the old pins whatever the
   tree says.
9. Every relay must be provisioned **fresh** afterwards. cloud-init has no
   upgrade path, and a relay built from relay-v1.5.0 cannot be managed by
   a publisher built after this commit at all (management token format
   v2, `specs/daal-relay-mgmt-v1.md` §3).

## What relay-v1.5.1 carries (since relay-v1.5.0)

| change | where | finding / backlog |
|---|---|---|
| shadowsocks, anytls, tuic on the box | `cmd/daal-relay-mgmt` (`families.go`, `singbox_*.go`) | F-002 |
| a relay binds and opens only the families it serves | `families.go` + cloud-init | FAM-4, W5-1 |
| mutating tokens are single-use | `main.go` | LC-1 |
| **token format v2: the signature covers the relay (its mgmt TLS fingerprint), method, path and body** — v1 refused | `main.go` (`tokenSigningInput`), `publisher/deploy/mgmt/token.go` | LC-1 residual, TW-12 |
| `alpn` written into `naive-in` (no start-up race) | `singbox_users.go` | INT-2 |
| one in-process reload per verb | `main.go`, cloud-init | INT-O1 |
| `rotate-tls` re-issues the TLS certificate for the new cover host, same key | `tlscert.go` | LC-3 remainder, TW-11 |
| `GET /identity` | `identity.go` | F-005 (another lane; rides this release) |

Not in the artefacts, but minted differently from the same commit on: the
naive outbound carries `udp_over_tcp` (FAM-6 / TW-8). The released
sing-box already accepts it; packs must be re-minted to get it.
