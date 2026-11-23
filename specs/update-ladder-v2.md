# Update ladder v2: the secret, names and the wrapped code

Status: §2 and §3 built 2026-11-22 (wave 1, lanes 1A, 1B, 1E). §4 (notes,
their text forms and the carriers member) built 2026-11-22 (wave 2, lane
F); the writers and readers of each carrier build on it. The study behind
this is `docs/update-ladder-v2.md` §3 and §4.

## 1. One derivation

Every value below is HKDF-SHA256 (RFC 5869) with

- salt = the 14 ASCII bytes `daal/update-v2`,
- IKM and info as given, `‖` meaning concatenation with no separator
  unless one is written.

`bundle.UpdateHKDF` (Go) and `addon_standby::derive_update_secret` /
`wrap_key` (Rust) are the two implementations; the vectors in §5 are
computed independently in Python.

## 2. The update secret `u`

```
u = HKDF(ikm = update_root, info = relay_pack_id ‖ 0x0A ‖ audience)[0:32]
```

- **`update_root`**: 32 random bytes the publisher's app makes once
  (custody alias `update_root`). It never leaves the app: the helper
  binary and every file see only `u`.
- **`relay_pack_id`**: the id the relay had when its first secret was
  made. The app keeps it for the relay's life (relay update state,
  custody alias `update_people_<operator>`), so a rotation that renames
  the pack does not change the secret phones hold.
- **`audience`**: `everyone` (the Everyone file; assume the censor has
  it), `people` (every file made for a named person; the whole family
  shares it), `people/<g>` for generation g ≥ 2 (canonical decimal), or a
  recipient fingerprint (64 lowercase hex; allowed, not used yet).

**Removal.** When a person who held the current `people` generation is
no longer a person on the relay, the app moves the relay to the next
generation the next time a file is made or the code is asked for. Every
file made from then on carries the new `u`. A person who was removed
keeps only the old one, which wraps no code made after that.

### In the file

The archive member `update/secret.json` of the inner `.sbp`:

```json
{"v":1,"audience":"people","secret":"<standard base64 of 32 bytes>"}
```

- Exactly the members `v` (1), `audience` and `secret`; at most 1 KiB.
  Anything else is malformed, and a malformed member is **absent**: the
  file imports and its standby codes work in the plain form only.
- It sits beside `profiles/`, outside `manifest.json`, so it is not in
  the signed skeleton the freshness channel republishes. A person's file
  is a `.sbpx`, so the member is inside the age envelope. The Everyone
  file is a plain `.sbp` and may carry only the `everyone` audience (the
  helper refuses anything else).
- It is not signed. A planted secret only makes a real wrapped code fail
  to open; it cannot steer a phone (§3).
- Old builds skip unknown archive members (Go `ParseSBP`, Rust
  `bundle-rs`), so they import such a file as before
  (`bundle/go/importer/update_secret_test.go`, against the frozen rules
  of 079ef96).

### On the helper's command line

`users-pack-sbpx` and `users-pack-sbp` read `update_secret` (base64 of
`u`) and `update_audience` from the creds JSON they already read (`--creds-file`,
0600, deleted after the call). Never a flag. Stdout says only
`"update_secret": true|false`.

### On the device

`core/trust` SaveImport keeps the members beside each route's endpoint
commitment, at `update-secret:<route_id>` (`bundle.UpdateSecretStoreKey`),
in the encrypted secrets table, as a JSON array of members, newest first
(`bundle.MergeHeldUpdateSecrets`; a single member, as the first build
wrote it, is still read):

- a `people` secret (any generation) goes first; up to 4 distinct
  `people` secrets are kept, and the oldest is let go. The member is not
  signed, so an older copy of one's own file, or a planted member, must
  not cost the phone the secret that opens the next code;
- an `everyone` secret is written only where no `people` secret is held;
- a save without a secret (a refresh, an older file) keeps what is held;
- a route saved without a commitment holds none, and deleting a route
  deletes them (`routestore` perRouteSecretKeys).

## 3. The wrapped standby code

```
pad     = HKDF(ikm = u, info = "wrap" ‖ commit)[0:16]
wrapped = standby_key XOR pad
```

`commit` is the 32 raw bytes of the signed `_standby.commit`
(`specs/relaypack-v1.md`, "`_standby` key"), and `standby_key` is
`salt ‖ ipv4`. The wrapped code is shown exactly like the plain one: 26
Crockford base32 symbols in groups of 6-5-5-5-5.

- **Recipient.** `engine_standby_key` (no new export) tries the code as
  typed on each held sealed `_standby`, then unwrapped with each secret
  stored for that route. The signed commitment decides. An `everyone` secret,
  or none, means the plain form only. The key kept is always the plain
  key.
- **Publisher.** `wizard_addon_standby_key` returns `{key, form}` and a
  switch returns `{key, key_form}`, where the form is `wrapped` or
  `plain`; a wrapped answer also carries `plain_key`, which the code sheet
  offers behind one quiet action for a phone that cannot open the
  wrapped form (an older build, a file not imported yet). The code is
  wrapped only when the relay has no Everyone file (staged, or stamped in
  the database) and every current person's newest file carries the
  current generation. A person counts as holding it only once the helper
  reported `"update_secret": true` for their file (`record_holder`), so
  an older helper that ignores the secret records nobody. In every other
  case it is the plain key, with the earlier wording.
- **Why a leaked wrapped code reveals nothing.** Without `u` the pad is
  a PRF output under an unknown 256-bit key, so `wrapped` is a one-time
  pad of the key. The pad is used once: its input binds `commit`, and
  `commit` is a hash of the key. The commit itself hides the address
  behind 96 random salt bits.

## 4. Notes

Code: `bundle/go/bundle/update_note.go` (names, keys, pads, the micro
note and its text forms, the full note's framing),
`bundle/go/fullnote` (the full seal; its own package because it needs
`golang.org/x/crypto`, which modules that import only package `bundle`
do not carry), `bundle/go/bundle/update_carriers.go` (§4.5).

### 4.1 Names, keys and pads

```
info(p, c, e) = p ‖ 0x0A ‖ c ‖ 0x0A ‖ uint64be(e)

name(c, e) = base32lower(HKDF(ikm = u, info = info("name", c, e))[0:10])     16 characters
key(c, e)  = HKDF(ikm = u, info = info("key", c, e))[0:32]
pad(c, e)  = HKDF(ikm = u, info = info("pad", c, e) ‖ commit)[0:16]
```

- `c` is the carrier label, 1–16 of `[a-z0-9]` (so never 0x0A); `e` is
  always 8 bytes big-endian; `commit` is the 32 raw bytes of the signed
  `_standby.commit`. Every info string therefore parses one way.
- `base32lower` is RFC 4648 base32, alphabet `a–z 2–7`, no padding.
- The purposes `name`, `key`, `pad` and the wrap pad's `wrap` (§3, info
  `"wrap" ‖ commit`) begin with different bytes: no two derivations share
  an info string.

### 4.2 Carrier labels and epochs

| label | write | read by | epoch |
|---|---|---|---|
| `gittag` | a tag and a file in the publisher's GitHub repository | `github.com` (`tags.atom`), `raw.githubusercontent.com`, `proxy.golang.org` (direct and through the Google front), `goproxy.cn`, `goproxy.io`, jsDelivr | 7 days |
| `dns` | six A records in the publisher's zone | the phone's own resolver | 7 days |

A label names a WRITE: every reader of the git tag uses `gittag`
(`goproxy` is not a label). Epochs: `e = floor(unix_time / 604800)`; a
future write-once registry would use `floor(unix_time / 2419200)`. A
reader tries `e`, then `e − 1` (only `0` at epoch 0); a writer writes at
`e`.

### 4.3 The micro note

```
sealed = standby_key XOR pad(c, e)          16 bytes, no tag
```

- **Opening.** For each held secret (newest first) and each reader epoch:
  `candidate = sealed XOR pad(c, e)`; the candidate is used only when
  SHA-256(`daal/standby-v1` ‖ candidate) is the signed commit
  (`Standby.OpenMicroNote`, the discipline of `MatchStandbyCode`).
  Anything else is "nothing new".
- **Audience rule.** On `dns` only an audience that wraps (any but
  `everyone`) may write or read a micro note (`MicroNoteAllowed`): the
  national resolver logs the name, and the Everyone secret is assumed
  known. A writer refuses, a reader skips that secret.
- **Git tag form.** `v0.<seq>.0-<t>`, `<seq>` canonical decimal (the
  writer's counter), `<t>` the 16 bytes in 26 base32lower symbols, the
  last 3 bits zero (`GitNoteTag`, `ParseGitNoteTag`, strict). It is a
  valid Go module pre-release version, so the Go proxies list it.
- **DNS form.** Six questions, A only:

  ```
  q_i = name(dns, e)[0:12] ‖ decimal(i) ‖ "." ‖ zone          i = 0..5
  ```

  The 18-byte block `sealed ‖ r0 ‖ r1` (two random bytes) is cut into six
  3-byte pieces; answer `i` is `o_i . block[3i] . block[3i+1] .
  block[3i+2]`, with `o_i` drawn at random from the fixed list
  `23, 34, 35, 52, 54, 104, 151, 199` (ordinary public /8s). A reader
  refuses an answer that is not IPv4 or whose first octet is not in the
  list (that is how a sinkhole such as `10.10.34.36` is told apart) and
  ignores the two tail bytes. The zone is at most 80 characters, so a
  question stays under the 101-character cap seen in January 2026.

### 4.4 The full note

```
plaintext = uint32be(len(container)) ‖ container ‖ 0x00 …   to 4096, 16384 or 65536 bytes
sealed    = nonce(24) ‖ XChaCha20-Poly1305(key(c, e), nonce, plaintext, aad = "")
```

- The bucket is the smallest that holds `4 + len(container)`; the largest
  container is 65532 bytes. Opening checks the bucket, that the length
  fits it, and that the padding is all zero. Sealed sizes are 4136,
  16424 or 65576 bytes.
- The nonce is fresh random bytes for every seal.
- **Text form**: standard base64 with padding, canonical (no line
  breaks). A reader bounds its read at 87 436 characters
  (`MaxSealedFullNoteText`) plus whatever its carrier wraps around it, not
  at 64 KiB.
- The container is the `daal-refresh-v2` container of
  `specs/relaypack-v1.md`, with `slot` set to `name(c, e)`: a note copied
  to another name or carrier is refused. Its parts are verified exactly
  as a container from any mirror (signature chain, `sequence`, `not_after`,
  pack hash). The seal adds secrecy, never trust.

### 4.5 The carriers member

Where a phone reads its notes. The archive member `update/carriers.json`
of the inner `.sbp`, beside `update/secret.json`:

```json
{"v":1,"gittag":{"owner":"<o>","repo":"<r>"},"dns":{"zone":"<zone>"}}
```

- Every carrier is optional; `{"v":1}` names none. Exact member sets, no
  duplicate keys, at most 1 KiB, canonical order `v`, `gittag`, `dns` when
  written. Character rules (they go into URLs and DNS names as they are):
  owner 1–39 of `[A-Za-z0-9-]`, no leading, trailing or doubled hyphen;
  repo 1–100 of `[A-Za-z0-9._-]`, not starting with `.`, not ending in
  `.git`; zone a lowercase host name of two or more labels, each 1–63 of
  `[a-z0-9-]` without a leading or trailing hyphen, no trailing dot, a TLD
  of letters (or `xn--`), at most 80 characters.
- Malformed is **absent**, never a refusal. Old builds skip the member
  (`bundle/go/importer/update_carriers_test.go`, against the frozen rules
  of 079ef96).
- **Not signed.** A planted member can make the phone's next walk read
  from a repository or zone the planter controls (the planter learns that
  some phone asked, when, from where) or from nowhere (a denial for that
  carrier). It cannot give the phone an address or a document: a micro
  note must match the signed commitment and a full note is verified as any
  mirror's.
- **Helper.** `users-pack-sbpx` reads `update_carriers` (that JSON object)
  from the creds file; it needs a person's `update_secret` in the same
  creds, and is refused for the Everyone file (`users-pack-sbp`), which is
  public. Stdout says only `"update_carriers": true|false`.
  `users-pack-sbpx` without `--creds-file` refuses an input that already
  carries the member.
- **Device.** `core/trust` SaveImport keeps it at
  `update-carriers:<route_id>` (`bundle.UpdateCarriersStoreKey`), canonical,
  in the encrypted secrets table, beside the commitment. A valid member
  replaces what is held; a save without one (a refresh, an older file, a
  malformed member) keeps it; a route saved without a commitment holds
  none, and deleting a route deletes it (routestore `perRouteSecretKeys`).
- **Publisher app** (`client-shell/tauri/daal-wizard/src/addon_notes.rs`).
  A relay's switch («Updates through GitHub», kind `gittag`; «Updates
  through DNS», kind `dnsnote`; ledger V021) puts its carrier in the
  member once its first write went through (state `ready`). From then on
  every person's file carries it (`addon_standby::people_secret_for_file`
  → `update_carriers`); the Everyone file never does. GitHub: one public
  repository per relay under the account's login, named with 12 random
  letters and digits. DNS: the zone of the relay's way in through
  Cloudflare, else the Cloudflare account's zone.
- **What the app writes.** Only under the relay's current people audience
  (after a removal, the next generation): a removed person never reads a
  later note. Each write is one `note-gittag publish` / `note-dns publish`
  with every input on stdin. The full note carries the freshness document
  `publish-freshness` signed last (its pack inline when it fits under
  `MaxFullNoteContainer`), and only while it names the relay's current
  pack and has not expired; otherwise filler. The micro note (and the
  container's `standby_key`) reveals the most recent switch to a standby;
  otherwise filler. Writes run after every freshness publish, after a
  switch to the standby, and on app open for a switch whose last write is
  from an earlier epoch (or failed ten minutes or more ago). A failed
  write fails nothing else; the switch's row keeps `last_error`.

### 4.6 Always present

At the start of each epoch a writer puts filler at the next name: 16
random bytes for a micro note (`MicroFiller`, in the same text form), and
for a full note random bytes of the sealed size of the bucket the real
note will need (`FullFiller`). A reveal replaces filler with a note. An
observer who knows the name cannot tell "nothing yet" from "moved".

### 4.7 The git-tag write, as built

- The repository (public, under the publisher's note account; its name
  holds nothing of the relay) has two files only, at its root: `n` and
  `go.mod`.
- `n` holds `bundle.EncodeFullNoteText` of the sealed full note (or its
  filler); a trailing newline is allowed.
- `go.mod` begins `module github.com/<Owner>/<Repo>`, spelled exactly as
  in the carriers member (the Go proxies refuse anything else), and
  carries the same text as `// <chunk>` lines. The reading rule: take
  every line that starts with `//`, trim the text after `//`, keep those
  that are non-empty and only of the base64 alphabet, join them in file
  order, then `DecodeFullNoteText`. No other comment is a single
  base64-looking word.
- One lightweight tag per write: `bundle.GitNoteTag(seq, sealed)`, that is
  `v0.<seq>.0-<26 base32>`, on the commit that holds that write's `n`.
  `seq` grows with every write and is shared by the repository's
  audiences. The branch head holds only the latest write's `n`, so a
  reader reads by tag, never by branch. Note tags are the repository's
  only tags; a write deletes those beyond the newest 40 by seq (best
  effort), so the readers' 64 KiB indexes stay small (GitHub's
  `tags.atom` lists only the newest 10).
- The writer lists the tags with `per_page=100` page by page (GitHub
  pages the list); writer-only derivations use the HKDF purposes
  `gittag-writer-micro-filler`, `gittag-writer-full-filler` and
  `gittag-writer-nonce`.

## 5. Vectors

These use `update_root` = `00 01 … 1f`,
`relay_pack_id` = `rp-0123456789abcdef0123456789abcdef`, and the
`_standby` vector key (salt `00 01 … 0b`, `203.0.113.20`, plain
`000G40 R40M3 0E209 185WP 03H2G`, commit
`oLKATgHpOx6iddfCqnGCuDAi1XSE7ysXDZ1tUmE5HHY=`).

| | value |
|---|---|
| `u` people | `92b41abddf99cd530b5f2603f924f47059d1614d763b9aa012b71e39870ca072` |
| `u` everyone | `0021e1088f401278348c56d9c449d97557de9106dd9ad0d2b0986655abdf34e2` |
| `u` people/2 | `042011ad414559d3ba0b4d4c60725a0d261de2161222d8f800f64529f0ab9659` |
| wrap pad (people) | `6f018cd4e2ce853e3d2c23f9645338b6` |
| wrapped code (people) | `DW08XN Z6SE1 KJD95 57SAY MT9M8` |

Pinned in `bundle/go/bundle/standby_wrap_test.go`,
`core/abi/standby_wrap_test.go` and `daal-wizard` `addon_standby_tests.rs`.

### Notes (§4)

The same `u` (people) and `_standby` vector key, at
t = 2026-11-22T00:00:00Z (unix 1795305600, `e` = 2968; the 28-day epoch
is 742). Computed independently in Python (stdlib `hmac`/`hashlib`, own
info encoding and base32).

| | value |
|---|---|
| `name(gittag, 2968)` | `tvkj5326y3wnq2dr` |
| `key(gittag, 2968)` | `cbb7c0a356c427f587020ae06d2db1eb6b1674f3f682a5f1df58ce584359b9e1` |
| `pad(gittag, 2968)` | `c8e3e01ffff968c9b996464973ecc06b` |
| micro note (gittag) | `c8e2e21cfbfc6eceb19f4c42b8ecb17f` |
| tag, seq 7 | `v0.7.0-zdroehh37rxm5mm7jrblr3frp4` |
| `name(dns, 2968)` | `h5vbe4rwqtnl4xcu` |
| `pad(dns, 2968)` | `e79b33bc5e41c35d784dd9b650105aae` |
| micro note (dns) | `e79a31bf5a44c55a7044d3bd9b102bba` |
| DNS questions, zone `example.org` | `h5vbe4rwqtnl0.example.org` … `h5vbe4rwqtnl5.example.org` |
| DNS answers, tail `ee ff`, octet choices 0–5 | `23.231.154.49 34.191.90.68 35.197.90.112 52.68.211.189 54.155.16.43 104.186.238.255` |
| `name(gittag, 2968)`, everyone | `xay52jfi2iavjgwa` |

Full note: `key(gittag, 2968)` above, nonce `40 41 … 57`, container
`{"kind":"daal-refresh-v2","slot":"x"}` (padded to 4096). Sealed: 4136
bytes, SHA-256
`9f93800b695e3e89456d5bc4f3fad1ebc111a1f98b004c47ba40ef52e6fbcdee`, tag
`f5be064af25dbd117ba7ec1e49a364d1`. The Python side writes HChaCha20 out
by hand (checked against the known answer of draft-irtf-cfrg-xchacha-03
§2.2.1 and the AEAD tag of its §A.3.1) and uses the IETF
ChaCha20-Poly1305 of the `cryptography` package for the rest; Go uses
`golang.org/x/crypto/chacha20poly1305.NewX`.

Pinned in `bundle/go/bundle/update_note_test.go` and
`bundle/go/fullnote/fullnote_test.go`.
