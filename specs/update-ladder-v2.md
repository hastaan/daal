# Update ladder v2: the secret, names and the wrapped code

Status: §2 and §3 built 2026-11-22 (wave 1, lanes 1A, 1B, 1E). §4 is
reserved for lane 1C (notes) and is not built. The study behind this is
`docs/update-ladder-v2.md` §3.

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

## 4. Names, keys and pads for notes (lane 1C, not built)

```
name(c, e) = base32lower(HKDF(ikm = u, info = "name" ‖ c ‖ e)[0:10])
key(c, e)  = HKDF(ikm = u, info = "key"  ‖ c ‖ e)[0:32]
pad(c, e)  = HKDF(ikm = u, info = "pad"  ‖ c ‖ e ‖ commit)[0:16]
```

The encoding of `c` and `e` is fixed when lane 1C builds them. The
labels `wrap`, `name`, `key` and `pad` never collide.

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
