# Release runbook — from this tree to a phone

Written 2026-11-19 at the close of the release-ready wave. It is for the
OWNER: every step here needs something only the owner has (the release
key, the GitHub account, the cloud account that is billed, the phone).
Nothing in it has been done yet. Do the steps in order; each one says what
"pass" looks like, and what to do when it does not.

Every command is run from the repository root unless it says otherwise:

```
cd /home/nima/Projects/daal
```

**The one command that publishes anything is step 8.** Steps 1–7 prepare
and prove the commit that has to be pushed right after it; nothing before
step 8 leaves this machine.

Why the order matters, once: a relay downloads three programs at first
boot and checks each against a hash and a signature compiled into the app
(`publisher/deploy/cloudinit/artifacts.go`). The app in this tree speaks a
newer management protocol than the programs the tree currently pins, so
until the pin moves **this tree cannot build a working relay at all**, and
the pre-push hook is red on purpose (`release` world, `STOPPED at
provision`). The release (step 8) and the pin bump (steps 3–7, 10) fix
that together.

---

## Part 1 — The release, and the commit that goes with it

### 1. Commit the wave, check the machine

The wave itself must be committed before you start, on a branch (not
`main`), and **not pushed yet**: the pre-push hook fails on it alone, by
design. It is pushed together with the pin-bump commit in step 10.

```
git switch -c release-ready-wave
git add -A
git status --short             # read it: only source, specs, docs, tests
git commit -m "Release-ready wave: authenticated bootstrap, token v2 bound to relay and request, honest connect states"
```

Then:

```
go version                     # must print: go version go1.26.8 linux/amd64
gh auth status                 # must be logged in to the account that owns hastaan/daal
ls -l release-keys/release.key release-keys/android-device-signing.jks
git status --short | wc -l     # 0
git branch --show-current      # release-ready-wave
```

The Go version is part of the result: the same source under another Go
patch release gives different bytes and therefore different pins. If
`go version` prints anything else, stop and install go1.26.8, or accept
that every hash below will differ from the ones proven on 2026-11-19
(then step 7 is the first proof of those bytes — that is allowed).

### 2. Stage the candidate (uploads nothing)

```
bash tools/release/relay-v1.5.1.sh
cat dist-release/relay-v1.5.1/toolchain.txt
sha256sum dist-release/relay-v1.5.1/*-linux-amd64
```

It builds `daal-relay-health` and `daal-relay-mgmt` from this tree, takes
`sing-box` 1.13.12 from the checked tarball in `tools/vendor/`, signs all
three with `release-keys/release.key`, and writes the new pins to
`dist-release/relay-v1.5.1/artifacts.snippet.go`.

Pass: the script ends with `Staged under …/dist-release/relay-v1.5.1
(nothing was uploaded)`. With go1.26.8 and no change under
`cmd/daal-relay-mgmt/`, `cmd/daal-relay-health/` or
`publisher/deploy/health/` since 2026-11-19, the three hashes are:

```
989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2  sing-box-1.13.12-linux-amd64
407581d6b583d5d55f477b473087ed6e6cab65e6b9b88a0ba8eb1b196a76d055  daal-relay-health-0.1.0-linux-amd64
4f13e4538e5299c35ecd648c48754790d3859fac6b03695aecda42354e61f9de  daal-relay-mgmt-0.1.0-linux-amd64
```

Different hashes for the two `daal-relay-*` files mean the source or the
toolchain changed since. That is not an error; it means the proof in
step 7 is the only proof those bytes have.

### 3. Apply the pin bump (edits files; commits nothing)

```
python3 tools/release/pin-bump.py
gofmt -w publisher/deploy/cloudinit/artifacts.go
git diff --stat
```

What it changes — check each with the command beside it:

| what | where | check |
|---|---|---|
| the three pins (hash, signature, download addresses for `relay-v1.5.1` and `relay-v1.5.1-mirror`) | `publisher/deploy/cloudinit/artifacts.go` | `for f in dist-release/relay-v1.5.1/*.sha256; do grep -c "$(cat $f)" publisher/deploy/cloudinit/artifacts.go; done` prints three numbers, none of them 0 |
| constant flips to `true` | `publisher/deploy/cloudinit/artifacts.go` | `grep -n 'const PinnedMgmtServesOptInFamilies' publisher/deploy/cloudinit/artifacts.go` → `= true` |
| its mirror flips to `true` | `client-ui/src/publisher/extraFamilies.ts` | `grep -n 'RELEASED_RELAY_SERVES_EXTRA_FAMILIES =' client-ui/src/publisher/extraFamilies.ts` → `= true;` |
| known-findings entries deleted: `F-002`, `LC-1`, `INT-2`, `F-005` | `test-rigs/worldbox/known-findings.json` | `python3 -c "import json;print([e['id'] for e in json.load(open('test-rigs/worldbox/known-findings.json'))])"` → `['CEN-4']` |
| every `relay-v1.5.0` → `relay-v1.5.1` | the rig (`run.sh`, `driver/run.go`, `README.md`, `repro/int2-naive-alpn-race.sh`), three Go tests, `.github/workflows/gate.yml` | `git grep -n 'relay-v1\.5\.0' -- test-rigs/worldbox/run.sh test-rigs/worldbox/driver/run.go cmd/daal-relay-mgmt/singbox_mux_test.go publisher/deploy/cloudinit/template_test.go publisher/deploy/providers/hetzner/cover_sni_singbox_test.go .github/workflows/gate.yml` prints nothing |

If the script stops with a message, nothing it had not yet written was
touched: read the message, do not edit around it.

Also edit by hand, in `publisher/deploy/cloudinit/artifacts.go`, the
RELEASE COUPLING comment: the OPT-IN FAMILIES note is resolved by this
release (write the date).

### 4. Re-pin the cloud-init golden

The rendered cloud-init embeds the pins, so its golden hash moves with
them. The test prints the new value; this puts it in place:

```
OUT=$(cd publisher/deploy && go test ./cloudinit/ -run TestRender_GoldenSHA256 2>&1)
OLD=$(printf '%s\n' "$OUT" | sed -n 's/.*want \([0-9a-f]\{64\}\).*/\1/p')
NEW=$(printf '%s\n' "$OUT" | sed -n 's/.*got \([0-9a-f]\{64\}\) want.*/\1/p')
echo "old=$OLD new=$NEW"       # both must be 64 hex characters
sed -i "s/$OLD/$NEW/" publisher/deploy/cloudinit/template_test.go
(cd publisher/deploy && go test ./cloudinit/)
```

Then add one dated comment line above `want` in `TestRender_GoldenSHA256`
saying why it moved ("2026-MM-DD: relay-v1.5.1 pin bump").

Pass: `ok  daal/publisher/deploy/cloudinit`. With the hashes of step 2 the
new value is
`141280b3108d0127d75b83879095857235ae63b8305519712538b928f18de9e4`.
That same test run also verifies every staged file against its pinned
signature (`TestArtifacts_AllSigsVerifyAgainstPubkey`).

### 5. Mark the findings

In `test-rigs/worldbox/FINDINGS.md`:

* index table "Open": move `F-002`, `F-005` and `REL-1` to the "Fixed"
  table (status: "fixed — released as relay-v1.5.1, <date>"); update the
  two counts in the table headings;
* rows `LC-1`, `INT-2`, `BOOT-1`, `FAM-4`, `LC-3`: replace "rides the
  re-release" / "fixed in the tree" with "released as relay-v1.5.1";
* the sections `## REL-1`, `## F-002`, `## F-005`, `## BOOT-1`: add
  "(released <date>)" to the heading;
* the "Repo state" line near the top.

In `docs/backlog-post-45.md` §13: tick **TW-1**.

### 6. Unit tests, every module

```
./daal test
```

Pass: ends without `FAIL`. Two tests exist only for this commit and fail
on half of it: `TestPinnedMgmtOptInGateMatchesThePin` (pin without the
constant, or the reverse) and the `extraFamilies` test (the TypeScript
mirror).

### 7. Prove the candidate before anything is uploaded

```
./daal e2e full
./daal e2e full
```

The rig's "pinned" box now downloads from `dist-release/relay-v1.5.1/`
through a lab mirror and verifies the real hashes and the real signature.

Pass, both times:

* last lines: `RESULT: PASS — <n> checks; nothing unexpected (1 known
  finding(s) reproduced, listed above)` and exit status 0;
* the first table has **no** row saying `STOPPED`; rows `release.lifecycle`
  and `release.all-families` show `pass` under all seven families;
* the only `KNOWN` line is `CEN-4`; no `KNOWN [F-002|LC-1|INT-2|F-005]`.

(Proven on 2026-11-19 on a scratch copy of the tree with exactly steps 3–4
applied — see `docs/backlog-post-45.md` §13 for the numbers.)

If it is red: fix the cause, go back to step 2 (any change under
`cmd/daal-relay-mgmt/`, `cmd/daal-relay-health/` or
`publisher/deploy/health/` changes the pins), and repeat. Do not go on.

### 8. Publish — THE release command

```
cp dist-release/relay-v1.5.1/artifacts.snippet.go /tmp/snippet.proven.go
bash tools/release/relay-v1.5.1.sh --upload
diff /tmp/snippet.proven.go dist-release/relay-v1.5.1/artifacts.snippet.go && echo SAME-BYTES
```

What it uploads, to the public repository `hastaan/daal`, as two GitHub
releases with the same six files each — tags **`relay-v1.5.1`** and
**`relay-v1.5.1-mirror`**:

```
sing-box-1.13.12-linux-amd64                 sing-box-1.13.12-linux-amd64.sig
daal-relay-health-0.1.0-linux-amd64          daal-relay-health-0.1.0-linux-amd64.sig
daal-relay-mgmt-0.1.0-linux-amd64            daal-relay-mgmt-0.1.0-linux-amd64.sig
```

Nothing else: no source, no key, no app. `relay-v1.5.0` and
`relay-v1.5.0-mirror` are not touched and must stay published.

Pass: `SAME-BYTES` is printed (the script rebuilds before uploading; the
rebuilt pins must be the ones step 7 proved). Then check what the world
now gets:

```
for f in sing-box-1.13.12-linux-amd64 daal-relay-health-0.1.0-linux-amd64 daal-relay-mgmt-0.1.0-linux-amd64; do
  for tag in relay-v1.5.1 relay-v1.5.1-mirror; do
    printf '%s  %s/%s\n' "$(curl -fsSL "https://github.com/hastaan/daal/releases/download/$tag/$f" | sha256sum | cut -d' ' -f1)" "$tag" "$f"
  done
done
cat dist-release/relay-v1.5.1/*.sha256
```

Pass: each downloaded hash equals the staged one for that file, on both
tags.

If `SAME-BYTES` is not printed, or a downloaded hash differs: **do not
push.** Nothing pins the new tag until step 10, so it is still safe to
find the cause and run this step again. After step 10 the tag is frozen
for good: a later change of bytes needs a new tag (copy the script, bump
`TAG`), never a second upload.

### 9. Commit the pin bump

```
git add -A
git status --short             # the files of steps 3–5, nothing else
git commit -m "Pin relay-v1.5.1: token v2, authenticated bootstrap, /identity, opt-in families on the box"
```

### 10. Push (upload first, push second — CI downloads the published tag)

```
bash tools/hooks/pre-push      # must end: pre-push: all checks passed.
git push -u origin release-ready-wave
```

Open the pull request, wait for the `gate` workflow to be green, merge.

Pass: the hook prints no `✗`; the rig table has a `release` row with
`pass` cells, not `STOPPED`.

---

## Part 2 — What the follow-up commit contains (reference)

One commit (step 9). A test or the rig fails on any half of it alone.

| item | file | value comes from |
|---|---|---|
| `V15Artifacts`, `V2Artifacts` (hash, signature, two addresses × 3 files) | `publisher/deploy/cloudinit/artifacts.go` | `dist-release/relay-v1.5.1/artifacts.snippet.go`; single values: `cat dist-release/relay-v1.5.1/<file>.sha256` and `cat dist-release/relay-v1.5.1/<file>.sig.hex` |
| `PinnedMgmtServesOptInFamilies = true` | same file | fixed |
| `RELEASED_RELAY_SERVES_EXTRA_FAMILIES = true` | `client-ui/src/publisher/extraFamilies.ts` | fixed |
| delete entries `F-002`, `LC-1`, `INT-2`, `F-005` | `test-rigs/worldbox/known-findings.json` | fixed list; `CEN-4` stays |
| `relay-v1.5.0` → `relay-v1.5.1` in 8 files | listed in `tools/release/pin-bump.py` (`TAGGED`) | fixed |
| `want` in `TestRender_GoldenSHA256` | `publisher/deploy/cloudinit/template_test.go` | step 4 |
| findings and backlog marks | `test-rigs/worldbox/FINDINGS.md`, `docs/backlog-post-45.md` | step 5 |

---

## Part 3 — Native libraries, APK, signature

Do this AFTER step 9. The publisher library inside the APK carries the
pins; one built before the pin bump provisions relays that cannot be
managed.

### 11. Environment

```
export ANDROID_HOME=/home/nima/Android/sdk
export JAVA_HOME=/home/nima/Android/jdk21
export ANDROID_NDK_HOME=/home/nima/Android/android-ndk-r27
export NDK_HOME=$ANDROID_NDK_HOME
export PATH=$JAVA_HOME/bin:$PATH
```

### 12. Rebuild the native libraries

`npm run android:build` rebuilds none of these. Skipping this step ships
an old engine and old pins inside a new app.

```
bash tools/build-engine-android.sh       # libdaalcore.so + libcronet.so, 3 ABIs, about a minute
bash tools/build-deploy-android.sh       # libdaal_deploy.so, about 15 s
bash tools/check-engine-so-manifest.sh
bash tools/check-deploy-so-manifest.sh
```

This is not optional for a release that changes a helper verb or the
creds JSON the app writes. Wave 1 (2026-11-22) needs all three rebuilt
together: `users-share-links` ("Links for other apps") exists only in a
rebuilt `daal-deploy` / `libdaal_deploy.so`, and an older helper answers
it as an unknown verb (the person sees only "Couldn't make the links");
`users-pack-sbp[x]` must report `"update_secret"`, or no person is
recorded as holding the update secret and the standby code stays plain;
and the engine library must carry the wrapped-code check of
`engine_standby_key`. On the desktop the same holds for the `daal-deploy`
binary beside the app.

Pass: both checks end without an error. `check-deploy-so-manifest.sh`
fails if the library does not contain every hash and signature of
`artifacts.go` — the thing that goes wrong when this step is skipped. To
see it yourself:

```
strings client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libdaal_deploy.so \
  | grep -c "$(cat dist-release/relay-v1.5.1/daal-relay-mgmt-0.1.0-linux-amd64.sha256)"
```

Pass: prints `1` or more.

### 13. Tell the build which key to sign with

**Only `release-keys/android-device-signing.jks`.** The phone's installed
Daal is signed with it. An APK signed with any other key — including the
debug key the build falls back to silently, and
`gen/android/daal-phase45-test.jks`, which looks right and is not — is
refused with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, and the only way past
that is to uninstall the app, which **destroys the operator database**:
the relay records and the keys that manage every relay. Never uninstall.

```
cat > client-shell/tauri/src-tauri/gen/android/keystore.properties <<'EOF'
keyAlias=daal
password=daaltest
storeFile=/home/nima/Projects/daal/release-keys/android-device-signing.jks
EOF
```

(The file is git-ignored. Without it the release build is signed with the
Android debug key and still says "release".)

### 14. Build the APK

```
(cd client-shell/tauri && npm run android:build)
```

Pass: `Finished 1 APK at: …/app-universal-release.apk` (and an `.aab`).

### 15. Check the signature before the file goes anywhere

```
APK=client-shell/tauri/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk
$ANDROID_HOME/build-tools/35.0.0/apksigner verify --print-certs "$APK" | grep 'SHA-256'
```

Pass — exactly this digest:

```
Signer #1 certificate SHA-256 digest: 6026ec39c12cedc3112c9693b6cd2e6ba9c502fcb3716ee43261890977bb4796
```

Anything else (in particular `c1024abe…`, the debug key): do not install.
Fix step 13 and rebuild.

### 16. Install as an UPDATE

```
adb install -r "$APK"
```

Pass: `Success`.

* `INSTALL_FAILED_UPDATE_INCOMPATIBLE` → wrong key. Go back to step 15.
  **Do not uninstall.**
* `INSTALL_FAILED_VERSION_DOWNGRADE` → the installed app has a higher
  version number. Raise `version` in
  `client-shell/tauri/src-tauri/tauri.conf.json`, rebuild from step 14.
  **Do not uninstall.**

Open the app once. Pass: it opens, and the relays and connections that
were there before are still listed (they will be dead or refused — the
old relays are gone; that is expected and is checklist line P3).

---

## Part 4 — A fresh relay

Every relay must be created new. There is no upgrade path: a relay's
software and its service files are written once, at first boot, and a
relay built before step 8 cannot be managed by this app.

This step rents a server. It bills from the moment it is created until it
is deleted.

### 17. Clear out what the phone still lists

In the app: **Relays** → each old relay → remove → **Remove from Daal
only** (the servers no longer exist). If you are not sure a server is
gone, look in the cloud provider's console first; "Delete the server too"
is the choice when it still exists.

### 18. Provision

In the app: **Relays → + New relay**, the provider token, a plan and
region. Leave "More ways to connect" closed for the first relay (line P13
of the checklist makes a second one with a switch on).

Keep the app open and the screen on until it finishes. If the app is
killed half-way, **do not simply retry**: look in the provider's console
first and delete any half-made server and its SSH key, or you pay for two.

Pass: the wizard reaches its finished screen and the relay is listed.
This is the first time the authenticated bootstrap, token v2 and
`/identity` run against a real server.

Known ways to fail, and what each means:

| message contains | meaning |
|---|---|
| `does not recognise this provisioning secret` | the server downloaded the OLD health program: the app was built before the pin bump, or step 12 was skipped |
| `artifact verification failed` | the pins in the app do not match what is published: step 8's download check, then step 12 |
| `401` / `malformed token` on the first recipient | the server runs the old management program: same causes |

In each case: delete the server (provider console, or the app's "Delete
the server too"), fix the cause, start again at the step named.

### 19. First recipient

**Recipients → + Add** → your own Daal address (the phone's, or a second
device's). Save / show the file and import it under **Network → + Add**.

Pass: "Imported." and the relay's routes appear (four on a default
relay).

---

## Part 5 — Phone checklist

One relay from Part 4, the phone, and the provider's console in a browser
(to power the server off and on). Tick each line; write down the exact
words on screen for any line that does not pass. "Freeze" means the app
stops answering touches or Android shows "isn't responding".

| # | do | pass |
|---|---|---|
| **P1** | Tap Connect on a route of the new relay | "Checking the connection…" for a moment, then "You're connected." Open a website: it loads. Not "Reached the server, but the server itself cannot reach the internet" (that would mean the built-in check targets are unreachable from this server — write down the provider and region). |
| **P2** | Disconnect | "Press to connect." within a second. |
| **P3** | On **Network**, tap Connect on a route that was on the phone before the update (made by the old app) | Refused in words: "This file was made by an older version of Daal. Ask the person who gave it to you for a new one." Not silence, not "engine call returned -1". |
| **P4** | Same as P3, but first connect on the new relay and leave it connected | The same sentence appears, and the new route stays connected. |
| **P5** | Power the server OFF in the provider's console. Tap Connect | "Checking the connection…", then within about 8 seconds "Could not connect on this route. Try another one." No freeze at any point. The headline must NOT fall back to a bare "Press to connect." with no reason. |
| **P6** | Right away, tap Connect on the same route again (Connection page: the button opens the recovery sheet; use **Network → Connect** on that route) | "This route failed a little while ago, so Daal is giving it a rest. Try another route, or try this one again in a few minutes." |
| **P7** | Wait until P6's rest is over (5 minutes), tap Connect, and tap the button again while it says "Checking the connection…" | The button reads "Cancel" during the check; after the tap the check stops at once, "Press to connect.", no freeze, no error left behind. |
| **P8** | Power the server ON, wait a minute, connect (P1 again). Then power it OFF while connected | Within about a minute: "Connection lost. Trying again…". The button offers Disconnect; tapping it stops the retrying and returns to "Press to connect." |
| **P9** | Power the server ON. Android settings: Private DNS **Off**. Connect on the **naive** route; open a site you have not opened today, by name | The page loads. |
| **P10** | Still on naive: make a one-minute voice call in any messenger (calls are UDP) | Sound in both directions. Note anything unusual about delay or battery. |
| **P11** | If you have Tor bridges: **Network → + Add → Add Tor bridges**, connect on tor, Private DNS still off, open a site by name | The page loads (tor may take minutes to connect the first time; the headline stays on "Checking the connection…" meanwhile and Cancel works). |
| **P12** | Leave naive connected for a day of normal use. Then: `adb logcat -b crash -d > crash.txt; grep -i -c -e libdaalcore -e libcronet crash.txt` | Prints `0`: no crash entry names `libdaalcore.so` or `libcronet.so`. |
| **P13** | **Relays → + New relay**, open "More ways to connect": the three switches can now be turned on (before the release they were locked with "Not available yet"). Turn one on, provision, add yourself, import | The extra route is in the list and P1 passes on it. Delete this second server afterwards ("Delete the server too") and confirm in the provider's console that it is gone. |
| **P14** | On the first relay: add a second recipient, then Revoke them | Both succeed; no message containing `401` or `unauthorized`. |
| **P15** | On the first relay: Danger zone → "Change this relay's disguise" → ↻ Change disguise | It finishes; the result says in words who needs a new file ("Nobody is cut off…", or one of the other verdict sentences) — not "every file you have handed out is dead". Then P1 still passes with the file you already hold, on a route other than the disguised one. |
| **P16** | After P15: rebuild your own file on the Recipients screen, import it, connect on naive | "You're connected." (the server's certificate followed the new disguise). |
| **P17** | After P16, import the file from step 19 again (the old one) | Either "Imported." with a list titled "Some ways to connect are not in this file", each line in plain words, or a plain refusal. Whatever appears must be a sentence of the app's — never raw text from inside the file, never a code. Write down what you saw: this line has not been seen on any screen yet. |
| **P18** | Any time a connect ends with "The network is too slow right now to finish connecting. Try again in a moment." or "Reached the server, but the server itself cannot reach the internet…" | The main button says Connect and a tap tries the SAME route again (it does not open the recovery sheet). Cannot be forced on demand; tick it if it happens. |
| **P19** | Whole session | The app never froze and Android never offered "Close app / Wait". |

When you are done testing and do not want to keep the relay: remove it
with **"Delete the server too"** and confirm in the provider's console
that no server and no SSH key are left.

### What a failed line means

* P1 fails on every route, right after provisioning → Part 4's table.
* P5 or P7 freezes → the Android threading change does not hold on a real
  device; capture `adb logcat -d > logcat.txt` and keep the file.
* P5 ends on a bare "Press to connect." → the service's teardown is still
  erasing the reason; capture the diagnostics export from the app.
* P9 loads on Private DNS "Automatic" and not on "Off" → name lookups on
  naive (FAM-1 / TW-8).
* P12 shows a crash → INT-1 is not fixed on Android; keep the full
  `adb logcat -b crash -d` output.
