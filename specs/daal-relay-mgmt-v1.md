# `daal-relay-mgmt` — V2 in-box management plane (v1)

**Status:** locked at FRP-10 (May 2026); **extended at FRP-14** (lifts the 3-route invariant to 6 routes; see `specs/per-recipient-credentials-v1.md`); **extended again at the publisher redesign** (7th route `/whoami`, §4.7). · **Supplement reference:** §9.5.2, §9.5.5. · **Engine line:** `daal-core 0.9.0+v3-share` (no engine ABI surface — this is an in-box userspace daemon).

This spec defines the contract between the FRP Helper and the persistent in-box `daal-relay-mgmt` service that ships with FRP-10's V2 deploys. It locks the wire format, the auth scheme, the TLS posture, the port discipline, and the API surface (eleven routes today; §4 counts them and names the amendment each one needed). The Helper-side mirror (`publisher/deploy/mgmt/`) and the box-side service (`cmd/daal-relay-mgmt/`) are both pinned by tests against this contract.

---

## 1. Service identity

* **Binary path on box:** `/usr/local/bin/daal-relay-mgmt`
* **Systemd unit:** `daal-relay-mgmt.service` (installed by the V2 cloud-init template)
* **Runs as:** `root` (needed to rewrite `/etc/sing-box/config.json` and reload `sing-box`; the mgmt port itself is high and does not require `CAP_NET_BIND_SERVICE`)
* **Listening port:** read at boot from `/etc/daal/mgmt/port`, in `[10000, 65000]` per the V2 cloud-init render. Refuses to start on values outside this range.
* **Listening address:** `0.0.0.0:<port>` — the cloud-provider firewall is the gate, not box-side `ufw`. See §4 below.

## 2. TLS posture

* **Cert:** self-signed leaf on a P-256 ECDSA key pair, generated on-box at first boot if `cert.pem` / `key.pem` are absent under the service's data dir.
* **Lifetime:** 10 years (`NotAfter = NotBefore + 10y`). There is no in-place management-cert rotation endpoint in v1; replacing the management cert requires a redeploy or a future explicit management-cert rotation spec.
* **Fingerprint publication:** the SHA-256 of the cert DER is written hex-encoded to `/var/log/daal/mgmt-tls.fpr` and read by the FRP-9 bootstrap-window relay (`daal-relay-health`) which emits it to the Helper alongside the standard health JSON during the provisioning window. The Helper persists it into `OperatorRecord.MgmtTLSFingerprint` (FRP-10 invariant 26) — **only if it is authenticated, §2.1.**
* **TLS minimum:** TLS 1.3.

The cert is intentionally **not** issued by a public CA. The trust model is fingerprint-pinned-per-deploy; system trust stores are never consulted. The Helper-side mgmt client (`publisher/deploy/mgmt/client.go`) sets `InsecureSkipVerify: true` and supplies a `VerifyPeerCertificate` callback that compares `sha256(rawCerts[0])` against `rec.MgmtTLSFingerprint`; mismatch returns `ErrFingerprintMismatch` (no fallback).

### 2.1. How the pin is learned — the authenticated bootstrap

Everything in this spec rests on `rec.MgmtTLSFingerprint`: §3 authenticates the Helper's *requests*, and every *reply* — including `GET /identity` (§4.9), which the publisher signs into a pack — is believed only because it arrives on the session pinned to that fingerprint. The fingerprint is learned once, during provisioning, from `daal-relay-health` on port 9876 over **plain HTTP** (the box has no certificate the Helper could verify yet). The path between the two is not trusted: the box-side firewall rule limits who may *ask*, not who may *answer*.

What the two ends share and the path does not is the **health token**: the Helper generates it (≥ 128 random bits) per provision and it reaches the box inside cloud-init user-data, over the cloud provider's HTTPS API (`/etc/daal-health/config.json`, `one_time_token`). It is **never sent between the Helper and the box**. Two values are derived from it, under distinct labels:

```
path_token = hex( HMAC-SHA256( key = health_token, msg = "daal-health-path-v1" ) )
mac_key    =      HMAC-SHA256( key = health_token, msg = "daal-mgmt-fpr-v1" )
fpr_mac    = hex( HMAC-SHA256( key = mac_key,      msg = fingerprint ) )      # fingerprint: 64 lowercase hex chars, no whitespace
```

* **Request:** `GET http://<box>:9876/healthz/<path_token>`. The box answers that path only (constant-time compare); the raw health token in the URL is a 404 like any other path. Reading the URL off the wire yields `path_token`, from which neither `health_token` nor `mac_key` follows.
* **Reply:** the health JSON carries `mgmt_tls_fingerprint` and, beside it, `mgmt_tls_fingerprint_mac` = `fpr_mac`. The box sends the MAC whenever it sends a fingerprint.
* **Helper:** a reply whose `mgmt_tls_fingerprint` is non-empty and whose MAC does not verify (constant-time) is an error (`health.ErrFingerprintUnauthenticated`) and yields no fingerprint — in every provider adapter, because the check is inside the poller (`publisher/deploy/health`, `Poller.poll`). **There is no unauthenticated fallback**: a box whose health binary predates this (relay-v1.5.0) answers the derived path with 404, and the Helper stops with `health.ErrBootstrapRefused` once that has lasted 10 s rather than send the token in the clear.
* **Not authenticated, on purpose:** `healthy`, `singbox_running`, `uptime_sec`, `debug_log`. They are progress hints; a machine on the path can delay or fail a provision (it could do that by dropping packets) and nothing else. No security decision may read them.

Test vector (`TestFingerprintMAC`): `health_token = "health-token-vector"`, fingerprint `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` → `path_token = ec458bcc5ada54679b67f5dc2a803ff199ce544a8ae49d7bb5e544e69eaa62a3`, `fpr_mac = c5e0cec94dd3c83f8f3269c292aa6df26853b799ea7adf5b1cd9690cfe7d8c26`.

**Second line, in the wizard.** A relay's REALITY key and TLS key have no operation that replaces them (§4.2 re-issues the certificate on the same key; §4.2.1), so only a rebuild changes them, and a rebuild changes the management certificate. The wizard therefore refuses — `E_RELAY_KEYS_CHANGED`, nothing signed, no refresh note published — when a relay whose record still carries the management fingerprint its identity was learned under states a different REALITY key or TLS pin than the one the active pack commits to (`relay_identity::refuse_keys_changed_in_place`). A wrong pin, however it came about, then cannot be turned into a publisher signature over somebody else's key on an existing relay.

## 3. Auth — Ed25519 request-bound tokens (token format v2)

Every endpoint except `/health` requires an `Authorization` header of the form:

    Authorization: Daal-Mgmt-Token v2:<nonce>:<ts>:<op>:<base64-sig>

where:

* `v2` is the token format. **The box refuses every other format**, including the unversioned v1 shape (`<nonce>:<ts>:<op>:<base64-sig>`, signature over `<nonce>:<ts>:<op>`), which signed neither the body nor the method. There is no compatibility path in either direction: a v1 publisher cannot drive a v2 box and a v2 publisher cannot drive a v1 box. Nothing was fielded on v1 when the format changed; a relay provisioned with a v1 daemon is rebuilt, like every other daemon change (cloud-init has no upgrade path).
* `nonce` is 16 random bytes hex-encoded (32 hex chars), fresh per request. The on-box service tracks seen nonces for every **mutating** op, each of which is single-use (see **Replay** below).
* `ts` is the Helper's clock as seconds-since-Unix-epoch.
* `op` names the route: `rotate-credentials`, `rotate-tls`, `users-provision`, `users-revoke`, `users-list`, `whoami`, `identity` (§4.9), `bind-address`, `unbind-address`, `cdn` (§4.10) (and any read op a later section adds), matching `opFromPath` in `cmd/daal-relay-mgmt/main.go` and the `opRoutes` table in `publisher/deploy/mgmt/token.go`. The on-box service rejects any token whose `op` does not match the URL path.
* `<base64-sig>` is the standard-encoding base64 of `Ed25519.Sign(privKey, signing_input)`.

**What is signed.** `signing_input` is eight lines joined by a single `\n` (0x0A), with no trailing newline:

    daal-mgmt-token-v2
    <relay>
    <nonce>
    <ts>
    <op>
    <METHOD>
    <path>
    <hex sha256(body)>

* line 1 is a fixed context string: it separates this signature from every other document the publisher key signs;
* `<relay>` names the **one relay the token is for**: the lower-case hex SHA-256 of the DER bytes of that relay's management TLS certificate (64 hex chars) — the value the publisher pins the session on (`OperatorRecord.MgmtTLSFingerprint`, §2.1), trimmed and lower-cased before signing. The box computes its own from the certificate it serves, at start-up, and never from anything in the request; a box that cannot name itself refuses every token. The publisher refuses to mint for a fingerprint that is not 32 bytes of hex. This line is not on the wire: each end supplies it from what it already knows;
* `<METHOD>` is the HTTP method in upper case (`POST`, `GET`);
* `<path>` is the request path exactly as registered (`/users/revoke`), with no query string — no route takes one, and the box refuses any request to an authenticated route that carries one (even a bare `?`) with `400`, before it reads the token, so nothing the publisher did not sign can reach a handler;
* `<hex sha256(body)>` is the lower-case hex SHA-256 of the request body **bytes as sent**. An absent body and an empty body are the same (the digest of zero bytes). There is no canonicalisation: the publisher signs the bytes it sends and the box hashes the bytes it received.

So a token authorises **one request to one relay**: this relay, this op, this method, this path, these body bytes. Presented with anything else, or to any other relay, it is `401`.

**Why the relay is named.** One publisher key can be trusted by more than one relay: a key imported into a second installation, or the old and the new box around a rebuild, which keep the operator's key. Without `<relay>` a token was good on every one of them, so a relay that received a request could present the identical request to a sibling inside the accept window (it would still need a path through the sibling's firewalls) — and the sibling's nonce set, being per process, had never seen it. The line was added before any v2 verifier was released, so it is part of v2, not a v3. The box reads the whole body (at most 64 KiB — larger is `413` before any signature work) before verifying, and hands the handler exactly the bytes whose digest was signed.

A shared fixture, `publisher/deploy/mgmt/testdata/token_v2_vector.json`, pins both ends to the same bytes: the publisher's minter must reproduce its tokens (`TestTokenV2Vector_PublisherProducesTheFixture`) and the box must accept them and refuse them for another body and on another relay (`TestTokenV2Vector_BoxAcceptsWhatThePublisherSigns`). The two ends are separate Go modules and share no symbol.

The `privKey` is the Helper's per-deploy publisher Ed25519 private key. Its public half is written to `/etc/daal/mgmt/pubkey` by cloud-init at first boot (hex-encoded, 64 chars) so the on-box service can verify tokens without ever holding the private half.

**Timestamp window:** the on-box service accepts `ts` in `[serverNow - 300 s, serverNow + 60 s]`. Older tokens are rejected to bound replay; future tokens are rejected to bound clock-skew abuse.

**Op-binding:** the on-box service refuses to accept a token signed for `rotate-credentials` against `/rotate-tls` and vice versa — twice over, since the path is also under the signature.

**Replay.** With the relay and the request under the signature, the only thing a captured token can do is repeat **the identical request to the same relay**. For the mutating ops the box refuses even that: each is **single-use per token**, by a bounded, window-pruned nonce set (4096 entries, pruned at 300 s). The read-only ops, `users-list`, `whoami` and `identity` (§4.9) (and any read op a later section adds), stay replayable on purpose: they change nothing, and a `GET` rides on a request the HTTP transport may legitimately re-send with the same token, while every mutating op is a `POST` with a body, which the transport never replays once a byte reached the server.

**What single use does and does not cover.** The nonce set lives in the memory of the `daal-relay-mgmt` process and is not persisted, so it holds **for the life of that process**. It is defence in depth, not the guarantee: after a restart of the service or a reboot of the box, a token captured before it can be presented once more until its timestamp leaves the accept window — and, because the body is signed, all that buys is a repeat of the request the publisher already made. What a repeat does, per op: `users-revoke`, `bind-address`, `unbind-address` are idempotent; `rotate-tls` with an unchanged body changes nothing and is `400`; `users-provision` for a name that exists is refused; **`rotate-credentials` re-mints the same recipient once more**, which cuts that one recipient off until they are re-delivered again — the one residual, reachable only by somebody who holds a token (it travels inside the fingerprint-pinned TLS session), has a path to the port (two firewalls) and can restart the daemon or the box within 300 s. The nonce is consumed when the token verifies, before the handler parses the body, so a request the handler then rejects (400/405/500) has still spent its token; a caller retries with a freshly minted one, which is what the publisher client does on every call.

History: v1 tokens signed `nonce:ts:op` only, so a captured token authorised any body on its route; single use was added for the address verbs (Wave 3c) and then for every mutating verb after the one-machine end-to-end rig replayed a `users-revoke` token against a second recipient (`test-rigs/worldbox/FINDINGS.md` LC-1). That left the restart case open, which v2 closes.

## 4. API surface — exactly eleven routes

The FRP-10 baseline locked three routes (`/rotate-credentials`, `/rotate-tls`, `/health`). FRP-14 adds three per-recipient routes (`/users/provision`, `/users/revoke`, `/users/list`), specified in `specs/per-recipient-credentials-v1.md`. The publisher redesign adds a seventh, `/whoami` (§4.7). **Wave 3c adds the eighth and ninth, `/bind-address` and `/unbind-address` (§4.8)** — this paragraph is that supplement amendment. **The truth wave adds the tenth, `GET /identity` (§4.9)** — read-only, and this sentence is its amendment. **The optional add-ons add the eleventh, `POST /cdn` (§4.10)**, the relay's door for the way in through Cloudflare (`specs/optional-addons-v1.md` §4) — and this sentence is its amendment. Adding a **twelfth** route requires another. The implementation-level invariant is pinned by `TestExactlyNRoutes` (n=11) in `cmd/daal-relay-mgmt/main_test.go`.

The two address routes are counted as one addition, not two, and ship together: an unbind with no bind has nothing to undo, and a box with one and not the other is a shape no release produces. They share a single capability token (§4.8).

### 4.1. `POST /rotate-credentials` — L1, ~5 s

**Revised at Wave 3 Step 7.** This route previously accepted an empty body, rotated *every* recipient, and rotated the box-wide REALITY keypair as a side effect. That conflated a targeted revocation with a fleet-wide invalidation; the two have completely different blast radii and are now separate operations. The old shape is described in §4.1.1 only so that publishers can recognise a box that still implements it.

Auth required. Body names exactly one recipient:

    { "name": "r1" }

`name` is **required**. Omitting it, sending a blank value, or sending a name outside `r[0-9]{1,12}` is `400` — there is deliberately no "rotate all" spelling, because the operation whose blast radius is every recipient must never be reachable by forgetting a field. An unknown recipient is `404`.

Response is the `/users/provision` credential shape (same field names, including `reality_public_key`, `tls_cert_sha256`, `tls_cert_pem`, `cover_sni`, `mux_inbound`) plus `updated_inbounds`, `warnings`, `box_keys_rotated`, `rotated_at_unix`, `generated_at_unix`. One call yields everything needed to mint the replacement pack. `reality_private_key` is **not** returned: this route no longer rotates the keypair, and a field named after an operation that did not happen is worse than no field. This box always answers `box_keys_rotated: false`; a publisher receiving `true` (only possible from some other implementation) must treat the call as a **success with a fleet-wide escalation** — the box has moved, so the credentials still have to be persisted — never as a failure, which would discard them and leave the roster pinning credentials the relay no longer accepts.

Side effects on the box — **scope: one recipient**:

1. Re-mint that recipient's VLESS UUID (one consistent value across every vless-family inbound), REALITY `short_id` (index-paired with its `users[]` row; when `short_id[]` and `users[]` have drifted out of correspondence the fresh entry is **appended** rather than overwriting one that cannot be attributed, and a warning says so — handing back an existing entry would tie this recipient's REALITY tier to somebody else's revocation), Hysteria2 password, and Naive password. Rows are located by inbound **type** and then by `users[].name` — except `naive`, which keys on `users[].username`.
2. Leave every other recipient, the shared ws `transport.path`, `tls.server_name`, `reality.handshake`, and `reality.private_key` byte-identical.
3. Verify every retired secret is absent from the whole document, then commit via temp file → `sing-box check` → rename. A candidate the parser rejects is `500` with the live config untouched.
4. **One** `reload` (the on-box apply wrapper: `systemctl reload sing-box.service || systemctl restart sing-box.service`; `reload` is SIGHUP, which sing-box 1.13 handles in-process by re-checking the config and then closing every inbound and every live connection before starting the new instance). There is no separate "kick": sing-box has no SIGUSR2 handler, and the earlier kick-then-reload pair restarted the relay twice per call (finding INT-O1; `specs/per-recipient-credentials-v1.md` §3.2 step 3). Eviction is required for the revocation to be real: rewriting the file alone stops only *new* authentications, while the seized credential's established session would keep carrying traffic. Every recipient is briefly disconnected; all but the rotated one reconnect automatically on credentials that did not change.
5. **A failed `reload` rolls the config back.** The rename happens before the reload, so between them the box holds a config it is not running. If activation fails the pre-rotation bytes are restored and a reload is attempted again, then `500` is returned — so a failure genuinely means "nothing was applied" rather than "applied on disk, waiting for whatever reloads sing-box next". Without this the new credentials, which leave the box only in this response, would exist solely in an orphaned file and cut the recipient off at some later, unrelated reload.

#### 4.1.1. Pre-Step-7 behaviour (recognition only)

A box whose `/health` omits the §4.3 advertisement implements the old shape: it ignores `name`, rotates all recipients, rotates the REALITY keypair, and returns `reality_private_key`. Publishers **must not** call it optimistically — see §4.3.

### 4.2. `POST /rotate-tls` — L2, ~20 s

Auth required. Body is JSON, and every field is optional:

    {
      "new_sni": "<fqdn>",
      "new_dests": ["<fqdn>:443", ...],
      "new_ws_path": "<optional, only for ws-shaped profiles>"
    }

Response:

    {
      "applied_at_unix": <int>,
      "applied_sni": "<fqdn>",
      "applied_handshake": "<fqdn:port>",
      "applied_ws_path": "<path>",
      "changed": ["cover_sni", "reality_handshake", "ws_path", "tls_certificate"],
      "tls_cert_pem": "<PEM, only when tls_certificate is in changed>",
      "warnings": ["..."]
    }

`changed` is the subset that actually moved, and it is what keeps the caller honest: a `{}` request must not be reported to the operator as "cover host rotated". A request that would change nothing is `400`, not a green tick over a no-op.

`new_dests[0]`'s host **must** equal `new_sni` (the port may differ) or the request is `400`. A dest naming a different host than the advertised SNI is precisely the mismatch REALITY exists to prevent.

With an empty body `{}` the box rotates only what it legitimately owns: a freshly minted shared ws path (shape-preserving, `/r<id>/<8 hex>`) plus repair of any `server_name` / `handshake.server` drift. **The box does not invent a cover host** — plausibility depends on provider and region, which is publisher knowledge, and a constant compiled into this binary is one string match from burning the fleet.

Side effects on the box — **scope: the whole relay, parameters only**:

1. Move `tls.server_name` and `reality.handshake.{server,server_port}` **together** across the vless family, and/or the shared ws `transport.path`. Moving `server_name` without `handshake.server` is the L2 bug fixed in Wave 2.
2. Touch **no** user row and **no** REALITY keypair.
3. Commit via temp file → `sing-box check` → rename, as in §4.1.
4. `reload`, with the same rollback-on-failure discipline as §4.1 step 5. It matters more here: the publisher treats a rotate-tls failure as "nothing was applied" and keeps the old cover host in its record, so an orphaned config would put the relay on a name no pack carries, at whatever unrelated moment something else reloads sing-box.
5. **Re-issue the data-plane certificate when `cover_sni` moved** (`cmd/daal-relay-mgmt/tlscert.go`), before the reload, so one reload applies both and a failed reload restores both:
   * **the same key** — `/etc/daal/tls-key.pem` and `/etc/daal/tls-spki-sha256.b64` are not touched, so no pin moves: every signed endpoint and every pinned family's pack is unaffected;
   * `dNSName` SANs: **the new cover host first**, then every name the previous certificate carried (at most 8 in all; the oldest are dropped). The first name is the one a naive pack minted from now on verifies and presents when the address it dials is not in the certificate (`bundle.NaiveVerificationName`, i.e. after an L3); the kept names are what naive packs minted **before** the rotation verify, and dropping one kills them;
   * `iPAddress` SANs: **exactly the previous certificate's, never an address read off the interface.** This certificate is served, with no credentials, to anyone who opens a TLS connection to a pinned-family port, and after an address swap the old address keeps answering: naming an address bound since first boot (`/bind-address`) would tell whoever probes the burned address where the relay moved to. The cost: a naive pack minted for a later-bound address verifies and presents the cover host rather than no name, exactly as after any address move not followed by a cover-host move. No name on the wire for a moved address needs a certificate per listener, which is not specified;
   * same subject, self-signed, valid 90 days from now (Chromium's ceiling for a locally trusted root — see `v2.yaml.tmpl`), so a rotation also renews.
   A client that installed the **previous** certificate as its trusted root accepts the new one (same subject, same key). `changed` gains `tls_certificate` and the reply carries `tls_cert_pem`; `/users/provision` and `/rotate-credentials` return the new certificate from then on, which is where a re-mint gets it. **A certificate that cannot be re-issued does not fail the rotation**: the cover host still moves, `tls_certificate` is absent from `changed`, and `warnings` says the naive route keeps the names it had. A request that moves only the ws path, or names the host the certificate already leads with, issues nothing.
   What this does **not** do: a phone that holds a naive file from before the rotation and is handed nothing keeps verifying — and presenting — the old name after a later address move, because the name it uses is derived from the certificate *it holds*. Moving that phone without a file needs the name in the signed endpoint (`specs/relaypack-v1.md`), which is not specified.
6. Write `/etc/daal/cover-sni` **only** when `cover_sni` is in `changed`, from the effective value read back out of the committed config, and only after the reload the box confirmed.

The L2 path rotates the data-plane TLS/SNI profile used by sing-box and re-issues the data-plane certificate on its existing key. It deliberately does **not** rotate that key, nor the management-plane self-signed certificate or `rec.MgmtTLSFingerprint`; a management-cert compromise is handled as a redeploy until a future explicit management-cert rotation endpoint is specified.

**What it costs recipients, and what the publisher must say.** The cover host is on the wire for **vless-reality only**: every other family's TLS name is the relay address, and L2 touches no credential. So a pack already distributed keeps connecting on every route except that one (measured, seven families: `test-rigs/worldbox/FINDINGS.md` LC-O1). The publisher does not tell an operator that every recipient needs a new pack. It re-reads the relay's identity (§4.9), signs the pack again and republishes the freshness document; a recipient whose pack carries freshness mirrors then takes the new cover host with no new file (`specs/relaypack-v1.md`, the rotation table). A new file is needed only by a recipient whose pack has no mirrors — for the vless-reality route alone, unless the relay serves nothing else. `daal-deploy rotate-tls` reports this as `next_step`; its `warnings` are empty after a clean rotation.

### 4.2.1. Box REALITY keypair rotation — not specified, not implemented

Rotating the box's REALITY keypair invalidates every recipient's pinned public key, so every pack ever distributed stops working until each recipient receives a new one — which is exactly what does not work under blackout. It is therefore a **third** operation and must never be a side effect or a flag on §4.1 or §4.2. It would be a **new route** (the twelfth — Wave 3c took the eighth and ninth, §4.8, `GET /identity` the tenth, §4.9, and `POST /cdn` the eleventh, §4.10) and requires a supplement amendment to §4, plus Step 8's redistribution path underneath it. `publisher/deploy/mgmt` has a tripwire test (`TestNoBoxKeyRotationSurfaceExists`) asserting no such surface exists.

### 4.3. `GET /health` — liveness probe **and capability advertisement**

No auth. Status 200. Used by the Helper for end-to-end TLS-pinned probing of a freshly-deployed box during V2 provisioning, and — since Wave 3 Step 7 — as the box's capability advertisement.

    {
      "ok": true,
      "mgmt_api_version": 2,
      "capabilities": ["rotate-credentials-scoped", "rotate-tls-scoped", "bind-address"],
      "capability_notes": ["address binding available: applied in-process (CAP_NET_ADMIN held)"]
    }

`ok` is unchanged and remains the liveness signal; every other field is additive, so an old publisher reading a new box is unaffected.

`bind-address` (§4.8) appears **only when the box has probed that it can actually configure an address**, and `capability_notes` carries the box's own account of why when it cannot. That field must be declared on the publisher's `mgmt.BoxCapabilities` or it dies in transit — `encoding/json` drops unknown keys silently, which is how `cover_sni` and `mux_inbound` were once lost between two ends that both had them right.

**Why the advertisement lives on this route.** `daal-relay-mgmt` ships as a hash-pinned artifact (`publisher/deploy/cloudinit/artifacts.go`), so a relay keeps running the binary it was born with until a human rebuilds, re-signs, re-uploads and bumps the pin. The fleet therefore contains pre- and post-Step-7 boxes simultaneously, and the publisher must tell them apart *before* sending anything mutating. It cannot do so by probing: `/rotate-credentials` and `/rotate-tls` have been registered since FRP-10, so an old box answers 200 rather than 404, and probing by behaviour is destructive — the pre-Step-7 handler ignores the body and rotates the box-wide REALITY keypair, invalidating every pack already distributed. Advertising here costs no new route of its own.

The tokens name the **semantics**, not the route: the `-scoped` suffix distinguishes the split, targeted Step-7 behaviour from the old conflated one, because the bare route name is true of every box ever shipped. A box that omits these fields is read as pre-Step-7 and refused, so detection **fails closed**. For the two rotation verbs either signal alone is sufficient — an explicit token, or `mgmt_api_version >= 2`. **`bind-address` is the exception and has no version fallback at all**; see §4.8.

This is a cross-module wire contract with `publisher/deploy/mgmt` (`CapRotateCredentialsScoped`, `CapRotateTLSScoped`, `MgmtAPIVersionSplitRotation`). The two modules share no symbol, and drift is silent at compile time in both, so the exact literals are pinned by `TestHealthAdvertisesSplitRotation` (box) and `TestCapabilities_AcceptsRealBoxHealthBody` (publisher).

### 4.4. `POST /users/provision`, `POST /users/revoke`, `GET /users/list` (FRP-14)

Auth required. The wire format, sing-box rewriter, and force-kick mechanism for per-recipient credentials are specified in full in `specs/per-recipient-credentials-v1.md` §3. The summary is:

* `POST /users/provision` — append a fresh per-recipient user to the inbounds of the families **this relay was provisioned to serve** (`/etc/daal/families`; `specs/per-recipient-credentials-v1.md` §2.3), creating the on-first-use inbounds of those families only; reload; return the credentials JSON, with a credential present only for a row that exists in the live config. A family the relay does not serve gets no inbound, no row and no credential.
* `POST /users/revoke` — remove a user from all inbounds and apply with exactly one reload of sing-box, which closes live sessions. Bound: ≤ 10 s for live sessions.
* `GET  /users/list` — return the current user names (no credentials).

Both state-changing routes require op-bound tokens (`users-provision`, `users-revoke`); the read route requires `users-list`.

### 4.7. `GET|POST /whoami` — L0, instant

Echoes the source IP the box actually observes for the connection.

* **Auth:** the standard `requireAuth` wrapper; op-bound as `whoami` in `opFromPath`. The publisher mints the op (`mgmt.MintToken`, `opRoutes`) and calls it through `mgmt.Client.WhoAmI`, as a `GET`. (Until token format v2 the box served this route and the publisher's minter refused the op, so nothing could authenticate to it — `test-rigs/worldbox/FINDINGS.md` LC-O2.)
* **Methods:** `GET` and `POST`; anything else → `405`. The method is under the token's signature (§3): a token minted for `GET` is `401` on a `POST`. The publisher sends `GET`.
* **Response:** `200 application/json` — `{"source_ip":"<ip>","server_time_unix":<int64>,"api_version":1}`.
* **Derivation:** `net.SplitHostPort(r.RemoteAddr)`; if the split fails, the raw `RemoteAddr`. `X-Forwarded-For` / `X-Real-IP` are **deliberately ignored** — the mgmt plane is dialled directly, and honouring a client header would let a caller spoof the very value it is asking the box to verify.
* **Why it exists:** the publisher's helper IP comes from third-party echo services and can be wrong behind CGNAT, split-horizon NAT or a captive proxy. This is the only authoritative answer. It cannot *bootstrap* the allowlist — it is itself behind the firewall — so it only confirms an IP that already works, letting the client stop re-detecting and store a verified value.
* **Feature detection is mandatory on the client.** Boxes deployed before this route exists answer `404`. A `404`, `405`, connection error or malformed body (`mgmt.ErrWhoAmIUnsupported`; a `source_ip` that does not parse as an address is malformed) must be treated as "older box" and must never fail, block or degrade any publisher action; the stored `helper_ip` stays authoritative.

### 4.8. `POST /bind-address`, `POST /unbind-address` — L3's guest-OS half (Wave 3c)

**Why these exist.** Measured on a real Hetzner relay on 2026-08-17: an L3 swap reserved the address, attached it to the server, stamped both ownership labels and rewrote `rec.PublicIP`, and the provider API reported success in under a second — and the box never answered on the new address. A floating IP is **routed** to the server at the provider's network layer, but the guest OS does not reply on it until the address is configured on an interface. Nothing configured it: cloud-init cannot (the address does not exist at render time and changes on every swap) and the assign path was pure API. `health.AddressServes` made that fail closed; these two routes make it succeed.

**No sing-box change is involved and none is permitted here.** Every inbound already listens on `0.0.0.0`, so the moment the kernel holds the address sing-box accepts on it. Holding the address is the entire change; neither handler touches the config or its lock.

* **Auth:** the standard `requireAuth` wrapper; op-bound as `bind-address` / `unbind-address` in `opFromPath`. The op string and the path are the same word by construction on both ends.
* **Request:** `{"ip":"<addr>"}`. The publisher's API takes a parsed `net.IP` and re-renders it, so the body always carries a canonical literal; the box parses and re-renders again before use and never interpolates a caller byte into a command line.
* **`POST /bind-address` → 200:** `{"ip","interface","already_bound","persisted","persist_path","bound_addresses","applied_at_unix","warnings"}`. Idempotent; `already_bound:true` is success.
* **`POST /unbind-address` → 200:** `{"ip","removed","was_bound","persistence_removed","still_configured","bound_addresses","applied_at_unix","warnings"}`. Idempotent; `removed:false` with `was_bound:false` is the no-op. **`still_configured` is the field that keeps that no-op honest.** The box refuses to remove an address it did not bind (the record gate below), so a live-but-foreign address — the box's own primary address being the obvious one — answers with exactly the no-op shape. It was previously distinguishable only by a warning string, which every publisher call site discarded, after which `floating-ip release` handed the address back to the provider pool while the relay was still answering on it. The publisher turns `still_configured:true` with `removed:false` into a hard error.
* **Success is decided by re-reading the interface**, never by an exit status. That is the same mistake the provider API layer made, one layer down.

**Adoption is refused.** `POST /bind-address` returns **409** for an address that is already configured on the interface and is not already in the record set. The record set is what makes an address removable, and the safety of the whole unbind path rests on the claim that the box's primary address is never in it. Adopting a live address is the one way that claim could be broken: two signed calls — bind(primary) then unbind(primary) — would run `ip addr del <primary>` on a relay with no SSH. Nothing legitimate is lost: an L3 binds an address the guest OS does **not** yet hold (that is the entire hardware finding), and a re-bind of an address the box itself bound short-circuits on the existing record.

**Address class.** Only a plausible **public unicast** address may be bound. Unspecified, loopback, link-local (which contains `169.254.169.254`, the cloud metadata service), multicast, broadcast, RFC1918/ULA, CGNAT, reserved, benchmark, 6to4/Teredo/NAT64 and IPv4-mapped spellings of any of the above are refused, by both ends, and by the publisher **before** any firewall window is opened. The documentation ranges are deliberately allowed: they shadow no route and reach no metadata service, and they are what every fixture in this tree uses.

**Quantity.** At most `4` addresses may be held at once (`maxBoundAddresses` on the box, `mgmt.MaxBoundAddresses` on the publisher — the two must stay equal). The box is the enforcement point, against the persisted set so a restart cannot reset it; the publisher refuses a box that reports more, so a box that forgets to enforce fails loudly.

**Persistence** is a record set (`/etc/daal/bound-addresses/<addr>.addr`) re-applied at boot by a `Type=oneshot` unit that runs *this same binary* with `-reapply-addresses`, so the boot path and the live path are the same validated code. It is **reported, not enforced**: `persisted:false` is a warning, because refusing would abort the swap and strand the relay on the address the operator is rotating away from.

**Capability.** Advertised as the single token `bind-address` on `/health` (§4.3), covering both routes. It is **conditional on a runtime probe**, not on `mgmt_api_version`, and this is the one capability in the protocol for which a version fallback is forbidden: binding needs `CAP_NET_ADMIN`, which the *service unit* decides, so a box can be running the right binary and still be unable to bind. `mgmt_api_version` stays at **2**; `publisher/deploy/mgmt` consults the token alone (`MgmtAPIVersionAddressBinding` exists as documentation of the route contract and is not read as permission).

**The probe requires `CAP_NET_ADMIN` in the mgmt process itself**, plus `ip` and `systemctl`. One token covers two verbs, so it may only be advertised when both work. The boot-unit delegation (`daal-bound-addresses.service`, which PID 1 launches with the capability) can only **add**: it reconciles the record set, and it must not remove anything the records do not mention, because at boot the interface holds the primary address, which is not a record. A box advertising the token off the delegation alone therefore promised two verbs and could perform one — and the one it could not perform is the one on every failure path (the rollback of a swap whose reachability probe failed, and the whole of `floating-ip release`), each of which then hands an address back to the provider's pool while the box still holds it. The V2 cloud-init accordingly grants `AmbientCapabilities=CAP_NET_ADMIN` to `daal-relay-mgmt.service`, matching `sing-box.service` on the same box; that is not a widening, since the service runs as root, writes `/etc/systemd/system` and starts a unit it authored with that capability. **A relay provisioned before this change advertises nothing and the publisher refuses L3 on it, before anything is reserved** — correct, because such a box could bind and never unbind.

**Replay.** Both verbs are single-use per token, and — like every authenticated request — the token signs the body (§3), so a token minted to bind one address cannot bind another, before or after it was used, across a restart or not. (Before token format v2 the body was unsigned and a captured token could be re-aimed at another `ip` up to the 4-address cap, each persisted across reboot; the in-memory single-use set was the only defence and a restart of the service re-opened it.)

**Ordering, on the publisher side.** Assign: capability probe → reserve → provider attach → **bind** → `health.AddressServes` → commit the record. The bind is delivered over the **pre-swap** address, never over `rec.PublicIP` — the adapter has already moved the record onto the new address and the box does not answer there yet, which is the whole point of the call. Release: detach at the provider (so the record falls back to a working address) → **unbind** → release. A failed unbind stops the release rather than handing a live box's address back to the provider pool — and so does an unbind that could not be *attempted*: the provider speaks ids and the box speaks addresses, so `floating-ip release` refuses (exit 2) when it cannot resolve the id to an address. A rotation always hits that case, because it releases the **prior** id after the record has already been replaced with the swap's output, so it passes the address explicitly (`--fip-address`). `--skip-unbind` remains the only way past, and only for a relay that no longer exists.

### 4.9. `GET /identity` — the relay states who it is (truth wave)

**Why it exists.** A RelayPack commits every route to a signed endpoint (`specs/relaypack-v1.md` "Endpoint commitment"): where the route points and what proves the far end is this relay. The publisher signs that pack **before any recipient exists**, so it needs the relay's half of the commitment without provisioning anybody. Until this route the only sources were a provider-specific SSH read at provision time — which the Hetzner adapter did and the Vultr adapter did not — and the box-wide fields of a `/users/provision` reply, which needs a recipient. On Vultr the publisher app could not sign at all, and nowhere could it commit shadowsocks, whose key is in no record (`test-rigs/worldbox/FINDINGS.md` F-005).

* **Auth:** the standard `requireAuth` wrapper; op `identity`, `GET` only (anything else → `405`). **Read-only**: it changes nothing, reloads nothing, and is not single-use (§3 "Replay").
* **The reply is authenticated the way every reply is** — it arrives on the TLS session pinned to `rec.MgmtTLSFingerprint` (§2). That matters more here than on any other route: the reply is what the publisher puts under its signature.
* **Nothing in it is a secret.** Every value is either visible to anyone who connects or carried in every pack. The one exception to "visible" is the shadowsocks server key, and it is **not sent**: its digest is, which is exactly what a signed endpoint carries.
* **Response** `200 application/json`:

      {
        "identity_version": 1,
        "reality_public_key": "<base64 x25519>",
        "tls_cert_sha256": "<base64 SHA-256 of the data-plane leaf's SubjectPublicKeyInfo>",
        "cover_sni": "<fqdn>",
        "ss_method": "2022-blake3-aes-128-gcm",
        "ss_server_key_sha256": "<hex>",
        "families": [ {"family": "vless-reality", "port": 443, "listening": true}, ... ],
        "pending_families": ["shadowsocks"],
        "generated_at_unix": <int>
      }

  Field names and encodings are the ones `/users/provision` uses for the same values (`tls_cert_sha256` is the SPKI pin; the name is historical). A field is present only for a family the relay serves: a shadowsocks-only relay states no REALITY key and no TLS pin.
* **Everything is read from disk at request time**, never remembered: `cover_sni` from the live sing-box config, so it names the new host immediately after `/rotate-tls`.
* **`ss_server_key_sha256`** is `hex(sha256("daal/ss-server-key/v1\x00" + <box-wide iPSK, as it appears in the config>))` — `bundle.SSServerKeyDigest`. The box, the publisher and the recipient's client share no symbol; one test vector pins all of them (`TestIdentitySSDigestMatchesTheSignedEndpointRule` on the box, `TestSSServerKeyDigestVector` in `publisher/deploy/cli`, `ss_digest_matches_the_signed_endpoint_rule` in the wizard). `ss_method` and the digest are sent together or not at all, and the publisher refuses a document with one and not the other.
* **`families`** lists every family the relay serves, sorted by name, with its port. `listening:false` marks a family the relay was provisioned to serve whose inbound does not exist yet (four inbounds are created with the first recipient); its port is the one this binary will create it on. A relay built before `/etc/daal/families` (§4.4) lists only what is live.
* **`pending_families`** names the served families whose *identity material* does not exist yet. Today that is only shadowsocks, whose box-wide key is minted together with the first recipient. Always present, possibly empty. **A pack signed while a family is pending cannot commit that route; the publisher must sign again once the list is empty** — see "Publisher" below.
* **Fails closed.** A relay that cannot read its own config, or was told its family set and cannot read it, answers `500`. A partial identity would be signed.
* **Feature detection.** A box that predates the route answers `404` (`405` is read the same way): `mgmt.ErrIdentityUnsupported`, exit `3` from `daal-deploy relay-identity`. That is an answer, not a failure, and the publisher falls back (below). A `401`, a `500`, a timeout or a reply the publisher cannot read exactly (unknown `identity_version`, a method without its digest) is a **failure** and is never turned into a fallback: signing from an older source because the relay could not be reached would produce a pack that is one route short, or names a cover host the relay has left, with nothing saying so.

**Publisher.** `daal-deploy relay-identity` fetches the document (same flags as the `users-*` verbs; `--output` saves it, mode 0600). `daal-deploy bind-and-sign --relay-identity <file>` signs from it:

* Where the relay speaks it **outranks the OperatorRecord** — keys and cover host (`relaypack.EndpointMaterial.PreferRelay`). The record is a note of what was requested or read once; the relay answering just before the signature is the authority, and every disagreement is printed (`identity_warnings` in the summary). This is the opposite precedence to `--endpoint-creds`, whose argument is a reply saved earlier and only fills what the record lacks. **One exception, on the cover host only:** an identity whose `generated_at_unix` is more than 15 minutes from the signing time and which names a different cover host than the record is the stale one — `/rotate-tls` moves the cover host and rewrites the record — so the record's host is signed and the publisher is told to run `relay-identity` again. (Its keys cannot go stale that way: a relay with other keys is another relay, with another record.)
* The **address and the ports stay the record's**: the relay does not know which address recipients dial (a floating IP is routed to it by the provider), and a CDN-fronted route is dialled on the front's port. A port the relay does not serve a direct family on is reported, not corrected.
* The summary carries `committed_identity` — what the signed endpoints commit the relay to, read back out of the pack — and `uncommitted_families`.

The publisher app asks before **every** signature (the address swap may reuse an identity already learned from the same relay, identified by `MgmtTLSFingerprint`: it moves the address, not the relay's keys, and has a 15-second budget). It stores `committed_identity`, compares the relay-wide fields of every later reply against it, and **signs again and republishes freshness when they differ** — after the first recipient on a relay with a pending family, after `/rotate-tls`, after a rebuild. For a relay that predates the route it builds the same document from the relay-wide fields of a `/users/provision` reply; if the record carries no key at all and no reply exists yet, it provisions the shared `r0` to obtain one (the reply's recipient secrets are discarded).

### 4.10. `POST /cdn` — the Cloudflare door (optional add-on 2)

**Why it exists.** The way in through Cloudflare (`specs/optional-addons-v1.md` §4) needs a door on the relay that only Cloudflare can open: a dedicated inbound, `ws-cdn-in` (VLESS over WebSocket on port 8448, `relayports.CDNOrigin`), serving the zone's Cloudflare Origin CA certificate and **requiring** Cloudflare's Authenticated Origin Pull client certificate. Its material is a private key, so it can only arrive through this session, never through cloud-init user-data.

* **Auth:** the standard `requireAuth` wrapper; op `cdn`, `POST` only. **Mutating and single-use** (§3 "Replay"), `status` included: the route has one method.
* **Request** (`cdnReq` on the box, `cloudflare.DoorRequest` on the publisher; JSON names pinned on both ends by `TestCDNRequestFieldNames` and `TestBuildDoorEnable`; unknown members are refused):

      {"action": "enable", "port": 8448, "ws_path": "/<32 hex>",
       "origin_cert_pem": "…", "origin_key_pem": "…", "aop_ca_pem": "…",
       "edge_ranges": ["173.245.48.0/20", "2400:cb00::/32", …]}
      {"action": "disable"}
      {"action": "status"}

* **enable** checks everything before writing anything: the port is 8448 (the only port both firewalls open to Cloudflare), the path is a usable WebSocket path, the certificate and key are a pair valid now, `aop_ca_pem` holds only CA certificates, and every `edge_ranges` entry is a CIDR that is not everyone (at most 64; each re-printed from its parse). It refuses (`409`) while the relay has no recipient: sing-box refuses an inbound with no users. Then, in this order: the box firewall (ufw) is opened on 8448 to each range it does not hold yet (`ufw allow from <cidr> to any port 8448 proto tcp`, argv, no shell); the three files go to `/etc/daal/cdn`; `ws-cdn-in` is written with the recipients of `vless-in` and `ws-in` (uuid and name); sing-box reloads. Any failure undoes all of it, rules included. After the reload, rules for ranges no longer sent are removed, and the set the box opened is recorded in `/etc/daal/cdn/edge_ranges.json`. An `edge_ranges` that is absent or empty leaves the box firewall as it is (a relay whose first boot already opened it, `provision --cdn-edge-ranges`).
* **disable** removes the inbound, then the files, then every box-firewall rule enable opened. Idempotent. A rule ufw would not remove stays recorded and is tried again by the next disable; nothing listens behind it.
* **status** reports the door without changing it.
* **Response** `200 application/json`, never key material: `{"action", "enabled", "changed", "port", "ws_path", "users", "origin_cert_sha256", "origin_cert_not_after_unix", "box_firewall_rules"}`. `box_firewall_rules` is how many Cloudflare ranges the box firewall opens the door's port to by rules this service wrote. The publisher refuses an enable that answered for another port or path, or that opened no rule although ranges were sent.
* **Recipients follow the door.** `/users/provision` adds a new recipient to an open door and `/users/revoke` takes one off it. The last one leaving **parks** the door: the inbound goes (sing-box refuses one with no users), its files and its path (`/etc/daal/cdn/ws_path`) stay, and the next recipient provisioned opens it again on the same path, so the signed packs that name the route keep working. Only `disable` closes it for good. `/rotate-credentials` re-keys it like every VLESS inbound.
* **Feature detection.** The box advertises `cdn` in `/health` `capabilities` (§4.3), and the publisher sends the key only to a box that does (`mgmt.CDNDoorEnable`, `mgmt.ErrCDNDoorUnsupported`, exit `3` from `daal-deploy cdn-door`). No version fallback: the verb rides the pinned artifact (relay-v1.6.0 and later).
* **Publisher.** `daal-deploy cdn-door --action enable|disable` (inside the usual ephemeral firewall window, `mgmt.CDNDoorEnableWithFW` / `CDNDoorDisableWithFW`); `cdn-remove` closes the door first when it is given the relay's record and key.

## 5. Cloud-firewall as gate

The Helper opens a 300-second `(callerIP, mgmtPort)` allowlist via `Provider.SetEphemeralFirewallRule(serverID, callerIP, port, 300)` immediately before each L1/L2 call, then drives the call, then removes the rule via `RemoveEphemeralFirewallRule(rule)` in a `defer` so cleanup runs even on error. The provider auto-expires the rule at 300 s as belt-and-braces.

Box-side `ufw` does **not** open the mgmt port. FRP-10 invariant 18 is structurally enforced by the V2 cloud-init template (`publisher/deploy/cloudinit/v2.yaml.tmpl`) which contains no `ufw allow` for the mgmt port; `TestRenderV2_NoBoxTokenInTemplate` asserts the absence of any cloud-provider-token marker in the rendered YAML.

## 6. Failure modes

| Condition | Server response | Helper action |
|---|---|---|
| Missing `Authorization` header | 401 | Operator-visible error; suggest redeploy |
| Token timestamp outside `[-300 s, +60 s]` | 401 | Surface "clock skew or replay" warning |
| Token `op` does not match URL path | 401 | Hard fail (token replay attempt) |
| Signature verification fails | 401 | Hard fail (wrong key, tampered token, or a method/path/body other than the one the token was minted for) |
| Token is not format `v2` | 401 | Hard fail: the publisher build and the relay's daemon are from different sides of the v2 change; rebuild the relay |
| Body larger than 64 KiB on an authenticated route | 413 | Client bug; no legitimate body approaches it |
| Mutating token presented a second time | 401 | Mint a fresh token (the client does, per call) |
| TLS fingerprint mismatch (Helper-side) | n/a (TLS handshake fails) | `ErrFingerprintMismatch` → operator must redeploy |
| Body validation fails on `/rotate-tls` | 400 | Operator-visible error |
| `systemctl reload-or-restart` fails | 500, config rolled back to its pre-operation contents (§4.1 step 5) | Operator-visible error; the operation may be retried — the box is not left with an un-activated rewrite. The error text says so, and names the divergence if the restore's own reload also failed |
| Two mutating calls overlap | serialized on the box | All four mutating routes (`/rotate-credentials`, `/rotate-tls`, `/users/provision`, `/users/revoke`) hold one mutex across load → mutate → commit → reload. Ephemeral firewall windows are additive and last 300 s, so overlap is ordinary; unserialized, the second rename would silently discard the first operation — and a discarded rotation is a revocation the publisher has already reported as complete |
| `MgmtPort == 0` in `OperatorRecord` (V1.5 record) | n/a (Helper short-circuits) | Fall back to FRP-7 redeploy path |

## 7. What this spec does NOT cover

* **Rotation orchestration above the in-box service.** The wizard's mode-aware rotation copy, audit log, and history table (`signed_sbps.rotation_kind`) live in `client-shell/tauri/daal-wizard` and are documented under `specs/relaypack-v1.md` §rotation.
* **Provider-firewall rule shapes.** Each `Provider` adapter implements `SetEphemeralFirewallRule` against its native API; the contract is `publisher/deploy/provider/provider.go::Provider`.
* **The Android wizard.** Per FRP-10 invariant 30 the Android wizard is provision-only and never calls this service. See `specs/android-client-v1.md` for the Android boundary.

## 8. Test surface (FRP-10 + future)

| File | Purpose |
|---|---|
| `cmd/daal-relay-mgmt/identity_test.go` | `GET /identity` (§4.9): everything a signer needs before any recipient, and that asking changes nothing; agreement with the `/users/provision` reply; the shadowsocks digest vector and that the key itself is never in the reply; only what the relay serves; follows `/rotate-tls`; needs an `identity` token; fails closed on an unreadable family set |
| `publisher/deploy/mgmt/identity_test.go`, `publisher/deploy/cli/cli_identity_test.go` | the client decodes every field a signer reads; an older relay is `ErrIdentityUnsupported` / exit 3 and a refusal or a 500 is not; `bind-and-sign --relay-identity` signs a record with no key material, commits shadowsocks once the relay has a key, and outranks a stale record; `rotate-tls` no longer claims every recipient needs a new file |
| `cmd/daal-relay-mgmt/main_test.go` | 11 baseline + ~10 FRP-14 tests + the `/whoami` set, pinning the wire format, the route invariant, the Ed25519 token (op-binding + timestamp window; request-binding: `TestTokenIsBoundToTheRequest`, `TestV1TokenIsRefused`, `TestAuthedBodyIsBounded`, `TestTokenV2Vector_BoxAcceptsWhatThePublisherSigns`; single use: `TestMutatingTokensAreSingleUse`), the self-signed cert fingerprint stability across restarts, the surgical sing-box JSON rewriters (rotate + per-user paths), and the per-recipient isolation invariants |
| `publisher/deploy/mgmt/token_test.go`, `whoami_test.go` | the v2 token: a token verifies for one method, path and body only; the v1 shape is neither minted nor parsed; the op → route table; the shared fixture; `/whoami` authenticates and an older box is "no answer", not a failure |
| `publisher/deploy/mgmt/client_test.go` | 12 tests pinning the Helper-side TLS-pin (wrong fingerprint = error), the token mint/parse round-trip, the ephemeral firewall open/close ordering, and the V1.5-fallback-on-zero-port path |
| `publisher/deploy/cloudinit/template_test.go` | 6 tests pinning the V2 cloud-init template's mgmt-unit installation, port-input determinism, and the no-cloud-provider-token-in-template invariant |

## 9. Carry-overs

* **Live alpha pilot.** The full FRP-10 mgmt-plane requires a real cloud-provider account at each of Hetzner / Vultr / Stark with billing enabled to verify the firewall-API timing in production. The pilot gate is documented in `specs/v2-closure-v1.md` (HOLD — see that spec for the exit criteria).
* **govultr/v3 + Stark live wiring.** The Vultr and Stark adapters compile + test against an injected client interface; the live SDK / REST wiring is part of the alpha-pilot work above.
