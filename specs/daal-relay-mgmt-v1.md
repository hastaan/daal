# `daal-relay-mgmt` — V2 in-box management plane (v1)

**Status:** locked at FRP-10 (May 2026); **extended at FRP-14** (lifts the 3-route invariant to 6 routes; see `specs/per-recipient-credentials-v1.md`); **extended again at the publisher redesign** (7th route `/whoami`, §4.7). · **Supplement reference:** §9.5.2, §9.5.5. · **Engine line:** `daal-core 0.9.0+v3-share` (no engine ABI surface — this is an in-box userspace daemon).

This spec defines the contract between the FRP Helper and the persistent in-box `daal-relay-mgmt` service that ships with FRP-10's V2 deploys. It locks the wire format, the auth scheme, the TLS posture, the port discipline, and the seven-route API surface (six at FRP-14, plus `/whoami`). The Helper-side mirror (`publisher/deploy/mgmt/`) and the box-side service (`cmd/daal-relay-mgmt/`) are both pinned by tests against this contract.

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
* **Fingerprint publication:** the SHA-256 of the cert DER is written hex-encoded to `/var/log/daal/mgmt-tls.fpr` and read by the FRP-9 bootstrap-window relay (`daal-relay-health`) which emits it to the Helper alongside the standard health JSON during the 60-second provisioning window. The Helper persists it into `OperatorRecord.MgmtTLSFingerprint` (FRP-10 invariant 26).
* **TLS minimum:** TLS 1.3.

The cert is intentionally **not** issued by a public CA. The trust model is fingerprint-pinned-per-deploy; system trust stores are never consulted. The Helper-side mgmt client (`publisher/deploy/mgmt/client.go`) sets `InsecureSkipVerify: true` and supplies a `VerifyPeerCertificate` callback that compares `sha256(rawCerts[0])` against `rec.MgmtTLSFingerprint`; mismatch returns `ErrFingerprintMismatch` (no fallback).

## 3. Auth — Ed25519 op-bound tokens

Every state-changing endpoint requires an `Authorization` header of the form:

    Authorization: Daal-Mgmt-Token <nonce>:<ts>:<op>:<base64-sig>

where:

* `nonce` is 16 random bytes hex-encoded (32 hex chars). The on-box service does NOT track seen nonces — replay protection comes from the timestamp window plus op-binding.
* `ts` is the Helper's clock as seconds-since-Unix-epoch.
* `op` is one of `rotate-credentials`, `rotate-tls`, `users-provision`, `users-revoke`, `users-list` (these three added at FRP-14), or `whoami` (§6) — **six** ops in total, matching `opFromPath` at `cmd/daal-relay-mgmt/main.go:258-272`. The on-box service rejects any token whose `op` does not match the URL path.
* `<base64-sig>` is the standard-encoding base64 of `Ed25519.Sign(privKey, "<nonce>:<ts>:<op>")`, i.e., the signature covers the first three colon-separated fields verbatim.

The `privKey` is the Helper's per-deploy publisher Ed25519 private key. Its public half is written to `/etc/daal/mgmt/pubkey` by cloud-init at first boot (hex-encoded, 64 chars) so the on-box service can verify tokens without ever holding the private half.

**Timestamp window:** the on-box service accepts `ts` in `[serverNow - 300 s, serverNow + 60 s]`. Older tokens are rejected to bound replay; future tokens are rejected to bound clock-skew abuse.

**Op-binding:** the on-box service refuses to accept a token signed for `rotate-credentials` against `/rotate-tls` and vice versa. This pins token-flow integrity even if the URL path is otherwise unprotected.

## 4. API surface — exactly seven routes

The FRP-10 baseline locked three routes (`/rotate-credentials`, `/rotate-tls`, `/health`). FRP-14 adds three per-recipient routes (`/users/provision`, `/users/revoke`, `/users/list`), specified in `specs/per-recipient-credentials-v1.md`. The publisher redesign adds a seventh, `/whoami` (§4.7). Adding an **eighth** route requires a supplement amendment. The implementation-level invariant is pinned by `TestExactlyNRoutes` (n=7) in `cmd/daal-relay-mgmt/main_test.go`.

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
4. SIGUSR2 kick + `reload`. Eviction is required for the revocation to be real: rewriting the file alone stops only *new* authentications, while the seized credential's established session would keep carrying traffic. Every recipient is briefly disconnected; all but the rotated one reconnect automatically on credentials that did not change.
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
      "changed": ["cover_sni", "reality_handshake", "ws_path"]
    }

`changed` is the subset that actually moved, and it is what keeps the caller honest: a `{}` request must not be reported to the operator as "cover host rotated". A request that would change nothing is `400`, not a green tick over a no-op.

`new_dests[0]`'s host **must** equal `new_sni` (the port may differ) or the request is `400`. A dest naming a different host than the advertised SNI is precisely the mismatch REALITY exists to prevent.

With an empty body `{}` the box rotates only what it legitimately owns: a freshly minted shared ws path (shape-preserving, `/r<id>/<8 hex>`) plus repair of any `server_name` / `handshake.server` drift. **The box does not invent a cover host** — plausibility depends on provider and region, which is publisher knowledge, and a constant compiled into this binary is one string match from burning the fleet.

Side effects on the box — **scope: the whole relay, parameters only**:

1. Move `tls.server_name` and `reality.handshake.{server,server_port}` **together** across the vless family, and/or the shared ws `transport.path`. Moving `server_name` without `handshake.server` is the L2 bug fixed in Wave 2.
2. Touch **no** user row and **no** REALITY keypair.
3. Commit via temp file → `sing-box check` → rename, as in §4.1.
4. `reload`, with the same rollback-on-failure discipline as §4.1 step 5. It matters more here: the publisher treats a rotate-tls failure as "nothing was applied" and keeps the old cover host in its record, so an orphaned config would put the relay on a name no pack carries, at whatever unrelated moment something else reloads sing-box.
5. Write `/etc/daal/cover-sni` **only** when `cover_sni` is in `changed`, from the effective value read back out of the committed config, and only after the reload the box confirmed.

The L2 path rotates the data-plane TLS/SNI profile used by sing-box. It deliberately does **not** rotate the management-plane self-signed certificate or `rec.MgmtTLSFingerprint`; a management-cert compromise is handled as a redeploy until a future explicit management-cert rotation endpoint is specified.

Because this invalidates the connection parameters in every pack already distributed, and no remote redistribution path exists yet (Wave 3 Step 8), it is currently a manual-courier operation and the publisher UI must say so.

### 4.2.1. Box REALITY keypair rotation — not specified, not implemented

Rotating the box's REALITY keypair invalidates every recipient's pinned public key, so every pack ever distributed stops working until each recipient receives a new one — which is exactly what does not work under blackout. It is therefore a **third** operation and must never be a side effect or a flag on §4.1 or §4.2. It would be the **eighth route** and requires a supplement amendment to §4, plus Step 8's redistribution path underneath it. `publisher/deploy/mgmt` has a tripwire test (`TestNoBoxKeyRotationSurfaceExists`) asserting no such surface exists.

### 4.3. `GET /health` — liveness probe **and capability advertisement**

No auth. Status 200. Used by the Helper for end-to-end TLS-pinned probing of a freshly-deployed box during V2 provisioning, and — since Wave 3 Step 7 — as the box's capability advertisement.

    {
      "ok": true,
      "mgmt_api_version": 2,
      "capabilities": ["rotate-credentials-scoped", "rotate-tls-scoped"]
    }

`ok` is unchanged and remains the liveness signal; the other two fields are additive, so an old publisher reading a new box is unaffected.

**Why the advertisement lives on this route.** `daal-relay-mgmt` ships as a hash-pinned artifact (`publisher/deploy/cloudinit/artifacts.go`), so a relay keeps running the binary it was born with until a human rebuilds, re-signs, re-uploads and bumps the pin. The fleet therefore contains pre- and post-Step-7 boxes simultaneously, and the publisher must tell them apart *before* sending anything mutating. It cannot do so by probing: `/rotate-credentials` and `/rotate-tls` have been registered since FRP-10, so an old box answers 200 rather than 404, and probing by behaviour is destructive — the pre-Step-7 handler ignores the body and rotates the box-wide REALITY keypair, invalidating every pack already distributed. Advertising here costs no new route, keeping the §4 surface at seven.

The tokens name the **semantics**, not the route: the `-scoped` suffix distinguishes the split, targeted Step-7 behaviour from the old conflated one, because the bare route name is true of every box ever shipped. A box that omits these fields is read as pre-Step-7 and refused, so detection **fails closed**. Either signal alone is sufficient — an explicit token, or `mgmt_api_version >= 2`.

This is a cross-module wire contract with `publisher/deploy/mgmt` (`CapRotateCredentialsScoped`, `CapRotateTLSScoped`, `MgmtAPIVersionSplitRotation`). The two modules share no symbol, and drift is silent at compile time in both, so the exact literals are pinned by `TestHealthAdvertisesSplitRotation` (box) and `TestCapabilities_AcceptsRealBoxHealthBody` (publisher).

### 4.4. `POST /users/provision`, `POST /users/revoke`, `GET /users/list` (FRP-14)

Auth required. The wire format, sing-box rewriter, and force-kick mechanism for per-recipient credentials are specified in full in `specs/per-recipient-credentials-v1.md` §3. The summary is:

* `POST /users/provision` — append a fresh per-recipient user (UUID, Reality short_id, Hy2/Naive passwords, WS path) to the sing-box config, reload, return the credentials JSON.
* `POST /users/revoke` — remove a user from all inbounds, run the SIGUSR2 + reload kick wrapper, restore drain settings. Bound: ≤ 10 s for live sessions.
* `GET  /users/list` — return the current user names (no credentials).

Both state-changing routes require op-bound tokens (`users-provision`, `users-revoke`); the read route requires `users-list`.

### 4.7. `GET|POST /whoami` — L0, instant

Echoes the source IP the box actually observes for the connection.

* **Auth:** the standard `requireAuth` wrapper; op-bound as `whoami` in `opFromPath`.
* **Methods:** `GET` and `POST`; anything else → `405`.
* **Response:** `200 application/json` — `{"source_ip":"<ip>","server_time_unix":<int64>,"api_version":1}`.
* **Derivation:** `net.SplitHostPort(r.RemoteAddr)`; if the split fails, the raw `RemoteAddr`. `X-Forwarded-For` / `X-Real-IP` are **deliberately ignored** — the mgmt plane is dialled directly, and honouring a client header would let a caller spoof the very value it is asking the box to verify.
* **Why it exists:** the publisher's helper IP comes from third-party echo services and can be wrong behind CGNAT, split-horizon NAT or a captive proxy. This is the only authoritative answer. It cannot *bootstrap* the allowlist — it is itself behind the firewall — so it only confirms an IP that already works, letting the client stop re-detecting and store a verified value.
* **Feature detection is mandatory on the client.** Boxes deployed before this route exists answer `404`. A `404`, `405`, connection error or malformed body must be treated as "older box" and must never fail, block or degrade any publisher action; the stored `helper_ip` stays authoritative.

## 5. Cloud-firewall as gate

The Helper opens a 300-second `(callerIP, mgmtPort)` allowlist via `Provider.SetEphemeralFirewallRule(serverID, callerIP, port, 300)` immediately before each L1/L2 call, then drives the call, then removes the rule via `RemoveEphemeralFirewallRule(rule)` in a `defer` so cleanup runs even on error. The provider auto-expires the rule at 300 s as belt-and-braces.

Box-side `ufw` does **not** open the mgmt port. FRP-10 invariant 18 is structurally enforced by the V2 cloud-init template (`publisher/deploy/cloudinit/v2.yaml.tmpl`) which contains no `ufw allow` for the mgmt port; `TestRenderV2_NoBoxTokenInTemplate` asserts the absence of any cloud-provider-token marker in the rendered YAML.

## 6. Failure modes

| Condition | Server response | Helper action |
|---|---|---|
| Missing `Authorization` header | 401 | Operator-visible error; suggest redeploy |
| Token timestamp outside `[-300 s, +60 s]` | 401 | Surface "clock skew or replay" warning |
| Token `op` does not match URL path | 401 | Hard fail (token replay attempt) |
| Signature verification fails | 401 | Hard fail (wrong key or tampered token) |
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
| `cmd/daal-relay-mgmt/main_test.go` | 11 baseline + ~10 FRP-14 tests + the `/whoami` set, pinning the wire format, the seven-route invariant, the Ed25519 token shape (op-binding for all 6 ops + timestamp window), the self-signed cert fingerprint stability across restarts, the surgical sing-box JSON rewriters (rotate + per-user paths), and the per-recipient isolation invariants |
| `publisher/deploy/mgmt/client_test.go` | 12 tests pinning the Helper-side TLS-pin (wrong fingerprint = error), the token mint/parse round-trip, the ephemeral firewall open/close ordering, and the V1.5-fallback-on-zero-port path |
| `publisher/deploy/cloudinit/template_test.go` | 6 tests pinning the V2 cloud-init template's mgmt-unit installation, port-input determinism, and the no-cloud-provider-token-in-template invariant |

## 9. Carry-overs

* **Live alpha pilot.** The full FRP-10 mgmt-plane requires a real cloud-provider account at each of Hetzner / Vultr / Stark with billing enabled to verify the firewall-API timing in production. The pilot gate is documented in `specs/v2-closure-v1.md` (HOLD — see that spec for the exit criteria).
* **govultr/v3 + Stark live wiring.** The Vultr and Stark adapters compile + test against an injected client interface; the live SDK / REST wiring is part of the alpha-pilot work above.
