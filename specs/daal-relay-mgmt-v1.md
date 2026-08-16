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
* `op` is one of `rotate-credentials`, `rotate-tls`, `users-provision`, `users-revoke`, or `users-list` (the last three added at FRP-14). The on-box service rejects any token whose `op` does not match the URL path.
* `<base64-sig>` is the standard-encoding base64 of `Ed25519.Sign(privKey, "<nonce>:<ts>:<op>")`, i.e., the signature covers the first three colon-separated fields verbatim.

The `privKey` is the Helper's per-deploy publisher Ed25519 private key. Its public half is written to `/etc/daal/mgmt/pubkey` by cloud-init at first boot (hex-encoded, 64 chars) so the on-box service can verify tokens without ever holding the private half.

**Timestamp window:** the on-box service accepts `ts` in `[serverNow - 300 s, serverNow + 60 s]`. Older tokens are rejected to bound replay; future tokens are rejected to bound clock-skew abuse.

**Op-binding:** the on-box service refuses to accept a token signed for `rotate-credentials` against `/rotate-tls` and vice versa. This pins token-flow integrity even if the URL path is otherwise unprotected.

## 4. API surface — exactly seven routes

The FRP-10 baseline locked three routes (`/rotate-credentials`, `/rotate-tls`, `/health`). FRP-14 adds three per-recipient routes (`/users/provision`, `/users/revoke`, `/users/list`), specified in `specs/per-recipient-credentials-v1.md`. The publisher redesign adds a seventh, `/whoami` (§4.7). Adding an **eighth** route requires a supplement amendment. The implementation-level invariant is pinned by `TestExactlyNRoutes` (n=7) in `cmd/daal-relay-mgmt/main_test.go`.

### 4.1. `POST /rotate-credentials` — L1, ~5 s

Auth required. Body MAY be empty. Response is JSON:

    {
      "uuid": "<v4>",
      "reality_private_key": "<hex>",
      "generated_at_unix": <int>
    }

Side effects on the box:

1. Generate a fresh VLESS UUID (v4, RFC 4122-conformant — random nibbles via `crypto/rand`).
2. Generate a fresh REALITY X25519 private key (32 random bytes via `crypto/rand`; the public half is derivable but the on-box service returns only the private half because the Helper re-derives the public half when it re-signs the RelayPack).
3. Surgically rewrite `/etc/sing-box/config.json`: locate the VLESS inbound, replace the `users[].uuid` and `tls.reality.private_key` fields, leave every other key (route tables, outbounds, DNS config, log levels) byte-identical.
4. `systemctl reload-or-restart sing-box.service`.
5. Return the new credentials as JSON.

The Helper writes the new credentials into the next signed RelayPack. The on-box service holds no state about whether the Helper successfully consumed them; if the Helper crashes between L1 and the next bind, the operator can re-run L1 and the box will simply replace the credentials again.

### 4.2. `POST /rotate-tls` — L2, ~20 s

Auth required. Body is JSON:

    {
      "new_sni": "<fqdn>",
      "new_dests": ["<fqdn>:443", ...],
      "new_ws_path": "<optional, only for ws-shaped profiles>"
    }

Response:

    { "applied_at_unix": <int> }

Side effects on the box:

1. Surgically rewrite the VLESS inbound's `tls.server_name`, `tls.reality.handshake.server`, and `tls.reality.dest` fields. Replace any `transport.path` if `new_ws_path` is supplied.
2. `systemctl reload-or-restart sing-box.service`.

The L2 path rotates the data-plane TLS/SNI profile used by sing-box. It deliberately does **not** rotate the management-plane self-signed certificate or `rec.MgmtTLSFingerprint`; a management-cert compromise is handled as a redeploy until a future explicit management-cert rotation endpoint is specified.

### 4.3. `GET /health` — liveness probe

No auth. Response is `{"ok":true}` with status 200. Used by the Helper for end-to-end TLS-pinned probing of a freshly-deployed box during V2 provisioning.

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
| `systemctl reload-or-restart` fails | 500 | Operator-visible error; box may be in inconsistent state — recommend redeploy |
| `MgmtPort == 0` in `OperatorRecord` (V1.5 record) | n/a (Helper short-circuits) | Fall back to FRP-7 redeploy path |

## 7. What this spec does NOT cover

* **Rotation orchestration above the in-box service.** The wizard's mode-aware rotation copy, audit log, and history table (`signed_sbps.rotation_kind`) live in `client-desktop/daal-wizard` and are documented under `specs/relaypack-v1.md` §rotation.
* **Provider-firewall rule shapes.** Each `Provider` adapter implements `SetEphemeralFirewallRule` against its native API; the contract is `publisher/deploy/provider/provider.go::Provider`.
* **The Android wizard.** Per FRP-10 invariant 30 the Android wizard is provision-only and never calls this service. See `specs/android-client-v1.md` for the Android boundary.

## 8. Test surface (FRP-10 + future)

| File | Purpose |
|---|---|
| `cmd/daal-relay-mgmt/main_test.go` | 11 baseline + ~10 FRP-14 tests + the `/whoami` set, pinning the wire format, the seven-route invariant, the Ed25519 token shape (op-binding for all 5 ops + timestamp window), the self-signed cert fingerprint stability across restarts, the surgical sing-box JSON rewriters (rotate + per-user paths), and the per-recipient isolation invariants |
| `publisher/deploy/mgmt/client_test.go` | 12 tests pinning the Helper-side TLS-pin (wrong fingerprint = error), the token mint/parse round-trip, the ephemeral firewall open/close ordering, and the V1.5-fallback-on-zero-port path |
| `publisher/deploy/cloudinit/template_test.go` | 6 tests pinning the V2 cloud-init template's mgmt-unit installation, port-input determinism, and the no-cloud-provider-token-in-template invariant |

## 9. Carry-overs

* **Live alpha pilot.** The full FRP-10 mgmt-plane requires a real cloud-provider account at each of Hetzner / Vultr / Stark with billing enabled to verify the firewall-API timing in production. The pilot gate is documented in `specs/v2-closure-v1.md` (HOLD — see that spec for the exit criteria).
* **govultr/v3 + Stark live wiring.** The Vultr and Stark adapters compile + test against an injected client interface; the live SDK / REST wiring is part of the alpha-pilot work above.
