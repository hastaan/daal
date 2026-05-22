// Package cloudflare implements the FRP-8 V1.6 CDN-fronted
// provisioning surface. It targets a Cloudflare zone the FRP
// controls (BYO domain) and stands up the §11.7 hardening
// template:
//
//   - Origin CA cert on the origin (no public CT log exposure).
//   - Authenticated Origin Pulls enabled; client cert deployed
//     to the origin via the FRP-4a cloud-init template.
//   - Provider-firewall rule allowing 443/tcp only from
//     Cloudflare's published edge IP ranges (refreshed from the
//     Helper machine, never from the origin box).
//   - Public random path → Worker rewrite → stable origin path
//     indirection so public-path rotation is Cloudflare-API-only.
//   - Proxied A + AAAA DNS records only; no DNS-only records.
//
// The package never imports `core/...` (the existing module-
// boundary invariant `core → bundle, deploy → bundle, deploy →
// core never` is preserved).
//
// The package is structured around a small CFClient interface
// (cf_client.go). The live implementation talks to Cloudflare's
// v4 REST API directly through that narrow surface; tests use a
// mock. `cloudflare-go/v4` is pinned in publisher/go.mod for the
// phase dependency lock, but the critical path stays behind the
// wrapper to keep the runtime surface small and testable.
//
// See `phases of development/38-phase-frp-8-v1-6-cdn-fronted.md`.
package cloudflare
