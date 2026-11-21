// Package cloudflare builds the Cloudflare side of add-on 2, the way in
// through Cloudflare (docs/optional-addons-plan.md §2,
// specs/optional-addons-v1.md §4). It targets a zone the publisher owns
// and stands up:
//
//   - an Origin CA certificate for the zone and `*.<zone>` (no public CT
//     entry for the origin);
//   - Authenticated Origin Pull with a client certificate of this
//     front's own (aop.go), so the relay's door opens for this zone only;
//   - SSL mode Full (strict) and WebSockets on;
//   - a proxied A (and AAAA) record `<label>.<zone>`;
//   - an Origin Rule sending that hostname to the relay's dedicated CDN
//     port (relayports.CDNOrigin), so the edge never lands on REALITY;
//   - a read of the ECH posture: the zone setting and, over DoH, the
//     ECHConfigList the hostname publishes (ech.go, B-5). ECH is left as
//     Cloudflare has it.
//
// There is no Worker (decision D-5). The token needs exactly five zone
// permissions on one zone (token_check.go), and Daal never spends money
// through Cloudflare.
//
// The relay firewall rule is Hetzner's (providers/hetzner/firewall_cf.go)
// and the relay door is daal-relay-mgmt's (POST /cdn, door.go). The
// package never imports `core/...`.
//
// The live client (cf_client_live.go) talks to Cloudflare's v4 REST API
// directly; tests use MockCFClient, an in-memory Cloudflare.
// `cloudflare-go/v4` stays pinned in publisher/go.mod (sdk_pin.go) for
// the phase dependency lock only.
package cloudflare
