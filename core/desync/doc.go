// Package desync splits the first bytes a TCP connection sends — in
// practice the TLS ClientHello — across several TCP segments (and,
// optionally, several TLS records), so that a censor's box that reads
// only the first data packet or two of a flow, and does not reassemble
// the stream, never sees a whole hello.
//
// It is plan item T2 of docs/blackout-tier-plan.md. Three properties
// matter, and they are why this package exists instead of sing-box's own
// tls fragmenter (common/tlsfragment):
//
//   - It sits BELOW the TLS library. The wrapper is applied to the raw
//     TCP connection the TLS client (uTLS, REALITY) is handed, by a Daal
//     outbound ("daal-desync") the route's outbound names as its
//     `detour`. sing-box 1.13.12 never wraps a REALITY hello in its own
//     fragmenter (common/tls/reality_client.go); a detour conn sees it
//     like any other bytes.
//   - It has no SNI gate. sing-box's fragmenter splits only when it finds
//     a server_name; this one cuts at the offsets the strategy names,
//     whether or not there is a name (a cut "inside the server_name" is
//     one optional cut among others, skipped when there is none).
//   - A hello may arrive in several Writes. A first TLS handshake record
//     is buffered until it is complete (its header says how long it is,
//     and a TLS client always writes a whole record before it reads), so
//     the cuts land where the strategy says however the TLS library
//     chunked its writes. A first flight that is not TLS is cut as it
//     arrives, within the first Write.
//
// The strategy is data (Strategy, strategy.go): a signed pack may offer
// one per route (family_specific_config._desync, pack.go), and the
// selection ladder may set or force off one per route for the network
// the phone is on (core/engine SetRouteDesync, SetDesyncNetwork), or
// hand one to a single config build (BuildSingBoxConfigWithDesync).
//
// Loss: only the ACK-wait presets (split1, sni-cut, tlsrec-sni) survive
// a lost segment uncut. Without the ACK (chain, or a wait that timed
// out) Linux may retransmit adjacent unacked segments merged
// (tcp_retrans_collapse), and a box that missed the originals reads the
// merged one. Where TCP_INFO is missing (Windows, macOS, iOS) there is
// no ACK wait and no autocork guard: delays alone, unmeasured. The zero Strategy is OFF, and an absent,
// unknown-versioned or invalid one is OFF: nothing about an existing
// route changes unless a strategy is explicitly turned on.
//
// What this package does NOT do: low-TTL decoys, out-of-order delivery,
// out-of-band bytes, out-of-window injection (plan T3; the first three
// are gated on on-device checks, the last needs root).
package desync
