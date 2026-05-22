// Package health implements the FRP-4a health endpoint:
//
//   - Box side: a tiny http.Server with one route
//     GET /healthz/<one_time_token> that returns box state.
//     Built into cmd/daal-relay-health.
//
//   - Helper side: a poller that hits the box's /healthz route over
//     the IP-bound ufw rule during the 60-second provisioning
//     window. Verifies sing-box is up, returns liveness signal.
//
// Both sides keep their behaviour minimal: ONE bound interface, ONE
// route per token, ONE shape of body. Position B is preserved
// because the only outbound HTTP traffic from the Helper goes to
// the box on a port the box just opened for our IP, and the only
// inbound traffic the box accepts is from our IP on that port.
//
// This package is on the OPSEC test allowlist (per-package
// exemption for /deploy/health/).
package health
