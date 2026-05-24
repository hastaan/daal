// Package deploy is the FRP-4a operator-side deploy substrate.
//
// It lands the Provider interface (provider/), the Hetzner adapter
// (provider/hetzner/), the deterministic cloud-init template
// (cloudinit/), the hardened health endpoint client + handler
// (health/), the iran-default toolbox profile (profiles/), the CLI
// subcommand dispatcher (cli/), and the OPSEC test (opsec_test.go).
//
// Position B: this package opens connections ONLY to (a) the
// cloud-provider API (e.g. hetznercloud/hcloud-go), and (b) the
// box's health endpoint over an IP-bound ufw rule for the
// 60-second provisioning window. No telemetry, no project
// endpoint. Verified by opsec_test.go.
//
// FRP-4a does NOT generate publisher keys (FRP-5) or sign
// RelayPacks (FRP-4b). It emits unsigned OperatorRecord JSON; the
// wizard (FRP-5) reads it and the binder (FRP-4b) signs it.
package deploy
