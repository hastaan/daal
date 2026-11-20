package cli

// Add-on 2, way in through Cloudflare (docs/optional-addons-plan.md §2,
// items B-3, B-5). NOT BUILT YET: lane L-cdn-server fills in this file.
//
//	cdn-token-check --token-file              verify the token, list the zones it sees, refuse one
//	                                          that can do more than the five zone permissions
//	cdn-test        --record-file ...         a real WebSocket handshake through the front, with ECH
//	cdn-posture     --record-file --token-file  ECH state, AOP, firewall, last test (read-only)
//	cdn-remove      --record-file --token-file  delete the DNS record and origin rule, revoke the origin
//	                                          certificate, close the firewall rule, disable the inbound
//
// The existing cdn-provision verb (cli.go) is rewritten in place by B-3;
// its Worker calls go (decision D-5).

import (
	"context"
	"io"
)

func runCDNTokenCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "cdn-token-check")
}

func runCDNTest(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "cdn-test")
}

func runCDNPosture(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "cdn-posture")
}

func runCDNRemove(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_, _, _ = ctx, args, stdout
	return addonNotBuilt(stderr, "cdn-remove")
}
