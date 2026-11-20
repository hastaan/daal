package cli

// Add-on 1, standby address (docs/optional-addons-plan.md §1, item S5).
// NOT BUILT YET: lane L-standby-pub fills in this file.
//
//	standby price   --record-file --token-file              monthly price of one Floating IPv4 in the relay's location
//	standby add     --record-file --token-file --priv-key --helper-ip [--mode sealed|open]
//	                                                       rent, assign, bind on the box without adopting it,
//	                                                       check the mgmt pin over it; rolls back on failure
//	standby promote --record-file ...                       the standby becomes the advertised address
//	standby remove  --record-file --token-file ...          unbind, delete the Floating IP (after re-signing)
//
// The binder side (`_standby` in every route) is publisher/deploy/relaypack/endpoint.go.

import (
	"context"
	"fmt"
	"io"
)

func runStandby(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	_, _, _ = ctx, stdin, stdout
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: daal-deploy standby price|add|promote|remove [flags]")
		return 2
	}
	switch args[0] {
	case "price", "add", "promote", "remove":
		return addonNotBuilt(stderr, "standby "+args[0])
	default:
		fmt.Fprintf(stderr, "unknown standby verb %q (want price|add|promote|remove)\n", args[0])
		return 2
	}
}
