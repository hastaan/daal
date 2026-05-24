// daal-deploy is the Helper-side CLI driver for FRP-4a VPS
// provisioning. The wizard (FRP-5) calls the Provider interface
// directly; this binary exists so the Helper operator can drive
// deployment from the command line during development and field
// operation.
//
// Usage:
//
//	daal-deploy provision --pubkey-file pub --region fsn1 \
//	    --toolbox-profile iran-default --helper-ip $HOST_IP \
//	    --token-file ~/.daal/hetzner.token -o record.json
//
// See `daal-deploy --help` for the full subcommand surface.
package main

import (
	"os"

	"daal/publisher/deploy/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
