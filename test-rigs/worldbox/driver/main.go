// Command wb is the worldbox driver: one binary, several roles.
//
//	wb run <scenario> [family…]   build a world, run the matrix, tear it down
//	wb fakecloud …                the cloud provider + release mirror (internet ns)
//	wb target …                   the "blocked site" (internet ns)
//	wb inet …                     DNS + every other website (internet ns)
//	wb probe …                    an app on the phone (client ns)
//	wb storage …                  static hosting the insider can reach without a tunnel (ops_freshness.go)
//	wb mgmtprobe …                hand-built requests to a relay's mgmt API (ops_mgmtauth.go)
//	wb dpi | rawprobe | elsewhere the censor's payload box and its Daal-free probes (censor_*.go)
//	wb flows …                    the censor's packet log of the client's connections to the relay (flowtap.go)
//	wb summary …                  many worlds → one report and one exit status (summary.go)
//	wb fakecf | fakecdn | fakegoogle  Cloudflare's API and edge, Google's front and Apps Script (add-ons; addons_net.go)
//
// `run` must be PID 1 of a fresh user+net+mount+pid namespace; run.sh
// arranges that. See ../README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wb <run|fakecloud|target|probe|list> …")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "list":
		os.Exit(cmdList(os.Args[2:]))
	case "fakecloud":
		os.Exit(cmdFakeCloud(os.Args[2:]))
	case "inet":
		os.Exit(cmdInet(os.Args[2:]))
	case "target":
		os.Exit(cmdTarget(os.Args[2:]))
	case "probe":
		os.Exit(cmdProbe(os.Args[2:]))
	case "mgmtprobe":
		os.Exit(cmdMgmtProbe(os.Args[2:]))
	case "storage":
		os.Exit(cmdStorage(os.Args[2:]))
	case "summary": // many worlds → one report (summary.go; e2e.sh calls it)
		os.Exit(cmdSummary(os.Args[2:]))
	case "dpi": // the censor's payload-aware box (censor_dpi.go)
		os.Exit(cmdDPI(os.Args[2:]))
	case "flows": // when the client opened each connection to the relay (flowtap.go)
		os.Exit(cmdFlows(os.Args[2:]))
	case "rawprobe": // a Daal-free probe from the client's seat (censor_probe.go)
		os.Exit(cmdRawProbe(os.Args[2:]))
	case "elsewhere": // the unblocked control host (censor_probe.go)
		os.Exit(cmdElsewhere(os.Args[2:]))
	case "fakecf": // Cloudflare's API, published ranges and DoH (fakecf_api.go)
		os.Exit(cmdFakeCF(os.Args[2:]))
	case "fakecdn": // Cloudflare's edge (fakecdn.go)
		os.Exit(cmdFakeCDN(os.Args[2:]))
	case "tlsface": // a stranger's TLS handshake to relay ports (prober.go)
		os.Exit(cmdTLSFace(os.Args[2:]))
	case "fakegoogle": // Google's front, web apps and Apps Script API (fakegfe.go, fakegas_api.go)
		os.Exit(cmdFakeGoogle(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "wb: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}
