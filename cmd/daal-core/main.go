// daal-core is a Linux/Windows CLI that drives the same in-process API
// the Android/Tauri bridges call. It is the developer-side test harness
// when no phone or sing-box engine is available.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"daal/core/abi"
)

func main() {
	stateDir := flag.String("state-dir", defaultStateDir(), "state directory")
	logLevel := flag.String("log", "warn", "log level")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: daal-core [--state-dir DIR] <command> [args]")
		fmt.Fprintln(os.Stderr, "  version")
		fmt.Fprintln(os.Stderr, "  import <file.sbp>")
		fmt.Fprintln(os.Stderr, "  resolve <fingerprint> <trust|once|cancel>")
		fmt.Fprintln(os.Stderr, "  list")
		fmt.Fprintln(os.Stderr, "  connect <route_id>")
		fmt.Fprintln(os.Stderr, "  disconnect")
		fmt.Fprintln(os.Stderr, "  mode <lifeline|normal|bulk>")
		fmt.Fprintln(os.Stderr, "  probe")
		fmt.Fprintln(os.Stderr, "  diag")
		fmt.Fprintln(os.Stderr, "  panic-wipe")
		fmt.Fprintln(os.Stderr, "  share-begin <route_id> [--lan] [--qr URI]")
		fmt.Fprintln(os.Stderr, "  share-serve <route_id> [--qr URI]    (foreground; LAN on; Ctrl+C to end)")
		fmt.Fprintln(os.Stderr, "  share-end <session_id>")
		fmt.Fprintln(os.Stderr, "  share-pull <host> <port> <pin> <session_id> <spki_b64>")
		fmt.Fprintln(os.Stderr, "  uri-detect <text>")
		fmt.Fprintln(os.Stderr, "  uri-import <uri>")
		fmt.Fprintln(os.Stderr, "  bootstrap-install")
		fmt.Fprintln(os.Stderr, "  bootstrap-refresh [timeout-ms]")
		fmt.Fprintln(os.Stderr, "  bootstrap-status")
		fmt.Fprintln(os.Stderr, "  subscription-add <publisher_fp> <url> [display_name]")
		fmt.Fprintln(os.Stderr, "  subscription-refresh <subscription_id> [timeout-ms]")
		fmt.Fprintln(os.Stderr, "  subscription-list")
		fmt.Fprintln(os.Stderr, "  subscription-remove <subscription_id>")
		fmt.Fprintln(os.Stderr, "  revocation-refresh-all [timeout-ms]")
		fmt.Fprintln(os.Stderr, "  pointer-rotation-status")
		fmt.Fprintln(os.Stderr, "  diag-explain")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := abi.Init(*stateDir, *logLevel); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		os.Exit(1)
	}
	defer abi.Shutdown()

	switch args[0] {
	case "version":
		fmt.Println(abi.VersionString())
	case "import":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		body, err := abi.ImportSBP(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "import:", err)
		}
		fmt.Println(body)
	case "resolve":
		if len(args) != 3 {
			flag.Usage()
			os.Exit(2)
		}
		dec := -1
		switch args[2] {
		case "trust":
			dec = 0
		case "once":
			dec = 1
		case "cancel":
			dec = 2
		default:
			fmt.Fprintln(os.Stderr, "decision must be trust|once|cancel")
			os.Exit(2)
		}
		body, err := abi.ResolveTrustPrompt(args[1], dec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "resolve:", err)
		}
		fmt.Println(body)
	case "list":
		body, err := abi.ExportDiagnostics()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "connect":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		if err := abi.SetRoute(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "connect:", err)
			os.Exit(1)
		}
		fmt.Println("connected:", args[1])
	case "disconnect":
		if err := abi.ClearRoute(); err != nil {
			fmt.Fprintln(os.Stderr, "disconnect:", err)
			os.Exit(1)
		}
		fmt.Println("disconnected")
	case "mode":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		if err := abi.SetMode(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("mode:", abi.Mode())
	case "probe":
		fmt.Println("udp:    ", abi.ProbeUDP(2000))
		fmt.Println("dns:    ", abi.ProbeDNS(2000))
		fmt.Println("tcp443: ", abi.ProbeTCP443(2000))
	case "diag":
		body, err := abi.ExportDiagnostics()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "share-begin":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		routeIDs := args[1]
		lan := false
		qr := ""
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--lan":
				lan = true
			case "--qr":
				if i+1 < len(args) {
					qr = args[i+1]
					i++
				}
			}
		}
		body, err := abi.ShareBegin(routeIDs, lan, qr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "share-begin:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "share-serve":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		routeIDs := args[1]
		qr := ""
		for i := 2; i < len(args); i++ {
			if args[i] == "--qr" && i+1 < len(args) {
				qr = args[i+1]
				i++
			}
		}
		body, err := abi.ShareBegin(routeIDs, true, qr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "share-serve:", err)
			os.Exit(1)
		}
		fmt.Println(body)
		// Block until SIGINT/SIGTERM.
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		fmt.Fprintln(os.Stderr, "share-serve: shutting down")
		// Shutdown closes all sessions via core teardown.
	case "share-end":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		if err := abi.ShareEnd(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "share-end:", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	case "share-pull":
		// <spki_b64> is mandatory: the receiver pins the sender's leaf
		// certificate SPKI, and share.PullURL refuses to dial without it.
		// Read it from the sender's `lan_spki` (share-begin output) or from
		// the `#spki=` fragment of its daalshare:// URI.
		if len(args) != 6 {
			flag.Usage()
			os.Exit(2)
		}
		port, err := strconv.Atoi(args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "port:", err)
			os.Exit(2)
		}
		body, err := abi.SharePull(args[1], port, args[3], args[4], args[5])
		if err != nil {
			fmt.Fprintln(os.Stderr, "share-pull:", err)
		}
		fmt.Println(body)
	case "uri-detect":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		body, err := abi.URIDetect(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "uri-detect:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "uri-import":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		body, err := abi.URIImport(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "uri-import:", err)
		}
		fmt.Println(body)
	case "bootstrap-install":
		body, err := abi.BootstrapInstallSeeds()
		if err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap-install:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "bootstrap-refresh":
		timeoutMs := 15000
		if len(args) >= 2 {
			n, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "timeout:", err)
				os.Exit(2)
			}
			timeoutMs = n
		}
		body, err := abi.BootstrapRefresh(timeoutMs)
		if err != nil && body == "" {
			fmt.Fprintln(os.Stderr, "bootstrap-refresh:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "bootstrap-status":
		body, err := abi.BootstrapStatus()
		if err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap-status:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "subscription-add":
		if len(args) < 3 {
			flag.Usage()
			os.Exit(2)
		}
		display := ""
		if len(args) >= 4 {
			display = args[3]
		}
		body, err := abi.SubscriptionAdd(args[1], args[2], display)
		if err != nil {
			fmt.Fprintln(os.Stderr, "subscription-add:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "subscription-refresh":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		timeoutMs := 15000
		if len(args) >= 3 {
			n, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Fprintln(os.Stderr, "timeout:", err)
				os.Exit(2)
			}
			timeoutMs = n
		}
		body, err := abi.SubscriptionRefresh(args[1], timeoutMs)
		if err != nil && body == "" {
			fmt.Fprintln(os.Stderr, "subscription-refresh:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "subscription-list":
		body, err := abi.SubscriptionList()
		if err != nil {
			fmt.Fprintln(os.Stderr, "subscription-list:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "subscription-remove":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		if err := abi.SubscriptionRemove(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "subscription-remove:", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	case "revocation-refresh-all":
		timeoutMs := 15000
		if len(args) >= 2 {
			n, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "timeout:", err)
				os.Exit(2)
			}
			timeoutMs = n
		}
		body, err := abi.RevocationRefreshAll(timeoutMs)
		if err != nil && body == "" {
			fmt.Fprintln(os.Stderr, "revocation-refresh-all:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "pointer-rotation-status":
		body, err := abi.PointerRotationStatus()
		if err != nil {
			fmt.Fprintln(os.Stderr, "pointer-rotation-status:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	case "diag-explain":
		body, err := abi.DiagnosticsExplain()
		if err != nil {
			fmt.Fprintln(os.Stderr, "diag-explain:", err)
			os.Exit(1)
		}
		fmt.Println(body)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func defaultStateDir() string {
	if d := os.Getenv("DAAL_STATE_DIR"); d != "" {
		return d
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h + "/.daal"
	}
	return "./.daal"
}
