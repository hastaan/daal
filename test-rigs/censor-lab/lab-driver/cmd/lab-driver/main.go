package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"daal/lab-driver/internal/netns"
	"daal/lab-driver/internal/scenarios"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "replay":
		os.Exit(runReplay(os.Args[2:]))
	case "run":
		os.Exit(runLive(os.Args[2:]))
	case "validate":
		os.Exit(runValidate(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lab-driver {replay|run|validate} [flags]")
	fmt.Fprintln(os.Stderr, "  replay   --scenarios <dir> --out <dir>  : produce fixtures offline")
	fmt.Fprintln(os.Stderr, "  validate --scenarios <dir>              : parse and validate scenarios")
	fmt.Fprintln(os.Stderr, "  run      --scenario <file>              : live run (requires CAP_NET_ADMIN)")
}

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	scen := fs.String("scenarios", "", "directory of scenario JSON files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scen == "" {
		fs.Usage()
		return 2
	}
	all, err := scenarios.LoadDir(*scen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	ids := make([]string, 0, len(all))
	for _, s := range all {
		ids = append(ids, s.ID)
	}
	sort.Strings(ids)
	fmt.Printf("validated %d scenarios\n", len(all))
	for _, id := range ids {
		fmt.Println("  -", id)
	}
	return 0
}

func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	scenDir := fs.String("scenarios", "", "directory of scenario JSON files")
	outDir := fs.String("out", "", "output directory for fixtures")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scenDir == "" || *outDir == "" {
		fs.Usage()
		return 2
	}
	all, err := scenarios.LoadDir(*scenDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	now := time.Now()
	written := 0
	for _, s := range all {
		fx := s.Replay(now)
		paths, err := scenarios.WriteFixtures(*outDir, fx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error writing fixtures for", s.ID, err)
			return 1
		}
		written += len(paths)
	}
	fmt.Printf("wrote %d fixtures into %s\n", written, filepath.Clean(*outDir))
	return 0
}

func runLive(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	scen := fs.String("scenario", "", "single scenario JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scen == "" {
		fs.Usage()
		return 2
	}
	if !netns.Available() {
		fmt.Fprintln(os.Stderr, "error:", netns.ErrNeedsNetAdmin)
		return 1
	}
	// The live netns runner is staged for incremental delivery alongside
	// real Linux+netns testing. Phase 0C ships the offline replay path and
	// prints an actionable message here so users do not assume otherwise.
	fmt.Fprintln(os.Stderr, "live netns runner is staged; use 'lab-driver replay' for offline fixture generation in Phase 0C")
	return 1
}
