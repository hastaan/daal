package engine

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"daal/bundle-go/uri"
)

// materialiseTorOutbound turns the device-independent `tor` outbound the
// importer produced (bundle/go/uri/tor_bridge.go) into one this device
// can actually run, or returns an error naming what is missing.
//
// Three things are added here and nowhere else, because all three are
// properties of the device rather than of the bridge:
//
//	executable_path       where tor itself lives
//	data_directory        where tor may cache its consensus
//	--ClientTransportPlugin  where each pluggable transport lives
//
// The transports are DERIVED from the `--Bridge` arguments rather than
// carried alongside them. A bridge line's first token is its transport
// name, so the two can never drift apart; had we stored the list
// separately, an importer that learned a new transport and an engine
// that did not would disagree silently, and the failure would surface as
// a tor bootstrap that never completes.
//
// FAIL CLOSED. Every error path returns before a config is produced.
// This is the deliberate choice for this family: the alternative — emit
// the config anyway and let sing-box start tor without a plugin it needs
// — produces a process that retries a bridge it can never reach and logs
// only at tor's own info level. The user sees a spinner. A route that
// hangs is worse than a route that refuses, because the path manager
// cannot rank a hang.
func materialiseTorOutbound(outbound map[string]any) error {
	rawArgs, err := torExtraArgs(outbound)
	if err != nil {
		return err
	}
	bridges := bridgeLinesFrom(rawArgs)
	if len(bridges) == 0 {
		return errors.New("engine: tor outbound carries no --Bridge line; " +
			"a tor route without a bridge would connect to the public Tor network directly")
	}

	// Resolve tor itself first: without it nothing else matters, and
	// its absence is the error most worth reporting cleanly.
	torPath, err := TorBinaryPath("")
	if err != nil {
		return err
	}
	if torPath != "" {
		outbound["executable_path"] = torPath
	}
	// torPath == "" means desktop-with-tor-on-PATH. Leaving
	// executable_path unset makes bine exec "tor" via PATH lookup,
	// which fails fast with a plain exec error if it is not installed
	// (verified: fork/exec ... no such file or directory, in well
	// under a millisecond).

	dataDir, err := TorDataDirectory()
	if err != nil {
		return err
	}
	// Create it now rather than letting tor do it, so a sandbox
	// permission problem is reported by us, with our vocabulary,
	// instead of arriving as a tor stderr line nobody reads.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("engine: cannot create Tor data directory %s: %w", dataDir, err)
	}
	outbound["data_directory"] = dataDir

	// One ClientTransportPlugin argument per DISTINCT transport.
	// Sorted so the argv is deterministic — a config that differs
	// run-to-run defeats the config-hash comparisons the driver uses to
	// decide whether a restart is needed.
	pts := map[string]bool{}
	for _, b := range bridges {
		if b.Transport != "" {
			pts[strings.ToLower(b.Transport)] = true
		}
	}
	names := make([]string, 0, len(pts))
	for n := range pts {
		names = append(names, n)
	}
	sort.Strings(names)

	var plugins []string
	for _, pt := range names {
		p, err := TorBinaryPath(pt)
		if err != nil {
			return err
		}
		// tor's ClientTransportPlugin grammar is
		//   <methods> exec <path> [args]
		// as a SINGLE argv element; tor splits it itself. Passing the
		// path as a separate argv element would make tor read "exec"
		// as the whole command.
		plugins = append(plugins, fmt.Sprintf("%s exec %s", pt, p))
	}
	// Write extra_args back UNCONDITIONALLY, even when no plugin was
	// added. torExtraArgs normalises the []any that survives a JSON
	// round trip into []string, and storing the normalised slice keeps
	// the outbound one shape for every caller — a test that reads
	// extra_args as []string would otherwise silently assert nothing on
	// the vanilla-bridge path.
	args := rawArgs
	for _, pl := range plugins {
		args = append(args, "--ClientTransportPlugin", pl)
	}
	outbound["extra_args"] = args
	return nil
}

// torExtraArgs reads extra_args back out of a decoded outbound. The map
// arrives from encoding/json, so a []string written by the importer is a
// []any of strings by the time it gets here; both shapes are accepted
// because BuildSingBoxConfig is also called directly in tests with
// hand-built maps.
func torExtraArgs(outbound map[string]any) ([]string, error) {
	v, ok := outbound["extra_args"]
	if !ok {
		return nil, nil
	}
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...), nil
	case []any:
		out := make([]string, 0, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("engine: tor extra_args[%d] is %T, want string", i, e)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("engine: tor extra_args is %T, want array of strings", v)
	}
}

// bridgeLinesFrom extracts and parses every value following a --Bridge
// flag, in argv order. Unparseable values are skipped: they cannot be
// turned into a transport requirement, and tor will reject them itself
// with a message naming the line.
func bridgeLinesFrom(args []string) []uri.TorBridgeLine {
	var out []uri.TorBridgeLine
	for i := 0; i < len(args)-1; i++ {
		if args[i] != "--Bridge" && args[i] != "-Bridge" {
			continue
		}
		b, err := uri.ParseTorBridgeLine(args[i+1])
		if err != nil {
			continue
		}
		out = append(out, b)
		i++
	}
	return out
}
