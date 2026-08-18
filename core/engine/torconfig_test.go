package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/bundle-go/uri"
	"daal/core/routestore"
)

// torTestDirs points the resolver at a temp directory holding fake
// binaries, so these tests exercise the real resolution logic without
// shipping a tor binary.
func torTestDirs(t *testing.T, binaries ...string) (binDir string) {
	t.Helper()
	binDir = t.TempDir()
	for _, b := range binaries {
		if err := os.WriteFile(filepath.Join(binDir, b), []byte("#!/bin/false\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	SetTorBinaryDir(binDir)
	SetTorStateDir(t.TempDir())
	t.Cleanup(func() { SetTorBinaryDir(""); SetTorStateDir("") })
	return binDir
}

func torProfile(t *testing.T, lines ...string) []byte {
	t.Helper()
	profs, _, err := uri.ParseAny([]byte(strings.Join(lines, "\n")+"\n"), "tor-bridge")
	if err != nil {
		t.Fatalf("import bridge lines: %v", err)
	}
	if len(profs) != 1 {
		t.Fatalf("want 1 profile, got %d", len(profs))
	}
	b, err := json.Marshal(profs[0].Outbound)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const obfs4Line = "obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=zZ+/x iat-mode=0"

// The emitted outbound must match sing-box's ACTUAL option/tor.go shape.
// The companion assertion — that sing-box's strict decoder accepts it —
// lives in client_outbound_singbox_test.go, which builds under the
// `singbox` tag with the real parser linked.
func TestTorOutboundHasSingBoxShape(t *testing.T) {
	torTestDirs(t, "libtor.so", "liblyrebird.so")
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"}, torProfile(t, obfs4Line))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	out := cfg.Outbounds[0]
	if out["type"] != "tor" {
		t.Fatalf("type = %v, want tor", out["type"])
	}
	// Exactly the four fields option.TorOutboundOptions declares, plus
	// the tag every outbound carries. An extra field would be rejected
	// by sing-box's strict decoder.
	allowed := map[string]bool{"type": true, "tag": true, "executable_path": true, "extra_args": true, "data_directory": true, "torrc": true}
	for k := range out {
		if !allowed[k] {
			t.Errorf("unexpected field %q — sing-box's decoder rejects unknown fields", k)
		}
	}
	if !strings.HasSuffix(out["executable_path"].(string), "/libtor.so") {
		t.Errorf("executable_path = %v", out["executable_path"])
	}
	if !strings.HasSuffix(out["data_directory"].(string), "/tor") {
		t.Errorf("data_directory = %v", out["data_directory"])
	}
	if _, err := os.Stat(out["data_directory"].(string)); err != nil {
		t.Errorf("data_directory not created: %v", err)
	}
}

// Bridge lines must survive into extra_args IN ORDER and BYTE-EXACT.
// obfs4 cert= values are base64 with significant padding and '+'/'/'
// characters; any re-encoding en route silently produces a bridge that
// cannot authenticate.
func TestBridgeLinesSurviveIntoExtraArgsInOrder(t *testing.T) {
	torTestDirs(t, "libtor.so", "liblyrebird.so")
	l2 := "obfs4 5.6.7.8:9001 1111111111111111111111111111111111111111 cert=aa/bb+cc== iat-mode=1"
	profs, _, err := uri.ParseAny([]byte(obfs4Line+"\n"+l2+"\n"), "tor-bridge")
	if err != nil {
		t.Fatal(err)
	}
	// One route per bridge, by design — assert that first.
	if len(profs) != 2 {
		t.Fatalf("want one route per bridge line, got %d", len(profs))
	}
	// Now build a single outbound carrying BOTH, which is what the
	// engine must tolerate if a future caller folds them together.
	ob := uri.TorOutboundForBridge(mustParseLine(t, obfs4Line))
	args, _ := ob["extra_args"].([]string)
	args = append(args, "--Bridge", l2)
	ob["extra_args"] = args
	if err := materialiseTorOutbound(ob); err != nil {
		t.Fatalf("materialise: %v", err)
	}
	got, _ := ob["extra_args"].([]string)
	var bridges []string
	for i := 0; i < len(got)-1; i++ {
		if got[i] == "--Bridge" {
			bridges = append(bridges, got[i+1])
		}
	}
	want := []string{obfs4Line, l2}
	if len(bridges) != 2 {
		t.Fatalf("bridges = %q", bridges)
	}
	for i := range want {
		if bridges[i] != want[i] {
			t.Errorf("bridge[%d]\n got %q\nwant %q", i, bridges[i], want[i])
		}
	}
	// UseBridges must precede them, or tor ignores Bridge entirely and
	// silently joins the public network.
	if got[0] != "--UseBridges" || got[1] != "1" {
		t.Errorf("argv must open with --UseBridges 1, got %q", got[:2])
	}
	// Exactly one ClientTransportPlugin for the one distinct transport.
	n := 0
	for i, a := range got {
		if a == "--ClientTransportPlugin" {
			n++
			// tor parses "<methods> exec <path>" out of ONE argv element.
			if !strings.HasPrefix(got[i+1], "obfs4 exec /") {
				t.Errorf("plugin arg %q is not '<pt> exec <abs path>'", got[i+1])
			}
		}
	}
	if n != 1 {
		t.Errorf("ClientTransportPlugin count = %d, want 1 (deduplicated)", n)
	}
}

func mustParseLine(t *testing.T, s string) uri.TorBridgeLine {
	t.Helper()
	b, err := uri.ParseTorBridgeLine(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A missing tor binary must fail CLOSED, at config time, with a message
// naming the cause. The failure mode this prevents is the bad one: tor
// starting and looping on a bridge it cannot reach while the UI spins.
func TestMissingTorExecutableFailsClosedNamingTheCause(t *testing.T) {
	dir := torTestDirs(t) // no binaries at all
	_, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"}, torProfile(t, obfs4Line))
	if err == nil {
		t.Fatal("expected a closed failure, got a config")
	}
	for _, want := range []string{"libtor.so", dir, "not installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %q; got: %v", want, err)
		}
	}
}

// tor present but the pluggable transport absent is the more likely
// packaging slip, and the more dangerous one: tor WILL start.
func TestMissingPluggableTransportFailsClosed(t *testing.T) {
	torTestDirs(t, "libtor.so")
	_, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"}, torProfile(t, obfs4Line))
	if err == nil {
		t.Fatal("expected a closed failure, got a config")
	}
	if !strings.Contains(err.Error(), "liblyrebird.so") || !strings.Contains(err.Error(), "obfs4") {
		t.Errorf("error must name the transport and its file; got: %v", err)
	}
}

func TestUnknownPluggableTransportRejected(t *testing.T) {
	torTestDirs(t, "libtor.so")
	_, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"},
		torProfile(t, "quantumobfs 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"))
	if err == nil || !strings.Contains(err.Error(), "quantumobfs") {
		t.Fatalf("want a rejection naming the transport, got: %v", err)
	}
}

// A vanilla (transport-less) bridge needs tor and nothing else.
func TestVanillaBridgeNeedsNoPlugin(t *testing.T) {
	torTestDirs(t, "libtor.so")
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"},
		torProfile(t, "1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"))
	if err != nil {
		t.Fatalf("vanilla bridge should build with tor alone: %v", err)
	}
	args, ok := cfg.Outbounds[0]["extra_args"].([]string)
	if !ok {
		t.Fatalf("extra_args must be normalised to []string, got %T", cfg.Outbounds[0]["extra_args"])
	}
	if len(args) == 0 {
		t.Fatal("vanilla bridge lost its extra_args entirely")
	}
	for _, a := range args {
		if a == "--ClientTransportPlugin" {
			t.Error("vanilla bridge must not request a pluggable transport")
		}
	}
	// The bridge itself must still be there.
	if args[0] != "--UseBridges" || args[2] != "--Bridge" {
		t.Errorf("vanilla argv malformed: %q", args)
	}
}

// A tor outbound with no bridge at all must be refused. Falling back to
// the public Tor network for a user who asked for a bridge is a privacy
// failure, not a graceful degradation.
func TestTorWithoutBridgeRefused(t *testing.T) {
	torTestDirs(t, "libtor.so")
	_, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"},
		[]byte(`{"type":"tor"}`))
	if err == nil || !strings.Contains(err.Error(), "--Bridge") {
		t.Fatalf("want refusal naming the missing bridge, got: %v", err)
	}
}

// Every transport Daal advertises must map to a binary name, and every
// binary name must follow Android's lib*.so extraction rule.
func TestEveryKnownTransportMapsToAnExtractableName(t *testing.T) {
	for pt, name := range torBinaryNames {
		if !strings.HasPrefix(name, "lib") || !strings.HasSuffix(name, ".so") {
			t.Errorf("transport %q -> %q: Android only extracts lib*.so from the APK", pt, name)
		}
	}
}
