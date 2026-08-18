//go:build singbox

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/uri"
	"daal/core/routestore"

	"github.com/cretz/bine/tor"
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// This file is the client half of the tor family, proven against the
// engine that actually ships rather than against our own idea of it.
// It builds only under the `singbox` tag, where sing-box's strict
// option decoder and cretz/bine are both linked.

// The config BuildSingBoxConfig emits for a tor route must be accepted
// by sing-box's real decoder — the same parser the recipient engine
// runs. This is what "tor-bridge" could never do: sing-box 1.13.12
// registers `tor` (include/registry.go:88) and nothing named
// `tor-bridge`, so the old outbound died at "unknown outbound type".
func TestTorConfigAcceptedBySingBoxDecoder(t *testing.T) {
	bin := t.TempDir()
	for _, n := range []string{"libtor.so", "liblyrebird.so", "libwebtunnel.so", "libsnowflake.so"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	SetTorBinaryDir(bin)
	SetTorStateDir(t.TempDir())
	defer func() { SetTorBinaryDir(""); SetTorStateDir("") }()

	for _, line := range []string{
		"obfs4 1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD cert=aa/bb+cc== iat-mode=0",
		"webtunnel 5.6.7.8:443 1111111111111111111111111111111111111111 url=https://x.example.com/p ver=0.0.1",
		"snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/",
		"meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.example/",
		"1.2.3.4:443 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD", // vanilla
		"[2001:db8::1]:9001 ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
	} {
		t.Run(strings.Fields(line)[0], func(t *testing.T) {
			profs, _, err := uri.ParseAny([]byte(line+"\n"), "tor-bridge")
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			prof, err := singjson.Marshal(profs[0].Outbound)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "tor-bridge"}, prof)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			raw, err := MarshalSingBox(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx := include.Context(context.Background())
			opts, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, raw)
			if err != nil {
				t.Fatalf("sing-box REJECTED the config we emit: %v\n%s", err, raw)
			}
			var to *boxoption.TorOutboundOptions
			for _, o := range opts.Outbounds {
				if o.Type == "tor" {
					to, _ = o.Options.(*boxoption.TorOutboundOptions)
				}
			}
			if to == nil {
				t.Fatal("no tor outbound decoded")
			}
			if to.ExecutablePath == "" || to.DataDirectory == "" {
				t.Errorf("device paths lost in the round trip: %+v", to)
			}
			// The bridge line must arrive at tor byte-identical.
			found := false
			for i, a := range to.ExtraArgs {
				if a == "--Bridge" && to.ExtraArgs[i+1] == line {
					found = true
				}
			}
			if !found {
				t.Errorf("bridge line did not survive the round trip: %q", to.ExtraArgs)
			}
		})
	}
}

// The old emission must stay rejected, so nobody reintroduces it.
func TestTorBridgeTypeIsNotASingBoxType(t *testing.T) {
	ctx := include.Context(context.Background())
	_, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx,
		[]byte(`{"outbounds":[{"type":"tor-bridge","tag":"x","server":"1.2.3.4","server_port":443}]}`))
	if err == nil {
		t.Fatal("sing-box accepted type tor-bridge; the family comment in routestore/family.go is now wrong")
	}
	if !strings.Contains(err.Error(), "unknown outbound type") {
		t.Errorf("unexpected rejection reason: %v", err)
	}
}

// sing-box's tor outbound EXECS a binary; it does not link tor in.
// Proven by observing that a nonexistent executable_path produces a
// fork/exec error — and, critically, that it does so immediately.
// A blocked or missing tor must never hang the connect path.
func TestTorFailsClosedAndFastOnMissingExecutable(t *testing.T) {
	dir := t.TempDir()
	torrc := filepath.Join(dir, "torrc")
	if err := os.WriteFile(torrc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, err := tor.Start(ctx, &tor.StartConf{
		ExePath:         filepath.Join(dir, "libtor.so"), // absent
		DataDir:         dir,
		TempDataDirBase: os.TempDir(),
		TorrcFile:       torrc,
		ExtraArgs:       []string{"--UseBridges", "1", "--Bridge", "obfs4 1.2.3.4:443 AAAA"},
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("tor.Start succeeded with no tor binary")
	}
	if !strings.Contains(err.Error(), "fork/exec") {
		t.Errorf("expected a fork/exec failure (proving tor is a subprocess, not linked in), got: %v", err)
	}
	if !strings.Contains(err.Error(), "libtor.so") {
		t.Errorf("error should name the missing binary, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %v — a missing tor must fail, not hang", elapsed)
	}
	t.Logf("failed closed in %v: %v", elapsed, err)
}
