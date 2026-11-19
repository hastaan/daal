//go:build singbox

package engine

import (
	"context"
	"strings"
	"testing"
)

// Start used to append the whole merged sing-box config — credentials
// and server address included — to the device log when sing-box could
// not parse it. A config that cannot be parsed must leave only the
// class of the failure and the kind of outbound in the log.
func TestStartParseFailureDoesNotLogTheConfig(t *testing.T) {
	const (
		password = "s3cr3t-Passw0rd-do-not-log"
		server   = "relay.secret-host.example"
		uuid     = "5f1c0f3e-9a41-4f7b-8f55-0d5c3a1b2c9d"
	)
	var lines []string
	restore := SetLogTapForTest(func(_ int, line string) { lines = append(lines, line) })
	defer restore()

	// Any fd will do: the parse fails long before the TUN is opened.
	SetCurrentTunFD(0)
	defer SetCurrentTunFD(-1)

	// `server_port` is a string: sing-box's option parser rejects it,
	// and its error quotes the offending value's surroundings.
	cfg := `{"outbounds":[{"type":"vless","tag":"active","server":"` + server + `","server_port":"` + password + `","uuid":"` + uuid + `","password":"` + password + `"}],"route":{"final":"active"}}`
	s := newSingBox()
	err := s.Start(context.Background(), []byte(cfg))
	if err == nil {
		_ = s.Stop()
		t.Fatal("premise: sing-box accepted a config with a string server_port")
	}
	if !strings.Contains(err.Error(), "option parse") {
		t.Fatalf("premise: the failure is not an option-parse failure: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("an option-parse failure logged nothing")
	}
	found := false
	for _, l := range lines {
		if strings.Contains(l, "option parse failed") && strings.Contains(l, "outbound=vless") {
			found = true
		}
		for _, secret := range []string{password, server, "secret-host", uuid, `"outbounds"`, "server_port"} {
			if strings.Contains(l, secret) {
				t.Errorf("the log line carries %q: %q", secret, l)
			}
		}
	}
	if !found {
		t.Fatalf("no line names the failure class and the outbound kind: %v", lines)
	}
}
