//go:build singbox

package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/diagnostics"
	"daal/core/routestore"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// startTestBox builds and starts the linked sing-box from the config the
// engine really generates for `profile`, minus the TUN inbound (which
// needs a VpnService's fd). It returns the instance, the active
// outbound's kind and the function that ends the instance's context —
// the three things singBox.Start keeps.
func startTestBox(t *testing.T, profile string) (*box.Box, outboundKind, context.CancelFunc) {
	t.Helper()
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: "vless-reality"}, []byte(profile))
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	t.Cleanup(retireRefreshInlet)
	blob, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	if route, ok := raw["route"].(map[string]any); ok {
		delete(route, "udp_gated")
	}
	raw["dns"] = defaultDNSBlock()
	merged, _ := json.Marshal(raw)
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, merged)
	if err != nil {
		cancel()
		t.Fatalf("option parse: %v", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatalf("box.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	return inst, kindOfActive(raw), cancel
}

// connectProxy is a minimal HTTP CONNECT proxy: the "relay" for an
// `http` outbound. It counts the tunnels it opened.
func connectProxy(t *testing.T) (addr *net.TCPAddr, tunnels *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tunnels = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				up, err := net.DialTimeout("tcp", req.Host, 2*time.Second)
				if err != nil {
					fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				tunnels.Add(1)
				fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr), tunnels
}

func quickProof(targets ...string) ProofConfig {
	return ProofConfig{Targets: targets, AttemptTimeout: 1500 * time.Millisecond, Attempts: 2, SlowAfter: time.Second}
}

// The proof is a real round trip THROUGH the active outbound: with a
// working relay it succeeds and the relay saw the tunnel; with nothing
// at the relay's address it fails — where sing-box's Start succeeds
// either way (CEN-1: that nil used to be read as "Connected").
func TestProveInstance_RoundTripGoesThroughTheOutbound(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	proxy, tunnels := connectProxy(t)

	inst, kind, cancel := startTestBox(t, fmt.Sprintf(`{"type":"http","server":"127.0.0.1","server_port":%d}`, proxy.Port))
	defer closeInstance(inst, cancel)
	res := proveInstance(context.Background(), inst, kind, quickProof(target.Listener.Addr().String()))
	if !res.OK {
		t.Fatalf("a working relay did not prove: %+v (%v)", res, res.Err)
	}
	if tunnels.Load() == 0 {
		t.Fatal("the proof succeeded without the relay carrying it: it did not go through the outbound")
	}
	if res.Slow {
		t.Fatalf("a loopback round trip was called slow: %s", res.RoundTrip)
	}
}

func TestProveInstance_DeadRelayFailsAndIsClassified(t *testing.T) {
	// A port nothing listens on: the SYN is refused.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	inst, kind, cancel := startTestBox(t, fmt.Sprintf(`{"type":"http","server":"127.0.0.1","server_port":%d}`, dead))
	defer closeInstance(inst, cancel)
	res := proveInstance(context.Background(), inst, kind, quickProof("192.0.2.1:443", "192.0.2.2:443"))
	if res.OK {
		t.Fatal("a relay that refuses every connection proved")
	}
	if res.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", res.Attempts)
	}
	if got := res.Category(); got != diagnostics.TCPReset {
		t.Fatalf("category = %s (%+v), want tcp_reset", got, res.Observation)
	}
	if res.Observation.Phase != diagnostics.PhaseReach {
		t.Fatalf("phase = %q, want reach", res.Observation.Phase)
	}
}

// A relay that reaches the far side for nobody: the tunnel opens and
// nothing comes back through it. Not a connect timeout, not a handshake
// failure — and above all not a success.
func TestProveInstance_RelayThatCarriesNothingFails(t *testing.T) {
	proxy, _ := connectProxy(t)
	// The target accepts and never answers the ClientHello.
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	inst, kind, cancel := startTestBox(t, fmt.Sprintf(`{"type":"http","server":"127.0.0.1","server_port":%d}`, proxy.Port))
	defer closeInstance(inst, cancel)
	cfg := quickProof(silent.Addr().String())
	cfg.AttemptTimeout, cfg.Attempts = 400*time.Millisecond, 1
	res := proveInstance(context.Background(), inst, kind, cfg)
	if res.OK {
		t.Fatal("proved a route through which nothing came back")
	}
	if res.Observation.Phase != diagnostics.PhaseCarry || res.Category() != diagnostics.Unknown {
		t.Fatalf("got phase=%q category=%s; the relay answered, so this is neither a connect timeout nor a handshake failure", res.Observation.Phase, res.Category())
	}
}

// silentRelay accepts connections and never answers them: a censor that
// swallows the ClientHello (the end-to-end rig's scenario sni-drop).
func silentRelay(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	t.Cleanup(func() {
		ln.Close()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

const muxedVless = `{"type":"vless","server":"127.0.0.1","server_port":%d,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811",` +
	`"multiplex":{"enabled":true,"protocol":"h2mux","max_streams":64,"padding":true},` +
	`"tls":{"enabled":true,"server_name":"cover.example","insecure":true}}`

// CEN-2, the row the string table cannot get right: a ClientHello that
// is swallowed. The address answers its SYN, so this is
// tls_handshake_failed and must not be filed as a dead address.
//
// The profile is multiplexed on purpose — the vless routes a relay
// mints are — because that is where reading the error literally goes
// wrong: sing-mux retries its session dial on the expired context and
// the error that comes back is "dial tcp …: i/o timeout"
// (timeoutPhaseIsUnknown). Without the reach check this test gets
// tcp_connect_timeout.
func TestProveInstance_SwallowedHelloIsNotADeadAddress(t *testing.T) {
	port := silentRelay(t)
	inst, kind, cancel := startTestBox(t, fmt.Sprintf(muxedVless, port))
	defer closeInstance(inst, cancel)
	if !kind.TLS || kind.UDP {
		t.Fatalf("kind = %+v, want a TLS-over-TCP outbound", kind)
	}
	cfg := quickProof("192.0.2.1:443", "192.0.2.2:443")
	cfg.AttemptTimeout = 500 * time.Millisecond
	res := proveInstance(context.Background(), inst, kind, cfg)
	if res.OK {
		t.Fatal("a relay that never answers the ClientHello proved")
	}
	if got := res.Category(); got != diagnostics.TLSHandshakeFailed {
		t.Fatalf("category = %s (phase %q, %q), want tls_handshake_failed", got, res.Observation.Phase, res.Observation.Message)
	}
}

// The end-to-end rig's finding O-2: Disconnect hung for ~5 s when the relay was
// blackholed, on exactly the families whose profile is multiplexed.
// sing-mux holds its client lock for the whole of a session dial, and
// closing the outbound waits for that lock — so Close waits for a dial
// to a dead address to run out its own timeout. Cancelling the
// instance's context first ends the dial at once; closeInstance does
// that. Remove the cancel and this takes seconds.
func TestCloseInstance_DoesNotWaitForADialToADeadRelay(t *testing.T) {
	port := silentRelay(t)
	inst, _, cancel := startTestBox(t, fmt.Sprintf(muxedVless, port))
	in := pendingRefreshInletForTest()
	if in == nil {
		t.Fatal("no refresh inlet was planned; this test needs an inbound to push a connection through")
	}
	// An app connection in flight: through the inlet, into the mux,
	// stuck in a TLS handshake the relay will never answer.
	app := socks5Open(t, in, "192.0.2.1", 443)
	defer app.Close()
	time.Sleep(200 * time.Millisecond) // let sing-box reach the dial

	done := make(chan struct{})
	t0 := time.Now()
	go func() { _ = closeInstance(inst, cancel); close(done) }()
	select {
	case <-done:
		if d := time.Since(t0); d > time.Second {
			t.Fatalf("closing the instance took %s with a connection stuck on a dead relay", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("closing the instance is still blocked after 3 s: Disconnect would hang exactly when the relay is blocked")
	}
}

func pendingRefreshInletForTest() *RefreshInlet {
	inletMu.Lock()
	defer inletMu.Unlock()
	if inletPending == nil {
		return nil
	}
	cp := *inletPending
	return &cp
}

// socks5Open authenticates to the refresh inlet and sends a CONNECT; it
// does not wait for the reply (there will be none).
func socks5Open(t *testing.T, in *RefreshInlet, ip string, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(in.Host, fmt.Sprint(in.Port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	_, _ = c.Write([]byte{5, 1, 2})
	if _, err := io.ReadFull(c, buf); err != nil || buf[1] != 2 {
		t.Fatalf("inlet did not ask for username/password auth: %v %v", buf, err)
	}
	req := append([]byte{1, byte(len(in.Username))}, in.Username...)
	req = append(append(req, byte(len(in.Password))), in.Password...)
	_, _ = c.Write(req)
	if _, err := io.ReadFull(c, buf); err != nil || buf[1] != 0 {
		t.Fatalf("inlet refused its own credential: %v %v", buf, err)
	}
	_, _ = c.Write(append(append([]byte{5, 1, 0, 1}, net.ParseIP(ip).To4()...), byte(port>>8), byte(port)))
	_ = c.SetDeadline(time.Time{})
	return c
}

func TestKindOfActive(t *testing.T) {
	cases := []struct {
		profile  string
		udp, tls bool
		lazy     bool
	}{
		{`{"type":"vless","server":"203.0.113.10","server_port":443,"tls":{"enabled":true,"reality":{"enabled":true}}}`, false, true, false},
		{`{"type":"vless","server":"203.0.113.10","server_port":443}`, false, false, false},
		{`{"type":"shadowsocks","server":"203.0.113.10","server_port":8446}`, false, false, false},
		{`{"type":"naive","server":"203.0.113.10","server_port":8444}`, false, true, true},
		{`{"type":"anytls","server":"203.0.113.10","server_port":8447}`, false, true, false},
		{`{"type":"hysteria2","server":"203.0.113.10","server_port":443,"tls":{"enabled":true}}`, true, true, false},
		{`{"type":"tuic","server":"203.0.113.10","server_port":8443,"tls":{"enabled":true}}`, true, true, false},
		{`{"type":"wireguard","address":["10.0.0.2/32"]}`, true, false, false},
	}
	for _, c := range cases {
		cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r"}, []byte(c.profile))
		if err != nil {
			t.Fatalf("%s: %v", c.profile, err)
		}
		retireRefreshInlet()
		blob, _ := MarshalSingBox(cfg)
		k := kindFromJSON(blob)
		if k.Type == "" || k.UDP != c.udp || k.TLS != c.tls || k.Lazy != c.lazy {
			t.Errorf("%s → %+v, want udp=%v tls=%v lazy=%v", c.profile, k, c.udp, c.tls, c.lazy)
		}
	}
}
