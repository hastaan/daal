//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/desync"
	"daal/core/routestore"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The config BuildSingBoxConfig writes for a desync route parses in the
// context the engine builds its instances in — and only there: the stock
// include.Context does not know the type (the call-site change).
func TestDesyncConfigParsesInEngineContext(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	row := realityRow("")
	if err := SetRouteDesync(row.RouteID, desync.Strategy{Preset: "sni-cut"}); err != nil {
		t.Fatal(err)
	}
	// Dialer options the route outbound carried move onto the desync
	// outbound, whose options are sing-box's DialerOptions: they parse.
	var ob map[string]any
	_ = json.Unmarshal([]byte(desyncRealityProfile), &ob)
	ob["connect_timeout"] = "5s"
	ob["tcp_keep_alive"] = "30s"
	ob["bind_interface"] = "lo"
	raw := buildForTest(t, row, string(mustJSON(t, ob)))
	if _, ds := activeAndDesync(raw); ds == nil || ds["connect_timeout"] != "5s" {
		t.Fatalf("dialer options not on the desync outbound: %v", ds)
	}
	if route, ok := raw["route"].(map[string]any); ok {
		delete(route, "udp_gated")
	}
	blob := mustJSON(t, raw)
	if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](desync.BoxContext(context.Background()), blob); err != nil {
		t.Fatalf("engine context: %v", err)
	}
	if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](include.Context(context.Background()), blob); err == nil {
		t.Fatal("the stock context parsed a daal-desync outbound")
	}
	if k := kindOfActive(raw); !k.Twin || k.Server != "203.0.113.10" {
		t.Fatalf("kind %+v: the engine's own desync detour must keep the twin and the server", k)
	}
	// And the side instance's view of it (side_singbox.go) builds too.
	merged, _, err := sideConfig(blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](desync.BoxContext(context.Background()), merged); err != nil {
		t.Fatalf("side config: %v", err)
	}
}

// protectCounting is the engine's platform with the protect hook
// observed: what the host's VpnService.protect() would be offered.
type protectCounting struct {
	*androidPlatform
	calls atomic.Int32
	nm    adapter.NetworkManager
}

// Initialize keeps the network manager: a platform pushes its interface
// list into it (UpdateInterfaces), as the host app does on a phone.
func (p *protectCounting) Initialize(nm adapter.NetworkManager) error { p.nm = nm; return nil }

func (p *protectCounting) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *protectCounting) AutoDetectInterfaceControl(int) error        { p.calls.Add(1); return nil }

// splitObservingProxy is connectProxy with the size of every read from
// the client recorded (first connection), so the test can see the cut.
func splitObservingProxy(t *testing.T) (addr *net.TCPAddr, reads func() []int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var sizes []int
	var seen atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			first := seen.Add(1) == 1
			go func(c net.Conn) {
				defer c.Close()
				// Read the CONNECT request by hand (segment by segment),
				// then splice.
				var req []byte
				buf := make([]byte, 4096)
				for !containsCRLFCRLF(req) {
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, err := c.Read(buf)
					if n > 0 {
						req = append(req, buf[:n]...)
						if first {
							mu.Lock()
							sizes = append(sizes, n)
							mu.Unlock()
						}
					}
					if err != nil {
						return
					}
				}
				_ = c.SetReadDeadline(time.Time{})
				host := connectHost(req)
				up, err := net.DialTimeout("tcp", host, 2*time.Second)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr), func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), sizes...)
	}
}

func containsCRLFCRLF(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}

func connectHost(req []byte) string {
	// "CONNECT host:port HTTP/1.1\r\n…"
	var method, host string
	for i, f := 0, 0; i < len(req) && f < 2; f++ {
		j := i
		for j < len(req) && req[j] != ' ' {
			j++
		}
		if f == 0 {
			method = string(req[i:j])
		} else {
			host = string(req[i:j])
		}
		i = j + 1
	}
	if method != "CONNECT" {
		return ""
	}
	return host
}

// A route the ladder turned desync on for: the engine's own config, in
// the engine's own context, with the engine's platform — the connection
// is carried, its first flight left in the strategy's segments, and the
// socket that carried it was offered to protect() (the desync outbound
// dials it; the route's own outbound, detoured, opens none).
func TestDesyncRouteCarriesAndIsProtected(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	proxy, reads := splitObservingProxy(t)

	for _, on := range []bool{true, false} { // on first: the proxy records the first connection's reads
		row := routestore.RouteRow{RouteID: "rt-protect", TransportFamily: "http"}
		ClearAllRouteDesync()
		if on {
			if err := SetRouteDesync(row.RouteID, desync.Strategy{SplitAt: []int{1, 4}, DelayMs: []int{40}, WaitAck: true}); err != nil {
				t.Fatal(err)
			}
		}
		profile := `{"type":"http","tag":"active","server":"127.0.0.1","server_port":` + itoa(proxy.Port) + `}`
		raw := buildForTest(t, row, profile)
		if _, ds := activeAndDesync(raw); (ds != nil) != on {
			t.Fatalf("on=%v: desync outbound present=%v", on, ds != nil)
		}
		route := raw["route"].(map[string]any)
		delete(route, "udp_gated")
		route["auto_detect_interface"] = true // the switch that makes sing-box offer sockets to the platform
		raw["dns"] = defaultDNSBlock()
		blob := mustJSON(t, raw)

		plat := &protectCounting{androidPlatform: newAndroidPlatform()}
		ctx, cancel := context.WithCancel(desync.BoxContext(context.Background()))
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, plat)
		options, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, blob)
		if err != nil {
			cancel()
			t.Fatalf("on=%v: parse: %v", on, err)
		}
		inst, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			cancel()
			t.Fatalf("on=%v: box.New: %v", on, err)
		}
		if err := inst.Start(); err != nil {
			cancel()
			t.Fatalf("on=%v: Start: %v", on, err)
		}
		if plat.nm != nil {
			_ = plat.nm.UpdateInterfaces()
		}
		ob, _ := inst.Outbound().Outbound("active")
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := ob.DialContext(dctx, N.NetworkTCP, M.SocksaddrFromNet(target.Addr()))
		dcancel()
		if err != nil {
			_ = closeInstance(inst, cancel)
			t.Fatalf("on=%v: dial: %v", on, err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = conn.Write([]byte("ping"))
		back := make([]byte, 4)
		_, rerr := io.ReadFull(conn, back)
		_ = conn.Close()
		_ = closeInstance(inst, cancel)
		if rerr != nil || string(back) != "ping" {
			t.Fatalf("on=%v: round trip: %q %v", on, back, rerr)
		}
		if plat.calls.Load() == 0 {
			t.Fatalf("on=%v: the upstream socket was never offered to protect()", on)
		}
		if on {
			got := reads()
			if len(got) < 3 || got[0] != 1 || got[1] != 3 {
				t.Fatalf("the proxy read the CONNECT request in pieces of %v, want 1, 3, …", got)
			}
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// With auto_detect_interface on, sing-box dials "on an interface" from
// the platform's list; the phone's is the uplink, this test's is
// loopback (where its relay is).
func (p *protectCounting) UsePlatformNetworkInterfaces() bool { return true }
func (p *protectCounting) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	return []adapter.NetworkInterface{{
		Interface: control.Interface{Index: lo.Index, MTU: lo.MTU, Name: lo.Name,
			Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}, Flags: lo.Flags},
		Type: C.InterfaceTypeOther,
	}}, nil
}
