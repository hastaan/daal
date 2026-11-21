//go:build singbox

package desync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const testUUID = "11111111-2222-3333-4444-555555555555"

// startBox parses and starts one sing-box instance from a config, in a
// context built the way the engine builds it (BoxContext).
func startBox(t *testing.T, ctx context.Context, cfg map[string]any) *box.Box {
	t.Helper()
	blob, _ := json.Marshal(cfg)
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, blob)
	if err != nil {
		t.Fatalf("option parse: %v", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return inst
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServer answers every connection with what it receives.
func echoServer(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// tap is a TCP forwarder between the client box and the relay that
// records the size of every read from the client side: with the
// strategy's gaps longer than the forwarder's read loop, one read is one
// segment.
type tap struct {
	addr  *net.TCPAddr
	mu    sync.Mutex
	reads [][]byte // client→relay, first connection only
	conns int
}

func newTap(t *testing.T, upstream string) *tap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	tp := &tap{addr: ln.Addr().(*net.TCPAddr)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tp.mu.Lock()
			tp.conns++
			first := tp.conns == 1
			tp.mu.Unlock()
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(c, up); c.Close() }()
				buf := make([]byte, 64<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if first {
							tp.mu.Lock()
							tp.reads = append(tp.reads, append([]byte(nil), buf[:n]...))
							tp.mu.Unlock()
						}
						if _, werr := up.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return tp
}

func (tp *tap) firstReads(n int) [][]byte {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if len(tp.reads) < n {
		n = len(tp.reads)
	}
	return append([][]byte(nil), tp.reads[:n]...)
}

// roundTrip dials the echo target through the client's active outbound
// and checks the bytes come back.
func roundTrip(t *testing.T, client *box.Box, target *net.TCPAddr) {
	t.Helper()
	ob, ok := client.Outbound().Outbound("active")
	if !ok {
		t.Fatal("no active outbound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(target))
	if err != nil {
		t.Fatalf("dial through the outbound: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	msg := []byte("daal desync round trip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, back); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("echo %q, want %q", back, msg)
	}
}

func desyncOutbound(strategy map[string]any) map[string]any {
	return map[string]any{"type": Type, "tag": Tag, "strategy": strategy}
}

// A VLESS outbound (no TLS) with `detour: daal-desync` builds in a
// BoxContext, carries a round trip, and its first flight — the VLESS
// request header plus the first payload — leaves in the segments the
// strategy names.
func TestVLESSThroughDesyncDetour(t *testing.T) {
	target := echoServer(t)
	relayPort := freePort(t)
	startBox(t, BoxContext(context.Background()), map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": relayPort,
			"users": []any{map[string]any{"uuid": testUUID}},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	tp := newTap(t, fmt.Sprintf("127.0.0.1:%d", relayPort))
	client := startBox(t, BoxContext(context.Background()), map[string]any{
		"log": map[string]any{"disabled": true},
		"outbounds": []any{
			map[string]any{"type": "vless", "tag": "active", "server": "127.0.0.1", "server_port": tp.addr.Port,
				"uuid": testUUID, "detour": Tag},
			desyncOutbound(map[string]any{"split_at": []int{1, 5}, "delay_ms": []int{50}, "wait_ack": true}),
		},
	})
	roundTrip(t, client, target)
	reads := tp.firstReads(3)
	if len(reads) < 3 || len(reads[0]) != 1 || len(reads[1]) != 4 {
		t.Fatalf("relay saw first reads of %v bytes, want 1, 4, …", lens(reads))
	}
}

// The stock registry does not know the type: the reason the engine's two
// box-building call sites use BoxContext instead of include.Context.
func TestStockContextRejectsDesyncOutbound(t *testing.T) {
	blob, _ := json.Marshal(map[string]any{"outbounds": []any{desyncOutbound(map[string]any{"preset": "sni-cut"})}})
	if _, err := singjson.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), blob); err == nil {
		t.Fatal("include.Context parsed a daal-desync outbound")
	}
	if _, err := singjson.UnmarshalExtendedContext[option.Options](BoxContext(context.Background()), blob); err != nil {
		t.Fatalf("BoxContext: %v", err)
	}
}

// The outbound's options are as strict as any other sing-box outbound's,
// and a detour of its own is refused.
func TestDesyncOutboundOptionsStrict(t *testing.T) {
	for _, bad := range []map[string]any{
		{"type": Type, "tag": Tag, "strategy": map[string]any{"splitat": []int{1}}},
		{"type": Type, "tag": Tag, "strategy": map[string]any{"preset": "sni-cut"}, "bogus": true},
	} {
		blob, _ := json.Marshal(map[string]any{"outbounds": []any{bad}})
		if _, err := singjson.UnmarshalExtendedContext[option.Options](BoxContext(context.Background()), blob); err == nil {
			t.Errorf("parsed %v", bad)
		}
	}
	ctx := BoxContext(context.Background())
	for _, cfg := range []map[string]any{
		{"type": Type, "tag": Tag, "detour": "direct", "strategy": map[string]any{"preset": "sni-cut"}},
		{"type": Type, "tag": Tag, "strategy": map[string]any{"preset": "no-such-preset"}},
	} {
		blob, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true},
			"outbounds": []any{cfg, map[string]any{"type": "direct", "tag": "direct"}}})
		options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, blob)
		if err != nil {
			continue // refused at parse: fine too
		}
		if inst, err := box.New(box.Options{Context: ctx, Options: options}); err == nil {
			_ = inst.Close()
			t.Errorf("box.New accepted %v", cfg)
		} else if !strings.Contains(err.Error(), "detour") && !strings.Contains(err.Error(), "preset") {
			t.Errorf("box.New refused %v for another reason: %v", cfg, err)
		}
	}
}
