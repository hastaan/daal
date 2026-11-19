//go:build singbox

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"daal/core/diagnostics"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// A real relay for the tests below: the linked sing-box serving trojan
// over TLS with multiplexing, the shape of a route that HOLDS A SESSION
// — which is what makes a mid-session block look different from a
// failed connect.

func pemLines(typ string, der []byte) []string {
	return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))), "\n")
}

func startRelayBox(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"},
		DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "trojan", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
			"users":     []any{map[string]any{"name": "u", "password": "pw"}},
			"tls":       map[string]any{"enabled": true, "server_name": "relay.test", "certificate": pemLines("CERTIFICATE", certDER), "key": pemLines("PRIVATE KEY", keyDER)},
			"multiplex": map[string]any{"enabled": true},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	body, _ := json.Marshal(cfg)
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, body)
	if err != nil {
		cancel()
		t.Fatalf("relay options: %v", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatalf("relay box.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		cancel()
		t.Fatalf("relay Start: %v", err)
	}
	t.Cleanup(func() { cancel(); _ = inst.Close() })
	return port
}

// censorHop forwards TCP to the relay until block() is called. From
// then on it behaves as a filter that swallows the route: connections
// already open stop moving in both directions (not reset — silence),
// and a new one has its SYN answered and nothing after.
type censorHop struct {
	port    int
	blocked atomic.Bool
	mu      sync.Mutex
	conns   []net.Conn
}

func (c *censorHop) block() { c.blocked.Store(true) }

func startCensorHop(t *testing.T, relayPort int) *censorHop {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &censorHop{port: ln.Addr().(*net.TCPAddr).Port}
	t.Cleanup(func() {
		ln.Close()
		h.mu.Lock()
		for _, c := range h.conns {
			c.Close()
		}
		h.mu.Unlock()
	})
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if h.blocked.Load() {
				// Swallow: keep reading so the sender sees an open,
				// silent connection, and forward nothing.
				if err != nil {
					return
				}
				continue
			}
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
			if h.blocked.Load() {
				go io.Copy(io.Discard, c)
				continue
			}
			up, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort))
			if err != nil {
				c.Close()
				continue
			}
			h.mu.Lock()
			h.conns = append(h.conns, up)
			h.mu.Unlock()
			go pump(up, c)
			go pump(c, up)
		}
	}()
	return h
}

const muxedTrojan = `{"type":"trojan","server":"127.0.0.1","server_port":%d,"password":"pw",` +
	`"multiplex":{"enabled":true,"protocol":"h2mux","max_streams":64},` +
	`"tls":{"enabled":true,"server_name":"relay.test","insecure":true}}`

// silentTarget accepts and never answers: the far side of a relay whose
// way out is a black hole.
func silentTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// THE defect behind "a mid-session block is recorded as unknown": the
// route is connected and holds a multiplexed session; a filter then
// starts swallowing it. The route's own outbound answers the next dial
// from that session, so all the check sees through it is "a connection,
// then nothing" — the carry phase, `unknown`. Asked again on a fresh
// connection the answer is the one a connect would get: the address
// answers its SYN and the ClientHello is swallowed.
func TestProveSubject_MidSessionBlockIsClassifiedLikeAFailedConnect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	hop := startCensorHop(t, startRelayBox(t))
	sub, cancel := startTestSubject(t, fmt.Sprintf(muxedTrojan, hop.port))
	defer closeInstance(sub.inst, cancel)
	if !sub.kind.Twin || !sub.kind.HandshakeAtDial || sub.twin == nil {
		t.Fatalf("kind = %+v twin=%v; this route must be diagnosable", sub.kind, sub.twin != nil)
	}
	cfg := quickProof(target.Listener.Addr().String())
	cfg.AttemptTimeout = 600 * time.Millisecond
	if res := sub.prove(context.Background(), cfg); !res.OK {
		t.Fatalf("the route did not connect before the block: %+v (%v)", res, res.Err)
	}

	hop.block()

	// What the route's own outbound says, with no fresh connection to
	// ask: the session it holds hands over a stream and nothing comes
	// back. This is the "unknown" that was recorded.
	blind := proofSubject{inst: sub.inst, kind: sub.kind}
	if res := blind.prove(context.Background(), cfg); res.OK || res.Category() != diagnostics.Unknown ||
		res.Observation.Phase != diagnostics.PhaseCarry {
		t.Fatalf("premise: without a fresh connection the block should read carry/unknown, got %s phase=%q (%v)",
			res.Category(), res.Observation.Phase, res.Err)
	}

	res := sub.prove(context.Background(), cfg)
	if res.OK {
		t.Fatal("a swallowed route proved")
	}
	if got := res.Category(); got != diagnostics.TLSHandshakeFailed {
		t.Fatalf("mid-session block classified %s (phase %q: %s); a connect through the same filter is tls_handshake_failed",
			got, res.Observation.Phase, proofText(res))
	}
	if n := len(sub.inst.Outbound().Outbounds()); n != outboundsOf(t, sub) {
		t.Fatalf("the diagnostic outbound was left behind: %d outbounds", n)
	}
}

func proofText(res ProofResult) string {
	out := ""
	for i, o := range res.Failed {
		out += fmt.Sprintf("[%d %s: %s] ", i+1, o.Phase, o.Message)
	}
	return out
}

// outboundsOf: how many outbounds the instance has with no twin open.
func outboundsOf(t *testing.T, sub proofSubject) int {
	t.Helper()
	n := 0
	for _, ob := range sub.inst.Outbound().Outbounds() {
		if !strings.HasPrefix(ob.Tag(), activeTag+"-check-") {
			n++
		}
	}
	return n
}

// A relay that answers its handshake and reaches nothing beyond itself
// is "the relay has no internet" — not a route failure, not `unknown`
// (backlog TW-14). Three far-side hosts stay silent through a relay that
// has just completed a fresh handshake with this device.
func TestProveSubject_RelayThatReachesNothingIsRelayNoEgress(t *testing.T) {
	relay := startRelayBox(t)
	sub, cancel := startTestSubject(t, fmt.Sprintf(muxedTrojan, relay))
	defer closeInstance(sub.inst, cancel)
	cfg := quickProof(silentTarget(t), silentTarget(t), silentTarget(t))
	cfg.AttemptTimeout = 500 * time.Millisecond
	res := sub.prove(context.Background(), cfg)
	if res.OK {
		t.Fatal("proved through a relay that reaches nothing")
	}
	if got := res.Category(); got != diagnostics.RelayNoEgress {
		t.Fatalf("category = %s (%s), want relay_no_egress", got, proofText(res))
	}
	if res.Attempts != 3 || res.Extended {
		t.Fatalf("attempts=%d extended=%v; want the two ordinary attempts and one on a fresh connection", res.Attempts, res.Extended)
	}
	// One far-side host answering is enough: the relay has a way out.
	live := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer live.Close()
	cfg.Targets = []string{silentTarget(t), live.Listener.Addr().String()}
	seen := false
	for i := 0; i < 8 && !seen; i++ {
		r := sub.prove(context.Background(), cfg)
		if !r.OK {
			t.Fatalf("a relay that reaches one of two hosts did not prove: %s", proofText(r))
		}
		seen = r.Attempts == 2
	}
}

// slowHop delays everything that comes back toward the client — the
// relay's handshake answer by `first`, every later read by `each` — as a
// queue does. Nothing is dropped.
func slowHop(t *testing.T, relayPort int, first, each time.Duration) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				up, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort))
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				buf := make([]byte, 32<<10)
				wait := first
				for {
					n, err := up.Read(buf)
					if n > 0 {
						time.Sleep(wait)
						wait = each
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// CEN-O5: behind seconds of queue the ordinary attempts finish nothing.
// The relay's answer took over a second to arrive — a slow path, not a
// swallowed handshake — so the proof makes its long attempt, connects,
// and says "slow". Before: `unknown` or tls_handshake_failed, "could not
// connect", and 5–30 minutes of cooldown.
func TestProveSubject_SlowPathConnectsSlowInsteadOfFailing(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	// No multiplexing: every attempt opens its own connection and pays
	// the delay again, which is the case that never finished.
	plain := `{"type":"trojan","server":"127.0.0.1","server_port":%d,"password":"pw","tls":{"enabled":true,"server_name":"relay.test","insecure":true}}`
	sub, cancel := startTestSubject(t, fmt.Sprintf(plain, slowHop(t, startRelayBox(t), 1100*time.Millisecond, 700*time.Millisecond)))
	defer closeInstance(sub.inst, cancel)
	cfg := ProofConfig{Targets: []string{target.Listener.Addr().String()},
		AttemptTimeout: 1500 * time.Millisecond, Attempts: 2, SlowAfter: time.Second, SlowBudget: 8 * time.Second}
	res := sub.prove(context.Background(), cfg)
	if !res.OK {
		t.Fatalf("a slow path was called dead: %s — %s", res.Category(), proofText(res))
	}
	if !res.Slow || !res.Extended {
		t.Fatalf("slow=%v extended=%v after %s; want connected-and-slow by the long attempt", res.Slow, res.Extended, res.Elapsed)
	}
}

// The other half: a relay that swallows the handshake at once is still
// a failure in attempts × attempt_timeout. Nothing was seen moving, so
// there is no long attempt to wait through.
func TestProveSubject_SwallowedHelloGetsNoLongAttempt(t *testing.T) {
	sub, cancel := startTestSubject(t, fmt.Sprintf(muxedTrojan, silentRelay(t)))
	defer closeInstance(sub.inst, cancel)
	cfg := ProofConfig{Targets: []string{"192.0.2.1:443", "192.0.2.2:443"},
		AttemptTimeout: 500 * time.Millisecond, Attempts: 2, SlowAfter: 300 * time.Millisecond, SlowBudget: 30 * time.Second}
	t0 := time.Now()
	res := sub.prove(context.Background(), cfg)
	if res.OK || res.Extended {
		t.Fatalf("got ok=%v extended=%v", res.OK, res.Extended)
	}
	if got := res.Category(); got != diagnostics.TLSHandshakeFailed {
		t.Fatalf("category = %s (%s), want tls_handshake_failed", got, proofText(res))
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("a dead route took %s to fail", d)
	}
}

// tallyHop forwards TCP to the relay and keeps, per connection, how
// many bytes the CLIENT sent on it. A connection that was opened and
// closed with nothing sent is what a port scanner makes; none of the
// families' own connections look like that.
type tallyHop struct {
	port int
	mu   sync.Mutex
	sent []*atomic.Int64
}

// empty: connections on which the client never sent a byte.
func (h *tallyHop) empty() (empty, total int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.sent {
		if n.Load() == 0 {
			empty++
		}
	}
	return empty, len(h.sent)
}

func startTallyHop(t *testing.T, relayPort int) *tallyHop {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &tallyHop{port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := &atomic.Int64{}
			h.mu.Lock()
			h.sent = append(h.sent, n)
			h.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				up, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort))
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(c, up)
				buf := make([]byte, 32<<10)
				for {
					k, err := c.Read(buf)
					if k > 0 {
						n.Add(int64(k))
						if _, werr := up.Write(buf[:k]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return h
}

// A liveness check that fails in the CARRY phase on a family that dials
// eagerly (the relay's way out is slow or down for a moment: the common
// mid-session failure) must not put a bare connect-and-close to the
// relay's port on the wire. The error gives that timeout's phase, so
// the reach check has nothing to settle, and its one other answer — the
// path is slow — is already measured on the family's own connections
// (how long the dial took, whether bytes came back). The check repeats
// every RecheckInterval while the route is failed; an empty connection
// each time is a scanner's pattern, to the relay, in front of the
// censor.
func TestProveSubject_CarryTimeoutMakesNoBareConnectToTheRelay(t *testing.T) {
	live := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer live.Close()
	hop := startTallyHop(t, startRelayBox(t))
	sub, cancel := startTestSubject(t, fmt.Sprintf(muxedTrojan, hop.port))
	defer closeInstance(sub.inst, cancel)
	if sub.kind.Lazy || sub.kind.UDP || sub.kind.Server != "127.0.0.1" || sub.kind.ServerPort == 0 {
		t.Fatalf("kind = %+v; this must be an eager TCP route the reach check could dial", sub.kind)
	}
	cfg := quickProof(live.Listener.Addr().String())
	cfg.AttemptTimeout = 500 * time.Millisecond
	if res := sub.prove(context.Background(), cfg); !res.OK {
		t.Fatalf("the route did not connect: %s", proofText(res))
	}

	// The relay stops reaching anything. Both shapes of the check: the
	// route's own outbound alone, and with the fresh connection the
	// driver adds.
	cfg.Targets = []string{silentTarget(t), silentTarget(t), silentTarget(t)}
	for _, s := range []proofSubject{{inst: sub.inst, kind: sub.kind}, sub} {
		res := s.prove(context.Background(), cfg)
		if res.OK {
			t.Fatal("proved through a relay that reaches nothing")
		}
		for i, o := range res.Failed {
			if !o.Timeout || o.Phase != diagnostics.PhaseCarry {
				t.Fatalf("premise: attempt %d should be a carry-phase timeout, got phase %q (%s)", i+1, o.Phase, o.Message)
			}
		}
	}
	// A bare connect is closed as soon as it is answered; give the hop
	// a moment to have accepted it.
	time.Sleep(300 * time.Millisecond)
	if empty, total := hop.empty(); empty != 0 {
		t.Fatalf("%d of %d connections to the relay's port carried nothing: a carry-phase timeout started the bare reach check", empty, total)
	}
}
