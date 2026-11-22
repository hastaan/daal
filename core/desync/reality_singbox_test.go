//go:build singbox && with_utls

package desync

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

const realitySNI = "www.cover-host.example"

// realityWorld is a REALITY relay on loopback: a TLS 1.3 "cover" site
// the relay hands unauthenticated handshakes to, a vless+REALITY inbound,
// and a tap in front of it that sees the client's segments.
type realityWorld struct {
	target *net.TCPAddr
	tap    *tap
	pub    string
}

func newRealityWorld(t *testing.T) *realityWorld {
	t.Helper()
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	cover.StartTLS()
	t.Cleanup(cover.Close)
	coverAddr := cover.Listener.Addr().(*net.TCPAddr)

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv := base64.RawURLEncoding.EncodeToString(key.Bytes())
	pub := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())

	relayPort := freePort(t)
	startBox(t, BoxContext(context.Background()), map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": relayPort,
			"users": []any{map[string]any{"uuid": testUUID, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{
				"enabled": true, "server_name": realitySNI,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": "127.0.0.1", "server_port": coverAddr.Port},
					"private_key": priv,
					"short_id":    []any{"deadbeef"},
				},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	return &realityWorld{target: echoServer(t), tap: newTap(t, fmt.Sprintf("127.0.0.1:%d", relayPort)), pub: pub}
}

func (w *realityWorld) client(t *testing.T, strategy map[string]any) {
	t.Helper()
	client := startBox(t, BoxContext(context.Background()), map[string]any{
		"log": map[string]any{"disabled": true},
		"outbounds": []any{
			map[string]any{
				"type": "vless", "tag": "active", "server": "127.0.0.1", "server_port": w.tap.addr.Port,
				"uuid": testUUID, "flow": "xtls-rprx-vision", "detour": Tag,
				"tls": map[string]any{
					"enabled": true, "server_name": realitySNI,
					"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
					"reality": map[string]any{"enabled": true, "public_key": w.pub, "short_id": "deadbeef"},
				},
			},
			desyncOutbound(strategy),
		},
	})
	roundTrip(t, client, w.target)
}

// The headline of plan T2: a vless-reality outbound with detour
// daal-desync builds, completes its REALITY handshake through a relay
// and carries a round trip — and the hello left in three segments, the
// first two of which together do not hold the cover name.
func TestRealityThroughDesyncSNICut(t *testing.T) {
	w := newRealityWorld(t)
	w.client(t, map[string]any{"split_at": []int{1}, "sni_cut": true, "wait_ack": true, "delay_ms": []int{50}})
	reads := w.tap.firstReads(3)
	if len(reads) < 3 || len(reads[0]) != 1 {
		t.Fatalf("relay saw first reads of %v bytes, want 1, …", lens(reads))
	}
	firstTwo := append(append([]byte(nil), reads[0]...), reads[1]...)
	if bytes.Contains(firstTwo, []byte(realitySNI)) {
		t.Fatal("the first two segments together hold the whole cover name")
	}
	if !bytes.Contains(firstTwo, []byte(realitySNI[:len(realitySNI)/2])) {
		t.Fatal("the second segment does not end inside the cover name")
	}
	hello := bytes.Join(reads, nil)
	if _, ok := parseRecord(hello); !ok {
		t.Fatalf("the first three segments are not one whole record (%v bytes)", lens(reads))
	}
}

// The chain preset: many small segments, no ACK wait.
func TestRealityThroughDesyncChain(t *testing.T) {
	w := newRealityWorld(t)
	w.client(t, map[string]any{"preset": "chain"})
}

// The hello in two TLS records, split mid-name: REALITY's server (a fork
// of crypto/tls) reassembles a handshake message across records.
func TestRealityThroughDesyncRecordSplit(t *testing.T) {
	w := newRealityWorld(t)
	w.client(t, map[string]any{"preset": "tlsrec-sni"})
}
