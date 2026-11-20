package mgmt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"daal/publisher/deploy/cloudflare"
)

func cdnTestFront(t *testing.T) *cloudflare.FrontRecord {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org"},
		DNSNames:  []string{"example.org", "*.example.org"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	mat, err := cloudflare.NewAOPMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return &cloudflare.FrontRecord{
		EdgeRanges:       []string{"173.245.48.0/20", "2400:cb00::/32"},
		Hostname:         "door.example.org",
		OriginPath:       "/0123456789abcdef0123456789abcdef",
		OriginCACertPath: write("c.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		OriginCAPrivPath: write("c.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})),
		AOPCACertPath:    write("ca.pem", mat.CACertPEM),
	}
}

type fakeDoorBox struct {
	pub       ed25519.PublicKey
	caps      string
	calls     atomic.Int32
	lastBody  []byte
	answer    func(req cloudflare.DoorRequest) (int, string)
	noCDNPath bool
}

func (b *fakeDoorBox) mux(t *testing.T) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(b.caps))
	})
	if b.noCDNPath {
		return mux
	}
	mux.HandleFunc("/cdn", func(w http.ResponseWriter, r *http.Request) {
		b.calls.Add(1)
		if op, ok := boxVerifies(b.pub, r); !ok || op != "cdn" || r.Method != http.MethodPost {
			http.Error(w, "bad token", 401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		b.lastBody = body
		var req cloudflare.DoorRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "decode", 400)
			return
		}
		code, out := b.answer(req)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(out))
	})
	return mux
}

func TestCDNDoorEnable_SignedAndChecked(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	front := cdnTestFront(t)
	box := &fakeDoorBox{pub: pub, caps: `{"ok":true,"capabilities":["cdn"]}`,
		answer: func(req cloudflare.DoorRequest) (int, string) {
			if len(req.EdgeRanges) != 2 {
				return 400, "no edge ranges"
			}
			return 200, `{"action":"enable","enabled":true,"changed":true,"port":8448,"ws_path":"` + req.WSPath + `","users":2,"box_firewall_rules":2}`
		}}
	ts, fp := startTLSServer(t, box.mux(t))
	rec := recForServer(t, ts, fp)
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cli.CDNDoorEnable(context.Background(), rec, priv, front)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !got.Enabled || got.Users != 2 || got.WSPath != front.OriginPath {
		t.Fatalf("got %+v", got)
	}
	if !strings.Contains(string(box.lastBody), `"origin_key_pem"`) || !strings.Contains(string(box.lastBody), `"action":"enable"`) {
		t.Fatalf("body sent = %s", box.lastBody)
	}

	// A relay that opened its door behind no box-firewall rule is a
	// failure: Cloudflare could never reach it.
	box.answer = func(req cloudflare.DoorRequest) (int, string) {
		return 200, `{"action":"enable","enabled":true,"port":8448,"ws_path":"` + req.WSPath + `","users":2}`
	}
	if _, err := cli.CDNDoorEnable(context.Background(), rec, priv, front); err == nil {
		t.Fatal("an enable that opened no box-firewall rule was accepted")
	}

	// An answer about another door is a failure.
	box.answer = func(req cloudflare.DoorRequest) (int, string) {
		return 200, `{"action":"enable","enabled":true,"port":8448,"ws_path":"/other","users":2}`
	}
	if _, err := cli.CDNDoorEnable(context.Background(), rec, priv, front); err == nil {
		t.Fatal("an enable answered for another path was accepted")
	}

	box.answer = func(req cloudflare.DoorRequest) (int, string) {
		if req.Action != "disable" || req.OriginKeyPEM != "" {
			return 400, "bad"
		}
		return 200, `{"action":"disable","enabled":false,"changed":true,"users":0}`
	}
	if _, err := cli.CDNDoorDisable(context.Background(), rec, priv); err != nil {
		t.Fatalf("disable: %v", err)
	}
	box.answer = func(req cloudflare.DoorRequest) (int, string) {
		return 200, `{"action":"disable","enabled":true,"users":1}`
	}
	if _, err := cli.CDNDoorDisable(context.Background(), rec, priv); err == nil {
		t.Fatal("a disable that left the door open was accepted")
	}
}

// The key is never sent to a box that does not advertise the door,
// and a box without the route answers ErrCDNDoorUnsupported.
func TestCDNDoorEnable_OldBoxGetsNothing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	front := cdnTestFront(t)
	box := &fakeDoorBox{pub: pub, caps: `{"ok":true,"capabilities":["tuic-users"]}`,
		answer: func(cloudflare.DoorRequest) (int, string) { return 200, `{"enabled":true}` }}
	ts, fp := startTLSServer(t, box.mux(t))
	rec := recForServer(t, ts, fp)
	cli, _ := NewClient(rec)
	if _, err := cli.CDNDoorEnable(context.Background(), rec, priv, front); !errors.Is(err, ErrCDNDoorUnsupported) {
		t.Fatalf("err = %v, want ErrCDNDoorUnsupported", err)
	}
	if box.calls.Load() != 0 {
		t.Fatal("door material was sent to a box that does not advertise the door")
	}

	old := &fakeDoorBox{pub: pub, caps: `{"ok":true}`, noCDNPath: true}
	ts2, fp2 := startTLSServer(t, old.mux(t))
	rec2 := recForServer(t, ts2, fp2)
	cli2, _ := NewClient(rec2)
	if _, err := cli2.CDNDoorDisable(context.Background(), rec2, priv); !errors.Is(err, ErrCDNDoorUnsupported) {
		t.Fatalf("disable on an old box: %v, want ErrCDNDoorUnsupported", err)
	}
}
