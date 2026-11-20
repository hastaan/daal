//go:build singbox && with_naive_outbound && with_purego

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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Can a naive route be proved in a side instance BESIDE a running naive
// tunnel? Real Cronet (libcronet.so, loaded at run time: run with
// LD_LIBRARY_PATH pointing at a directory holding it, e.g.
// test-rigs/worldbox/bin), real sing-box naive inbounds on loopback.
//
// This is the evidence behind the decision written in side.go
// (sideProbeTypes / cronetSideTypes): the survey may prove naive beside
// the tunnel; a race may not. It needs the naive tag set and the
// library, so `./daal test` (tags singbox only) does not run it.

// naiveCA is a throwaway CA and a leaf for 127.0.0.1 / localhost signed
// by it. Cronet takes the CA as its trusted root (tls.certificate).
func naiveCA(t *testing.T) (caPEM, certPath, keyPath string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "daal test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600)
	kb, _ := x509.MarshalECPrivateKey(leafKey)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), certPath, keyPath
}

// naiveServer starts a sing-box naive inbound on loopback that dials
// everything direct, and returns its port.
func naiveServer(t *testing.T, certPath, keyPath string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"naive","tag":"in","listen":"127.0.0.1","listen_port":%d,
		"users":[{"username":"u","password":"p"}],
		"tls":{"enabled":true,"server_name":"localhost","certificate_path":%q,"key_path":%q}}],
		"outbounds":[{"type":"direct","tag":"direct"}]}`, port, certPath, keyPath)
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, []byte(cfg))
	if err != nil {
		cancel()
		t.Fatalf("server options: %v", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatalf("server box.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		cancel()
		t.Fatalf("server Start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close(); cancel() })
	return port
}

func naiveProfile(port int, caPEM string) string {
	ca, _ := json.Marshal(caPEM)
	return fmt.Sprintf(`{"type":"naive","server":"127.0.0.1","server_port":%d,"username":"u","password":"p",
		"tls":{"enabled":true,"server_name":"localhost","certificate":[%s]}}`, port, ca)
}

func TestNaiveSideProbe_BesideARunningNaiveTunnel(t *testing.T) {
	loadCronet()
	if attempted, ok := CronetStatus(); !attempted || !ok {
		t.Skip("libcronet.so not loadable here (set LD_LIBRARY_PATH to a directory holding it)")
	}
	caPEM, certPath, keyPath := naiveCA(t)
	portA := naiveServer(t, certPath, keyPath)
	portB := naiveServer(t, certPath, keyPath)
	target := tlsTarget(t)
	echo := echoServer(t)
	proof := ProofConfig{Targets: []string{target}, AttemptTimeout: 5 * time.Second, Attempts: 2, SlowAfter: 4 * time.Second}

	s := runningDriver(t, naiveProfile(portA, caPEM))
	if res := s.Prove(context.Background(), proof); !res.OK {
		t.Fatalf("premise: the naive tunnel does not carry: %+v (%v)", res, res.Err)
	}
	instA := s.instance
	ob, _ := instA.Outbound().Outbound(activeTag)
	app, err := ob.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", uint16(echo.Port)))
	if err != nil {
		t.Fatalf("premise: no connection through the naive tunnel: %v", err)
	}
	defer app.Close()
	roundTrip := func(when string) {
		t.Helper()
		_ = app.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := app.Write([]byte("ping\n")); err != nil {
			t.Fatalf("%s: the connection through the tunnel is dead: %v", when, err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(app, buf); err != nil || string(buf) != "ping\n" {
			t.Fatalf("%s: the connection through the tunnel no longer carries: %q %v", when, buf, err)
		}
	}
	roundTrip("before")

	cfgB := sideCfgFor(t, "naive", naiveProfile(portB, caPEM))
	// A race may still not.
	if s.CanSideProbe(cfgB) {
		t.Fatal("naive is side-probeable for a race")
	}
	if _, err := s.SideProbe(context.Background(), cfgB, proof); !errors.Is(err, ErrSideProbeUnsupported) {
		t.Fatalf("a side probe of naive without SideCronet: err = %v", err)
	}
	if !s.CanSurveyProbe(cfgB) {
		t.Fatal("naive is not survey-probeable with Cronet loaded")
	}
	proof.SideCronet = true
	// The probe really goes to B: with nothing at B's port it fails.
	dead := sideCfgFor(t, "naive", naiveProfile(1, caPEM))
	if res, err := s.SideProbe(context.Background(), dead, proof); err != nil || res.OK {
		t.Fatalf("a side probe of a dead naive relay proved: %+v err=%v", res, err)
	}
	roundTrip("after a failed side probe")
	fdsBefore := openFDs(t)
	startedBefore, closedBefore := sideInstancesStarted.Load(), sideInstancesClosed.Load()
	for i := 0; i < 5; i++ {
		t0 := time.Now()
		res, err := s.SideProbe(context.Background(), cfgB, proof)
		if err != nil || !res.OK {
			t.Fatalf("side probe %d of a working naive route: %+v err=%v", i+1, res, err)
		}
		t.Logf("side probe %d proved in %s", i+1, time.Since(t0).Round(time.Millisecond))
		roundTrip(fmt.Sprintf("after side probe %d", i+1))
	}
	// Two at once, and one stopped half-way.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := s.SideProbe(ctx, cfgB, proof)
			done <- err
		}()
	}
	time.Sleep(30 * time.Millisecond)
	cancel()
	for i := 0; i < 2; i++ {
		<-done
	}
	roundTrip("after two stopped side probes")
	if s.instance != instA {
		t.Fatal("a side probe replaced the tunnel's instance")
	}
	if res := s.Prove(context.Background(), proof); !res.OK {
		t.Fatalf("the naive tunnel stopped proving after side probes: %+v (%v)", res, res.Err)
	}
	if st, cl := sideInstancesStarted.Load()-startedBefore, sideInstancesClosed.Load()-closedBefore; st != cl {
		t.Fatalf("%d side instances started, %d closed", st, cl)
	}
	if n := s.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d side probes in flight", n)
	}
	if got, ok := settles(func() int { return openFDs(t) }, fdsBefore); !ok {
		t.Fatalf("%d file descriptors after the side probes, %d before", got, fdsBefore)
	}
}
