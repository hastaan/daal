package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// `wb inet` is the rest of the internet that a relay needs to exist:
//
//   - a DNS resolver (DNSIP:53/udp). Every name resolves to CoverIP except
//     the two the lab hosts itself. A REALITY relay resolves its cover
//     host before it can answer ANY handshake, so without this the relay
//     is dead in a way a real one never is.
//   - "every HTTPS site" (CoverIP:443): a TLS 1.3 server that presents a
//     certificate for whatever SNI it is asked for. This is what REALITY
//     borrows a handshake from, and what an unauthenticated prober of the
//     relay must be shown.
//
// Queries and SNIs are logged (logs/inet.log) so a scenario can assert on
// what the relay asked the outside world.

func cmdInet(args []string) int {
	fs := flag.NewFlagSet("inet", flag.ExitOnError)
	run := fs.String("run-dir", "", "")
	_ = fs.Parse(args)

	caCert, caKey, err := loadCA(*run)
	if err != nil {
		log.Fatalf("inet: %v", err)
	}
	go serveDNS()

	var mu sync.Mutex
	cache := map[string]*tls.Certificate{}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = "cover.invalid"
			}
			mu.Lock()
			defer mu.Unlock()
			if c, ok := cache[name]; ok {
				return c, nil
			}
			log.Printf("cover: handshake for SNI %q from %s", name, hello.Conn.RemoteAddr())
			c, err := mintLeaf(caCert, caKey, name)
			if err == nil {
				cache[name] = c
			}
			return c, err
		},
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort(CoverIP, "443"), cfg)
	if err != nil {
		log.Fatalf("inet: cover: %v", err)
	}
	fmt.Println("inet: listening")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><h1>%s</h1><p>an ordinary website</p></body></html>\n", r.Host)
	})}
	log.Fatal(srv.Serve(ln))
	return 1
}

func loadCA(run string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(filepath.Join(run, "lab-ca.pem"))
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(filepath.Join(run, "lab-ca.key"))
	if err != nil {
		return nil, nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, nil, fmt.Errorf("lab CA files are not PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	return cert, key, err
}

func mintLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}, nil
}

// serveDNS answers A queries: the lab's own two names get their lab
// addresses, everything else is "some website" at CoverIP. AAAA and
// every other type get an empty NOERROR answer (this world is IPv4-only).
func serveDNS() {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(DNSIP, "53"))
	if err != nil {
		log.Fatalf("inet: dns: %v", err)
	}
	special := map[string]string{"api.hetzner.cloud.": CloudIP, "github.com.": MirrorIP}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := buf[:n]
		if n < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
			continue
		}
		// parse the single question
		var labels []string
		i := 12
		for i < n && q[i] != 0 {
			l := int(q[i])
			if l > 63 || i+1+l > n {
				labels = nil
				break
			}
			labels = append(labels, string(q[i+1:i+1+l]))
			i += 1 + l
		}
		if i+5 > n {
			continue
		}
		qtype := binary.BigEndian.Uint16(q[i+1 : i+3])
		qend := i + 5
		name := strings.ToLower(strings.Join(labels, ".")) + "."
		resp := append([]byte{}, q[:qend]...)
		resp[2] = 0x84 | (q[2] & 0x01) // QR, AA, copy RD
		resp[3] = 0x80                 // RA, NOERROR
		binary.BigEndian.PutUint16(resp[6:8], 0)
		binary.BigEndian.PutUint16(resp[8:10], 0)
		binary.BigEndian.PutUint16(resp[10:12], 0)
		if qtype == 1 {
			ip := CoverIP
			if v, ok := special[name]; ok {
				ip = v
			}
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			resp = append(resp, net.ParseIP(ip).To4()...)
			log.Printf("dns: A %s → %s (asked by %s)", name, ip, from)
		}
		_, _ = pc.WriteTo(resp, from)
	}
}
