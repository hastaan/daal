package share

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultListen binds an HTTPS server to each supplied private address on
// a random high port. The server serves exactly one resource:
//
//	GET /bundle.sbp           Authorization: Bearer <token>
//
// All other requests get 404. Cert is freshly self-signed per session; the
// receiver pins its SPKI hash from the mDNS TXT record.
//
// The returned `urls` are full https://addr:port/<token-suffix> URLs that
// are convenient to render as a fallback QR for mDNS-filtered networks.
func defaultListen(addrs []string, token string, body []byte) ([]string, func(), error) {
	if len(addrs) == 0 {
		return nil, nil, errors.New("share: no addrs")
	}
	cert, _, err := generateSelfSignedCert(addrs)
	if err != nil {
		return nil, nil, err
	}

	var (
		urls   []string
		stops  []func()
		mu     sync.Mutex
		closed bool
	)

	for _, addr := range addrs {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		go serveLoop(tlsLn, token, body)
		stops = append(stops, func() {
			mu.Lock()
			defer mu.Unlock()
			if closed {
				return
			}
			tlsLn.Close()
		})
		urls = append(urls, fmt.Sprintf("https://%s/bundle.sbp", net.JoinHostPort(addr, strconv.Itoa(port))))
	}
	if len(urls) == 0 {
		return nil, nil, errors.New("share: failed to bind any address")
	}
	stop := func() {
		mu.Lock()
		closed = true
		mu.Unlock()
		for _, s := range stops {
			s()
		}
	}
	return urls, stop, nil
}

// defaultAdvertise is the mDNS publisher. We emit a TXT record with the
// SPKI hash so the receiver can pin the cert without trusting any CA.
//
// Phase 1C ships a stub that doesn't publish anything (the manager treats
// a nil mDNS as "the receiver must use the QR-encoded URL fallback"). The
// real mDNS publisher lives in lan_sender_mdns.go behind the `mdns` build
// tag and depends on golang.org/x/net/dns/dnsmessage.
func defaultAdvertise(serviceName string, port int, txt map[string]string) (func(), error) {
	return func() {}, nil
}

func serveLoop(ln net.Listener, token string, body []byte) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConn(conn, token, body)
	}
}

func handleConn(conn net.Conn, token string, body []byte) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	req := string(buf[:n])
	// Very small HTTP/1.1 parser — we only support GET /bundle.sbp.
	lines := strings.Split(req, "\r\n")
	if len(lines) == 0 {
		return
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 || parts[0] != "GET" {
		writeHTTP(conn, 405, "method not allowed", nil)
		return
	}
	if !strings.HasPrefix(parts[1], "/bundle.sbp") {
		writeHTTP(conn, 404, "not found", nil)
		return
	}
	authOK := false
	for _, l := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(l), "authorization:") {
			val := strings.TrimSpace(l[len("authorization:"):])
			if strings.HasPrefix(val, "Bearer ") {
				if hmac_eq(val[len("Bearer "):], token) {
					authOK = true
				}
			}
		}
	}
	if !authOK {
		writeHTTP(conn, 401, "unauthorized", nil)
		return
	}
	writeHTTP(conn, 200, "ok", body)
}

func writeHTTP(w io.Writer, status int, reason string, body []byte) {
	hdr := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: application/vnd.daal.sbp\r\nConnection: close\r\n\r\n",
		status, reason, len(body))
	w.Write([]byte(hdr))
	if len(body) > 0 {
		w.Write(body)
	}
}

func hmac_eq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// generateSelfSignedCert creates a fresh ECDSA P-256 cert valid for the
// supplied SAN addresses for the next hour. Returns the cert plus its SPKI
// SHA-256 (base64url) for mDNS TXT pinning.
func generateSelfSignedCert(sans []string) (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "daal-share"},
		NotBefore:    time.Now().Add(-time.Minute).UTC(),
		NotAfter:     time.Now().Add(time.Hour).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	spki := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return cert, base64.RawURLEncoding.EncodeToString(spki[:]), nil
}

// DetectPrivateAddrs enumerates non-loopback private interfaces on the
// device. The HTTPS sender binds only to these — never to 0.0.0.0 or to a
// public address. CC.6.
func DetectPrivateAddrs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			// IPv6 link-local needs a zone-id (`fe80::...%ifname`) to
			// dial. The URL form has no portable way to thread that
			// through, so we cannot publish a usable LAN URL for these
			// addresses yet. Skip them; the loopback fallback below
			// keeps the in-process round-trip test working when the
			// host has no other private NIC (e.g. Windows GH runners).
			if ip.To4() == nil && ip.IsLinkLocalUnicast() {
				continue
			}
			if isPrivateIP(ip) {
				out = append(out, ip.String())
			}
		}
	}
	if len(out) == 0 {
		// As a last resort (test environments without a private NIC), bind
		// to loopback so the in-process round-trip test works.
		out = append(out, "127.0.0.1")
	}
	return out, nil
}

func isPrivateIP(ip net.IP) bool {
	// IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
	// Link-local: 169.254.0.0/16. CGNAT: 100.64.0.0/10.
	if v4 := ip.To4(); v4 != nil {
		switch v4[0] {
		case 10:
			return true
		case 192:
			return v4[1] == 168
		case 172:
			return v4[1] >= 16 && v4[1] <= 31
		case 169:
			return v4[1] == 254
		case 100:
			return v4[1] >= 64 && v4[1] <= 127
		case 127:
			return true
		}
		return false
	}
	// IPv6 ULA: fc00::/7. Link-local: fe80::/10.
	if ip[0]&0xfe == 0xfc {
		return true
	}
	if ip[0] == 0xfe && ip[1]&0xc0 == 0x80 {
		return true
	}
	return ip.IsLoopback()
}

func portFromURL(u string) int {
	// crude but enough — we control the URLs.
	idx := strings.LastIndex(u, ":")
	end := strings.Index(u[idx+1:], "/")
	if end < 0 {
		end = len(u) - idx - 1
	}
	p, _ := strconv.Atoi(u[idx+1 : idx+1+end])
	return p
}

// CtxDeadline returns a context with the supplied per-request deadline.
// Used by the receiver to bound how long a single GET may take.
func CtxDeadline(parent context.Context, ms int) (context.Context, context.CancelFunc) {
	if ms <= 0 {
		ms = 15000
	}
	return context.WithTimeout(parent, time.Duration(ms)*time.Millisecond)
}
