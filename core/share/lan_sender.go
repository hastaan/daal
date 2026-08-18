package share

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

// ErrPublicBindRefused is returned when defaultListen is handed an address
// that is not a private/link-local IP literal.
//
// specs/lan-share-v1.md claims the private-only rule is "enforced by an
// OPSEC source-grep test". A source grep can only see the string
// "0.0.0.0" not appearing in this file; it cannot see what DetectPrivateAddrs
// (or a future caller, or a test double) actually passes in. So the rule is
// enforced HERE, at the bind, where it is a property of the running program
// rather than of the source text — and TestSenderRefusesPublicBind proves it.
var ErrPublicBindRefused = errors.New("share: refusing to bind a non-private address")

// defaultListen binds an HTTPS server to each supplied private address on
// a random high port. The server serves exactly one resource:
//
//	GET /bundle.sbp           Authorization: Bearer <token>
//
// All other requests get 404. Cert is freshly self-signed per session; the
// receiver pins its SPKI hash, which this function returns so the manager
// can publish it in the mDNS TXT record and in the QR fallback URI.
//
// The returned `urls` are full https://addr:port/bundle.sbp URLs that are
// convenient to render as a fallback QR for mDNS-filtered networks.
func defaultListen(addrs []string, token string, body []byte) ([]string, string, func(), error) {
	if len(addrs) == 0 {
		return nil, "", nil, errors.New("share: no addrs")
	}
	// Refuse the whole session if ANY supplied address is off-limits. We
	// do not silently skip it: a caller that thinks it is sharing on five
	// interfaces and is actually sharing on four has a bug we want loud,
	// and a caller that passed 0.0.0.0 has a bug we want louder.
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, "", nil, fmt.Errorf("%w: %q is not an IP literal", ErrPublicBindRefused, addr)
		}
		if ip.IsUnspecified() || ip.IsMulticast() || !isPrivateIP(ip) {
			return nil, "", nil, fmt.Errorf("%w: %s", ErrPublicBindRefused, addr)
		}
	}
	cert, spki, err := generateSelfSignedCert(addrs)
	if err != nil {
		return nil, "", nil, err
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
		return nil, "", nil, errors.New("share: failed to bind any address")
	}
	stop := func() {
		mu.Lock()
		closed = true
		mu.Unlock()
		for _, s := range stops {
			s()
		}
	}
	return urls, spki, stop, nil
}

// defaultAdvertise is where the mDNS publisher WILL go. It is a no-op in
// every build that exists today.
//
// The old comment here said the real publisher "lives in
// lan_sender_mdns.go behind the `mdns` build tag". There is no such file
// in the repository and no such build tag — that claim was wrong when it
// was written and stayed wrong because nothing tested it. Stating it
// plainly instead: on Go-side builds NOTHING is broadcast, so the `spki`
// key the manager passes in `txt` is not on any wire yet.
//
// This does not leave receivers unpinned. The pin reaches them by the
// path that actually works on the networks this project targets — where
// mDNS is filtered anyway — as `lan_uris` from engine_share_begin: a
// `daalshare://lan?u=..&p=..&s=..` string shown as a QR or read aloud,
// which ParseShareTarget refuses to accept without a well-formed pin. The
// TXT map is populated now so that whoever lands the publisher (or the
// Android NsdManager side, which registers the service itself) has the
// field to emit rather than having to rediscover that it was missing.
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
	// One implementation of the hash, shared with the receiver-side pin
	// check (spki.go). Two copies of this three-line computation is
	// exactly how a sender and a receiver end up hashing different bytes
	// and nobody notices, because the pin "just never matches" and the
	// feature "just doesn't work on this network".
	spki, err := SPKIHashFromDER(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, spki, nil
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
