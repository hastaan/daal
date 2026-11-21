package fieldprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/metacubex/utls"
)

// One TCP probe: connect, hello, (request), read — and every signal the
// classifier needs, measured on the way.

// Hello fingerprints (fieldreport.ProbeFPs). FPChrome is uTLS's current
// Chrome hello, unmodified (ALPN h2 + http/1.1, ALPS as Chrome sends
// it): what sing-box's uTLS Chrome sends, so used wherever only the
// handshake and the byte count matter. FPChromeH1 narrows ALPN to
// http/1.1 and drops ALPS: a rarer hello, kept only where the test must
// parse an HTTP/1.1 answer (a status line, a Location header). FPGoStd
// is Go's crypto/tls (the ECH probes need it).
const (
	FPChrome   = "chrome_auto"
	FPChromeH1 = "chrome_auto_h1"
	FPGoStd    = "go_std"
)

// tcpSpec is what one TCP probe does.
type tcpSpec struct {
	To  netip.AddrPort
	SNI string // "" = no TLS at all
	// FP is the hello to send (FPChrome, FPChromeH1, FPGoStd); "" is
	// FPChromeH1.
	FP  string
	ECH []byte
	// Verify: check the server's chain against Roots (nil: the device's)
	// for SNI after the handshake. A chain that does not verify ends the
	// probe there — cert_invalid — and no request is sent: the address is
	// not the name's, and the test talks to nobody else.
	Verify bool
	Roots  *x509.CertPool
	// Request: send one HTTP request after the handshake (HTTP/2 when
	// the server picked h2, else HTTP/1.1).
	Request   bool
	Method    string
	Host      string
	Path      string
	ReadLimit int64
	// CarryExpected: the classifier should judge how many bytes came.
	CarryExpected bool
}

func (sp tcpSpec) fp() string {
	switch {
	case sp.SNI == "":
		return ""
	case sp.FP == "":
		return FPChromeH1
	}
	return sp.FP
}

// tcpObs is what one TCP probe saw. No address and no name in here: it
// is turned into a report entry by the classifier and dropped.
type tcpObs struct {
	// ConnectKind: "" connected; refused | timeout | unreachable |
	// local_blocked | local_error | other.
	ConnectKind string
	ConnectRTT  time.Duration
	// RTTKernel: ConnectRTT is the kernel's smoothed RTT (TCP_INFO
	// tcpi_rtt), not wall time around the dial.
	RTTKernel    bool
	HelloWritten bool
	HelloAcked   bool
	AckKnown     bool
	FirstEvent   string // bytes | rst | fin | timeout | ""
	FirstAfter   time.Duration
	HandshakeOK  bool
	TLSAlert     bool
	// HandshakeEnd: how a TLS handshake ended (fieldreport.HSEnds):
	// ok | alert | rst | fin | timeout | other; "" without TLS.
	HandshakeEnd string
	// CertChecked / CertValid: Verify ran, and what it said.
	CertChecked   bool
	CertValid     bool
	EndKind       string // how the read after the handshake ended: fin | rst | timeout | limit | ""
	Rx            int64
	HTTPStatus    int
	Location      string
	ECHAccepted   bool
	ECHRetry      []byte
	Body          []byte // the first 2 KiB only, for /cdn-cgi/trace
	FP            string
	ALPN          string // in memory only (tests): what the server picked
	CarryExpected bool
	Cancelled     bool
}

// recConn counts what comes back and notes the first event after the
// first write (the hello).
type recConn struct {
	net.Conn
	mu         sync.Mutex
	wroteAt    time.Time
	first      string
	firstAfter time.Duration
	rx         int64
	onWrite    func()
}

func (c *recConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	first := c.wroteAt.IsZero() && n > 0
	if first {
		c.wroteAt = time.Now()
	}
	c.mu.Unlock()
	if first && c.onWrite != nil {
		c.onWrite()
	}
	return n, err
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.rx += int64(n)
	if c.first == "" && !c.wroteAt.IsZero() && (n > 0 || err != nil) {
		if n > 0 {
			c.first = "bytes"
		} else {
			c.first = eventOf(err)
		}
		c.firstAfter = time.Since(c.wroteAt)
	}
	c.mu.Unlock()
	return n, err
}

func eventOf(err error) string {
	switch k := errKind(err); k {
	case "rst", "fin", "timeout":
		return k
	case "refused":
		return "rst"
	}
	if errors.Is(err, io.EOF) {
		return "fin"
	}
	return "other"
}

// connectKind turns a dial error into the closed ConnectKind.
func connectKind(err error) string {
	switch k := errKind(err); k {
	case "cancelled", "fin":
		// A dial cut by our own deadline is a timeout.
		return "timeout"
	case "rst":
		// One reset before it opened is a refusal.
		return "refused"
	default:
		return k
	}
}

// runTCP performs one TCP probe through n.
func runTCP(ctx context.Context, n Net, sp tcpSpec, to Timeouts, ackWatch func(net.Conn, time.Duration) func() (bool, bool)) tcpObs {
	o := tcpObs{CarryExpected: sp.CarryExpected, FP: sp.fp()}
	cctx, cancel := context.WithTimeout(ctx, to.Connect)
	t0 := time.Now()
	raw, err := n.DialTCP(cctx, sp.To)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			o.Cancelled = true
		}
		o.ConnectKind = connectKind(err)
		return o
	}
	o.ConnectRTT = time.Since(t0)
	// The wall time above includes the protect() hop to the host and
	// scheduling; the kernel's own measure of the SYN round trip is what
	// the injected-reset ratio needs.
	if rtt, ok := kernelRTT(raw); ok && rtt > 0 {
		o.ConnectRTT, o.RTTKernel = rtt, true
	}
	defer raw.Close()
	if ackWatch == nil {
		ackWatch = watchHelloAck
	}
	rc := &recConn{Conn: raw}
	var verdict func() (bool, bool)
	rc.onWrite = func() { verdict = ackWatch(raw, to.Handshake) }
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()

	_ = raw.SetDeadline(time.Now().Add(to.Handshake))
	var conn net.Conn = rc
	var peer []*x509.Certificate
	alpn := ""
	hsErr := error(nil)
	switch o.FP {
	case "":
		// No TLS: the "hello" is the request itself.
	case FPGoStd:
		cfg := &tls.Config{ServerName: sp.SNI, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
		if len(sp.ECH) > 0 {
			cfg.EncryptedClientHelloConfigList = sp.ECH
			cfg.MinVersion = tls.VersionTLS13
		}
		tc := tls.Client(rc, cfg)
		hsErr = tc.HandshakeContext(ctx)
		if hsErr == nil {
			cs := tc.ConnectionState()
			o.ECHAccepted, peer, alpn = cs.ECHAccepted, cs.PeerCertificates, cs.NegotiatedProtocol
		} else {
			var rej *tls.ECHRejectionError
			if errors.As(hsErr, &rej) {
				o.ECHRetry = rej.RetryConfigList
			}
		}
		conn = tc
	default:
		var uc *utls.UConn
		if o.FP == FPChrome {
			uc = utls.UClient(rc, &utls.Config{ServerName: sp.SNI, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
		} else {
			uc = utls.UClient(rc, &utls.Config{ServerName: sp.SNI, InsecureSkipVerify: true}, utls.HelloCustom)
			spec, err := chromeH1Spec()
			if err == nil {
				err = uc.ApplyPreset(&spec)
			}
			if err != nil {
				o.ConnectKind = "local_error"
				return o
			}
		}
		hsErr = uc.HandshakeContext(ctx)
		if hsErr == nil {
			cs := uc.ConnectionState()
			peer, alpn = cs.PeerCertificates, cs.NegotiatedProtocol
		}
		conn = uc
	}
	if hsErr != nil {
		o.HelloWritten = !rc.wroteAt.IsZero()
		o.TLSAlert = strings.Contains(hsErr.Error(), "remote error")
		o.HandshakeEnd = handshakeEnd(hsErr, o.TLSAlert)
		if verdict != nil {
			o.HelloAcked, o.AckKnown = verdict()
		}
		fillFirst(&o, rc)
		if o.FirstEvent == "" {
			o.FirstEvent = eventOf(hsErr)
			if !rc.wroteAt.IsZero() {
				o.FirstAfter = time.Since(rc.wroteAt)
			}
		}
		o.Cancelled = ctx.Err() != nil
		return o
	}
	o.HandshakeOK = true
	o.ALPN = alpn
	if o.FP != "" {
		o.HandshakeEnd = "ok"
	}
	if sp.Verify && o.FP != "" {
		o.CertChecked = true
		o.CertValid = verifyChain(peer, sp.SNI, sp.Roots, time.Now())
	}
	if sp.Request && (!o.CertChecked || o.CertValid) {
		_ = raw.SetDeadline(time.Now().Add(to.Carry))
		if alpn == "h2" {
			h2Request(conn, sp, &o)
		} else if _, err := conn.Write(httpRequest(sp)); err != nil {
			o.EndKind = eventOf(err)
		} else {
			readResponse(conn, sp.ReadLimit, &o)
		}
	}
	o.HelloWritten = !rc.wroteAt.IsZero()
	if verdict != nil {
		o.HelloAcked, o.AckKnown = verdict()
	}
	fillFirst(&o, rc)
	o.Cancelled = ctx.Err() != nil
	return o
}

// handshakeEnd names how a failed TLS handshake ended.
func handshakeEnd(err error, alert bool) string {
	if alert {
		return "alert"
	}
	switch k := eventOf(err); k {
	case "rst", "fin", "timeout":
		return k
	}
	return "other"
}

// verifyChain checks the server's chain for name against roots (nil:
// the system's). Nothing about the chain is kept: only the yes/no.
func verifyChain(peer []*x509.Certificate, name string, roots *x509.CertPool, now time.Time) bool {
	if len(peer) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range peer[1:] {
		inter.AddCert(c)
	}
	_, err := peer[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter, CurrentTime: now})
	return err == nil
}

func fillFirst(o *tcpObs, rc *recConn) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	o.Rx = rc.rx
	if o.FirstEvent == "" {
		o.FirstEvent, o.FirstAfter = rc.first, rc.firstAfter
	}
}

const userAgent = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

func (sp tcpSpec) method() string {
	if sp.Method == "" {
		return "GET"
	}
	return sp.Method
}

func (sp tcpSpec) host() string {
	if sp.Host == "" {
		return sp.SNI
	}
	return sp.Host
}

func httpRequest(sp tcpSpec) []byte {
	var b bytes.Buffer
	b.WriteString(sp.method() + " " + sp.Path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + sp.host() + "\r\n")
	b.WriteString("User-Agent: " + userAgent + "\r\n")
	b.WriteString("Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
	return b.Bytes()
}

// readResponse reads the status line, the headers it needs and the body
// up to limit, and says how the read ended.
func readResponse(conn net.Conn, limit int64, o *tcpObs) {
	br := bufio.NewReaderSize(conn, 4096)
	line, err := br.ReadString('\n')
	if err != nil {
		o.EndKind = eventOf(err)
		return
	}
	if f := strings.Fields(line); len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/") {
		o.HTTPStatus, _ = strconv.Atoi(f[1])
	}
	for i := 0; i < 64; i++ {
		h, err := br.ReadString('\n')
		if err != nil {
			o.EndKind = eventOf(err)
			return
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		if k, v, ok := strings.Cut(h, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
			o.Location = strings.TrimSpace(v)
		}
	}
	if limit <= 0 {
		limit = 4096
	}
	buf := make([]byte, 8192)
	var got int64
	for got < limit {
		n, err := br.Read(buf)
		if n > 0 {
			if len(o.Body) < 2048 {
				o.Body = append(o.Body, buf[:min(n, 2048-len(o.Body))]...)
			}
			got += int64(n)
		}
		if err != nil {
			o.EndKind = eventOf(err)
			return
		}
	}
	o.EndKind = "limit"
}

// chromeH1Spec is uTLS's current Chrome hello with ALPN narrowed to
// http/1.1 and the ALPS extension, which only means something with h2,
// removed. The report names it chrome_auto_h1. Used only where an
// HTTP/1.1 answer must be parsed (B1–B5: status, Location).
func chromeH1Spec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return spec, err
	}
	exts := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch x := e.(type) {
		case *utls.ALPNExtension:
			x.AlpnProtocols = []string{"http/1.1"}
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			continue
		}
		exts = append(exts, e)
	}
	spec.Extensions = exts
	return spec, nil
}
