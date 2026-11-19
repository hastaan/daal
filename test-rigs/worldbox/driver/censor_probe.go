package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// `wb rawprobe` is what proves a censor rule BITES, independently of
// Daal: plain sockets from the client namespace, no engine, no pack, no
// tunnel. A scenario under which a Daal family "is blocked" proves nothing
// about the censor unless a probe that knows nothing about Daal is blocked
// the same way — and an innocent neighbour is not.
//
// One probe, one observation, from a closed vocabulary:
//
//	tcp    ok | connect_timeout | connect_reset | unreachable
//	tls    ok | reset_after_hello | timeout_after_hello | (the connect_* above)
//	bytes  answered | reset_after_data | silent | (the connect_* above)
//	udp    sent            (delivered|dropped is read off the censor's tap by the driver)
//	tcp_burst  all | some | none      40 connects, one SYN each: is loss random, total, or absent
//	bulk       fast | slow            32 KiB echoed back within 2 s, or not: is the path throttled
type RawProbe struct {
	Kind   string `json:"kind"`
	Addr   string `json:"addr"`
	Port   int    `json:"port"`
	SNI    string `json:"sni,omitempty"`
	Split  bool   `json:"split,omitempty"`  // tls: send the ClientHello in two TCP segments
	Shape  string `json:"shape,omitempty"`  // udp: plain | quic
	Sport  int    `json:"sport,omitempty"`  // udp: fixed source port (what the tap counts)
	Local  string `json:"local,omitempty"`  // tcp: our end of the connection (ip:port), to find the flow in the censor's log
	Result string `json:"result,omitempty"` // the observation
	Error  string `json:"error,omitempty"`  // the Go error text behind it, verbatim
	Ms     int64  `json:"ms"`
}

// How long a raw probe waits for a SYN to be answered and for a first
// flight to be answered. Variables only because a scenario whose whole
// point is DELAY (deep-queue: 2.4 s per round trip) would otherwise be
// "proved" a dead address by the probe's own impatience: such a
// scenario declares `probe_patience_ms`, which is added to both
// (--patience-ms; rawPatience on the driver's side).
var (
	rawConnectTimeout = 2 * time.Second
	rawAnswerTimeout  = 2500 * time.Millisecond
)

// rawPatience is the running scenario's probe_patience_ms, set once by
// the run (run.go) and passed to every `wb rawprobe` it starts.
var rawPatience time.Duration

const (
	tapSportPlain = 40001 // source port of a plain-UDP probe datagram
	tapSportQUIC  = 40002 // source port of a QUIC-Initial-shaped probe datagram
)

func cmdRawProbe(args []string) int {
	fs := flag.NewFlagSet("rawprobe", flag.ExitOnError)
	var p RawProbe
	fs.StringVar(&p.Kind, "kind", "tcp", "tcp | tls | bytes | udp")
	fs.StringVar(&p.Addr, "addr", "", "destination address")
	fs.IntVar(&p.Port, "port", 443, "destination port")
	fs.StringVar(&p.SNI, "sni", "", "tls: server_name to send (empty = none)")
	fs.BoolVar(&p.Split, "split", false, "tls: split the ClientHello across two TCP segments")
	fs.StringVar(&p.Shape, "shape", "plain", "udp: plain | quic")
	patience := fs.Int("patience-ms", 0, "extra time to wait for a connect and for an answer (a scenario that delays)")
	_ = fs.Parse(args)
	if *patience > 0 {
		extra := time.Duration(*patience) * time.Millisecond
		rawConnectTimeout += extra
		rawAnswerTimeout += extra
	}
	t0 := time.Now()
	switch p.Kind {
	case "tcp", "tls", "bytes":
		probeTCP(&p)
	case "tcp_burst":
		probeBurst(&p)
	case "bulk":
		probeBulk(&p)
	case "udp":
		probeUDP(&p)
	default:
		p.Result, p.Error = "error", "unknown kind "+p.Kind
	}
	p.Ms = time.Since(t0).Milliseconds()
	_ = json.NewEncoder(os.Stdout).Encode(p)
	return 0
}

func connectOutcome(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return "connect_reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.As(err, &ne) && ne.Timeout():
		return "connect_timeout"
	}
	return "connect_error"
}

// countingConn records whether the far end ever said anything, and can
// cut the first write in two real TCP segments.
type countingConn struct {
	net.Conn
	read     atomic.Int64
	split    bool
	wroteOne bool
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	if c.split && !c.wroteOne && len(b) > 8 {
		c.wroteOne = true
		half := len(b) / 2
		n, err := c.Conn.Write(b[:half])
		if err != nil {
			return n, err
		}
		time.Sleep(40 * time.Millisecond) // TCP_NODELAY is on: this is a second segment
		m, err := c.Conn.Write(b[half:])
		return n + m, err
	}
	c.wroteOne = true
	return c.Conn.Write(b)
}

func probeTCP(p *RawProbe) {
	d := net.Dialer{Timeout: rawConnectTimeout}
	conn, err := d.Dial("tcp4", net.JoinHostPort(p.Addr, strconv.Itoa(p.Port)))
	if err != nil {
		p.Result, p.Error = connectOutcome(err), err.Error()
		return
	}
	defer conn.Close()
	p.Local = conn.LocalAddr().String()
	if p.Kind == "tcp" {
		p.Result = "ok"
		return
	}
	cc := &countingConn{Conn: conn, split: p.Split}
	_ = conn.SetDeadline(time.Now().Add(rawAnswerTimeout))
	if p.Kind == "bytes" {
		// Eight opaque bytes: enough for a censor that judges a flow by
		// how it begins, too few for any server to have an opinion yet (a
		// shadowsocks server is still waiting for the rest of its salt) —
		// so a reset after this is the path's doing, not the far end's.
		junk := make([]byte, 8)
		_, _ = rand.Read(junk)
		junk[0] = 0xb7 // not a TLS record, not an HTTP verb, not printable
		if _, err = cc.Write(junk); err == nil {
			_, err = cc.Read(make([]byte, 1024))
		}
		switch {
		case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
			p.Result, p.Error = "reset_after_data", err.Error()
		case cc.read.Load() > 0 || errors.Is(err, io.EOF):
			p.Result = "answered" // bytes, or an orderly close: the far end saw ours
		default:
			p.Result, p.Error = "silent", errText(err)
		}
		return
	}
	// A real ClientHello from the Go TLS stack. Certificate verification is
	// off on purpose: the question is "did the handshake's first flight
	// get an answer through the censor", not "is this the right server".
	cfg := &tls.Config{ServerName: p.SNI, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	if !p.Split {
		// Classical key shares only: a ClientHello of a few hundred bytes
		// that fits one TCP segment. With --split the default hello is
		// used (post-quantum key share, larger than one segment, like a
		// current browser's or uTLS chrome's) and cut in two regardless.
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	err = tls.Client(cc, cfg).Handshake()
	switch {
	case cc.read.Load() > 0 && !errors.Is(err, syscall.ECONNRESET):
		// The server answered (a ServerHello, or an alert because it did
		// not like us): the hello crossed the censor and the reply came back.
		p.Result, p.Error = "ok", errText(err)
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		p.Result, p.Error = "reset_after_hello", err.Error()
	case err == nil:
		p.Result = "ok"
	default:
		p.Result, p.Error = "timeout_after_hello", err.Error()
	}
}

// probeBurst opens burstN connections at once, each given just under one
// second — less than the kernel's first SYN retransmission — so every
// attempt is exactly one SYN and one SYN-ACK. Random loss shows as "some".
func probeBurst(p *RawProbe) {
	const burstN = 40
	ok := make(chan bool, burstN)
	for i := 0; i < burstN; i++ {
		go func() {
			c, err := (&net.Dialer{Timeout: 900 * time.Millisecond}).Dial("tcp4", net.JoinHostPort(p.Addr, strconv.Itoa(p.Port)))
			if err == nil {
				c.Close()
			}
			ok <- err == nil
		}()
	}
	n := 0
	for i := 0; i < burstN; i++ {
		if <-ok {
			n++
		}
	}
	p.Error = fmt.Sprintf("%d of %d connects completed on the first SYN", n, burstN)
	switch n {
	case burstN:
		p.Result = "all"
	case 0:
		p.Result = "none"
	default:
		p.Result = "some"
	}
}

// probeBulk pushes 32 KiB through an echo service and waits two seconds
// for all of it to come back.
func probeBulk(p *RawProbe) {
	const size = 32 << 10
	conn, err := (&net.Dialer{Timeout: rawConnectTimeout}).Dial("tcp4", net.JoinHostPort(p.Addr, strconv.Itoa(p.Port)))
	if err != nil {
		p.Result, p.Error = connectOutcome(err), err.Error()
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	go func() { _, _ = conn.Write(make([]byte, size)) }()
	n, err := io.ReadFull(conn, make([]byte, size))
	p.Error = fmt.Sprintf("%d of %d bytes echoed in 2 s", n, size)
	if err != nil {
		p.Result = "slow"
		// What was already sent is still queued in the throttle; let it
		// drain so the next probe measures the censor and not this one.
		conn.Close()
		time.Sleep(4 * time.Second)
		return
	}
	p.Result = "fast"
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// quicInitialShape is a datagram with the invariant header of a QUIC v1
// Initial (long header, fixed bit, type Initial, version 1, an 8-byte
// DCID) and 1200 bytes, as a client's first flight is padded to. The
// payload is random: this is the SHAPE a header-matching censor keys on,
// not a handshake a server would answer.
func quicInitialShape() []byte {
	b := make([]byte, 1200)
	_, _ = rand.Read(b)
	b[0] = 0xc3
	binary.BigEndian.PutUint32(b[1:], 1)
	b[5] = 8  // DCID length
	b[14] = 0 // SCID length
	b[15] = 0 // token length
	binary.BigEndian.PutUint16(b[16:], 0x4000|1182)
	return b
}

func probeUDP(p *RawProbe) {
	sport, payload := tapSportPlain, append([]byte("worldbox plain udp probe "), make([]byte, 40)...)
	if p.Shape == "quic" {
		sport, payload = tapSportQUIC, quicInitialShape()
	}
	p.Sport = sport
	conn, err := net.DialUDP("udp4", &net.UDPAddr{Port: sport}, &net.UDPAddr{IP: net.ParseIP(p.Addr), Port: p.Port})
	if err != nil {
		p.Result, p.Error = "error", err.Error()
		return
	}
	defer conn.Close()
	sent := 0
	for i := 0; i < 3; i++ { // three copies: one stray loss must not read as a block
		// A closed port answers with ICMP port-unreachable, which a
		// connected UDP socket reports on the NEXT write. That is a
		// delivery, not a failure to send; the tap decides.
		if _, err := conn.Write(payload); err != nil {
			p.Error = err.Error()
		} else {
			sent++
		}
		time.Sleep(15 * time.Millisecond)
	}
	if sent == 0 {
		p.Result = "error"
		return
	}
	p.Result = "sent"
}

// `wb elsewhere` is a host the censor has no quarrel with: an ordinary
// site on the far side of the same border, reached through the same
// censor rules. It is the CONTROL for every blocking claim — "the relay's
// address is blocked" only means something if this address is not, and
// "the border is shut" only if this one is shut too.
//
//	:443/tcp          TLS, a certificate for whatever SNI is asked
//	:80, :8443/tcp    echo
//
// It never sees the relay, the target or the internet namespace.
func cmdElsewhere(args []string) int {
	fs := flag.NewFlagSet("elsewhere", flag.ExitOnError)
	listen := fs.String("listen", ElsewhereIP, "address to serve on")
	_ = fs.Parse(args)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "elsewhere"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	tl, err := tls.Listen("tcp4", net.JoinHostPort(*listen, "443"), cfg)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	for _, port := range []string{"80", "8443"} {
		ln, err := net.Listen("tcp4", net.JoinHostPort(*listen, port))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = io.Copy(c, c)
				}()
			}
		}()
	}
	fmt.Println("elsewhere: listening")
	select {}
}
