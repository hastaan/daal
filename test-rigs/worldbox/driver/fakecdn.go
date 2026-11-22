package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// `wb fakecdn` is Cloudflare's edge for the CDN add-on (plan §2.2, item
// B-8): a TLS-terminating reverse proxy that answers on EVERY address of
// 198.19.8.0/24 (the lab's "Cloudflare ranges"; addons_net.go makes the
// whole prefix local), the way an anycast edge does — a recipient's edge
// picker may dial any address inside a signed seed prefix.
//
// What it enforces, because Daal's CDN route depends on each:
//
//   - SNI == Host. The request's Host must be the name the TLS session
//     was opened for — with ECH, the INNER name. Anything else is 421
//     (Misdirected Request): no domain fronting through this edge.
//   - The zone's configuration, read from the fake Cloudflare API's state
//     (cf-state.json, fakecf_api.go): only a host with a PROXIED A record
//     is served (else 403, "error code: 1001"); the origin is that
//     record's address on the port an enabled origin rule names (else
//     443); WebSockets must be on for an upgrade (else 400); SSL mode
//     decides how the edge reaches the origin — flexible: plain HTTP on
//     80; full: TLS, any certificate; strict: TLS, a certificate from the
//     lab's Origin CA valid for the host.
//   - Origin pull: with AOP on, the edge presents the zone's uploaded
//     client certificate to the origin. The relay's CDN door requires it.
//   - ECH with the lab key (ech_lab.go): outer name cloudflare-ech.com.
//     A hello without ECH is served too (the name is then on the wire —
//     what a censor's SNI rule sees).
//   - Idle WebSockets are closed after --ws-idle (Cloudflare: ~100 s).
//
// The edge pulls from --pull-from, an address inside the published
// ranges: the relay's firewall lets in exactly those.
//
// Every request is a line in cdn-requests.jsonl: which edge address,
// the outer and inner names, whether ECH was accepted, Host, path,
// status, and what the origin said.
//
// Not modelled: caching, the HTTP/2 and HTTP/3 edges (HTTP/1.1 only —
// sing-box's WebSocket client sends ALPN http/1.1), Cloudflare's bot
// and WAF layers, per-colo behaviour.

const cdnReqFile = "cdn-requests.jsonl"

// CDNRequest is one line of cdn-requests.jsonl.
type CDNRequest struct {
	TS          string `json:"ts"`
	Edge        string `json:"edge"`
	From        string `json:"from"`
	OuterSNI    string `json:"outer_sni,omitempty"`
	SNI         string `json:"sni"`
	ECH         bool   `json:"ech_accepted"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Upgrade     bool   `json:"upgrade,omitempty"`
	Status      int    `json:"status"`
	Why         string `json:"why,omitempty"`
	Origin      string `json:"origin,omitempty"`
	OriginState string `json:"origin_state,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
}

func CDNRequests(run string) []CDNRequest {
	body, _ := os.ReadFile(filepath.Join(run, cdnReqFile))
	var out []CDNRequest
	for _, l := range strings.Split(string(body), "\n") {
		var q CDNRequest
		if json.Unmarshal([]byte(l), &q) == nil && q.TS != "" {
			out = append(out, q)
		}
	}
	return out
}

type edge struct {
	run      string
	pullFrom string
	wsIdle   time.Duration
	mu       sync.Mutex
	logf     *os.File
	certs    map[string]*tls.Certificate
}

func (e *edge) logReq(q CDNRequest) {
	q.TS = time.Now().UTC().Format(time.RFC3339Nano)
	line, _ := json.Marshal(q)
	e.mu.Lock()
	e.logf.Write(append(line, '\n'))
	e.mu.Unlock()
}

func cmdFakeCDN(args []string) int {
	fs := flag.NewFlagSet("fakecdn", flag.ExitOnError)
	run := fs.String("run-dir", "", "")
	pull := fs.String("pull-from", CDNOriginPull, "source address toward origins")
	idle := fs.Duration("ws-idle", 100*time.Second, "close a WebSocket idle this long")
	_ = fs.Parse(args)
	e := &edge{run: *run, pullFrom: *pull, wsIdle: *idle, certs: map[string]*tls.Certificate{}}
	var err error
	if e.logf, err = os.OpenFile(filepath.Join(*run, cdnReqFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		log.Fatalf("fakecdn: %v", err)
	}
	cfg, err := e.tlsConfig()
	if err != nil {
		log.Fatalf("fakecdn: %v", err)
	}
	ln, err := net.Listen("tcp4", ":443")
	if err != nil {
		log.Fatalf("fakecdn: %v", err)
	}
	fmt.Println("fakecdn: listening")
	srv := &http.Server{Handler: e, ReadHeaderTimeout: 20 * time.Second,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	log.Fatal(srv.Serve(tls.NewListener(ln, cfg)))
	return 1
}

func (e *edge) tlsConfig() (*tls.Config, error) {
	labCA, labKey, err := loadCA(e.run)
	if err != nil {
		return nil, err
	}
	_, single, priv, err := LabECH(e.run)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: single, PrivateKey: priv, SendAsRetry: true}},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(h.ServerName)
			if name == "" {
				name = "edge.invalid"
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if c, ok := e.certs[name]; ok {
				return c, nil
			}
			c, err := mintLeaf(labCA, labKey, name)
			if err == nil {
				e.certs[name] = c
			}
			return c, err
		},
	}, nil
}

func (e *edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := CDNRequest{From: r.RemoteAddr, Path: r.URL.Path, Host: strings.ToLower(strings.Split(r.Host, ":")[0]),
		Upgrade: strings.EqualFold(r.Header.Get("Upgrade"), "websocket")}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		q.Edge, _, _ = net.SplitHostPort(la.String())
	}
	if r.TLS != nil {
		q.SNI, q.ECH = strings.ToLower(r.TLS.ServerName), r.TLS.ECHAccepted
		if q.ECH {
			q.OuterSNI = ECHPublicName
		} else {
			q.OuterSNI = q.SNI
		}
	}
	fail := func(status int, why, body string) {
		q.Status, q.Why = status, why
		e.logReq(q)
		w.Header().Set("Server", "cloudflare")
		http.Error(w, body, status)
	}
	if q.Host != q.SNI {
		fail(http.StatusMisdirectedRequest, "sni_host_mismatch", "421 Misdirected Request")
		return
	}
	st, err := LoadCFState(e.run)
	if err != nil {
		fail(502, "no_state", "error code: 502")
		return
	}
	z := st.ZoneFor(q.Host)
	if z == nil {
		fail(403, "no_zone", "error code: 1001")
		return
	}
	rec, ok := z.Proxied(q.Host)
	if !ok {
		fail(403, "no_proxied_record", "error code: 1001")
		return
	}
	if q.Upgrade && z.Settings["websockets"] != "on" {
		fail(400, "websockets_off", "WebSockets are off for this zone")
		return
	}
	port := z.OriginPort(q.Host)
	mode := z.Settings["ssl"]
	if mode == "flexible" {
		port = 80
	}
	q.Origin = net.JoinHostPort(rec.Content, fmt.Sprint(port))
	oc, state, err := e.dialOrigin(z, st, q.Host, q.Origin, mode)
	q.OriginState = state
	if err != nil {
		fail(502, "origin: "+err.Error(), "error code: 502")
		return
	}
	defer oc.Close()
	// One request, as the browser sent it, with the edge's own headers.
	r.Header.Set("CF-Connecting-IP", strings.Split(r.RemoteAddr, ":")[0])
	r.Header.Del("Proxy-Connection")
	r.RequestURI = ""
	_ = oc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := r.Write(oc); err != nil {
		fail(502, "origin write: "+err.Error(), "error code: 502")
		return
	}
	br := bufio.NewReader(oc)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		fail(502, "origin read: "+err.Error(), "error code: 502")
		return
	}
	q.Status = resp.StatusCode
	if resp.StatusCode != http.StatusSwitchingProtocols {
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		q.Bytes, _ = io.Copy(w, io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		e.logReq(q)
		return
	}
	// 101: splice the two connections until either side goes or the
	// WebSocket idles out.
	hj, ok := w.(http.Hijacker)
	if !ok {
		fail(500, "no_hijack", "error code: 500")
		return
	}
	cc, cbuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer cc.Close()
	_ = oc.SetDeadline(time.Time{})
	if err := resp.Write(cc); err != nil {
		return
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var total atomic.Int64
	pump := func(dst io.Writer, src io.Reader) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				total.Add(int64(n))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { pump(oc, io.MultiReader(cbuf, cc)); done <- struct{}{} }()
	go func() { pump(cc, br); done <- struct{}{} }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	why := "closed"
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			if time.Since(time.Unix(0, last.Load())) > e.wsIdle {
				why = "idle_timeout"
				break loop
			}
		}
	}
	q.Why, q.Bytes = "ws_"+why, total.Load()
	e.logReq(q)
}

// dialOrigin reaches the origin the way the zone's SSL mode says.
func (e *edge) dialOrigin(z *cfZone, st *CFState, host, addr, mode string) (net.Conn, string, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(e.pullFrom)}}
	raw, err := d.Dial("tcp4", addr)
	if err != nil {
		return nil, "connect_failed", err
	}
	if mode == "flexible" || mode == "off" {
		return raw, "plain_http", nil
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	switch mode {
	case "strict":
		pool := x509.NewCertPool()
		body, err := os.ReadFile(filepath.Join(e.run, cfOriginCA))
		if err != nil || !pool.AppendCertsFromPEM(body) {
			raw.Close()
			return nil, "no_origin_ca", fmt.Errorf("no origin CA")
		}
		cfg.RootCAs = pool
	default: // full: any certificate
		cfg.InsecureSkipVerify = true
	}
	state := "tls_" + mode
	if z.AOPEnabled && len(z.AOPCerts) > 0 {
		c := z.AOPCerts[len(z.AOPCerts)-1]
		pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if err != nil {
			raw.Close()
			return nil, "bad_aop_cert", err
		}
		cfg.Certificates = []tls.Certificate{pair}
		state += "+aop"
	}
	tc := tls.Client(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, state + ":handshake_failed", err
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, state, nil
}
