package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// `wb dpi` is the censor's payload-aware half: an in-path middlebox that
// receives every client→world TCP packet from the kernel (NFQUEUE), keeps
// a little per-flow state, and returns a verdict. It exists for the
// techniques a static nft rule cannot express — reading the TLS
// ClientHello's server_name, acting on "the first data packet", forging
// RSTs toward both ends.
//
// It models documented blocking TECHNIQUES (research/filtering-the-flow.md,
// research/protocol-level-anatomy.md), not anybody's classifier. Known
// differences from the real thing are listed in the README ("Fidelity").
//
// Fail closed: the nft rule that feeds it has no `bypass`, so if this
// process dies every queued packet is dropped — and the scenario's own
// control probes ("an innocent SNI still gets through") go red instead of
// a dead censor looking like a permissive one.

// DPIRule is one payload rule. Rules are evaluated in order on each
// in-order data packet of a flow until one fires or none is still waiting
// for more bytes.
type DPIRule struct {
	// When: what the rule looks at.
	//   tls_sni          the server_name of a TLS ClientHello
	//   first_data       the first packet that carries payload (whatever it is)
	//   first_bytes_not  the first payload does NOT start like one of Allow
	When string `json:"when"`
	// SNI: exact names (case-insensitive) a tls_sni rule matches.
	SNI []string `json:"sni,omitempty"`
	// Reassemble: a tls_sni rule follows a ClientHello across TCP
	// segments (a GFW-like box). false = it reads the first data packet
	// only and misses a name that lies beyond it (a stateless box).
	Reassemble bool `json:"reassemble,omitempty"`
	// Allow: for first_bytes_not — "tls" (record type 0x16, version 3.x)
	// and/or "http" (a request verb).
	Allow []string `json:"allow,omitempty"`
	// Dst / Port narrow the rule to flows toward one address / port.
	Dst  string `json:"dst,omitempty"`
	Port int    `json:"port,omitempty"`
	// Action: "drop" — swallow this packet and every later client packet
	// of the flow, silently; "rst" — the same, plus forged RSTs.
	Action string `json:"action"`
	// RSTTo: "both" (default: toward client and server, as the GFW does)
	// or "client" (Iran's single RST+ACK toward the client).
	RSTTo string `json:"rst_to,omitempty"`
}

func (r DPIRule) validate() error {
	switch r.When {
	case "tls_sni":
		if len(r.SNI) == 0 {
			return fmt.Errorf("dpi rule tls_sni needs a non-empty sni list")
		}
	case "first_data":
	case "first_bytes_not":
		if len(r.Allow) == 0 {
			return fmt.Errorf("dpi rule first_bytes_not needs allow")
		}
		for _, a := range r.Allow {
			if a != "tls" && a != "http" {
				return fmt.Errorf("dpi rule first_bytes_not: allow %q, want tls|http", a)
			}
		}
	default:
		return fmt.Errorf("dpi rule: when=%q, want tls_sni|first_data|first_bytes_not", r.When)
	}
	if r.Action != "drop" && r.Action != "rst" {
		return fmt.Errorf("dpi rule %s: action=%q, want drop|rst", r.When, r.Action)
	}
	if r.RSTTo != "" && r.RSTTo != "both" && r.RSTTo != "client" {
		return fmt.Errorf("dpi rule %s: rst_to=%q, want both|client", r.When, r.RSTTo)
	}
	return nil
}

// ---- TLS ClientHello ---------------------------------------------------

const (
	chNeedMore = iota // a ClientHello so far, but not all of it
	chNotTLS          // does not start like a TLS handshake record
	chNoSNI           // a complete ClientHello without server_name
	chSNI             // a complete ClientHello with server_name
	chOpaque          // TLS, but not parseable here (handshake split across records, garbage)
)

// parseClientHello reads the server_name out of the start of a TCP
// stream. It understands exactly one TLS record holding the whole
// ClientHello; a ClientHello fragmented across several records is
// chOpaque — the same blind spot the real boxes have (Niere et al. 2023).
func parseClientHello(b []byte) (sni string, state int) {
	if len(b) == 0 {
		return "", chNeedMore
	}
	if b[0] != 0x16 {
		return "", chNotTLS
	}
	if len(b) < 5 {
		return "", chNeedMore
	}
	if b[1] != 3 {
		return "", chNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 {
		return "", chOpaque
	}
	if len(b) < 5+recLen {
		return "", chNeedMore
	}
	hs := b[5 : 5+recLen]
	if hs[0] != 1 { // not a ClientHello
		return "", chOpaque
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return "", chOpaque // continues in another record
	}
	p := hs[4 : 4+hsLen]
	skip := func(n int) bool {
		if n < 0 || n > len(p) {
			return false
		}
		p = p[n:]
		return true
	}
	if !skip(2 + 32) { // version, random
		return "", chOpaque
	}
	if len(p) < 1 || !skip(1+int(p[0])) { // session id
		return "", chOpaque
	}
	if len(p) < 2 || !skip(2+int(binary.BigEndian.Uint16(p))) { // cipher suites
		return "", chOpaque
	}
	if len(p) < 1 || !skip(1+int(p[0])) { // compression methods
		return "", chOpaque
	}
	if len(p) == 0 {
		return "", chNoSNI // no extensions at all
	}
	if len(p) < 2 {
		return "", chOpaque
	}
	extLen := int(binary.BigEndian.Uint16(p))
	if !skip(2) || extLen > len(p) {
		return "", chOpaque
	}
	p = p[:extLen]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		if 4+l > len(p) {
			return "", chOpaque
		}
		body := p[4 : 4+l]
		p = p[4+l:]
		if typ != 0 {
			continue
		}
		// server_name_list: len(2) { type(1) len(2) name }
		if len(body) < 5 || body[2] != 0 {
			return "", chOpaque
		}
		n := int(binary.BigEndian.Uint16(body[3:]))
		if 5+n > len(body) {
			return "", chOpaque
		}
		return string(body[5 : 5+n]), chSNI
	}
	return "", chNoSNI
}

func looksLikeHTTP(b []byte) bool {
	for _, v := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT "} {
		if len(b) >= len(v) && string(b[:len(v)]) == v {
			return true
		}
	}
	return false
}

func looksLikeTLS(b []byte) bool { return len(b) >= 3 && b[0] == 0x16 && b[1] == 3 && b[2] <= 4 }

// ---- per-flow engine ---------------------------------------------------

type flowKey struct {
	src, dst     [4]byte
	sport, dport uint16
}

type flowState struct {
	next    uint32 // next expected sequence number
	seen    int    // payload bytes seen in order
	buf     []byte // in-order payload seen so far (bounded)
	pkts    int    // data packets seen
	decided bool   // no rule can fire any more: forward untouched
	blocked bool   // a rule fired: every later client packet is dropped
}

type tcpPacket struct {
	key      flowKey
	seq, ack uint32
	flags    byte
	payload  []byte
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10

	dpiBufCap  = 16 << 10 // bytes of a flow's start the box will hold
	dpiMaxPkts = 8        // data packets it will wait for a ClientHello to complete
)

// parseIPv4TCP decodes an IPv4/TCP packet; ok=false for anything else.
func parseIPv4TCP(b []byte) (pk tcpPacket, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 || b[9] != syscall.IPPROTO_TCP {
		return pk, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total > len(b) || total < ihl+20 {
		return pk, false
	}
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 { // a fragment: not modelled, forwarded
		return pk, false
	}
	t := b[ihl:total]
	doff := int(t[12]>>4) * 4
	if doff < 20 || doff > len(t) {
		return pk, false
	}
	copy(pk.key.src[:], b[12:16])
	copy(pk.key.dst[:], b[16:20])
	pk.key.sport = binary.BigEndian.Uint16(t[0:2])
	pk.key.dport = binary.BigEndian.Uint16(t[2:4])
	pk.seq = binary.BigEndian.Uint32(t[4:8])
	pk.ack = binary.BigEndian.Uint32(t[8:12])
	pk.flags = t[13]
	pk.payload = t[doff:]
	return pk, true
}

// dpiEvent is one line of dpi-events.jsonl: a rule that fired.
type dpiEvent struct {
	T      string `json:"t"`
	Rule   int    `json:"rule"`
	When   string `json:"when"`
	Action string `json:"action"`
	Flow   string `json:"flow"`
	SNI    string `json:"sni,omitempty"`
	Packet int    `json:"data_packet"`
	Bytes  int    `json:"bytes_seen"`
}

type dpiEngine struct {
	rules  []DPIRule
	flows  map[flowKey]*flowState
	inject func(pk tcpPacket, toClient, toServer bool) // nil in unit tests
	log    func(dpiEvent)
}

func newDPIEngine(rules []DPIRule) *dpiEngine {
	return &dpiEngine{rules: rules, flows: map[flowKey]*flowState{}}
}

// verdict decides one client→world packet: true = forward, false = drop.
func (e *dpiEngine) verdict(raw []byte) bool {
	pk, ok := parseIPv4TCP(raw)
	if !ok {
		return true
	}
	if pk.flags&tcpSYN != 0 && pk.flags&tcpACK == 0 {
		if len(e.flows) > 1<<16 {
			e.flows = map[flowKey]*flowState{}
		}
		e.flows[pk.key] = &flowState{next: pk.seq + 1}
		return true
	}
	fl := e.flows[pk.key]
	if fl == nil {
		return true // a flow that started before the box did
	}
	if fl.blocked {
		return false
	}
	if fl.decided || len(pk.payload) == 0 {
		return true
	}
	if pk.seq != fl.next {
		// Retransmission or reordering before a decision: this box keeps
		// no out-of-order queue. Forward and keep waiting.
		return true
	}
	fl.next += uint32(len(pk.payload))
	fl.seen += len(pk.payload)
	fl.pkts++
	if room := dpiBufCap - len(fl.buf); room > 0 {
		n := len(pk.payload)
		if n > room {
			n = room
		}
		fl.buf = append(fl.buf, pk.payload[:n]...)
	}

	pending := false
	for i, r := range e.rules {
		if r.Dst != "" && r.Dst != net.IP(pk.key.dst[:]).String() {
			continue
		}
		if r.Port != 0 && r.Port != int(pk.key.dport) {
			continue
		}
		fire, sni := false, ""
		switch r.When {
		case "first_data":
			fire = fl.pkts == 1
		case "first_bytes_not":
			if fl.pkts == 1 {
				ok := false
				for _, a := range r.Allow {
					ok = ok || (a == "tls" && looksLikeTLS(pk.payload)) || (a == "http" && looksLikeHTTP(pk.payload))
				}
				fire = !ok
			}
		case "tls_sni":
			data := fl.buf
			if !r.Reassemble {
				if fl.pkts != 1 {
					continue
				}
				data = pk.payload
			}
			name, st := parseClientHello(data)
			switch st {
			case chNeedMore:
				if r.Reassemble && fl.pkts < dpiMaxPkts && len(fl.buf) < dpiBufCap {
					pending = true
				}
			case chSNI:
				for _, want := range r.SNI {
					if strings.EqualFold(want, name) {
						fire, sni = true, name
					}
				}
			}
		}
		if !fire {
			continue
		}
		fl.blocked = true
		fl.buf = nil
		if r.Action == "rst" && e.inject != nil {
			e.inject(pk, true, r.RSTTo != "client")
		}
		if e.log != nil {
			e.log(dpiEvent{T: time.Now().UTC().Format(time.RFC3339Nano), Rule: i, When: r.When, Action: r.Action, SNI: sni, Packet: fl.pkts,
				Bytes: fl.seen, Flow: fmt.Sprintf("%s:%d>%s:%d", net.IP(pk.key.src[:]), pk.key.sport, net.IP(pk.key.dst[:]), pk.key.dport)})
		}
		return false
	}
	if !pending {
		fl.decided = true
		fl.buf = nil
	}
	return true
}

// ---- forged RSTs -------------------------------------------------------

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, b := range parts {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// buildRST returns a bare IPv4/TCP segment src→dst with the given flags.
func buildRST(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 40)
	binary.BigEndian.PutUint16(p[6:], 0x4000) // DF
	p[8] = 64
	p[9] = syscall.IPPROTO_TCP
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	t := p[20:]
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12] = 5 << 4
	t[13] = flags
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], 20)
	binary.BigEndian.PutUint16(t[16:], checksum(pseudo, t))
	return p
}

// rstInjector forges the resets on a raw socket in the censor namespace.
// Toward the client: RST+ACK that looks like the server answering the
// offending segment. Toward the server: RST that looks like the client
// giving up at exactly the sequence number the server expects next.
func rstInjector(fd int) func(pk tcpPacket, toClient, toServer bool) {
	return func(pk tcpPacket, toClient, toServer bool) {
		k := pk.key
		if toClient {
			p := buildRST(k.dst, k.src, k.dport, k.sport, pk.ack, pk.seq+uint32(len(pk.payload)), tcpRST|tcpACK)
			_ = syscall.Sendto(fd, p, 0, &syscall.SockaddrInet4{Addr: k.src})
		}
		if toServer {
			p := buildRST(k.src, k.dst, k.sport, k.dport, pk.seq, 0, tcpRST)
			_ = syscall.Sendto(fd, p, 0, &syscall.SockaddrInet4{Addr: k.dst})
		}
	}
}

// ---- NFQUEUE over raw netlink (stdlib only) -----------------------------

const (
	nfnlSubsysQueue = 3
	nfqMsgPacket    = 0
	nfqMsgVerdict   = 1
	nfqMsgConfig    = 2

	nfqaPacketHdr  = 1
	nfqaVerdictHdr = 2
	nfqaPayload    = 10
	nfqaCfgCmd     = 1
	nfqaCfgParams  = 2

	nfqCfgCmdBind = 1
	nfqCopyPacket = 2

	nfDrop   = 0
	nfAccept = 1
)

func nlAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, (l+3)&^3)
	binary.NativeEndian.PutUint16(b[0:], uint16(l))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func nfqMessage(msg uint16, flags uint16, seq uint32, queue uint16, attrs ...[]byte) []byte {
	body := []byte{syscall.AF_UNSPEC, 0, 0, 0}
	binary.BigEndian.PutUint16(body[2:], queue)
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, 16, 16+len(body))
	binary.NativeEndian.PutUint32(b[0:], uint32(16+len(body)))
	binary.NativeEndian.PutUint16(b[4:], nfnlSubsysQueue<<8|msg)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	return append(b, body...)
}

// nfqPacket extracts the kernel's packet id and the payload from one
// NFQNL_MSG_PACKET netlink message body (after the 16-byte header).
func nfqPacket(body []byte) (id uint32, payload []byte, ok bool) {
	if len(body) < 4 {
		return 0, nil, false
	}
	a := body[4:]
	seenID := false
	for len(a) >= 4 {
		l := int(binary.NativeEndian.Uint16(a[0:]))
		typ := binary.NativeEndian.Uint16(a[2:]) & 0x3fff
		if l < 4 || l > len(a) {
			break
		}
		data := a[4:l]
		switch typ {
		case nfqaPacketHdr:
			if len(data) >= 4 {
				id, seenID = binary.BigEndian.Uint32(data), true
			}
		case nfqaPayload:
			payload = data
		}
		adv := (l + 3) &^ 3
		if adv > len(a) {
			break
		}
		a = a[adv:]
	}
	return id, payload, seenID
}

func cmdDPI(args []string) int {
	fs := flag.NewFlagSet("dpi", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "JSON file: []DPIRule")
	queue := fs.Int("queue", 0, "NFQUEUE number")
	events := fs.String("events", "", "append one JSON line per fired rule")
	ready := fs.String("ready", "", "create this file once the queue is bound")
	_ = fs.Parse(args)
	var rules []DPIRule
	if err := loadJSON(*rulesPath, &rules); err != nil {
		fmt.Fprintln(os.Stderr, "dpi:", err)
		return 2
	}
	for _, r := range rules {
		if err := r.validate(); err != nil {
			fmt.Fprintln(os.Stderr, "dpi:", err)
			return 2
		}
	}
	fail := func(what string, err error) int {
		fmt.Fprintf(os.Stderr, "dpi: %s: %v\n", what, err)
		return 2
	}
	nl, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return fail("netlink socket", err)
	}
	if err := syscall.Bind(nl, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fail("netlink bind", err)
	}
	_ = syscall.SetsockoptInt(nl, 270 /* SOL_NETLINK */, 5 /* NETLINK_NO_ENOBUFS */, 1)
	_ = syscall.SetsockoptInt(nl, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	kernel := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	q := uint16(*queue)
	buf := make([]byte, 1<<17)
	config := func(seq uint32, attr []byte) error {
		const nlmRequest, nlmAck = 1, 4
		if err := syscall.Sendto(nl, nfqMessage(nfqMsgConfig, nlmRequest|nlmAck, seq, q, attr), 0, kernel); err != nil {
			return err
		}
		n, _, err := syscall.Recvfrom(nl, buf, 0)
		if err != nil {
			return err
		}
		if n >= 20 && binary.NativeEndian.Uint16(buf[4:]) == syscall.NLMSG_ERROR {
			if e := int32(binary.NativeEndian.Uint32(buf[16:])); e != 0 {
				return syscall.Errno(-e)
			}
		}
		return nil
	}
	if err := config(1, nlAttr(nfqaCfgCmd, []byte{nfqCfgCmdBind, 0, 0, 0})); err != nil {
		return fail("bind queue", err)
	}
	params := make([]byte, 5)
	binary.BigEndian.PutUint32(params, 0xffff)
	params[4] = nfqCopyPacket
	if err := config(2, nlAttr(nfqaCfgParams, params)); err != nil {
		return fail("queue copy mode", err)
	}
	raw, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fail("raw socket", err)
	}

	eng := newDPIEngine(rules)
	eng.inject = rstInjector(raw)
	var evf *os.File
	if *events != "" {
		if evf, err = os.OpenFile(*events, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
			return fail("events file", err)
		}
	}
	eng.log = func(ev dpiEvent) {
		line, _ := json.Marshal(ev)
		fmt.Println(string(line))
		if evf != nil {
			evf.Write(append(line, '\n'))
		}
	}
	fmt.Fprintf(os.Stderr, "dpi: queue %d bound, %d rule(s)\n", q, len(rules))
	if *ready != "" {
		_ = os.WriteFile(*ready, []byte("ready\n"), 0o644)
	}
	for {
		n, _, err := syscall.Recvfrom(nl, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.ENOBUFS {
				continue
			}
			return fail("netlink recv", err)
		}
		msgs := buf[:n]
		for len(msgs) >= 16 {
			l := int(binary.NativeEndian.Uint32(msgs[0:]))
			if l < 16 || l > len(msgs) {
				break
			}
			if binary.NativeEndian.Uint16(msgs[4:]) == nfnlSubsysQueue<<8|nfqMsgPacket {
				if id, payload, ok := nfqPacket(msgs[16:l]); ok {
					v := uint32(nfAccept)
					if !eng.verdict(payload) {
						v = nfDrop
					}
					vh := make([]byte, 8)
					binary.BigEndian.PutUint32(vh[0:], v)
					binary.BigEndian.PutUint32(vh[4:], id)
					_ = syscall.Sendto(nl, nfqMessage(nfqMsgVerdict, 1, 0, q, nlAttr(nfqaVerdictHdr, vh)), 0, kernel)
				}
			}
			adv := (l + 3) &^ 3
			if adv >= len(msgs) {
				break
			}
			msgs = msgs[adv:]
		}
	}
}
