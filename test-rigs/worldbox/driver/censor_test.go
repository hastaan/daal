package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// Hermetic tests for the censor: declarations, the ClientHello parser, the
// per-flow DPI engine and the netlink/packet encoders. No namespaces.

// Every scenario is a complete, checkable claim: an analogue, a failure
// category from the product's own taxonomy for every family it blocks, and
// raw probes that show the rules bite and spare.
func TestScenariosAreProvableAndUseTheProductTaxonomy(t *testing.T) {
	rig := rigDir(t)
	_, fams, err := LoadFamilies(rig)
	if err != nil {
		t.Fatal(err)
	}
	tax, err := TaxonomyCategories(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"tcp_connect_timeout", "tcp_reset", "tls_handshake_failed", "tls_sni_or_cert_block_suspected",
		"udp_unavailable", "quic_unavailable", "udp_address_blocked", "udp_port_blocked", "udp_no_reply", "path_too_slow", "unknown"} {
		if !tax[must] {
			t.Errorf("%s no longer lists %s; the censor's truth ladder (censor.go) returns it", taxonomySpecPath, must)
		}
	}
	names := listNames(rig, "scenarios")
	for _, want := range []string{"clean", "udp-blackhole", "port-whitelist", "protocol-whitelist", "relay-ip-block", "sni-drop", "sni-rst",
		"sni-rst-stateless", "tcp-reset-mid-handshake", "quic-drop", "heavy-loss", "lossy-throttle", "throttle-56k", "total-blackout"} {
		if !contains(names, want) {
			t.Errorf("scenarios/%s.json is part of the documented library and is missing", want)
		}
	}
	vars := scenarioVars("cover.example")
	for _, name := range names {
		s, err := LoadScenario(rig, name)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		for _, e := range ValidateScenario(s, fams, tax) {
			t.Error(e)
		}
		var texts []string
		for _, r := range s.Censor.DPI {
			texts = append(texts, r.Dst)
			texts = append(texts, r.SNI...)
		}
		for _, pr := range s.Prove {
			texts = append(texts, pr.SNI)
		}
		for _, txt := range texts {
			if out := substVars(txt, vars); strings.Contains(out, "$") {
				t.Errorf("scenario %s: %q uses a variable that is not in scenarioVars", name, txt)
			}
		}
	}
}

// realClientHello captures the first flight of the Go TLS stack.
func realClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = tls.Client(a, cfg).Handshake() }()
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := readFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := readFull(b, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestParseClientHello(t *testing.T) {
	small := realClientHello(t, &tls.Config{ServerName: "blocked.example", InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}})
	if sni, st := parseClientHello(small); st != chSNI || sni != "blocked.example" {
		t.Fatalf("real ClientHello: state=%d sni=%q", st, sni)
	}
	// Every strict prefix is "need more", never a wrong answer and never a panic.
	for i := 0; i < len(small); i++ {
		if _, st := parseClientHello(small[:i]); st != chNeedMore {
			t.Fatalf("prefix of %d/%d bytes: state=%d, want chNeedMore", i, len(small), st)
		}
	}
	// The default (post-quantum key share) hello is larger than one segment and still parses.
	big := realClientHello(t, &tls.Config{ServerName: "blocked.example", InsecureSkipVerify: true})
	if sni, st := parseClientHello(big); st != chSNI || sni != "blocked.example" {
		t.Fatalf("large ClientHello (%d bytes): state=%d sni=%q", len(big), st, sni)
	}
	// An IP literal is not sent as server_name: this is why Daal's
	// websocket-tls / hysteria2 / tuic routes are invisible to an SNI rule.
	noSNI := realClientHello(t, &tls.Config{ServerName: "203.0.113.10", InsecureSkipVerify: true})
	if _, st := parseClientHello(noSNI); st != chNoSNI {
		t.Fatalf("ClientHello for an IP literal: state=%d, want chNoSNI", st)
	}
	if _, st := parseClientHello([]byte("GET / HTTP/1.1\r\n")); st != chNotTLS {
		t.Fatalf("HTTP: state=%d, want chNotTLS", st)
	}
	// A ClientHello fragmented across TLS records is the documented blind spot.
	frag := append([]byte{0x16, 3, 1, 0, 8}, small[5:13]...)
	if _, st := parseClientHello(frag); st != chOpaque {
		t.Fatalf("record-fragmented hello: state=%d, want chOpaque", st)
	}
	// Garbage of every length must not panic.
	junk := bytes.Repeat([]byte{0x16, 3, 3, 0xff, 0xff, 1, 0xff}, 40)
	for i := range junk {
		parseClientHello(junk[:i])
	}
}

// pkt builds an IPv4/TCP packet client→server on one flow.
func pkt(seq uint32, flags byte, payload []byte) []byte {
	p := buildRST([4]byte{198, 51, 100, 2}, [4]byte{203, 0, 113, 10}, 40000, 443, seq, 7, flags)
	p = append(p, payload...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	return p
}

func TestDPIEngine(t *testing.T) {
	hello := realClientHello(t, &tls.Config{ServerName: "cover.example", InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}})
	other := realClientHello(t, &tls.Config{ServerName: "innocent.example", InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}})
	type injected struct{ client, server bool }
	run := func(rule DPIRule, segments ...[]byte) (verdicts []bool, inj []injected) {
		e := newDPIEngine([]DPIRule{rule})
		e.inject = func(_ tcpPacket, c, s bool) { inj = append(inj, injected{c, s}) }
		seq := uint32(1000)
		verdicts = append(verdicts, e.verdict(pkt(seq, tcpSYN, nil)))
		seq++
		verdicts = append(verdicts, e.verdict(pkt(seq, tcpACK, nil)))
		for _, s := range segments {
			verdicts = append(verdicts, e.verdict(pkt(seq, tcpACK, s)))
			seq += uint32(len(s))
		}
		return verdicts, inj
	}
	eq := func(name string, got []bool, want ...bool) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: verdicts %v, want %v", name, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: verdicts %v, want %v", name, got, want)
			}
		}
	}
	half := len(hello) / 2
	sni := DPIRule{When: "tls_sni", SNI: []string{"COVER.example"}, Action: "rst"}

	v, inj := run(sni, hello, []byte("more"))
	eq("stateless, whole hello", v, true, true, false, false)
	if len(inj) != 1 || !inj[0].client || !inj[0].server {
		t.Fatalf("rst (default both): injected %v", inj)
	}
	v, inj = run(sni, hello[:half], hello[half:], []byte("more"))
	eq("stateless, split hello slips through", v, true, true, true, true, true)
	if len(inj) != 0 {
		t.Fatalf("stateless box injected on a split hello: %v", inj)
	}
	sni.Reassemble, sni.RSTTo = true, "client"
	v, inj = run(sni, hello[:half], hello[half:], []byte("more"))
	eq("reassembling, split hello", v, true, true, true, false, false)
	if len(inj) != 1 || !inj[0].client || inj[0].server {
		t.Fatalf("rst_to=client: injected %v", inj)
	}
	v, _ = run(sni, other, []byte("more"))
	eq("another name is spared", v, true, true, true, true)

	sni.Action = "drop"
	v, inj = run(sni, hello, []byte("retransmit"), nil)
	eq("drop swallows the rest of the flow, bare ACKs included", v, true, true, false, false, false)
	if len(inj) != 0 {
		t.Fatalf("action=drop injected %v", inj)
	}

	v, _ = run(DPIRule{When: "first_data", Dst: "203.0.113.10", Action: "rst"}, []byte("anything"))
	eq("first_data", v, true, true, false)
	v, _ = run(DPIRule{When: "first_data", Dst: "198.19.0.2", Action: "rst"}, []byte("anything"))
	eq("first_data toward another address", v, true, true, true)

	wl := DPIRule{When: "first_bytes_not", Allow: []string{"tls", "http"}, Action: "drop"}
	v, _ = run(wl, hello, []byte{0xde, 0xad})
	eq("whitelist: TLS first, then anything", v, true, true, true, true)
	v, _ = run(wl, []byte("GET / HTTP/1.1\r\n\r\n"))
	eq("whitelist: HTTP", v, true, true, true)
	v, _ = run(wl, []byte{0xb7, 0x01, 0x02, 0x03, 0x04, 0x05}, []byte("GET / "))
	eq("whitelist: opaque first bytes are dropped for good", v, true, true, false, false)

	// A flow the box never saw start, and non-TCP, are forwarded untouched.
	e := newDPIEngine([]DPIRule{sni})
	if !e.verdict(pkt(5, tcpACK, hello)) {
		t.Fatal("mid-flow packet of an unknown flow was dropped")
	}
	if !e.verdict([]byte{0x45, 0, 0, 20}) || !e.verdict(nil) {
		t.Fatal("a non-TCP / truncated packet was dropped")
	}
}

func TestRuleValidation(t *testing.T) {
	bad := []DPIRule{
		{When: "tls_sni", Action: "drop"},
		{When: "tls_sni", SNI: []string{"x"}, Action: "reject"},
		{When: "first_bytes_not", Action: "drop"},
		{When: "first_bytes_not", Allow: []string{"quic"}, Action: "drop"},
		{When: "sometimes", Action: "drop"},
		{When: "first_data", Action: "rst", RSTTo: "server"},
	}
	for _, r := range bad {
		if r.validate() == nil {
			t.Errorf("rule %+v validated", r)
		}
	}
}

func TestForgedRSTIsWellFormed(t *testing.T) {
	p := buildRST([4]byte{203, 0, 113, 10}, [4]byte{198, 51, 100, 2}, 443, 40000, 0x01020304, 0x0a0b0c0d, tcpRST|tcpACK)
	pk, ok := parseIPv4TCP(p)
	if !ok || pk.key.sport != 443 || pk.key.dport != 40000 || pk.seq != 0x01020304 || pk.ack != 0x0a0b0c0d || pk.flags != tcpRST|tcpACK {
		t.Fatalf("round trip: ok=%v %+v", ok, pk)
	}
	if checksum(p[:20]) != 0 {
		t.Fatal("IP header checksum does not verify")
	}
	pseudo := []byte{203, 0, 113, 10, 198, 51, 100, 2, 0, 6, 0, 20}
	if checksum(pseudo, p[20:]) != 0 {
		t.Fatal("TCP checksum does not verify")
	}
}

func TestNFQueueCodec(t *testing.T) {
	// A verdict message must be exactly what the kernel parses: nlmsghdr,
	// nfgenmsg with the queue number in network order, one 12-byte attribute.
	vh := make([]byte, 8)
	binary.BigEndian.PutUint32(vh[0:], nfAccept)
	binary.BigEndian.PutUint32(vh[4:], 77)
	m := nfqMessage(nfqMsgVerdict, 1, 0, 9, nlAttr(nfqaVerdictHdr, vh))
	if len(m) != 16+4+12 || binary.NativeEndian.Uint32(m) != uint32(len(m)) ||
		binary.NativeEndian.Uint16(m[4:]) != nfnlSubsysQueue<<8|nfqMsgVerdict || binary.BigEndian.Uint16(m[18:]) != 9 {
		t.Fatalf("verdict message malformed: % x", m)
	}
	// And a packet message as the kernel sends it parses back.
	payload := []byte{1, 2, 3, 4, 5}
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint32(hdr, 4242)
	body := append([]byte{2, 0, 0, 9}, nlAttr(nfqaPacketHdr, hdr)...)
	body = append(body, nlAttr(5 /* some other attribute */, []byte{9, 9, 9})...)
	body = append(body, nlAttr(nfqaPayload, payload)...)
	id, got, ok := nfqPacket(body)
	if !ok || id != 4242 || !bytes.Equal(got, payload) {
		t.Fatalf("nfqPacket: ok=%v id=%d payload=% x", ok, id, got)
	}
	if _, _, ok := nfqPacket([]byte{2, 0}); ok {
		t.Fatal("a truncated message parsed")
	}
}

func TestQUICProbeShapeMatchesTheRule(t *testing.T) {
	// scenarios/quic-drop.json matches: first nibble 0xC (long header, fixed
	// bit, Initial) and version 1. The probe datagram must be that shape,
	// and at least the 1200 bytes a client Initial is padded to.
	b := quicInitialShape()
	if b[0]>>4 != 0xc || binary.BigEndian.Uint32(b[1:]) != 1 || len(b) < 1200 {
		t.Fatalf("probe is not QUIC-v1-Initial shaped: first=%#x version=%d len=%d", b[0], binary.BigEndian.Uint32(b[1:]), len(b))
	}
	s, err := LoadScenario(rigDir(t), "quic-drop")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Censor.NFT) != 1 || !strings.Contains(s.Censor.NFT[0], "@th,64,4 0xc") || !strings.Contains(s.Censor.NFT[0], "@th,72,32 0x00000001") {
		t.Fatalf("quic-drop's rule changed (%v); keep quicInitialShape() in step with it", s.Censor.NFT)
	}
}

func TestCategoryFor(t *testing.T) {
	var s Scenario
	s.Name = "x"
	s.Expect = map[string]string{"*": Blocked, "a": Pass}
	s.Category = map[string]string{"b": "tcp_reset"}
	if c, err := s.CategoryFor("a"); err != nil || c != CategoryNone {
		t.Fatalf("a passing family: %q %v", c, err)
	}
	if c, err := s.CategoryFor("b"); err != nil || c != "tcp_reset" {
		t.Fatalf("b: %q %v", c, err)
	}
	if _, err := s.CategoryFor("c"); err == nil {
		t.Fatal("a blocked family with no category must be an error, not a default")
	}
}
