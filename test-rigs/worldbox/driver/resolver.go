package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// The public resolvers. DaalVpnService.kt hands Android exactly these two
// (`.addDnsServer("1.1.1.1")`, `.addDnsServer("9.9.9.9")`), so while the
// VPN is up every app's name lookup is a packet to one of them, inside the
// tunnel. In this world they live in the internet namespace, next to the
// blocked site — reachable through a relay and by no other path.
//
//	blocked.example        A → the target (the site the insider wants)
//	asker.blocked.example  A → the address the QUERY came from. This is the
//	                           path proof for DNS: through the tunnel it is
//	                           the relay's egress address and nothing else.
//
// Served over UDP and TCP on port 53, because the phone's resolver uses
// either (UDP first; TCP on truncation or when UDP is unavailable).
const (
	PublicDNS1  = "1.1.1.1"
	PublicDNS2  = "9.9.9.9"
	BlockedName = "blocked.example"
	AskerName   = "asker.blocked.example"
)

func servePublicDNS() {
	for _, ip := range []string{PublicDNS1, PublicDNS2} {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, "53"))
		if err != nil {
			log.Fatalf("resolver: udp %s: %v", ip, err)
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, "53"))
		if err != nil {
			log.Fatalf("resolver: tcp %s: %v", ip, err)
		}
		go func(ip string) {
			buf := make([]byte, 1500)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if resp := answerPublicDNS(buf[:n], hostOf(from), ip+"/udp"); resp != nil {
					_, _ = pc.WriteTo(resp, from)
				}
			}
		}(ip)
		go func(ip string) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					if resp := answerPublicDNS(q, hostOf(c.RemoteAddr()), ip+"/tcp"); resp != nil {
						binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
						_, _ = c.Write(append(l[:], resp...))
					}
				}()
			}
		}(ip)
	}
}

func hostOf(a net.Addr) string {
	h, _, _ := net.SplitHostPort(a.String())
	return h
}

// answerPublicDNS answers one single-question query. Unknown names get
// NXDOMAIN; AAAA and other types of a known name get an empty NOERROR.
func answerPublicDNS(q []byte, asker, via string) []byte {
	name, qtype, qend, ok := parseDNSQuestion(q)
	if !ok {
		return nil
	}
	resp := append([]byte{}, q[:qend]...)
	resp[2] = 0x84 | (q[2] & 0x01) // QR, AA, copy RD
	resp[3] = 0x80                 // RA, NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	var ip string
	switch name {
	case BlockedName + ".":
		ip = TargetIP
	case AskerName + ".":
		ip = asker
	default:
		resp[3] |= 3 // NXDOMAIN
		return resp
	}
	if v4 := net.ParseIP(ip).To4(); qtype == 1 && v4 != nil {
		binary.BigEndian.PutUint16(resp[6:8], 1)
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4) // TTL 0: never cached
		resp = append(resp, v4...)
	}
	log.Printf("resolver: %s type %d asked by %s via %s", name, qtype, asker, via)
	return resp
}

func parseDNSQuestion(q []byte) (name string, qtype uint16, qend int, ok bool) {
	n := len(q)
	if n < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return "", 0, 0, false
	}
	var labels []string
	i := 12
	for i < n && q[i] != 0 {
		l := int(q[i])
		if l > 63 || i+1+l > n {
			return "", 0, 0, false
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+5 > n {
		return "", 0, 0, false
	}
	return strings.ToLower(strings.Join(labels, ".")) + ".", binary.BigEndian.Uint16(q[i+1 : i+3]), i + 5, true
}

// dnsQuery builds an A query for name.
func dnsQuery(id uint16, name string) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// dnsAnswerA extracts the first A record of a response to a query built
// by dnsQuery. The owner name may be compressed or spelled out: an answer
// that passed through another DNS implementation on the way (the engine's
// own, when it answers the app itself) is re-encoded.
func dnsAnswerA(resp []byte, id uint16) (string, error) {
	_, _, qend, ok := parseDNSQuestion(resp)
	if !ok || binary.BigEndian.Uint16(resp[0:2]) != id {
		return "", fmt.Errorf("not an answer to this query")
	}
	if rcode := resp[3] & 0x0f; rcode != 0 {
		return "", fmt.Errorf("rcode %d", rcode)
	}
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	i := qend
	for ; an > 0; an-- {
		// owner name: labels until a zero byte, or a 2-byte pointer
		for i < len(resp) {
			if resp[i]&0xc0 == 0xc0 {
				i += 2
				break
			}
			if resp[i] == 0 {
				i++
				break
			}
			i += 1 + int(resp[i])
		}
		if i+10 > len(resp) {
			break
		}
		typ, rdlen := binary.BigEndian.Uint16(resp[i:i+2]), int(binary.BigEndian.Uint16(resp[i+8:i+10]))
		i += 10
		if i+rdlen > len(resp) {
			break
		}
		if typ == 1 && rdlen == 4 {
			return net.IP(resp[i : i+4]).String(), nil
		}
		i += rdlen
	}
	return "", fmt.Errorf("no A record among %d answers", binary.BigEndian.Uint16(resp[6:8]))
}
