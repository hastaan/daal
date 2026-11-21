package main

import (
	"testing"
	"time"
)

func at(base time.Time, ms int) int64 {
	return base.Add(time.Duration(ms) * time.Millisecond).UnixNano()
}

// The race the engine promises: two silent routes beside each other,
// then a third alone. Retransmitted SYNs are not new flows.
func TestFlowUses_ARaceOfTwoThenOneIsTwoAtATime(t *testing.T) {
	b := time.Unix(1_700_000_000, 0)
	pk := []flowPacket{
		{T: at(b, 10), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 300), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 1010), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 1300), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 3010), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 3300), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 4500), Proto: "udp", Sport: 50001, Dport: 443},
		{T: at(b, 4600), Proto: "udp", Sport: 50001, Dport: 443},
	}
	uses := flowUses(pk, b, b.Add(5*time.Second))
	if len(uses) != 3 || uses[0].Endpoint != "tcp/443" || uses[1].Endpoint != "tcp/8445" || uses[2].Endpoint != "udp/443" {
		t.Fatalf("uses = %+v", uses)
	}
	for _, u := range uses {
		if u.Flows != 1 {
			t.Fatalf("%s: %d flows, want 1 (a retransmitted SYN is not a new flow)", u.Endpoint, u.Flows)
		}
	}
	if n, set := maxConcurrent(uses); n != 2 || set[0] != "tcp/443" || set[1] != "tcp/8445" {
		t.Fatalf("max concurrent = %d %v, want 2 (tcp/443, tcp/8445)", n, set)
	}
}

// What the check exists to catch: three routes started together.
func TestFlowUses_ThreeStartedTogetherIsThree(t *testing.T) {
	b := time.Unix(1_700_000_000, 0)
	pk := []flowPacket{
		{T: at(b, 10), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 200), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 400), Proto: "udp", Sport: 50001, Dport: 443},
		{T: at(b, 1010), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 1200), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 1400), Proto: "udp", Sport: 50001, Dport: 443},
	}
	if n, _ := maxConcurrent(flowUses(pk, b, b.Add(5*time.Second))); n != 3 {
		t.Fatalf("max concurrent = %d, want 3", n)
	}
}

// One after another, each over before the next begins: one at a time,
// however many endpoints.
func TestFlowUses_OneAfterAnotherIsOne(t *testing.T) {
	b := time.Unix(1_700_000_000, 0)
	pk := []flowPacket{
		{T: at(b, 10), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 3010), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 4100), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 7100), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true},
		{T: at(b, 8200), Proto: "udp", Sport: 50001, Dport: 443},
	}
	if n, _ := maxConcurrent(flowUses(pk, b, b.Add(9*time.Second))); n != 1 {
		t.Fatalf("max concurrent = %d, want 1", n)
	}
}

// The tail of the session before (a flow first seen before the window)
// is not this pass's, whatever it still sends; a packet after the window
// is not either. A source port the kernel hands out again is a new flow
// once a SYN says so.
func TestFlowUses_OnlyFlowsThatBeganInTheWindow(t *testing.T) {
	b := time.Unix(1_700_000_000, 0)
	pk := []flowPacket{
		{T: at(b, -500), Proto: "udp", Sport: 50001, Dport: 443},
		{T: at(b, -400), Proto: "tcp", Sport: 40009, Dport: 8444, Syn: true},
		{T: at(b, 100), Proto: "udp", Sport: 50001, Dport: 443},  // old QUIC session's close
		{T: at(b, 150), Proto: "tcp", Sport: 40009, Dport: 8444}, // old connection's FIN
		{T: at(b, 200), Proto: "tcp", Sport: 40001, Dport: 8445, Syn: true},
		{T: at(b, 250), Proto: "tcp", Sport: 40001, Dport: 8445},
		{T: at(b, 300), Proto: "tcp", Sport: 40009, Dport: 8444, Syn: true}, // the port again: a new connection
		{T: at(b, 2500), Proto: "tcp", Sport: 40003, Dport: 443, Syn: true}, // after the window
		{T: at(b, 900), Proto: "tcp", Sport: 55452, Dport: 443},             // mid-stream, never seen to begin: an orphan from before the tap
	}
	uses := flowUses(pk, b, b.Add(2*time.Second))
	if len(uses) != 2 || uses[0].Endpoint != "tcp/8445" || uses[1].Endpoint != "tcp/8444" {
		t.Fatalf("uses = %+v, want tcp/8445 then tcp/8444", uses)
	}
	if uses[0].Flows != 1 || uses[1].Flows != 1 {
		t.Fatalf("flows = %+v", uses)
	}
}

func TestParseFlowPacket(t *testing.T) {
	src, relay, other := [4]byte{198, 51, 100, 2}, [4]byte{203, 0, 113, 10}, [4]byte{192, 0, 2, 1}
	dsts := map[[4]byte]bool{relay: true}
	ip := func(proto byte, s, d [4]byte, l4 []byte) []byte {
		h := make([]byte, 20)
		h[0], h[9] = 0x45, proto
		copy(h[12:16], s[:])
		copy(h[16:20], d[:])
		return append(h, l4...)
	}
	tcp := func(sport, dport uint16, flags byte) []byte {
		b := make([]byte, 20)
		b[0], b[1], b[2], b[3], b[13] = byte(sport>>8), byte(sport), byte(dport>>8), byte(dport), flags
		return b
	}
	if pk, _, ok := parseFlowPacket(ip(6, src, relay, tcp(40001, 8445, 0x02)), src, dsts); !ok || pk.Proto != "tcp" || pk.Sport != 40001 || pk.Dport != 8445 || !pk.Syn {
		t.Fatalf("SYN: %+v %v", pk, ok)
	}
	if pk, _, ok := parseFlowPacket(ip(6, src, relay, tcp(40001, 8445, 0x10)), src, dsts); !ok || pk.Syn {
		t.Fatalf("ACK: %+v %v", pk, ok)
	}
	if pk, _, ok := parseFlowPacket(ip(17, src, relay, []byte{0xc3, 0x51, 0x01, 0xbb, 0, 8, 0, 0}), src, dsts); !ok || pk.Proto != "udp" || pk.Sport != 50001 || pk.Dport != 443 {
		t.Fatalf("UDP: %+v %v", pk, ok)
	}
	if _, _, ok := parseFlowPacket(ip(6, src, other, tcp(1, 2, 2)), src, dsts); ok {
		t.Fatal("a packet to somewhere that is not the relay was kept")
	}
	if _, _, ok := parseFlowPacket(ip(6, relay, src, tcp(1, 2, 0x12)), src, dsts); ok {
		t.Fatal("the relay's answer was kept as the client's packet")
	}
	if _, _, ok := parseFlowPacket(ip(1, src, relay, make([]byte, 8)), src, dsts); ok {
		t.Fatal("ICMP was kept")
	}
}

// The client's segment sizes: a data packet's TCP payload length is
// read off the IP total length and the TCP data offset, and
// firstSegments groups the first ones per flow that began in the window.
func TestFlowTapSegmentSizes(t *testing.T) {
	src, relay := [4]byte{198, 51, 100, 2}, [4]byte{203, 0, 113, 10}
	pkt := make([]byte, 20+20+7)
	pkt[0], pkt[9] = 0x45, 6
	pkt[2], pkt[3] = 0, byte(len(pkt))
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], relay[:])
	tcp := pkt[20:]
	tcp[0], tcp[1], tcp[2], tcp[3] = 0x9c, 0x41, 0x01, 0xbb // 40001 → 443
	tcp[12], tcp[13] = 5<<4, 0x18                           // doff 20, PSH|ACK
	copy(tcp[20:], "payload")
	if pk, payload, ok := parseFlowPacket(pkt, src, map[[4]byte]bool{relay: true}); !ok || pk.Data != 7 || pk.Syn || string(payload) != "payload" {
		t.Fatalf("data packet: %+v %q %v", pk, payload, ok)
	}
	// A total length past the captured bytes: the size, no payload.
	if _, payload, ok := parseFlowPacket(pkt[:len(pkt)-2], src, map[[4]byte]bool{relay: true}); !ok || payload != nil {
		t.Fatalf("truncated capture: %q %v", payload, ok)
	}

	b := time.Unix(1_700_000_000, 0)
	pk := []flowPacket{
		{T: at(b, -500), Proto: "tcp", Sport: 39999, Dport: 443, Syn: true}, // before the window
		{T: at(b, -400), Proto: "tcp", Sport: 39999, Dport: 443, Data: 600},
		{T: at(b, 10), Proto: "tcp", Sport: 40001, Dport: 443, Syn: true},
		{T: at(b, 20), Proto: "tcp", Sport: 40001, Dport: 443, Data: 1},
		{T: at(b, 25), Proto: "tcp", Sport: 40001, Dport: 443, Data: 120},
		{T: at(b, 30), Proto: "tcp", Sport: 40001, Dport: 443, Data: 480},
		{T: at(b, 40), Proto: "tcp", Sport: 40002, Dport: 8445, Syn: true}, // another endpoint
		{T: at(b, 45), Proto: "tcp", Sport: 40002, Dport: 8445, Data: 700},
		{T: at(b, 50), Proto: "tcp", Sport: 40003, Dport: 443, Syn: true},
		{T: at(b, 60), Proto: "tcp", Sport: 40003, Dport: 443, Data: 1},
	}
	got := firstSegments(pk, 443, b, b.Add(time.Second))
	if len(got) != 2 || len(got[0]) != 3 || got[0][0] != 1 || got[0][1] != 120 || len(got[1]) != 1 || got[1][0] != 1 {
		t.Fatalf("firstSegments = %v", got)
	}
}
