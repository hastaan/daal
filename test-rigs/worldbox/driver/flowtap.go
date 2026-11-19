package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// The flow tap: WHEN the client opened each connection to the relay.
//
// The wire tap (wire.go) counts, per session, what crossed the censor and
// to which endpoint. It cannot say that two things happened at the same
// time, and since the automatic connect began checking two routes beside
// each other (core/abi/connect_race.go) that is the question: the engine
// promises never to have more than two routes in flight, because one
// phone starting every handshake it knows to one relay address in the
// same second is a burst a censor can recognise — and block every route
// of the file for.
//
// A promise about what a censor sees is checked where the censor sits.
// `wb flows` is a packet socket on the censor's client-side interface: it
// writes one line per packet the client sends to the relay's addresses —
// time, protocol, source port, destination port, SYN — thinned to one
// line per flow per 50 ms once a flow is known (a QUIC session carrying a
// megabyte is thousands of packets and two facts: when it began and when
// it was last seen). It filters nothing and sees a packet before the
// censor's rules do: a SYN the censor then drops is still an attempt.
//
// What is judged (flowUses, maxConcurrent): a FLOW is a 5-tuple, new when
// its first packet falls inside the window asked about — for TCP, when
// that packet is a SYN (a retransmitted SYN is not a new flow; conntrack would call it one, because a dropped
// SYN never confirms an entry — which is why this is not an nft counter;
// a connection first seen mid-stream is an older one's leftovers).
// A relay ENDPOINT (protocol and port: one per route in the lab) is IN USE
// from the first packet of its first new flow to the last packet of any
// of them. The number of endpoints in use at one moment is the number of
// routes the phone has in flight as the censor sees it.
//
// What that cannot see: the end of an attempt that is being dropped. A
// silent endpoint is "in use" until the client's last retransmission,
// which is up to a second or so before the engine gives up (TCP SYNs go
// out at 0, 1 and 3 s of a 4 s budget). An engine that started a third
// route in that last second would not be caught here; one that starts
// three together is. The engine's own account (`auto.racing` never names
// more than two; raced_with pairs) is asserted beside it.
type flowPacket struct {
	T     int64  `json:"t"` // unix ns
	Proto string `json:"p"` // tcp | udp
	Sport int    `json:"s"`
	Dport int    `json:"d"`
	Syn   bool   `json:"syn,omitempty"`
}

const flowThin = 50 * time.Millisecond

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// cmdFlows is `wb flows --dev D --src A --dst A[,A…] --out F --ready F`.
func cmdFlows(args []string) int {
	fs := flag.NewFlagSet("flows", flag.ExitOnError)
	dev := fs.String("dev", "", "interface to listen on")
	src := fs.String("src", "", "the client's address")
	dst := fs.String("dst", "", "comma list: the relay's addresses")
	outPath := fs.String("out", "", "packet log (JSON lines, appended)")
	ready := fs.String("ready", "", "file created once the socket is bound")
	_ = fs.Parse(args)
	ifc, err := net.InterfaceByName(*dev)
	if err != nil {
		fmt.Fprintln(os.Stderr, "flows:", err)
		return 1
	}
	var srcIP [4]byte
	copy(srcIP[:], net.ParseIP(*src).To4())
	dsts := map[[4]byte]bool{}
	for _, d := range strings.Split(*dst, ",") {
		var a [4]byte
		if ip := net.ParseIP(strings.TrimSpace(d)).To4(); ip != nil {
			copy(a[:], ip)
			dsts[a] = true
		}
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "flows: socket:", err)
		return 1
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_IP), Ifindex: ifc.Index}); err != nil {
		fmt.Fprintln(os.Stderr, "flows: bind:", err)
		return 1
	}
	f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "flows:", err)
		return 1
	}
	if *ready != "" {
		_ = os.WriteFile(*ready, nil, 0o644)
	}
	type key struct {
		udp          bool
		sport, dport int
	}
	last := map[key]int64{}
	enc := json.NewEncoder(f)
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			fmt.Fprintln(os.Stderr, "flows: recv:", err)
			return 1
		}
		pk, ok := parseFlowPacket(buf[:n], srcIP, dsts)
		if !ok {
			continue
		}
		pk.T = time.Now().UnixNano()
		k := key{pk.Proto == "udp", pk.Sport, pk.Dport}
		if t, seen := last[k]; seen && !pk.Syn && pk.T-t < int64(flowThin) {
			continue
		}
		last[k] = pk.T
		_ = enc.Encode(pk)
	}
}

// parseFlowPacket reads one IPv4 packet: the client's, to the relay, TCP
// or UDP, first fragment.
func parseFlowPacket(b []byte, src [4]byte, dsts map[[4]byte]bool) (flowPacket, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return flowPacket{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+8 {
		return flowPacket{}, false
	}
	var s, d [4]byte
	copy(s[:], b[12:16])
	copy(d[:], b[16:20])
	if s != src || !dsts[d] {
		return flowPacket{}, false
	}
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return flowPacket{}, false // a later fragment has no ports
	}
	l4 := b[ihl:]
	pk := flowPacket{Sport: int(binary.BigEndian.Uint16(l4[0:2])), Dport: int(binary.BigEndian.Uint16(l4[2:4]))}
	switch b[9] {
	case syscall.IPPROTO_TCP:
		if len(l4) < 14 {
			return flowPacket{}, false
		}
		pk.Proto = "tcp"
		pk.Syn = l4[13]&0x12 == 0x02 // SYN without ACK
	case syscall.IPPROTO_UDP:
		pk.Proto = "udp"
	default:
		return flowPacket{}, false
	}
	return pk, true
}

// ---- the driver's side ---------------------------------------------------

// flowTapPath is the packet log of this world.
func flowTapPath(p Paths) string { return filepath.Join(p.Run, "flows.jsonl") }

// StartFlowTap starts the tap in the censor namespace (once per world;
// it lives until the world is torn down).
func StartFlowTap(ctx context.Context, p Paths) error {
	ready := filepath.Join(p.Run, "flows.ready")
	if _, err := os.Stat(ready); err == nil {
		return nil
	}
	dst := strings.Join(append([]string{Relay1IP}, FloatingIPPool...), ",")
	if _, err := Spawn(p, "flows", nil, inNS(NSCensor, filepath.Join(p.Bin, "wb"), "flows", "--dev", CensorDevClient,
		"--src", ClientIP, "--dst", dst, "--out", flowTapPath(p), "--ready", ready)...); err != nil {
		return err
	}
	if !waitFor(ctx, 5*time.Second, func() bool { _, err := os.Stat(ready); return err == nil }) {
		return fmt.Errorf("the flow tap did not bind its socket; see logs/flows.log")
	}
	return nil
}

// ReadFlowTap returns every packet logged so far.
func ReadFlowTap(p Paths) ([]flowPacket, error) {
	f, err := os.Open(flowTapPath(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []flowPacket
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var pk flowPacket
		if json.Unmarshal(sc.Bytes(), &pk) == nil && pk.T != 0 {
			out = append(out, pk)
		}
	}
	return out, sc.Err()
}

// endpointUse is one relay endpoint as the censor saw the client use it
// inside a window.
type endpointUse struct {
	Endpoint    string // "tcp/443"
	First, Last int64  // unix ns: first packet of the first new flow, last packet of any new flow
	Flows       int    // new flows (5-tuples) opened to it
}

// flowUses reduces a packet log to the endpoints the client opened NEW
// flows to between from and to, in the order they were first used. A
// flow whose first packet is older than the window is not new and is
// left out with all its packets (the previous session's tail).
func flowUses(pkts []flowPacket, from, to time.Time) []endpointUse {
	type key struct {
		proto        string
		sport, dport int
	}
	lo, hi := from.UnixNano(), to.UnixNano()
	old := map[key]bool{}
	seen := map[key]bool{}
	uses := map[string]*endpointUse{}
	var order []string
	sorted := append([]flowPacket(nil), pkts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].T < sorted[j].T })
	for _, pk := range sorted {
		k := key{pk.Proto, pk.Sport, pk.Dport}
		if pk.T < lo {
			// A TCP port is reused only by a new SYN; a UDP 5-tuple seen
			// before the window stays the old flow.
			old[k] = true
			continue
		}
		if pk.T > hi {
			break
		}
		if pk.Syn && old[k] && !seen[k] {
			delete(old, k) // the same source port, a new connection
		}
		if pk.Proto == "tcp" && !pk.Syn && !seen[k] {
			// A TCP connection begins with a SYN and the tap logs every
			// one. A 5-tuple that turns up mid-stream was opened before
			// the tap was there to see it: an orphan of some earlier
			// session still retransmitting (seen: one packet, minutes
			// after its owner had gone).
			old[k] = true
		}
		if old[k] {
			continue
		}
		ep := fmt.Sprintf("%s/%d", pk.Proto, pk.Dport)
		u := uses[ep]
		if u == nil {
			u = &endpointUse{Endpoint: ep, First: pk.T}
			uses[ep] = u
			order = append(order, ep)
		}
		if !seen[k] {
			seen[k] = true
			u.Flows++
		}
		u.Last = pk.T
	}
	out := make([]endpointUse, 0, len(order))
	for _, ep := range order {
		out = append(out, *uses[ep])
	}
	return out
}

// maxConcurrent is the largest number of endpoints in use at one moment,
// and which they were.
func maxConcurrent(uses []endpointUse) (int, []string) {
	type edge struct {
		t    int64
		open bool
		ep   string
	}
	var edges []edge
	for _, u := range uses {
		edges = append(edges, edge{u.First, true, u.Endpoint}, edge{u.Last, false, u.Endpoint})
	}
	// At one instant an opening counts before a closing: two uses that
	// touch were both there.
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].t != edges[j].t {
			return edges[i].t < edges[j].t
		}
		return edges[i].open && !edges[j].open
	})
	open := map[string]bool{}
	best, bestSet := 0, []string(nil)
	for _, e := range edges {
		if !e.open {
			delete(open, e.ep)
			continue
		}
		open[e.ep] = true
		if len(open) > best {
			best = len(open)
			bestSet = bestSet[:0]
			for ep := range open {
				bestSet = append(bestSet, ep)
			}
			sort.Strings(bestSet)
		}
	}
	return best, bestSet
}

// flowText is the uses as one line of evidence, times relative to from.
func flowText(uses []endpointUse, from time.Time) string {
	var parts []string
	for _, u := range uses {
		parts = append(parts, fmt.Sprintf("%s %d–%d ms (%d flow(s))", u.Endpoint,
			(u.First-from.UnixNano())/1e6, (u.Last-from.UnixNano())/1e6, u.Flows))
	}
	return strings.Join(parts, "; ")
}
