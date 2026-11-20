package desync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syntheticHello is one TLS record holding a ClientHello whose
// server_name host starts at byte `at` of the record (header included)
// and that is padded to about `total` bytes — the shape of a uTLS chrome
// hello (name near 387 of ~511) or a post-quantum one (name past 1500).
func syntheticHello(t *testing.T, at, total int, name string) []byte {
	t.Helper()
	const fixed = 97 // record, handshake headers … the padding extension's header, SNI headers
	pad := at - fixed
	if pad < 0 {
		t.Fatalf("name cannot start at %d", at)
	}
	ext := func(typ uint16, body []byte) []byte {
		b := binary.BigEndian.AppendUint16(nil, typ)
		b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
		return append(b, body...)
	}
	sni := binary.BigEndian.AppendUint16(nil, uint16(3+len(name)))
	sni = append(sni, 0)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)
	var exts []byte
	exts = append(exts, ext(0x0015, make([]byte, pad))...)
	exts = append(exts, ext(0x0000, sni)...)
	if tail := total - (at + len(name)) - 4; tail > 0 {
		exts = append(exts, ext(0x0015, make([]byte, tail))...)
	}
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{0xaa}, 32)...) // random
	body = append(body, 32)
	body = append(body, bytes.Repeat([]byte{0xbb}, 32)...) // session id
	body = append(body, 0, 2, 0x13, 0x01)                  // one cipher suite
	body = append(body, 1, 0)                              // null compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 3, 1}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	if got, n := locateSNI(rec); got != at || n != len(name) {
		t.Fatalf("synthetic hello: name at %d (%d bytes), want %d", got, n, at)
	}
	return rec
}

// The review's H1: on a hello whose name is late (every real uTLS
// hello), no preset that claims to cut the name leaves it whole in one
// segment — and chain does not grow with the bytes before the name.
func TestPresetsCutALateName(t *testing.T) {
	for _, c := range []struct{ at, total int }{{147, 273}, {387, 513}, {697, 823}, {1597, 1723}} {
		h := syntheticHello(t, c.at, c.total, testSNI)
		for _, name := range []string{"sni-cut", "chain", "tlsrec-sni"} {
			p := Presets[name].PlanFor(h)
			segs := p.Segments()
			for i, seg := range segs {
				if bytes.Contains(seg, []byte(testSNI)) {
					t.Errorf("%s, name at %d: segment %d of %d holds the whole name (cuts %v)", name, c.at, i, len(segs), p.Cuts)
				}
			}
			if name == "tlsrec-sni" {
				if !bytes.Equal(recordsPayload(t, p.Out), h[5:]) {
					t.Errorf("tlsrec-sni, name at %d: the records do not join back", c.at)
				}
			} else if !bytes.Equal(bytes.Join(segs, nil), h) {
				t.Errorf("%s, name at %d: the segments do not join back", name, c.at)
			}
			if name == "sni-cut" && bytes.Contains(append(append([]byte(nil), segs[0]...), segs[1]...), []byte(testSNI)) {
				t.Errorf("sni-cut, name at %d: the first two segments hold the name", c.at)
			}
			if name == "chain" && len(segs) > 10 {
				t.Errorf("chain, name at %d: %d segments, want a handful (the pieces are across the name only)", c.at, len(segs))
			}
		}
	}
}

// Over the cap, the cuts inside the name survive; the earliest others
// fill what is left.
func TestCapKeepsTheNameCuts(t *testing.T) {
	h := syntheticHello(t, 1597, 1723, testSNI)
	s := Strategy{SplitAt: []int{1}, Chunk: 6, MaxSegments: 64} // pieces from byte 1: ~270 cuts
	p := s.PlanFor(h)
	if len(p.Cuts) != 63 {
		t.Fatalf("%d cuts, want the cap's 63", len(p.Cuts))
	}
	for _, seg := range p.Segments() {
		if bytes.Contains(seg, []byte(testSNI)) {
			t.Fatalf("a segment holds the whole name: cuts %v", p.Cuts)
		}
	}
	if p.Cuts[0] != 1 {
		t.Fatalf("the earliest cut was not kept: %v", p.Cuts[:4])
	}
}

// fakeKernel replaces TCP_INFO for one test.
func fakeKernel(t *testing.T, ti tcpInfo) {
	t.Helper()
	prev := readTCPInfo
	readTCPInfo = func(syscall.RawConn) tcpInfo { return ti }
	t.Cleanup(func() { readTCPInfo = prev })
}

// An ACK that never comes: each gap waits its timeout (counted), and the
// flight still leaves cut.
func TestAckTimeout(t *testing.T) {
	fakeKernel(t, tcpInfo{ok: true, unacked: 1})
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{1, 2}, WaitAck: true, AckTimeoutMs: 40})
	before := ReadStats()
	start := time.Now()
	if _, err := c.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 70*time.Millisecond {
		t.Fatalf("two 40 ms ACK waits took %v", el)
	}
	if got := lens(rc.got()); len(got) != 3 {
		t.Fatalf("writes %v, want 1,1,2", got)
	}
	after := ReadStats()
	if after.AckTimeouts-before.AckTimeouts != 2 || after.AckTCPInfo-before.AckTCPInfo != 1 {
		t.Fatalf("stats %+v → %+v, want two ACK timeouts on a tcpinfo flight", before, after)
	}
}

// The first gap waits at least the RTO + 50 ms: a lost first segment is
// retransmitted alone before the second is written.
func TestFirstGapCoversTheRTO(t *testing.T) {
	fakeKernel(t, tcpInfo{ok: true, unacked: 1, rto: 150 * time.Millisecond})
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{1}, WaitAck: true, AckTimeoutMs: 20})
	start := time.Now()
	if _, err := c.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 190*time.Millisecond {
		t.Fatalf("first gap %v, want ≥ RTO 150 ms + 50 ms", el)
	}
}

// Without an ACK wait, a gap still waits for the kernel to have sent the
// segment (autocork guard), bounded.
func TestAutocorkGuard(t *testing.T) {
	fakeKernel(t, tcpInfo{ok: true, notsent: 1})
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{1}})
	start := time.Now()
	if _, err := c.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < sentWait || el > sentWait+500*time.Millisecond {
		t.Fatalf("a never-sent queue held the gap %v, want about %v", el, sentWait)
	}
}

// A write deadline bounds the gaps: past it the rest leaves in one piece
// (and the budget is reported spent).
func TestWriteDeadlineBoundsTheFlight(t *testing.T) {
	fakeKernel(t, tcpInfo{ok: true, unacked: 1})
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{1, 2, 3}, WaitAck: true, AckTimeoutMs: 5000})
	_ = c.SetWriteDeadline(time.Now().Add(80 * time.Millisecond))
	before := ReadStats()
	start := time.Now()
	if _, err := c.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("the flight took %v past an 80 ms deadline", el)
	}
	got := rc.got()
	if len(got) != 2 || string(got[0]) != "a" || string(got[1]) != "bcdef" {
		t.Fatalf("writes %q, want a, then the rest whole", got)
	}
	if ReadStats().BudgetSpent-before.BudgetSpent != 1 {
		t.Fatal("budget spent not counted")
	}
}

// Close while the first record is still incomplete: nothing is sent,
// the late flush does nothing, and later Writes say closed.
func TestCloseWhilePending(t *testing.T) {
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{2}})
	if _, err := c.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(firstFlightWait + 50*time.Millisecond)
	if got := rc.got(); len(got) != 0 {
		t.Fatalf("held bytes were sent after Close: %q", got)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close: %v, want net.ErrClosed", err)
	}
}

// Close during the gaps returns at once and ends the send: it does not
// wait out a delay, and nothing more is written.
func TestCloseInterruptsTheGaps(t *testing.T) {
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{1, 2, 3}, DelayMs: []int{1000}})
	werr := make(chan error, 1)
	go func() { _, err := c.Write([]byte("abcdef")); werr <- err }()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	_ = c.Close()
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Fatalf("Close blocked %v behind the first flight", el)
	}
	select {
	case err := <-werr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the interrupted Write returned %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the Write was not interrupted by Close")
	}
	if got := rc.got(); len(got) != 1 || string(got[0]) != "a" {
		t.Fatalf("writes %q, want only the first segment", got)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close: %v", err)
	}
}

// failConn fails every Write after the first n.
type failConn struct {
	*recordConn
	mu     sync.Mutex
	n      int
	writes int
}

var errBoom = errors.New("boom")

func (f *failConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	w := f.writes
	f.mu.Unlock()
	if w > f.n {
		return 0, errBoom
	}
	return f.recordConn.Write(b)
}

// A first flight that failed fails every later Write the same way, and
// nothing more reaches the socket.
func TestFirstFlightErrorSticks(t *testing.T) {
	fc := &failConn{recordConn: newRecordConn(), n: 1}
	c := Wrap(fc, Strategy{SplitAt: []int{1}})
	if _, err := c.Write([]byte("abc")); !errors.Is(err, errBoom) {
		t.Fatalf("first Write: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Write([]byte("later")); !errors.Is(err, errBoom) {
			t.Fatalf("later Write %d: %v", i, err)
		}
	}
	if fc.writes != 2 {
		t.Fatalf("%d writes reached the socket, want the two of the failed flight", fc.writes)
	}
}

// Writes and Close racing (run under -race): no data race, no deadlock.
func TestConcurrentWriteAndClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		rc := newRecordConn()
		c := Wrap(rc, Strategy{SplitAt: []int{1, 2}, DelayMs: []int{0, 2}})
		var wg sync.WaitGroup
		for w := 0; w < 3; w++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = c.Write([]byte("abc")) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Close() }()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Write/Close deadlocked")
		}
	}
}

// Without a socket under the wrappers the flight is cut on sleeps alone,
// and says so once (ack=delay).
func TestDelayOnlyIsReported(t *testing.T) {
	var lines []string
	var mu sync.Mutex
	SetLogger(func(s string) { mu.Lock(); lines = append(lines, s); mu.Unlock() })
	logMu.Lock()
	logSeen = map[string]bool{}
	logMu.Unlock()
	t.Cleanup(func() { SetLogger(nil) })
	before := ReadStats()
	for i := 0; i < 2; i++ {
		c := Wrap(newRecordConn(), Strategy{SplitAt: []int{1}})
		if _, err := c.Write([]byte("ab")); err != nil {
			t.Fatal(err)
		}
	}
	if d := ReadStats().AckDelay - before.AckDelay; d != 2 {
		t.Fatalf("ack=delay counted %d times, want 2", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(strings.Join(lines, "\n"), "ack=delay"); n != 1 {
		t.Fatalf("ack=delay logged %d times, want once: %q", n, lines)
	}
}
