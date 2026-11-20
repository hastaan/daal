package desync

import (
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// firstFlightWait bounds how long an incomplete first record is held.
// A TLS client writes a whole record before it reads, so the wait ends
// as soon as the rest arrives; the bound is for a non-TLS stream whose
// first bytes happen to look like a record header and that then waits
// for the server — it gets its bytes sent (and cut as a plain first
// flight) after this long instead of hanging.
const firstFlightWait = 150 * time.Millisecond

// Conn applies a Strategy to the first flight of the wrapped connection
// and is transparent afterwards. Make one with Wrap.
//
// The cut first flight never outlives the connection: Close interrupts
// its gaps at once (it does not wait for the send), the gaps stop at a
// write deadline set on the Conn, and the whole flight is bounded by
// firstFlightBudget, past which the rest is written in one piece.
type Conn struct {
	net.Conn
	s Strategy

	closed    chan struct{}
	closeOnce sync.Once
	// wdl is the write deadline last set through the Conn (UnixNano; 0:
	// none), which bounds the gaps as it bounds the Writes.
	wdl atomic.Int64

	mu      sync.Mutex
	pending []byte
	timer   *time.Timer
	err     error // a failed first-flight send, reported to every later Write
	done    atomic.Bool
}

// Wrap returns conn unchanged when the strategy cuts nothing, and a
// *Conn otherwise. The strategy should be Normalized; an unresolved
// preset is resolved here, and one that does not resolve leaves conn
// unwrapped (OFF, never an error on the data path).
func Wrap(conn net.Conn, s Strategy) net.Conn {
	n, err := s.Normalized()
	if err != nil || !n.Enabled() {
		return conn
	}
	return &Conn{Conn: conn, s: n, closed: make(chan struct{})}
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// Write buffers until the first flight is known, sends it cut per the
// strategy, and from then on writes straight through.
func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil // nothing to cut, and no reason to call the first flight over
	}
	if c.done.Load() {
		if c.err != nil {
			return 0, c.err
		}
		return c.Conn.Write(b)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done.Load() {
		if c.err != nil {
			return 0, c.err
		}
		return c.Conn.Write(b)
	}
	if c.isClosed() {
		c.finishClosedLocked()
		return 0, c.err
	}
	c.pending = append(c.pending, b...)
	need, isTLS, more := recordState(c.pending)
	if more || (isTLS && len(c.pending) < need) {
		if c.timer == nil {
			c.timer = time.AfterFunc(firstFlightWait, c.flushLate)
		}
		return len(b), nil
	}
	if err := c.flushLocked(); err != nil {
		return 0, err
	}
	return len(b), nil
}

// flushLate sends a first flight that never completed (see
// firstFlightWait).
func (c *Conn) flushLate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done.Load() {
		return
	}
	if c.isClosed() {
		c.finishClosedLocked()
		return
	}
	_ = c.flushLocked()
}

func (c *Conn) flushLocked() error {
	c.stopTimerLocked()
	first := c.pending
	c.pending = nil
	// Everything after this goes straight through — but only once the
	// first flight has left: a concurrent Write blocks on mu until then.
	// err is set before done, so a Write that sees done sees it too.
	c.err = c.send(first)
	c.done.Store(true)
	return c.err
}

func (c *Conn) stopTimerLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

// finishClosedLocked ends a first flight the connection was closed
// under: the held bytes are dropped, and every later Write says closed.
func (c *Conn) finishClosedLocked() {
	c.stopTimerLocked()
	c.pending = nil
	if !c.done.Load() {
		c.err = net.ErrClosed
		c.done.Store(true)
	}
}

func (c *Conn) send(first []byte) error {
	plan := c.s.PlanFor(first)
	segs := plan.Segments()
	if len(segs) < 2 {
		_, err := c.Conn.Write(plan.Out)
		return err
	}
	raw := rawSyscallConn(c.Conn)
	restore := setNoDelay(raw)
	defer restore()
	until := time.Now().Add(firstFlightBudget)
	if d := c.writeDeadline(); !d.IsZero() && d.Before(until) {
		until = d
	}
	rep := FlightReport{Segments: len(segs), Ack: AckDelay}
	if readTCPInfo(raw).ok {
		rep.Ack = AckTCPInfo
	}
	defer func() { record(rep) }()
	sent := 0
	for i, seg := range segs {
		if i > 0 {
			if ok := c.gap(raw, i == 1, until, &rep); !ok {
				if c.isClosed() {
					return net.ErrClosed
				}
				// Out of time: the rest in one piece (a Write past the
				// deadline fails as it would have without us).
				rep.BudgetSpent = true
				_, err := c.Conn.Write(plan.Out[sent:])
				return err
			}
		}
		if _, err := c.Conn.Write(seg); err != nil {
			return err
		}
		sent += len(seg)
	}
	return nil
}

// gap separates one segment from the next: the ACK of the one just sent
// (where the kernel can say and the strategy asks), else the kernel
// having sent it (the autocork guard), then the strategy's delay. It
// returns false when Close or the deadline `until` cut it short.
func (c *Conn) gap(raw syscall.RawConn, first bool, until time.Time, rep *FlightReport) bool {
	info := readTCPInfo(raw)
	acked := false
	if c.s.WaitAck && info.ok {
		timeout := c.s.ackTimeout()
		if first && info.rto+rtoSlack > timeout {
			timeout = info.rto + rtoSlack
		}
		acked = c.poll(raw, earlier(time.Now().Add(timeout), until), func(ti tcpInfo) bool { return ti.unacked == 0 })
		if !acked {
			rep.AckTimeouts++
		}
	}
	if !acked && info.ok {
		// Without the ACK, the segment just written may still sit in
		// the write queue (autocorked behind a busy qdisc), where the
		// next Write would join it. Wait until the kernel sent it.
		c.poll(raw, earlier(time.Now().Add(sentWait), until), func(ti tcpInfo) bool { return ti.notsent == 0 })
	}
	if c.isClosed() || !time.Now().Before(until) {
		return false
	}
	d := c.delay()
	if d == 0 && !acked {
		d = minGap
	}
	if d > 0 {
		if rest := time.Until(until); d >= rest {
			return false
		}
		return c.sleep(d)
	}
	return true
}

// poll reads TCP_INFO every millisecond until cond holds (true), or the
// deadline passes, Close is called or TCP_INFO stops answering (false).
func (c *Conn) poll(raw syscall.RawConn, until time.Time, cond func(tcpInfo) bool) bool {
	for {
		ti := readTCPInfo(raw)
		if !ti.ok {
			return false
		}
		if cond(ti) {
			return true
		}
		if !time.Now().Before(until) {
			return false
		}
		if !c.sleep(time.Millisecond) {
			return false
		}
	}
}

// sleep waits d, or until Close (false).
func (c *Conn) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.closed:
		return false
	}
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (c *Conn) delay() time.Duration {
	switch len(c.s.DelayMs) {
	case 1:
		return time.Duration(c.s.DelayMs[0]) * time.Millisecond
	case 2:
		lo, hi := c.s.DelayMs[0], c.s.DelayMs[1]
		return time.Duration(lo+rand.IntN(hi-lo+1)) * time.Millisecond
	}
	return 0
}

func (c *Conn) writeDeadline() time.Time {
	if n := c.wdl.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func (c *Conn) noteWriteDeadline(t time.Time) {
	if t.IsZero() {
		c.wdl.Store(0)
		return
	}
	c.wdl.Store(t.UnixNano())
}

// SetDeadline and SetWriteDeadline pass through, and the write deadline
// also bounds the first flight's gaps.
func (c *Conn) SetDeadline(t time.Time) error {
	c.noteWriteDeadline(t)
	return c.Conn.SetDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.noteWriteDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

// Close interrupts a first flight being sent (its gaps end, its Writes
// fail on the closed socket) and closes the connection without waiting
// for it; bytes still held were never sent and are dropped.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	err := c.Conn.Close()
	// A send in progress holds mu and finishes on its own, now quickly;
	// otherwise tidy up here. Either way nothing waits on the other.
	if c.mu.TryLock() {
		c.finishClosedLocked()
		c.mu.Unlock()
	}
	return err
}

// sing-box's buffer and splice paths look through wrappers with these
// (sing/common/network: ReaderWithUpstream, WriterWithUpstream,
// common.WithUpstream). Reads are never touched; writes are, until the
// first flight is out.

func (c *Conn) ReaderReplaceable() bool { return true }
func (c *Conn) WriterReplaceable() bool { return c.done.Load() }
func (c *Conn) Upstream() any           { return c.Conn }

// readTCPInfo is tcpInfoOf; a test replaces it to play a kernel that
// never acknowledges.
var readTCPInfo = tcpInfoOf

// tcpInfo is what the gaps read from the kernel (wait_linux.go).
type tcpInfo struct {
	ok      bool
	unacked uint32        // segments sent and not acknowledged
	notsent uint32        // bytes written and not yet sent
	rto     time.Duration // the socket's retransmission timeout
}

// rawSyscallConn finds the socket under a stack of wrappers, by the
// interfaces sing-box's wrappers expose. nil when there is none (a
// net.Pipe in a test, a userspace stack): then only delays separate
// segments, which the flight's report says (ack=delay).
func rawSyscallConn(c net.Conn) syscall.RawConn {
	var cur any = c
	for i := 0; i < 16 && cur != nil; i++ {
		if sc, ok := cur.(syscall.Conn); ok {
			if raw, err := sc.SyscallConn(); err == nil {
				return raw
			}
			return nil
		}
		switch u := cur.(type) {
		case interface{ UpstreamWriter() any }:
			cur = u.UpstreamWriter()
		case interface{ Upstream() any }:
			cur = u.Upstream()
		case interface{ NetConn() net.Conn }:
			cur = u.NetConn()
		default:
			return nil
		}
	}
	return nil
}
