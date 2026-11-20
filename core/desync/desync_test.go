package desync

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSNI = "www.cover-host.example"

// recordConn is a net.Conn that records every Write and can hand back
// nothing on Read (the far side never answers).
type recordConn struct {
	mu     sync.Mutex
	writes [][]byte
	closed chan struct{}
	once   sync.Once
}

func newRecordConn() *recordConn { return &recordConn{closed: make(chan struct{})} }

func (r *recordConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (r *recordConn) Read([]byte) (int, error)         { <-r.closed; return 0, errors.New("closed") }
func (r *recordConn) Close() error                     { r.once.Do(func() { close(r.closed) }); return nil }
func (r *recordConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (r *recordConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (r *recordConn) SetDeadline(time.Time) error      { return nil }
func (r *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (r *recordConn) SetWriteDeadline(time.Time) error { return nil }
func (r *recordConn) got() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.writes...)
}

// realHello is the first flight crypto/tls sends for testSNI: one TLS
// record holding the ClientHello.
func realHello(t *testing.T) []byte {
	t.Helper()
	rc := newRecordConn()
	c := tls.Client(rc, &tls.Config{ServerName: testSNI, MinVersion: tls.VersionTLS12})
	done := make(chan struct{})
	go func() { _ = c.Handshake(); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(rc.got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_ = rc.Close()
	<-done
	w := rc.got()
	if len(w) == 0 {
		t.Fatal("crypto/tls wrote no ClientHello")
	}
	hello := w[0]
	if _, ok := parseRecord(hello); !ok {
		t.Fatalf("first write is not one complete record (%d bytes)", len(hello))
	}
	return hello
}

func TestParseStrategy(t *testing.T) {
	ok := map[string]Strategy{
		`{}`:                   Off,
		`{"preset":"sni-cut"}`: Presets["sni-cut"],
		`{"preset":"chain"}`:   Presets["chain"],
		`{"split_at":[1,6],"delay_ms":[1,2],"wait_ack":true,"ack_timeout_ms":100}`: {SplitAt: []int{1, 6}, DelayMs: []int{1, 2}, WaitAck: true, AckTimeoutMs: 100},
		`{"record_split_at":[10],"record_cut":true}`:                               {RecordSplitAt: []int{10}, RecordCut: true},
		`{"chunk":6,"chunk_until":120,"max_segments":32}`:                          {Chunk: 6, ChunkUntil: 120, MaxSegments: 32},
		`{"chunk":6,"chunk_from_sni":true}`:                                        {Chunk: 6, ChunkFromSNI: true},
	}
	for in, want := range ok {
		got, err := ParseStrategy([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %+v, want %+v", in, got, want)
		}
	}
	bad := []string{
		`{"preset":"nope"}`,
		`{"preset":"sni-cut","split_at":[2]}`, // a preset is alone
		`{"preset":"sni-cut","wait_ack":true}`,
		`{"split_at":[0]}`,
		`{"split_at":[99999]}`,
		`{"splitat":[1]}`, // strict: a typo is not "off with a default"
		`{"delay_ms":[5,1]}`,
		`{"delay_ms":[1,2,3]}`,
		`{"chunk_until":10}`,
		`{"chunk_from_sni":true}`,
		`{"preset":"chain","chunk_from_sni":true}`,
		`{"record_cut":true}`,
		`{"ack_timeout_ms":10}`,
		`{"max_segments":1,"split_at":[1]}`,
		`{"max_segments":999}`,
		`{"split_at":[1]} {}`,
		`[1]`,
	}
	for _, in := range bad {
		if s, err := ParseStrategy([]byte(in)); err == nil {
			t.Errorf("%s: accepted as %+v", in, s)
		} else if s.Enabled() {
			t.Errorf("%s: an invalid strategy must come back OFF", in)
		}
	}
	if Off.Enabled() {
		t.Error("the zero strategy cuts something")
	}
	for name, p := range Presets {
		if !p.Enabled() {
			t.Errorf("preset %s cuts nothing", name)
		}
		if _, err := p.Normalized(); err != nil {
			t.Errorf("preset %s does not validate: %v", name, err)
		}
	}
}

func TestLocateSNI(t *testing.T) {
	h := realHello(t)
	at, n := locateSNI(h)
	if at < 0 || string(h[at:at+n]) != testSNI {
		t.Fatalf("locateSNI = (%d,%d), want the name %q", at, n, testSNI)
	}
	// No name: a hello without server_name → (-1, 0), and the other cuts
	// still apply (no SNI gate).
	rc := newRecordConn()
	c := tls.Client(rc, &tls.Config{InsecureSkipVerify: true})
	go func() { _ = c.Handshake() }()
	for len(rc.got()) == 0 {
		time.Sleep(time.Millisecond)
	}
	_ = rc.Close()
	noName := rc.got()[0]
	if at, _ := locateSNI(noName); at != -1 {
		t.Fatalf("found a name in a hello without one at %d", at)
	}
	p := Presets["sni-cut"].PlanFor(noName)
	if !reflect.DeepEqual(p.Cuts, []int{1}) {
		t.Fatalf("sni-cut on a nameless hello: cuts %v, want [1] (the name is a cut, not a gate)", p.Cuts)
	}
	// Garbage never panics and never finds a name.
	for _, g := range [][]byte{nil, {0x16}, {0x16, 3, 1, 0, 4, 1, 0, 0, 0}, bytes.Repeat([]byte{0x16, 3, 3, 0xff}, 50)} {
		if at, _ := locateSNI(g); at != -1 {
			t.Errorf("garbage %x: name at %d", g, at)
		}
	}
}

func TestPlanForPresets(t *testing.T) {
	h := realHello(t)
	at, n := locateSNI(h)

	p := Presets["split1"].PlanFor(h)
	if !reflect.DeepEqual(p.Cuts, []int{1}) || !bytes.Equal(p.Out, h) {
		t.Fatalf("split1: cuts %v", p.Cuts)
	}

	p = Presets["sni-cut"].PlanFor(h)
	want := []int{1, at + n/2}
	if !reflect.DeepEqual(p.Cuts, want) {
		t.Fatalf("sni-cut: cuts %v, want %v", p.Cuts, want)
	}
	segs := p.Segments()
	if len(segs) != 3 || !bytes.Equal(bytes.Join(segs, nil), h) {
		t.Fatalf("sni-cut: %d segments, or they do not join back into the hello", len(segs))
	}
	// The property the strategy exists for: neither of the first two
	// segments, nor both together, carries the whole name.
	firstTwo := append(append([]byte(nil), segs[0]...), segs[1]...)
	if bytes.Contains(firstTwo, []byte(testSNI)) {
		t.Fatal("sni-cut: the first two segments together still hold the whole name")
	}

	// chain: one byte, the bytes up to the name, then 6-byte pieces
	// across the name — wherever the name is.
	p = Presets["chain"].PlanFor(h)
	want = []int{1}
	for c := at; c < at+n; c += 6 {
		want = append(want, c)
	}
	want = append(want, at+n)
	if !reflect.DeepEqual(p.Cuts, want) {
		t.Fatalf("chain: cuts %v, want %v", p.Cuts, want)
	}

	p = Presets["tlsrec-sni"].PlanFor(h)
	if len(p.Out) != len(h)+5 || len(p.Cuts) != 1 {
		t.Fatalf("tlsrec-sni: out %d bytes (hello %d), cuts %v", len(p.Out), len(h), p.Cuts)
	}
	payload := recordsPayload(t, p.Out)
	if !bytes.Equal(payload, h[5:]) {
		t.Fatal("tlsrec-sni: the records' payloads do not join back into the hello")
	}
	if !bytes.Equal(p.Out[p.Cuts[0]:p.Cuts[0]+3], h[:3]) {
		t.Fatal("tlsrec-sni: the TCP cut is not at the second record's header")
	}
	if bytes.Contains(p.Out[:p.Cuts[0]], []byte(testSNI)) || bytes.Contains(p.Out[p.Cuts[0]:], []byte(testSNI)) {
		t.Fatal("tlsrec-sni: one record still holds the whole name")
	}

	// Cuts beyond the first flight are dropped, never deferred.
	far := Strategy{SplitAt: []int{1, len(h) + 100}}
	if got := far.PlanFor(h).Cuts; !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("a cut past the first record survived: %v", got)
	}
	// max_segments caps the count: with no name, the earliest are kept.
	capped := Strategy{Chunk: 1, ChunkUntil: 200, MaxSegments: 4}
	if got := capped.PlanFor(bytes.Repeat([]byte("x"), 300)).Cuts; !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("max_segments 4: cuts %v", got)
	}
	// With a name, the cuts inside it are kept first.
	if got := capped.PlanFor(h).Cuts; !reflect.DeepEqual(got, []int{at + 1, at + 2, at + 3}) {
		t.Fatalf("max_segments 4 on a hello: cuts %v, want the first three inside the name at %d", got, at)
	}
}

func recordsPayload(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 0x16 {
			t.Fatalf("not a record at %x", b[:min(len(b), 5)])
		}
		l := int(binary.BigEndian.Uint16(b[3:5]))
		out = append(out, b[5:5+l]...)
		b = b[5+l:]
	}
	return out
}

// A hello that arrives in several Writes (a post-quantum-sized REALITY
// hello may) is cut exactly where it would be had it come in one.
func TestConnMultiWriteHello(t *testing.T) {
	h := realHello(t)
	s := Strategy{SplitAt: []int{1}, SNICut: true, DelayMs: []int{0}}
	want := s.PlanFor(h).Segments()
	for _, chunks := range [][]int{{len(h)}, {5, len(h) - 5}, {3, 2, 100, len(h) - 105}, {1, 1, 1, 1, 1, len(h) - 5}} {
		rc := newRecordConn()
		c := Wrap(rc, s)
		off := 0
		for _, n := range chunks {
			k, err := c.Write(h[off : off+n])
			if err != nil || k != n {
				t.Fatalf("chunks %v: Write = %d, %v", chunks, k, err)
			}
			off += n
		}
		if got := rc.got(); !reflect.DeepEqual(got, want) {
			t.Fatalf("chunks %v: wrote %d pieces %v, want %d %v", chunks, len(got), lens(got), len(want), lens(want))
		}
		// After the first flight: straight through, untouched.
		_, _ = c.Write([]byte("after"))
		if got := rc.got(); string(got[len(got)-1]) != "after" {
			t.Fatal("a write after the first flight was not passed through as is")
		}
	}
}

// A first Write that carries more than the first record: the record is
// cut, the rest follows unchanged.
func TestConnRecordPlusTail(t *testing.T) {
	h := realHello(t)
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{1}})
	in := append(append([]byte(nil), h...), []byte("tail")...)
	if _, err := c.Write(in); err != nil {
		t.Fatal(err)
	}
	got := rc.got()
	if len(got) != 2 || len(got[0]) != 1 || !bytes.Equal(bytes.Join(got, nil), in) {
		t.Fatalf("pieces %v", lens(got))
	}
}

func TestConnNonTLSFirstWrite(t *testing.T) {
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{3, 7}})
	if _, err := c.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("klm"))
	want := []string{"abc", "defg", "hij", "klm"}
	var got []string
	for _, w := range rc.got() {
		got = append(got, string(w))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Bytes that look like the start of a record and never complete one are
// sent after firstFlightWait instead of being held forever.
func TestConnIncompleteRecordIsFlushed(t *testing.T) {
	rc := newRecordConn()
	c := Wrap(rc, Strategy{SplitAt: []int{2}})
	head := []byte{0x16, 0x03, 0x01, 0x10, 0x00, 'x', 'y', 'z'} // claims 4096 bytes
	if _, err := c.Write(head); err != nil {
		t.Fatal(err)
	}
	if len(rc.got()) != 0 {
		t.Fatal("an incomplete record was sent at once")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(rc.got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := bytes.Join(rc.got(), nil); !bytes.Equal(got, head) {
		t.Fatalf("after the wait: %x, want %x", got, head)
	}
	_ = c.Close()
}

func TestWrapOffIsIdentity(t *testing.T) {
	rc := newRecordConn()
	for _, s := range []Strategy{Off, {Preset: "nope"}, {SplitAt: []int{0}}} {
		if c := Wrap(rc, s); c != net.Conn(rc) {
			t.Errorf("Wrap(%+v) wrapped the conn", s)
		}
	}
}

// The segmentation on a real loopback TCP pair: the receiver's reads
// show the segment boundaries (the gaps are long enough that no two
// segments wait in the receive buffer together), Nagle is restored to
// what it was, and the stream is intact.
func TestLoopbackSegmentBoundaries(t *testing.T) {
	h := realHello(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	reads := make(chan []int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			reads <- nil
			return
		}
		defer c.Close()
		var ns []int
		total := 0
		buf := make([]byte, 64<<10)
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for total < len(h)+5 {
			n, err := c.Read(buf)
			if n > 0 {
				ns = append(ns, n)
				total += n
			}
			if err != nil {
				break
			}
		}
		reads <- ns
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	if err := tcp.SetNoDelay(false); err != nil {
		t.Fatal(err)
	}
	s := Strategy{SplitAt: []int{1}, SNICut: true, WaitAck: true, DelayMs: []int{60}}
	want := lens(s.PlanFor(h).Segments())
	c := Wrap(raw, s)
	// Two writes for the hello: the multi-Write path on a real socket.
	if _, err := c.Write(h[:40]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(h[40:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	got := <-reads
	// The trailing "after" may arrive with the last segment or alone.
	if len(got) > 0 && len(got) == len(want)+1 && got[len(got)-1] == 5 {
		got = got[:len(got)-1]
	} else if len(got) == len(want) {
		got[len(got)-1] -= 5
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("receiver read %v, want segment sizes %v", got, want)
	}
	if nd := noDelay(t, tcp); nd {
		t.Fatal("TCP_NODELAY left on: it was off before the first flight")
	}
}

func lens(bs [][]byte) []int {
	var out []int
	for _, b := range bs {
		out = append(out, len(b))
	}
	return out
}

func TestRawSyscallConnUnwraps(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	wrapped := &upstreamConn{Conn: &upstreamConn{Conn: raw}}
	if rawSyscallConn(wrapped) == nil {
		t.Fatal("did not find the socket under two Upstream() wrappers")
	}
	if rawSyscallConn(newRecordConn()) != nil {
		t.Fatal("found a socket in a conn that has none")
	}
	if !strings.Contains(Type, "desync") || Tag == "" {
		t.Fatal("names")
	}
}

type upstreamConn struct{ net.Conn }

func (u *upstreamConn) Upstream() any { return u.Conn }

func TestOfferFromFamilyConfig(t *testing.T) {
	if _, err := OfferFromFamilyConfig([]byte(`{"_endpoint":{}}`)); !errors.Is(err, ErrNoOffer) {
		t.Fatalf("no member: %v", err)
	}
	if _, err := OfferFromFamilyConfig(nil); !errors.Is(err, ErrNoOffer) {
		t.Fatalf("empty: %v", err)
	}
	o, err := OfferFromFamilyConfig([]byte(`{"_desync":{"v":1,"strategy":{"preset":"sni-cut"}}}`))
	if err != nil || o.Apply != ApplyOffer || !reflect.DeepEqual(o.StrategyValue(), Presets["sni-cut"]) {
		t.Fatalf("offer: %+v %v", o, err)
	}
	o, err = OfferFromFamilyConfig([]byte(`{"_desync":{"v":1,"apply":"always","strategy":{"split_at":[1]}}}`))
	if err != nil || o.Apply != ApplyAlways {
		t.Fatalf("always: %+v %v", o, err)
	}
	for _, bad := range []string{
		`{"_desync":{"v":2,"strategy":{"preset":"sni-cut"}}}`,
		`{"_desync":{"strategy":{"preset":"sni-cut"}}}`,
		`{"_desync":{"v":1,"apply":"sometimes","strategy":{"preset":"sni-cut"}}}`,
		`{"_desync":{"v":1,"strategy":{}}}`,
		`{"_desync":{"v":1,"strategy":{"preset":"x"}}}`,
		`{"_desync":{"v":1,"strategy":{"preset":"sni-cut"},"extra":1}}`,
		`{"_desync":[]}`,
		`not json`,
	} {
		if _, err := OfferFromFamilyConfig([]byte(bad)); err == nil || errors.Is(err, ErrNoOffer) {
			t.Errorf("%s: want a refusal, got %v", bad, err)
		}
	}
}
