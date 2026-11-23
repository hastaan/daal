package bootstrap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// rawResolver answers each datagram with whatever reply builds.
func rawResolver(t *testing.T, reply func(q *dns.Msg) [][]byte) (netip.AddrPort, chan *dns.Msg) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	seen := make(chan *dns.Msg, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			seen <- q
			for _, b := range reply(q) {
				pc.WriteTo(b, from)
			}
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String()), seen
}

func aReply(q *dns.Msg, ips ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
	}
	return m
}

func pack(t *testing.T, m *dns.Msg) []byte {
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAQuerier_PlainQuestionAndAnswer(t *testing.T) {
	srv, seen := rawResolver(t, func(q *dns.Msg) [][]byte {
		r := aReply(q, "23.1.2.3")
		// An answer for another owner is ignored.
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: "other.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("34.1.1.1")})
		b, _ := r.Pack()
		return [][]byte{b}
	})
	q := &AQuerier{Server: srv, Timeout: time.Second}
	ans, err := q.A(context.Background(), "abc0.Example.org.")
	if err != nil || len(ans.Addrs) != 1 || ans.Addrs[0] != netip.MustParseAddr("23.1.2.3") {
		t.Fatalf("ans %+v err %v", ans, err)
	}
	m := <-seen
	if m.IsEdns0() != nil || !m.RecursionDesired || len(m.Question) != 1 || m.Question[0].Qtype != dns.TypeA ||
		m.Question[0].Name != "abc0.example.org." || len(m.Extra) != 0 {
		t.Fatalf("question %v", m)
	}
}

func TestAQuerier_SkipsWrongIDThenTakesRight(t *testing.T) {
	srv, _ := rawResolver(t, func(q *dns.Msg) [][]byte {
		bad := aReply(q, "99.9.9.9")
		bad.Id = q.Id + 1
		return [][]byte{pack(t, bad), []byte("junk"), pack(t, aReply(q, "52.0.0.1"))}
	})
	ans, err := (&AQuerier{Server: srv, Timeout: time.Second}).A(context.Background(), "x.example.org")
	if err != nil || len(ans.Addrs) != 1 || ans.Addrs[0].String() != "52.0.0.1" {
		t.Fatalf("ans %+v err %v", ans, err)
	}
}

func TestAQuerier_Refusals(t *testing.T) {
	cases := map[string]struct {
		reply func(q *dns.Msg) *dns.Msg
		want  error
	}{
		"nxdomain":  {func(q *dns.Msg) *dns.Msg { m := aReply(q); m.Rcode = dns.RcodeNameError; return m }, ErrDNSRcode},
		"refused":   {func(q *dns.Msg) *dns.Msg { m := aReply(q); m.Rcode = dns.RcodeRefused; return m }, ErrDNSRcode},
		"truncated": {func(q *dns.Msg) *dns.Msg { m := aReply(q, "23.0.0.1"); m.Truncated = true; return m }, ErrDNSAnswer},
		"other name": {func(q *dns.Msg) *dns.Msg {
			m := aReply(q, "23.0.0.1")
			m.Question[0].Name = "y.example.org."
			return m
		}, ErrDNSAnswer},
		"too many": {func(q *dns.Msg) *dns.Msg {
			return aReply(q, "23.0.0.1", "23.0.0.2", "23.0.0.3", "23.0.0.4", "23.0.0.5", "23.0.0.6", "23.0.0.7", "23.0.0.8", "23.0.0.9")
		}, ErrDNSAnswer},
	}
	for name, tc := range cases {
		srv, _ := rawResolver(t, func(q *dns.Msg) [][]byte { return [][]byte{pack(t, tc.reply(q))} })
		ans, err := (&AQuerier{Server: srv, Timeout: time.Second}).A(context.Background(), "x.example.org")
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: ans %+v err %v", name, ans, err)
		}
	}
}

func TestAQuerier_DeadlineAndBounds(t *testing.T) {
	srv, _ := rawResolver(t, func(*dns.Msg) [][]byte { return nil })
	start := time.Now()
	_, err := (&AQuerier{Server: srv, Timeout: 150 * time.Millisecond}).A(context.Background(), "x.example.org")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	// A cancelled context stops the wait at once.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start = time.Now()
	_, err = (&AQuerier{Server: srv, Timeout: 5 * time.Second}).A(ctx, "x.example.org")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("cancel: err %v after %v", err, time.Since(start))
	}
	long := make([]byte, 101)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := (&AQuerier{Server: srv}).A(context.Background(), string(long)); !errors.Is(err, ErrDNSAnswer) {
		t.Fatalf("long name: %v", err)
	}
	if _, err := (&AQuerier{}).A(context.Background(), "x.example.org"); !errors.Is(err, ErrNoLinkResolver) {
		t.Fatalf("no server: %v", err)
	}
}

func TestLinkResolver_HostServersAndPublicRefused(t *testing.T) {
	t.Cleanup(ForgetHostLinkResolvers)
	SetLinkResolvers([]string{"8.8.8.8", "192.168.1.1"})
	if r, ok := LinkResolver(); !ok || r.String() != "192.168.1.1:53" {
		t.Fatalf("got %v %v", r, ok)
	}
	SetLinkResolvers([]string{"1.1.1.1", "9.9.9.9"})
	if r, ok := LinkResolver(); ok {
		t.Fatalf("a public resolver was picked: %v", r)
	}
	SetLinkResolvers([]string{"fe80::1%wlan0", "10.0.0.1:5353"})
	if r, ok := LinkResolver(); !ok || r.String() != "10.0.0.1:5353" {
		t.Fatalf("got %v %v", r, ok)
	}
	if _, ok := ParseLinkResolver("8.8.4.4:53"); ok {
		t.Fatal("public accepted")
	}
	if r, ok := ParseLinkResolver("127.0.0.1:5353"); !ok || r.Port() != 5353 {
		t.Fatal("local refused")
	}
	if _, ok := ParseLinkResolver("nonsense"); ok {
		t.Fatal("nonsense accepted")
	}
}
