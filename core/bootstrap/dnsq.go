package bootstrap

// dnsq.go — plain A questions to the resolver the network gave the
// device, for the DNS micro-note (docs/update-ladder-v2.md §4.3,
// core/refresh/carrier_dns.go).
//
// The shape is what the evidence from the cuts allows: one UDP datagram
// per question, type A only, recursion desired, NO EDNS (no OPT record,
// so the question is as short and ordinary as a stub resolver's), no
// TCP fallback, no retry. The answer is read into a 512-byte buffer
// (the classic UDP limit without EDNS) and held to the question: same
// id, same name, class IN, type A. Only A records whose owner is the
// asked name count, at most MaxAAnswers of them.
//
// The resolver is the LINK's resolver, found the way the field test
// finds it (core/fieldprobe): the servers the host passed
// (SetLinkResolvers: Android's LinkProperties.getDnsServers), else
// /etc/resolv.conf on a Linux desktop. A well-known public resolver
// (1.1.1.1, 8.8.8.8, …) is never asked: the note is read through the
// resolver the network itself provides, which is the one that keeps
// answering in a cut. No resolver found: the caller does nothing.
//
// Nothing here logs a name or an answer.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"daal/core/fieldprobe"
)

const (
	// MaxAAnswers is the most A records one answer may carry before it
	// is refused as not ours.
	MaxAAnswers = 8
	// dnsUDPMax is the read bound: a DNS message over UDP without EDNS.
	dnsUDPMax = 512
	// DefaultAQuestionTimeout bounds one question.
	DefaultAQuestionTimeout = 3 * time.Second
	// maxQueryName: the name cap seen in Iran in January 2026 was
	// between 101 and 102 characters.
	maxQueryName = 100
)

var (
	// ErrNoLinkResolver: no resolver of the link is known.
	ErrNoLinkResolver = errors.New("bootstrap: the network's resolver is not known")
	// ErrDNSAnswer: an answer that does not fit the question (truncated,
	// another id or name, too many records).
	ErrDNSAnswer = errors.New("bootstrap: malformed DNS answer")
	// ErrDNSRcode: the resolver answered with an error rcode.
	ErrDNSRcode = errors.New("bootstrap: DNS error answer")
)

// AAnswer is one reply to an A question.
type AAnswer struct {
	// Rcode is the reply's rcode (dns.RcodeSuccess, RcodeNameError, …).
	Rcode int
	// Addrs are the IPv4 addresses of A records owned by the asked name.
	Addrs []netip.Addr
}

// AQuerier asks A questions of one resolver.
type AQuerier struct {
	// Server is the resolver (LinkResolver or a host-given one).
	Server netip.AddrPort
	// Timeout bounds each question (DefaultAQuestionTimeout when 0).
	Timeout time.Duration
	// DialUDP opens the socket (nil: a plain net.Dialer). The update
	// walk never runs while a Daal route is up, so there is no tunnel
	// to keep the socket out of.
	DialUDP func(ctx context.Context, network, address string) (net.Conn, error)
}

// A asks one A question. A reply with an error rcode returns the
// AAnswer (with Rcode set) and ErrDNSRcode; a reply that does not fit
// the question returns ErrDNSAnswer; no reply in time returns the
// timeout.
func (q *AQuerier) A(ctx context.Context, name string) (AAnswer, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(name) > maxQueryName {
		return AAnswer{}, ErrDNSAnswer
	}
	if !q.Server.IsValid() {
		return AAnswer{}, ErrNoLinkResolver
	}
	to := q.Timeout
	if to <= 0 {
		to = DefaultAQuestionTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return AAnswer{}, ErrDNSAnswer
	}

	dial := q.DialUDP
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	c, err := dial(ctx, "udp", q.Server.String())
	if err != nil {
		return AAnswer{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := c.Write(wire); err != nil {
		return AAnswer{}, err
	}
	buf := make([]byte, dnsUDPMax)
	// Datagrams that are not the answer (another id: a late reply, a
	// spoof) are skipped; a few at most, then the deadline decides.
	for tries := 0; tries < 4; tries++ {
		n, err := c.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return AAnswer{}, ctx.Err()
			}
			return AAnswer{}, err
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf[:n]); err != nil || r.Id != m.Id || !r.Response {
			continue
		}
		return reduceA(r, name)
	}
	return AAnswer{}, ErrDNSAnswer
}

func reduceA(r *dns.Msg, name string) (AAnswer, error) {
	if r.Truncated || len(r.Question) != 1 {
		return AAnswer{}, ErrDNSAnswer
	}
	qq := r.Question[0]
	if qq.Qtype != dns.TypeA || qq.Qclass != dns.ClassINET ||
		!strings.EqualFold(strings.TrimSuffix(qq.Name, "."), name) {
		return AAnswer{}, ErrDNSAnswer
	}
	out := AAnswer{Rcode: r.Rcode}
	if r.Rcode != dns.RcodeSuccess {
		return out, ErrDNSRcode
	}
	for _, rr := range r.Answer {
		a, ok := rr.(*dns.A)
		if !ok || !strings.EqualFold(strings.TrimSuffix(rr.Header().Name, "."), name) {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.A.To4())
		if !ok {
			continue
		}
		if len(out.Addrs) == MaxAAnswers {
			return AAnswer{}, ErrDNSAnswer
		}
		out.Addrs = append(out.Addrs, ip)
	}
	return out, nil
}

// --- The link's resolver ---------------------------------------------------

var (
	linkMu        sync.Mutex
	linkResolvers []netip.AddrPort
	// linkHostSet: the host has spoken (engine_set_link_resolvers). From
	// then on its list is the whole answer: an empty one means the
	// network is gone, not "look in /etc/resolv.conf".
	linkHostSet bool
)

// SetLinkResolvers records the link's DNS servers as the host reports
// them (Android: LinkProperties.getDnsServers of the underlying, non-VPN
// network; "addr" or "addr:port"). An empty list means the host knows of
// none (the network was lost): no resolver until it says again.
func SetLinkResolvers(servers []string) {
	rs := fieldprobe.ParseResolvers(servers)
	linkMu.Lock()
	linkResolvers = rs
	linkHostSet = true
	linkMu.Unlock()
}

// ForgetHostLinkResolvers drops what the host said, so LinkResolver
// falls back to the system's list again (tests; a host that stops
// reporting).
func ForgetHostLinkResolvers() {
	linkMu.Lock()
	linkResolvers, linkHostSet = nil, false
	linkMu.Unlock()
}

// LinkResolver is the resolver to ask: the host's servers, else
// /etc/resolv.conf where that means something (fieldprobe.SystemResolvers),
// picked as the field test picks (fieldprobe.PickResolver). A well-known
// public resolver is refused. false: none is known.
func LinkResolver() (netip.AddrPort, bool) {
	linkMu.Lock()
	rs := append([]netip.AddrPort(nil), linkResolvers...)
	hostSet := linkHostSet
	linkMu.Unlock()
	if len(rs) == 0 && !hostSet {
		rs = fieldprobe.SystemResolvers()
	}
	return pickLinkResolver(rs)
}

// ParseLinkResolver checks one "host:port" (or bare address) the caller
// was given as the link's resolver. A well-known public resolver is
// refused.
func ParseLinkResolver(s string) (netip.AddrPort, bool) {
	return pickLinkResolver(fieldprobe.ParseResolvers([]string{s}))
}

func pickLinkResolver(rs []netip.AddrPort) (netip.AddrPort, bool) {
	var ok []netip.AddrPort
	for _, r := range rs {
		if fieldprobe.ResolverClass([]netip.AddrPort{r}) == "well_known_public" {
			continue
		}
		ok = append(ok, r)
	}
	return fieldprobe.PickResolver(ok)
}
