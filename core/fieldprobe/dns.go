package fieldprobe

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS is how Stage A asks. The real one (miekgDNS) sends one UDP
// datagram per question through Net (so through protect()), and reads
// one answer. No retry, no TCP fallback.
type DNS interface {
	Query(ctx context.Context, server netip.AddrPort, name string, qtype uint16) (DNSAnswer, error)
}

// DNSAnswer is one reply, reduced to what the classifier reads.
type DNSAnswer struct {
	Rcode int
	Addrs []netip.Addr
	CNAME []string
	TXT   []string
	// ECH is the ech SvcParam of an HTTPS record, if any.
	ECH []byte
	// Typed: at least one record of the type asked for.
	Typed bool
}

var qtypeOf = map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CNAME": dns.TypeCNAME,
	"TXT": dns.TypeTXT, "HTTPS": dns.TypeHTTPS}

type miekgDNS struct {
	net     Net
	timeout time.Duration
}

func (d miekgDNS) Query(ctx context.Context, server netip.AddrPort, name string, qtype uint16) (DNSAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	c, err := d.net.DialUDP(ctx, server)
	if err != nil {
		return DNSAnswer{}, err
	}
	defer c.Close()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	cl := &dns.Client{Net: "udp", Timeout: d.timeout, UDPSize: 1232}
	r, _, err := cl.ExchangeWithConnContext(ctx, m, &dns.Conn{Conn: c, UDPSize: 1232})
	if err != nil {
		return DNSAnswer{}, err
	}
	return reduceDNS(r, qtype), nil
}

func reduceDNS(r *dns.Msg, qtype uint16) DNSAnswer {
	out := DNSAnswer{Rcode: r.Rcode}
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == qtype {
			out.Typed = true
		}
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out.Addrs = append(out.Addrs, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				out.Addrs = append(out.Addrs, a)
			}
		case *dns.CNAME:
			out.CNAME = append(out.CNAME, strings.ToLower(v.Target))
		case *dns.TXT:
			out.TXT = append(out.TXT, strings.Join(v.Txt, ""))
		case *dns.HTTPS:
			for _, kv := range v.Value {
				if e, ok := kv.(*dns.SVCBECHConfig); ok {
					out.ECH = append([]byte(nil), e.ECH...)
				}
			}
		}
	}
	return out
}

// dnsRcode is the report's closed word for an rcode.
func dnsRcode(rc int) string {
	switch rc {
	case dns.RcodeSuccess:
		return "noerror"
	case dns.RcodeNameError:
		return "nxdomain"
	case dns.RcodeServerFailure:
		return "servfail"
	case dns.RcodeRefused:
		return "refused"
	}
	return "other"
}

// dnsExpect is what a question is held to.
type dnsExpect struct {
	qtype uint16
	// expect: for a known-zone record, the answer must contain this
	// ("" = any typed, non-bogon answer).
	expect      string
	calibration netip.Prefix
}

// classifyDNS is the §1 DNS table. aAnswered: the A question for the
// same name was answered (for type_dropped).
func classifyDNS(ans DNSAnswer, err error, ex dnsExpect, aAnswered bool) string {
	if err != nil {
		switch errKind(err) {
		case "local_error", "local_blocked":
			// The device did not let the question out: not the network.
			return "local_error"
		case "cancelled":
			return "skipped"
		case "timeout":
			if ex.qtype != dns.TypeA && aAnswered {
				return "type_dropped"
			}
		}
		return "dns_timeout"
	}
	switch ans.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return "nxdomain"
	default:
		return "servfail"
	}
	for _, a := range ans.Addrs {
		if isBogon(a, ex.calibration) {
			return "bogon"
		}
	}
	if ex.expect != "" {
		hay := strings.ToLower(strings.Join(append(append([]string{}, ans.CNAME...), ans.TXT...), "\n"))
		if !strings.Contains(hay, strings.ToLower(ex.expect)) {
			if !ans.Typed {
				return "type_dropped"
			}
			return "answer_altered"
		}
		return "ok"
	}
	if !ans.Typed {
		if ex.qtype != dns.TypeA && aAnswered {
			return "type_dropped"
		}
		// NOERROR with nothing: an empty answer is a real answer for
		// AAAA/HTTPS of names that have none; it is "ok" (the resolver
		// spoke) unless the type was expected (the known zone).
		return "ok"
	}
	return "ok"
}
