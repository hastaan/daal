// carrier_dns.go — the DNS micro-note reader (rung 3;
// docs/update-ladder-v2.md §4.3, specs/update-ladder-v2.md §4).
//
// The publisher keeps six A records in its own zone,
// <name(dns, e)[0:12]><i>.<zone> for i = 0..5, whose answers carry the
// 16 sealed bytes of the standby key (or filler). This carrier asks for
// them through the resolver the network gave the phone (never a public
// resolver, A only, no EDNS: bootstrap.AQuerier), one question every
// 1–3 s, puts the 16 bytes back together (bundle.DNSNoteJoin) and opens
// them against the route's SIGNED standby commitment (CarrierEnv.OpenMicro).
// What it returns is a candidate the ladder checks again.
//
// Order and budget. Each held secret that may use DNS (not Everyone:
// bundle.MicroNoteAllowed), newest first, at epoch e and then e−1
// (CarrierEnv.Tries). A try costs six questions; it is abandoned at the
// first missing or odd answer (NXDOMAIN, an error rcode, a timeout, more
// than one record, an address whose first octet is not in the list — a
// sinkhole), which costs only the questions already asked. A next try is
// started only while six more questions fit in the budget: Info().Cost
// (6, one try) unless the ladder gives another with WithDNSQuestionBudget.
// So with the walk's 6 questions only one epoch of the newest secret is
// asked: e, or e−1 first when the ladder's hint says the last walk found
// nothing at e at this epoch (DNSEpochHint, ladder.go), so a reveal
// written before the weekly rollover stays readable.
//
// Before every question the carrier asks RouteActive(), and stops with
// ErrTunnelRequired once a route is up: these names are the ones a
// national resolver logs.
//
// Results. A note that opens: one Note. Anything else from a resolver
// that answered at least once: "nothing new" (zero notes, no strike).
// A resolver that never answered (every question timed out or the socket
// failed): an error, a strike against the DNS class. No resolver known
// (bootstrap.LinkResolver), no zone, no sealed standby, no secret allowed
// on DNS: not usable, and it costs nothing.
//
// Never logged: the zone, a name, an answer, the resolver.

package refresh

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// CarrierNameDNS is the DNS reader's CarrierInfo.Name.
const CarrierNameDNS = "dns"

// errDNSNoReply: the resolver answered none of the questions.
var errDNSNoReply = errors.New("refresh: the network's resolver did not answer")

type dnsBudgetKey struct{}

// WithDNSQuestionBudget gives the DNS carrier n questions for this
// Fetch instead of its Cost (the ladder passes what is left of the
// walk's 6). n < 6 means no try fits and Fetch asks nothing.
func WithDNSQuestionBudget(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, dnsBudgetKey{}, n)
}

// DNSEpochHint is the ladder's per-pack memory of the DNS epochs.
// PreferOlder (in): ask e−1 before e. Absent / AbsentEpoch (out): the
// first question at epoch e of the newest secret came back NXDOMAIN or
// with no address.
type DNSEpochHint struct {
	PreferOlder bool
	Absent      bool
	AbsentEpoch uint64
}

type dnsHintKey struct{}

// WithDNSEpochHint hands the DNS carrier the ladder's hint for this Fetch.
func WithDNSEpochHint(ctx context.Context, h *DNSEpochHint) context.Context {
	return context.WithValue(ctx, dnsHintKey{}, h)
}

func dnsEpochHint(ctx context.Context) *DNSEpochHint {
	h, _ := ctx.Value(dnsHintKey{}).(*DNSEpochHint)
	return h
}

// olderFirst reorders tries so each secret's e−1 comes before its e.
func olderFirst(tries []NoteTry) []NoteTry {
	out := append([]NoteTry(nil), tries...)
	for i := 0; i+1 < len(out); i++ {
		if out[i].Secret == out[i+1].Secret && out[i+1].Epoch < out[i].Epoch {
			out[i], out[i+1] = out[i+1], out[i]
			i++
		}
	}
	return out
}

func dnsQuestionBudget(ctx context.Context, def int) int {
	if n, ok := ctx.Value(dnsBudgetKey{}).(int); ok {
		return n
	}
	return def
}

type dnsCarrier struct {
	// pace waits between two questions (nil: a random 1–3 s).
	pace func(ctx context.Context) error
	// timeout bounds one question (0: bootstrap's default).
	timeout time.Duration
	// dial opens the UDP socket (nil: plain).
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// linkResolver finds the resolver when the env names none (nil:
	// bootstrap.LinkResolver).
	linkResolver func() (netip.AddrPort, bool)
}

func init() { RegisterCarrier(&dnsCarrier{}) }

func (c *dnsCarrier) Info() CarrierInfo {
	return CarrierInfo{
		Name:  CarrierNameDNS,
		Label: bundle.NoteCarrierDNS,
		Class: ClassDNS,
		Rung:  RungDNS,
		Cost:  CarrierCost{TCP: 0, DNS: bundle.DNSNoteAnswers},
		Kinds: NoteMicro,
	}
}

// resolver is the server to ask: env.Resolver when set (refused if it
// is a well-known public resolver), else the link's.
func (c *dnsCarrier) resolver(env *CarrierEnv) (netip.AddrPort, bool) {
	if env.Resolver != "" {
		return bootstrap.ParseLinkResolver(env.Resolver)
	}
	if c.linkResolver != nil {
		return c.linkResolver()
	}
	return bootstrap.LinkResolver()
}

func (c *dnsCarrier) zone(env *CarrierEnv) (string, bool) {
	if env == nil || env.Carriers == nil || env.Carriers.DNS == nil {
		return "", false
	}
	z := env.Carriers.DNS.Zone
	return z, bundle.DNSNoteZoneOK(z)
}

func (c *dnsCarrier) Usable(env *CarrierEnv) bool {
	if _, ok := c.zone(env); !ok {
		return false
	}
	if env.Standby == nil || env.Standby.Mode != bundle.StandbyModeSealed {
		return false
	}
	if len(env.Tries(bundle.NoteCarrierDNS, NoteMicro)) == 0 {
		return false
	}
	_, ok := c.resolver(env)
	return ok
}

// SkipReason says why the reader is not usable, for the drill
// (drill.go): no zone in the file, nothing held it may use, or no
// resolver of the network known. "" when it is usable. No I/O.
func (c *dnsCarrier) SkipReason(env *CarrierEnv) string {
	if _, ok := c.zone(env); !ok {
		return DrillSkipNotInFile
	}
	if env.Standby == nil || env.Standby.Mode != bundle.StandbyModeSealed ||
		len(env.Tries(bundle.NoteCarrierDNS, NoteMicro)) == 0 {
		return DrillSkipNotHeld
	}
	if _, ok := c.resolver(env); !ok {
		return DrillSkipNoResolver
	}
	return ""
}

func (c *dnsCarrier) Fetch(ctx context.Context, env *CarrierEnv) ([]Note, error) {
	if !c.Usable(env) {
		return nil, ErrCarrierUnconfigured
	}
	zone, _ := c.zone(env)
	server, _ := c.resolver(env)
	q := &bootstrap.AQuerier{Server: server, Timeout: c.timeout, DialUDP: c.dial}
	budget := dnsQuestionBudget(ctx, c.Info().Cost.DNS)
	name := c.Info().Name

	hint := dnsEpochHint(ctx)
	tries := env.Tries(bundle.NoteCarrierDNS, NoteMicro)
	if hint != nil && hint.PreferOlder {
		tries = olderFirst(tries)
	}
	asked, answered := 0, false
	for ti, t := range tries {
		if budget-asked < bundle.DNSNoteAnswers {
			break
		}
		names, err := bundle.DNSNoteNames(t.Secret.Secret, t.Epoch, zone)
		if err != nil {
			break
		}
		var ips [bundle.DNSNoteAnswers]net.IP
		whole := true
		for i, n := range names {
			if asked > 0 {
				if err := c.wait(ctx); err != nil {
					return c.end(answered, err)
				}
			}
			if RouteActive() {
				return nil, ErrTunnelRequired
			}
			asked++
			ans, err := q.A(ctx, n)
			if ti == 0 && i == 0 && hint != nil && !hint.PreferOlder {
				nx := errors.Is(err, bootstrap.ErrDNSRcode) && ans.Rcode == dns.RcodeNameError
				if nx || (err == nil && len(ans.Addrs) == 0) {
					hint.Absent, hint.AbsentEpoch = true, t.Epoch
				}
			}
			switch {
			case err == nil, errors.Is(err, bootstrap.ErrDNSRcode), errors.Is(err, bootstrap.ErrDNSAnswer):
				answered = true
			default:
				if ctx.Err() != nil {
					return c.end(answered, ctx.Err())
				}
			}
			if err != nil || len(ans.Addrs) != 1 {
				whole = false
				break
			}
			a := ans.Addrs[0].As4()
			if !bundle.DNSNoteFirstOctetOK(a[0]) {
				whole = false // a sinkhole or someone else's record
				break
			}
			ips[i] = net.IP(a[:])
		}
		if !whole {
			continue
		}
		sealed, err := bundle.DNSNoteJoin(ips)
		if err != nil {
			continue
		}
		if n, ok := env.OpenMicro(name, bundle.NoteCarrierDNS, sealed); ok {
			return []Note{n}, nil
		}
		// Filler, or a note of another secret or epoch: try on.
	}
	if asked > 0 && !answered {
		return nil, errDNSNoReply
	}
	return nil, nil
}

// end is the result when the walk's time runs out mid-Fetch: "nothing
// new" if the resolver spoke, else the context's error.
func (c *dnsCarrier) end(answered bool, err error) ([]Note, error) {
	if answered {
		return nil, nil
	}
	return nil, err
}

func (c *dnsCarrier) wait(ctx context.Context) error {
	if c.pace != nil {
		return c.pace(ctx)
	}
	// 1–3 s, uniformly, in milliseconds.
	d := time.Second
	if n, err := rand.Int(rand.Reader, big.NewInt(2001)); err == nil {
		d += time.Duration(n.Int64()) * time.Millisecond
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
