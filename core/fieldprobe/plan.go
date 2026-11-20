package fieldprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"daal/bundle-go/fieldreport"

	"github.com/miekg/dns"
)

// THE PLAN — specs/field-probe-v2.md §1–§2.
//
// Quietest first, the Test relay last (so that if a probe burns the
// relay's address everything else is already collected). Strictly
// sequential, a jittered gap between steps, no retry anywhere, a hard
// cap on connections and a hard stop on time. Nothing here retries a
// failed step, sweeps ports, sends a bare SYN, ICMP or a TTL-limited
// packet.

// Timeouts are the per-operation bounds (§1).
type Timeouts struct {
	Connect, Handshake, Carry, DNS, QUIC, Relay time.Duration
}

// DefaultTimeouts are the production bounds.
func DefaultTimeouts() Timeouts {
	return Timeouts{Connect: 6 * time.Second, Handshake: 8 * time.Second, Carry: 8 * time.Second,
		DNS: 4 * time.Second, QUIC: 6 * time.Second, Relay: 12 * time.Second}
}

const (
	// DefaultHardStop ends a run that is still going after 4 minutes.
	DefaultHardStop = 4 * time.Minute
	// DefaultMaxConns is the hard cap on TCP connections in one run.
	DefaultMaxConns = 30
	// MaxDatagrams caps the DNS questions of one run.
	MaxDatagrams = 18
	// DefaultReserve: past this point of a run, what is left of Stage B
	// is dropped and the run goes straight to the Test relay (C2), so a
	// network where every Stage A and B probe times out still answers
	// the main question inside the hard stop.
	DefaultReserve = 150 * time.Second
	// MaxRelayFlows caps the connections to the Test relay in one run
	// (C2, C3 ×2, C4–C6, C7 ×2, C8, C9 would be ten): the relay's
	// address is the one thing the test must not burn.
	MaxRelayFlows = 9
	// MaxSteps is the longest plan (A1–A6, B1–B9, C2–C9).
	MaxSteps = 23
)

// Why a run stopped early. A caller cancels the run's context with one
// of these as the cause (context.WithCancelCause).
var (
	ErrCancelled      = errors.New("fieldprobe: cancelled")
	ErrBackgrounded   = errors.New("fieldprobe: the app went to the background")
	ErrNetworkChanged = errors.New("fieldprobe: the network changed")
	ErrShutdown       = errors.New("fieldprobe: engine shutting down")
	// ErrConnecting: Daal started connecting (a route, or the automatic
	// connect) — the test is for the network WITHOUT a VPN.
	ErrConnecting = errors.New("fieldprobe: Daal is connecting")
	// ErrVPNActive: another VPN came up (the host's TRANSPORT_VPN, or
	// the network facts it reported).
	ErrVPNActive = errors.New("fieldprobe: a VPN came up")
)

// RelayTarget is the Test relay, as the engine knows it. Handles are
// opaque to this package (the ABI's route ids); the address and the
// cover name are used for C4–C6 and never leave the run.
type RelayTarget struct {
	Addr            netip.Addr
	Port            uint16
	CoverName       string
	PackID          string
	Main            string
	Alt             []string
	QUIC            string
	DesyncOffer     bool
	DesyncAvailable bool
}

// Relay proves Test-relay routes in the engine's side instance.
type Relay interface {
	Target() (RelayTarget, bool)
	// Prove makes one connection proof of the route with the ClientHello
	// split as named: "off", "pack" (the route's signed offer) or a
	// core/desync preset name.
	Prove(ctx context.Context, handle, desync string) RelayOutcome
	// Restore is called once, at the end, on every path: whatever Prove
	// changed is put back. (The engine's Prove changes nothing: each
	// proof's split setting is handed to that one config build.)
	Restore()
}

// Env is everything a run needs. Zero values get production defaults,
// except Net and Targets, which are required.
type Env struct {
	Net       Net
	DNS       DNS
	QUIC      QUICer
	Relay     Relay
	Targets   *Targets
	Resolvers []netip.AddrPort
	Timeouts  Timeouts
	// Gap is the pause before a step of the given stage ('A','B','C').
	Gap      func(stage byte) time.Duration
	HardStop time.Duration
	MaxConns int
	Progress func(step, of int)
	// Log gets one line per step: ids and closed words only.
	Log      func(string)
	AckWatch func(net.Conn, time.Duration) func() (bool, bool)
	// Roots verifies Stage B's certificates; nil: the device's roots.
	Roots *x509.CertPool
	// Reserve: see DefaultReserve. < 0 turns it off.
	Reserve time.Duration
	// PrivateDNSStrict: the phone sends no cleartext DNS of its own
	// (Android Private DNS "strict"), so the test does not either: the
	// link-resolver questions are skipped. A6 (one resolver, plain
	// UDP/53, named in the consent text) still runs.
	PrivateDNSStrict bool
	// OnFirstSend is called once, just before the first packet of the
	// run goes out — where the run allowance is charged, so a run that
	// stops before sending anything costs nothing.
	OnFirstSend func()
}

// ProbeRecord is one report entry plus what produced it (in memory only).
type ProbeRecord struct {
	fieldreport.Probe
	tcp *tcpObs
	udp bool
}

// Result is a finished (or stopped) run.
type Result struct {
	Probes       []ProbeRecord
	StepsRun     int
	Of           int
	Complete     bool
	AbortReason  string
	ShortCircuit bool
	Elapsed      time.Duration
	Conns        int
	QUICs        int
	Datagrams    int
	// LocalBlocked: the device itself does not let the test out (Android
	// "block connections without VPN"): the preflight or the first
	// connection said so.
	LocalBlocked bool
	// Blackout: B1 and every public-resolver question failed: the run
	// went to C2 and stopped. TimeReserve: the rest of Stage B was
	// dropped to keep time for Stage C. Either sets the report's
	// short_circuit.
	Blackout        bool
	TimeReserve     bool
	RelayFlows      int
	HelloFP         string
	RelayPackID     string
	DesyncAvailable bool
	ECHEncrypted    bool
}

// DefaultGap is 2–5 s before steps A–B and 4–8 s before Stage C.
func DefaultGap(stage byte) time.Duration {
	if stage == 'C' {
		return 4*time.Second + time.Duration(rand.Int64N(int64(4*time.Second)))
	}
	return 2*time.Second + time.Duration(rand.Int64N(int64(3*time.Second)))
}

type step struct {
	id  string
	run func(ctx context.Context)
}

type runner struct {
	env     Env
	res     *Result
	t       *Targets
	conn    int
	fps     map[string]bool
	charged bool

	googleAddr, githubAddr, cfAddr, whiteAddr addrPick
	echConfig                                 []byte
	location                                  string
	relay                                     RelayTarget
	haveRelay                                 bool
}

// addrPick is an address and where it came from.
type addrPick struct {
	a   netip.Addr
	src string // addr_link | addr_public | addr_hint
}

func (p addrPick) ok() bool { return p.a.IsValid() }

// Run performs the plan. It always returns a Result, partial when the
// run was stopped; it never returns an error.
func Run(parent context.Context, env Env) *Result {
	if env.Timeouts == (Timeouts{}) {
		env.Timeouts = DefaultTimeouts()
	}
	if env.Gap == nil {
		env.Gap = DefaultGap
	}
	if env.HardStop <= 0 {
		env.HardStop = DefaultHardStop
	}
	if env.MaxConns <= 0 {
		env.MaxConns = DefaultMaxConns
	}
	if env.Reserve == 0 {
		env.Reserve = DefaultReserve
	}
	if env.Log == nil {
		env.Log = func(string) {}
	}
	base, stopBase := context.WithCancelCause(parent)
	defer stopBase(nil)
	// Every socket of the run, the DNS and QUIC ones included, is watched
	// for the path changing under the test.
	watched := &pathWatch{Net: env.Net, changed: func() { stopBase(ErrNetworkChanged) }}
	env.Net = watched
	if env.DNS == nil {
		env.DNS = miekgDNS{net: env.Net, timeout: env.Timeouts.DNS}
	}
	if env.QUIC == nil {
		env.QUIC = quicGo{net: env.Net, timeout: env.Timeouts.QUIC}
	}
	r := &runner{env: env, res: &Result{}, t: env.Targets, fps: map[string]bool{}}
	if env.Relay != nil {
		r.relay, r.haveRelay = env.Relay.Target()
		if r.haveRelay {
			r.res.RelayPackID = r.relay.PackID
			r.res.DesyncAvailable = r.relay.DesyncAvailable
			if r.relay.CoverName != "" && checkName(r.relay.CoverName) != nil {
				// The pack's cover name goes in a plain hello (C5): held to
				// the list's own rule for names.
				r.relay.CoverName = ""
			}
			defer env.Relay.Restore()
		}
	}
	ctx, cancel := context.WithTimeout(base, env.HardStop)
	defer cancel()
	start := time.Now()
	steps := r.plan()
	r.res.Of = len(steps)

	if r.preflight(ctx) {
		r.loop(ctx, steps, start)
	}
	r.res.Elapsed = time.Since(start)
	if r.res.AbortReason == "" {
		switch {
		case base.Err() != nil:
			r.res.AbortReason = abortReasonOf(context.Cause(base))
		case ctx.Err() != nil:
			r.res.AbortReason = "time_limit"
		}
	}
	r.res.Complete = r.res.AbortReason == ""
	r.res.ShortCircuit = r.res.Blackout || r.res.TimeReserve
	r.reclassify()
	switch len(r.fps) {
	case 0:
		r.res.HelloFP = "none"
	case 1:
		for fp := range r.fps {
			r.res.HelloFP = fp
		}
	default:
		r.res.HelloFP = "mixed"
	}
	return r.res
}

// preflight asks the device, without sending anything, whether the test
// may go out at all: a UDP connect() to the public resolver sets the
// socket's route and sends no packet. "Block connections without VPN"
// answers EPERM / EACCES, or ENETUNREACH; the run then stops before its
// first probe, so the report says "the phone blocks this" rather than
// "the international internet is cut".
func (r *runner) preflight(ctx context.Context) bool {
	c, err := r.env.Net.DialUDP(ctx, r.t.resolver)
	if err == nil {
		_ = c.Close()
		return true
	}
	switch errKind(err) {
	case "local_blocked", "unreachable":
		r.res.LocalBlocked = true
		r.res.AbortReason = "local_blocked"
		return false
	case "local_error":
		r.res.AbortReason = "error"
		return false
	}
	return true
}

func (r *runner) loop(ctx context.Context, steps []step, start time.Time) {
	env := r.env
	var prev byte
	for i := 0; i < len(steps); i++ {
		if steps[i].id[0] == 'B' && env.Reserve > 0 && time.Since(start) > env.Reserve {
			// Out of time for the public controls: keep what is left for
			// the Test relay.
			r.res.TimeReserve = true
			kept := append([]step{}, steps[:i]...)
			for _, s := range steps[i:] {
				if s.id[0] != 'B' {
					kept = append(kept, s)
				}
			}
			steps = kept
			r.res.Of = len(steps)
			if i >= len(steps) {
				break
			}
		}
		st := steps[i]
		if i > 0 && prev != 0 {
			if err := sleepCtx(ctx, env.Gap(st.id[0])); err != nil {
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
		if env.Progress != nil {
			env.Progress(i+1, len(steps))
		}
		if ctx.Err() != nil {
			break
		}
		before := len(r.res.Probes)
		st.run(ctx)
		prev = st.id[0]
		if ctx.Err() == nil {
			r.res.StepsRun++
		}
		for _, p := range r.res.Probes[before:] {
			env.Log(fmt.Sprintf("fieldprobe step=%s variant=%s result=%s phase=%s", p.ID, p.Variant, p.Result, p.Phase))
		}
		if r.res.LocalBlocked {
			r.res.AbortReason = "local_blocked"
			break
		}
		if r.res.AbortReason == "budget" {
			break
		}
		if st.id == "B1" && r.blackout() {
			// Blackout day: do not hammer. C2 only, then stop.
			r.res.Blackout = true
			var rest []step
			for _, s := range steps[i+1:] {
				if s.id == "C2" {
					rest = append(rest, s)
				}
			}
			steps = append(steps[:i+1:i+1], rest...)
			r.res.Of = len(steps)
		}
	}
}

// charge: the first packet of the run is about to go out.
func (r *runner) charge() {
	if r.charged {
		return
	}
	r.charged = true
	if r.env.OnFirstSend != nil {
		r.env.OnFirstSend()
	}
}

func abortReasonOf(cause error) string {
	switch {
	case errors.Is(cause, ErrBackgrounded):
		return "backgrounded"
	case errors.Is(cause, ErrNetworkChanged):
		return "network_changed"
	case errors.Is(cause, ErrShutdown):
		return "shutdown"
	case errors.Is(cause, ErrConnecting):
		return "connected"
	case errors.Is(cause, ErrVPNActive):
		return "vpn_active"
	}
	return "cancelled"
}

func (r *runner) plan() []step {
	// No C1: a cleartext request to the relay's port 80, where nothing
	// listens, is a connect-and-reset — the one shape the design rules
	// out — and a HEAD with the relay's address as Host is not a
	// browser's request either.
	s := []step{
		{"A1", r.a1}, {"A2", r.a2}, {"A3", r.a3}, {"A4", r.a4}, {"A5", r.a5}, {"A6", r.a6},
		{"B1", r.b1}, {"B2", r.b2}, {"B3", r.b3}, {"B4", r.b4}, {"B5", r.b5}, {"B6", r.b6},
		{"B7", r.b7}, {"B8", r.b8}, {"B9", r.b9},
		{"C2", r.c2}, {"C3", r.c3}, {"C4", r.c4}, {"C5", r.c5}, {"C6", r.c6},
	}
	if r.haveRelay && len(r.relay.Alt) > 0 {
		s = append(s, step{"C7", r.c7})
	}
	if r.haveRelay && r.relay.QUIC != "" {
		s = append(s, step{"C8", r.c8})
	}
	return append(s, step{"C9", r.c9})
}

// blackout: the international link looks cut. B1 (Google, the address
// a resolver gave inside Google's blocks) failed before any byte of a
// handshake completed, or had no address at all, AND every question to
// the public resolver (A6) timed out. The link resolver's answers are
// not evidence either way: in a shutdown the domestic resolvers keep
// answering.
func (r *runner) blackout() bool {
	var b1 *ProbeRecord
	for i := range r.res.Probes {
		if r.res.Probes[i].ID == "B1" {
			b1 = &r.res.Probes[i]
		}
	}
	if b1 == nil || okish(b1.Result) || (b1.Result != "skipped" && b1.Phase == "carry") {
		return false
	}
	timedOut := 0
	for _, p := range r.res.Probes {
		if p.ID != "A6" || p.Result == "skipped" {
			continue
		}
		if p.Result != "dns_timeout" {
			return false
		}
		timedOut++
	}
	return timedOut > 0
}

// ---- recording ------------------------------------------------------------

func (r *runner) add(id, role, variant, result, phase string, sig fieldreport.Signals) {
	r.res.Probes = append(r.res.Probes, ProbeRecord{Probe: fieldreport.Probe{
		ID: id, Name: fieldreport.ProbeNames[id], TargetRole: role, Variant: variant,
		Result: result, Phase: phase, Signals: sig,
	}})
}

func (r *runner) skip(id, role, variant string) {
	r.add(id, role, variant, "skipped", "none", fieldreport.Signals{})
}

func (r *runner) result(id string) (string, bool) {
	for i := len(r.res.Probes) - 1; i >= 0; i-- {
		if r.res.Probes[i].ID == id {
			return r.res.Probes[i].Result, true
		}
	}
	return "", false
}

// ---- Stage A: DNS ---------------------------------------------------------

func (r *runner) query(ctx context.Context, server netip.AddrPort, name string, qtype uint16) (DNSAnswer, error, bool) {
	if r.res.Datagrams >= MaxDatagrams {
		return DNSAnswer{}, nil, false
	}
	r.res.Datagrams++
	r.charge()
	a, err := r.env.DNS.Query(ctx, server, name, qtype)
	return a, err, true
}

func (r *runner) linkResolver() (netip.AddrPort, bool) {
	if r.env.PrivateDNSStrict {
		return netip.AddrPort{}, false
	}
	return PickResolver(r.env.Resolvers)
}

// judgeA holds an A answer for a role to the role's address blocks: the
// first answer inside them is the address Stage B may use; a public
// answer with none inside them is dns_wrong_public, and nothing is used.
func (r *runner) judgeA(role string, ans DNSAnswer, res string) (string, netip.Addr) {
	if res != "ok" || len(r.t.allow[role]) == 0 {
		return res, netip.Addr{}
	}
	public := false
	for _, a := range ans.Addrs {
		if !a.Is4() || isBogon(a, r.t.calibration) {
			continue
		}
		if r.t.Allowed(role, a) {
			return res, a
		}
		public = true
	}
	if public {
		return "dns_wrong_public", netip.Addr{}
	}
	return res, netip.Addr{}
}

// ask runs one question against the link resolver and records it. For
// an A question of a role with address blocks it also returns the
// address Stage B may connect to (judgeA).
func (r *runner) ask(ctx context.Context, id, role, variant, name string, qtype uint16, ex dnsExpect, aAnswered bool) (string, netip.Addr) {
	srv, ok := r.linkResolver()
	if !ok {
		r.skip(id, role, variant)
		return "skipped", netip.Addr{}
	}
	ans, err, sent := r.query(ctx, srv, name, qtype)
	if !sent {
		r.skip(id, role, variant)
		return "skipped", netip.Addr{}
	}
	ex.qtype = qtype
	if !ex.calibration.IsValid() {
		ex.calibration = r.t.calibration
	}
	res := classifyDNS(ans, err, ex, aAnswered)
	var pick netip.Addr
	if qtype == dns.TypeA {
		res, pick = r.judgeA(role, ans, res)
	}
	if qtype == dns.TypeHTTPS && res == "ok" && len(ans.ECH) > 0 {
		r.echConfig = ans.ECH
	}
	sig := fieldreport.Signals{}
	if err == nil {
		sig.DNSRcode = dnsRcode(ans.Rcode)
	}
	r.add(id, role, variant, res, "reach", sig)
	return res, pick
}

func (r *runner) a1(ctx context.Context) {
	for _, n := range []struct {
		name, role string
		pick       *addrPick
	}{{r.t.Google, "google", &r.googleAddr}, {r.t.GitHub, "github", &r.githubAddr}} {
		res, a := r.ask(ctx, "A1", n.role, "a", n.name, dns.TypeA, dnsExpect{}, false)
		if a.IsValid() {
			*n.pick = addrPick{a, "addr_link"}
		}
		r.ask(ctx, "A1", n.role, "aaaa", n.name, dns.TypeAAAA, dnsExpect{}, res == "ok" || res == "bogon" || res == "dns_wrong_public")
	}
}

func (r *runner) a2(ctx context.Context) {
	res, a := r.ask(ctx, "A2", "cf_edge", "a", r.t.CFECHOuter, dns.TypeA, dnsExpect{}, false)
	if a.IsValid() {
		r.cfAddr = addrPick{a, "addr_link"}
	}
	r.ask(ctx, "A2", "cf_edge", "https", r.t.CFECHOuter, dns.TypeHTTPS, dnsExpect{}, res == "ok" || res == "bogon" || res == "dns_wrong_public")
}

func (r *runner) a3(ctx context.Context) {
	if _, a := r.ask(ctx, "A3", "white_name", "a", r.t.WhiteName, dns.TypeA, dnsExpect{}, false); a.IsValid() {
		r.whiteAddr = addrPick{a, "addr_link"}
	}
}

func (r *runner) a4(ctx context.Context) {
	aOK := false
	for _, k := range r.t.KnownZone {
		qt := qtypeOf[k.Type]
		res, _ := r.ask(ctx, "A4", "known_zone", strings.ToLower(k.Type), k.Name, qt, dnsExpect{expect: k.Expect}, aOK)
		if qt == dns.TypeA && res == "ok" {
			aOK = true
		}
	}
}

func (r *runner) a5(ctx context.Context) {
	// Calibration: the link resolver is EXPECTED to answer this one with
	// the sinkhole. The result is recorded as it is.
	r.ask(ctx, "A5", "cf_edge", "a", r.t.CFDNSName, dns.TypeA, dnsExpect{}, false)
}

func (r *runner) a6(ctx context.Context) {
	pub := r.t.resolver
	one := func(variant, name, allowRole string, pick *addrPick) {
		ans, err, sent := r.query(ctx, pub, name, dns.TypeA)
		if !sent {
			r.skip("A6", "public_resolver", variant)
			return
		}
		res := classifyDNS(ans, err, dnsExpect{qtype: dns.TypeA, calibration: r.t.calibration}, false)
		// The answer from 1.1.1.1 is held to the same blocks: UDP/53 to
		// a foreign resolver is answered on the path, too.
		res, a := r.judgeA(allowRole, ans, res)
		sig := fieldreport.Signals{}
		if err == nil {
			sig.DNSRcode = dnsRcode(ans.Rcode)
		}
		r.add("A6", "public_resolver", variant, res, "reach", sig)
		if pick != nil && !pick.ok() && a.IsValid() {
			*pick = addrPick{a, "addr_public"}
		}
	}
	one("calibration", r.t.CFDNSName, "cf_edge", nil)
	if len(r.t.KnownZone) > 0 {
		one("known_zone", r.t.KnownZone[0].Name, "", nil)
	}
	// Names whose link answer was missing, a lie or outside the name's
	// blocks: ask once here, so Stage B connects to a real address of
	// the name.
	for _, f := range []struct {
		v, name, role string
		pick          *addrPick
	}{{"fill_google", r.t.Google, "google", &r.googleAddr}, {"fill_github", r.t.GitHub, "github", &r.githubAddr},
		{"fill_cf", r.t.CFECHOuter, "cf_edge", &r.cfAddr}, {"fill_white", r.t.WhiteName, "white_name", &r.whiteAddr}} {
		if !f.pick.ok() {
			one(f.v, f.name, f.role, f.pick)
		}
	}
	if !r.whiteAddr.ok() && len(r.t.hints) > 0 {
		r.whiteAddr = addrPick{r.t.hints[0], "addr_hint"}
	}
}

// ---- Stage B: public controls ----------------------------------------------

// tcp runs one TCP probe within the connection budget and records it.
// The result is provisional until reclassify: whether a stall is a cap
// depends on whether another probe of the run carried.
func (r *runner) tcp(ctx context.Context, id, role, variant string, sp tcpSpec) (tcpObs, bool) {
	if r.res.Conns >= r.env.MaxConns {
		r.skip(id, role, variant)
		r.res.AbortReason = "budget"
		return tcpObs{}, false
	}
	r.res.Conns++
	r.charge()
	if sp.Verify {
		sp.Roots = r.env.Roots
	}
	o := runTCP(ctx, r.env.Net, sp, r.env.Timeouts, r.env.AckWatch)
	if o.FP != "" && o.HelloWritten {
		r.fps[o.FP] = true
	}
	if o.ConnectKind == "local_blocked" && r.res.Conns == 1 {
		r.res.LocalBlocked = true
	}
	if o.Cancelled {
		r.skip(id, role, variant)
		return o, false
	}
	res, phase := classifyTCP(o, nil)
	r.res.Probes = append(r.res.Probes, ProbeRecord{Probe: fieldreport.Probe{
		ID: id, Name: fieldreport.ProbeNames[id], TargetRole: role, Variant: variant,
		Result: res, Phase: phase, Signals: tcpSignals(o),
	}, tcp: &o})
	return o, true
}

func ap(a netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(a, port) }

func (r *runner) b1(ctx context.Context) {
	if !r.googleAddr.ok() {
		r.skip("B1", "google", "no_address")
		return
	}
	r.tcp(ctx, "B1", "google", r.googleAddr.src, tcpSpec{To: ap(r.googleAddr.a, 443), SNI: r.t.Google, FP: FPChromeH1,
		Verify: true, Request: true, Path: "/generate_204", ReadLimit: 4096})
}

func (r *runner) b2(ctx context.Context) {
	r.location = ""
	if !r.googleAddr.ok() {
		r.skip("B2", "google", "no_address")
		return
	}
	o, _ := r.tcp(ctx, "B2", "google", r.googleAddr.src, tcpSpec{To: ap(r.googleAddr.a, 443), SNI: r.t.Google, FP: FPChromeH1,
		Verify: true, Request: true, Host: r.t.GoogleFrontHost, Path: r.t.GoogleFrontPath, ReadLimit: 8192})
	if o.HTTPStatus >= 300 && o.HTTPStatus < 400 {
		r.location = o.Location
	}
}

// b3 follows ONE redirect of the front, and only to a name under the
// list's redirect suffix; anything else is not followed.
func (r *runner) b3(ctx context.Context) {
	loc := r.location
	r.location = ""
	u, err := url.Parse(loc)
	suffix := "." + strings.TrimPrefix(r.t.RedirectSuffix, ".")
	if loc == "" || err != nil || u.Scheme != "https" || !strings.HasSuffix(strings.ToLower(u.Hostname()), suffix) || checkName(u.Hostname()) != nil {
		r.skip("B3", "google", "")
		return
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	r.tcp(ctx, "B3", "google", r.googleAddr.src, tcpSpec{To: ap(r.googleAddr.a, 443), SNI: r.t.Google, FP: FPChromeH1,
		Verify: true, Request: true, Host: strings.ToLower(u.Hostname()), Path: path, ReadLimit: 8192})
}

func (r *runner) b4(ctx context.Context) {
	if !r.githubAddr.ok() {
		r.skip("B4", "github", "no_address")
		return
	}
	r.tcp(ctx, "B4", "github", r.githubAddr.src, tcpSpec{To: ap(r.githubAddr.a, 443), SNI: r.t.GitHub, FP: FPChromeH1,
		Verify: true, Request: true, Path: r.t.GitHubFeedPath, ReadLimit: 32 * 1024})
}

func (r *runner) b5(ctx context.Context) {
	if !r.whiteAddr.ok() {
		r.skip("B5", "white_name", "no_address")
		return
	}
	r.tcp(ctx, "B5", "white_name", r.whiteAddr.src, tcpSpec{To: ap(r.whiteAddr.a, 443), SNI: r.t.WhiteName, FP: FPChromeH1,
		Verify: true, Request: true, Path: r.t.WhitePath, ReadLimit: 64 * 1024, CarryExpected: true})
}

// b6 counts bytes only: Chrome's own hello, answered h2 or HTTP/1.1.
func (r *runner) b6(ctx context.Context) {
	if !r.cfAddr.ok() {
		r.skip("B6", "cf_edge", "no_address")
		return
	}
	r.tcp(ctx, "B6", "cf_edge", r.cfAddr.src, tcpSpec{To: ap(r.cfAddr.a, 443), SNI: r.t.CFNeutral, FP: FPChrome,
		Verify: true, Request: true, Path: r.t.CFNeutralPath, ReadLimit: 64 * 1024, CarryExpected: true})
}

func (r *runner) b7(ctx context.Context) {
	cfg, variant := r.echConfig, "dns_config"
	if len(cfg) == 0 {
		cfg, variant = r.t.echConfig, "list_config"
	}
	if !r.cfAddr.ok() || len(cfg) == 0 {
		r.skip("B7", "cf_edge", "no_config")
		return
	}
	sp := tcpSpec{To: ap(r.cfAddr.a, 443), SNI: r.t.CFECHInner, FP: FPGoStd, ECH: cfg, Verify: true,
		Request: true, Path: r.t.CFTracePath, ReadLimit: 4096}
	o, ok := r.tcp(ctx, "B7", "cf_edge", variant, sp)
	if ok && !o.HandshakeOK && len(o.ECHRetry) > 0 && ctx.Err() == nil {
		// The server's retry configs, honoured once.
		sp.ECH = o.ECHRetry
		o, _ = r.tcp(ctx, "B7", "cf_edge", variant+"+retry", sp)
	}
	if o.HandshakeOK && o.CertValid && o.ECHAccepted && strings.Contains(string(o.Body), "sni=encrypted") {
		r.res.ECHEncrypted = true
	}
}

func (r *runner) b8(ctx context.Context) {
	if !r.cfAddr.ok() {
		r.skip("B8", "cf_edge", "no_address")
		return
	}
	r.tcp(ctx, "B8", "cf_edge", r.cfAddr.src, tcpSpec{To: ap(r.cfAddr.a, 443), SNI: r.t.CFECHInner, FP: FPGoStd,
		Verify: true, Request: true, Path: r.t.CFTracePath, ReadLimit: 4096})
}

func (r *runner) b9(ctx context.Context) {
	for _, q := range []struct {
		v, sni string
		at     addrPick
		role   string
	}{{"google", r.t.Google, r.googleAddr, "google"}, {"cloudflare", r.t.CFECHInner, r.cfAddr, "cf_edge"}} {
		if !q.at.ok() || r.res.QUICs >= 4 {
			r.skip("B9", q.role, q.v)
			continue
		}
		r.res.QUICs++
		r.charge()
		ok, kind := r.env.QUIC.Handshake(ctx, ap(q.at.a, 443), q.sni)
		if ctx.Err() != nil {
			r.skip("B9", q.role, q.v)
			return
		}
		res := "ok"
		switch {
		case ok:
		case kind == "refused":
			res = "refused"
		case kind == "local_error" || kind == "local_blocked":
			res = "local_error"
		case kind == "unreachable":
			res = "unreachable"
		default:
			res = "timeout"
		}
		phase := "handshake"
		switch {
		case ok:
			phase = "carry"
		case res == "local_error" || res == "unreachable":
			phase = "reach"
		}
		r.res.Probes = append(r.res.Probes, ProbeRecord{Probe: fieldreport.Probe{ID: "B9", Name: fieldreport.ProbeNames["B9"],
			TargetRole: q.role, Variant: q.v, Result: res, Phase: phase}, udp: true})
	}
}

// ---- Stage C: the Test relay ------------------------------------------------

// relayFlow takes one of the run's MaxRelayFlows connections to the Test
// relay, or says there is none left.
func (r *runner) relayFlow() bool {
	if r.res.RelayFlows >= MaxRelayFlows {
		return false
	}
	r.res.RelayFlows++
	return true
}

func (r *runner) prove(ctx context.Context, id, variant, handle, desync string) string {
	if !r.haveRelay || handle == "" {
		r.skip(id, "relay", variant)
		return "skipped"
	}
	if r.res.Conns >= r.env.MaxConns {
		r.skip(id, "relay", variant)
		r.res.AbortReason = "budget"
		return "skipped"
	}
	if !r.relayFlow() {
		r.skip(id, "relay", variant)
		return "skipped"
	}
	r.res.Conns++
	r.charge()
	out := r.env.Relay.Prove(ctx, handle, desync)
	if ctx.Err() != nil {
		out.Cancelled = true
	}
	res, phase := classifyRelay(out)
	r.add(id, "relay", variant, res, phase, fieldreport.Signals{})
	return res
}

func (r *runner) c2(ctx context.Context) { r.prove(ctx, "C2", "desync_off", r.relay.Main, "off") }

func (r *runner) c3(ctx context.Context) {
	if !r.haveRelay || !r.relay.DesyncAvailable {
		r.skip("C3", "relay", "unavailable")
		return
	}
	first := "sni-cut"
	if r.relay.DesyncOffer {
		first = "pack"
	}
	res := r.prove(ctx, "C3", first, r.relay.Main, first)
	c2, _ := r.result("C2")
	if res != "ok" && res != "skipped" && c2 != "ok" && ctx.Err() == nil {
		second := "tlsrec-sni"
		if first == "pack" {
			second = "sni-cut"
		}
		if err := sleepCtx(ctx, r.env.Gap('C')); err == nil {
			r.prove(ctx, "C3", second, r.relay.Main, second)
		}
	}
}

// plain is C4–C6: a plain TLS hello with the given name to the relay's
// own address and port, Chrome's unmodified hello (only the handshake
// and the byte count are read), one GET /. REALITY forwards a hello it
// does not own to the cover site, so what comes back is the cover
// origin's answer — often a small 4xx or an alert, which still proves
// the hello passed the path (findings.go relayPathPassed).
func (r *runner) plain(ctx context.Context, id, variant, sni string) {
	if !r.haveRelay || sni == "" {
		r.skip(id, "relay", variant)
		return
	}
	if !r.relayFlow() {
		r.skip(id, "relay", variant)
		return
	}
	port := r.relay.Port
	if port == 0 {
		port = 443
	}
	r.tcp(ctx, id, "relay", variant, tcpSpec{To: ap(r.relay.Addr, port), SNI: sni, FP: FPChrome, Request: true, Path: "/",
		ReadLimit: 32 * 1024, CarryExpected: true})
}

func (r *runner) c4(ctx context.Context) { r.plain(ctx, "C4", "sni_white", r.t.WhiteName) }
func (r *runner) c5(ctx context.Context) { r.plain(ctx, "C5", "sni_cover", r.relay.CoverName) }
func (r *runner) c6(ctx context.Context) { r.plain(ctx, "C6", "sni_neutral", r.t.NeutralSNI) }

func (r *runner) c7(ctx context.Context) {
	for i, h := range r.relay.Alt {
		if i >= 2 {
			break
		}
		if i > 0 {
			if sleepCtx(ctx, r.env.Gap('C')) != nil {
				return
			}
		}
		r.prove(ctx, "C7", fmt.Sprintf("alt_%d", i+1), h, "off")
	}
}

func (r *runner) c8(ctx context.Context) {
	r.res.QUICs++
	r.prove(ctx, "C8", "udp", r.relay.QUIC, "off")
}

func (r *runner) c9(ctx context.Context) { r.prove(ctx, "C9", "desync_off", r.relay.Main, "off") }

// relayNames are the probes that share one address (the relay's) and
// so can be each other's control.
func relayName(id string) bool { return id == "C4" || id == "C5" || id == "C6" }

// reclassify applies the controls once the run is over. A stall under
// 16 KB (after the handshake, or in the middle of the server's flight)
// is a suspected cap only when another probe that can stand as this
// one's control carried ≥ 32 KB on this network: for C4–C6, another of
// them (same address); for Stage B, another Stage B probe.
func (r *runner) reclassify() {
	carried := func(i int, same func(string) bool) bool {
		for j, q := range r.res.Probes {
			if j != i && q.tcp != nil && same(q.ID) && q.tcp.Rx >= carriedBytes {
				return true
			}
		}
		return false
	}
	for i := range r.res.Probes {
		p := &r.res.Probes[i]
		if p.tcp == nil {
			continue
		}
		var c bool
		switch {
		case relayName(p.ID):
			c = carried(i, relayName)
		case p.ID[0] == 'B':
			c = carried(i, func(id string) bool { return id[0] == 'B' })
		default:
			continue
		}
		p.Result, p.Phase = classifyTCP(*p.tcp, &c)
	}
}
