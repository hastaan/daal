// Package edgepick chooses the CDN edge address a CDN-fronted route
// dials (optional add-ons item B-6; docs/optional-addons-plan.md §2.2,
// §2.7, §4; specs/relaypack-v1.md "The CDN-fronted endpoint").
//
// A CDN-fronted route's signed commitment names a host name and a few
// edge PREFIXES (`edge_seeds`), never an address: the recipient never
// resolves the name (domestic DNS answers 10.10.34.x) and never
// downloads a range list. Which addresses inside those prefixes pass
// on a given network is unknown from outside — reports differ per ISP,
// and some edge addresses are allowed only a handful of packets before
// the connection is cut. This package is the device's answer:
//
//   - CANDIDATES (Candidates): a few addresses inside the seeds, spread
//     across them, chosen deterministically from a salt (the network
//     and the route). The same network sees the same few addresses —
//     never a sweep of a prefix — and another network other ones.
//   - A PROBE (Prober, Exchange) run only in the failure state: when
//     the address in use stopped answering. It opens TLS to the
//     candidate with a NEUTRAL name (never the route's zone) and makes
//     more than ten packets' worth of exchange, so an address that
//     lets a handshake through and cuts the connection a few packets
//     later is not taken for a clean one.
//   - PER-NETWORK MEMORY (Memory): which addresses passed or failed on
//     this network, and when. A pass is good for GoodFor, a failure
//     keeps the address out for BadFor. Addresses only — public CDN
//     addresses, the same for every customer of the CDN — and the
//     caller stores the memory encrypted beside the network's other
//     memory.
//
// Pick puts the three together. It never resolves a name, never reads
// a range list, and dials nothing outside the signed seeds. The caller
// (core/abi connect_cdn.go) bounds how often it runs against the
// network's hourly side-probe allowance.
package edgepick

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"
)

const (
	// GoodFor: an address that passed here is preferred for this long
	// without a fresh pass.
	GoodFor = 7 * 24 * time.Hour
	// BadFor: an address that failed here is not tried again for this
	// long (the ladder's variant expiry, netmem VariantBlockedExpiry).
	BadFor = 72 * time.Hour
	// MaxRecords bounds the memory of one network.
	MaxRecords = 32
	// DefaultMaxProbes: candidates probed in one Pick at most.
	DefaultMaxProbes = 3
	// candidatesPerSeed: how many distinct addresses one seed prefix
	// contributes to the candidate list at most.
	candidatesPerSeed = 4
)

// Candidates returns up to n distinct host addresses inside seeds, in
// the order they should be tried: round-robin over the prefixes, and
// inside each prefix a pseudo-random address derived from salt. The
// network and subnet-broadcast-looking ends of an IPv4 prefix (.0,
// .255) are never chosen. Deterministic: the same seeds and salt give
// the same list.
func Candidates(seeds []netip.Prefix, salt string, n int) []netip.Addr {
	if n <= 0 || len(seeds) == 0 {
		return nil
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for round := 0; round < candidatesPerSeed && len(out) < n; round++ {
		for si, p := range seeds {
			if len(out) >= n {
				break
			}
			if !p.IsValid() {
				continue
			}
			p = p.Masked()
			for try := 0; try < 8; try++ {
				a, ok := addrIn(p, salt, si, round, try)
				if ok && !seen[a] {
					seen[a] = true
					out = append(out, a)
					break
				}
			}
		}
	}
	return out
}

// addrIn derives one host address inside p from the salt.
func addrIn(p netip.Prefix, salt string, si, round, try int) (netip.Addr, bool) {
	h := sha256.New()
	h.Write([]byte("daal/edgepick-v1|"))
	h.Write([]byte(salt))
	var idx [12]byte
	binary.BigEndian.PutUint32(idx[0:], uint32(si))
	binary.BigEndian.PutUint32(idx[4:], uint32(round))
	binary.BigEndian.PutUint32(idx[8:], uint32(try))
	h.Write(idx[:])
	h.Write([]byte(p.String()))
	sum := h.Sum(nil)
	base := p.Addr().AsSlice()
	bits := len(base)*8 - p.Bits()
	if bits <= 0 {
		a := p.Addr()
		return a, !(a.Is4() && (base[3] == 0 || base[3] == 255))
	}
	// Fill the host bits from the digest, most significant first.
	out := append([]byte(nil), base...)
	for i := 0; i < bits; i++ {
		bit := len(out)*8 - 1 - i
		byteIdx, mask := bit/8, byte(1)<<(7-uint(bit%8))
		if sum[(i/8)%len(sum)]&(byte(1)<<(uint(i)%8)) != 0 {
			out[byteIdx] |= mask
		} else {
			out[byteIdx] &^= mask
		}
	}
	a, ok := netip.AddrFromSlice(out)
	if !ok || !p.Contains(a) {
		return netip.Addr{}, false
	}
	if a.Is4() {
		last := out[3]
		if last == 0 || last == 255 {
			return netip.Addr{}, false
		}
	}
	return a, true
}

// Record is what one network remembers of one edge address.
type Record struct {
	// OK: the last thing known is a pass (a probe, or the route carried
	// through it); false: a failure.
	OK bool `json:"ok"`
	// At is when that was learnt (Unix seconds).
	At int64 `json:"at"`
}

// Memory is one network's record of edge addresses, by address.
type Memory struct {
	Edges map[string]Record `json:"edges"`
}

// Unmarshal reads a Memory; anything unreadable is an empty one.
func Unmarshal(b []byte) *Memory {
	m := &Memory{}
	if len(b) > 0 && json.Unmarshal(b, m) == nil && m.Edges != nil {
		return m
	}
	return &Memory{Edges: map[string]Record{}}
}

// Marshal writes the memory.
func (m *Memory) Marshal() []byte {
	b, _ := json.Marshal(m)
	return b
}

// Clone is a copy that shares nothing with m.
func (m *Memory) Clone() *Memory {
	out := &Memory{Edges: make(map[string]Record, len(m.Edges))}
	for k, v := range m.Edges {
		out.Edges[k] = v
	}
	return out
}

// Note records a pass or a failure of addr at now, and keeps the
// memory within MaxRecords (the oldest records go first).
func (m *Memory) Note(addr netip.Addr, ok bool, now time.Time) {
	if !addr.IsValid() {
		return
	}
	if m.Edges == nil {
		m.Edges = map[string]Record{}
	}
	m.Edges[addr.Unmap().String()] = Record{OK: ok, At: now.Unix()}
	if len(m.Edges) <= MaxRecords {
		return
	}
	type kv struct {
		k  string
		at int64
	}
	all := make([]kv, 0, len(m.Edges))
	for k, r := range m.Edges {
		all = append(all, kv{k, r.At})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at < all[j].at || (all[i].at == all[j].at && all[i].k < all[j].k) })
	for _, e := range all[:len(all)-MaxRecords] {
		delete(m.Edges, e.k)
	}
}

// Bad: addr failed here within BadFor.
func (m *Memory) Bad(addr netip.Addr, now time.Time) bool {
	r, ok := m.Edges[addr.Unmap().String()]
	return ok && !r.OK && now.Sub(time.Unix(r.At, 0)) < BadFor
}

// GoodIn is the most recent address inside seeds that passed here
// within GoodFor; false when there is none.
func (m *Memory) GoodIn(seeds []netip.Prefix, now time.Time) (netip.Addr, bool) {
	var best netip.Addr
	var bestAt int64
	for k, r := range m.Edges {
		if !r.OK || now.Sub(time.Unix(r.At, 0)) >= GoodFor {
			continue
		}
		a, err := netip.ParseAddr(k)
		if err != nil || !inSeeds(seeds, a) {
			continue
		}
		if !best.IsValid() || r.At > bestAt || (r.At == bestAt && a.Less(best)) {
			best, bestAt = a, r.At
		}
	}
	return best, best.IsValid()
}

func inSeeds(seeds []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range seeds {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Prober answers whether an edge address carries more than a handshake
// from here. nil error: it did.
type Prober interface {
	Probe(ctx context.Context, addr netip.AddrPort) error
}

// ErrNoCandidate: no address inside the seeds is left to try here.
var ErrNoCandidate = errors.New("edgepick: no edge address left to try on this network")

// PickInput is one Pick.
type PickInput struct {
	Seeds []netip.Prefix
	Port  int
	// Salt makes the candidate list this network's and this route's
	// (the caller passes a digest; never shown).
	Salt string
	// Failed is the address that has just stopped answering (zero when
	// none): noted as a failure and never picked again in this Pick.
	Failed netip.Addr
	// Mem is the network's memory; Pick updates it.
	Mem    *Memory
	Prober Prober
	// MaxProbes bounds the probes of this Pick (DefaultMaxProbes when
	// 0); the caller passes what is left of its hourly allowance.
	MaxProbes int
	// ProbeTimeout bounds each probe (5 s when 0).
	ProbeTimeout time.Duration
	Now          time.Time
}

// PickResult is what a Pick found.
type PickResult struct {
	Addr netip.Addr
	// OK: Addr passed (a probe of this Pick, or a fresh pass on record).
	OK bool
	// Probed: probes made (each one connection to the CDN).
	Probed int
	// FromMemory: Addr is a recorded pass; nothing was probed for it.
	FromMemory bool
}

// Pick finds an edge address for a route on this network:
//
//  1. Failed (if any) is noted as a failure;
//  2. a recorded pass inside the seeds, other than Failed, is taken
//     without a probe;
//  3. otherwise the candidates (Candidates) not recorded as failed are
//     probed in order, at most MaxProbes of them; the first that
//     passes is taken. Each probe's result is recorded.
//
// ErrNoCandidate when nothing passed (or nothing was left to probe);
// the context's error when it ended first.
func Pick(ctx context.Context, in PickInput) (PickResult, error) {
	if in.Mem == nil {
		in.Mem = &Memory{Edges: map[string]Record{}}
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if in.Failed.IsValid() {
		in.Mem.Note(in.Failed, false, now)
	}
	if a, ok := in.Mem.GoodIn(in.Seeds, now); ok && a != in.Failed.Unmap() {
		return PickResult{Addr: a, OK: true, FromMemory: true}, nil
	}
	max := in.MaxProbes
	if max <= 0 {
		max = DefaultMaxProbes
	}
	timeout := in.ProbeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var res PickResult
	if in.Prober == nil || in.Port <= 0 || in.Port > 65535 {
		return res, ErrNoCandidate
	}
	for _, a := range Candidates(in.Seeds, in.Salt, 4*candidatesPerSeed) {
		if res.Probed >= max {
			break
		}
		if a == in.Failed.Unmap() || in.Mem.Bad(a, now) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		err := in.Prober.Probe(pctx, netip.AddrPortFrom(a, uint16(in.Port)))
		cancel()
		res.Probed++
		if ctx.Err() != nil {
			// Stopped from outside: what this probe saw says nothing.
			return res, ctx.Err()
		}
		in.Mem.Note(a, err == nil, now)
		if err == nil {
			res.Addr, res.OK = a, true
			return res, nil
		}
	}
	return res, ErrNoCandidate
}
