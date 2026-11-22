// carrier.go — the update-note carriers, as the ladder sees them
// (docs/update-ladder-v2.md §2 "Walk order", §3, §4.1–4.4;
// specs/update-ladder-v2.md §4).
//
// A Carrier is one READER of a note write: github.com's tag feed and
// raw file, a Go module proxy, jsDelivr, the DNS micro-note. Reader
// lanes implement it in carrier_<name>.go and register it with
// RegisterCarrier from an init function; the ladder (ladder.go) asks the
// registry for them, orders them, spends the walk budget, and checks
// what they return. This file holds the types only: no network code.
//
// WHAT A CARRIER RETURNS IS NEVER TRUSTED BY BEING RETURNED.
//   - A micro note is a CANDIDATE standby key. The ladder uses it only
//     when Standby.Matches accepts it against the SIGNED commitment (the
//     carrier may use CarrierEnv.OpenMicro, which already checks, to
//     pick the one candidate worth returning out of many tags; the
//     ladder checks again).
//   - A full note is an opened daal-refresh-v2 container with the slot
//     it must name (bundle.NoteName). The ladder parses it with that slot
//     and verifies it exactly as a container from any mirror: signature
//     chain, sequence high-water mark, not_after, pack hash.
//
// A carrier never logs secrets, note names, tag names, the repository,
// the zone, or an address it read.

package refresh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fullnote"
	"daal/core/bootstrap"
)

// NoteKind is which notes a carrier can return (a bit set).
type NoteKind uint8

const (
	// NoteMicro: the 16-byte sealed standby key.
	NoteMicro NoteKind = 1 << iota
	// NoteFull: the sealed daal-refresh-v2 container.
	NoteFull
	// NoteBoth: either.
	NoteBoth = NoteMicro | NoteFull
)

// Carrier classes: the "one host per class" unit of the walk budget and
// of the strike rule (a class that failed twice on this network is
// skipped for 6 hours). One walk uses at most one carrier of a class.
const (
	ClassGitHub   = "github"   // github.com, raw.githubusercontent.com (rung 1)
	ClassGoogle   = "google"   // anything through the Google front (rung 2)
	ClassGoProxy  = "goproxy"  // proxy.golang.org direct, goproxy.cn, goproxy.io (rung 4)
	ClassJSDelivr = "jsdelivr" // the jsDelivr hosts (rung 4)
	ClassDNS      = "dns"      // the DNS micro-note (rung 3)
)

// Rungs of study §2 a carrier sits on. The walk order (1 → 2 → 4 → 3) is
// the ladder's, not the carrier's.
const (
	RungGitTag  = 1
	RungGoogle  = 2
	RungDNS     = 3
	RungReaders = 4
)

// CarrierCost is what one Fetch may spend at most: the ladder adds it to
// the walk's totals before calling (8 TCP connections and 6 DNS
// questions per walk) and skips a carrier that would not fit.
type CarrierCost struct {
	TCP int // TCP connections (TLS or not)
	DNS int // DNS questions
}

// CarrierInfo describes a carrier. It is constant for a carrier value.
type CarrierInfo struct {
	// Name is unique in the registry: "github", "goproxy-front",
	// "goproxy-direct", "goproxy-cn", "goproxy-io", "jsdelivr", "dns".
	// It is what the ladder's strikes and logs name (never a host the
	// carrier was configured with).
	Name string
	// Label is the note label the carrier reads (bundle.NoteCarrierGitTag
	// for every reader of the git-tag write, bundle.NoteCarrierDNS).
	Label string
	// Class is the budget class (Class*).
	Class string
	// Rung is the study §2 rung (Rung*).
	Rung int
	// Cost is the most one Fetch spends.
	Cost CarrierCost
	// Kinds is what Fetch can return.
	Kinds NoteKind
}

// Carrier is one reader. Fetch must honour ctx (the ladder bounds it by
// the walk's remaining time), dial only through env.Dialer (TCP) or to
// env.Resolver (DNS), stay within Info().Cost, and bound every read
// (bundle.MaxSealedFullNoteText for a full note's text, 64 KiB for an
// index such as a tag feed).
//
// Results:
//   - (notes, nil): what it found; zero notes means "nothing new here"
//     (filler, no tag yet, a note no held secret opens) and is NOT a
//     strike against the class;
//   - (nil, ErrCarrierUnconfigured): env lacks what this carrier needs
//     (no carriers member for it, no secret its audience rule allows, no
//     standby for a micro-only carrier). Not a strike; the ladder should
//     have asked Usable first;
//   - (nil, other error): the network failed (refused, reset, timeout,
//     a blocked name, an answer that is not the expected shape). A strike.
type Carrier interface {
	Info() CarrierInfo
	// Usable reports, without any I/O, whether Fetch has what it needs
	// in env. The ladder skips an unusable carrier without spending.
	Usable(env *CarrierEnv) bool
	Fetch(ctx context.Context, env *CarrierEnv) ([]Note, error)
}

// ErrCarrierUnconfigured: see Carrier.
var ErrCarrierUnconfigured = errors.New("refresh: carrier not configured for this relay")

// Note is one candidate a carrier found.
type Note struct {
	Kind    NoteKind // NoteMicro or NoteFull, never both
	Carrier string   // CarrierInfo.Name of the carrier that found it
	Epoch   uint64   // the epoch that opened it
	// Audience of the held secret that opened it (never the secret).
	Audience string

	// StandbyKey (NoteMicro) is a CANDIDATE: use it only when the
	// route's signed sealed standby Matches it.
	StandbyKey bundle.StandbyKeyBytes

	// Container (NoteFull) is the opened daal-refresh-v2 container, and
	// Slot the name it must carry (bundle.NoteName(u, Label, Epoch)).
	Container []byte
	Slot      string
}

// CarrierEnv is what a Fetch may use. The ladder builds one per relay
// pack per walk; carriers must not keep it.
type CarrierEnv struct {
	// RelayPackID is the relay pack the walk is for (for the carrier's
	// own bookkeeping only; it is not part of any name).
	RelayPackID string
	// Secrets are the route's held update secrets, newest first
	// (bundle.ParseHeldUpdateSecrets of bundle.UpdateSecretStoreKey).
	// Every helper below tries each in this order.
	Secrets []*bundle.UpdateSecret
	// Carriers is the held carriers member
	// (bundle.UpdateCarriersStoreKey), nil when none is held.
	Carriers *bundle.UpdateCarriers
	// Standby is the route's signed `_standby` when it is sealed (its
	// Commit binds every micro pad), nil otherwise. Micro notes need it.
	Standby *bundle.Standby
	// Now is the walk's clock (epochs are taken from it).
	Now time.Time
	// Dialer is the only way a carrier opens a TCP connection.
	Dialer bootstrap.Dialer
	// Resolver is "host:port" of the resolver the network gave the
	// phone, for DNS carriers; empty when unknown (a DNS carrier may
	// then find it itself through bootstrap, or be unusable). Never a
	// public resolver.
	Resolver string
}

// NoteTry is one (secret, epoch) a reader tries, with the name it gives.
type NoteTry struct {
	Secret *bundle.UpdateSecret
	Epoch  uint64
	Name   string // bundle.NoteName(Secret, label, Epoch)
}

// Tries lists what a reader of label tries for notes of kind k: each
// held secret (newest first) at each reader epoch (e, then e−1), with
// the note name. For NoteMicro on DNS the audience rule applies
// (bundle.MicroNoteAllowed): the Everyone secret is skipped.
func (env *CarrierEnv) Tries(label string, k NoteKind) []NoteTry {
	if env == nil {
		return nil
	}
	var out []NoteTry
	for _, u := range env.Secrets {
		if u == nil || (k == NoteMicro && !bundle.MicroNoteAllowed(label, u.Audience)) {
			continue
		}
		for _, e := range bundle.NoteReaderEpochs(label, env.Now) {
			n, err := bundle.NoteName(u.Secret, label, e)
			if err != nil {
				return nil
			}
			out = append(out, NoteTry{Secret: u, Epoch: e, Name: n})
		}
	}
	return out
}

// OpenMicro opens a sealed micro note read from a carrier of label:
// every held secret at every reader epoch, the first candidate the
// signed commitment accepts (bundle.Standby.OpenMicroNote). false when
// none does, or env has no sealed standby.
func (env *CarrierEnv) OpenMicro(carrier, label string, sealed [bundle.MicroNoteLen]byte) (Note, bool) {
	if env == nil || env.Standby == nil {
		return Note{}, false
	}
	k, u, e, ok := env.Standby.OpenMicroNote(label, env.Now, sealed, env.Secrets)
	if !ok {
		return Note{}, false
	}
	return Note{Kind: NoteMicro, Carrier: carrier, Epoch: e, Audience: u.Audience, StandbyKey: k}, true
}

// OpenFull opens a sealed full note (raw bytes; decode a text form with
// bundle.DecodeFullNoteText first) read from a carrier of label. false
// when no held secret at any reader epoch opens it.
func (env *CarrierEnv) OpenFull(carrier, label string, sealed []byte) (Note, bool) {
	if env == nil {
		return Note{}, false
	}
	o, err := fullnote.Open(label, env.Now, sealed, env.Secrets)
	if err != nil {
		return Note{}, false
	}
	return Note{Kind: NoteFull, Carrier: carrier, Epoch: o.Epoch, Audience: o.Secret.Audience,
		Container: o.Container, Slot: o.Slot}, true
}

// OpenFullAt opens a sealed full note found under one try's name (the
// carrier already knows which secret and epoch it asked for).
func (env *CarrierEnv) OpenFullAt(carrier, label string, t NoteTry, sealed []byte) (Note, bool) {
	if t.Secret == nil {
		return Note{}, false
	}
	c, err := fullnote.OpenWith(t.Secret.Secret, label, t.Epoch, sealed)
	if err != nil {
		return Note{}, false
	}
	return Note{Kind: NoteFull, Carrier: carrier, Epoch: t.Epoch, Audience: t.Secret.Audience,
		Container: c, Slot: t.Name}, true
}

// --- Registry --------------------------------------------------------------

var (
	carrierMu  sync.Mutex
	carrierReg = map[string]Carrier{}
)

// RegisterCarrier adds a carrier to the registry, from an init function
// of the file that defines it. It panics on an empty or duplicate name,
// an unknown label or class, or a carrier that returns nothing.
func RegisterCarrier(c Carrier) {
	if err := checkCarrierInfo(c.Info()); err != nil {
		panic(err)
	}
	carrierMu.Lock()
	defer carrierMu.Unlock()
	n := c.Info().Name
	if _, dup := carrierReg[n]; dup {
		panic(fmt.Sprintf("refresh: carrier %q registered twice", n))
	}
	carrierReg[n] = c
}

func checkCarrierInfo(i CarrierInfo) error {
	switch {
	case i.Name == "":
		return errors.New("refresh: carrier without a name")
	case !bundle.NoteCarrierLabelOK(i.Label):
		return fmt.Errorf("refresh: carrier %q: bad label", i.Name)
	case i.Class == "":
		return fmt.Errorf("refresh: carrier %q: no class", i.Name)
	case i.Kinds&NoteBoth == 0:
		return fmt.Errorf("refresh: carrier %q returns nothing", i.Name)
	case i.Cost.TCP < 0 || i.Cost.DNS < 0 || i.Cost.TCP+i.Cost.DNS == 0:
		return fmt.Errorf("refresh: carrier %q: bad cost", i.Name)
	}
	return nil
}

// RegisteredCarriers is every registered carrier, sorted by rung then
// name. The ladder applies its own walk order and budget.
func RegisteredCarriers() []Carrier {
	carrierMu.Lock()
	out := make([]Carrier, 0, len(carrierReg))
	for _, c := range carrierReg {
		out = append(out, c)
	}
	carrierMu.Unlock()
	SortCarriers(out)
	return out
}

// SortCarriers sorts by rung, then name (deterministic; tests rely on it).
func SortCarriers(cs []Carrier) {
	sort.SliceStable(cs, func(a, b int) bool {
		ia, ib := cs[a].Info(), cs[b].Info()
		if ia.Rung != ib.Rung {
			return ia.Rung < ib.Rung
		}
		return ia.Name < ib.Name
	})
}

// --- Fake ------------------------------------------------------------------

// FakeCarrier is a carrier for tests: it returns Notes and Err, counts
// its calls, and can run FetchFn instead. It does no I/O. UsableFn nil
// means always usable.
type FakeCarrier struct {
	InfoV    CarrierInfo
	Notes    []Note
	Err      error
	FetchFn  func(ctx context.Context, env *CarrierEnv) ([]Note, error)
	UsableFn func(env *CarrierEnv) bool

	mu    sync.Mutex
	calls int
	envs  []*CarrierEnv
}

func (f *FakeCarrier) Info() CarrierInfo { return f.InfoV }

func (f *FakeCarrier) Usable(env *CarrierEnv) bool {
	if f.UsableFn == nil {
		return true
	}
	return f.UsableFn(env)
}

func (f *FakeCarrier) Fetch(ctx context.Context, env *CarrierEnv) ([]Note, error) {
	f.mu.Lock()
	f.calls++
	f.envs = append(f.envs, env)
	f.mu.Unlock()
	if f.FetchFn != nil {
		return f.FetchFn(ctx, env)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Err != nil {
		return nil, f.Err
	}
	return append([]Note(nil), f.Notes...), nil
}

// Calls is how many times Fetch ran.
func (f *FakeCarrier) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Envs are the envs Fetch was called with, in order.
func (f *FakeCarrier) Envs() []*CarrierEnv {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*CarrierEnv(nil), f.envs...)
}

// noDialer is a bootstrap.Dialer that refuses every dial: for envs in
// tests that must prove a carrier does no I/O.
type noDialer struct{}

func (noDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("refresh: dial refused (test)")
}

// NoDialer is a dialer that refuses every connection.
var NoDialer bootstrap.Dialer = noDialer{}
