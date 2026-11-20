// relaypack_recover.go — the two UNSCHEDULED ways a freshness walk
// runs (blackout plan §3, work item C0).
//
// THE GAP THIS CLOSES. A recipient whose relay address is null-routed
// while the app still holds the route never learned the new address:
//
//   - the scheduled poll runs through the tunnel guard, and while a
//     route is active the guard refuses a direct fetch (dialer.go) — so
//     every tick of a connected-but-dead route was refused;
//   - each refusal stamped a FAILURE, doubling the retry gap up to the
//     6 h staleness ceiling, so the first direct try after the person
//     finally disconnected could be hours away;
//   - nothing else ever called the walk.
//
// Two kinds are added beside the scheduled one, and neither weakens the
// guard. Both dial DIRECT only after TunnelRequired() has said false —
// that is, after the engine has stopped the dead instance and cleared
// the flag itself (core/abi/relaypack_recover.go) — and the dialer they
// get re-asks that question on every dial, so a route that comes up
// half-way through the walk turns its remaining dials into refusals
// rather than into the leak the guard exists for.
//
//	failure    the engine's own call when a route is failed-but-running
//	           and an automatic pass found nothing else that carries.
//	           Bypasses the cadence floor (NOT the lifeline-strict gate:
//	           in that mode only the person's button walks). Rate-limited
//	           on its OWN stamps, per pack:
//	             - per network: once per FailureFloor (10 min, doubling
//	               per walk on that network that found nothing new,
//	               capped at 1 h);
//	             - a network not walked yet: after networkChangeFloor
//	               (1 min) since the last walk anywhere;
//	             - a hard ceiling whatever the network:
//	               failureHourCeiling walks an hour, failureDayCeiling a
//	               day — a phone flapping between networks must not turn
//	               "a new network is new information" into a beacon.
//	           No pointer recovery: one bounded walk, nothing more. A
//	           walk that was cancelled, or never reached the network,
//	           does not spend the floor and is not a miss.
//	on_demand  the person pressed a button (engine_relaypack_refresh).
//	           Rides the tunnel while a route is active (or is refused),
//	           dials direct when none is. Rate-limited per pack to one
//	           walk per OnDemandFloor (1 min), then 2 min, then 5 min for
//	           presses in a row that found nothing new, so a button
//	           cannot become a per-tap beacon from the real address.
//
// The direct dialer asks RouteActive(), not TunnelRequired(): while the
// engine has paused a dead route for its walk, the RECOVERY WINDOW keeps
// TunnelRequired() true for every other fetcher (dialer.go), so the walk
// is the only thing that leaves the device directly.
//
// Neither kind touches LastFailureAt or ConsecutiveFailures. Those two
// drive the SCHEDULED poll's escalation, which exists so that a device
// whose mirrors are all blocked gets quieter over time; a walk the
// engine made because the RELAY went dead, or one the person asked for,
// says nothing about the mirrors' cadence and must not move it. A walk
// that verifies a document still counts as a success (markSuccess) —
// it is one: the publisher's statement reached the device.

package refresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"daal/core/bootstrap"
)

// refreshKind says which entry point started an attempt.
type refreshKind int

const (
	kindScheduled refreshKind = iota
	kindUser
	kindFailure
	kindOnDemand
)

func (k refreshKind) String() string {
	switch k {
	case kindUser:
		return "user"
	case kindFailure:
		return "failure"
	case kindOnDemand:
		return "on_demand"
	}
	return "scheduled"
}

// unscheduled: the two kinds this file adds.
func (k refreshKind) unscheduled() bool { return k == kindFailure || k == kindOnDemand }

// Rate limits of the unscheduled kinds. Exported where the ABI or a rig
// needs to reason about them.
const (
	// DefaultFailureFloor is the least gap between two failure-triggered
	// walks of one pack on one network. It doubles per walk that found
	// nothing new, up to MaxFailureFloor.
	DefaultFailureFloor = 10 * time.Minute
	MaxFailureFloor     = time.Hour
	// networkChangeFloor: on a network not walked yet (in the last
	// failureNetsMax networks), the walk may run this long after the last
	// walk anywhere — a new network is new information (another ISP,
	// another block list). A network already walked keeps its OWN
	// escalating floor, so a phone flapping between two access points
	// gets one walk per network per floor, not one per flap.
	networkChangeFloor = time.Minute
	// failureNetsMax: how many networks' stamps a pack keeps.
	failureNetsMax = 4
	// The hard ceiling of failure-triggered walks per pack, whatever the
	// network.
	failureHourCeiling = 4
	failureDayCeiling  = 12
	// DefaultOnDemandFloor is the least gap between two walks the person
	// asked for, per pack. It is 2× after two presses in a row that found
	// nothing new and 5× after three or more; a press more than
	// onDemandStreakReset after the last starts the count again.
	DefaultOnDemandFloor = time.Minute
	onDemandStreakReset  = time.Hour
)

// failureNetStamp is one network's failure-walk stamp.
type failureNetStamp struct {
	Tag    string `json:"t"`
	At     string `json:"at"`
	Misses int    `json:"m,omitempty"`
}

// ---- one attempt per pack at a time ---------------------------------

// packLocks serialises the attempts on one pack's record: the scheduled
// poll, the engine's failure walk and the person's button each read,
// change and write the same freshnessRecord, and two of them racing
// would lose one's stamps. A pack already being walked is not walked a
// second time beside it — the attempt that finds it busy returns at once
// (packBusy) and stamps nothing.
var packLocks = struct {
	sync.Mutex
	busy map[string]bool
}{busy: map[string]bool{}}

func lockPack(relayPackID string) (unlock func(), ok bool) {
	packLocks.Lock()
	defer packLocks.Unlock()
	if packLocks.busy[relayPackID] {
		return nil, false
	}
	packLocks.busy[relayPackID] = true
	return func() {
		packLocks.Lock()
		delete(packLocks.busy, relayPackID)
		packLocks.Unlock()
	}, true
}

// packBusyRetry is what a busy pack's attempt reports as retry_after_s:
// about one walk.
const packBusyRetry = 30 * time.Second

func packBusy(relayPackID string, kind refreshKind) RelayPackResult {
	return RelayPackResult{RelayPackID: relayPackID, Kind: kind.String(),
		Outcome: OutcomeFreshnessRateLimited, RetryAfterS: ceilSeconds(packBusyRetry)}
}

// dialFor picks the dialer for one attempt of the given kind.
func (r *RelayPackRefresher) dialFor(kind refreshKind) (bootstrap.Dialer, bool, error) {
	switch kind {
	case kindFailure:
		d, err := r.directDial()
		return d, false, err
	case kindOnDemand:
		if RouteActive() {
			// A route is up: the same rule as every other fetch — the
			// tunnel, or nothing.
			return r.dial()
		}
		d, err := r.directDial()
		return d, false, err
	}
	if RecoveryWindowOpen() {
		// The engine has paused a dead route for its own walk. The
		// scheduled poll neither rides the dead tunnel's inlet nor goes
		// direct beside the walk: it is refused, like any fetch while a
		// route is held (and, like one, does not escalate).
		return nil, false, ErrTunnelRequired
	}
	return r.dial()
}

// directDial is the ONLY direct dialer the unscheduled kinds get, and it
// is conditional on there being no route: RouteActive is asked first,
// and again on every dial.
//
// The process-wide tunnel dialer is deliberately NOT consulted here: it
// points at the inlet of the instance that was running when it was
// installed, and with no instance running that inlet is gone — a walk
// through it would fail for a reason that has nothing to do with the
// mirrors, which is the other half of the connected-but-dead trap.
func (r *RelayPackRefresher) directDial() (bootstrap.Dialer, error) {
	if RouteActive() {
		return nil, ErrTunnelRequired
	}
	var inner bootstrap.Dialer
	if r.DirectDialer != nil {
		d, _, err := r.DirectDialer()
		if err != nil {
			return nil, err
		}
		inner = d
	}
	if inner == nil {
		inner = bootstrap.NewDirectDialer(15 * time.Second)
	}
	return routeDownDialer{inner: inner}, nil
}

// routeDownDialer refuses to dial once a route is active again. A walk
// is several dials (one per mirror, then the pack); a route the person
// starts half-way through must not find the rest of them going out from
// the device's real address.
type routeDownDialer struct{ inner bootstrap.Dialer }

func (d routeDownDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if RouteActive() {
		return nil, ErrTunnelRequired
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.inner.DialContext(ctx, network, address)
}

// failed records a walk that reached the network and found nothing
// usable. A cancelled unscheduled walk records nothing here: it learned
// nothing, and its caller restores what it stamped.
func (r *RelayPackRefresher) failed(kind refreshKind, relayPackID string, now time.Time, outcome string) {
	switch kind {
	case kindFailure, kindOnDemand:
		if outcome == OutcomeFreshnessCancelled {
			return
		}
		rec := r.loadRecord(relayPackID)
		rec.LastOutcome = outcome
		r.saveRecord(relayPackID, rec)
	default:
		r.markFailure(relayPackID, now, outcome)
	}
}

// refused records an attempt the tunnel guard stopped before it reached
// the network. The scheduled kinds keep their failure STAMP (so the base
// retry gap applies and a refused poll is not re-attempted every tick)
// but do not escalate: nothing was learned about the mirrors.
func (r *RelayPackRefresher) refused(kind refreshKind, relayPackID string, now time.Time, outcome string) {
	rec := r.loadRecord(relayPackID)
	rec.LastOutcome = outcome
	if kind == kindScheduled || kind == kindUser {
		rec.LastFailureAt = now.UTC().Format(time.RFC3339)
		rec.JitterMillis = drawJitter(r.policy().MaxJitter)
	}
	r.saveRecord(relayPackID, rec)
}

// netTag turns the engine's (already hashed) network id into the short
// value stored beside the stamp. Only equality is ever asked of it.
func netTag(networkKey string) string {
	if networkKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("daal/freshness-c0-net\x00" + networkKey))
	return hex.EncodeToString(sum[:8])
}

func (r *RelayPackRefresher) failureFloor(misses int) time.Duration {
	base := r.FailureFloor
	if base <= 0 {
		base = DefaultFailureFloor
	}
	ceiling := MaxFailureFloor
	if base > ceiling {
		ceiling = base
	}
	d := base
	for i := 1; i < misses && d < ceiling; i++ {
		d *= 2
	}
	if d > ceiling {
		d = ceiling
	}
	return d
}

func (r *RelayPackRefresher) onDemandFloor() time.Duration {
	if r.OnDemandFloor > 0 {
		return r.OnDemandFloor
	}
	return DefaultOnDemandFloor
}

// sinceStamp is how long ago a stamp was, or ok=false when there is
// none — or when it lies in the future: a clock that jumped backwards
// must not freeze recovery for as long as the jump.
func sinceStamp(stamp string, now time.Time) (time.Duration, bool) {
	t := parseStamp(stamp)
	if t.IsZero() || t.After(now) {
		return 0, false
	}
	return now.Sub(t), true
}

// netStampFor returns the stamp of the network tagged tag, or nil.
func (rec *freshnessRecord) netStampFor(tag string) *failureNetStamp {
	for i := range rec.OnFailureNets {
		if rec.OnFailureNets[i].Tag == tag {
			return &rec.OnFailureNets[i]
		}
	}
	return nil
}

// stampNet moves (or puts) the network tagged tag to the front of the
// list, stamped at, keeping its misses; at most failureNetsMax entries.
func (rec *freshnessRecord) stampNet(tag string, at string) {
	kept := failureNetStamp{Tag: tag, At: at}
	out := []failureNetStamp{}
	for _, e := range rec.OnFailureNets {
		if e.Tag == tag {
			kept.Misses = e.Misses
			continue
		}
		out = append(out, e)
	}
	out = append([]failureNetStamp{kept}, out...)
	if len(out) > failureNetsMax {
		out = out[:failureNetsMax]
	}
	rec.OnFailureNets = out
}

// pruneFailureLog keeps the stamps of the last 24 h (dropping any in
// the future: a clock that jumped backwards must not freeze recovery).
func pruneFailureLog(log []string, now time.Time) []string {
	var out []string
	for _, s := range log {
		if el, ok := sinceStamp(s, now); ok && el < 24*time.Hour {
			out = append(out, s)
		}
	}
	return out
}

// ceilingWait is how long until the hard ceiling allows another walk; 0
// when it does now.
func ceilingWait(log []string, now time.Time) time.Duration {
	var wait time.Duration
	check := func(window time.Duration, ceiling int) {
		var in []time.Time
		for _, s := range log {
			if el, ok := sinceStamp(s, now); ok && el < window {
				in = append(in, parseStamp(s))
			}
		}
		if len(in) < ceiling {
			return
		}
		oldest := in[0]
		for _, t := range in {
			if t.Before(oldest) {
				oldest = t
			}
		}
		// The (len-ceiling+1)-th oldest would do as well; the oldest is
		// the conservative, simple answer.
		if w := oldest.Add(window).Sub(now); w > wait {
			wait = w
		}
	}
	check(time.Hour, failureHourCeiling)
	check(24*time.Hour, failureDayCeiling)
	return wait
}

// FailureTriggeredDue reports whether a failure-triggered walk of this
// pack may run now on the network networkKey names, and if not, how long
// until it may. Reads the persisted record only; no network.
func (r *RelayPackRefresher) FailureTriggeredDue(relayPackID, networkKey string) (bool, time.Duration) {
	if r.Store == nil {
		return false, 0
	}
	rec := r.loadRecord(relayPackID)
	now := r.now()
	if w := ceilingWait(rec.OnFailureLog, now); w > 0 {
		return false, w
	}
	elapsed, ok := sinceStamp(rec.OnFailureAt, now)
	if !ok {
		return true, 0
	}
	// Whatever the network: not twice within networkChangeFloor.
	wait := networkChangeFloor - elapsed
	if e := rec.netStampFor(netTag(networkKey)); e != nil {
		// A network walked before keeps its own escalating floor.
		if el, ok := sinceStamp(e.At, now); ok {
			if w := r.failureFloor(e.Misses) - el; w > wait {
				wait = w
			}
		}
	}
	if wait <= 0 {
		return true, 0
	}
	return false, wait
}

// RefreshFailureTriggered is the engine's walk for a route that has
// stopped carrying (see the file comment). The caller must already have
// stopped the instance (RouteActive false); if it has not, the attempt
// is refused by the guard and NOTHING is stamped, so the next legitimate
// walk is not held back by one that never happened.
func (r *RelayPackRefresher) RefreshFailureTriggered(ctx context.Context, relayPackID, networkKey string) (RelayPackResult, error) {
	res := RelayPackResult{RelayPackID: relayPackID, Kind: kindFailure.String()}
	if r.Store == nil {
		return res, errNilStore
	}
	if RouteActive() {
		res.Outcome = OutcomeFreshnessTunnel
		recordAudit(r.Store, auditKindFreshness, relayPackID, res.Outcome, 0, false, r.now())
		return res, ErrTunnelRequired
	}
	if !r.shouldFire(false) {
		res.Outcome = SkippedLifelineStrict
		return res, nil
	}
	unlock, ok := lockPack(relayPackID)
	if !ok {
		return packBusy(relayPackID, kindFailure), nil
	}
	defer unlock()
	if due, wait := r.FailureTriggeredDue(relayPackID, networkKey); !due {
		res.Outcome = OutcomeFreshnessRateLimited
		res.RetryAfterS = ceilSeconds(wait)
		return res, nil
	}
	// Stamp BEFORE the walk: a process killed half-way still went out,
	// and the floor is about what went out. A walk that is CANCELLED, or
	// that never reached the network, gives the stamp back below.
	now := r.now()
	stamp := now.UTC().Format(time.RFC3339)
	tag := netTag(networkKey)
	before := r.loadRecord(relayPackID)
	rec := before
	rec.OnFailureAt = stamp
	rec.stampNet(tag, stamp)
	rec.OnFailureLog = append(pruneFailureLog(rec.OnFailureLog, now), stamp)
	r.saveRecord(relayPackID, rec)

	res, err := r.refresh(ctx, relayPackID, kindFailure)

	// The record may have moved with an applied pack (re-key).
	key := res.RelayPackID
	if key == "" {
		key = relayPackID
	}
	after := r.loadRecord(key)
	switch {
	case res.Applied || res.StandbyKeyAccepted:
		// New information (a pack applied, or a standby key that
		// opens a held route): every network's escalation starts again.
		after.OnFailureMisses = 0
		for i := range after.OnFailureNets {
			after.OnFailureNets[i].Misses = 0
		}
	case res.EndpointsTried == 0:
		// Nothing reached the network (refused, no endpoints, cancelled
		// before the first dial): as if it never happened.
		after.OnFailureAt, after.OnFailureNets, after.OnFailureLog = before.OnFailureAt, before.OnFailureNets, before.OnFailureLog
		after.OnFailureMisses = before.OnFailureMisses
	case res.Outcome == OutcomeFreshnessCancelled || errors.Is(ctx.Err(), context.Canceled):
		// Cut off from outside after it went out: the floor and the
		// escalation are given back (the next real outage must not wait
		// for a walk that learned nothing); the ceiling keeps counting
		// it, because bytes did leave.
		after.OnFailureAt, after.OnFailureNets = before.OnFailureAt, before.OnFailureNets
		after.OnFailureMisses = before.OnFailureMisses
		after.LastOutcome = before.LastOutcome
	default:
		after.OnFailureMisses++
		if e := after.netStampFor(tag); e != nil {
			e.Misses++
		}
	}
	r.saveRecord(key, after)
	return res, err
}

// onDemandFloorFor is the button's floor after streak presses in a row
// that found nothing new.
func (r *RelayPackRefresher) onDemandFloorFor(streak int) time.Duration {
	base := r.onDemandFloor()
	switch {
	case streak >= 3:
		return 5 * base
	case streak == 2:
		return 2 * base
	}
	return base
}

// OnDemandDue reports whether the person's button may walk this pack
// now, and if not, how long until it may. Reads the record only.
func (r *RelayPackRefresher) OnDemandDue(relayPackID string) (bool, time.Duration) {
	if r.Store == nil {
		return false, 0
	}
	rec := r.loadRecord(relayPackID)
	elapsed, ok := sinceStamp(rec.OnDemandAt, r.now())
	if !ok {
		return true, 0
	}
	floor := r.onDemandFloorFor(rec.OnDemandStreak)
	if elapsed >= floor {
		return true, 0
	}
	return false, floor - elapsed
}

// RefreshOnDemand is the walk the person asked for
// (engine_relaypack_refresh). See the file comment for the dialer rule.
func (r *RelayPackRefresher) RefreshOnDemand(ctx context.Context, relayPackID string) (RelayPackResult, error) {
	res := RelayPackResult{RelayPackID: relayPackID, Kind: kindOnDemand.String()}
	if r.Store == nil {
		return res, errNilStore
	}
	unlock, ok := lockPack(relayPackID)
	if !ok {
		return packBusy(relayPackID, kindOnDemand), nil
	}
	defer unlock()
	if due, wait := r.OnDemandDue(relayPackID); !due {
		res.Outcome = OutcomeFreshnessRateLimited
		res.RetryAfterS = ceilSeconds(wait)
		return res, nil
	}
	now := r.now()
	before := r.loadRecord(relayPackID)
	rec := before
	if el, ok := sinceStamp(rec.OnDemandAt, now); !ok || el >= onDemandStreakReset {
		rec.OnDemandStreak = 0
	}
	rec.OnDemandAt = now.UTC().Format(time.RFC3339)
	r.saveRecord(relayPackID, rec)
	res, err := r.refresh(ctx, relayPackID, kindOnDemand)
	key := res.RelayPackID
	if key == "" {
		key = relayPackID
	}
	after := r.loadRecord(key)
	switch {
	case res.Applied || res.StandbyKeyAccepted:
		after.OnDemandStreak = 0
	case res.EndpointsTried == 0 || res.Outcome == OutcomeFreshnessCancelled || errors.Is(ctx.Err(), context.Canceled):
		// Refused before it reached anything, or cut off: it does not
		// spend the person's next minute.
		after.OnDemandAt, after.OnDemandStreak = before.OnDemandAt, before.OnDemandStreak
	default:
		after.OnDemandStreak = rec.OnDemandStreak + 1
	}
	r.saveRecord(key, after)
	return res, err
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// errNilStore mirrors the message refresh() returns for the same case.
var errNilStore = errors.New("relaypack refresh: nil store")
