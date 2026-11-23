// drill.go — the person's check of the backup update routes (the
// "drill"; build/ux/notes/wave3-requirements.md §1, docs/update-ladder-v2.md
// §2 "The drill").
//
// WHAT IT IS. A walk the person starts for ONE pack that skips the
// ordinary mirrors and runs only the update ladder (ladder.go), so the
// person can see whether each backup route answers on this network. It
// is the ladder walk with three differences:
//
//   - it does not stop at the first note: every class it may ask is
//     asked (within the same caps: 8 TCP connections, 6 DNS questions,
//     120 s, 2–10 s between hosts, two connections to Google's front, one
//     carrier per class, one rung-4 reader);
//   - it ignores the strike hold, like the person's button (a failure
//     still counts as a strike, an answer still clears one), and it asks
//     a micro-only carrier even when every route keeps the key already
//     (whether the route answers is the question);
//   - its own rate limit: once per DrillFloor per pack, persisted in the
//     pack's freshness record (DrillAt); a stamp in the future (a clock
//     that jumped back) holds nothing.
//
// WHAT IS TRUSTED. Exactly what a ladder walk trusts: every note goes
// through weighNotes → verifyFullNote / acceptMicro, unchanged. A note
// that verifies as NEWER is real news and is applied through the same
// gate as any walk (refresh(): adoptDocument, applyBundle, the standby
// key store). When several classes bring a newer note, the one with the
// highest sequence is applied. Nothing found by the drill is trusted
// more or less than on any other walk.
//
// WHEN. Never while a route is up (refused before anything is dialled,
// and the walk's dialer refuses once one comes up), never from the
// scheduled poll, and only for a pack whose routes hold an update secret
// and a carriers member (otherwise OutcomeDrillNotHeld, nothing dialled).
//
// WHAT IT SAYS. RelayPackResult.Drill: per class one DrillClass — a word
// (reached / verified / nothing_new / failed / skipped) and, for
// skipped, a reason (not_in_file / no_resolver / budget / route_up /
// not_held). Never a host, a repository, a zone, a note name or an
// address. It is returned only; what is recorded is what any ladder walk
// records: RelayPackResult.Ladder and the "update_ladder" audit rows keep
// their three words (verified is nothing_new there, skipped is absent).

package refresh

import (
	"context"
	"time"

	"daal/bundle-go/bundle"
)

// DrillFloor is the least gap between two drills of one pack.
const DrillFloor = 10 * time.Minute

// OutcomeDrillNotHeld: the pack's routes hold no update secret or no
// carriers member, so there is no backup route to check. Nothing was
// dialled and nothing stamped.
const OutcomeDrillNotHeld = "ladder_not_held"

// The drill's per-class words.
const (
	// DrillReached: a newer note from this class verified and was applied
	// (a pack, or a standby key the engine's store kept).
	DrillReached = "reached"
	// DrillVerified: a note was read, opened and verified; nothing new.
	DrillVerified = "verified"
	// DrillNothingNew: the class answered, but no note verified (filler,
	// no note yet, a note no held secret opens or that failed a check).
	DrillNothingNew = "nothing_new"
	// DrillFailed: the network failed (a strike against the class).
	DrillFailed = "failed"
	// DrillSkipped: not asked; DrillClass.Reason says why.
	DrillSkipped = "skipped"
)

// Why a class was not asked.
const (
	// DrillSkipNotInFile: the file names no such route (no repository
	// for the git-tag readers, no zone for DNS).
	DrillSkipNotInFile = "not_in_file"
	// DrillSkipNoResolver: DNS is in the file but the phone knows no
	// resolver of its network to ask.
	DrillSkipNoResolver = "no_resolver"
	// DrillSkipBudget: the walk's caps left no room (connections,
	// questions, time, the one rung-4 reader per walk).
	DrillSkipBudget = "budget"
	// DrillSkipRouteUp: a route was up (or came up): nothing more went out.
	DrillSkipRouteUp = "route_up"
	// DrillSkipNotHeld: the file names the route but this phone holds
	// nothing it needs (no secret it may use there, no sealed standby).
	DrillSkipNotHeld = "not_held"
)

// DrillClass is one class's result of a drill.
type DrillClass struct {
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}

// skipRank orders the reasons when several carriers of one class were
// skipped for different ones: the reason closest to "it would have been
// asked" wins.
var skipRank = map[string]int{
	DrillSkipNotInFile:  1,
	DrillSkipNotHeld:    2,
	DrillSkipNoResolver: 3,
	DrillSkipBudget:     4,
	DrillSkipRouteUp:    5,
}

// drillTrace is what one ladder walk saw, class by class, in the drill's
// words. Built on every walk; read only by the drill.
type drillTrace struct {
	classes map[string]DrillClass
	// newerClass: the class whose newer note the walk handed back to be
	// applied (it says reached once refresh() applied it).
	newerClass string
	// cut: why the walk stopped early (route_up / budget), "" when it
	// walked to the end.
	cut string
}

func (d *drillTrace) set(class, word string) {
	if d == nil {
		return
	}
	d.classes[class] = DrillClass{Result: word}
}

// skip records a skipped class unless the class was asked, or was
// skipped for a reason that ranks higher.
func (d *drillTrace) skip(class, reason string) {
	if d == nil {
		return
	}
	if cur, ok := d.classes[class]; ok {
		if cur.Result != DrillSkipped || skipRank[cur.Reason] >= skipRank[reason] {
			return
		}
	}
	d.classes[class] = DrillClass{Result: DrillSkipped, Reason: reason}
}

// fill gives every class of order that has no entry yet one: its
// carrier's own reason (whyNot, no I/O) or, for a carrier the walk never
// reached, why the walk stopped.
func (d *drillTrace) fill(order []Carrier, whyNot func(Carrier) string) {
	if d == nil {
		return
	}
	for _, c := range order {
		why := ""
		if whyNot != nil && d.cut != DrillSkipRouteUp {
			why = whyNot(c)
		}
		if why == "" {
			why = d.cut
		}
		if why == "" {
			why = DrillSkipBudget
		}
		d.skip(c.Info().Class, why)
	}
}

// skipReasoner is what a carrier may implement to say precisely why it
// is not usable (the DNS reader: no resolver). Without it the ladder
// tells "not in the file" from "not held" by the carriers member alone.
type skipReasoner interface {
	SkipReason(env *CarrierEnv) string
}

// carrierSkipReason is the drill's reason a carrier is not usable.
func carrierSkipReason(c Carrier, env *CarrierEnv) string {
	if s, ok := c.(skipReasoner); ok {
		if w := s.SkipReason(env); w != "" {
			return w
		}
	}
	if env == nil || env.Carriers == nil {
		return DrillSkipNotInFile
	}
	switch c.Info().Label {
	case bundle.NoteCarrierGitTag:
		if env.Carriers.GitTag == nil {
			return DrillSkipNotInFile
		}
	case bundle.NoteCarrierDNS:
		if env.Carriers.DNS == nil {
			return DrillSkipNotInFile
		}
	}
	return DrillSkipNotHeld
}

// finish turns the trace into the answer: the class whose newer note
// was applied says reached; nil when the walk never reached the ladder.
func (d *drillTrace) finish(res RelayPackResult) map[string]DrillClass {
	if d == nil || len(d.classes) == 0 {
		return nil
	}
	out := make(map[string]DrillClass, len(d.classes))
	for k, v := range d.classes {
		out[k] = v
	}
	if d.newerClass != "" && (res.Applied || res.StandbyKeyAccepted) {
		out[d.newerClass] = DrillClass{Result: DrillReached}
	}
	return out
}

// DrillClasses is every class the drill would report on, in walk order
// (the walked rungs of the registry, or of LadderCarriers).
func (r *RelayPackRefresher) DrillClasses() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range ladderOrder(r.ladderCarriers()) {
		if cl := c.Info().Class; !seen[cl] {
			seen[cl] = true
			out = append(out, cl)
		}
	}
	return out
}

func (r *RelayPackRefresher) routeUpDrill() map[string]DrillClass {
	out := map[string]DrillClass{}
	for _, cl := range r.DrillClasses() {
		out[cl] = DrillClass{Result: DrillSkipped, Reason: DrillSkipRouteUp}
	}
	return out
}

// DrillDue reports whether a drill of this pack may run now, and if not,
// how long until it may. Reads the record only.
func (r *RelayPackRefresher) DrillDue(relayPackID string) (bool, time.Duration) {
	if r.Store == nil {
		return false, 0
	}
	rec := r.loadRecord(relayPackID)
	elapsed, ok := sinceStamp(rec.DrillAt, r.now())
	if !ok || elapsed >= DrillFloor {
		return true, 0
	}
	return false, DrillFloor - elapsed
}

// RefreshDrill is the person's check of the backup routes of one pack
// (see the file comment). The error is that of the walk (nil when a
// document verified, or when the drill was refused before anything
// went out); everything the caller shows is in the result.
func (r *RelayPackRefresher) RefreshDrill(ctx context.Context, relayPackID string) (RelayPackResult, error) {
	res := RelayPackResult{RelayPackID: relayPackID, Kind: kindDrill.String()}
	if r.Store == nil {
		return res, errNilStore
	}
	if RouteActive() {
		// Never while a route is up: nothing is dialled or stamped.
		res.Outcome = OutcomeFreshnessTunnel
		res.Drill = r.routeUpDrill()
		return res, ErrTunnelRequired
	}
	if r.loadLadderHeld(relayPackID) == nil {
		res.Outcome = OutcomeDrillNotHeld
		return res, nil
	}
	unlock, ok := lockPack(relayPackID)
	if !ok {
		return packBusy(relayPackID, kindDrill), nil
	}
	defer unlock()
	if due, wait := r.DrillDue(relayPackID); !due {
		res.Outcome = OutcomeFreshnessRateLimited
		res.RetryAfterS = ceilSeconds(wait)
		return res, nil
	}
	// Stamp BEFORE the walk: a process killed half-way still went out.
	// A drill that never reached the network gives the stamp back; one
	// that did keeps it even when cut off (bytes left the device).
	before := r.loadRecord(relayPackID)
	rec := before
	rec.DrillAt = r.now().UTC().Format(time.RFC3339)
	r.saveRecord(relayPackID, rec)
	networkKey := ""
	if r.NetworkKey != nil {
		networkKey = r.NetworkKey()
	}
	res, err := r.refresh(ctx, relayPackID, kindDrill, networkKey)
	if res.EndpointsTried == 0 {
		key := res.RelayPackID
		if key == "" {
			key = relayPackID
		}
		after := r.loadRecord(key)
		after.DrillAt = before.DrillAt
		r.saveRecord(key, after)
	}
	res.Drill = res.drill.finish(res)
	if res.Drill == nil && RouteActive() {
		res.Drill = r.routeUpDrill()
	}
	res.drill = nil
	return res, err
}

// Backup route words (BackupRoutes).
const (
	BackupRouteGitTag = "gittag"
	BackupRouteDNS    = "dns"
)

// BackupRoutes lists the backup update routes the pack's routes hold, in
// a fixed order: "gittag" when an update secret and the git-tag carrier
// are held, "dns" when an update secret DNS may use (not the Everyone
// one: bundle.MicroNoteAllowed), the DNS carrier and a sealed standby
// are held (a DNS note is a micro note: without the standby it can open
// nothing). nil for a file without them. Names nothing: no repository,
// no zone. Reads the store only.
func (r *RelayPackRefresher) BackupRoutes(relayPackID string) []string {
	h := r.loadLadderHeld(relayPackID)
	if h == nil {
		return nil
	}
	var out []string
	if h.carriers.GitTag != nil {
		out = append(out, BackupRouteGitTag)
	}
	if h.carriers.DNS != nil && h.standby != nil {
		for _, u := range h.secrets {
			if bundle.MicroNoteAllowed(bundle.NoteCarrierDNS, u.Audience) {
				out = append(out, BackupRouteDNS)
				break
			}
		}
	}
	return out
}
