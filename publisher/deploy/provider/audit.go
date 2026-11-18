package provider

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// ACCOUNT AUDIT — THE OPERATOR'S WAY OUT OF A HALF-DONE ROTATION.
//
// # Why this exists
//
// Provisioning has no rollback that can be relied on. Provider.Provision
// tries (see the RollbackOnFailure branch), but that only covers the
// window where the process is still alive and still holds the record. A
// killed wizard, a dropped link, a laptop lid, or an L4/L5/L6 that dies
// between "new server created" and "record written back" all land in the
// same place: a VPS that is billing, an SSH key whose name collides with
// the next attempt, and nothing on the operator's disk that knows either
// exists. This has already happened to this project's operator, and the
// destructive rungs make it strictly worse — but NOT in the way it is
// tempting to write down. L4/L5/L6 do not run the two boxes side by
// side: Reprovision deletes and returns without re-creating (see
// hetzner/provider.go and vultr/provider.go, and the guard tests that
// pin it), and the wizard calls it BEFORE Provision. So a single failed
// pass leaves no relay at all, not two of them.
//
// Two paid servers is the RETRY shape. The first attempt's box survives
// — rollback was declined, or rollback itself failed, or the wizard died
// between "created" and "record written back" — nothing on disk names
// it, and the operator's natural next action builds a second one beside
// it. For L5 those two sit on two different providers, and the console
// the operator is looking at belongs to the one they were leaving.
//
// Decommission is not the answer to that. It takes a record and tears
// down what the record names. The failure being described is precisely
// the one where there is no record.
//
// So the audit is record-OPTIONAL and account-WIDE. It asks the provider
// what actually exists, matches it against the ownership marks
// daal-deploy stamps on everything it creates, and joins that to
// whichever records the operator can still produce. Three answers come
// out and they are deliberately different from each other:
//
//	in-use     — something alive is behind this. Never touch it.
//	unclaimed  — ours by ownership mark, alive, and no record handed in
//	             claims it. This is the two-paid-servers signal.
//	orphan     — proven dead: nothing alive is behind it. Reclaimable.
//	unproven   — could not be established. Named, with where to look.
//
// # The rule that keeps it safe
//
// Nothing is reclaimable unless the audit can PROVE it is ours AND prove
// nothing alive depends on it. Proof is the ownership label pair
// (managed-by + the per-relay label), never a name prefix — the same
// discipline ownsFloatingIP and ownsEphemeralKey already enforce, and
// for the same reason: an account can run two relays, and the managed-by
// label alone is exactly what a sibling relay's resources also carry.
//
// Everything that cannot be proven becomes "unproven" and is reported by
// name with the place to look. It is never quietly dropped, and it is
// never deleted. An audit that silently omits a billing resource is
// worse than no audit, because the operator stops looking.
//
// # What it will never do
//
// It will never delete a server. Not an unclaimed one, not one whose
// labels match perfectly. A server IS the relay — the thing recipients
// are dialling right now — and no label can distinguish "the old box
// from the failed L4" from "the box every pack in the field points at".
// Only the operator knows which. So an unclaimed server is reported with
// its id, region, address and the exact `daal-deploy decommission`
// invocation that removes it, and the decision stays human.

// AuditVerdict is the audit's answer for one cloud resource. The
// values are a wire contract (JSON, consumed by the CLI renderer),
// so they are strings and not an enum of ints.
type AuditVerdict string

const (
	// VerdictInUse: something alive is behind this resource — an
	// attached server, or a server bearing the relay label this
	// resource carries. Never reclaimable, whatever else is true.
	VerdictInUse AuditVerdict = "in-use"

	// VerdictUnclaimed: the resource carries daal-deploy's ownership
	// marks and is alive, but none of the OperatorRecords handed to
	// the audit claims it. Reported loudly, never reclaimed. The
	// common cause is the one this whole file exists for: a
	// provision or a destructive rotation that built the box and
	// then failed before its record was persisted.
	VerdictUnclaimed AuditVerdict = "unclaimed"

	// VerdictOrphan: proven ours, and proven that nothing alive is
	// behind it. The only verdict Reclaim will act on.
	VerdictOrphan AuditVerdict = "orphan"

	// VerdictUnproven: ownership or liveness could not be
	// established — a list call failed, a label pair is incomplete,
	// a name does not parse. Reported with Reason naming where to
	// look. Never reclaimed: "we could not tell" and "it is safe to
	// delete" are the two answers that must never be confused.
	VerdictUnproven AuditVerdict = "unproven"
)

// Resource kinds. Strings for the same wire reason as the verdicts.
const (
	KindServer     = "server"
	KindFloatingIP = "floating-ip"
	KindSSHKey     = "ssh-key"
	KindFirewall   = "firewall"
)

// ResourceRef identifies one cloud object. Kind is needed as well as
// ID because provider ids are only unique within a kind — a floating
// IP and a server can both be "42".
type ResourceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func (r ResourceRef) String() string { return r.Kind + ":" + r.ID }

// AuditedResource is one cloud object and what the audit could prove
// about it.
type AuditedResource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`

	// Relay is the derived relay name this resource is stamped for
	// ("daal-<region>-<hex16>"), taken from the per-relay ownership
	// label or from the resource's own name where the adapter mints
	// a name that is a pure function of our material. Empty when it
	// could not be established, which is itself a reason for
	// VerdictUnproven.
	Relay string `json:"relay,omitempty"`

	Verdict AuditVerdict `json:"verdict"`

	// Reason is always populated, for every verdict including
	// in-use. A report that explains only its refusals teaches the
	// operator nothing about why it believes the rest is safe.
	Reason string `json:"reason"`

	// Billing marks resources that cost money while they sit there.
	// Servers and floating IPs do; SSH keys and firewalls do not,
	// but an orphaned SSH key blocks the next provision, which is
	// its own kind of expensive.
	Billing bool `json:"billing"`

	// Reclaimable is true only for VerdictOrphan on a kind Reclaim
	// is willing to delete. It is a separate field from the verdict
	// so a future kind can be classified as an orphan and still be
	// left alone.
	Reclaimable bool `json:"reclaimable"`

	// Hint is the operator's next move in their own terms — the
	// command to run, or the console page to open. Populated for
	// everything that is not plainly in-use.
	Hint string `json:"hint,omitempty"`
}

// Ref returns this resource's identity.
func (a AuditedResource) Ref() ResourceRef { return ResourceRef{Kind: a.Kind, ID: a.ID} }

// KnownRelay is one OperatorRecord handed to the audit, joined to
// what the provider actually reports.
//
// The join is the point. A record on its own is a belief; the
// provider's answer on its own is a list of objects. Only the pair
// tells the operator "the box you think you own is gone" or "the box
// you think you own is running under a different id than your record
// says", and both of those are real states this project has produced.
type KnownRelay struct {
	// Relay is the derived server name — the join key for every
	// ownership label on the account.
	Relay string `json:"relay"`
	// RecordServerID is what the record claims. Empty is the
	// interesting case: the wizard writes the record back only on a
	// successful provision, so an empty id plus a live server is
	// exactly the orphaned-provision state.
	RecordServerID string `json:"record_server_id,omitempty"`
	// LiveServerID is what the provider reports for a server
	// bearing Relay as its name, or empty if there is none.
	LiveServerID string `json:"live_server_id,omitempty"`
	Region       string `json:"region,omitempty"`
	// Note explains any disagreement between the two ids. Empty
	// when they agree.
	Note string `json:"note,omitempty"`
}

// AccountAudit is the whole answer: what we believe, what is there,
// and what can be proven about the difference.
//
// Wire shape: canonical-JSON serialisable. Warnings is never null.
type AccountAudit struct {
	Provider  string    `json:"provider"`
	CheckedAt time.Time `json:"checked_at"`

	// Known is the record side of the join, one entry per
	// OperatorRecord handed in. Empty when the operator has no
	// records left — which is a supported way to run this, and the
	// case the audit was built for.
	Known []KnownRelay `json:"known"`

	// Resources is everything on the account carrying daal-deploy's
	// ownership marks. Resources with no mark at all are not listed:
	// they are the operator's own property and this tool has no
	// opinion about them.
	Resources []AuditedResource `json:"resources"`

	// ServerListComplete records whether the audit was able to
	// enumerate the account's servers.
	//
	// This one boolean gates every orphan finding in the report. A
	// resource is an orphan because NO SERVER stands behind it, and
	// that is a claim about the whole server list. If the list could
	// not be read, the claim cannot be made about anything — so the
	// audit downgrades every candidate to unproven and Reclaim
	// refuses outright. False here is the difference between a sweep
	// and a rake.
	ServerListComplete bool `json:"server_list_complete"`

	// Warnings are the non-fatal failures and the reasons the audit
	// could not prove something. Never null; rendered verbatim.
	Warnings []string `json:"warnings"`
}

// NewAccountAudit returns an audit with non-nil slices.
func NewAccountAudit(providerName string, now time.Time) *AccountAudit {
	return &AccountAudit{
		Provider:  providerName,
		CheckedAt: now.UTC(),
		Warnings:  []string{},
	}
}

// Warnf appends one operator-readable warning.
func (a *AccountAudit) Warnf(format string, args ...any) {
	a.Warnings = append(a.Warnings, fmt.Sprintf(format, args...))
}

// Add appends one classified resource.
func (a *AccountAudit) Add(r AuditedResource) { a.Resources = append(a.Resources, r) }

// Sort puts the report in a stable, operator-useful order: the things
// that cost money and cannot be fixed automatically first, then the
// reclaimable ones, then the rest. Within a bucket, by kind then id,
// so two runs against an unchanged account produce identical output
// and a diff means something changed.
func (a *AccountAudit) Sort() {
	rank := map[AuditVerdict]int{
		VerdictUnclaimed: 0,
		VerdictUnproven:  1,
		VerdictOrphan:    2,
		VerdictInUse:     3,
	}
	sort.SliceStable(a.Resources, func(i, j int) bool {
		ri, rj := a.Resources[i], a.Resources[j]
		if rank[ri.Verdict] != rank[rj.Verdict] {
			return rank[ri.Verdict] < rank[rj.Verdict]
		}
		if ri.Kind != rj.Kind {
			return ri.Kind < rj.Kind
		}
		return ri.ID < rj.ID
	})
	sort.SliceStable(a.Known, func(i, j int) bool { return a.Known[i].Relay < a.Known[j].Relay })
}

// Reclaimable returns the refs Reclaim would act on.
func (a *AccountAudit) Reclaimable() []ResourceRef {
	var out []ResourceRef
	for _, r := range a.Resources {
		if r.Reclaimable {
			out = append(out, r.Ref())
		}
	}
	return out
}

// NeedsAttention reports whether anything on this account is billing
// or blocking without an automatic fix. It is what a caller renders
// as "you have a problem" versus "nothing to do".
func (a *AccountAudit) NeedsAttention() bool {
	for _, r := range a.Resources {
		if r.Verdict == VerdictUnclaimed || r.Verdict == VerdictUnproven || r.Verdict == VerdictOrphan {
			return true
		}
	}
	return len(a.Warnings) > 0
}

// ReclaimOutcome is what happened to one resource Reclaim was asked
// to remove.
type ReclaimOutcome struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Deleted is true only when the resource is provably gone.
	Deleted bool `json:"deleted"`
	// Reason is why it was deleted, or — far more importantly — why
	// it was not. Every refusal names the guard that fired.
	Reason string `json:"reason"`
}

// ReclaimReport is the outcome of a reclaim run.
//
// Wire shape: canonical-JSON serialisable; Outcomes and Warnings are
// never null.
type ReclaimReport struct {
	Provider string           `json:"provider"`
	Outcomes []ReclaimOutcome `json:"outcomes"`
	Warnings []string         `json:"warnings"`
}

// NewReclaimReport returns a report with non-nil slices.
func NewReclaimReport(providerName string) *ReclaimReport {
	return &ReclaimReport{Provider: providerName, Outcomes: []ReclaimOutcome{}, Warnings: []string{}}
}

// Warnf appends one operator-readable warning.
func (r *ReclaimReport) Warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Add appends one outcome.
func (r *ReclaimReport) Add(o ReclaimOutcome) { r.Outcomes = append(r.Outcomes, o) }

// Deleted counts the resources provably removed.
func (r *ReclaimReport) Deleted() int {
	n := 0
	for _, o := range r.Outcomes {
		if o.Deleted {
			n++
		}
	}
	return n
}

// AccountAuditor is the OPTIONAL half of the provider contract.
//
// Optional on purpose. Provider is the contract every adapter must
// satisfy to deploy a relay; auditing an account needs enumeration
// calls (list every floating IP, list every firewall) that a
// half-built adapter does not have. Folding these into Provider would
// have forced vultr and stark — both of which currently answer
// ErrLiveNotImplemented from every method — to grow stub
// implementations that return empty lists, and an empty list from an
// adapter that cannot enumerate reads exactly like a clean account.
// That is the "unproven rendered as proven" failure this package
// spends its whole design refusing.
//
// So: a caller type-asserts, and an adapter that does not implement
// this says so in the operator's words rather than lying quietly.
type AccountAuditor interface {
	// AuditAccount enumerates the account and classifies everything
	// carrying this tool's ownership marks. records are the
	// OperatorRecords the operator can still produce; nil or empty
	// is supported and is the case the audit exists for.
	//
	// A non-nil error means the audit could not be performed at all.
	// A partial audit — some list calls succeeded, some did not —
	// returns a report with ServerListComplete and Warnings telling
	// the truth, and no orphan findings that depend on the missing
	// data.
	AuditAccount(ctx context.Context, records []*OperatorRecord) (*AccountAudit, error)

	// ReclaimOrphans deletes resources the audit proved orphaned.
	//
	// It re-runs the audit itself against fresh provider reads
	// rather than trusting a report the caller passes in: between an
	// operator reading a report and confirming it, a relay can be
	// provisioned, an address attached, a rotation started. The
	// audit the human approved is a description of the past, and
	// deleting against it is how a sweep eats a live relay.
	//
	// only, when non-empty, restricts the run to those refs; refs
	// that are not reclaimable in the fresh audit are reported as
	// refusals with the reason, never silently skipped.
	ReclaimOrphans(ctx context.Context, records []*OperatorRecord, only []ResourceRef) (*ReclaimReport, error)
}
