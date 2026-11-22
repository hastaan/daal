package cloudflare

// The DNS micro-note's write side (docs/update-ladder-v2.md §4.3,
// specs/update-ladder-v2.md §4): six UNPROXIED A records in the
// publisher's own zone,
//
//	<name(dns, e)[0:12]><i>.<zone>     i = 0..5, TTL 300
//
// that carry the 16 sealed bytes of the standby key (bundle.SealMicroNote)
// or, before a reveal, filler of the same shape (bundle.MicroFiller).
//
// What this code may touch. Only records it can prove it wrote: a record
// whose name is EXACTLY one of the six derived names of this secret at
// one of the epochs it manages, of type A, not proxied, whose address
// starts with one of bundle.DNSNoteFirstOctets. Every other record in the
// zone — the CDN route's proxied record, the publisher's own mail and web
// records, a stranger's record that happens to sit at a derived name — is
// never changed or removed. A foreign record at a name of the CURRENT
// epoch makes the plan refuse (ErrNoteNameTaken) before anything is
// written.
//
// Epochs. A writer writes at e = bundle.NoteEpochAt("dns", now); readers
// try e, then e−1, so e−1 is left alone; e−2 and the few before it
// (noteSweepEpochs) are removed, so a publisher who was away for some
// weeks does not leave old notes behind.
//
// Reveal and filler. Filler is written once per epoch and kept: running
// the filler publish again leaves an existing set as it is (it never
// overwrites a revealed note with filler). A reveal replaces the six,
// unless the six already hold this exact note (then nothing is written,
// so cached answers stay right).
//
// Audience. The People audiences only: the Everyone audience may not use
// the micro note on DNS (bundle.MicroNoteAllowed), because the national
// resolver logs every name a phone asks.
//
// Nothing here logs or returns the secret, a name, the zone or an
// address: the plan's public view (NotePlan.Summary) holds counts,
// indexes and epoch offsets only.
//
// The wire calls (ListNoteRecords, CreateNoteRecord, ReplaceNoteRecord)
// are methods of liveCFClient and go through its do(), so this file
// opens no connection of its own and the opsec allowlist stays the two
// files it names.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// NoteRecordTTL is the TTL of every note record (study §4.3).
const NoteRecordTTL = 300

// noteSweepEpochs is how many epochs before e−1 a publish removes:
// e−2 … e−(1+noteSweepEpochs).
const noteSweepEpochs = 4

var (
	// ErrNoteAudience: the Everyone audience asked for a DNS note.
	ErrNoteAudience = errors.New("cloudflare: the DNS note is for the People audiences only")
	// ErrNoteNameTaken: a record this code did not write sits at a
	// derived name of the current epoch. Nothing was written.
	ErrNoteNameTaken = errors.New("cloudflare: a record that is not a note already uses a note name")
	// ErrNoteZoneNotFound: the token sees no Cloudflare zone holding
	// the note zone.
	ErrNoteZoneNotFound = errors.New("cloudflare: no zone this token sees holds the note zone")
	// ErrNoteInput: the input is not usable (zone, secret, key).
	ErrNoteInput = errors.New("cloudflare: bad DNS note input")
)

// NoteRecord is one DNS record as the note writer reads it (with TTL,
// which DNSRecord does not carry).
type NoteRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied *bool  `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// NoteDNSAPI is the narrow Cloudflare surface of the DNS note. Every
// call needs Zone — Zone — Read (LookupZone) or Zone — DNS — Edit, the
// permissions the CDN add-on's token already has. The token travels per
// call and is never kept, logged or put into an error.
type NoteDNSAPI interface {
	// LookupZone is GET /zones?name=<name> (as CFClient).
	LookupZone(ctx context.Context, cfToken []byte, name string) (zone Zone, found bool, err error)
	// ListNoteRecords is GET /zones/{id}/dns_records?name=<name>: every
	// record of exactly that name, any type.
	ListNoteRecords(ctx context.Context, cfToken []byte, zoneID, name string) ([]NoteRecord, error)
	// CreateNoteRecord is POST /zones/{id}/dns_records of an unproxied
	// A record, TTL NoteRecordTTL. Returns its id.
	CreateNoteRecord(ctx context.Context, cfToken []byte, zoneID, name, ipv4 string) (string, error)
	// ReplaceNoteRecord is PUT /zones/{id}/dns_records/{rid}: the same
	// name, type A, unproxied, TTL NoteRecordTTL, the new address.
	ReplaceNoteRecord(ctx context.Context, cfToken []byte, zoneID, recordID, name, ipv4 string) error
	// DeleteDNSRecord deletes one record; an absent one is success.
	DeleteDNSRecord(ctx context.Context, cfToken []byte, zoneID, recordID string) error
}

// NewLiveNoteDNSClient returns the production client (api.cloudflare.com).
func NewLiveNoteDNSClient() NoteDNSAPI {
	return newLiveCFClient(cloudflareAPIBase, nil)
}

var _ NoteDNSAPI = (*liveCFClient)(nil)

func (c *liveCFClient) ListNoteRecords(ctx context.Context, tok []byte, zoneID, name string) ([]NoteRecord, error) {
	var recs []NoteRecord
	err := c.do(ctx, tok, "GET", zp(zoneID)+"/dns_records", url.Values{"name": {name}, "per_page": {"100"}}, nil, &recs)
	return recs, err
}

func (c *liveCFClient) CreateNoteRecord(ctx context.Context, tok []byte, zoneID, name, ipv4 string) (string, error) {
	var out NoteRecord
	if err := c.do(ctx, tok, "POST", zp(zoneID)+"/dns_records", nil,
		dnsRecordPayload{Type: "A", Name: name, Content: ipv4, Proxied: false, TTL: NoteRecordTTL}, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("cloudflare: dns record create returned no id")
	}
	return out.ID, nil
}

func (c *liveCFClient) ReplaceNoteRecord(ctx context.Context, tok []byte, zoneID, recordID, name, ipv4 string) error {
	var out NoteRecord
	return c.do(ctx, tok, "PUT", zp(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil,
		dnsRecordPayload{Type: "A", Name: name, Content: ipv4, Proxied: false, TTL: NoteRecordTTL}, &out)
}

// NoteDNSInput is one publish (or removal) for one audience's secret.
type NoteDNSInput struct {
	// Secret is the audience's update secret (u and its audience).
	Secret bundle.UpdateSecret
	// Zone is the note zone (the carriers member's dns.zone). It may be
	// the Cloudflare zone itself or a name under it.
	Zone string
	// Now picks the epoch.
	Now time.Time
	// StandbyKey, when set, is revealed; nil writes filler.
	StandbyKey *bundle.StandbyKeyBytes
	// Rand supplies filler, first octets and tail bytes (nil:
	// crypto/rand).
	Rand io.Reader
}

// NoteOpKind is what the plan does to one record.
type NoteOpKind string

const (
	NoteOpCreate  NoteOpKind = "create"
	NoteOpReplace NoteOpKind = "replace"
	NoteOpKeep    NoteOpKind = "keep"
	NoteOpDelete  NoteOpKind = "delete"
	// NoteOpForeign: a record at a derived name this code did not
	// write (an old epoch only; it is left as it is).
	NoteOpForeign NoteOpKind = "foreign"
)

// NoteOp is one step. Name, content and record id stay unexported: the
// public view is Kind, Index and EpochOffset.
type NoteOp struct {
	Kind NoteOpKind `json:"op"`
	// Index is the answer index 0..5.
	Index int `json:"index"`
	// EpochOffset is 0 for the current epoch, -2 … for swept ones.
	EpochOffset int `json:"epoch_offset"`

	name, content, recordID string
}

// NotePlan is what a publish or removal would do, computed from reads
// only. Apply carries it out.
type NotePlan struct {
	ZoneID string
	Epoch  uint64
	// Mode is "filler", "reveal" or "remove".
	Mode string
	Ops  []NoteOp
}

// NotePlanSummary is the plan as it may be shown or printed: no name,
// zone, address or secret.
type NotePlanSummary struct {
	Epoch    uint64   `json:"epoch"`
	Mode     string   `json:"mode"`
	Created  int      `json:"created"`
	Replaced int      `json:"replaced"`
	Kept     int      `json:"kept"`
	Removed  int      `json:"removed"`
	Foreign  int      `json:"foreign_kept"`
	Ops      []NoteOp `json:"ops"`
}

// Summary is the printable view of p.
func (p *NotePlan) Summary() NotePlanSummary {
	s := NotePlanSummary{Epoch: p.Epoch, Mode: p.Mode, Ops: append([]NoteOp{}, p.Ops...)}
	for _, op := range p.Ops {
		switch op.Kind {
		case NoteOpCreate:
			s.Created++
		case NoteOpReplace:
			s.Replaced++
		case NoteOpKeep:
			s.Kept++
		case NoteOpDelete:
			s.Removed++
		case NoteOpForeign:
			s.Foreign++
		}
	}
	return s
}

// isNoteRecord: a record at a derived name that this code wrote — type
// A, not proxied, an IPv4 address whose first octet is in the list.
func isNoteRecord(r NoteRecord, name string) bool {
	if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), name) || r.Type != "A" {
		return false
	}
	if r.Proxied != nil && *r.Proxied {
		return false
	}
	ip := net.ParseIP(r.Content).To4()
	return ip != nil && bundle.DNSNoteFirstOctetOK(ip[0])
}

// FindNoteZone finds the Cloudflare zone that holds the note zone: the
// note zone itself, else each parent down to two labels.
func FindNoteZone(ctx context.Context, api NoteDNSAPI, tok []byte, noteZone string) (Zone, error) {
	labels := strings.Split(noteZone, ".")
	for i := 0; i+2 <= len(labels); i++ {
		z, found, err := api.LookupZone(ctx, tok, strings.Join(labels[i:], "."))
		if err != nil {
			return Zone{}, noteErr("zone lookup", err, tok)
		}
		if found && z.ID != "" {
			return z, nil
		}
	}
	return Zone{}, ErrNoteZoneNotFound
}

func checkNoteInput(in *NoteDNSInput) error {
	if !bundle.MicroNoteAllowed(bundle.NoteCarrierDNS, in.Secret.Audience) {
		if in.Secret.Audience == bundle.AudienceEveryone {
			return ErrNoteAudience
		}
		return fmt.Errorf("%w: audience", ErrNoteInput)
	}
	if !bundle.DNSNoteZoneOK(in.Zone) {
		return fmt.Errorf("%w: zone", ErrNoteInput)
	}
	var zero [bundle.UpdateSecretLen]byte
	if in.Secret.Secret == zero {
		return fmt.Errorf("%w: secret", ErrNoteInput)
	}
	if in.StandbyKey != nil && !bundle.StandbyAddressOK(in.StandbyKey.Address()) {
		return fmt.Errorf("%w: standby key", ErrNoteInput)
	}
	return nil
}

// PlanNoteDNS reads the zone and works out the publish: the six records
// of the current epoch (filler or reveal) and the removal of old epochs.
// It writes nothing.
func PlanNoteDNS(ctx context.Context, api NoteDNSAPI, tok []byte, in NoteDNSInput) (*NotePlan, error) {
	if err := checkNoteInput(&in); err != nil {
		return nil, err
	}
	rnd := in.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	zone, err := FindNoteZone(ctx, api, tok, in.Zone)
	if err != nil {
		return nil, err
	}
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, in.Now)
	plan := &NotePlan{ZoneID: zone.ID, Epoch: e, Mode: "filler"}

	var sealed [bundle.MicroNoteLen]byte
	if in.StandbyKey != nil {
		plan.Mode = "reveal"
		if sealed, err = bundle.SealMicroNote(in.Secret.Secret, bundle.NoteCarrierDNS, e, *in.StandbyKey); err != nil {
			return nil, err
		}
	} else if sealed, err = bundle.MicroFiller(rnd); err != nil {
		return nil, err
	}
	names, err := bundle.DNSNoteNames(in.Secret.Secret, e, in.Zone)
	if err != nil {
		return nil, err
	}
	ips, err := bundle.DNSNoteAddresses(sealed, rnd)
	if err != nil {
		return nil, err
	}

	// Read the six current names. A foreign record refuses the plan.
	var have [bundle.DNSNoteAnswers][]NoteRecord
	for i, n := range names {
		recs, err := api.ListNoteRecords(ctx, tok, zone.ID, n)
		if err != nil {
			return nil, noteErr("list", err, tok)
		}
		for _, r := range recs {
			if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), n) {
				continue // the API answered more than was asked
			}
			if !isNoteRecord(r, n) {
				return nil, ErrNoteNameTaken
			}
			have[i] = append(have[i], r)
		}
	}

	// Is the current set complete, one record per name, TTL right?
	complete := true
	var cur [bundle.DNSNoteAnswers]net.IP
	for i := range have {
		if len(have[i]) != 1 || have[i][0].TTL != NoteRecordTTL {
			complete = false
			break
		}
		cur[i] = net.ParseIP(have[i][0].Content).To4()
	}
	keepAll := false
	if complete {
		if in.StandbyKey == nil {
			keepAll = true // filler never overwrites what is there
		} else if got, err := bundle.DNSNoteJoin(cur); err == nil && got == sealed {
			keepAll = true // this very note is already there
		}
	}

	for i, n := range names {
		recs := have[i]
		switch {
		case keepAll:
			plan.Ops = append(plan.Ops, NoteOp{Kind: NoteOpKeep, Index: i, name: n, recordID: recs[0].ID})
		case len(recs) == 0:
			plan.Ops = append(plan.Ops, NoteOp{Kind: NoteOpCreate, Index: i, name: n, content: ips[i].String()})
		case in.StandbyKey == nil && len(recs) == 1 && recs[0].TTL == NoteRecordTTL:
			// A partial filler set: keep what is there, fill the rest.
			plan.Ops = append(plan.Ops, NoteOp{Kind: NoteOpKeep, Index: i, name: n, recordID: recs[0].ID})
		default:
			plan.Ops = append(plan.Ops, NoteOp{Kind: NoteOpReplace, Index: i, name: n, content: ips[i].String(), recordID: recs[0].ID})
		}
		if !keepAll && len(recs) > 1 {
			for _, extra := range recs[1:] {
				plan.Ops = append(plan.Ops, NoteOp{Kind: NoteOpDelete, Index: i, name: n, recordID: extra.ID})
			}
		}
	}

	// Sweep e−2 … e−(1+noteSweepEpochs). e−1 stays for readers.
	if err := planSweep(ctx, api, tok, zone.ID, in, e, 2, 1+noteSweepEpochs, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// PlanNoteDNSRemove works out the removal of every note of this secret
// at e+1, e, e−1 … e−(1+noteSweepEpochs) (the DNS switch turned off).
func PlanNoteDNSRemove(ctx context.Context, api NoteDNSAPI, tok []byte, in NoteDNSInput) (*NotePlan, error) {
	in.StandbyKey = nil
	if err := checkNoteInput(&in); err != nil {
		return nil, err
	}
	zone, err := FindNoteZone(ctx, api, tok, in.Zone)
	if err != nil {
		return nil, err
	}
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, in.Now)
	plan := &NotePlan{ZoneID: zone.ID, Epoch: e, Mode: "remove"}
	if err := planSweep(ctx, api, tok, zone.ID, in, e, -1, 1+noteSweepEpochs, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// planSweep adds a delete for every note record of epochs e−from …
// e−to (from may be −1 for e+1), and a "foreign" entry for anything
// else at those names.
func planSweep(ctx context.Context, api NoteDNSAPI, tok []byte, zoneID string, in NoteDNSInput, e uint64, from, to int, plan *NotePlan) error {
	for off := from; off <= to; off++ {
		if off > 0 && uint64(off) > e {
			break
		}
		var old uint64
		if off < 0 {
			old = e + uint64(-off)
		} else {
			old = e - uint64(off)
		}
		names, err := bundle.DNSNoteNames(in.Secret.Secret, old, in.Zone)
		if err != nil {
			return err
		}
		for i, n := range names {
			recs, err := api.ListNoteRecords(ctx, tok, zoneID, n)
			if err != nil {
				return noteErr("list", err, tok)
			}
			for _, r := range recs {
				if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), n) {
					continue
				}
				k := NoteOpForeign
				if isNoteRecord(r, n) {
					k = NoteOpDelete
				}
				plan.Ops = append(plan.Ops, NoteOp{Kind: k, Index: i, EpochOffset: -off, name: n, recordID: r.ID})
			}
		}
	}
	return nil
}

// ApplyNoteDNS carries out a plan: the current epoch's writes first,
// then the deletes. It stops at the first error; running the publish
// again finishes the job (every step is idempotent).
func ApplyNoteDNS(ctx context.Context, api NoteDNSAPI, tok []byte, plan *NotePlan) error {
	for _, pass := range []NoteOpKind{NoteOpCreate, NoteOpDelete} {
		for _, op := range plan.Ops {
			var err error
			switch {
			case pass == NoteOpCreate && op.Kind == NoteOpCreate:
				_, err = api.CreateNoteRecord(ctx, tok, plan.ZoneID, op.name, op.content)
			case pass == NoteOpCreate && op.Kind == NoteOpReplace:
				err = api.ReplaceNoteRecord(ctx, tok, plan.ZoneID, op.recordID, op.name, op.content)
			case pass == NoteOpDelete && op.Kind == NoteOpDelete:
				err = api.DeleteDNSRecord(ctx, tok, plan.ZoneID, op.recordID)
			}
			if err != nil {
				return noteErr(string(op.Kind), err, tok)
			}
		}
	}
	return nil
}

// IsNoteAuthError reports whether a DNS-note error is Cloudflare
// refusing the token (401/403).
func IsNoteAuthError(err error) bool { return isAuthError(err) }

// noteAPIError is an API failure with nothing in it but the step and
// the HTTP status: the underlying error may name the request URL (which
// carries a note name in its query) or echo the record back, and a note
// name must not reach stderr or a log.
type noteAPIError struct {
	step   string
	status int
	auth   bool
}

func (e *noteAPIError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("cloudflare: DNS note %s: status %d", e.step, e.status)
	}
	return "cloudflare: DNS note " + e.step + ": the request failed"
}

func (e *noteAPIError) Unwrap() error {
	if e.auth {
		return &authError{msg: "cloudflare: not authorised"}
	}
	return nil
}

func noteErr(step string, err error, tok []byte) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("cloudflare: DNS note %s: %w", step, ctxErr(err))
	}
	out := &noteAPIError{step: step}
	var se *statusError
	if errors.As(err, &se) {
		out.status = se.Status
	}
	var ae *authError
	out.auth = errors.As(err, &ae) || out.status == 401 || out.status == 403
	_ = tok // nothing of err's text is kept, so nothing of the token either
	return out
}

func ctxErr(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

// PublishNoteDNS is PlanNoteDNS then ApplyNoteDNS.
func PublishNoteDNS(ctx context.Context, api NoteDNSAPI, tok []byte, in NoteDNSInput) (*NotePlan, error) {
	plan, err := PlanNoteDNS(ctx, api, tok, in)
	if err != nil {
		return nil, err
	}
	return plan, ApplyNoteDNS(ctx, api, tok, plan)
}
