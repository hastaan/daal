package desync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Strategy is how the first flight of a connection is cut. Every field
// is optional; the zero value cuts nothing (OFF).
//
// Offsets are byte positions in the stream AS SENT (after any TLS record
// split): a cut at 1 means "the first segment carries one byte". Cuts
// apply only within the first flight — the first TLS record when the
// stream opens with one, otherwise the first Write — and a cut beyond it
// is ignored, never deferred to later traffic.
//
// JSON (strict: an unknown member makes the whole strategy invalid):
//
//	{"preset": "sni-cut"}                              a named strategy, alone
//	{"split_at": [1, 6], "sni_cut": true,              explicit
//	 "chunk": 6, "chunk_until": 0, "chunk_from_sni": false,
//	 "record_split_at": [], "record_sni_cut": false, "record_cut": false,
//	 "delay_ms": [1, 2], "wait_ack": true, "ack_timeout_ms": 300,
//	 "max_segments": 64}
type Strategy struct {
	// Preset names a strategy from Presets. When set, no other field may
	// be: a preset is one name the pack, the ladder and the per-network
	// memory can carry, and mixing it with fields would make "which
	// strategy won here" ambiguous. Normalized resolves it.
	Preset string `json:"preset,omitempty"`

	// SplitAt: explicit cut offsets.
	SplitAt []int `json:"split_at,omitempty"`
	// SNICut: also cut in the middle of the TLS server_name, when the
	// first flight is a ClientHello that has one. NOT a gate: with no
	// name the other cuts still happen.
	SNICut bool `json:"sni_cut,omitempty"`
	// Chunk > 0: after the last explicit cut (or from offset 0), cut every
	// Chunk bytes up to ChunkUntil; ChunkUntil 0 means "through the end of
	// the server_name" when there is one, else the first 512 bytes. The
	// "6-byte pieces" family (research/intel-and-some-working-methods.md:93).
	Chunk      int `json:"chunk,omitempty"`
	ChunkUntil int `json:"chunk_until,omitempty"`
	// ChunkFromSNI: start the Chunk pieces at the server_name instead of
	// after the last explicit cut, so the pieces fall ACROSS the name
	// wherever the hello puts it (a uTLS chrome hello has it near byte
	// 387, a post-quantum one far later) and the segment count does not
	// grow with the bytes before it. Without a name it changes nothing.
	ChunkFromSNI bool `json:"chunk_from_sni,omitempty"`

	// RecordSplitAt: split the first TLS handshake record's payload at
	// these payload offsets into separate records (same type and
	// version). RecordSNICut adds a split in the middle of the
	// server_name. RecordCut: also cut TCP at every record boundary this
	// creates (without it the records may share a segment: a box that
	// reassembles TCP but parses one record is the target then).
	RecordSplitAt []int `json:"record_split_at,omitempty"`
	RecordSNICut  bool  `json:"record_sni_cut,omitempty"`
	RecordCut     bool  `json:"record_cut,omitempty"`

	// DelayMs: [min, max] (or [n]) milliseconds to pause between
	// segments, uniformly drawn per gap.
	DelayMs []int `json:"delay_ms,omitempty"`
	// WaitAck: before sending the next segment, wait until the kernel
	// reports nothing unacknowledged (TCP_INFO tcpi_unacked, Linux and
	// Android), bounded by AckTimeoutMs (default 300; for the first gap
	// at least the socket's RTO + 50 ms, so a lost first segment is
	// retransmitted alone). Only ACK-wait strategies survive loss: an
	// unacked neighbour may be retransmitted merged with the next piece.
	// Where TCP_INFO is not available (Windows, macOS, iOS) the delay
	// alone separates segments. The whole cut flight is bounded by a
	// 2 s budget, after which the rest goes in one piece.
	WaitAck      bool `json:"wait_ack,omitempty"`
	AckTimeoutMs int  `json:"ack_timeout_ms,omitempty"`

	// MaxSegments caps how many segments the first flight becomes
	// (default 64, at most 256). Over the cap, the cuts that fall inside
	// the server_name are kept first, then the earliest of the rest.
	MaxSegments int `json:"max_segments,omitempty"`
}

const (
	maxOffset          = 16384 + 2048 // a TLS record plus slack
	maxExplicitCuts    = 64
	maxRecordSplits    = 16
	defaultMaxSegments = 64
	hardMaxSegments    = 256
	defaultAckTimeout  = 300 * time.Millisecond
	maxAckTimeoutMs    = 5000
	maxDelayMs         = 1000
	defaultChunkSpan   = 512
	// minGap separates two segments when neither an ACK wait nor a delay
	// does: Linux autocorking can otherwise merge back-to-back small
	// writes into one segment.
	minGap = 2 * time.Millisecond
	// rtoSlack: the first gap's ACK wait is at least the socket's RTO
	// plus this, so a lost first segment is retransmitted ALONE before
	// the second is written (Linux's tcp_retrans_collapse otherwise
	// merges adjacent unacked segments into one retransmit, and a box
	// that missed the originals reads the name whole).
	rtoSlack = 50 * time.Millisecond
	// sentWait bounds the wait for "the kernel has sent what was
	// written" (TCP_INFO tcpi_notsent_bytes == 0) between segments when
	// no ACK separates them: the autocork guard.
	sentWait = 50 * time.Millisecond
	// firstFlightBudget bounds the whole cut first flight. Past it the
	// rest is written in one piece: a connection that connects uncut
	// beats one that hangs in the gaps.
	firstFlightBudget = 2 * time.Second
)

// Presets are the named strategies. They are data: adding one here is
// the whole change, and a pack or the ladder names it by key.
//
//   - split1: the record header's first byte alone. Beats a box that
//     wants a whole TLS header in packet one; a box that joins the first
//     two packets sees everything.
//   - sni-cut: one byte, then up to the middle of the server_name, then
//     the rest. Neither of the first two packets, nor both together,
//     holds the whole name. The default the ladder should try first.
//   - chain: one byte, then the bytes up to the server_name, then 6-byte
//     pieces across the name, 1–2 ms apart, no ACK wait — the
//     Serverless-for-Iran shape (many small segments, cheap per
//     segment). Without ACK wait it does NOT survive loss: a lost piece
//     may be retransmitted merged with its neighbours (Linux
//     tcp_retrans_collapse), name whole. The ladder tries sni-cut first.
//   - tlsrec-sni: the hello in two TLS records split mid-name, cut at the
//     record boundary. Beats a box that parses one record; needs a server
//     that reassembles handshake messages across records (Go's crypto/tls
//     and REALITY's fork do; desync's tests check REALITY).
var Presets = map[string]Strategy{
	"split1":     {SplitAt: []int{1}, WaitAck: true},
	"sni-cut":    {SplitAt: []int{1}, SNICut: true, WaitAck: true},
	"chain":      {SplitAt: []int{1}, Chunk: 6, ChunkFromSNI: true, DelayMs: []int{1, 2}},
	"tlsrec-sni": {RecordSNICut: true, RecordCut: true, WaitAck: true},
}

// Off is the strategy that cuts nothing.
var Off = Strategy{}

// Enabled reports whether the strategy cuts anything at all.
func (s Strategy) Enabled() bool {
	if s.Preset != "" {
		p, ok := Presets[s.Preset]
		return ok && p.Enabled()
	}
	return len(s.SplitAt) > 0 || s.SNICut || s.Chunk > 0 || len(s.RecordSplitAt) > 0 || s.RecordSNICut
}

// ParseStrategy decodes and validates one strategy object, strictly, and
// returns it Normalized. Callers that must fail closed to OFF treat any
// error as Off.
func ParseStrategy(raw []byte) (Strategy, error) {
	var s Strategy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Off, fmt.Errorf("desync: strategy: %w", err)
	}
	if dec.More() {
		return Off, errors.New("desync: strategy: trailing data")
	}
	return s.Normalized()
}

// Normalized resolves a preset into its fields and validates the result.
func (s Strategy) Normalized() (Strategy, error) {
	if s.Preset != "" {
		rest := s
		rest.Preset = ""
		if rest.Enabled() || len(rest.DelayMs) > 0 || rest.WaitAck || rest.AckTimeoutMs != 0 || rest.MaxSegments != 0 || rest.RecordCut || rest.ChunkUntil != 0 || rest.ChunkFromSNI {
			return Off, fmt.Errorf("desync: preset %q cannot be combined with other fields", s.Preset)
		}
		p, ok := Presets[s.Preset]
		if !ok {
			return Off, fmt.Errorf("desync: unknown preset %q", s.Preset)
		}
		s = p
	}
	if err := s.validate(); err != nil {
		return Off, err
	}
	return s, nil
}

func (s Strategy) validate() error {
	if len(s.SplitAt) > maxExplicitCuts {
		return fmt.Errorf("desync: split_at has %d cuts, at most %d", len(s.SplitAt), maxExplicitCuts)
	}
	for _, c := range s.SplitAt {
		if c < 1 || c > maxOffset {
			return fmt.Errorf("desync: split_at %d out of range 1..%d", c, maxOffset)
		}
	}
	if s.Chunk < 0 || s.Chunk > 4096 {
		return fmt.Errorf("desync: chunk %d out of range 0..4096", s.Chunk)
	}
	if s.ChunkUntil < 0 || s.ChunkUntil > maxOffset {
		return fmt.Errorf("desync: chunk_until %d out of range 0..%d", s.ChunkUntil, maxOffset)
	}
	if s.ChunkUntil != 0 && s.Chunk == 0 {
		return errors.New("desync: chunk_until without chunk")
	}
	if s.ChunkFromSNI && s.Chunk == 0 {
		return errors.New("desync: chunk_from_sni without chunk")
	}
	if len(s.RecordSplitAt) > maxRecordSplits {
		return fmt.Errorf("desync: record_split_at has %d splits, at most %d", len(s.RecordSplitAt), maxRecordSplits)
	}
	for _, c := range s.RecordSplitAt {
		if c < 1 || c > 16384 {
			return fmt.Errorf("desync: record_split_at %d out of range 1..16384", c)
		}
	}
	if s.RecordCut && len(s.RecordSplitAt) == 0 && !s.RecordSNICut {
		return errors.New("desync: record_cut without a record split")
	}
	switch len(s.DelayMs) {
	case 0:
	case 1, 2:
		for _, d := range s.DelayMs {
			if d < 0 || d > maxDelayMs {
				return fmt.Errorf("desync: delay_ms %d out of range 0..%d", d, maxDelayMs)
			}
		}
		if len(s.DelayMs) == 2 && s.DelayMs[0] > s.DelayMs[1] {
			return errors.New("desync: delay_ms min above max")
		}
	default:
		return errors.New("desync: delay_ms is [n] or [min, max]")
	}
	if s.AckTimeoutMs < 0 || s.AckTimeoutMs > maxAckTimeoutMs {
		return fmt.Errorf("desync: ack_timeout_ms %d out of range 0..%d", s.AckTimeoutMs, maxAckTimeoutMs)
	}
	if s.AckTimeoutMs != 0 && !s.WaitAck {
		return errors.New("desync: ack_timeout_ms without wait_ack")
	}
	if s.MaxSegments < 0 || s.MaxSegments > hardMaxSegments {
		return fmt.Errorf("desync: max_segments %d out of range 0..%d", s.MaxSegments, hardMaxSegments)
	}
	if s.MaxSegments == 1 {
		return errors.New("desync: max_segments 1 cuts nothing; leave the strategy off instead")
	}
	return nil
}

func (s Strategy) maxSegments() int {
	if s.MaxSegments == 0 {
		return defaultMaxSegments
	}
	return s.MaxSegments
}

func (s Strategy) ackTimeout() time.Duration {
	if s.AckTimeoutMs == 0 {
		return defaultAckTimeout
	}
	return time.Duration(s.AckTimeoutMs) * time.Millisecond
}

// Plan is what the strategy makes of one first flight: the bytes to
// send (different from the input only when TLS records were split) and
// the offsets in them at which a segment ends.
type Plan struct {
	Out  []byte
	Cuts []int
}

// Segments returns the plan's pieces, in order.
func (p Plan) Segments() [][]byte {
	var segs [][]byte
	prev := 0
	for _, c := range p.Cuts {
		segs = append(segs, p.Out[prev:c])
		prev = c
	}
	return append(segs, p.Out[prev:])
}

// PlanFor applies the strategy to a first flight. first is either a
// complete first TLS record (possibly followed by more bytes, which are
// sent unchanged after it) or, when the stream does not open with a TLS
// handshake record, the first Write.
func (s Strategy) PlanFor(first []byte) Plan {
	out := first
	// Where the server_name lies in `first` (-1: nowhere), and how an
	// offset in `first` moves in `out` (only a record split moves it).
	sniAt, sniLen := -1, 0
	at := func(i int) int { return i }
	rec, isRec := parseRecord(first)
	if isRec {
		sniAt, sniLen = locateSNI(first[:5+rec])
	}
	var recordCuts []int
	if isRec && (len(s.RecordSplitAt) > 0 || (s.RecordSNICut && sniAt >= 0)) {
		splits := append([]int(nil), s.RecordSplitAt...)
		if s.RecordSNICut && sniAt >= 0 {
			splits = append(splits, sniAt-5+mid(sniLen))
		}
		out, recordCuts, at = splitRecord(first, rec, splits)
	}
	cuts := make([]int, 0, len(s.SplitAt)+8)
	cuts = append(cuts, s.SplitAt...)
	if s.SNICut && sniAt >= 0 {
		cuts = append(cuts, at(sniAt+mid(sniLen)))
	}
	if s.RecordCut {
		cuts = append(cuts, recordCuts...)
	}
	if s.Chunk > 0 {
		start := 0
		for _, c := range s.SplitAt {
			if c > start {
				start = c
			}
		}
		if s.ChunkFromSNI && sniAt >= 0 {
			// The first piece boundary is the name's first byte.
			if from := at(sniAt) - s.Chunk; from > start {
				start = from
			}
		}
		end := s.ChunkUntil
		if end == 0 {
			if sniAt >= 0 {
				end = at(sniAt + sniLen)
			} else {
				end = defaultChunkSpan
			}
		}
		for c := start + s.Chunk; c < end; c += s.Chunk {
			cuts = append(cuts, c)
		}
		if end > start {
			cuts = append(cuts, end)
		}
	}
	nameLo, nameHi := -1, -1
	if sniAt >= 0 {
		nameLo, nameHi = at(sniAt), at(sniAt+sniLen)
	}
	return Plan{Out: out, Cuts: normaliseCuts(cuts, flightLen(out, isRec, rec, len(recordCuts)), s.maxSegments(), nameLo, nameHi)}
}

// flightLen is how many bytes of `out` the cuts may fall in: the first
// record (grown by the headers a record split inserted), or all of a
// non-TLS first Write.
func flightLen(out []byte, isRec bool, rec, newRecords int) int {
	if !isRec {
		return len(out)
	}
	n := 5 + rec + 5*newRecords
	if n > len(out) {
		n = len(out)
	}
	return n
}

func mid(n int) int {
	if n < 2 {
		return 1
	}
	return n / 2
}

// normaliseCuts sorts, deduplicates and bounds the cuts to (0, limit),
// keeping at most maxSeg-1 of them. Over the cap the cuts strictly
// inside the server_name (nameLo, nameHi) are kept first — they are the
// ones the strategy exists for, and a large hello must not push them
// past the cap — then the earliest of the rest (the bytes a first-packet
// box reads are at the front). nameLo < 0: there is no name.
func normaliseCuts(cuts []int, limit, maxSeg, nameLo, nameHi int) []int {
	sort.Ints(cuts)
	var all []int
	for _, c := range cuts {
		if c <= 0 || c >= limit {
			continue
		}
		if len(all) > 0 && all[len(all)-1] == c {
			continue
		}
		all = append(all, c)
	}
	keep := maxSeg - 1
	if len(all) <= keep {
		return all
	}
	inName := func(c int) bool { return nameLo >= 0 && c > nameLo && c < nameHi }
	out := make([]int, 0, keep)
	for _, c := range all {
		if len(out) < keep && inName(c) {
			out = append(out, c)
		}
	}
	for _, c := range all {
		if len(out) < keep && !inName(c) {
			out = append(out, c)
		}
	}
	sort.Ints(out)
	return out
}
