// Package fountain implements a Luby-Transform (LT) fountain code suitable
// for animated QR transport, modeled on divan/txqr's design parameters.
//
// Wire format (one frame, before the QR alphabet/byte encoding):
//
//	bytes  0..3   total payload length (uint32 LE)
//	bytes  4..5   block size in bytes (uint16 LE)
//	byte   6      version (1)
//	byte   7      reserved (0)
//	bytes  8..11  frame seed (uint32 LE) — uniquely seeds the LT degree+block selection
//	bytes  12..   block_size bytes of XOR-combined source blocks
//
// The decoder reads the header, knows k = ceil(payload_len/block_size),
// and reconstructs source blocks via belief propagation. Robust soliton
// distribution constants match txqr (c=0.03, delta=0.5).
package fountain

import (
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
)

const (
	headerLen = 12
	version   = 1
)

// Hard ceilings on what a decoder will accept from a frame header.
//
// These bound work and memory BEFORE any attacker-supplied number is used
// to size an allocation or as a divisor. They are deliberately generous
// relative to real traffic — the sender uses a 256-byte block size and a
// shared route pack is single-digit KB — and deliberately far below what
// a phone can absorb.
//
// MaxPayloadLen matches the base64-paste lane's MAX_DECODED_BYTES
// (client-shell/tauri/daal-wizard/src/recipient_paste.rs) so that the two
// offline intake paths agree on the largest bundle either will carry.
const (
	// MaxBlockSize caps one frame's body. A QR symbol tops out near 2953
	// bytes of binary payload, so anything past this cannot have come off
	// a camera at all.
	MaxBlockSize = 4096
	// MaxPayloadLen caps the reconstructed payload.
	MaxPayloadLen = 1 << 20
	// MaxBlocks caps k, which bounds both the `known` table and the
	// per-frame degree-sampling weights in robustSolitonDegree.
	MaxBlocks = 1 << 16
)

// Encoder produces an unbounded stream of fountain frames for a fixed
// payload. Callers loop NextFrame() until the receiver indicates decode
// complete.
type Encoder struct {
	payload     []byte
	blockSize   int
	blocks      [][]byte
	rng         *rand.Rand
	frameSeed   uint32
	totalFrames int
}

// NewEncoder builds an encoder that will produce frames of approximately
// blockSize+headerLen bytes each.
func NewEncoder(payload []byte, blockSize int, seed int64) *Encoder {
	if blockSize <= 0 {
		blockSize = 256
	}
	k := (len(payload) + blockSize - 1) / blockSize
	blocks := make([][]byte, k)
	for i := 0; i < k; i++ {
		end := (i + 1) * blockSize
		if end > len(payload) {
			end = len(payload)
		}
		blk := make([]byte, blockSize)
		copy(blk, payload[i*blockSize:end])
		blocks[i] = blk
	}
	return &Encoder{
		payload:     payload,
		blockSize:   blockSize,
		blocks:      blocks,
		rng:         rand.New(rand.NewSource(seed)),
		totalFrames: k,
	}
}

// SourceBlocks returns k, the number of source blocks the receiver must
// recover.
func (e *Encoder) SourceBlocks() int { return len(e.blocks) }

// NextFrame returns one fountain frame.
func (e *Encoder) NextFrame() []byte {
	seed := e.rng.Uint32() | 1 // never zero (tested)
	frame := buildFrame(e.payload, e.blocks, e.blockSize, seed)
	return frame
}

func buildFrame(payload []byte, blocks [][]byte, blockSize int, seed uint32) []byte {
	k := len(blocks)
	r := rand.New(rand.NewSource(int64(seed)))
	degree := robustSolitonDegree(r, k)
	indices := pickIndices(r, k, degree)
	combined := make([]byte, blockSize)
	for _, idx := range indices {
		xorInPlace(combined, blocks[idx])
	}
	frame := make([]byte, headerLen+blockSize)
	binary.LittleEndian.PutUint32(frame[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint16(frame[4:6], uint16(blockSize))
	frame[6] = version
	frame[7] = 0
	binary.LittleEndian.PutUint32(frame[8:12], seed)
	copy(frame[12:], combined)
	return frame
}

// Decoder reconstructs the payload from a stream of frames.
type Decoder struct {
	payloadLen int
	blockSize  int
	k          int
	known      [][]byte // recovered source blocks, nil until known
	pending    []*pendingFrame
}

type pendingFrame struct {
	indices []int
	data    []byte
}

// NewDecoder constructs an empty decoder. Header is parsed from the first
// fed frame.
func NewDecoder() *Decoder { return &Decoder{} }

// Add ingests one frame. Returns (payload, true) once decode is complete.
func (d *Decoder) Add(frame []byte) ([]byte, bool, error) {
	if len(frame) < headerLen+1 {
		return nil, false, errors.New("fountain: frame too short")
	}
	pl := int(binary.LittleEndian.Uint32(frame[0:4]))
	bs := int(binary.LittleEndian.Uint16(frame[4:6]))
	if frame[6] != version {
		return nil, false, errors.New("fountain: bad version")
	}
	// The header is attacker-controlled: every frame arrives from a camera
	// pointed at an arbitrary QR code, or from a pasted line. Validate it
	// COMPLETELY before any value derived from it is used to divide or to
	// size an allocation. Getting this order wrong is not a recoverable
	// error in Go — `bs == 0` is an integer divide-by-zero panic, and an
	// unbounded `pl` is `fatal error: out of memory`, which no recover()
	// can catch and which kills the whole app on the handset.
	if bs <= 0 || bs > MaxBlockSize {
		return nil, false, errors.New("fountain: bad block size in header")
	}
	if pl <= 0 || pl > MaxPayloadLen {
		return nil, false, errors.New("fountain: payload length out of range")
	}
	// Check the body length against THIS frame's header before trusting
	// the header at all, so a lone oversized frame is rejected on arrival
	// rather than after it has resized the decoder.
	if len(frame) != headerLen+bs {
		return nil, false, errors.New("fountain: bad block size")
	}
	if k := (pl + bs - 1) / bs; k > MaxBlocks {
		return nil, false, errors.New("fountain: too many blocks")
	}
	if d.k == 0 {
		d.payloadLen = pl
		d.blockSize = bs
		d.k = (pl + bs - 1) / bs
		d.known = make([][]byte, d.k)
	} else if d.payloadLen != pl || d.blockSize != bs {
		return nil, false, errors.New("fountain: header mismatch across frames")
	}
	seed := binary.LittleEndian.Uint32(frame[8:12])
	r := rand.New(rand.NewSource(int64(seed)))
	degree := robustSolitonDegree(r, d.k)
	indices := pickIndices(r, d.k, degree)
	body := make([]byte, d.blockSize)
	copy(body, frame[12:])
	pf := &pendingFrame{indices: indices, data: body}
	d.pending = append(d.pending, pf)
	d.propagate()
	if d.complete() {
		out := make([]byte, d.payloadLen)
		offset := 0
		for i := 0; i < d.k; i++ {
			n := d.blockSize
			if offset+n > d.payloadLen {
				n = d.payloadLen - offset
			}
			copy(out[offset:offset+n], d.known[i][:n])
			offset += n
		}
		return out, true, nil
	}
	return nil, false, nil
}

// Progress returns (recovered, total). Useful for UI.
func (d *Decoder) Progress() (int, int) {
	got := 0
	for _, b := range d.known {
		if b != nil {
			got++
		}
	}
	return got, d.k
}

func (d *Decoder) complete() bool {
	for _, b := range d.known {
		if b == nil {
			return false
		}
	}
	return d.k > 0
}

// propagate is the standard belief-propagation loop for LT codes:
// repeatedly find frames with exactly one unknown index and solve it.
func (d *Decoder) propagate() {
	changed := true
	for changed {
		changed = false
		filtered := d.pending[:0]
		for _, pf := range d.pending {
			// Reduce: XOR out any already-known indices.
			rem := pf.indices[:0]
			for _, idx := range pf.indices {
				if d.known[idx] != nil {
					xorInPlace(pf.data, d.known[idx])
				} else {
					rem = append(rem, idx)
				}
			}
			pf.indices = rem
			switch len(pf.indices) {
			case 0:
				// Useless, drop.
				continue
			case 1:
				idx := pf.indices[0]
				d.known[idx] = make([]byte, d.blockSize)
				copy(d.known[idx], pf.data)
				changed = true
				continue
			default:
				filtered = append(filtered, pf)
			}
		}
		d.pending = filtered
	}
}

// robustSolitonDegree picks a degree per Luby's robust soliton
// distribution. We use ideal-soliton when k<=2 to avoid edge cases.
func robustSolitonDegree(r *rand.Rand, k int) int {
	if k <= 1 {
		return 1
	}
	const c = 0.03
	const delta = 0.5
	// R = c * ln(k/delta) * sqrt(k)
	R := c * math.Log(float64(k)/delta) * math.Sqrt(float64(k))
	if R < 1 {
		R = 1
	}
	rnd := r.Float64()
	// Sample by inverse CDF. We approximate by truncated normal-ish sampling.
	// Cheap but adequate: select degree d with prob mass mu(d) = (rho(d)+tau(d))/Z.
	weights := make([]float64, k+1) // 1..k
	total := 0.0
	for d := 1; d <= k; d++ {
		var rho, tau float64
		if d == 1 {
			rho = 1.0 / float64(k)
		} else {
			rho = 1.0 / float64(d*(d-1))
		}
		switch {
		case d <= int(math.Floor(float64(k)/R))-1:
			tau = R / (float64(d) * float64(k))
		case d == int(math.Floor(float64(k)/R)):
			tau = R * math.Log(R/delta) / float64(k)
		default:
			tau = 0
		}
		weights[d] = rho + tau
		total += weights[d]
	}
	cumulative := 0.0
	pick := rnd * total
	for d := 1; d <= k; d++ {
		cumulative += weights[d]
		if pick <= cumulative {
			return d
		}
	}
	return k
}

// pickIndices returns `degree` distinct indices in [0,k).
func pickIndices(r *rand.Rand, k, degree int) []int {
	if degree >= k {
		out := make([]int, k)
		for i := range out {
			out[i] = i
		}
		return out
	}
	picked := make(map[int]struct{}, degree)
	out := make([]int, 0, degree)
	for len(out) < degree {
		idx := r.Intn(k)
		if _, ok := picked[idx]; ok {
			continue
		}
		picked[idx] = struct{}{}
		out = append(out, idx)
	}
	return out
}

func xorInPlace(dst, src []byte) {
	n := len(src)
	if len(dst) < n {
		n = len(dst)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i]
	}
}
