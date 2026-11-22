package bootstrap

// h2mini.go — the client side of HTTP/2 (RFC 9113) and HPACK (RFC 7541),
// cut down to what the Google-front fetch needs (front.go): GET requests
// on one connection, one after the other, a bounded response body, and a
// full header decoder (Google answers with Huffman-coded, table-indexed
// headers, and the redirect's Location is the header that matters).
//
// WHY BY HAND. core/ may not import net/http (core/opsec_test.go), and
// the import paths of golang.org/x/net/http2 and of its hpack package
// both contain that string; http2 imports net/http as well. So, like
// core/fieldprobe/h2.go, this is written out — but unlike that probe it
// decodes every header block, because a missed dynamic-table insert
// would misread every header after it.
//
// Everything here runs inside TLS. The SETTINGS and WINDOW_UPDATE values
// are Chrome's, so what Google's front sees of the connection set-up is
// ordinary; the frame ORDER and the header encoding are Go-shaped, which
// the plan accepts for one short fetch on failure (docs/optional-addons-
// plan.md §3.6, "Fingerprint").

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FramePriority     = 0x2
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	// h2MaxFrameSize is the SETTINGS_MAX_FRAME_SIZE we accept: the
	// protocol default, which Chrome does not raise.
	h2MaxFrameSize = 1 << 14

	// Chrome's connection settings.
	h2HeaderTableSize   = 65536
	h2InitialWindowSize = 6291456
	h2MaxHeaderListSize = 262144
	h2ConnWindowBump    = 15663105

	// h2MaxHeaderBlock bounds one response header block, compressed and
	// decoded. A redirect's headers are well under 4 KB.
	h2MaxHeaderBlock = 64 << 10
)

// ErrResponseTooLarge: a response body went past the caller's bound.
// The read stops there; nothing is truncated and handed on.
var ErrResponseTooLarge = errors.New("fetcher: response larger than allowed")

// h2Response is one answer.
type h2Response struct {
	status  int
	headers []hpackField
	body    []byte
}

func (r *h2Response) header(name string) (string, bool) {
	for _, f := range r.headers {
		if f.name == name {
			return f.value, true
		}
	}
	return "", false
}

// h2Client is one client connection.
type h2Client struct {
	conn   net.Conn
	br     *bufio.Reader
	dec    hpackDecoder
	stream uint32 // the last stream id used
	// goAway is set once the server sent GOAWAY; lastStream is the
	// highest stream id it will still answer.
	goAway     bool
	lastStream uint32
	// budget bounds every byte read from the connection, frames of
	// any type included, so a server cannot keep us reading forever
	// (a PING or SETTINGS flood) inside the caller's deadline.
	budget int
}

// newH2Client writes the connection preface, Chrome's SETTINGS and its
// connection WINDOW_UPDATE. readBudget bounds all bytes read.
func newH2Client(conn net.Conn, readBudget int) (*h2Client, error) {
	c := &h2Client{
		conn:   conn,
		br:     bufio.NewReaderSize(conn, 16<<10),
		dec:    newHPACKDecoder(h2HeaderTableSize),
		budget: readBudget,
	}
	out := []byte(h2ClientPreface)
	var st []byte
	for _, kv := range [][2]uint32{
		{0x1, h2HeaderTableSize},   // HEADER_TABLE_SIZE
		{0x2, 0},                   // ENABLE_PUSH
		{0x4, h2InitialWindowSize}, // INITIAL_WINDOW_SIZE
		{0x6, h2MaxHeaderListSize}, // MAX_HEADER_LIST_SIZE
	} {
		st = binary.BigEndian.AppendUint16(st, uint16(kv[0]))
		st = binary.BigEndian.AppendUint32(st, kv[1])
	}
	out = appendH2Frame(out, h2FrameSettings, 0, 0, st)
	out = appendH2Frame(out, h2FrameWindowUpdate, 0, 0, binary.BigEndian.AppendUint32(nil, h2ConnWindowBump))
	if _, err := conn.Write(out); err != nil {
		return nil, fmt.Errorf("h2: write preface: %w", err)
	}
	return c, nil
}

func appendH2Frame(b []byte, typ, flags byte, stream uint32, payload []byte) []byte {
	n := len(payload)
	b = append(b, byte(n>>16), byte(n>>8), byte(n), typ, flags)
	b = binary.BigEndian.AppendUint32(b, stream&0x7fffffff)
	return append(b, payload...)
}

// h2RequestHeaders encodes a GET's header block: static-table indexes
// for the exact fields the static table has, "literal without
// indexing" (no Huffman) for the rest, so nothing goes in the server's
// dynamic table and our encoder keeps no state.
func h2RequestHeaders(authority, path string) []byte {
	return h2RequestHeadersAccept(authority, path, "")
}

// h2DefaultAccept is the accept header every request sends unless its
// caller names another (front.go's fetches always send this one).
const h2DefaultAccept = "*/*"

// h2RequestHeadersAccept is h2RequestHeaders with the accept header
// chosen by the caller ("" = h2DefaultAccept, byte for byte what
// h2RequestHeaders has always sent). The value must already be a safe
// header value (browserget.go checks it).
func h2RequestHeadersAccept(authority, path, accept string) []byte {
	if accept == "" {
		accept = h2DefaultAccept
	}
	var b []byte
	b = append(b, 0x82) // :method GET
	b = hpackLiteralIndexedName(b, 1, authority)
	b = append(b, 0x87) // :scheme https
	if path == "/" {
		b = append(b, 0x84)
	} else {
		b = hpackLiteralIndexedName(b, 4, path)
	}
	for _, h := range [][2]string{
		{"user-agent", requestUserAgent},
		{"accept", accept},
		{"accept-encoding", "identity"},
		{"accept-language", "en-US,en;q=0.9"},
	} {
		b = append(b, 0x00)
		b = hpackAppendString(b, h[0])
		b = hpackAppendString(b, h[1])
	}
	return b
}

// get sends one GET on a new stream and reads its answer: at most
// maxBody bytes of body. A body longer than that is ErrResponseTooLarge.
func (c *h2Client) get(authority, path string, maxBody int) (*h2Response, error) {
	return c.getAccept(authority, path, "", maxBody)
}

// getAccept is get with the request's accept header chosen by the
// caller ("" = h2DefaultAccept).
func (c *h2Client) getAccept(authority, path, accept string, maxBody int) (*h2Response, error) {
	if c.stream == 0 {
		c.stream = 1
	} else {
		c.stream += 2
	}
	id := c.stream
	if c.goAway && id > c.lastStream {
		return nil, errors.New("h2: the server is closing the connection")
	}
	block := h2RequestHeadersAccept(authority, path, accept)
	if len(block) > h2MaxFrameSize {
		return nil, errors.New("h2: request headers too long")
	}
	if _, err := c.conn.Write(appendH2Frame(nil, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, id, block)); err != nil {
		return nil, fmt.Errorf("h2: write request: %w", err)
	}

	resp := &h2Response{}
	var (
		frag      []byte // a header block being assembled
		fragOpen  bool
		fragEnd   bool // that block's HEADERS carried END_STREAM
		gotFinal  bool // the final (non-1xx) response headers are in
		hdr       [9]byte
		payload   = make([]byte, h2MaxFrameSize)
		finishErr = func(err error) (*h2Response, error) { return nil, err }
	)
	for {
		if c.budget < 9 {
			return finishErr(ErrResponseTooLarge)
		}
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return finishErr(fmt.Errorf("h2: read: %w", err))
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		sid := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
		if n > h2MaxFrameSize {
			return finishErr(errors.New("h2: frame larger than the size we allow"))
		}
		c.budget -= 9 + n
		if c.budget < 0 {
			return finishErr(ErrResponseTooLarge)
		}
		p := payload[:n]
		if _, err := io.ReadFull(c.br, p); err != nil {
			return finishErr(fmt.Errorf("h2: read: %w", err))
		}
		// A header block, once started, must be continued by
		// CONTINUATION frames on the same stream and nothing else.
		if fragOpen && (typ != h2FrameContinuation || sid != id) {
			return finishErr(errors.New("h2: header block interrupted"))
		}
		switch typ {
		case h2FrameSettings:
			if sid != 0 {
				return finishErr(errors.New("h2: SETTINGS on a stream"))
			}
			if flags&h2FlagAck == 0 {
				if n%6 != 0 {
					return finishErr(errors.New("h2: malformed SETTINGS"))
				}
				if _, err := c.conn.Write(appendH2Frame(nil, h2FrameSettings, h2FlagAck, 0, nil)); err != nil {
					return finishErr(fmt.Errorf("h2: write: %w", err))
				}
			}
		case h2FramePing:
			if n != 8 {
				return finishErr(errors.New("h2: malformed PING"))
			}
			if flags&h2FlagAck == 0 {
				if _, err := c.conn.Write(appendH2Frame(nil, h2FramePing, h2FlagAck, 0, p)); err != nil {
					return finishErr(fmt.Errorf("h2: write: %w", err))
				}
			}
		case h2FrameGoAway:
			if n < 8 {
				return finishErr(errors.New("h2: malformed GOAWAY"))
			}
			c.goAway = true
			c.lastStream = binary.BigEndian.Uint32(p[:4]) & 0x7fffffff
			if c.lastStream < id {
				return finishErr(errors.New("h2: the server refused the request (GOAWAY)"))
			}
		case h2FrameRSTStream:
			if sid == id {
				return finishErr(errors.New("h2: the server reset the request"))
			}
		case h2FramePushPromise:
			// We said ENABLE_PUSH 0.
			return finishErr(errors.New("h2: unrequested PUSH_PROMISE"))
		case h2FrameHeaders:
			if sid != id {
				// No other stream of ours is open; a header block
				// for one is a protocol error, and skipping it
				// would desynchronise the HPACK table.
				return finishErr(errors.New("h2: HEADERS on an unknown stream"))
			}
			body, err := h2StripPaddingPriority(p, flags)
			if err != nil {
				return finishErr(err)
			}
			frag = append(frag[:0], body...)
			fragEnd = flags&h2FlagEndStream != 0
			fragOpen = flags&h2FlagEndHeaders == 0
			if !fragOpen {
				done, err := c.headerBlock(resp, frag, fragEnd, &gotFinal)
				if err != nil || done {
					return resp, err
				}
			}
		case h2FrameContinuation:
			if !fragOpen || sid != id {
				return finishErr(errors.New("h2: stray CONTINUATION"))
			}
			if len(frag)+len(p) > h2MaxHeaderBlock {
				return finishErr(errors.New("h2: response headers too long"))
			}
			frag = append(frag, p...)
			if flags&h2FlagEndHeaders != 0 {
				fragOpen = false
				done, err := c.headerBlock(resp, frag, fragEnd, &gotFinal)
				if err != nil || done {
					return resp, err
				}
			}
		case h2FrameData:
			if sid != id {
				return finishErr(errors.New("h2: DATA on an unknown stream"))
			}
			if !gotFinal {
				return finishErr(errors.New("h2: DATA before the response headers"))
			}
			body, err := h2StripPaddingPriority(p, flags&h2FlagPadded)
			if err != nil {
				return finishErr(err)
			}
			if len(resp.body)+len(body) > maxBody {
				return finishErr(ErrResponseTooLarge)
			}
			resp.body = append(resp.body, body...)
			if flags&h2FlagEndStream != 0 {
				return resp, nil
			}
		default:
			// WINDOW_UPDATE, PRIORITY, and frame types this client
			// does not know: ignored, as RFC 9113 §4.1 requires of
			// unknown types. Our windows (6 MB per stream, 15 MB on
			// the connection) are far beyond any body we accept, so
			// we never need to send a WINDOW_UPDATE ourselves.
		}
	}
}

// headerBlock decodes one complete header block for the request's
// stream. done reports the stream ended with it.
func (c *h2Client) headerBlock(resp *h2Response, block []byte, endStream bool, gotFinal *bool) (bool, error) {
	fields, err := c.dec.decode(block, h2MaxHeaderBlock)
	if err != nil {
		return false, err
	}
	if *gotFinal {
		// Trailers: they must end the stream; their content is
		// not used.
		if !endStream {
			return false, errors.New("h2: trailers without END_STREAM")
		}
		return true, nil
	}
	status := 0
	for _, f := range fields {
		if f.name == ":status" {
			s, err := strconv.Atoi(f.value)
			if err != nil || s < 100 || s > 999 {
				return false, errors.New("h2: malformed :status")
			}
			status = s
		}
	}
	if status == 0 {
		return false, errors.New("h2: response without :status")
	}
	if status < 200 {
		// An informational answer (103 Early Hints): the real one
		// follows on the same stream.
		if endStream {
			return false, errors.New("h2: stream ended on an informational answer")
		}
		return false, nil
	}
	*gotFinal = true
	resp.status = status
	resp.headers = fields
	return endStream, nil
}

// h2StripPaddingPriority drops the padding (and, on HEADERS, the
// priority fields) of a frame payload.
func h2StripPaddingPriority(p []byte, flags byte) ([]byte, error) {
	pad := 0
	if flags&h2FlagPadded != 0 {
		if len(p) < 1 {
			return nil, errors.New("h2: malformed padding")
		}
		pad, p = int(p[0]), p[1:]
	}
	if flags&h2FlagPriority != 0 {
		if len(p) < 5 {
			return nil, errors.New("h2: malformed priority")
		}
		p = p[5:]
	}
	if pad > len(p) {
		return nil, errors.New("h2: padding longer than the frame")
	}
	return p[:len(p)-pad], nil
}

// ---- HPACK ----------------------------------------------------------

type hpackField struct{ name, value string }

func (f hpackField) size() int { return len(f.name) + len(f.value) + 32 }

// hpackDecoder holds one connection's dynamic table (RFC 7541 §2.3.2),
// newest entry first.
type hpackDecoder struct {
	dyn     []hpackField
	size    int
	maxSize int // the current maximum, from table size updates
	limit   int // the SETTINGS_HEADER_TABLE_SIZE we advertised
}

func newHPACKDecoder(limit int) hpackDecoder {
	return hpackDecoder{maxSize: limit, limit: limit}
}

func (d *hpackDecoder) evict() {
	for d.size > d.maxSize && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.size -= last.size()
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
}

func (d *hpackDecoder) add(f hpackField) {
	if f.size() > d.maxSize {
		// RFC 7541 §4.4: an entry larger than the table empties it.
		d.dyn, d.size = d.dyn[:0], 0
		return
	}
	d.dyn = append([]hpackField{f}, d.dyn...)
	d.size += f.size()
	d.evict()
}

func (d *hpackDecoder) at(i int) (hpackField, error) {
	switch {
	case i <= 0:
		return hpackField{}, errors.New("hpack: index 0")
	case i <= len(hpackStatic):
		return hpackStatic[i-1], nil
	case i-len(hpackStatic) <= len(d.dyn):
		return d.dyn[i-len(hpackStatic)-1], nil
	}
	return hpackField{}, errors.New("hpack: index out of range")
}

// decode reads one complete header block. maxList bounds the decoded
// fields' total size.
func (d *hpackDecoder) decode(b []byte, maxList int) ([]hpackField, error) {
	var out []hpackField
	total := 0
	fieldsSeen := false
	for len(b) > 0 {
		c := b[0]
		var (
			f   hpackField
			err error
		)
		switch {
		case c&0x80 != 0: // indexed field
			var i int
			if i, b, err = hpackReadInt(b, 7); err != nil {
				return nil, err
			}
			if f, err = d.at(i); err != nil {
				return nil, err
			}
		case c&0xc0 == 0x40: // literal, incremental indexing
			if f, b, err = d.readLiteral(b, 6); err != nil {
				return nil, err
			}
			d.add(f)
		case c&0xe0 == 0x20: // dynamic table size update
			if fieldsSeen {
				return nil, errors.New("hpack: table size update after a field")
			}
			var n int
			if n, b, err = hpackReadInt(b, 5); err != nil {
				return nil, err
			}
			if n > d.limit {
				return nil, errors.New("hpack: table size above our setting")
			}
			d.maxSize = n
			d.evict()
			continue
		default: // literal without indexing (0000) or never indexed (0001)
			if f, b, err = d.readLiteral(b, 4); err != nil {
				return nil, err
			}
		}
		fieldsSeen = true
		total += f.size()
		if total > maxList {
			return nil, errors.New("hpack: header list too long")
		}
		out = append(out, f)
	}
	return out, nil
}

// readLiteral reads a literal field whose name index has an n-bit
// prefix (0 = the name follows as a string).
func (d *hpackDecoder) readLiteral(b []byte, n uint) (hpackField, []byte, error) {
	var f hpackField
	i, b, err := hpackReadInt(b, n)
	if err != nil {
		return f, nil, err
	}
	if i == 0 {
		if f.name, b, err = hpackReadString(b); err != nil {
			return f, nil, err
		}
	} else {
		named, err := d.at(i)
		if err != nil {
			return f, nil, err
		}
		f.name = named.name
	}
	if f.value, b, err = hpackReadString(b); err != nil {
		return f, nil, err
	}
	return f, b, nil
}

// hpackReadInt reads an integer with an n-bit prefix (RFC 7541 §5.1).
func hpackReadInt(b []byte, n uint) (int, []byte, error) {
	if len(b) == 0 {
		return 0, nil, errors.New("hpack: truncated")
	}
	max := 1<<n - 1
	v := int(b[0]) & max
	b = b[1:]
	if v < max {
		return v, b, nil
	}
	shift := uint(0)
	for {
		if len(b) == 0 {
			return 0, nil, errors.New("hpack: truncated integer")
		}
		c := b[0]
		b = b[1:]
		v += int(c&0x7f) << shift
		if v > 1<<24 {
			return 0, nil, errors.New("hpack: integer too large")
		}
		if c&0x80 == 0 {
			return v, b, nil
		}
		shift += 7
	}
}

// hpackReadString reads a string literal (§5.2), Huffman-coded or not.
func hpackReadString(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, errors.New("hpack: truncated")
	}
	huff := b[0]&0x80 != 0
	n, b, err := hpackReadInt(b, 7)
	if err != nil {
		return "", nil, err
	}
	if n > len(b) {
		return "", nil, errors.New("hpack: string past the block")
	}
	raw, rest := b[:n], b[n:]
	if !huff {
		return string(raw), rest, nil
	}
	s, err := hpackHuffmanDecode(raw)
	if err != nil {
		return "", nil, err
	}
	return s, rest, nil
}

// hpackLiteralIndexedName appends "literal without indexing" with the
// name taken from static index idx and a plain value.
func hpackLiteralIndexedName(b []byte, idx int, value string) []byte {
	b = hpackAppendInt(b, 0x00, 4, idx)
	return hpackAppendString(b, value)
}

// hpackAppendInt appends an integer with an n-bit prefix.
func hpackAppendInt(b []byte, first byte, n uint, v int) []byte {
	max := 1<<n - 1
	if v < max {
		return append(b, first|byte(v))
	}
	b = append(b, first|byte(max))
	v -= max
	for v >= 128 {
		b = append(b, byte(v%128+128))
		v /= 128
	}
	return append(b, byte(v))
}

// hpackAppendString appends a plain (not Huffman-coded) string literal.
func hpackAppendString(b []byte, s string) []byte {
	b = hpackAppendInt(b, 0x00, 7, len(s))
	return append(b, s...)
}

// The Huffman decoding tree, built once from hpackHuffmanCodes.
type huffNode struct {
	next [2]int16 // child node indexes; 0 = none (the root is never a child)
	sym  int16    // the byte at a leaf, -1 at an inner node
}

var huffTree = buildHuffTree()

func buildHuffTree() []huffNode {
	t := []huffNode{{sym: -1}}
	for sym := 0; sym < 256; sym++ {
		code, n := hpackHuffmanCodes[sym], int(hpackHuffmanLens[sym])
		at := 0
		for i := n - 1; i >= 0; i-- {
			bit := (code >> uint(i)) & 1
			if t[at].next[bit] == 0 {
				t = append(t, huffNode{sym: -1})
				t[at].next[bit] = int16(len(t) - 1)
			}
			at = int(t[at].next[bit])
		}
		t[at].sym = int16(sym)
	}
	return t
}

// hpackHuffmanDecode decodes a Huffman-coded string (§5.2): the padding
// at the end must be fewer than 8 bits, all ones (the EOS prefix), and
// EOS itself must not appear.
func hpackHuffmanDecode(b []byte) (string, error) {
	var sb strings.Builder
	at, depth, ones := 0, 0, true
	for _, c := range b {
		for i := 7; i >= 0; i-- {
			bit := (c >> uint(i)) & 1
			nx := huffTree[at].next[bit]
			if nx == 0 {
				// Only EOS (30 ones) reaches a missing child.
				return "", errors.New("hpack: invalid Huffman code")
			}
			at = int(nx)
			depth++
			if bit == 0 {
				ones = false
			}
			if s := huffTree[at].sym; s >= 0 {
				sb.WriteByte(byte(s))
				at, depth, ones = 0, 0, true
			}
		}
		if sb.Len() > h2MaxHeaderBlock {
			return "", errors.New("hpack: string too long")
		}
	}
	if depth > 7 || !ones {
		return "", errors.New("hpack: invalid Huffman padding")
	}
	return sb.String(), nil
}
