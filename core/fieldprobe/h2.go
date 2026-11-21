package fieldprobe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// A minimal HTTP/2 GET, for a probe that sent Chrome's unmodified hello
// (ALPN h2 first) and was answered h2. Only what the probe reads is
// implemented: one stream, the response status when the server sends
// it as a static-table index or a plain literal, and the DATA byte
// count. core/ may not import net/http (core/opsec_test.go), and the
// import path of golang.org/x/net/http2 contains that string, so this
// is written out by hand; it is RFC 9113's client side, cut down.
//
// Everything here is inside TLS: the frame layout is not something an
// on-path filter sees. The SETTINGS and WINDOW_UPDATE values are
// Chrome's, so the server-side view is ordinary too.

const (
	h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	h2Data         = 0x0
	h2Headers      = 0x1
	h2RSTStream    = 0x3
	h2Settings     = 0x4
	h2Ping         = 0x6
	h2GoAway       = 0x7
	h2Continuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	h2MaxFrame = 1 << 14 // the default SETTINGS_MAX_FRAME_SIZE we accept
)

func h2Frame(typ, flags byte, stream uint32, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	n := len(payload)
	b[0], b[1], b[2] = byte(n>>16), byte(n>>8), byte(n)
	b[3], b[4] = typ, flags
	binary.BigEndian.PutUint32(b[5:9], stream&0x7fffffff)
	copy(b[9:], payload)
	return b
}

// hpackInt appends an HPACK integer with an n-bit prefix (RFC 7541 §5.1).
func hpackInt(b []byte, first byte, n uint, v int) []byte {
	max := (1 << n) - 1
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

// hpackString appends a plain (non-Huffman) string literal.
func hpackString(b []byte, s string) []byte {
	b = hpackInt(b, 0x00, 7, len(s))
	return append(b, s...)
}

// h2RequestBlock is the request's header block: static-table indexes
// where the static table has the exact field (RFC 7541 Appendix A), and
// "literal without indexing" for the rest, so nothing goes in the
// server's dynamic table.
func h2RequestBlock(sp tcpSpec) []byte {
	var b []byte
	if sp.method() == "HEAD" {
		b = hpackString(hpackInt(b, 0x00, 4, 2), "HEAD") // :method, literal
	} else {
		b = append(b, 0x82) // :method GET
	}
	b = hpackString(hpackInt(b, 0x00, 4, 1), sp.host()) // :authority
	b = append(b, 0x87)                                 // :scheme https
	b = hpackString(hpackInt(b, 0x00, 4, 4), sp.Path)   // :path
	for _, h := range [][2]string{
		{"user-agent", userAgent}, {"accept", "*/*"},
		{"accept-encoding", "identity"}, {"accept-language", "en-US,en;q=0.9"},
	} {
		b = append(b, 0x00)
		b = hpackString(b, h[0])
		b = hpackString(b, h[1])
	}
	return b
}

// h2StatusOf reads :status from the start of a response header block,
// when the server put it there in one of the two plain forms; 0 when it
// cannot tell (a Huffman-coded or table-referenced literal).
func h2StatusOf(block []byte) int {
	// A dynamic table size update (001xxxxx, a 5-bit-prefix integer) may
	// come first: servers send one after our HEADER_TABLE_SIZE.
	for len(block) > 0 && block[0]&0xe0 == 0x20 {
		i := 1
		if block[0]&0x1f == 0x1f {
			for i < len(block) && block[i]&0x80 != 0 {
				i++
			}
			i++
		}
		if i > len(block) {
			return 0
		}
		block = block[i:]
	}
	if len(block) == 0 {
		return 0
	}
	switch block[0] {
	case 0x88:
		return 200
	case 0x89:
		return 204
	case 0x8a:
		return 206
	case 0x8b:
		return 304
	case 0x8c:
		return 400
	case 0x8d:
		return 404
	case 0x8e:
		return 500
	}
	// Literal with a static name index 8..14 (:status), any of the three
	// literal representations, a plain 3-digit value.
	var idx int
	switch {
	case block[0]&0xc0 == 0x40:
		idx = int(block[0] & 0x3f)
	case block[0]&0xf0 == 0x00, block[0]&0xf0 == 0x10:
		idx = int(block[0] & 0x0f)
	default:
		return 0
	}
	if idx < 8 || idx > 14 || len(block) < 5 || block[1] != 3 {
		return 0
	}
	v := 0
	for _, c := range block[2:5] {
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + int(c-'0')
	}
	return v
}

// h2Request sends the probe's GET on stream 1 and reads the answer up to
// sp.ReadLimit DATA bytes, filling HTTPStatus and EndKind like the
// HTTP/1.1 path does.
func h2Request(conn net.Conn, sp tcpSpec, o *tcpObs) {
	var out bytes.Buffer
	out.WriteString(h2Preface)
	// Chrome's SETTINGS: HEADER_TABLE_SIZE 65536, ENABLE_PUSH 0,
	// INITIAL_WINDOW_SIZE 6291456, MAX_HEADER_LIST_SIZE 262144.
	var st []byte
	for _, kv := range [][2]uint32{{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}} {
		st = binary.BigEndian.AppendUint16(st, uint16(kv[0]))
		st = binary.BigEndian.AppendUint32(st, kv[1])
	}
	out.Write(h2Frame(h2Settings, 0, 0, st))
	out.Write(h2Frame(0x8, 0, 0, binary.BigEndian.AppendUint32(nil, 15663105))) // WINDOW_UPDATE
	out.Write(h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 1, h2RequestBlock(sp)))
	if _, err := conn.Write(out.Bytes()); err != nil {
		o.EndKind = eventOf(err)
		return
	}
	limit := sp.ReadLimit
	if limit <= 0 {
		limit = 4096
	}
	br := bufio.NewReaderSize(conn, 16*1024)
	hdr := make([]byte, 9)
	var got int64
	var block []byte
	for got < limit {
		if _, err := io.ReadFull(br, hdr); err != nil {
			o.EndKind = h2End(err)
			return
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		stream := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
		if n > h2MaxFrame {
			o.EndKind = "other"
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			o.EndKind = h2End(err)
			return
		}
		switch typ {
		case h2Settings:
			if flags&h2FlagAck == 0 {
				if _, err := conn.Write(h2Frame(h2Settings, h2FlagAck, 0, nil)); err != nil {
					o.EndKind = eventOf(err)
					return
				}
			}
		case h2Ping:
			if flags&h2FlagAck == 0 {
				_, _ = conn.Write(h2Frame(h2Ping, h2FlagAck, 0, payload))
			}
		case h2GoAway:
			o.EndKind = "fin"
			return
		case h2RSTStream:
			if stream == 1 {
				o.EndKind = "fin"
				return
			}
		case h2Headers, h2Continuation:
			if stream != 1 {
				continue
			}
			p := payload
			if typ == h2Headers {
				p = h2StripHeaders(p, flags)
			}
			if o.HTTPStatus == 0 && len(block) < 64 {
				block = append(block, p...)
				if flags&h2FlagEndHeaders != 0 {
					o.HTTPStatus = h2StatusOf(block)
				}
			}
			if flags&h2FlagEndStream != 0 {
				o.EndKind = "fin"
				return
			}
		case h2Data:
			if stream != 1 {
				continue
			}
			got += int64(n)
			if len(o.Body) < 2048 {
				o.Body = append(o.Body, payload[:min(n, 2048-len(o.Body))]...)
			}
			if flags&h2FlagEndStream != 0 {
				o.EndKind = "fin"
				return
			}
		}
	}
	o.EndKind = "limit"
}

// h2StripHeaders drops a HEADERS frame's padding and priority fields.
func h2StripHeaders(p []byte, flags byte) []byte {
	pad := 0
	if flags&h2FlagPadded != 0 {
		if len(p) == 0 {
			return nil
		}
		pad, p = int(p[0]), p[1:]
	}
	if flags&h2FlagPriority != 0 {
		if len(p) < 5 {
			return nil
		}
		p = p[5:]
	}
	if pad > len(p) {
		return nil
	}
	return p[:len(p)-pad]
}

// h2End is eventOf for a frame read; a short read is the far end
// closing.
func h2End(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "fin"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return eventOf(err)
}
