package desync

import (
	"encoding/binary"
	"sort"
)

const (
	recordHeaderLen = 5
	// maxRecordLen bounds what is buffered as "the first record": a TLS
	// record's payload is at most 2^14 bytes (+256 for a compressed or
	// 2048 for an encrypted one; a ClientHello is neither, but a header
	// claiming more than this is not a hello we wait for).
	maxRecordLen = 16384 + 2048
)

// recordState reads a stream's opening bytes as a TLS handshake record
// header.
//
//	need > 0: it is one, and the record ends `need` bytes from the start
//	isTLS false: it is not one (or not one this package will wait for)
//	more: too few bytes to tell yet, and what there is looks like a header
func recordState(b []byte) (need int, isTLS, more bool) {
	if len(b) == 0 {
		return 0, false, true
	}
	if b[0] != 0x16 {
		return 0, false, false
	}
	if len(b) >= 2 && b[1] != 3 {
		return 0, false, false
	}
	if len(b) >= 3 && b[2] > 4 {
		return 0, false, false
	}
	if len(b) < recordHeaderLen {
		return 0, false, true
	}
	l := int(binary.BigEndian.Uint16(b[3:5]))
	if l < 1 || l > maxRecordLen {
		return 0, false, false
	}
	return recordHeaderLen + l, true, false
}

// parseRecord reports whether b opens with a COMPLETE TLS handshake
// record, and its payload length.
func parseRecord(b []byte) (payloadLen int, ok bool) {
	need, isTLS, _ := recordState(b)
	if !isTLS || len(b) < need {
		return 0, false
	}
	return need - recordHeaderLen, true
}

// locateSNI finds the host name of the server_name extension in one
// complete TLS record holding a ClientHello: its offset from the start
// of the record (header included) and its length. (-1, 0) when the
// record is not a ClientHello, has no server_name, or does not parse —
// never an error: the name is one optional cut, not a gate.
func locateSNI(rec []byte) (at, n int) {
	if len(rec) < recordHeaderLen+4 || rec[recordHeaderLen] != 1 {
		return -1, 0
	}
	hs := rec[recordHeaderLen:]
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return -1, 0 // the hello continues in another record
	}
	base := recordHeaderLen + 4
	p := hs[4 : 4+hsLen]
	off := 0
	skip := func(k int) bool {
		if k < 0 || off+k > len(p) {
			return false
		}
		off += k
		return true
	}
	if !skip(2 + 32) { // legacy_version, random
		return -1, 0
	}
	if off >= len(p) || !skip(1+int(p[off])) { // session id
		return -1, 0
	}
	if off+2 > len(p) || !skip(2+int(binary.BigEndian.Uint16(p[off:]))) { // cipher suites
		return -1, 0
	}
	if off >= len(p) || !skip(1+int(p[off])) { // compression methods
		return -1, 0
	}
	if off+2 > len(p) {
		return -1, 0
	}
	extEnd := off + 2 + int(binary.BigEndian.Uint16(p[off:]))
	off += 2
	if extEnd > len(p) {
		return -1, 0
	}
	for off+4 <= extEnd {
		typ := binary.BigEndian.Uint16(p[off:])
		l := int(binary.BigEndian.Uint16(p[off+2:]))
		body := off + 4
		if body+l > extEnd {
			return -1, 0
		}
		off = body + l
		if typ != 0 {
			continue
		}
		// server_name_list: len(2) { name_type(1) len(2) host }
		if l < 5 || p[body+2] != 0 {
			return -1, 0
		}
		hl := int(binary.BigEndian.Uint16(p[body+3:]))
		if hl == 0 || 5+hl > l {
			return -1, 0
		}
		return base + body + 5, hl
	}
	return -1, 0
}

// splitRecord rewrites the first record of `first` (payload length rec)
// into one record per piece, cutting the payload at `splits`. It returns
// the new bytes, the offsets in them where each added record starts, and
// the map from an offset in `first` to the same byte's offset in the
// result.
func splitRecord(first []byte, rec int, splits []int) (out []byte, boundaries []int, at func(int) int) {
	sort.Ints(splits)
	var cuts []int
	for _, s := range splits {
		if s <= 0 || s >= rec || (len(cuts) > 0 && cuts[len(cuts)-1] == s) {
			continue
		}
		cuts = append(cuts, s)
	}
	if len(cuts) == 0 {
		return first, nil, func(i int) int { return i }
	}
	hdr := first[:3]
	payload := first[recordHeaderLen : recordHeaderLen+rec]
	out = make([]byte, 0, len(first)+recordHeaderLen*len(cuts))
	prev := 0
	for i := 0; i <= len(cuts); i++ {
		end := rec
		if i < len(cuts) {
			end = cuts[i]
		}
		if i > 0 {
			boundaries = append(boundaries, len(out))
		}
		out = append(out, hdr...)
		out = binary.BigEndian.AppendUint16(out, uint16(end-prev))
		out = append(out, payload[prev:end]...)
		prev = end
	}
	out = append(out, first[recordHeaderLen+rec:]...)
	at = func(i int) int {
		if i < recordHeaderLen {
			return i
		}
		q := i - recordHeaderLen
		k := sort.SearchInts(cuts, q+1) // cuts ≤ q
		return i + recordHeaderLen*k
	}
	return out, boundaries, at
}
