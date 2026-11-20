package cloudflare

// B-5: the publisher-side ECH read (docs/optional-addons-plan.md §2.2).
//
// The publisher, abroad, reads the hostname's HTTPS record over DoH at
// sign time and at every freshness publish, and the ECHConfigList it
// carries goes into the signed endpoint. Recipients therefore never
// resolve the hostname through local DNS (which in Iran answers
// 10.10.34.x) and never need the HTTPS record to reach them.
//
// This file is the pure half: the DNS query bytes, the answer parser,
// the SVCB/HTTPS rdata parser and the ECHConfigList parser. The DoH
// round trip lives in cf_client_live.go with the other Helper-side
// network calls.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ECHFetcher reads the ECHConfigList a hostname publishes. resolver
// names where the answer came from (for the posture line), never a
// secret. A hostname that publishes no ech parameter returns
// (nil, resolver, nil).
type ECHFetcher interface {
	FetchECH(ctx context.Context, hostname string) (configList []byte, resolver string, err error)
}

// ECHPosture is the ECH state of one hostname as the publisher sees it.
type ECHPosture struct {
	// ZoneSetting is the zone's `ech` setting: "on", "off", or ""
	// when it could not be read.
	ZoneSetting string `json:"zone_setting"`
	// Published: the hostname's HTTPS record carries an ech parameter
	// that parses.
	Published bool `json:"published"`
	// ConfigListB64 is the ECHConfigList, standard base64, as the
	// signed endpoint carries it (`ech_config`).
	ConfigListB64 string `json:"config_list_b64,omitempty"`
	// PublicName is the outer SNI the configs name; on Cloudflare it
	// is the shared `cloudflare-ech.com`.
	PublicName    string `json:"public_name,omitempty"`
	Resolver      string `json:"resolver,omitempty"`
	FetchedAtUnix int64  `json:"fetched_at_unix,omitempty"`
	Error         string `json:"error,omitempty"`
}

// NameHidden is the card's "Name hidden" line: ECH is on for the zone,
// the hostname publishes a usable config, and the outer name is not the
// hostname itself.
func (p ECHPosture) NameHidden(hostname string) bool {
	return p.ZoneSetting == "on" && p.Published && p.PublicName != "" &&
		!strings.EqualFold(p.PublicName, hostname)
}

// ECHConfigInfo is what Daal needs to know about one ECHConfig.
type ECHConfigInfo struct {
	Version    uint16
	ConfigID   uint8
	KEMID      uint16
	PublicName string
}

// echVersion is the ECHConfig version of RFC 9849 (draft 13 onwards).
const echVersion = 0xfe0d

// ParseECHConfigList parses an ECHConfigList and returns the configs of
// the version Daal's clients speak. Configs of other versions are
// skipped, as the RFC requires; a list with none left is an error.
func ParseECHConfigList(b []byte) ([]ECHConfigInfo, error) {
	if len(b) < 2 {
		return nil, errors.New("ech: config list too short")
	}
	n := int(binary.BigEndian.Uint16(b))
	if n != len(b)-2 {
		return nil, fmt.Errorf("ech: config list length %d, have %d bytes", n, len(b)-2)
	}
	rest := b[2:]
	var out []ECHConfigInfo
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, errors.New("ech: truncated config header")
		}
		ver := binary.BigEndian.Uint16(rest)
		clen := int(binary.BigEndian.Uint16(rest[2:]))
		if len(rest) < 4+clen {
			return nil, errors.New("ech: truncated config")
		}
		body := rest[4 : 4+clen]
		rest = rest[4+clen:]
		if ver != echVersion {
			continue
		}
		info, err := parseECHConfigContents(body)
		if err != nil {
			return nil, err
		}
		info.Version = ver
		out = append(out, info)
	}
	if len(out) == 0 {
		return nil, errors.New("ech: no config of a supported version")
	}
	return out, nil
}

func parseECHConfigContents(b []byte) (ECHConfigInfo, error) {
	var info ECHConfigInfo
	r := byteReader{b: b}
	id, ok := r.u8()
	if !ok {
		return info, errors.New("ech: truncated config_id")
	}
	kem, ok := r.u16()
	if !ok {
		return info, errors.New("ech: truncated kem_id")
	}
	if _, ok := r.vec16(); !ok { // public_key
		return info, errors.New("ech: truncated public_key")
	}
	suites, ok := r.vec16()
	if !ok || len(suites) == 0 || len(suites)%4 != 0 {
		return info, errors.New("ech: bad cipher_suites")
	}
	if _, ok := r.u8(); !ok { // maximum_name_length
		return info, errors.New("ech: truncated maximum_name_length")
	}
	name, ok := r.vec8()
	if !ok || len(name) == 0 {
		return info, errors.New("ech: bad public_name")
	}
	if _, ok := r.vec16(); !ok { // extensions
		return info, errors.New("ech: truncated extensions")
	}
	if len(r.b) != 0 {
		return info, errors.New("ech: trailing bytes in config")
	}
	info.ConfigID, info.KEMID, info.PublicName = id, kem, string(name)
	return info, nil
}

// ECHConfigPEM wraps an ECHConfigList the way sing-box's `ech.config`
// takes it (PEM type "ECH CONFIGS").
func ECHConfigPEM(configList []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configList}))
}

// ReadECHPosture fills the HTTPS-record half of a posture. The zone
// setting is the caller's to fill (it needs the Cloudflare token; this
// does not). A fetch failure is recorded in Error, not returned: the
// posture line says "could not read", it does not fail the verb.
func ReadECHPosture(ctx context.Context, f ECHFetcher, hostname string, nowUnix int64) ECHPosture {
	var p ECHPosture
	if f == nil {
		p.Error = "not read"
		return p
	}
	list, resolver, err := f.FetchECH(ctx, hostname)
	p.Resolver = resolver
	p.FetchedAtUnix = nowUnix
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if len(list) == 0 {
		return p
	}
	infos, err := ParseECHConfigList(list)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Published = true
	p.ConfigListB64 = base64.StdEncoding.EncodeToString(list)
	p.PublicName = infos[0].PublicName
	return p
}

// ---- DNS wire format (only what an HTTPS-record query needs) ----

const (
	dnsTypeHTTPS = 65
	dnsTypeCNAME = 5
	dnsClassIN   = 1
	svcParamECH  = 5
)

// buildHTTPSQuery returns a DNS query for name/HTTPS with a random id
// and RD set. For DoH (RFC 8484) the id may be zero; a random one costs
// nothing and keeps answers matched to questions.
func buildHTTPSQuery(name string) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q := []byte{idb[0], idb[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	qn, err := encodeDNSName(name)
	if err != nil {
		return nil, 0, err
	}
	q = append(q, qn...)
	q = append(q, 0, dnsTypeHTTPS, 0, dnsClassIN)
	return q, id, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("dns: bad name %q", name)
	}
	var out []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, fmt.Errorf("dns: bad label in %q", name)
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0), nil
}

// echFromDNSAnswer finds the ech SvcParam in the HTTPS answers of a DNS
// response to the query with id. No HTTPS record, or one without ech,
// is (nil, nil). A CNAME chain is followed only as far as the answer
// section already carries it.
func echFromDNSAnswer(msg []byte, id uint16) ([]byte, error) {
	if len(msg) < 12 {
		return nil, errors.New("dns: short message")
	}
	if binary.BigEndian.Uint16(msg) != id {
		return nil, errors.New("dns: answer id does not match the query")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 {
		return nil, errors.New("dns: not a response")
	}
	switch rcode := flags & 0x000f; rcode {
	case 0:
	case 3:
		return nil, errors.New("dns: name does not exist")
	default:
		return nil, fmt.Errorf("dns: rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		if off, err = skipDNSName(msg, off); err != nil {
			return nil, err
		}
		off += 4
		if off > len(msg) {
			return nil, errors.New("dns: truncated question")
		}
	}
	for i := 0; i < an; i++ {
		var err error
		if off, err = skipDNSName(msg, off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("dns: truncated answer")
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("dns: truncated rdata")
		}
		rdata := msg[off : off+rdlen]
		off += rdlen
		if typ != dnsTypeHTTPS {
			continue
		}
		ech, err := echFromHTTPSRData(rdata)
		if err != nil {
			return nil, err
		}
		if ech != nil {
			return ech, nil
		}
	}
	return nil, nil
}

// skipDNSName steps over a (possibly compressed) name.
func skipDNSName(msg []byte, off int) (int, error) {
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return 0, errors.New("dns: truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, errors.New("dns: truncated pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, errors.New("dns: bad label type")
		default:
			off += 1 + l
		}
	}
	return 0, errors.New("dns: name too long")
}

// echFromHTTPSRData parses SVCB/HTTPS rdata (RFC 9460): priority,
// uncompressed target name, then key/length/value params in key order.
// AliasMode (priority 0) carries no params.
func echFromHTTPSRData(rd []byte) ([]byte, error) {
	if len(rd) < 3 {
		return nil, errors.New("svcb: short rdata")
	}
	prio := binary.BigEndian.Uint16(rd)
	off := 2
	for {
		if off >= len(rd) {
			return nil, errors.New("svcb: truncated target")
		}
		l := int(rd[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 {
			return nil, errors.New("svcb: compressed target name")
		}
		off += l
	}
	if prio == 0 {
		return nil, nil
	}
	var last int = -1
	var ech []byte
	for off < len(rd) {
		if off+4 > len(rd) {
			return nil, errors.New("svcb: truncated param")
		}
		key := int(binary.BigEndian.Uint16(rd[off:]))
		vlen := int(binary.BigEndian.Uint16(rd[off+2:]))
		off += 4
		if key <= last {
			return nil, errors.New("svcb: params out of order")
		}
		last = key
		if off+vlen > len(rd) {
			return nil, errors.New("svcb: truncated param value")
		}
		if key == svcParamECH {
			ech = append([]byte(nil), rd[off:off+vlen]...)
		}
		off += vlen
	}
	// The whole record is checked before its ech value is used.
	return ech, nil
}

type byteReader struct{ b []byte }

func (r *byteReader) u8() (uint8, bool) {
	if len(r.b) < 1 {
		return 0, false
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, true
}

func (r *byteReader) u16() (uint16, bool) {
	if len(r.b) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v, true
}

func (r *byteReader) vec8() ([]byte, bool) {
	n, ok := r.u8()
	if !ok || len(r.b) < int(n) {
		return nil, false
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, true
}

func (r *byteReader) vec16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok || len(r.b) < int(n) {
		return nil, false
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, true
}
