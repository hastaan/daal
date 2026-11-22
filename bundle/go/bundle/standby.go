package bundle

// standby.go — the `_standby` member of a route's signed
// family_specific_config (specs/relaypack-v1.md "`_standby` key";
// docs/optional-addons-plan.md §1).
//
// A standby is a second address of the SAME relay: same ports, same
// keys, attached from day one, not advertised. The pack commits to it in
// one of two ways:
//
//	sealed (default)  {"v":1,"mode":"sealed","commit":"<base64 32 bytes>"}
//	open              {"v":1,"mode":"open","server":"203.0.113.20"}
//
// commit = SHA-256("daal/standby-v1" ‖ salt ‖ ipv4). The STANDBY KEY is
// salt ‖ ipv4, 16 bytes; it needs no signature of its own because the
// signed pack already committed to it. A forged or mistyped key matches
// no commitment and steers nobody anywhere.
//
// WHY IT IS A SIBLING OF `_endpoint` AND NOT A MEMBER OF IT. `_endpoint`
// is decoded strictly (endpoint.go ParseEndpoint): an unknown member
// there refuses the whole pack on every build that predates it, the
// freshness merge included. `_standby` beside it is ignored by every
// earlier build (no decoder of the top-level family_specific_config is
// strict, and it is not in EngineFamilyConfigKeys), so an old phone keeps
// using the rest of the pack. Proved against a frozen copy of the
// earlier rules: bundle/go/importer/compat_old_test.go.
//
// A malformed `_standby` is treated as ABSENT, never as a refusal: it can
// only widen what a route may dial, so ignoring it is the closed reading,
// and a future version of this member must not cost a phone the pack.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// StandbyKey is the reserved family_specific_config member.
const StandbyKey = "_standby"

// StandbyVersion is the only `_standby` version this build reads.
const StandbyVersion = 1

// Standby modes.
const (
	StandbyModeSealed = "sealed"
	StandbyModeOpen   = "open"
)

const (
	standbyDomain = "daal/standby-v1"
	// StandbySaltLen is the length of the random salt in a key.
	StandbySaltLen = 12
	// StandbyKeyLen is the length of a standby key: salt ‖ ipv4.
	StandbyKeyLen = StandbySaltLen + 4
	// StandbyKeyTextLen is the number of base32 symbols in a key's
	// text form (128 bits + 2 zero bits).
	StandbyKeyTextLen = 26
)

var (
	// ErrNoStandby: the config carries no `_standby`.
	ErrNoStandby = errors.New("bundle: no _standby in family_specific_config")
	// ErrStandbyMalformed: `_standby` is present and unusable. Callers
	// treat it as absent (see the top of this file).
	ErrStandbyMalformed = errors.New("bundle: malformed _standby")
	// ErrStandbyNotForFamily: `_standby` on a route whose family takes
	// none (shadowsocks), or on a route with no direct `_endpoint`.
	// Ignored.
	ErrStandbyNotForFamily = errors.New("bundle: _standby is ignored on this route")
	// ErrStandbyKeyMalformed: a standby key that does not decode.
	ErrStandbyKeyMalformed = errors.New("bundle: malformed standby key")
)

// Standby is one parsed `_standby` member. Exactly one of Commit
// (sealed) and Server (open) is set.
type Standby struct {
	V      int    `json:"v"`
	Mode   string `json:"mode"`
	Commit string `json:"commit,omitempty"`
	Server string `json:"server,omitempty"`
}

// StandbyKeyBytes is a standby key: 12 bytes of salt, then the IPv4
// address in network order.
type StandbyKeyBytes [StandbyKeyLen]byte

// StandbyStoreKey is the secrets_kv key under which a device keeps a
// route's `_standby` (its JSON, exactly as signed), beside the route's
// endpoint commitment. Written and removed together with the
// commitment; a newer commitment without `_standby` removes it.
func StandbyStoreKey(routeID string) string { return "standby:" + routeID }

// StandbyKeyStoreKey is the secrets_kv key under which a device keeps a
// standby key it accepted for a route: the 16 raw key bytes.
func StandbyKeyStoreKey(routeID string) string { return "standby-key:" + routeID }

// ParseStandby reads `_standby` out of a route's family_specific_config.
// ErrNoStandby when absent, ErrStandbyMalformed when unusable.
func ParseStandby(familySpecificConfig json.RawMessage) (*Standby, error) {
	if len(bytes.TrimSpace(familySpecificConfig)) == 0 {
		return nil, ErrNoStandby
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStandbyMalformed, err)
	}
	raw, ok := probe[StandbyKey]
	if !ok {
		return nil, ErrNoStandby
	}
	return ParseStandbyJSON(raw)
}

// ParseStandbyJSON parses one `_standby` object (as signed, or as a
// device stored it under StandbyStoreKey). The member set is exact: a
// sealed standby has exactly v, mode, commit; an open one exactly v,
// mode, server.
func ParseStandbyJSON(raw []byte) (*Standby, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: not an object", ErrStandbyMalformed)
	}
	bad := func(format string, args ...any) (*Standby, error) {
		return nil, fmt.Errorf("%w: %s", ErrStandbyMalformed, fmt.Sprintf(format, args...))
	}
	var s Standby
	if err := json.Unmarshal(members["v"], &s.V); err != nil || s.V != StandbyVersion {
		return bad("version")
	}
	if err := json.Unmarshal(members["mode"], &s.Mode); err != nil {
		return bad("mode")
	}
	var want []string
	switch s.Mode {
	case StandbyModeSealed:
		want = []string{"v", "mode", "commit"}
		if err := json.Unmarshal(members["commit"], &s.Commit); err != nil {
			return bad("commit")
		}
		c, err := base64.StdEncoding.Strict().DecodeString(s.Commit)
		if err != nil || len(c) != sha256.Size || base64.StdEncoding.EncodeToString(c) != s.Commit {
			return bad("commit is not standard base64 of 32 bytes")
		}
	case StandbyModeOpen:
		want = []string{"v", "mode", "server"}
		if err := json.Unmarshal(members["server"], &s.Server); err != nil {
			return bad("server")
		}
		if !StandbyAddressOK(s.Server) {
			return bad("server is not a public canonical IPv4 address")
		}
	default:
		return bad("unknown mode")
	}
	if len(members) != len(want) {
		return bad("unexpected members")
	}
	for _, k := range want {
		if _, ok := members[k]; !ok {
			return bad("missing %s", k)
		}
	}
	return &s, nil
}

// StandbyForRoute is the standby a route of the given family, holding
// the given direct endpoint commitment, may use: ParseStandby plus the
// route rules. Every error means "this route has no standby".
//
//   - never on shadowsocks (ErrStandbyNotForFamily): it has no server
//     authentication independent of the shared key, so a stale standby
//     could hand a stranger the traffic;
//   - never without a direct `_endpoint` (a CDN-fronted route has no
//     address to stand in for);
//   - an open standby equal to the endpoint's own server is malformed.
func StandbyForRoute(family string, familySpecificConfig json.RawMessage, ep *Endpoint) (*Standby, error) {
	sb, err := ParseStandby(familySpecificConfig)
	if err != nil {
		return nil, err
	}
	if family == string(TransportShadowsocks) || ep == nil || !EndpointFamilySupported(family) {
		return nil, ErrStandbyNotForFamily
	}
	if sb.Mode == StandbyModeOpen && sameHost(sb.Server, ep.Server) {
		return nil, fmt.Errorf("%w: open standby is the endpoint's own server", ErrStandbyMalformed)
	}
	return sb, nil
}

// StandbyAddressOK: a canonical dotted-quad IPv4 address (no leading
// zeros) that is not unspecified, loopback, private, link-local,
// multicast or broadcast.
func StandbyAddressOK(s string) bool {
	if strings.Contains(s, ":") {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil || ip4.String() != s {
		return false
	}
	switch {
	case ip4.IsUnspecified(), ip4.IsLoopback(), ip4.IsPrivate(),
		ip4.IsLinkLocalUnicast(), ip4.IsLinkLocalMulticast(), ip4.IsMulticast(),
		ip4.Equal(net.IPv4bcast):
		return false
	}
	return true
}

// StandbyCommit is base64(SHA-256("daal/standby-v1" ‖ salt ‖ ipv4)) for
// a key.
func StandbyCommit(k StandbyKeyBytes) string {
	h := sha256.New()
	h.Write([]byte(standbyDomain))
	h.Write(k[:])
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// NewStandbyKey draws a fresh salt from r and returns the key for ipv4.
// The publisher calls it once per standby address.
func NewStandbyKey(ipv4 string, r io.Reader) (StandbyKeyBytes, error) {
	var k StandbyKeyBytes
	if !StandbyAddressOK(ipv4) {
		return k, fmt.Errorf("%w: %q is not a public canonical IPv4 address", ErrStandbyKeyMalformed, ipv4)
	}
	if _, err := io.ReadFull(r, k[:StandbySaltLen]); err != nil {
		return k, err
	}
	copy(k[StandbySaltLen:], net.ParseIP(ipv4).To4())
	return k, nil
}

// SealedStandby is the `_standby` a publisher signs for a key.
func SealedStandby(k StandbyKeyBytes) Standby {
	return Standby{V: StandbyVersion, Mode: StandbyModeSealed, Commit: StandbyCommit(k)}
}

// OpenStandby is the `_standby` a publisher signs for an address shown
// openly.
func OpenStandby(ipv4 string) Standby {
	return Standby{V: StandbyVersion, Mode: StandbyModeOpen, Server: ipv4}
}

// Address is the IPv4 address inside a key.
func (k StandbyKeyBytes) Address() string {
	return net.IPv4(k[12], k[13], k[14], k[15]).String()
}

// crockford is Crockford's base32 alphabet.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Text is the form a person reads aloud or types: the 128 bits, most
// significant first, then two zero bits, as 26 symbols of Crockford's
// base32 in groups of 6-5-5-5-5 separated by one space.
func (k StandbyKeyBytes) Text() string {
	var sym [StandbyKeyTextLen]byte
	for s := 0; s < StandbyKeyTextLen; s++ {
		v := 0
		for b := 0; b < 5; b++ {
			bit := s*5 + b
			v <<= 1
			if bit < 8*StandbyKeyLen && k[bit/8]&(0x80>>(bit%8)) != 0 {
				v |= 1
			}
		}
		sym[s] = crockford[v]
	}
	s := string(sym[:])
	return s[0:6] + " " + s[6:11] + " " + s[11:16] + " " + s[16:21] + " " + s[21:26]
}

// ParseStandbyKeyText reads a key's text form. Case is ignored, spaces
// and '-' are ignored, O reads as 0 and I and L as 1. Any other symbol,
// a count other than 26, or non-zero trailing bits is malformed. There
// is no checksum: the commitment is the check.
func ParseStandbyKeyText(s string) (StandbyKeyBytes, error) {
	var k StandbyKeyBytes
	vals := make([]int, 0, StandbyKeyTextLen)
	for _, r := range s {
		switch {
		case r == ' ' || r == '-':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		switch r {
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		i := -1
		if r < 128 {
			i = strings.IndexByte(crockford, byte(r))
		}
		if i < 0 {
			return k, fmt.Errorf("%w: symbol %q", ErrStandbyKeyMalformed, r)
		}
		vals = append(vals, i)
		if len(vals) > StandbyKeyTextLen {
			return k, fmt.Errorf("%w: too long", ErrStandbyKeyMalformed)
		}
	}
	if len(vals) != StandbyKeyTextLen {
		return k, fmt.Errorf("%w: %d symbols, want %d", ErrStandbyKeyMalformed, len(vals), StandbyKeyTextLen)
	}
	for s, v := range vals {
		for b := 0; b < 5; b++ {
			bit := s*5 + b
			on := v&(0x10>>b) != 0
			if bit >= 8*StandbyKeyLen {
				if on {
					return k, fmt.Errorf("%w: trailing bits", ErrStandbyKeyMalformed)
				}
				continue
			}
			if on {
				k[bit/8] |= 0x80 >> (bit % 8)
			}
		}
	}
	return k, nil
}

// StandbyKeyFromBytes reads the 16 raw bytes (the DNS form's AAAA
// record, or what a device stored under StandbyKeyStoreKey).
func StandbyKeyFromBytes(b []byte) (StandbyKeyBytes, error) {
	var k StandbyKeyBytes
	if len(b) != StandbyKeyLen {
		return k, fmt.Errorf("%w: %d bytes, want %d", ErrStandbyKeyMalformed, len(b), StandbyKeyLen)
	}
	copy(k[:], b)
	return k, nil
}

// AAAA is the key's DNS form: its 16 bytes as one IPv6 address.
func (k StandbyKeyBytes) AAAA() net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, k[:])
	return ip
}

// Matches reports whether a key opens this standby: only a sealed one,
// and only when SHA-256 of the key is the signed commitment.
func (s *Standby) Matches(k StandbyKeyBytes) bool {
	if s == nil || s.Mode != StandbyModeSealed {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(StandbyCommit(k)), []byte(s.Commit)) == 1
}

// DialAddress is the address a route may be dialled at instead of its
// committed server: the open standby's server, or the address inside
// a held key that matches the sealed commitment. false otherwise
// (sealed with no key or a key that does not match; a key whose
// address is not a public IPv4 address).
func (s *Standby) DialAddress(key *StandbyKeyBytes) (string, bool) {
	if s == nil {
		return "", false
	}
	switch s.Mode {
	case StandbyModeOpen:
		return s.Server, StandbyAddressOK(s.Server)
	case StandbyModeSealed:
		if key == nil || !s.Matches(*key) {
			return "", false
		}
		addr := key.Address()
		return addr, StandbyAddressOK(addr)
	}
	return "", false
}

// CheckOutboundStandby is CheckOutbound with the amended endpoint rule:
// the outbound's server may equal the committed server, OR the address
// sb.DialAddress(key) gives. Nothing else moves — port, TLS name, key
// pin, REALITY public key are checked exactly as before, against the
// same commitment with only the server swapped (for naive, the
// verification name is recomputed for the standby address, as it would
// be for a moved relay). sb nil, or shadowsocks: plain CheckOutbound.
func CheckOutboundStandby(family string, ep *Endpoint, sb *Standby, key *StandbyKeyBytes, profile []byte) error {
	err := CheckOutbound(family, ep, profile)
	if err == nil || sb == nil || ep == nil || family == string(TransportShadowsocks) {
		return err
	}
	addr, ok := sb.DialAddress(key)
	if !ok || sameHost(addr, ep.Server) {
		return err
	}
	alt := *ep
	alt.Server = addr
	if CheckOutbound(family, &alt, profile) == nil {
		return nil
	}
	return err
}
