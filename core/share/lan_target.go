package share

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotPrivateAddr is returned when a receiver is asked to dial anything
// that is not a private/link-local IP literal.
//
// This is a second, independent gate beside the SPKI pin. The pin proves
// "I am talking to the sender who published this hash"; this gate proves
// "and the connection never leaves the local network". They fail
// independently on purpose: a hostile mDNS TXT record or a doctored QR
// can name any address it likes, and without this check a receiver could
// be steered into opening a TLS connection to an attacker-chosen host on
// the public internet — which is a beacon that says "this device is
// running Daal and is trying to receive a route" to whoever is watching
// that address, whether or not the pin later rejects the certificate.
var ErrNotPrivateAddr = errors.New("share: refusing to dial a non-private address")

// ErrNotIPLiteral is returned when a target names a hostname rather than
// an IP literal. Resolving it would emit a DNS query, which violates the
// "no DNS lookup of any kind happens during the pull" privacy invariant
// in specs/lan-share-v1.md and would leak the fact of a share attempt to
// the network's resolver.
var ErrNotIPLiteral = errors.New("share: LAN target host must be an IP literal, not a name")

// Target is a fully-validated receiver-side pull destination. Every field
// has already been checked; PullTarget does not re-derive any of them.
type Target struct {
	Host      string // private IP literal, no brackets
	Port      int
	SPKI      string // base64url(sha256(SPKI)); never empty in a valid Target
	SessionID string // may be empty when the caller supplies it separately
}

// ParseShareTarget accepts the two receiver-side entry points described in
// specs/lan-share-v1.md and returns a validated Target, or an error.
//
//	daalshare://lan?u=<urlencoded https url>&p=<spki b64url>&s=<session id>
//	https://<private-ip>:<port>/bundle.sbp#spki=<spki b64url>
//
// Everything in the input is attacker-controlled — it arrives off a QR
// code held up by someone, or off a TXT record broadcast by anyone on the
// Wi-Fi — so nothing here is trusted: the scheme, the host form, the
// address range and the pin length are all checked before a Target
// exists, and a Target without a pin cannot be constructed.
func ParseShareTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, errors.New("share: empty target")
	}
	if strings.HasPrefix(raw, "daalshare://") {
		return parseDaalShareURI(raw)
	}
	return parseHTTPSTarget(raw, "", "")
}

func parseDaalShareURI(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("share: bad daalshare URI: %w", err)
	}
	if !strings.EqualFold(u.Host, "lan") {
		return Target{}, fmt.Errorf("share: unsupported daalshare action %q", u.Host)
	}
	q := u.Query()
	inner := q.Get("u")
	if inner == "" {
		return Target{}, errors.New("share: daalshare URI has no u= target")
	}
	return parseHTTPSTarget(inner, q.Get("p"), q.Get("s"))
}

// parseHTTPSTarget validates one https URL. pinOverride/sessionOverride
// come from the daalshare wrapper; when they are empty the pin is taken
// from the URL fragment instead (the mDNS-filtered fallback shape).
func parseHTTPSTarget(rawURL, pinOverride, sessionOverride string) (Target, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return Target{}, errors.New("share: only https targets accepted")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return Target{}, fmt.Errorf("share: bad target URL: %w", err)
	}
	if u.User != nil {
		return Target{}, errors.New("share: target URL must not carry userinfo")
	}
	host := u.Hostname() // strips IPv6 brackets
	portStr := u.Port()
	if portStr == "" {
		return Target{}, errors.New("share: target URL must name an explicit port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("share: bad target port %q", portStr)
	}
	if err := requirePrivateHost(host); err != nil {
		return Target{}, err
	}
	pin := pinOverride
	if pin == "" {
		pin = pinFromFragment(u.Fragment)
	}
	// Reject an unusable pin HERE, at parse time, so a Target can never
	// exist without one.
	if _, err := decodePin(pin); err != nil {
		return Target{}, err
	}
	return Target{Host: host, Port: port, SPKI: pin, SessionID: sessionOverride}, nil
}

// pinFromFragment accepts either `#spki=<v>` or a bare `#<v>`.
func pinFromFragment(frag string) string {
	frag = strings.TrimSpace(frag)
	if frag == "" {
		return ""
	}
	if v, err := url.ParseQuery(frag); err == nil {
		if s := v.Get("spki"); s != "" {
			return s
		}
	}
	if strings.ContainsAny(frag, "=&") {
		return ""
	}
	return frag
}

// requirePrivateHost enforces both the IP-literal rule and the
// private-range rule for a receiver-side dial.
func requirePrivateHost(host string) error {
	if host == "" {
		return ErrNotIPLiteral
	}
	// Reject a zone-id outright: `fe80::1%eth0` is unparseable by
	// net.ParseIP and the sender never publishes one (DetectPrivateAddrs
	// skips IPv6 link-local for exactly this reason).
	if strings.Contains(host, "%") {
		return ErrNotIPLiteral
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ErrNotIPLiteral
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return ErrNotPrivateAddr
	}
	if !isDialableLANHost(ip) {
		return ErrNotPrivateAddr
	}
	return nil
}

// isDialableLANHost is the RECEIVER-side gate: may this process open a
// TCP connection to this address on the strength of a scanned QR?
//
// It is deliberately stricter than isPrivateIP, which answers a
// different question — "may the SENDER bind here?" — for which the
// device's own CGNAT or loopback address is a perfectly good answer.
//
// The difference that matters is 100.64.0.0/10. On mobile data the
// handset's own address usually sits in CGNAT space, and that range
// spans an ENTIRE CARRIER'S subscriber pool: dialling it is an off-LAN
// connection to an attacker-chosen host, which is exactly what the
// "never leaves the local network" guarantee is supposed to exclude.
// The SPKI pin does not save us here, because the TCP connect and the
// TLS ClientHello are already on the wire before the pin can reject —
// the beacon has fired. So CGNAT is refused before the dial, not after.
//
// Loopback stays permitted: 127.0.0.0/8 cannot leave the machine, so it
// satisfies the guarantee by definition, and the in-process round-trip
// test binds there when the host has no other private NIC.
func isDialableLANHost(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		switch v4[0] {
		case 10:
			return true
		case 192:
			return v4[1] == 168
		case 172:
			return v4[1] >= 16 && v4[1] <= 31
		case 169: // link-local
			return v4[1] == 254
		case 127: // loopback — never leaves the host
			return true
		}
		return false
	}
	// IPv6 ULA fc00::/7 and link-local fe80::/10.
	if ip[0]&0xfe == 0xfc {
		return true
	}
	if ip[0] == 0xfe && ip[1]&0xc0 == 0x80 {
		return true
	}
	return ip.IsLoopback()
}

// ShareURI renders the QR-fallback URI for one bound LAN URL. The sender
// UI encodes this into a QR; the receiver hands it straight to
// ParseShareTarget.
func ShareURI(lanURL, spki, sessionID string) string {
	q := url.Values{}
	q.Set("u", lanURL)
	q.Set("p", spki)
	q.Set("s", sessionID)
	return "daalshare://lan?" + q.Encode()
}
