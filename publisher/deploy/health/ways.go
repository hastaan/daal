package health

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"
)

// Way states relay-health reports per way in (contract D3).
const (
	WayAnswers         = "answers"
	WayNoAnswer        = "no_answer"
	WayWrongServer     = "wrong_server"
	WayNotTestableHere = "not_testable_here"
)

// Way is one way in to probe: a family on a port.
type Way struct {
	Family string
	Port   int
	UDP    bool
}

// WayResult is what one probe found. Error is raw text (Details only).
type WayResult struct {
	Family string `json:"family"`
	Port   int    `json:"port"`
	UDP    bool   `json:"udp"`
	State  string `json:"state"`
	Error  string `json:"error"`
}

// WayProbeOpts are the relay-specific expectations of a probe.
type WayProbeOpts struct {
	// CoverSNI is the server name a REALITY client presents.
	CoverSNI string
	// CertPin is the base64 SHA-256 of the data-plane certificate's
	// SubjectPublicKeyInfo. Empty means "nothing to compare against":
	// a completed handshake then counts as answering.
	CertPin string
	Timeout time.Duration
}

// pinnedTLSFamilies serve the relay's own self-signed certificate, so a
// handshake can tell this relay from anything else on the address.
var pinnedTLSFamilies = map[string]bool{"naive": true, "websocket-tls": true, "anytls": true}

// ProbeWays checks, from THIS machine, whether each way in answers at
// ip. It proves only that: the publisher is outside the censored
// network, and whether a way is blocked inside it cannot be seen from
// here by anybody. UDP families are not tested (a UDP probe without the
// family's own handshake proves nothing).
//
//   - vless-reality: a TLS handshake presenting the cover host. REALITY
//     completes it (with the cover host's certificate) for a client it
//     does not recognise, so a finished handshake means the inbound is
//     up. The certificate is not checked — it is not the relay's.
//   - naive, websocket-tls, anytls: a TLS handshake whose leaf
//     certificate must carry the relay's pinned key; any other key is
//     "wrong_server" (the address answers, but not as this relay).
//   - shadowsocks, and any other TCP family: a TCP connect.
func ProbeWays(ctx context.Context, ip net.IP, ways []Way, opts WayProbeOpts) []WayResult {
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	out := make([]WayResult, 0, len(ways))
	for _, w := range ways {
		r := WayResult{Family: w.Family, Port: w.Port, UDP: w.UDP}
		switch {
		case w.UDP:
			r.State = WayNotTestableHere
		case ip == nil || ip.IsUnspecified():
			r.State, r.Error = WayNoAnswer, "the relay has no address on record"
		default:
			r.State, r.Error = probeTCP(ctx, ip, w, opts)
		}
		out = append(out, r)
	}
	return out
}

func probeTCP(ctx context.Context, ip net.IP, w Way, opts WayProbeOpts) (string, string) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(w.Port))
	dctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return WayNoAnswer, err.Error()
	}
	defer conn.Close()
	if w.Family != "vless-reality" && !pinnedTLSFamilies[w.Family] {
		return WayAnswers, ""
	}
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // identity is checked by pin below, or not at all (REALITY serves the cover host's certificate)
	if w.Family == "vless-reality" {
		cfg.ServerName = opts.CoverSNI
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(dctx); err != nil {
		return WayNoAnswer, err.Error()
	}
	if w.Family == "vless-reality" || strings.TrimSpace(opts.CertPin) == "" {
		return WayAnswers, ""
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return WayWrongServer, "no certificate presented"
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	if pinMatches(opts.CertPin, sum[:]) {
		return WayAnswers, ""
	}
	return WayWrongServer, "certificate key " + base64.StdEncoding.EncodeToString(sum[:]) + " is not the relay's " + opts.CertPin
}

// pinMatches accepts the pin in base64 (the record's and the identity's
// form) or hex (older creds files).
func pinMatches(pin string, sum []byte) bool {
	pin = strings.TrimSpace(pin)
	if pin == base64.StdEncoding.EncodeToString(sum) || pin == base64.RawStdEncoding.EncodeToString(sum) {
		return true
	}
	return strings.EqualFold(pin, hex.EncodeToString(sum))
}
