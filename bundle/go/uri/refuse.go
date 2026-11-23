package uri

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Refusals. A link this build cannot carry faithfully is REFUSED with
// one of these, never imported as something weaker: an xhttp link that
// silently becomes plain-TCP VLESS, or a REALITY link that fails the
// engine's strict option parse, is a route the person selects and
// loses (docs/transport-family-inventory.md, "worse than no family").
//
// Each sentinel's text after "uri: " is a stable token the host maps
// to its own copy (RefusalCode). Wrapped errors add only the scheme
// and the offending parameter NAME or a protocol keyword; never a
// credential, a host or the link itself.
var (
	// The link's transport (type=…) or its TLS layer is one the
	// shipped engine (sing-box 1.13.12) has no implementation of:
	// xhttp, splithttp, h2/http, quic, kcp, trojan+grpc, trojan+reality,
	// a legacy security mode, an unknown flow.
	ErrTransportUnsupported = errors.New("uri: transport_unsupported")

	// headerType=http: Xray's HTTP/1.1 header camouflage on raw TCP.
	// sing-box has no equivalent, so dialling without it sends bytes
	// the server does not expect.
	ErrHeaderTypeUnsupported = errors.New("uri: header_type_unsupported")

	// flow=xtls-rprx-vision-udp443 or any flow other than
	// xtls-rprx-vision: sing-vmess's VLESS client accepts exactly ""
	// and "xtls-rprx-vision" and fails at dial on anything else.
	ErrFlowUnsupported = errors.New("uri: flow_unsupported")

	// VLESS encryption other than "none" (Xray's post-quantum VLESS
	// encryption). sing-box's VLESS outbound has no such field, and
	// dropping it would talk to a server that expects it.
	ErrEncryptionUnsupported = errors.New("uri: encryption_unsupported")

	// security=none (or absent) on VLESS or Trojan, VMess with
	// security none/zero and no TLS, Shadowsocks method none/plain:
	// every destination address, and for the unencrypted ciphers the
	// payload, crosses the DPI box in clear text.
	ErrPlaintext = errors.New("uri: plaintext_refused")

	// The link turns certificate checking off (hy2 insecure=1). Whoever
	// sits on the path can then answer as the server and read the
	// password and everything sent through it.
	ErrInsecure = errors.New("uri: insecure_refused")

	// The link is missing something the engine needs or carries a
	// value it cannot use (REALITY key, port list).
	ErrMalformed = errors.New("uri: link_malformed")

	// The profile may be dialled only when the person picks it
	// (Profile.ManualOnly), and the host has nowhere to keep that, so it
	// is refused rather than stored as an ordinary route that an
	// automatic connect would race. core/abi URIImport keeps the flag
	// since wave 2 and no longer raises it; the token stays stable for
	// a host that cannot.
	ErrManualOnly = errors.New("uri: manual_only")
)

// RefusalCode returns the stable token for an importer refusal (for
// example "transport_unsupported"), or "" when err is not one.
func RefusalCode(err error) string {
	for _, s := range []error{ErrTransportUnsupported, ErrHeaderTypeUnsupported, ErrFlowUnsupported,
		ErrEncryptionUnsupported, ErrPlaintext, ErrInsecure, ErrMalformed, ErrManualOnly} {
		if errors.Is(err, s) {
			return strings.TrimPrefix(s.Error(), "uri: ")
		}
	}
	return ""
}

// parseLink is url.Parse without the link in the error. *url.Error
// quotes the whole input, and the input's userinfo is the route's
// credential (VLESS uuid, Trojan/hy2 password); an import error is
// shown and may be logged.
func parseLink(scheme, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s: bad URL: %v: %w", scheme, redactParseErr(err), ErrMalformed)
	}
	return u, nil
}

// redactParseErr keeps the class of a url.Parse failure and drops the
// quoted value ("invalid port \":x\" after host" names a port, which
// is harmless, but "invalid userinfo" variants can quote the secret).
func redactParseErr(err error) string {
	s := err.Error()
	if i := strings.IndexAny(s, "\"'"); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// splitALPN turns "h2,http/1.1" into ["h2","http/1.1"]. The link
// format comma-joins the list; putting the joined string in as one
// element offers a protocol called "h2,http/1.1", which no server has.
func splitALPN(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// utlsFingerprint maps a link's fp= to a name sing-box 1.13.12's
// uTLSClientHelloID accepts. ok=false means "no uTLS" (fp absent or
// "none"); an unknown name becomes "chrome", the default sing-box
// itself uses for an empty name, rather than an "unknown uTLS
// fingerprint" failure at connect.
func utlsFingerprint(fp string) (name string, ok bool) {
	switch fp = strings.ToLower(strings.TrimSpace(fp)); fp {
	case "", "none":
		return "", false
	case "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized":
		return fp, true
	case "randomizedalpn", "randomizednoalpn":
		return "randomized", true
	}
	return "chrome", true
}

// v2rayTransport builds the sing-box `transport` block for a vless://
// or trojan:// link's type= parameter. nil, nil means raw TCP (no
// transport block). allowGRPC is false for trojan, whose gRPC links
// are refused (sing-box builds the gRPC-lite client only; see
// docs/exotic-transports-plan.md, review "Corrected Wave 1").
func v2rayTransport(scheme string, q url.Values, allowGRPC bool) (map[string]any, error) {
	typ := strings.ToLower(strings.TrimSpace(q.Get("type")))
	switch typ {
	case "", "tcp", "raw": // Xray renamed tcp to raw in 2024; same wire
		switch ht := strings.ToLower(q.Get("headerType")); ht {
		case "", "none":
			return nil, nil
		default:
			return nil, fmt.Errorf("%s: headerType=%s: %w", scheme, safeToken(ht), ErrHeaderTypeUnsupported)
		}
	case "ws", "websocket":
		path, ed := splitEarlyData(q.Get("path"))
		if ed == 0 {
			ed, _ = strconv.Atoi(q.Get("ed"))
		}
		t := map[string]any{"type": "ws"}
		if path != "" {
			t["path"] = path
		}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]any{"Host": h}
		}
		// Xray's early data rides in Sec-WebSocket-Protocol; this is
		// the pair sing-box documents as Xray-compatible.
		if ed > 0 {
			t["max_early_data"] = ed
			t["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		return t, nil
	case "httpupgrade":
		// sing-box's httpupgrade client has no early data; ?ed= is a
		// client-side option the server does not require, so it is
		// stripped from the path rather than sent as part of it.
		path, _ := splitEarlyData(q.Get("path"))
		t := map[string]any{"type": "httpupgrade"}
		if path != "" {
			t["path"] = path
		}
		if h := q.Get("host"); h != "" {
			t["host"] = h
		}
		return t, nil
	case "grpc":
		if !allowGRPC {
			return nil, fmt.Errorf("%s: type=grpc: %w", scheme, ErrTransportUnsupported)
		}
		t := map[string]any{"type": "grpc"}
		if v := q.Get("serviceName"); v != "" {
			t["service_name"] = v
		}
		return t, nil
	}
	// xhttp, splithttp, h2/http, quic, kcp/mkcp and anything newer:
	// not in sing-box 1.13.12 (option/v2ray_transport.go registers
	// http, ws, quic, grpc, httpupgrade, and its http and quic do not
	// interoperate with Xray's). Never downgrade to plain TCP.
	if typ == "" {
		typ = "unknown"
	}
	return nil, fmt.Errorf("%s: type=%s: %w", scheme, safeToken(typ), ErrTransportUnsupported)
}

// splitEarlyData strips Xray's "?ed=2048" from a ws/httpupgrade path
// and returns it separately. Other query parameters in the path stay.
func splitEarlyData(path string) (string, int) {
	i := strings.Index(path, "?")
	if i < 0 {
		return path, 0
	}
	base, rawQ := path[:i], path[i+1:]
	vals, err := url.ParseQuery(rawQ)
	if err != nil || !vals.Has("ed") {
		return path, 0
	}
	ed, _ := strconv.Atoi(vals.Get("ed"))
	vals.Del("ed")
	if len(vals) > 0 {
		base += "?" + vals.Encode()
	}
	return base, ed
}

// safeToken keeps a protocol keyword short and printable for an error
// message; anything else becomes "unknown".
func safeToken(s string) string {
	if len(s) > 24 {
		return "unknown"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "unknown"
		}
	}
	return s
}

// checkVisionFlow refuses flow=xtls-rprx-vision over a transport
// block: Vision splices the inner TLS straight onto a raw TCP (TLS or
// REALITY) connection, and sing-box fails at dial when a ws, grpc or
// httpupgrade transport sits in between.
func checkVisionFlow(scheme string, out map[string]any) error {
	if _, hasFlow := out["flow"]; !hasFlow {
		return nil
	}
	if _, hasTransport := out["transport"]; hasTransport {
		return fmt.Errorf("%s: flow over a transport: %w", scheme, ErrFlowUnsupported)
	}
	return nil
}

// checkRealityShortID is the REALITY short id rule sing-box applies at
// connect: hex, at most 8 bytes ("" is allowed).
func checkRealityShortID(scheme, sid string) error {
	if b, err := hex.DecodeString(sid); err != nil || len(b) > 8 {
		return fmt.Errorf("%s: reality short id: %w", scheme, ErrMalformed)
	}
	return nil
}

// vmessSecurity validates a VMess cipher against the names
// sing-vmess's NewClient accepts and refuses the two that encrypt
// nothing ("none", and "zero", which also drops authentication) unless
// TLS wraps the connection. "" means auto, as in both link formats.
func vmessSecurity(scheme, scy string, tlsOn bool) (string, error) {
	switch scy = strings.ToLower(strings.TrimSpace(scy)); scy {
	case "":
		return "auto", nil
	case "auto", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb":
		return scy, nil
	case "none", "zero":
		if !tlsOn {
			return "", fmt.Errorf("%s: security=%s without tls: %w", scheme, scy, ErrPlaintext)
		}
		return scy, nil
	}
	return "", fmt.Errorf("%s: security=%s: %w", scheme, safeToken(scy), ErrEncryptionUnsupported)
}

// ssPlaintextMethod reports a Shadowsocks "cipher" that encrypts
// nothing. sing-box dials method "none" as a bare SOCKS-like stream.
func ssPlaintextMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "none", "plain", "dummy":
		return true
	}
	return false
}

// MinHopInterval is Hysteria's own floor for the port-hop interval.
// Shorter values make sing-quic rebind its UDP socket on a near-busy
// ticker, which on a phone is battery and CPU for nothing.
const MinHopInterval = 5 * time.Second

// linkInsecure reports whether any of a link's certificate-check
// switches (insecure=1, allow_insecure=true, Clash skip-cert-verify:
// true) is on.
func linkInsecure(vals ...string) bool {
	for _, v := range vals {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes":
			return true
		}
	}
	return false
}
