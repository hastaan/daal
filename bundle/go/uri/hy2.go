package uri

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// defaultHopInterval is Hysteria's own default port-hop interval; it is
// written explicitly so the imported route says what it will do.
const defaultHopInterval = "30s"

// parseHy2 handles both hysteria2:// and hy2:// per apernet's URI scheme,
// including the port-hopping authority (host:443,20000-50000) and the
// v2rayN-style mport= parameter.
//
// A multi-port authority is not a valid URL port, so url.Parse fails on
// it ("invalid port") before any of this code sees it. The authority is
// therefore rewritten to its first port BEFORE parsing, and the full
// list goes to sing-box's server_ports as "start:end" entries — the
// only shape hysteria.ParsePorts (sing-quic) accepts; a bare "443" or
// "20000-50000" fails there at connect.
//
// server_ports is refused on SIGNED pack endpoints
// (bundle.CheckOutbound), because there it would let a profile dial a
// port nobody signed. A pasted link has no signed endpoint: the import
// wraps it in a non-RelayPack share bundle, and the importer runs
// CheckOutbound only for RelayPack routes (importer/endpoint_plan.go).
func parseHy2(raw string) (Profile, Provenance, error) {
	rewritten, ranges, err := hy2PortRanges(raw)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	u, err := parseLink("hy2", rewritten)
	if err != nil {
		return Profile{}, Provenance{}, err
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, Provenance{}, fmt.Errorf("hy2: missing auth: %w", ErrMalformed)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, Provenance{}, fmt.Errorf("hy2: invalid port: %w", ErrMalformed)
	}
	q := u.Query()
	if mport := q.Get("mport"); mport != "" {
		extra, err := parsePortSpec(mport)
		if err != nil {
			return Profile{}, Provenance{}, err
		}
		if len(ranges) == 0 {
			ranges = []string{fmt.Sprintf("%d:%d", port, port)}
		}
		ranges = append(ranges, extra...)
	}
	out := map[string]any{
		"type":        "hysteria2",
		"server":      u.Hostname(),
		"server_port": port,
		"password":    u.User.Username(),
	}
	if len(ranges) > 0 {
		out["server_ports"] = ranges
		hop, err := hopInterval(firstNonEmpty(q.Get("hop_interval"), q.Get("hopInterval")))
		if err != nil {
			return Profile{}, Provenance{}, err
		}
		out["hop_interval"] = hop
	}
	tls := map[string]any{"enabled": true}
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer")); sni != "" {
		tls["server_name"] = sni
	}
	// insecure=1 turns certificate checking off. It is refused, not
	// dropped: dropped, the route fails at every connect against the
	// self-signed server it names; kept, anyone on the path can be
	// that server. pinSHA256 is no way out either: Hysteria's pin is a
	// hash of the whole certificate, sing-box's
	// certificate_public_key_sha256 a hash of its key.
	if linkInsecure(q.Get("insecure")) {
		return Profile{}, Provenance{}, fmt.Errorf("hy2: insecure: %w", ErrInsecure)
	}
	if alpn := splitALPN(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	out["tls"] = tls
	if obfs := q.Get("obfs"); obfs != "" && obfs != "none" {
		o := map[string]any{"type": obfs}
		if pw := q.Get("obfs-password"); pw != "" {
			o["password"] = pw
		}
		out["obfs"] = o
	}
	return Profile{
		TransportFamily: "hysteria2",
		Outbound:        out,
		Tag:             u.Fragment,
	}, Provenance{Scheme: "hy2"}, nil
}

// hy2PortRanges finds the port part of the link's authority. A single
// port leaves the link untouched (ranges nil). A list or range is
// converted to sing-box "start:end" entries and the authority rewritten
// to its first port so url.Parse can read the rest.
func hy2PortRanges(raw string) (string, []string, error) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw, nil, nil
	}
	start := i + 3
	end := len(raw)
	if j := strings.IndexAny(raw[start:], "/?#"); j >= 0 {
		end = start + j
	}
	auth := raw[start:end]
	hostStart := strings.LastIndex(auth, "@") + 1
	hostport := auth[hostStart:]
	var host, spec string
	if strings.HasPrefix(hostport, "[") {
		k := strings.Index(hostport, "]")
		if k < 0 || !strings.HasPrefix(hostport[k+1:], ":") {
			return raw, nil, nil // let url.Parse report it
		}
		host, spec = hostport[:k+1], hostport[k+2:]
	} else {
		k := strings.Index(hostport, ":")
		if k < 0 {
			return raw, nil, nil
		}
		host, spec = hostport[:k], hostport[k+1:]
	}
	if !strings.ContainsAny(spec, ",-") {
		return raw, nil, nil
	}
	ranges, err := parsePortSpec(spec)
	if err != nil {
		return "", nil, err
	}
	first := ranges[0][:strings.Index(ranges[0], ":")]
	rewritten := raw[:start] + auth[:hostStart] + host + ":" + first + raw[end:]
	return rewritten, ranges, nil
}

// parsePortSpec turns "443,20000-50000" into ["443:443","20000:50000"].
func parsePortSpec(spec string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, errA := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var errB error
		if isRange {
			b, errB = strconv.Atoi(strings.TrimSpace(hi))
		}
		if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("hy2: port list: %w", ErrMalformed)
		}
		out = append(out, fmt.Sprintf("%d:%d", a, b))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hy2: port list: %w", ErrMalformed)
	}
	return out, nil
}

// hopInterval accepts a Go duration ("30s") or a bare number of
// seconds, and returns the duration string sing-box's badoption
// decoder reads. A value under MinHopInterval is raised to it: the
// interval is the client's own timer (the server listens on every port
// of the range whatever it is), so the route still works as linked.
func hopInterval(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultHopInterval, nil
	}
	var d time.Duration
	if n, err := strconv.Atoi(s); err == nil {
		d = time.Duration(n) * time.Second
	} else if d, err = time.ParseDuration(s); err != nil {
		return "", fmt.Errorf("hy2: hop interval: %w", ErrMalformed)
	}
	if d <= 0 {
		return "", fmt.Errorf("hy2: hop interval: %w", ErrMalformed)
	}
	if d < MinHopInterval {
		d = MinHopInterval
	}
	return d.String(), nil
}
