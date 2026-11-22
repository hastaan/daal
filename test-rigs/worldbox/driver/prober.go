package main

// The prober's eye (W1-E of docs/exotic-transports-plan.md): what a
// censor that looks at Daal from the outside can learn without any
// secret. Two halves, both read-only:
//
//   - helloJA4 reads the ClientHello the phone's engine sends (captured
//     by the flow tap at the censor's interface) and computes its JA4,
//     the fingerprint DPI vendors and CDNs key on (FoxIO's spec,
//     technical_details/JA4.md);
//   - `wb tlsface` is a stranger's full handshake to one relay port:
//     what any scanner gets back (certificate, ALPN, unsolicited bytes,
//     an HTTP answer) and whether any of it names Daal.
//
// Findings and the recommendation: docs/prober-audit.md.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// chromeJA4 is the reference Chrome-over-TCP JA4, from the examples
// table of FoxIO's JA4 README (github.com/FoxIO-LLC/ja4, README.md,
// read 2026-11-22). The source does not say which Chrome version or
// platform; Chrome on Android sharing it is UNVERIFIED (no labelled
// Android capture found). Chrome randomises extension order, which JA4
// sorts away, so one value covers a release; a resumption hello
// (pre_shared_key) hashes differently in section c.
const chromeJA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"

// helloInfo is a parsed ClientHello: what JA4 needs, and what the
// evidence shows.
type helloInfo struct {
	JA4      string   `json:"ja4"`
	JA4R     string   `json:"ja4_r"` // the raw (sorted, unhashed) form
	SNI      string   `json:"sni"`
	ALPN     []string `json:"alpn"`
	Ciphers  int      `json:"ciphers"`
	Exts     int      `json:"extensions"`
	Groups   []string `json:"groups"`
	Bytes    int      `json:"hello_bytes"`
	HasPSK   bool     `json:"pre_shared_key"`
	HasECH   bool     `json:"ech"`
	Versions []string `json:"versions"`
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// parseHelloJA4 reads a ClientHello handshake message (record layer
// already removed, see deframeTLS) and computes its JA4.
func parseHelloJA4(hs []byte) (helloInfo, error) {
	var h helloInfo
	if len(hs) < 4 || hs[0] != 1 {
		return h, errors.New("not a ClientHello")
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return h, fmt.Errorf("incomplete ClientHello: %d of %d bytes", len(hs)-4, n)
	}
	b := hs[4 : 4+n]
	h.Bytes = n + 4
	rd := func(k int) ([]byte, bool) {
		if len(b) < k {
			return nil, false
		}
		out := b[:k]
		b = b[k:]
		return out, true
	}
	legacy, ok := rd(2)
	if !ok {
		return h, errors.New("short hello")
	}
	if _, ok = rd(32); !ok {
		return h, errors.New("short hello")
	}
	sid, ok := rd(1)
	if !ok {
		return h, errors.New("short hello")
	}
	if _, ok = rd(int(sid[0])); !ok {
		return h, errors.New("short hello")
	}
	cl, ok := rd(2)
	if !ok {
		return h, errors.New("short hello")
	}
	cs, ok := rd(int(binary.BigEndian.Uint16(cl)))
	if !ok {
		return h, errors.New("short cipher list")
	}
	var ciphers []string
	for i := 0; i+1 < len(cs); i += 2 {
		v := binary.BigEndian.Uint16(cs[i:])
		if !isGREASE(v) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", v))
		}
	}
	comp, ok := rd(1)
	if !ok {
		return h, errors.New("short hello")
	}
	if _, ok = rd(int(comp[0])); !ok {
		return h, errors.New("short hello")
	}
	version := binary.BigEndian.Uint16(legacy)
	var exts, sigs []string
	sni := false
	if el, ok := rd(2); ok {
		e, ok := rd(int(binary.BigEndian.Uint16(el)))
		if !ok {
			return h, errors.New("short extension list")
		}
		for len(e) >= 4 {
			typ := binary.BigEndian.Uint16(e)
			l := int(binary.BigEndian.Uint16(e[2:]))
			if len(e) < 4+l {
				return h, errors.New("short extension")
			}
			body := e[4 : 4+l]
			e = e[4+l:]
			if isGREASE(typ) {
				continue
			}
			h.Exts++
			switch typ {
			case 0x0000:
				sni = true
				if len(body) >= 5 {
					nl := int(binary.BigEndian.Uint16(body[3:]))
					if 5+nl <= len(body) {
						h.SNI = string(body[5 : 5+nl])
					}
				}
			case 0x0010:
				for p := body[min(2, len(body)):]; len(p) > 0 && int(p[0]) < len(p); p = p[1+int(p[0]):] {
					h.ALPN = append(h.ALPN, string(p[1:1+int(p[0])]))
				}
			case 0x000d:
				for p := body[min(2, len(body)):]; len(p) >= 2; p = p[2:] {
					sigs = append(sigs, fmt.Sprintf("%04x", binary.BigEndian.Uint16(p)))
				}
			case 0x000a:
				for p := body[min(2, len(body)):]; len(p) >= 2; p = p[2:] {
					if g := binary.BigEndian.Uint16(p); !isGREASE(g) {
						h.Groups = append(h.Groups, fmt.Sprintf("%04x", g))
					}
				}
			case 0x002b:
				best := uint16(0)
				for p := body[min(1, len(body)):]; len(p) >= 2; p = p[2:] {
					if v := binary.BigEndian.Uint16(p); !isGREASE(v) {
						h.Versions = append(h.Versions, fmt.Sprintf("%04x", v))
						if v > best {
							best = v
						}
					}
				}
				if best != 0 {
					version = best
				}
			case 0x0029:
				h.HasPSK = true
			case 0xfe0d:
				h.HasECH = true
			}
			if typ != 0x0000 && typ != 0x0010 {
				exts = append(exts, fmt.Sprintf("%04x", typ))
			}
		}
	}
	h.Ciphers = len(ciphers)
	ver := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[version]
	if ver == "" {
		ver = "00"
	}
	sniC := "i"
	if sni {
		sniC = "d"
	}
	alpn := "00"
	if len(h.ALPN) > 0 && h.ALPN[0] != "" {
		v := h.ALPN[0]
		alnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
		if alnum(v[0]) && alnum(v[len(v)-1]) {
			alpn = string(v[0]) + string(v[len(v)-1])
		} else {
			x := hex.EncodeToString([]byte(v))
			alpn = string(x[0]) + string(x[len(x)-1])
		}
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sniC, min(len(ciphers), 99), min(h.Exts, 99), alpn)
	sort.Strings(ciphers)
	sort.Strings(exts)
	bRaw := strings.Join(ciphers, ",")
	cRaw := strings.Join(exts, ",")
	if len(sigs) > 0 {
		cRaw += "_" + strings.Join(sigs, ",")
	}
	hash12 := func(s string, empty bool) string {
		if empty {
			return "000000000000"
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}
	h.JA4 = a + "_" + hash12(bRaw, len(ciphers) == 0) + "_" + hash12(cRaw, len(exts) == 0)
	h.JA4R = a + "_" + bRaw + "_" + cRaw
	return h, nil
}

// helloFromFlow finds the first complete ClientHello in one flow's
// first data packets.
func helloFromFlow(fd flowData) (helloInfo, error) {
	var joined []byte
	for _, p := range fd.Payloads {
		joined = append(joined, p...)
	}
	if !looksLikeTLS(joined) {
		return helloInfo{}, errors.New("the flow does not open with a TLS record")
	}
	return parseHelloJA4(deframeTLS(joined))
}

// ja4Diff names the JA4 sections in which two fingerprints differ.
func ja4Diff(got, ref string) []string {
	g, r := strings.Split(got, "_"), strings.Split(ref, "_")
	if len(g) != 3 || len(r) != 3 {
		return []string{"shape"}
	}
	var out []string
	for i, name := range []string{"a (version/SNI/counts/ALPN)", "b (cipher suites)", "c (extensions + signature algorithms)"} {
		if g[i] != r[i] {
			out = append(out, name)
		}
	}
	return out
}

// ---- `wb tlsface`: a stranger's handshake -----------------------------

// FaceTarget is one port to look at, and the names to present.
type FaceTarget struct {
	Port int      `json:"port"`
	SNIs []string `json:"snis"` // "" = no server_name at all
}

// FaceTLS is one handshake.
type FaceTLS struct {
	SNI       string   `json:"sni"`
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
	Version   string   `json:"version,omitempty"`
	ALPN      string   `json:"alpn,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	SANs      []string `json:"sans,omitempty"`
	SelfSig   bool     `json:"self_signed,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	HTTP      string   `json:"http,omitempty"` // first lines of the answer to GET / over this TLS
}

// FaceResult is what a stranger learns from one port.
type FaceResult struct {
	Port    int       `json:"port"`
	Open    bool      `json:"open"`
	Banner  string    `json:"banner,omitempty"`     // bytes the port sent before we said anything
	Plain   string    `json:"plain_http,omitempty"` // answer to a plain-text GET /
	TLS     []FaceTLS `json:"tls,omitempty"`
	Markers []string  `json:"markers,omitempty"` // Daal-specific strings seen anywhere above
	// Software: names of proxy software or its stack seen (recorded,
	// not judged: "golang" in a Go server's error page is common).
	Software []string `json:"software,omitempty"`
}

// daalMarkers are strings that would tell a stranger this is a Daal
// relay (judged), and generic proxy-software names (recorded).
var daalMarkers = []string{"daal", "relay-mgmt", "relay-health"}
var softwareMarkers = []string{"sing-box", "xray", "v2ray", "hysteria", "reality", "naive", "caddy", "go-http-client", "golang"}

func printable(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\n' {
			s.WriteByte(c)
		} else if c == '\r' {
			continue
		} else {
			fmt.Fprintf(&s, "\\x%02x", c)
		}
	}
	return s.String()
}

func readSome(c net.Conn, d time.Duration, max int) []byte {
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, max)
	n, _ := bufio.NewReader(c).Read(buf)
	return buf[:n]
}

func faceOne(host string, t FaceTarget) FaceResult {
	res := FaceResult{Port: t.Port}
	addr := net.JoinHostPort(host, fmt.Sprint(t.Port))
	dial := func() (net.Conn, error) { return net.DialTimeout("tcp", addr, 3*time.Second) }
	c, err := dial()
	if err != nil {
		return res
	}
	res.Open = true
	res.Banner = printable(readSome(c, 1500*time.Millisecond, 512))
	c.Close()
	if c, err = dial(); err == nil {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		res.Plain = printable(readSome(c, 2*time.Second, 512))
		c.Close()
	}
	for _, sni := range t.SNIs {
		res.TLS = append(res.TLS, faceTLS(dial, host, sni))
	}
	var all bytes.Buffer
	j, _ := json.Marshal(res)
	all.Write(bytes.ToLower(j))
	for _, m := range daalMarkers {
		if bytes.Contains(all.Bytes(), []byte(m)) {
			res.Markers = append(res.Markers, m)
		}
	}
	for _, m := range softwareMarkers {
		if bytes.Contains(all.Bytes(), []byte(m)) {
			res.Software = append(res.Software, m)
		}
	}
	return res
}

func faceTLS(dial func() (net.Conn, error), host, sni string) FaceTLS {
	out := FaceTLS{SNI: sni}
	c, err := dial()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err := tc.Handshake(); err != nil {
		out.Error = err.Error()
		return out
	}
	st := tc.ConnectionState()
	out.OK = true
	out.Version = tls.VersionName(st.Version)
	out.ALPN = st.NegotiatedProtocol
	if len(st.PeerCertificates) > 0 {
		crt := st.PeerCertificates[0]
		out.Subject, out.Issuer = crt.Subject.String(), crt.Issuer.String()
		out.SANs = append(append([]string(nil), crt.DNSNames...), ipStrings(crt)...)
		out.SelfSig = crt.CheckSignatureFrom(crt) == nil
		out.NotBefore, out.NotAfter = crt.NotBefore.UTC().Format(time.RFC3339), crt.NotAfter.UTC().Format(time.RFC3339)
	}
	if st.NegotiatedProtocol != "h2" {
		hostHdr := sni
		if hostHdr == "" {
			hostHdr = host
		}
		_, _ = tc.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostHdr + "\r\nConnection: close\r\n\r\n"))
		out.HTTP = printable(readSome(tc, 2*time.Second, 512))
	} else {
		out.HTTP = "(h2 negotiated; not spoken)"
	}
	return out
}

func ipStrings(c *x509.Certificate) []string {
	var out []string
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// cmdTLSFace is `wb tlsface --host IP` with a JSON list of FaceTarget
// on stdin; it prints a JSON list of FaceResult.
func cmdTLSFace(args []string) int {
	fs := flag.NewFlagSet("tlsface", flag.ExitOnError)
	host := fs.String("host", Relay1IP, "relay address")
	_ = fs.Parse(args)
	var targets []FaceTarget
	if err := json.NewDecoder(os.Stdin).Decode(&targets); err != nil {
		fmt.Fprintln(os.Stderr, "tlsface: stdin:", err)
		return 2
	}
	out := make([]FaceResult, 0, len(targets))
	for _, t := range targets {
		out = append(out, faceOne(*host, t))
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}
