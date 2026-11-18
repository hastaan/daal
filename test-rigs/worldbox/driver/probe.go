package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// ProbeResult is what one probe run reports (one JSON object on stdout).
// The probe is an ordinary process with ordinary sockets — "an app on the
// phone". It has no idea whether a tunnel exists; the kernel routes it.
//
// OK covers the TCP round trip in BOTH directions: a fresh nonce echoed,
// a payload downloaded and SHA-256-verified here, a payload uploaded and
// SHA-256-verified by the far end. UDP and DNS are reported separately
// (they are separate claims a family makes) and never change OK.
type ProbeResult struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Remote      string `json:"remote,omitempty"`       // source address the target saw (HTTP)
	NonceOK     bool   `json:"nonce_ok"`               // target echoed our fresh nonce
	BlobBytes   int    `json:"blob_bytes,omitempty"`   // payload size fetched
	BlobOK      bool   `json:"blob_ok"`                // SHA-256 matched the regenerated payload
	UploadBytes int    `json:"upload_bytes,omitempty"` // payload size the target received
	UploadOK    bool   `json:"upload_ok"`              // …and its SHA-256 as computed by the target matched

	// Burst: many connections at once, the way a phone behaves the moment
	// a VPN comes up (every app reconnects together).
	BurstN     int    `json:"burst_n,omitempty"`
	BurstOK    int    `json:"burst_ok,omitempty"`
	BurstError string `json:"burst_error,omitempty"`

	// UDP: a small datagram (a DNS-sized exchange) and a big one (what a
	// QUIC or WireGuard app sends all day; the size that finds a tunnel
	// whose datagram path cannot fragment).
	UDPOK       bool   `json:"udp_ok"`
	UDPRemote   string `json:"udp_remote,omitempty"` // source address the target saw (UDP)
	UDPError    string `json:"udp_error,omitempty"`
	UDPBigOK    bool   `json:"udp_big_ok"`
	UDPBigBytes int    `json:"udp_big_bytes,omitempty"`
	UDPBigError string `json:"udp_big_error,omitempty"`

	// DNS as the phone does it while the VPN is up: plain UDP/53 to the
	// resolvers DaalVpnService configures.
	DNSOK        bool   `json:"dns_ok"`                  // UDP: name resolved AND the resolver saw the query come from DNSAsker
	DNSAsker     string `json:"dns_asker,omitempty"`     // who the resolver saw asking (must be the relay)
	DNSError     string `json:"dns_error,omitempty"`     //
	DNSTCPOK     bool   `json:"dns_tcp_ok"`              // the same two lookups over TCP/53 (diagnostic)
	DNSTCPError  string `json:"dns_tcp_error,omitempty"` //
	NameFetchOK  bool   `json:"name_fetch_ok"`           // GET http://blocked.example/ via the address DNS returned
	NameFetchErr string `json:"name_fetch_error,omitempty"`

	Ms int64 `json:"ms"`
}

// BigDatagram is the payload size of the large UDP round trip. With the
// echo's "<ip>|" prefix and IP+UDP headers it is still one unfragmented
// packet on the phone's 1500-byte TUN.
const BigDatagram = 1400

// UploadSize is the body of the upload leg.
const UploadSize = 96 << 10

func cmdProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	target := fs.String("target", TargetIP, "target address")
	size := fs.Int("size", ProbeBlobBytes, "blob bytes to fetch and verify")
	timeout := fs.Duration("timeout", 8*time.Second, "overall deadline")
	udp := fs.Bool("udp", false, "also round-trip UDP datagrams (small and big)")
	udpBig := fs.Int("udp-big", BigDatagram, "payload bytes of the large UDP datagram")
	burst := fs.Int("burst", 0, "also open this many connections at once, each a verified nonce round trip")
	dns := fs.Bool("dns", false, "also resolve names the way the phone does (UDP/53 to the VPN's resolvers) and fetch by name")
	uid := fs.Int("uid", 0, "drop to this uid before opening any socket (an app's uid; 0 = stay as is)")
	whoamiOnly := fs.Bool("whoami-only", false, "stop after the nonce round trip: is there a path at all, and from which address")
	_ = fs.Parse(args)
	if *uid != 0 {
		// Become "some other app" for real: per-uid policy routing is how
		// a VPN captures traffic, on the phone and here.
		if err := syscall.Setgroups(nil); err != nil {
			fmt.Fprintln(os.Stderr, "probe: setgroups:", err)
			return 2
		}
		if err := syscall.Setgid(*uid); err != nil {
			fmt.Fprintln(os.Stderr, "probe: setgid:", err)
			return 2
		}
		if err := syscall.Setuid(*uid); err != nil {
			fmt.Fprintln(os.Stderr, "probe: setuid:", err)
			return 2
		}
	}

	if *whoamiOnly {
		*size = -1
	}
	res := runProbe(*target, *size, *timeout, *udp, *dns, *burst, *udpBig)
	_ = json.NewEncoder(os.Stdout).Encode(res)
	if !res.OK {
		return 1
	}
	return 0
}

func runProbe(target string, size int, timeout time.Duration, udp, dns bool, burst, udpBig int) (res ProbeResult) {
	t0 := time.Now()
	defer func() { res.Ms = time.Since(t0).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// A fresh transport per probe: no connection reuse can make a dead
	// path look alive.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}

	var nb [16]byte
	_, _ = rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	body, err := get(ctx, client, fmt.Sprintf("http://%s/whoami?nonce=%s", target, nonce))
	if err != nil {
		res.Error = "whoami: " + err.Error()
		return res
	}
	var who struct{ Nonce, Remote string }
	if err := json.Unmarshal(body, &who); err != nil {
		res.Error = "whoami: not the target's JSON: " + err.Error()
		return res
	}
	res.Remote, res.NonceOK = who.Remote, who.Nonce == nonce
	if !res.NonceOK {
		res.Error = "whoami: nonce mismatch (stale or forged response)"
		return res
	}
	if size < 0 { // --whoami-only
		res.OK = true
		return res
	}

	seed := uint64(t0.UnixNano())
	body, err = get(ctx, client, fmt.Sprintf("http://%s/blob?seed=%d&size=%d", target, seed, size))
	if err != nil {
		res.Error = "blob: " + err.Error()
		return res
	}
	sum := sha256.Sum256(body)
	res.BlobBytes = len(body)
	res.BlobOK = len(body) == size && hex.EncodeToString(sum[:]) == blobSum(seed, size)
	if !res.BlobOK {
		res.Error = fmt.Sprintf("blob: %d bytes, sha256 mismatch", len(body))
		return res
	}

	// The other direction. A tunnel that only moves bytes one way loads
	// a page and cannot send a message.
	up := blob(seed+1, UploadSize)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s/sink", target), bytes.NewReader(up))
	resp, err := client.Do(req)
	if err != nil {
		res.Error = "upload: " + err.Error()
		return res
	}
	var sink struct {
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	err = json.NewDecoder(resp.Body).Decode(&sink)
	resp.Body.Close()
	res.UploadBytes = sink.Bytes
	res.UploadOK = err == nil && sink.Bytes == UploadSize && sink.SHA256 == blobSum(seed+1, UploadSize)
	if !res.UploadOK {
		res.Error = fmt.Sprintf("upload: the target received %d of %d bytes, or a different payload (%v)", sink.Bytes, UploadSize, err)
		return res
	}
	if burst > 0 {
		res.BurstN = burst
		type one struct {
			ok  bool
			err string
		}
		done := make(chan one, burst)
		for i := 0; i < burst; i++ {
			go func(i int) {
				n := fmt.Sprintf("%s-%d", nonce, i)
				c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
				body, err := get(ctx, c, fmt.Sprintf("http://%s/whoami?nonce=%s", target, n))
				var w struct{ Nonce, Remote string }
				if err == nil {
					err = json.Unmarshal(body, &w)
				}
				switch {
				case err != nil:
					done <- one{false, err.Error()}
				case w.Nonce != n || w.Remote != who.Remote:
					done <- one{false, fmt.Sprintf("connection %d: wrong nonce or a different source address (%s)", i, w.Remote)}
				default:
					done <- one{true, ""}
				}
			}(i)
		}
		for i := 0; i < burst; i++ {
			if o := <-done; o.ok {
				res.BurstOK++
			} else if res.BurstError == "" {
				res.BurstError = o.err
			}
		}
		if res.BurstOK != burst {
			res.Error = fmt.Sprintf("burst: %d of %d simultaneous connections failed: %s", burst-res.BurstOK, burst, res.BurstError)
			return res
		}
	}
	res.OK = true

	if udp {
		small := []byte(nonce)
		from, echoed, err := udpEcho(ctx, target, small)
		res.UDPRemote, res.UDPOK = from, err == nil && bytes.Equal(echoed, small)
		if err != nil {
			res.UDPError = err.Error()
		}
		big := blob(seed+2, udpBig+8)[:udpBig]
		from, echoed, err = udpEcho(ctx, target, big)
		res.UDPBigBytes = len(echoed)
		res.UDPBigOK = err == nil && from == res.UDPRemote && bytes.Equal(echoed, big)
		if err != nil {
			res.UDPBigError = err.Error()
		} else if !res.UDPBigOK {
			res.UDPBigError = fmt.Sprintf("%d-byte datagram came back as %d bytes from %q", udpBig, len(echoed), from)
		}
	}
	if dns {
		probeDNS(ctx, client, &res)
	}
	return res
}

// udpEcho sends one datagram to the target's echo port and returns who the
// target saw and what came back. Three tries: one lost datagram is the
// network, three is the tunnel.
func udpEcho(ctx context.Context, target string, payload []byte) (from string, echoed []byte, err error) {
	for try := 0; try < 3 && ctx.Err() == nil; try++ {
		var conn net.Conn
		conn, err = net.DialTimeout("udp", net.JoinHostPort(target, "7"), 2*time.Second)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 4096)
		var n int
		if _, err = conn.Write(payload); err == nil {
			n, err = conn.Read(buf)
		}
		conn.Close()
		if err != nil {
			continue
		}
		f, e, ok := bytes.Cut(buf[:n], []byte("|"))
		if !ok {
			err = fmt.Errorf("not the target's echo")
			continue
		}
		return string(f), e, nil
	}
	return "", nil, err
}

// probeDNS is the phone's resolver with Private DNS off: an A query over
// UDP/53 to the first configured server, then the second. Two names: one
// whose answer is the address the resolver saw the query come from (the
// path proof), one that is the blocked site — which is then fetched by
// that name. The same lookups are repeated over TCP/53 as a diagnostic.
func probeDNS(ctx context.Context, client *http.Client, res *ProbeResult) {
	lookup := func(network, name string) (string, error) {
		var last error
		for _, srv := range []string{PublicDNS1, PublicDNS2} {
			for try := 0; try < 2 && ctx.Err() == nil; try++ {
				ip, err := dnsLookup(network, srv, name)
				if err == nil {
					return ip, nil
				}
				last = fmt.Errorf("%s %s/53: %w", network, srv, err)
			}
		}
		return "", last
	}
	both := func(network string) (asker, site string, err error) {
		if asker, err = lookup(network, AskerName); err != nil {
			return
		}
		site, err = lookup(network, BlockedName)
		return
	}
	asker, site, err := both("udp")
	res.DNSAsker = asker
	switch {
	case err != nil:
		res.DNSError = err.Error()
	case site != TargetIP:
		res.DNSError = fmt.Sprintf("%s resolved to %s, want %s", BlockedName, site, TargetIP)
	default:
		res.DNSOK = true
	}
	if a, s, err := both("tcp"); err != nil {
		res.DNSTCPError = err.Error()
	} else {
		res.DNSTCPOK = s == TargetIP
		if res.DNSAsker == "" {
			res.DNSAsker = a
		}
	}
	if site == "" {
		res.NameFetchErr = "no address to fetch: the name did not resolve"
		return
	}
	var nb [8]byte
	_, _ = rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/whoami?nonce=%s", site, nonce), nil)
	req.Host = BlockedName
	resp, err := client.Do(req)
	if err != nil {
		res.NameFetchErr = err.Error()
		return
	}
	defer resp.Body.Close()
	var who struct{ Nonce string }
	_ = json.NewDecoder(resp.Body).Decode(&who)
	res.NameFetchOK = who.Nonce == nonce
}

func dnsLookup(network, server, name string) (string, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := uint16(idb[0])<<8 | uint16(idb[1])
	q := dnsQuery(id, name)
	conn, err := net.DialTimeout(network, net.JoinHostPort(server, "53"), 1500*time.Millisecond)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 1500)
	var n int
	if network == "tcp" {
		if _, err := conn.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)); err != nil {
			return "", err
		}
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		n = int(l[0])<<8 | int(l[1])
		if n > len(buf) {
			return "", fmt.Errorf("oversized answer")
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return "", err
		}
	} else {
		if _, err := conn.Write(q); err != nil {
			return "", err
		}
		if n, err = conn.Read(buf); err != nil {
			return "", err
		}
	}
	ip, err := dnsAnswerA(buf[:n], id)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return ip, nil
}

func get(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
