package share

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
)

// startPinnedTestServer stands up a REAL TLS listener on loopback serving
// the sender's one resource, using a freshly generated self-signed cert.
// It returns the host, port and the SPKI pin for the cert it is actually
// presenting — so a test that wants a mismatch just uses a different
// server's pin, with no hand-computed constants anywhere.
func startPinnedTestServer(t *testing.T, token string, body []byte) (host string, port int, spki string) {
	t.Helper()
	urls, spki, stop, err := defaultListen([]string{"127.0.0.1"}, token, body)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(stop)
	if len(urls) != 1 {
		t.Fatalf("expected 1 url, got %v", urls)
	}
	hostport := strings.TrimSuffix(strings.TrimPrefix(urls[0], "https://"), "/bundle.sbp")
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split %q: %v", hostport, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return h, n, spki
}

// TestPinAcceptsRealCertAndRefusesAnother is the core of the fix: over two
// real TLS listeners with two independently generated certs, the pull
// succeeds against the cert whose SPKI it was given and fails against the
// other. Before this wave the second half of this test could not fail —
// InsecureSkipVerify accepted anything.
func TestPinAcceptsRealCertAndRefusesAnother(t *testing.T) {
	body := []byte("SBP-BODY-HONEST")
	tok := DeriveBearerToken("123456", "s-real")

	realHost, realPort, realSPKI := startPinnedTestServer(t, tok, body)
	// A second, independently generated cert. This stands in for the
	// attacker on the café Wi-Fi who answered the mDNS query first.
	evilHost, evilPort, evilSPKI := startPinnedTestServer(t, tok, []byte("SBP-BODY-HOSTILE"))

	if realSPKI == evilSPKI {
		t.Fatalf("two generated certs produced the same SPKI pin — the pin is not a pin")
	}

	// 1. Correct pin against the cert that owns it: accepted.
	got, err := PullURL(realHost, realPort, "123456", "s-real", realSPKI, 2000)
	if err != nil {
		t.Fatalf("pull with matching pin: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: %q", got)
	}

	// 2. The sender's pin against the impostor's listener: REFUSED, and
	// refused inside the handshake, so the impostor never sees the
	// Authorization header.
	if _, err := PullURL(evilHost, evilPort, "123456", "s-real", realSPKI, 2000); err == nil {
		t.Fatal("impostor cert accepted under the real sender's pin")
	} else if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("wrong error for impostor cert: %v", err)
	}

	// 3. And symmetrically, the impostor's own pin does not open the real
	// sender either — the check is a comparison, not a presence test.
	if _, err := PullURL(realHost, realPort, "123456", "s-real", evilSPKI, 2000); err == nil {
		t.Fatal("real cert accepted under the impostor's pin")
	} else if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("wrong error for wrong pin: %v", err)
	}
}

// TestMissingPinIsRefusedNotSkipped is the regression that matters most.
// The old code's comment said "we verify SPKI separately if known"; the
// failure mode of "if known" is that not-knowing silently means
// not-verifying. Every spelling of "I have no pin" must be an error.
func TestMissingPinIsRefusedNotSkipped(t *testing.T) {
	body := []byte("SBP")
	tok := DeriveBearerToken("123456", "s-1")
	host, port, realSPKI := startPinnedTestServer(t, tok, body)

	for _, tc := range []struct {
		name string
		pin  string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"not base64", "!!!!not-base64!!!!"},
		{"truncated digest", realSPKI[:16]},
		{"digest plus a byte", realSPKI + "AA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PullURL(host, port, "123456", "s-1", tc.pin, 2000)
			if err == nil {
				t.Fatalf("pull succeeded with pin %q — unpinned connection allowed", tc.pin)
			}
		})
	}

	// Sanity: the same server with the real pin does work, so the
	// refusals above are about the pin and not about a dead listener.
	if _, err := PullURL(host, port, "123456", "s-1", realSPKI, 2000); err != nil {
		t.Fatalf("control pull failed: %v", err)
	}
}

// TestPinnedTLSConfigAlwaysCarriesAVerifier guards the shape of the
// config itself: there must be no way to obtain a receiver-side
// tls.Config that has InsecureSkipVerify set and no VerifyPeerCertificate,
// which is exactly what lan_receiver.go used to hand to tls.Dial.
func TestPinnedTLSConfigAlwaysCarriesAVerifier(t *testing.T) {
	if _, err := pinnedTLSConfig(""); !errors.Is(err, ErrNoPin) {
		t.Fatalf("blank pin produced a config (err=%v)", err)
	}
	cfg, err := pinnedTLSConfig(strings.Repeat("A", 43)) // 43 b64url chars = 32 bytes
	if err != nil {
		t.Fatalf("valid-length pin rejected: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("config has InsecureSkipVerify with no VerifyPeerCertificate")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion regressed to %x", cfg.MinVersion)
	}
}

// TestHostileTXTCannotSteerReceiverOffLAN covers the second gate. A TXT
// record or QR is attacker-authored text; these are the addresses an
// attacker would like the receiver to dial.
func TestHostileTXTCannotSteerReceiverOffLAN(t *testing.T) {
	pin := strings.Repeat("A", 43)
	hostile := []struct {
		name string
		host string
	}{
		{"public ipv4", "93.184.216.34"},
		{"public ipv6", "2606:2800:220:1:248:1893:25c8:1946"},
		{"hostname", "evil.example.com"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"multicast", "224.0.0.251"},
		{"empty", ""},
		{"zoned link-local", "fe80::1%eth0"},
		{"decimal-encoded public", "3232235777.example"},
	}
	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PullURL(tc.host, 8443, "123456", "s", pin, 200); err == nil {
				t.Fatalf("receiver agreed to dial %q", tc.host)
			}
		})
	}
	// 100.64.0.0/10 is CGNAT, and the receiver must NOT dial it. On
	// mobile data the handset's own address typically sits in this
	// range, which spans an entire carrier's subscriber pool — so a
	// doctored QR naming a CGNAT host is an off-LAN connection to an
	// attacker-chosen machine. The SPKI pin cannot undo it: the TCP
	// connect and the TLS ClientHello are on the wire before the pin is
	// ever evaluated. The sender may still BIND there (see
	// isPrivateIP); only dialling is refused.
	for _, cgnat := range []string{"100.64.0.1", "100.100.50.1", "100.127.255.254"} {
		if err := requirePrivateHost(cgnat); err == nil {
			t.Errorf("receiver agreed to dial CGNAT address %s", cgnat)
		}
	}

	// The allowed shapes still work as inputs (they fail later, on dial,
	// not at the address gate) — otherwise this test would pass by
	// refusing everything.
	for _, ok := range []string{"192.168.1.10", "10.1.2.3", "172.16.0.1", "169.254.1.1", "fd00::1", "127.0.0.1"} {
		if err := requirePrivateHost(ok); err != nil {
			t.Errorf("private address %s rejected: %v", ok, err)
		}
	}
}

// TestSenderRefusesPublicBind makes the private-only binding rule a
// property of the program rather than of a source grep.
func TestSenderRefusesPublicBind(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::", "93.184.216.34", "example.com", "", "224.0.0.251"} {
		urls, spki, stop, err := defaultListen([]string{addr}, "tok", []byte("x"))
		if err == nil {
			if stop != nil {
				stop()
			}
			t.Fatalf("sender bound %q (urls=%v spki=%q)", addr, urls, spki)
		}
		if !errors.Is(err, ErrPublicBindRefused) {
			t.Errorf("addr %q: wrong error %v", addr, err)
		}
	}
	// One bad address in an otherwise-private list fails the whole
	// session rather than being quietly dropped.
	if _, _, stop, err := defaultListen([]string{"127.0.0.1", "93.184.216.34"}, "tok", []byte("x")); err == nil {
		if stop != nil {
			stop()
		}
		t.Fatal("mixed private/public list was accepted")
	}
}

// TestParseShareTargetCarriesThePin covers the QR-URL fallback shape the
// spec names, in both spellings, and proves an unpinned URL cannot be
// turned into a Target at all.
func TestParseShareTargetCarriesThePin(t *testing.T) {
	pin := strings.Repeat("B", 43)

	t.Run("daalshare wrapper", func(t *testing.T) {
		uri := ShareURI("https://192.168.1.50:44311/bundle.sbp", pin, "s-abc")
		got, err := ParseShareTarget(uri)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got.Host != "192.168.1.50" || got.Port != 44311 || got.SPKI != pin || got.SessionID != "s-abc" {
			t.Fatalf("bad target: %+v", got)
		}
	})

	t.Run("bare https with spki fragment", func(t *testing.T) {
		got, err := ParseShareTarget("https://10.0.0.7:9999/bundle.sbp#spki=" + pin)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got.Host != "10.0.0.7" || got.Port != 9999 || got.SPKI != pin {
			t.Fatalf("bad target: %+v", got)
		}
	})

	t.Run("bare fragment", func(t *testing.T) {
		got, err := ParseShareTarget("https://10.0.0.7:9999/bundle.sbp#" + pin)
		if err != nil || got.SPKI != pin {
			t.Fatalf("bare fragment pin not read: %+v %v", got, err)
		}
	})

	t.Run("ipv6 literal", func(t *testing.T) {
		got, err := ParseShareTarget("https://[fd00::5]:443/bundle.sbp#spki=" + pin)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got.Host != "fd00::5" {
			t.Fatalf("ipv6 host mangled: %q", got.Host)
		}
	})

	for _, bad := range []string{
		"",
		"http://192.168.1.50:443/bundle.sbp#spki=" + pin,                   // plaintext
		"https://192.168.1.50:443/bundle.sbp",                              // no pin at all
		"https://192.168.1.50/bundle.sbp#spki=" + pin,                      // no explicit port
		"https://93.184.216.34:443/bundle.sbp#spki=" + pin,                 // public host
		"https://evil.example.com:443/bundle.sbp#spki=" + pin,              // name, not literal
		"https://user:pw@192.168.1.50:443/bundle.sbp#spki=" + pin,          // userinfo
		"daalshare://lan?p=" + pin + "&s=x",                                // no u=
		"daalshare://exfil?u=https%3A%2F%2F192.168.1.5%3A443%2Fb&p=" + pin, // wrong action
		"daalshare://lan?u=https%3A%2F%2F192.168.1.5%3A443%2Fb",            // no pin
	} {
		if got, err := ParseShareTarget(bad); err == nil {
			t.Errorf("accepted hostile target %q -> %+v", bad, got)
		}
	}
}

// TestPullArbitraryURLEndToEnd drives the fallback path against the real
// listener: a QR string in, bundle bytes out, and the same string with a
// swapped pin refused.
func TestPullArbitraryURLEndToEnd(t *testing.T) {
	body := []byte("SBP-VIA-QR")
	tok := DeriveBearerToken("424242", "s-qr")
	host, port, spki := startPinnedTestServer(t, tok, body)
	lanURL := "https://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/bundle.sbp"

	got, err := PullArbitraryURL(ShareURI(lanURL, spki, "s-qr"), "424242", "", 2000)
	if err != nil {
		t.Fatalf("pull via daalshare URI: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: %q", got)
	}

	// Same URL, a different (well-formed) pin: refused.
	_, otherSPKI := func() (string, string) {
		_, s, stop, err := defaultListen([]string{"127.0.0.1"}, tok, body)
		if err != nil {
			t.Fatalf("second listener: %v", err)
		}
		stop()
		return "", s
	}()
	if _, err := PullArbitraryURL(ShareURI(lanURL, otherSPKI, "s-qr"), "424242", "", 2000); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("swapped pin was not refused: %v", err)
	}
}

// TestSPKIHashMatchesTheCertActuallyServed closes the loop between the
// value the sender publishes and the bytes on the wire: we hash the leaf
// the TLS handshake really presented and compare it to what defaultListen
// advertised.
func TestSPKIHashMatchesTheCertActuallyServed(t *testing.T) {
	tok := DeriveBearerToken("111111", "s-x")
	host, port, spki := startPinnedTestServer(t, tok, []byte("x"))

	conn, err := tls.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true, // this test IS the verification
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		t.Fatal("no peer certificates")
	}
	if got := SPKIHashFromCert(chain[0]); got != spki {
		t.Fatalf("published pin %q != served leaf %q", spki, got)
	}
}

// TestPullRefusesOversizedBodyFromPinnedPeer closes the gap between "we
// know who this peer is" and "we will accept anything they send".
//
// The SPKI pin authenticates the sender; it does not constrain them. A
// receiver reaches this code by scanning a QR the other party is holding
// up, so a hostile-but-correctly-pinned sender is in scope. The body is
// served by a REAL pinned TLS listener — the pin passes — and must still
// be refused on size alone, before anything tries to parse it.
func TestPullRefusesOversizedBodyFromPinnedPeer(t *testing.T) {
	const pin, sess = "654321", "s-huge"
	huge := make([]byte, bundle.MaxArchiveTotalBytes+1024)
	host, port, spki := startPinnedTestServer(t, DeriveBearerToken(pin, sess), huge)

	_, err := PullURL(host, port, pin, sess, spki, 15000)
	if err == nil {
		t.Fatal("receiver accepted a body larger than any bundle could be")
	}
	if !errors.Is(err, ErrShareBodyTooLarge) {
		t.Fatalf("want ErrShareBodyTooLarge, got %v", err)
	}
}

// The bound must not be so tight that a real bundle stops arriving: the
// same listener with a realistic payload still round-trips through the
// pinned pull unchanged.
func TestPullStillAcceptsARealisticBundleBody(t *testing.T) {
	const pin, sess = "654322", "s-real-size"
	body := make([]byte, 64*1024)
	for i := range body {
		body[i] = byte(i)
	}
	host, port, spki := startPinnedTestServer(t, DeriveBearerToken(pin, sess), body)

	got, err := PullURL(host, port, pin, sess, spki, 15000)
	if err != nil {
		t.Fatalf("realistic body refused: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body corrupted: got %d bytes, want %d", len(got), len(body))
	}
}
