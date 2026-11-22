package uri

import (
	"fmt"
	"strings"
	"testing"
)

// TestRefusalCodesAreStable pins the token set the hosts map to their
// own copy (specs/uri-import-v1.md, "Refusal codes"). Renaming one is a
// breaking change for every client that shows it.
func TestRefusalCodesAreStable(t *testing.T) {
	want := map[error]string{
		ErrTransportUnsupported:  "transport_unsupported",
		ErrHeaderTypeUnsupported: "header_type_unsupported",
		ErrFlowUnsupported:       "flow_unsupported",
		ErrEncryptionUnsupported: "encryption_unsupported",
		ErrPlaintext:             "plaintext_refused",
		ErrInsecure:              "insecure_refused",
		ErrMalformed:             "link_malformed",
	}
	for sentinel, code := range want {
		wrapped := fmt.Errorf("vless: type=xhttp: %w", sentinel)
		if got := RefusalCode(wrapped); got != code {
			t.Errorf("RefusalCode(%v) = %q, want %q", sentinel, got, code)
		}
		// The token is also readable from the error TEXT alone, which
		// is all a host behind a string-only ABI sees.
		if !strings.Contains(wrapped.Error(), "uri: "+code) {
			t.Errorf("error text %q does not carry %q", wrapped.Error(), "uri: "+code)
		}
	}
	if RefusalCode(ErrNoMatch) != "" {
		t.Error("ErrNoMatch is not a refusal (the item is simply not understood)")
	}
}

// TestRefusalsNeverQuoteTheLink: an import error is shown and may be
// logged, and the link's userinfo is the route's credential.
func TestRefusalsNeverQuoteTheLink(t *testing.T) {
	const secret = "s3cr3t-cred-0001"
	for _, raw := range []string{
		"vless://" + secret + "@x.example.com:443?security=tls&type=xhttp",
		"vless://" + secret + "@x.example.com:443?security=none",
		"trojan://" + secret + "@x.example.com:443?type=grpc",
		"hy2://" + secret + "@x.example.com:1-99999",
		"tuic://" + secret + ":" + secret + "@x.example.com:443?allow_insecure=1",
		"vless://" + secret + "@x.example.com:notaport?security=tls",
	} {
		_, _, err := ParseURI(raw)
		if err == nil {
			t.Fatalf("accepted %q", raw[:10])
		}
		if s := err.Error(); strings.Contains(s, secret) || strings.Contains(s, "x.example.com") {
			t.Errorf("refusal quotes the link: %s", s)
		}
	}
}

func TestAmneziaDowngradeIsManualOnly(t *testing.T) {
	base := "[Interface]\nPrivateKey = cGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGE=\nAddress = 10.0.0.2/32\n"
	peer := "[Peer]\nPublicKey = cGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGFkcGE=\nEndpoint = w.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
	cases := []struct {
		name       string
		extra      string
		family     string
		notice     string
		manualOnly bool
	}{
		{"plain", "", "wireguard", "", false},
		{"junk-only", "Jc = 4\nJmin = 40\nJmax = 70\n", "wireguard", NoticeAmneziaDowngraded, true},
		{"junk-and-neutral-headers", "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n", "wireguard", NoticeAmneziaDowngraded, true},
		{"headers", "Jc = 4\nS1 = 15\nH1 = 123456\n", "amneziawg", NoticeAmneziaUnsupported, false},
		{"2.0-signature", "Jc = 4\nJmin = 40\nJmax = 70\nI1 = <b 0xf6ab3267fa>\n", "amneziawg", NoticeAmneziaUnsupported, false},
		{"2.0-paddings", "S3 = 12\nS4 = 9\n", "amneziawg", NoticeAmneziaUnsupported, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profs, prov, err := ParseAny([]byte(base+tc.extra+peer), "wireguard")
			if err != nil {
				t.Fatal(err)
			}
			p := profs[0]
			if p.TransportFamily != tc.family {
				t.Errorf("family = %q, want %q", p.TransportFamily, tc.family)
			}
			if prov.Notice != tc.notice {
				t.Errorf("notice = %q, want %q", prov.Notice, tc.notice)
			}
			if p.ManualOnly != tc.manualOnly {
				t.Errorf("ManualOnly = %v, want %v", p.ManualOnly, tc.manualOnly)
			}
		})
	}
}

// TestClashEntryRefusals: the Clash mapping refuses what the URI
// parsers refuse, with the same codes.
func TestClashEntryRefusals(t *testing.T) {
	const key = testRealityKey
	cases := []struct {
		name  string
		entry map[string]string
		code  string
	}{
		{"vless-xhttp", map[string]string{"type": "vless", "server": "v.example.com", "port": "443", "uuid": "u", "tls": "true", "network": "xhttp"}, "transport_unsupported"},
		{"vless-h2", map[string]string{"type": "vless", "server": "v.example.com", "port": "443", "uuid": "u", "tls": "true", "network": "h2"}, "transport_unsupported"},
		{"vless-no-tls", map[string]string{"type": "vless", "server": "v.example.com", "port": "443", "uuid": "u"}, "plaintext_refused"},
		{"vless-encryption", map[string]string{"type": "vless", "server": "v.example.com", "port": "443", "uuid": "u", "tls": "true", "encryption": "mlkem768x25519plus"}, "encryption_unsupported"},
		{"trojan-grpc", map[string]string{"type": "trojan", "server": "t.example.com", "port": "443", "password": "p", "network": "grpc"}, "transport_unsupported"},
		{"trojan-reality", map[string]string{"type": "trojan", "server": "t.example.com", "port": "443", "password": "p", "public-key": key}, "transport_unsupported"},
		{"hy2-skip-cert", map[string]string{"type": "hysteria2", "server": "h.example.com", "port": "443", "password": "p", "skip-cert-verify": "true"}, "insecure_refused"},
		{"tuic-skip-cert", map[string]string{"type": "tuic", "server": "t.example.com", "port": "443", "uuid": "u", "password": "p", "skip-cert-verify": "true"}, "insecure_refused"},
		{"ss-none", map[string]string{"type": "ss", "server": "s.example.com", "port": "443", "cipher": "none", "password": "p"}, "plaintext_refused"},
		{"ss-plugin", map[string]string{"type": "ss", "server": "s.example.com", "port": "443", "cipher": "aes-128-gcm", "password": "p", "plugin": "obfs"}, "transport_unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ProfileFromClashEntry(tc.entry)
			if got := RefusalCode(err); got != tc.code {
				t.Errorf("code = %q, want %q (err %v)", got, tc.code, err)
			}
		})
	}
}
