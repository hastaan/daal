package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testCert returns a self-signed leaf (PEM) and its SPKI pin.
func testCert(t *testing.T, ips []string, dns []string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "daal-relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dns,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pin, err := SPKIPinFromCertPEM(pemText)
	if err != nil {
		t.Fatal(err)
	}
	return pemText, pin
}

type endpointCase struct {
	family   string
	ep       Endpoint
	outbound map[string]any
	// credential is a path to one per-recipient secret in outbound.
	credential []string
}

func endpointCases(t *testing.T) []endpointCase {
	t.Helper()
	certPEM, pin := testCert(t, []string{"203.0.113.10"}, []string{"cover.example"})
	const server = "203.0.113.10"
	pinned := func() map[string]any {
		return map[string]any{"enabled": true, "server_name": server, "certificate_public_key_sha256": pin}
	}
	ssKey := "aVBTS2lQU0tpUFNLaVBTSw=="
	return []endpointCase{
		{
			family: "vless-reality",
			ep:     Endpoint{V: 1, Server: server, Port: 443, ServerName: "cover.example", RealityPublicKey: "REALITYKEY"},
			outbound: map[string]any{"type": "vless", "tag": "active", "server": server, "server_port": 443, "uuid": "u-1",
				"tls": map[string]any{"enabled": true, "server_name": "cover.example",
					"reality": map[string]any{"enabled": true, "public_key": "REALITYKEY", "short_id": "ab"}}},
			credential: []string{"uuid"},
		},
		{
			family: "websocket-tls",
			ep:     Endpoint{V: 1, Server: server, Port: 8445, ServerName: server, TLSSPKISHA256: pin},
			outbound: map[string]any{"type": "vless", "tag": "active", "server": server, "server_port": 8445, "uuid": "u-1",
				"transport": map[string]any{"type": "ws", "path": "/r1/aa"}, "tls": pinned()},
			credential: []string{"uuid"},
		},
		{
			family: "hysteria2",
			ep:     Endpoint{V: 1, Server: server, Port: 443, ServerName: server, TLSSPKISHA256: pin},
			outbound: map[string]any{"type": "hysteria2", "tag": "active", "server": server, "server_port": 443,
				"password": "p-1", "tls": pinned()},
			credential: []string{"password"},
		},
		{
			family: "tuic",
			ep:     Endpoint{V: 1, Server: server, Port: 8443, ServerName: server, TLSSPKISHA256: pin},
			outbound: map[string]any{"type": "tuic", "tag": "active", "server": server, "server_port": 8443,
				"uuid": "u-1", "password": "p-1", "tls": pinned()},
			credential: []string{"password"},
		},
		{
			family: "anytls",
			ep:     Endpoint{V: 1, Server: server, Port: 8447, ServerName: server, TLSSPKISHA256: pin},
			outbound: map[string]any{"type": "anytls", "tag": "active", "server": server, "server_port": 8447,
				"password": "p-1", "tls": pinned()},
			credential: []string{"password"},
		},
		{
			family: "naive",
			ep:     Endpoint{V: 1, Server: server, Port: 8444, TLSSPKISHA256: pin},
			outbound: map[string]any{"type": "naive", "tag": "active", "server": server, "server_port": 8444,
				"username": "r1", "password": "p-1",
				"tls": map[string]any{"enabled": true, "server_name": server, "certificate": []any{certPEM}}},
			credential: []string{"password"},
		},
		{
			family: "shadowsocks",
			ep: Endpoint{V: 1, Server: server, Port: 8446, SSMethod: "2022-blake3-aes-128-gcm",
				SSServerKeySHA256: SSServerKeyDigest(ssKey)},
			outbound: map[string]any{"type": "shadowsocks", "tag": "active", "server": server, "server_port": 8446,
				"method": "2022-blake3-aes-128-gcm", "password": ssKey + ":dVBTS3VQU0t1UFNLdVBTSw=="},
			credential: nil, // covered separately: only the user half is free
		},
	}
}

func clone(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(m)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Every family's genuine outbound matches its commitment, and every
// alteration of where it points or what authenticates the relay is
// refused. This is F-004: before the commitment existed all of these
// imported cleanly under the publisher's fingerprint.
func TestCheckOutbound_RefusesEveryEndpointRewrite(t *testing.T) {
	_, otherPin := testCert(t, []string{"198.51.100.66"}, nil)
	otherPEM, _ := testCert(t, []string{"203.0.113.10"}, nil)
	for _, tc := range endpointCases(t) {
		tc := tc
		t.Run(tc.family, func(t *testing.T) {
			if err := tc.ep.Validate(tc.family); err != nil {
				t.Fatalf("fixture commitment invalid: %v", err)
			}
			if err := CheckOutbound(tc.family, &tc.ep, mustJSON(t, tc.outbound)); err != nil {
				t.Fatalf("genuine outbound refused: %v", err)
			}
			if err := CheckOutbound(tc.family, nil, mustJSON(t, tc.outbound)); !errors.Is(err, ErrEndpointUnauthenticated) {
				t.Fatalf("outbound with no commitment: err=%v, want ErrEndpointUnauthenticated", err)
			}
			rewrites := map[string]func(ob map[string]any){
				"server":   func(ob map[string]any) { ob["server"] = "198.51.100.66" },
				"port":     func(ob map[string]any) { ob["server_port"] = 4443 },
				"type":     func(ob map[string]any) { ob["type"] = "socks" },
				"detour":   func(ob map[string]any) { ob["detour"] = "elsewhere" },
				"no-port":  func(ob map[string]any) { delete(ob, "server_port") },
				"no-serve": func(ob map[string]any) { delete(ob, "server") },
				// hysteria2 dials a port from this list INSTEAD of
				// server_port.
				"port-hop": func(ob map[string]any) { ob["server_ports"] = []any{"4443:4500"} },
			}
			if tls, ok := tc.outbound["tls"].(map[string]any); ok {
				rewrites["insecure"] = func(ob map[string]any) { ob["tls"].(map[string]any)["insecure"] = true }
				rewrites["tls-off"] = func(ob map[string]any) { ob["tls"].(map[string]any)["enabled"] = false }
				rewrites["no-tls"] = func(ob map[string]any) { delete(ob, "tls") }
				rewrites["cert-path"] = func(ob map[string]any) { ob["tls"].(map[string]any)["certificate_path"] = "/sdcard/ca.pem" }
				if tc.ep.ServerName != "" {
					rewrites["sni"] = func(ob map[string]any) { ob["tls"].(map[string]any)["server_name"] = "blocked.example" }
				}
				if _, ok := tls["certificate_public_key_sha256"]; ok {
					rewrites["pin"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["certificate_public_key_sha256"] = otherPin
					}
					rewrites["pin-added"] = func(ob map[string]any) {
						t := ob["tls"].(map[string]any)
						t["certificate_public_key_sha256"] = []any{t["certificate_public_key_sha256"], otherPin}
					}
					rewrites["pin-removed"] = func(ob map[string]any) {
						delete(ob["tls"].(map[string]any), "certificate_public_key_sha256")
					}
					rewrites["root-added"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["certificate"] = []any{otherPEM}
					}
					rewrites["reality-on"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["reality"] = map[string]any{"enabled": true, "public_key": "x"}
					}
				}
				if _, ok := tls["reality"]; ok {
					rewrites["reality-key"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["reality"].(map[string]any)["public_key"] = "ATTACKERKEY"
					}
					rewrites["reality-off"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["reality"].(map[string]any)["enabled"] = false
					}
				}
				if _, ok := tls["certificate"]; ok {
					rewrites["naive-root-swapped"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["certificate"] = []any{otherPEM}
					}
					rewrites["naive-root-added"] = func(ob map[string]any) {
						t := ob["tls"].(map[string]any)
						t["certificate"] = append(t["certificate"].([]any), otherPEM)
					}
					rewrites["naive-root-removed"] = func(ob map[string]any) {
						delete(ob["tls"].(map[string]any), "certificate")
					}
					// The name Chromium verifies against is derived,
					// not free: a name of the attacker's own would be
					// enough wherever a public root is also trusted.
					rewrites["naive-name"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["server_name"] = "attacker.example"
					}
					rewrites["naive-name-other-san"] = func(ob map[string]any) {
						ob["tls"].(map[string]any)["server_name"] = "cover.example"
					}
				}
			}
			if tc.family == "shadowsocks" {
				rewrites["ss-server-key"] = func(ob map[string]any) {
					ob["password"] = "YXR0YWNrZXJhdHRhY2tlcg==:" + strings.SplitN(ob["password"].(string), ":", 2)[1]
				}
				rewrites["ss-single-key"] = func(ob map[string]any) { ob["password"] = "YXR0YWNrZXJhdHRhY2tlcg==" }
				rewrites["ss-method"] = func(ob map[string]any) { ob["method"] = "none" }
				rewrites["ss-plugin"] = func(ob map[string]any) { ob["plugin"] = "obfs-local" }
			}
			for name, rewrite := range rewrites {
				ob := clone(t, tc.outbound)
				rewrite(ob)
				err := CheckOutbound(tc.family, &tc.ep, mustJSON(t, ob))
				if !errors.Is(err, ErrEndpointMismatch) {
					t.Errorf("rewrite %q was not refused as a mismatch: err=%v", name, err)
				}
			}
		})
	}
}

// The other half of the argument: a credential is NOT covered, and it
// does not need to be. Changing one leaves the outbound pointing at the
// committed relay, authenticated by the committed key — so all a forged
// credential can do is be refused by that relay.
func TestCheckOutbound_CredentialsAreFreeAndCannotMoveTheEndpoint(t *testing.T) {
	for _, tc := range endpointCases(t) {
		ob := clone(t, tc.outbound)
		if tc.family == "shadowsocks" {
			// only the per-user half is a credential
			key := strings.SplitN(ob["password"].(string), ":", 2)[0]
			ob["password"] = key + ":Zm9yZ2VkZm9yZ2VkZm9yZw=="
		} else {
			ob[tc.credential[0]] = "forged-by-someone-on-the-path"
		}
		raw := mustJSON(t, ob)
		if err := CheckOutbound(tc.family, &tc.ep, raw); err != nil {
			t.Fatalf("%s: a changed credential must not be an endpoint mismatch: %v", tc.family, err)
		}
		var back map[string]any
		_ = json.Unmarshal(raw, &back)
		if back["server"] != tc.ep.Server || int(back["server_port"].(float64)) != tc.ep.Port {
			t.Fatalf("%s: outbound no longer points at the committed endpoint", tc.family)
		}
	}
}

func TestEndpointValidate_RefusesHalfFilledCommitments(t *testing.T) {
	_, pin := testCert(t, []string{"203.0.113.10"}, nil)
	bad := map[string]Endpoint{
		"vless-reality no key":   {V: 1, Server: "a", Port: 1, ServerName: "c"},
		"vless-reality no sni":   {V: 1, Server: "a", Port: 1, RealityPublicKey: "k"},
		"hysteria2 no pin":       {V: 1, Server: "a", Port: 1},
		"hysteria2 bad pin":      {V: 1, Server: "a", Port: 1, TLSSPKISHA256: "not-a-pin"},
		"hysteria2 wrong ver":    {V: 2, Server: "a", Port: 1, TLSSPKISHA256: pin},
		"hysteria2 no server":    {V: 1, Port: 1, TLSSPKISHA256: pin},
		"hysteria2 port 0":       {V: 1, Server: "a", TLSSPKISHA256: pin},
		"naive with sni":         {V: 1, Server: "a", Port: 1, TLSSPKISHA256: pin, ServerName: "x"},
		"shadowsocks no digest":  {V: 1, Server: "a", Port: 1, SSMethod: "m"},
		"shadowsocks with a pin": {V: 1, Server: "a", Port: 1, SSMethod: "m", SSServerKeySHA256: SSServerKeyDigest("k"), TLSSPKISHA256: pin},
	}
	for name, ep := range bad {
		family := strings.Fields(name)[0]
		if err := ep.Validate(family); !errors.Is(err, ErrEndpointMalformed) {
			t.Errorf("%s: err=%v, want ErrEndpointMalformed", name, err)
		}
	}
	if err := (&Endpoint{V: 1, Server: "a", Port: 1}).Validate("wireguard"); !errors.Is(err, ErrEndpointMalformed) {
		t.Errorf("a family with no rule must not validate: %v", err)
	}
}

func TestParseEndpoint(t *testing.T) {
	if _, err := ParseEndpoint(json.RawMessage(`{"port":443}`)); !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("absent: %v", err)
	}
	if _, err := ParseEndpoint(nil); !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("empty: %v", err)
	}
	ep, err := ParseEndpoint(json.RawMessage(`{"_endpoint":{"v":1,"server":"203.0.113.10","port":443,"server_name":"c","reality_public_key":"k"}}`))
	if err != nil || ep.Server != "203.0.113.10" || ep.Port != 443 {
		t.Fatalf("parse: %+v %v", ep, err)
	}
	// A member this build does not know is a commitment it would not
	// enforce: refuse rather than ignore.
	if _, err := ParseEndpoint(json.RawMessage(`{"_endpoint":{"v":1,"server":"a","port":1,"also_trust":"x"}}`)); !errors.Is(err, ErrEndpointMalformed) {
		t.Fatalf("unknown member: %v", err)
	}
}

// MergeEndpoint is the freshness path's swap: new signed endpoint,
// credentials the device already holds.
func TestMergeEndpoint_KeepsCredentialsAppliesSignedEndpoint(t *testing.T) {
	for _, tc := range endpointCases(t) {
		tc := tc
		t.Run(tc.family, func(t *testing.T) {
			// L3: the relay moved to a new address.
			moved := tc.ep
			moved.Server = "198.51.100.200"
			if moved.ServerName == tc.ep.Server {
				moved.ServerName = moved.Server
			}
			if tc.family == "naive" {
				// naive can only follow when its certificate has a name
				// that does not depend on the address (covered below).
				return
			}
			out, err := MergeEndpoint(tc.family, &moved, mustJSON(t, tc.outbound))
			if err != nil {
				t.Fatalf("merge: %v", err)
			}
			if err := CheckOutbound(tc.family, &moved, out); err != nil {
				t.Fatalf("merged outbound does not match the new commitment: %v", err)
			}
			var got map[string]any
			_ = json.Unmarshal(out, &got)
			if got["server"] != "198.51.100.200" {
				t.Fatalf("server not moved: %v", got["server"])
			}
			for _, k := range []string{"uuid", "password", "username"} {
				if want, ok := tc.outbound[k]; ok && got[k] != want {
					t.Fatalf("credential %q changed in the merge: %v -> %v", k, want, got[k])
				}
			}
		})
	}
}

func TestMergeEndpoint_L2CoverHostAndKeyMove(t *testing.T) {
	tc := endpointCases(t)[0] // vless-reality
	rotated := tc.ep
	rotated.ServerName = "new-cover.example"
	rotated.RealityPublicKey = "NEWREALITYKEY"
	out, err := MergeEndpoint(tc.family, &rotated, mustJSON(t, tc.outbound))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	tls := got["tls"].(map[string]any)
	if tls["server_name"] != "new-cover.example" || tls["reality"].(map[string]any)["public_key"] != "NEWREALITYKEY" {
		t.Fatalf("signed endpoint not applied: %v", tls)
	}
	if tls["reality"].(map[string]any)["short_id"] != "ab" || got["uuid"] != "u-1" {
		t.Fatalf("credentials not kept: %v", got)
	}
}

func TestMergeEndpoint_RefusesWhatCannotBelongToTheNewRelay(t *testing.T) {
	cases := endpointCases(t)
	// A profile with no outbound holds nothing to keep.
	if _, err := MergeEndpoint("hysteria2", &cases[2].ep, []byte(`{"port":443,"_relaypack":{}}`)); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("skeleton profile: %v", err)
	}
	// naive after a REBUILD: the box has a new key; the certificate the
	// device trusts is the old box's. That route needs a new file.
	var naive endpointCase
	for _, c := range cases {
		if c.family == "naive" {
			naive = c
		}
	}
	_, otherPin := testCert(t, []string{"203.0.113.10"}, nil)
	rebuilt := naive.ep
	rebuilt.TLSSPKISHA256 = otherPin
	if _, err := MergeEndpoint("naive", &rebuilt, mustJSON(t, naive.outbound)); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("naive with a stale certificate must not merge: %v", err)
	}
	// shadowsocks after the server key changed.
	ss := cases[len(cases)-1]
	rekeyed := ss.ep
	rekeyed.SSServerKeySHA256 = SSServerKeyDigest("b3RoZXJvdGhlcm90aGVybw==")
	if _, err := MergeEndpoint("shadowsocks", &rekeyed, mustJSON(t, ss.outbound)); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("shadowsocks with a stale server key must not merge: %v", err)
	}
	// A device outbound of another family is never repurposed.
	if _, err := MergeEndpoint("hysteria2", &cases[2].ep, mustJSON(t, cases[0].outbound)); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("cross-family merge: %v", err)
	}
}

// LC-3. The certificate names the first-boot address. After an address
// move the name to verify against is the certificate's DNS name; before
// one it is the address, so nothing new goes on the wire.
func TestNaiveVerificationName(t *testing.T) {
	withName, _ := testCert(t, []string{"203.0.113.10"}, []string{"cover.example"})
	ipOnly, _ := testCert(t, []string{"203.0.113.10"}, nil)
	cases := []struct {
		name, server, pem, want string
	}{
		{"address the certificate names", "203.0.113.10", withName, "203.0.113.10"},
		{"moved address, certificate has a name", "198.51.100.200", withName, "cover.example"},
		{"moved address, certificate has no name", "198.51.100.200", ipOnly, "198.51.100.200"},
		{"hostname the certificate names", "cover.example", withName, "cover.example"},
		{"no certificate", "203.0.113.10", "", "203.0.113.10"},
		{"garbage", "203.0.113.10", "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n", "203.0.113.10"},
	}
	for _, c := range cases {
		var pems []string
		if c.pem != "" {
			pems = []string{c.pem}
		}
		if got := NaiveVerificationName(c.server, pems); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// A naive route whose certificate carries a stable name follows the
// relay to a new address through a merge, with no new file.
func TestMergeEndpoint_NaiveFollowsAnAddressMove(t *testing.T) {
	certPEM, pin := testCert(t, []string{"203.0.113.10"}, []string{"cover.example"})
	device := map[string]any{"type": "naive", "tag": "active", "server": "203.0.113.10", "server_port": 8444,
		"username": "r1", "password": "p-1",
		"tls": map[string]any{"enabled": true, "server_name": "203.0.113.10", "certificate": []any{certPEM}}}
	moved := Endpoint{V: 1, Server: "198.51.100.200", Port: 8444, TLSSPKISHA256: pin}
	out, err := MergeEndpoint("naive", &moved, mustJSON(t, device))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["server"] != "198.51.100.200" || got["tls"].(map[string]any)["server_name"] != "cover.example" {
		t.Fatalf("naive did not follow the move: server=%v server_name=%v", got["server"], got["tls"].(map[string]any)["server_name"])
	}
	if got["password"] != "p-1" || got["username"] != "r1" {
		t.Fatalf("credentials not kept: %v", got)
	}
}

func TestProfileOutboundTypeAndUnavailable(t *testing.T) {
	if ProfileOutboundType([]byte(`{"type":"vless"}`)) != "vless" {
		t.Fatal("type")
	}
	for _, p := range []string{`{"port":443,"_relaypack":{}}`, `{"_daal_unavailable":{"family":"tuic"}}`, `not json`, `{"type":" "}`, ``} {
		if ProfileOutboundType([]byte(p)) != "" {
			t.Fatalf("%q must hold no outbound", p)
		}
	}
	if !ProfileUnavailable([]byte(`{"_daal_unavailable":{"family":"tuic","reason":"x"},"port":8443}`)) {
		t.Fatal("marker not seen")
	}
	if ProfileUnavailable([]byte(`{"port":443}`)) {
		t.Fatal("skeleton is not a marker")
	}
}

// sing-box matches a JSON member to a field without regard to case,
// with Unicode simple folding (U+017F "ſ" is an s, U+212A "K" is a k),
// and where two members fold onto one field the later one wins. The
// engine re-marshals a profile with its keys in byte order, so a
// non-ASCII spelling always lands after the genuine one. A profile
// could therefore leave every signed value in place under its exact
// name — so every equality in CheckOutbound held — and carry the
// attacker's value under a second spelling that only sing-box read.
// These are the three profiles from the review that found it, built as
// raw bytes so the genuine member really is still there.
func TestCheckOutbound_RefusesFoldedKeySpellings(t *testing.T) {
	_, otherPin := testCert(t, []string{"198.51.100.66"}, nil)
	byFamily := map[string]endpointCase{}
	for _, tc := range endpointCases(t) {
		byFamily[tc.family] = tc
	}
	// splice inserts `member` as the first member of the object that
	// follows `anchor` in raw ("" = the outbound itself).
	splice := func(t *testing.T, raw []byte, anchor, member string) []byte {
		t.Helper()
		s := string(raw)
		at := 0
		if anchor != "" {
			at = strings.Index(s, anchor)
			if at < 0 {
				t.Fatalf("no %s in %s", anchor, s)
			}
			at += len(anchor)
		}
		if s[at] != '{' {
			t.Fatalf("no object at %d in %s", at, s)
		}
		return []byte(s[:at+1] + member + "," + s[at+1:])
	}
	cases := []struct {
		name, family, anchor, member string
	}{
		// 1. dial another server, authenticated by another REALITY key.
		{"long-s server", "vless-reality", "", `"\u017ferver":"198.51.100.66"`},
		{"long-s server, literal", "vless-reality", "", `"ſerver":"198.51.100.66"`},
		{"reality public_Key", "vless-reality", `"reality":`, `"public_Key":"ATTACKERKEY"`},
		{"reality public_kelvin-ey", "vless-reality", `"reality":`, `"public_\u212aey":"ATTACKERKEY"`},
		// 2. a second pin for the pinned families.
		{"long-s pin", "hysteria2", `"tls":`, `"certificate_public_key_\u017fha256":["` + otherPin + `"]`},
		{"upper-case pin", "tuic", `"tls":`, `"Certificate_Public_Key_Sha256":["` + otherPin + `"]`},
		// 3. plain ASCII spellings of members that must be absent.
		{"Insecure", "hysteria2", `"tls":`, `"Insecure":true`},
		{"INSECURE", "websocket-tls", `"tls":`, `"INSECURE":true`},
		{"Server_Ports", "hysteria2", "", `"Server_Ports":["1:65535"]`},
		{"Detour", "anytls", "", `"Detour":"direct"`},
		{"Server_Port", "tuic", "", `"Server_Port":4443`},
		{"long-s server_name", "vless-reality", `"tls":`, `"\u017ferver_name":"blocked.example"`},
		{"naive Certificate", "naive", `"tls":`, `"Certificate":["x"]`},
		{"shadowsocks Password", "shadowsocks", "", `"Password":"YXR0YWNrZXJhdHRhY2tlcg==:dVBTS3VQU0t1UFNLdVBTSw=="`},
		{"shadowsocks Tls", "shadowsocks", "", `"Tls":{"enabled":true}`},
		// Not a field today; the rule is about the name, not a list.
		{"unknown non-ASCII member", "anytls", "", `"caf\u00e9":1`},
		{"empty member name", "anytls", "", `"":1`},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			tc := byFamily[c.family]
			genuine := mustJSON(t, tc.outbound)
			if err := CheckOutbound(tc.family, &tc.ep, genuine); err != nil {
				t.Fatalf("genuine outbound refused: %v", err)
			}
			raw := splice(t, genuine, c.anchor, c.member)
			var probe map[string]any
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("test profile is not JSON: %v\n%s", err, raw)
			}
			// The genuine values are all still there under their exact
			// names: that is what made this pass before.
			if probe["server"] != tc.outbound["server"] {
				t.Fatalf("test profile lost the genuine server: %s", raw)
			}
			if err := CheckOutbound(tc.family, &tc.ep, raw); !errors.Is(err, ErrEndpointMismatch) {
				t.Fatalf("a second spelling of a checked member was not refused: err=%v\n%s", err, raw)
			}
			// The freshness merge checks its own result, so it cannot
			// carry such a member from a stored profile into a new one.
			if _, err := MergeEndpoint(tc.family, &tc.ep, raw); !errors.Is(err, ErrEndpointMismatch) {
				t.Fatalf("merge kept a second spelling of a checked member: err=%v", err)
			}
		})
	}
}

// What the rule does NOT touch: names below the three walked objects.
// A websocket route's HTTP headers are mixed-case by nature.
func TestCheckOutbound_KeyRuleStopsAtTLSAndReality(t *testing.T) {
	for _, tc := range endpointCases(t) {
		if tc.family != "websocket-tls" {
			continue
		}
		ob := clone(t, tc.outbound)
		ob["transport"].(map[string]any)["headers"] = map[string]any{"Host": "cover.example", "User-Agent": "x"}
		if err := CheckOutbound(tc.family, &tc.ep, mustJSON(t, ob)); err != nil {
			t.Fatalf("mixed-case transport header names were refused: %v", err)
		}
	}
}
