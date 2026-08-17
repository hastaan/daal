package hetzner

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/relaypack"
	"daal/publisher/deploy/sni"
)

// The cover-host chain has exactly one place where its two halves can be
// compared automatically, and this is it.
//
// The box half (cloud-init's sing-box config) and the client half (the
// minted pack's outbound) are each internally consistent, so a mismatch
// between them is invisible to every other test in the tree — it shows
// up only on the wire, as a REALITY handshake that fails the SNI check
// before authentication and gets mirrored to the cover site. This test
// renders both from the same seed and asserts three things:
//
//  1. the box's tls.server_name and reality.handshake.server are ONE
//     string (a REALITY inbound whose advertised name and fallback dest
//     disagree is the probe mismatch REALITY exists to prevent);
//  2. the client outbound advertises exactly that string;
//  3. the real sing-box 1.13.12 parser — which is strict, and which
//     FATALs rather than warns — accepts the box config.
//
// It also proves two relays get DIFFERENT hosts, which is the entire
// point of Wave 2 Step 4.
//
// Skipped unless a sing-box binary is present: the release artefact is
// gitignored, so CI without it still runs everything up to step 3.
func TestCoverSNI_BoxAndPackAgree_RealSingBox(t *testing.T) {
	bin := singboxBinaryForTest(t)

	certPath, keyPath := selfSignedForTest(t)

	type relay struct{ region, seed string }
	relays := []relay{
		{"fsn1", "daal-fsn1-aaaaaaaaaaaaaaaa"},
		{"hel1", "daal-hel1-bbbbbbbbbbbbbbbb"},
	}
	seen := map[string]string{}

	for _, r := range relays {
		host := sni.Pick(r.seed, r.region)
		if host == "" {
			t.Fatalf("%s: pool produced no host", r.region)
		}
		if prev, dup := seen[host]; dup {
			t.Errorf("relays %q and %q both drew %q — the pool is not giving per-relay diversity",
				prev, r.region, host)
		}
		seen[host] = r.region

		body := defaultSingBoxConfig("iran-default", host)
		if strings.Contains(body, sni.LegacyCoverSNI) {
			t.Fatalf("%s: box config still names the fleet-wide constant", r.region)
		}

		// (1) one string, two required sites.
		var doc map[string]any
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("%s: box config is not JSON: %v", r.region, err)
		}
		in, _ := doc["inbounds"].([]any)[0].(map[string]any)
		tlsB, _ := in["tls"].(map[string]any)
		advertised, _ := tlsB["server_name"].(string)
		reality, _ := tlsB["reality"].(map[string]any)
		hs, _ := reality["handshake"].(map[string]any)
		dest, _ := hs["server"].(string)
		if advertised != host || dest != host {
			t.Fatalf("%s: server_name=%q handshake.server=%q, want both %q",
				r.region, advertised, dest, host)
		}

		// (2) the pack the recipient actually gets.
		params := relaypack.ClientConnParams{
			Server:           "203.0.113.7",
			Name:             "r1",
			VLESSUUID:        "831c3050-b834-4165-ae73-18dc092df511",
			RealityShortID:   "f219cd8d",
			RealityPublicKey: "F3oIDzfjiaDmYwQgEJJlL5oGUdy5x0lllgs8_2ctxzo",
			CoverSNI:         host,
		}
		ob, err := relaypack.ClientOutboundForFamily("vless-reality", 443, params)
		if err != nil {
			t.Fatalf("%s: render client outbound: %v", r.region, err)
		}
		var obDoc struct {
			TLS struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
		}
		if err := json.Unmarshal(ob, &obDoc); err != nil {
			t.Fatal(err)
		}
		if obDoc.TLS.ServerName != advertised {
			t.Fatalf("%s: pack advertises %q, box serves %q — the REALITY tier is dead for every recipient",
				r.region, obDoc.TLS.ServerName, advertised)
		}

		// (3) the real parser. Fill in the two values cloud-init
		// substitutes at first boot and point the hy2 inbound at a cert
		// that exists on this machine; neither is part of what is under
		// test, and both are FATALs that would mask the schema result.
		runnable := strings.Replace(body, `"private_key": ""`,
			`"private_key": "cME1Aymm3sBpsq_LOR-avwT8Cy5b6vXQhSTBpIrhtVI"`, 1)
		runnable = strings.Replace(runnable, `"short_id": []`, `"short_id": ["f219cd8d"]`, 1)
		runnable = strings.ReplaceAll(runnable, "/etc/daal/tls-cert.pem", certPath)
		runnable = strings.ReplaceAll(runnable, "/etc/daal/tls-key.pem", keyPath)
		cfg := filepath.Join(t.TempDir(), "box.json")
		if err := os.WriteFile(cfg, []byte(runnable), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "check", "-c", cfg).CombinedOutput(); err != nil {
			t.Fatalf("%s: sing-box rejected the box config: %v\n%s", r.region, err, out)
		}
		t.Logf("%s -> %s (box config loads; pack agrees)", r.region, host)
	}
}

// singboxBinaryForTest finds a real sing-box, or skips.
func singboxBinaryForTest(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SINGBOX_BIN"); p != "" {
		return p
	}
	// The release artefact, at the path the relay images pin. Gitignored,
	// so its absence is normal and must not fail the gate.
	for _, p := range []string{
		"../../../../dist-release/relay-v1.5.0/sing-box-1.13.12-linux-amd64",
	} {
		if _, err := os.Stat(p); err == nil {
			abs, err := filepath.Abs(p)
			if err == nil {
				return abs
			}
		}
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	t.Skip("no sing-box binary (set SINGBOX_BIN to run the real-parser cross-check)")
	return ""
}

// selfSignedForTest makes the leaf the hy2 inbound needs. openssl is not
// a build dependency of this repo, so a missing one skips rather than
// fails.
func selfSignedForTest(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available for the hy2 inbound's leaf")
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls-cert.pem")
	keyPath = filepath.Join(dir, "tls-key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "2",
		"-subj", "/CN=203.0.113.7", "-addext", "subjectAltName=IP:203.0.113.7")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl failed: %v\n%s", err, out)
	}
	return certPath, keyPath
}
