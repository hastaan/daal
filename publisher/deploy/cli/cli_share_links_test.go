package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// users-share-links takes the same inputs as users-pack-sbp, prints
// {links, left_out} on stdout, and keeps every credential off stderr.
func TestUsersShareLinks_Verb(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	addEndpointMaterial(t, recPath)
	body, _ := os.ReadFile(recPath)
	var rec map[string]any
	_ = json.Unmarshal(body, &rec)
	server, _ := rec["public_ip"].(string)

	tmp := t.TempDir()
	out := filepath.Join(tmp, "rp.sbp")
	var so, se bytes.Buffer
	if rc := Run([]string{"bind-and-sign", "--operator-record", recPath, "--priv-key", privPath,
		"--output", out, "--phase", testPhase}, &so, &se); rc != 0 {
		t.Fatalf("bind-and-sign: rc=%d stderr=%s", rc, se.String())
	}

	const uuid = "11111111-2222-3333-4444-555555555555"
	creds := map[string]any{
		"name": "r1", "vless_uuid": uuid, "reality_short_id": "deadbeef",
		"hy2_password":       "hy2secretpassword22ch",
		"reality_public_key": fixtureRealityPub, "tls_cert_sha256": fixtureTLSPin,
		"cover_sni": rec["cover_sni"],
	}
	credsPath := filepath.Join(tmp, "creds.json")
	cb, _ := json.Marshal(creds)
	if err := os.WriteFile(credsPath, cb, 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		rc := Run(append([]string{"users-share-links"}, args...), &stdout, &stderr)
		return rc, stdout.String(), stderr.String()
	}

	rc, stdout, stderr := run("--in", out, "--creds-file", credsPath, "--server", server, "--label", "Home")
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr)
	}
	if strings.Contains(stderr, uuid) || strings.Contains(stderr, "vless://") {
		t.Fatal("a link or credential reached stderr")
	}
	var res struct {
		Links []struct {
			Way, Label, Link string
		} `json:"links"`
		LeftOut []struct {
			Way, Reason string
		} `json:"left_out"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not the JSON shape: %v", err)
	}
	var reality bool
	for _, l := range res.Links {
		if l.Way == "vless-reality" {
			reality = true
			if !strings.HasPrefix(l.Link, "vless://"+uuid+"@") || !strings.Contains(l.Link, "security=reality") ||
				l.Label != "Home · REALITY" {
				t.Errorf("reality link = %q label=%q", l.Link, l.Label)
			}
		}
		if strings.Contains(strings.ToLower(l.Link), "insecure") {
			t.Errorf("%s link carries insecure", l.Way)
		}
	}
	if !reality {
		t.Fatalf("no REALITY link: %s", stdout)
	}
	if res.LeftOut == nil {
		t.Error("left_out must be present (possibly empty)")
	}

	// The relay moved since signing: no links, a loud error.
	if rc, stdout, stderr := run("--in", out, "--creds-file", credsPath, "--server", "203.0.113.77"); rc == 0 ||
		!strings.Contains(stderr, "bind-and-sign again") || stdout != "" {
		t.Fatalf("moved relay: rc=%d stdout=%q stderr=%s", rc, stdout, stderr)
	}
	// Secrets are never taken from argv: there is no flag for them.
	if rc, _, _ := run("--in", out, "--server", server); rc != 2 {
		t.Fatalf("missing --creds-file: rc=%d, want 2", rc)
	}
}
