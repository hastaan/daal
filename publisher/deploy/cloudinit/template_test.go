package cloudinit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Test-fixture sentinels (NOT real cryptographic material).
// All four are visible-prefix placeholders so secret-scanners do
// not flag them. FRP-7 release pipeline never touches this file.
const (
	fixtureSSHKey      = "TEST-FIXTURE-NOT-A-REAL-KEY ssh-ed25519 PUB daal-deploy"
	fixtureHelperIP    = "1.2.3.4"
	fixtureHealthToken = "changeme-not-a-real-value-test-only"
	fixtureSingBox     = `{"log":{"level":"info"},"inbounds":[]}`
)

// fixedInput returns a fixed RenderInput for golden-byte tests.
// FRP-7's release pipeline updates the pinned-artefact placeholders;
// the rest of the template is locked at FRP-4a.
func fixedInput() RenderInput {
	return RenderInput{
		EphemeralSSHPublicKey: fixtureSSHKey,
		ProvisioningClientIP:  fixtureHelperIP,
		HealthToken:           fixtureHealthToken,
		SingBoxConfigJSON:     fixtureSingBox,
	}
}

func TestRender_DeterministicForFixedInput(t *testing.T) {
	a, err := Render(fixedInput())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(fixedInput())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("Render must be deterministic for fixed input; differ")
	}
}

func TestRender_RoundTripsThroughYAMLv3(t *testing.T) {
	body, err := Render(fixedInput())
	if err != nil {
		t.Fatal(err)
	}
	// The cloud-init document begins with #cloud-config and is
	// otherwise a YAML document. Parse the YAML body.
	var doc map[string]any
	// Strip the #cloud-config first-line comment for the parser.
	yamlBody := body
	if i := bytes.IndexByte(yamlBody, '\n'); i >= 0 && bytes.HasPrefix(yamlBody, []byte("#")) {
		yamlBody = yamlBody[i+1:]
	}
	if err := yaml.Unmarshal(yamlBody, &doc); err != nil {
		t.Fatalf("rendered YAML does not parse: %v\nbody:\n%s", err, body)
	}
	for _, key := range []string{
		"hostname", "packages", "users", "ssh_authorized_keys",
		"write_files", "runcmd", "final_message",
	} {
		if _, ok := doc[key]; !ok {
			t.Errorf("rendered YAML missing top-level key %q", key)
		}
	}
}

func TestRender_EmbedsHelperIPInUFWRules(t *testing.T) {
	body, _ := Render(fixedInput())
	src := string(body)
	for _, want := range []string{
		"ufw allow from 1.2.3.4 to any port 22 proto tcp",
		"ufw allow from 1.2.3.4 to any port 9876 proto tcp",
		"ufw --force delete allow from 1.2.3.4 to any port 22 proto tcp",
		"ufw --force delete allow from 1.2.3.4 to any port 9876 proto tcp",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("rendered YAML missing rule %q", want)
		}
	}
}

func TestRender_EmbedsHealthToken(t *testing.T) {
	body, _ := Render(fixedInput())
	wantSubstring := []byte(fixtureHealthToken)
	if !bytes.Contains(body, wantSubstring) {
		t.Errorf("rendered YAML missing fixtureHealthToken; body:\n%s", body)
	}
}

func TestRender_EmbedsDaalUserPosture(t *testing.T) {
	body, _ := Render(fixedInput())
	src := string(body)
	for _, want := range []string{
		"name: daal",
		"sudo: false",
		"shell: /usr/sbin/nologin",
		"lock_passwd: true",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("rendered YAML missing daal-user posture %q", want)
		}
	}
}

func TestRender_EmbedsSSHSelfDestructAndUFWClose(t *testing.T) {
	body, _ := Render(fixedInput())
	src := string(body)
	for _, want := range []string{
		"sleep 60",
		"rm -f /root/.ssh/authorized_keys",
		"systemctl disable --now ssh.service",
		"systemctl stop daal-health",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("rendered YAML missing self-destruct line %q", want)
		}
	}
}

func TestRender_RejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		mut  func(in *RenderInput)
	}{
		{"no-ssh-key", func(in *RenderInput) { in.EphemeralSSHPublicKey = "" }},
		{"no-helper-ip", func(in *RenderInput) { in.ProvisioningClientIP = "" }},
		{"no-token", func(in *RenderInput) { in.HealthToken = "" }},
		{"no-singbox", func(in *RenderInput) { in.SingBoxConfigJSON = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixedInput()
			tc.mut(&in)
			if _, err := Render(in); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

// TestVerifierShim_LineCount pins the shim at <= 60 lines per phase
// doc invariant 19 (shim uses only base-image tools, kept minimal).
func TestVerifierShim_LineCount(t *testing.T) {
	n := VerifierShimLineCount()
	if n > 60 {
		t.Errorf("verifier shim too long: %d lines (≤60)", n)
	}
	if n < 20 {
		t.Errorf("verifier shim suspiciously short: %d lines", n)
	}
}

// TestVerifierShim_SHA256Pinned captures the shim's SHA-256 so
// FRP-7 / FRP-8 amendments are auditable. If the shim changes
// legitimately, update this constant in the same commit.
func TestVerifierShim_SHA256Pinned(t *testing.T) {
	const want = "fa6e2f0ccb246156899ed4db508085985986c2a65e27efad044e6cddb3735e63"
	got := sha256.Sum256(VerifierShimSource())
	gotHex := hex.EncodeToString(got[:])
	if gotHex != want {
		t.Errorf("verifier shim sha256 drift: got %s want %s", gotHex, want)
	}
}

// TestVerifierShim_UsesOnlyBaseImageTools enforces invariant 19
// by scanning the shim source for forbidden binary references.
func TestVerifierShim_UsesOnlyBaseImageTools(t *testing.T) {
	src := string(VerifierShimSource())
	allowed := []string{"bash", "python3", "openssl", "urllib", "hashlib", "subprocess", "tempfile"}
	forbidden := []string{"wget", "git", "go", "rustc", "cargo", "npm"}
	for _, w := range forbidden {
		if strings.Contains(src, w+" ") || strings.Contains(src, " "+w) {
			t.Errorf("shim uses forbidden tool %q (invariant 19)", w)
		}
	}
	have := 0
	for _, a := range allowed {
		if strings.Contains(src, a) {
			have++
		}
	}
	if have == 0 {
		t.Errorf("shim uses none of the allowed tools (something is very wrong)")
	}
}

// TestRender_GoldenSHA256 pins the rendered cloud-init bytes for
// the fixed input. FRP-8 amends this when adding cdn_fronted; the
// drift is then auditable in the diff.
func TestRender_GoldenSHA256(t *testing.T) {
	body, err := Render(fixedInput())
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(body)
	gotHex := hex.EncodeToString(got[:])
	// FRP-8: the conditional `{{ if .CDNEnabled }}` block introduces
	// a tiny whitespace pad even when disabled. Re-pinned post FRP-8.
	const want = "812e322f9389244241f09e719a0dc10b52e3dbedb1c5f5d1aa0fe67fe7a382cc"
	if gotHex != want {
		t.Errorf("rendered cloud-init drift: got %s want %s", gotHex, want)
	}
}

// TestPinnedArtefactManifest_Shape pins the V1.5 artefact set
// shape: 2 entries (sing-box + daal-relay-health), each with
// at least 2 mirrors, sha256+sig_hex non-empty (placeholders
// are non-empty strings at FRP-4a).
func TestPinnedArtefactManifest_Shape(t *testing.T) {
	if V15Artifacts.Version == "" {
		t.Errorf("V15Artifacts.Version empty")
	}
	if len(V15Artifacts.Artefacts) != 2 {
		t.Fatalf("V1.5 artefact count = %d; want 2", len(V15Artifacts.Artefacts))
	}
	wantNames := map[string]bool{"sing-box": false, "daal-relay-health": false}
	for _, a := range V15Artifacts.Artefacts {
		if a.Sha256 == "" || a.SigHex == "" {
			t.Errorf("artefact %s missing sha256/sig_hex", a.Name)
		}
		if len(a.Mirrors) < 2 {
			t.Errorf("artefact %s needs ≥2 mirrors; got %d", a.Name, len(a.Mirrors))
		}
		if _, ok := wantNames[a.InstallAs]; ok {
			wantNames[a.InstallAs] = true
		}
	}
	for n, ok := range wantNames {
		if !ok {
			t.Errorf("expected install_as %q in manifest", n)
		}
	}
}

// FRP-10 commit 6: V2 cloud-init template tests.

func fixedInputV2() RenderInputV2 {
	return RenderInputV2{
		RenderInput:   fixedInput(),
		MgmtPubKeyHex: hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)),
		MgmtPort:      42424,
	}
}

func TestRenderV2_DeterministicForFixedInput(t *testing.T) {
	a, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("RenderV2 not deterministic")
	}
}

func TestRenderV2_InstallsMgmtUnit(t *testing.T) {
	body, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	wants := []string{
		"daal-relay-mgmt.service",
		"systemctl enable --now daal-relay-mgmt",
		"/etc/daal/mgmt/pubkey",
		"/etc/daal/mgmt/port",
		"42424",
	}
	for _, w := range wants {
		if !bytes.Contains(body, []byte(w)) {
			t.Errorf("V2 template missing %q", w)
		}
	}
}

func TestRenderV2_NoBoxTokenInTemplate(t *testing.T) {
	// FRP-10 invariant 18 + supplement §10: no cloud-provider
	// token ever lands on the box. The cloud-init template must
	// not embed any cloud-provider API token (Hetzner / Vultr /
	// Stark / Cloudflare). The mgmt-plane pubkey is publisher-
	// issued, not a cloud-provider token.
	body, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"HCLOUD_TOKEN",
		"VULTR_API_KEY",
		"STARK_API_KEY",
		"CLOUDFLARE_API_TOKEN",
		"CF_API_TOKEN",
	}
	for _, f := range forbidden {
		if bytes.Contains(body, []byte(f)) {
			t.Errorf("V2 template contains forbidden token marker %q (invariant 18)", f)
		}
	}
}

func TestRenderV2_MgmtPortFromInput(t *testing.T) {
	// Different ports must produce different outputs (no
	// hardcoded constant).
	in1 := fixedInputV2()
	in1.MgmtPort = 12345
	b1, err := RenderV2(in1)
	if err != nil {
		t.Fatal(err)
	}
	in2 := fixedInputV2()
	in2.MgmtPort = 54321
	b2, err := RenderV2(in2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b1, b2) {
		t.Errorf("V2 template ignores MgmtPort (must vary by port)")
	}
	if !bytes.Contains(b1, []byte("12345")) {
		t.Errorf("port 12345 missing from output")
	}
	if !bytes.Contains(b2, []byte("54321")) {
		t.Errorf("port 54321 missing from output")
	}
}

func TestRenderV2_RejectsBadPort(t *testing.T) {
	for _, p := range []int{0, 1, 80, 443, 9999, 65001, 70000, -1} {
		in := fixedInputV2()
		in.MgmtPort = p
		if _, err := RenderV2(in); err == nil {
			t.Errorf("port %d must be rejected", p)
		}
	}
}

func TestRenderV2_RejectsMissingPubkey(t *testing.T) {
	in := fixedInputV2()
	in.MgmtPubKeyHex = ""
	if _, err := RenderV2(in); err == nil {
		t.Errorf("missing MgmtPubKeyHex must be rejected")
	}
}

func TestRenderV1vsV2Selection(t *testing.T) {
	// V1 output must NOT contain the V2 mgmt-plane unit.
	v1, err := Render(fixedInput())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(v1, []byte("daal-relay-mgmt.service")) {
		t.Errorf("V1 template contains V2 mgmt unit")
	}
	if bytes.Contains(v1, []byte("/etc/daal/mgmt/")) {
		t.Errorf("V1 template references V2 mgmt paths")
	}
	// V2 output MUST contain it.
	v2, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(v2, []byte("daal-relay-mgmt.service")) {
		t.Errorf("V2 template does not install mgmt unit")
	}
}

// silence unused-import warnings on environments that strip
// strings/sha256 if the V1 tests above are pruned.
var (
	_ = strings.TrimSpace
	_ = sha256.New
)

// yaml import is referenced by the V1 tests. Ensure it stays.
var _ = yaml.Unmarshal
