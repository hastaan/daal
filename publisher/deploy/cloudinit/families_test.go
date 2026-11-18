package cloudinit

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"daal/publisher/deploy/relayports"
)

// cloudInitDoc is the part of a rendered cloud-init these tests read.
type cloudInitDoc struct {
	WriteFiles []struct {
		Path    string `yaml:"path"`
		Content string `yaml:"content"`
	} `yaml:"write_files"`
	RunCmd []any `yaml:"runcmd"`
}

func parseCloudInit(t *testing.T, body []byte) cloudInitDoc {
	t.Helper()
	var doc cloudInitDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("rendered cloud-init is not valid YAML: %v\n%s", err, body)
	}
	return doc
}

func (d cloudInitDoc) file(path string) (string, bool) {
	for _, wf := range d.WriteFiles {
		if wf.Path == path {
			return wf.Content, true
		}
	}
	return "", false
}

// ufwAllows returns the `ufw allow <port>/<proto>` arguments in a
// rendered cloud-init, in order (the source-bound and mgmt-port rules
// have a different shape and are not data-plane rules).
func ufwAllows(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		line = strings.TrimPrefix(line, "run ")
		if !strings.HasPrefix(line, "ufw allow ") {
			continue
		}
		arg := strings.TrimPrefix(line, "ufw allow ")
		if strings.HasSuffix(arg, "/tcp") || strings.HasSuffix(arg, "/udp") {
			out = append(out, arg)
		}
	}
	return out
}

// FAM-4. The box-side ufw opens exactly RenderInput.DataPlanePorts, in
// both templates. 443/tcp and 443/udp were literal lines in the
// templates, so a relay provisioned without vless-reality or hysteria2
// still had both open.
func TestRender_UFWOpensExactlyTheDataPlanePorts(t *testing.T) {
	narrow := relayports.FirewallPortsFor([]string{"shadowsocks", "anytls"})
	cases := []struct {
		name  string
		ports []relayports.Endpoint
		want  []string
	}{
		{"shadowsocks+anytls", narrow, []string{"8446/tcp", "8447/tcp"}},
		{"hysteria2 only", relayports.FirewallPortsFor([]string{"hysteria2"}), []string{"443/udp"}},
		{"no declared set", nil, []string{"443/tcp", "443/udp", "8444/tcp", "8445/tcp"}},
	}
	for _, tc := range cases {
		in := fixedInput()
		in.DataPlanePorts = tc.ports
		v15, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		in2 := fixedInputV2()
		in2.DataPlanePorts = tc.ports
		v2, err := RenderV2(in2)
		if err != nil {
			t.Fatal(err)
		}
		// Labels name the template FILE, not a RelayPack phase
		// (tools/check-phase.sh reads a bare phase string as one).
		for which, body := range map[string][]byte{"template.yaml": v15, "v2.yaml": v2} {
			got := ufwAllows(body)
			if which == "v2.yaml" {
				// The V2 template also opens the mgmt port; it is not a
				// data-plane rule.
				var dp []string
				for _, g := range got {
					if g != "42424/tcp" {
						dp = append(dp, g)
					}
				}
				got = dp
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("%s / %s: ufw opens %v, want exactly %v", tc.name, which, got, tc.want)
			}
		}
	}
}

// FAM-4 / W5-1. The box is told its own family set, one name per line,
// because daal-relay-mgmt creates four inbounds on first use and has no
// other way to know which of them this relay was asked to serve.
func TestRenderV2_WritesTheFamilySetForTheBox(t *testing.T) {
	in := fixedInputV2()
	in.Families = []string{"shadowsocks", "anytls"}
	body, err := RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseCloudInit(t, body).file("/etc/daal/families")
	if !ok {
		t.Fatal("cloud-init does not write /etc/daal/families")
	}
	if got != "shadowsocks\nanytls\n" {
		t.Errorf("/etc/daal/families = %q, want one family per line", got)
	}

	// No declared set: no file. The daemon then behaves as it did before
	// the file existed, which is the only honest reading of "unknown".
	body, err = RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseCloudInit(t, body).file("/etc/daal/families"); ok {
		t.Error("/etc/daal/families written for an input that declared no family set")
	}

	for _, bad := range [][]string{{""}, {"naive", "naive"}, {"x\n      y"}, {"Naive"}, {"a b"}} {
		in := fixedInputV2()
		in.Families = bad
		if _, err := RenderV2(in); err == nil {
			t.Errorf("RenderV2 accepted the family list %q", bad)
		}
	}
}

// A relay with no REALITY inbound must still provision: the first-boot
// REALITY keying used to `sys.exit("no reality inbound found")`, which
// fails the whole provision of any relay that does not serve
// vless-reality. It must also not state a cover host or a REALITY key.
func TestRenderV2_NoRealityInboundIsNotAProvisioningFailure(t *testing.T) {
	in := fixedInputV2() // fixtureSingBox has no inbounds at all
	in.CoverSNI = "mirror.example.net"
	body, err := RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if strings.Contains(src, "no reality inbound found") {
		t.Error("cloud-init still treats a config with no REALITY inbound as fatal")
	}
	for _, want := range []string{"sys.exit(3)", `case "$reality_rc" in`, "3) ;;", `*) fail "inject reality priv failed" ;;`} {
		if !strings.Contains(src, want) {
			t.Errorf("cloud-init is missing %q", want)
		}
	}
	if _, ok := parseCloudInit(t, body).file("/etc/daal/cover-sni"); ok {
		t.Error("/etc/daal/cover-sni written for a config with no REALITY inbound")
	}
}

// The provisioning script is bash inside YAML inside a Go template; a
// quoting slip there is a relay that never comes up, found only on a
// billed box. Parse what the box would run.
func TestRenderV2_ProvisioningScriptParses(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	for _, fams := range [][]string{nil, {"shadowsocks", "anytls"}, {"vless-reality", "hysteria2", "naive", "websocket-tls", "tuic"}} {
		in := fixedInputV2()
		in.Families = fams
		if fams != nil {
			in.DataPlanePorts = relayports.FirewallPortsFor(fams)
		}
		body, err := RenderV2(in)
		if err != nil {
			t.Fatal(err)
		}
		doc := parseCloudInit(t, body)
		if len(doc.RunCmd) != 1 {
			t.Fatalf("runcmd has %d entries, want the single provisioning script", len(doc.RunCmd))
		}
		script, _ := doc.RunCmd[0].(string)
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(script)
		var out bytes.Buffer
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("families %v: provisioning script does not parse: %v\n%s", fams, err, out.String())
		}
	}
}

// INT-O1. Applying a rewritten sing-box config is ONE reload: SIGHUP via
// the unit's ExecReload (sing-box 1.13 reloads in-process on SIGHUP),
// falling back to a restart. The wrapper used to send SIGUSR2 — which
// sing-box does not handle — and sleep two seconds first.
func TestRenderV2_ApplyWrapperIsOneReloadAndNoSleep(t *testing.T) {
	body, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	doc := parseCloudInit(t, body)
	wrapper, ok := doc.file("/usr/local/lib/daal/singbox-kick.sh")
	if !ok {
		t.Fatal("cloud-init does not install /usr/local/lib/daal/singbox-kick.sh (the mgmt daemon execs it)")
	}
	var cmds []string
	for _, line := range strings.Split(wrapper, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "set -eu" {
			continue
		}
		cmds = append(cmds, line)
	}
	const want = "systemctl reload sing-box.service || systemctl restart sing-box.service"
	if len(cmds) != 1 || cmds[0] != want {
		t.Errorf("apply wrapper runs %q, want exactly %q", cmds, want)
	}
	for _, bad := range []string{"USR2", "sleep"} {
		if strings.Contains(wrapper, bad) {
			t.Errorf("apply wrapper still contains %q", bad)
		}
	}
	unit, ok := doc.file("/etc/systemd/system/sing-box.service")
	if !ok {
		t.Fatal("no sing-box.service")
	}
	if !strings.Contains(unit, "ExecReload=/bin/kill -HUP $MAINPID\n") {
		t.Errorf("sing-box.service has no SIGHUP ExecReload, so `systemctl reload` is not applicable and every apply is a restart:\n%s", unit)
	}
}
