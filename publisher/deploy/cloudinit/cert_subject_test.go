package cloudinit

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The data-plane certificate cloud-init mints is served to anybody who
// completes a handshake on 8444, 8445 or 443/udp. It used to carry
// CN=daal-relay on every relay (review C1). These tests read what a
// freshly provisioned relay would present, by running the template's
// own minting lines through bash and openssl.

// mintSnippet cuts the certificate-minting lines out of a rendered V2
// user-data, dedented, with /etc/daal/ pointed at dir.
func mintSnippet(t *testing.T, userData, dir string) string {
	t.Helper()
	start := strings.Index(userData, `DAAL_SAN="IP:${DAAL_IP4}"`)
	end := strings.Index(userData, `-addext "subjectAltName=${DAAL_SAN}"`)
	if start < 0 || end < start {
		t.Fatal("rendered V2 user-data has no certificate-minting block where this test expects it")
	}
	end += len(`-addext "subjectAltName=${DAAL_SAN}"`)
	var b strings.Builder
	for _, line := range strings.Split(userData[start:end], "\n") {
		b.WriteString(strings.TrimPrefix(line, "    "))
		b.WriteByte('\n')
	}
	return strings.ReplaceAll(b.String(), "/etc/daal/", dir+"/")
}

func mintAs(t *testing.T, coverSNI, ip4, ip6 string) *x509.Certificate {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	in := fixedInputV2()
	if coverSNI != "" {
		in.SingBoxConfigJSON = realityConfig(coverSNI, coverSNI)
		in.CoverSNI = coverSNI
	}
	body, err := RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := "set -euo pipefail\nrun() { \"$@\"; }\n" +
		"DAAL_IP4=" + ip4 + "\nDAAL_IP6=" + ip6 + "\n" +
		mintSnippet(t, string(body), dir)
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("minting block failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tls-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no certificate written")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func namesApp(c *x509.Certificate) bool {
	return strings.Contains(strings.ToLower(c.Subject.String()+" "+c.Issuer.String()), "daal")
}

func TestRenderV2_DataPlaneCertificateNamesNothing(t *testing.T) {
	for _, tc := range []struct {
		name, cover, ip4, ip6, wantCN string
	}{
		{"cover host", "mirror.dogado.de", "203.0.113.10", "2001:db8::10", "mirror.dogado.de"},
		{"no cover host", "", "203.0.113.10", "", "203.0.113.10"},
		{"cover host past the CN bound", strings.Repeat("a", 60) + ".example.org", "203.0.113.10", "", "203.0.113.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mintAs(t, tc.cover, tc.ip4, tc.ip6)
			if namesApp(c) {
				t.Errorf("a stranger reads subject %q issuer %q", c.Subject, c.Issuer)
			}
			if c.Subject.CommonName != tc.wantCN || len(c.Subject.Names) != 1 {
				t.Errorf("subject = %q, want exactly CN=%s", c.Subject, tc.wantCN)
			}
			// The subject repeats a SAN: it says nothing the certificate
			// did not already say.
			inSAN := false
			for _, n := range c.DNSNames {
				inSAN = inSAN || n == tc.wantCN
			}
			for _, ip := range c.IPAddresses {
				inSAN = inSAN || ip.String() == tc.wantCN
			}
			if !inSAN {
				t.Errorf("CN %q is not one of the certificate's own names (%v %v)", tc.wantCN, c.DNSNames, c.IPAddresses)
			}
			if err := c.CheckSignatureFrom(c); err != nil {
				t.Errorf("not self-signed: %v", err)
			}
		})
	}
}

// TestRender_HostnameNamesNothing: cloud-init sets the OS hostname,
// which the next banner or error page on the box would print.
func TestRender_HostnameNamesNothing(t *testing.T) {
	v1, err := Render(fixedInput())
	if err != nil {
		t.Fatal(err)
	}
	v2, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^(hostname|fqdn):\s*(.*)$`)
	for name, body := range map[string][]byte{"v1": v1, "v2": v2} {
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			if strings.Contains(strings.ToLower(m[2]), "daal") {
				t.Errorf("%s user-data sets %s: %s", name, m[1], m[2])
			}
		}
		if strings.Contains(string(body), "CN=daal") {
			t.Errorf("%s user-data still mints a certificate named after the app", name)
		}
	}
}
