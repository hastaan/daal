package cloudinit

import (
	"strconv"
	"strings"
	"testing"

	"daal/publisher/deploy/relayports"
)

// B-1/B-2: the box-side ufw opens the CDN door to Cloudflare's ranges
// only, rendered at provision time; without ranges nothing about the
// door appears.
func TestRenderV2_CDNDoorOpenToCloudflareRangesOnly(t *testing.T) {
	port := strconv.Itoa(relayports.CDNOrigin.Port)

	plain, err := RenderV2(fixedInputV2())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "port "+port) {
		t.Fatalf("a relay rendered without ranges opens the CDN door")
	}

	in := fixedInputV2()
	in.CDNEdgeRanges = []string{"173.245.48.0/20", "2400:cb00::/32", "173.245.48.0/20"}
	body, err := RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, want := range []string{
		"run ufw allow from 173.245.48.0/20 to any port " + port + " proto tcp",
		"run ufw allow from 2400:cb00::/32 to any port " + port + " proto tcp",
	} {
		if strings.Count(s, want) != 1 {
			t.Errorf("want exactly one %q", want)
		}
	}
	if strings.Contains(s, "ufw allow "+port) {
		t.Error("the CDN door must never be opened to everyone")
	}
	// Every other byte is the plain render: the block only adds lines.
	var extra []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(string(plain), l) {
			extra = append(extra, l)
		}
	}
	for _, l := range extra {
		if !strings.Contains(l, "port "+port) && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			t.Errorf("unexpected new line %q", l)
		}
	}
}

func TestRenderV2_CDNRangesRefusesAnythingButACIDR(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "1.2.3.4", "1.2.3.0/24; rm -rf /", "x"} {
		in := fixedInputV2()
		in.CDNEdgeRanges = []string{bad}
		if _, err := RenderV2(in); err == nil {
			t.Errorf("RenderV2 accepted CDN range %q", bad)
		}
	}
	in := fixedInputV2()
	for i := 0; i <= maxCDNEdgeRanges; i++ {
		in.CDNEdgeRanges = append(in.CDNEdgeRanges, "10."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250)+".0/24")
	}
	if _, err := RenderV2(in); err == nil {
		t.Error("RenderV2 accepted an over-long range list")
	}
}

// The door's private key never rides in user-data.
func TestRenderV2_RefusesCDNCertificatesInUserData(t *testing.T) {
	in := fixedInputV2()
	in.OriginCACertPEM = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
	in.OriginCAPrivPEM = "-----BEGIN EC PRIVATE KEY-----\nX\n-----END EC PRIVATE KEY-----\n"
	in.AOPClientCertPEM = in.OriginCACertPEM
	if _, err := RenderV2(in); err == nil || !strings.Contains(err.Error(), "daal-relay-mgmt") {
		t.Fatalf("want a refusal naming the mgmt path, got %v", err)
	}
}
