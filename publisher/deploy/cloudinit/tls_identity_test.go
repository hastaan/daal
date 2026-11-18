package cloudinit

import (
	"strings"
	"testing"
)

// The relay's data-plane certificate is minted once, at first boot. Two
// things about it are contracts with the publisher side:
//
//   - it names ONE stable DNS name beside the first-boot address, so the
//     naive route survives an L3 address move (the client verifies
//     against that name when the address it dials is not in the
//     certificate — bundle.NaiveVerificationName);
//   - the pin of its key is written where the provisioner reads it, so
//     bind-and-sign can commit every pinned route to it.
func TestRenderV2_DataPlaneCertificateIdentity(t *testing.T) {
	in := fixedInputV2()
	in.SingBoxConfigJSON = realityConfig("mirror.dogado.de", "mirror.dogado.de")
	in.CoverSNI = "mirror.dogado.de"
	body, err := RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, `DAAL_SAN="${DAAL_SAN},DNS:mirror.dogado.de"`) {
		t.Error("the certificate is not given a DNS name: naive cannot follow the relay to a new address")
	}
	if !strings.Contains(s, `-addext "subjectAltName=${DAAL_SAN}"`) {
		t.Error("the SAN list is not what openssl is handed")
	}
	// The DNS name is added BEFORE the certificate is minted.
	if strings.Index(s, "DNS:mirror.dogado.de") > strings.Index(s, "openssl req -x509") {
		t.Error("the DNS name is appended after the certificate was already minted")
	}
	if !strings.Contains(s, "> /etc/daal/tls-spki-sha256.b64") {
		t.Error("the TLS key pin is not written for the provisioner to read")
	}

	// No cover host (a relay without REALITY): no name is invented.
	in.CoverSNI = ""
	in.SingBoxConfigJSON = fixedInputV2().SingBoxConfigJSON
	body, err = RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), ",DNS:") {
		t.Error("a relay with no cover host was given a DNS name")
	}
}
