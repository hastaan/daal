package cloudinit

import (
	"strings"
	"testing"
)

func realityConfig(serverName, handshake string) string {
	return `{"log":{"level":"info"},"inbounds":[
	  {"type":"vless","tag":"vless-in","listen_port":443,"users":[],
	   "tls":{"enabled":true,"server_name":"` + serverName + `",
	          "reality":{"enabled":true,"private_key":"","short_id":[],
	                     "handshake":{"server":"` + handshake + `","server_port":443}}}}]}`
}

// TestRender_RejectsCoverSNIMismatch is the choke point. Every provider
// funnels its sing-box config through Render/RenderV2, so a REALITY
// inbound that advertises one name and falls back to another cannot
// reach a box no matter which adapter, profile or template built it.
func TestRender_RejectsCoverSNIMismatch(t *testing.T) {
	in := fixedInput()
	in.SingBoxConfigJSON = realityConfig("mirror.init7.net", "www.cloudflare.com")
	_, err := Render(in)
	if err == nil {
		t.Fatal("Render accepted a REALITY inbound whose server_name and handshake.server disagree")
	}
	if !strings.Contains(err.Error(), "cover sni") {
		t.Errorf("error does not name the problem: %v", err)
	}

	v2 := fixedInputV2()
	v2.SingBoxConfigJSON = in.SingBoxConfigJSON
	if _, err := RenderV2(v2); err == nil {
		t.Fatal("RenderV2 accepted the same mismatch")
	}
}

func TestRender_RejectsEmptyRealityCoverSNI(t *testing.T) {
	for name, cfg := range map[string]string{
		"empty server_name": realityConfig("", "mirror.init7.net"),
		"empty handshake":   realityConfig("mirror.init7.net", ""),
	} {
		in := fixedInput()
		in.SingBoxConfigJSON = cfg
		if _, err := Render(in); err == nil {
			t.Errorf("%s: Render accepted it", name)
		}
	}
}

// TestRender_AcceptsMatchingCoverSNI and non-REALITY configs, which is
// what the Stark/Vultr placeholder and any plain-TLS profile look like.
func TestRender_AcceptsMatchingCoverSNI(t *testing.T) {
	in := fixedInput()
	in.SingBoxConfigJSON = realityConfig("mirror.init7.net", "mirror.init7.net")
	if _, err := Render(in); err != nil {
		t.Errorf("matching cover SNI rejected: %v", err)
	}
	in.SingBoxConfigJSON = `{"profile":"iran-default"}`
	if _, err := Render(in); err != nil {
		t.Errorf("config with no REALITY inbound rejected: %v", err)
	}
}

func TestRender_RejectsNonJSONSingBoxConfig(t *testing.T) {
	in := fixedInput()
	in.SingBoxConfigJSON = "not json at all"
	if _, err := Render(in); err == nil {
		t.Fatal("Render accepted a sing-box config that is not JSON")
	}
}

// TestRenderV2_WritesCoverSNIFile: the box states what it serves, so
// /rotate-tls has a source of truth to rewrite and an operator on the
// box can read the current value without parsing sing-box's config.
func TestRenderV2_WritesCoverSNIFile(t *testing.T) {
	in := fixedInputV2()
	in.SingBoxConfigJSON = realityConfig("mirror.dogado.de", "mirror.dogado.de")
	in.CoverSNI = "mirror.dogado.de"
	body, err := RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "/etc/daal/cover-sni") {
		t.Error("rendered cloud-init does not write /etc/daal/cover-sni")
	}
	if !strings.Contains(s, "mirror.dogado.de") {
		t.Error("rendered cloud-init does not carry the cover host")
	}

	// Empty declares nothing and must not write a blank file — a blank
	// /etc/daal/cover-sni would be worse than none, because a reader
	// cannot tell "not set" from "serves nothing".
	in.CoverSNI = ""
	body, err = RenderV2(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "/etc/daal/cover-sni") {
		t.Error("empty CoverSNI still wrote the file")
	}
}

// TestRenderV2_RejectsDeclarationThatDisagreesWithConfig.
func TestRenderV2_RejectsDeclarationThatDisagreesWithConfig(t *testing.T) {
	in := fixedInputV2()
	in.SingBoxConfigJSON = realityConfig("mirror.dogado.de", "mirror.dogado.de")
	in.CoverSNI = "mirror.init7.net"
	if _, err := RenderV2(in); err == nil {
		t.Fatal("RenderV2 accepted a declared cover host the config does not serve")
	}
}
