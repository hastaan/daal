package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestCDNRotatePath_RequiresFlags asserts the cdn-rotate-path
// subcommand surfaces all required flags. We don't drive a live
// Cloudflare API in unit tests — that's covered by the FRP-8
// cf_client_live integration test plus the FRP-9 commit-1
// rotate_test.go in publisher/deploy/cloudflare. This test only
// guards against accidental flag-name regressions that would
// silently misroute the wizard.
func TestCDNRotatePath_RequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"cdn-rotate-path"}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("rc=0 with no flags; expected nonzero")
	}
	out := stderr.String()
	for _, want := range []string{
		"--hostname",
		"--zone-id",
		"--account-id",
		"--origin-path",
		"--cf-token-file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q: %s", want, out)
		}
	}
}

func TestCDNRotateHostname_RequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"cdn-rotate-hostname"}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("rc=0 with no flags; expected nonzero")
	}
	out := stderr.String()
	for _, want := range []string{
		"--old-hostname",
		"--old-zone-id",
		"--public-path",
		"--origin-path",
		"--new-hostname",
		"--origin-ipv4",
		"--cf-token-file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q: %s", want, out)
		}
	}
}

func TestCDNRotateOrigin_RequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"cdn-rotate-origin"}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("rc=0 with no flags; expected nonzero")
	}
	out := stderr.String()
	for _, want := range []string{
		"--hostname",
		"--zone-id",
		"--new-origin-ipv4",
		"--cf-token-file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q: %s", want, out)
		}
	}
}

// TestPublishFreshness_RequiresFlags asserts publish-freshness
// surfaces all required flags. The build + sign path itself is
// covered by publisher/deploy/freshness/document_test.go; this
// test only locks the wizard ↔ CLI flag contract.
func TestPublishFreshness_RequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"publish-freshness"}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("rc=0 with no flags; expected nonzero")
	}
	out := stderr.String()
	for _, want := range []string{
		"--relay-pack-id",
		"--current-bundle-sha256",
		"--current-signed-url",
		"--publisher-pub-hex",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q: %s", want, out)
		}
	}
}

// TestPublishFreshness_RejectsMissingPriv asserts publish-freshness
// requires either --root-priv-file or --subkey-priv-file. Failing
// to enforce this would let the wizard emit an unsigned freshness
// document.
func TestPublishFreshness_RejectsMissingPriv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"publish-freshness",
		"--relay-pack-id", "rp-1",
		"--current-bundle-sha256", "ababababababababababababababababababababababababababababababab",
		"--current-signed-url", "https://example.com/x.sbp",
		"--publisher-pub-hex", "11" + strings.Repeat("00", 31),
	}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("rc=0 with no priv-key flag; expected nonzero")
	}
	if !strings.Contains(stderr.String(), "root-priv-file") {
		t.Errorf("stderr missing root-priv-file mention: %s", stderr.String())
	}
}

// TestUsageMentionsFRP9Subcommands locks the help-text contract
// so wizard-side onboarding docs that reference the subcommands
// don't drift out of sync with what the CLI actually supports.
func TestUsageMentionsFRP9Subcommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_ = stderr
	rc := Run([]string{"--help"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("--help rc=%d", rc)
	}
	for _, want := range []string{
		"cdn-rotate-path",
		"cdn-rotate-hostname",
		"cdn-rotate-origin",
		"publish-freshness",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("usage missing %q", want)
		}
	}
	// Origin-only invariant must be visible in the help text so
	// operators know the wizard intentionally does not re-sign.
	if !strings.Contains(stdout.String(), "MUST NOT") {
		t.Errorf("usage missing the §14.4 origin-only MUST NOT directive")
	}
}
