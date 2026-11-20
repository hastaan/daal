package cli

import (
	"bytes"
	"strings"
	"testing"
)

// Every add-on verb is registered and, until its lane lands, refuses
// with E_NOT_BUILT and exit 8 — never "unknown subcommand" (exit 2),
// which the app reads as an old helper.
func TestAddonVerbsAreRegisteredAndRefuseAsNotBuilt(t *testing.T) {
	for _, argv := range [][]string{
		{"standby", "price"},
		{"standby", "add"},
		{"standby", "promote"},
		{"standby", "remove"},
		{"cdn-token-check"},
		{"cdn-test"},
		{"cdn-posture"},
		{"cdn-remove"},
		{"appsscript-script"},
		{"appsscript-deploy"},
		{"appsscript-check"},
		{"appsscript-clear"},
	} {
		var out, errb bytes.Buffer
		rc := Run(argv, &out, &errb)
		name := strings.Join(argv, " ")
		if rc != exitNotBuilt {
			t.Errorf("%s: rc=%d, want %d (stderr %q)", name, rc, exitNotBuilt, errb.String())
		}
		if !strings.HasPrefix(errb.String(), "E_NOT_BUILT: ") {
			t.Errorf("%s: stderr %q", name, errb.String())
		}
		if strings.Contains(strings.ToLower(errb.String()), "unknown subcommand") {
			t.Errorf("%s: reads as an unknown verb", name)
		}
		if out.Len() != 0 {
			t.Errorf("%s: wrote stdout %q", name, out.String())
		}
	}
}

func TestStandbyWithoutAKnownVerbIsUsage(t *testing.T) {
	for _, argv := range [][]string{{"standby"}, {"standby", "rent"}} {
		var out, errb bytes.Buffer
		if rc := Run(argv, &out, &errb); rc != 2 {
			t.Errorf("%v: rc=%d, want 2", argv, rc)
		}
	}
}

func TestAddonVerbsAreInTheUsage(t *testing.T) {
	u := usage()
	for _, v := range []string{"standby", "cdn-token-check", "cdn-test", "cdn-posture", "cdn-remove",
		"appsscript-script", "appsscript-deploy", "appsscript-check", "appsscript-clear"} {
		if !strings.Contains(u, v) {
			t.Errorf("usage does not mention %s", v)
		}
	}
}
