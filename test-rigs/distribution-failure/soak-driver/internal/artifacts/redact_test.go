package artifacts

import (
	"path/filepath"
	"testing"
)

// TestVerifyShapeOnCanned7d is the regression net for the rig's
// artifact format. It runs `verify` against a checked-in 7-day soak
// snapshot. If a future change to the rig produces malformed JSONL or
// invalid JSON snapshots, this test catches it without needing a fresh
// run.
func TestVerifyShapeOnCanned7d(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "canned-7d")
	if err := VerifyShape(dir); err != nil {
		t.Fatalf("verify canned 7d: %v", err)
	}
}

func TestRedactBytesScrubsIPAndURL(t *testing.T) {
	in := []byte(`{"endpoint":"127.0.0.1:8080","url":"https://example/sub"}`)
	out := redactBytes(in)
	got := string(out)
	if got == string(in) {
		t.Fatalf("redact did nothing: %s", got)
	}
	for _, want := range []string{"REDACTED_IP", "REDACTED_URL"} {
		if !contains(got, want) {
			t.Errorf("redact output missing %q: %s", want, got)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
