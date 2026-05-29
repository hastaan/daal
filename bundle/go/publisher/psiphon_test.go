package publisher

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBlobFile(t *testing.T, dir, name string, n int) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, bytes.Repeat([]byte{0xAB}, n), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPsiphonBundle_HappyPath — a 4 KB blob produces a valid
// route stub with the expected fields populated and the
// `transport_family = "psiphon"` token set.
func TestPsiphonBundle_HappyPath(t *testing.T) {
	dir := t.TempDir()
	in := writeBlobFile(t, dir, "psi.bin", 4096)
	out := filepath.Join(dir, "stub.json")

	stub, checksum, err := PsiphonBundle(PsiphonBundleOptions{
		BlobPath: in,
		OutPath:  out,
	})
	if err != nil {
		t.Fatalf("PsiphonBundle: %v", err)
	}
	if stub.TransportFamily != "psiphon" {
		t.Errorf("transport_family: got %q", stub.TransportFamily)
	}
	if stub.ScarcityClass != "normal" {
		t.Errorf("default scarcity: got %q", stub.ScarcityClass)
	}
	if !strings.HasPrefix(stub.ID, "ps-") {
		t.Errorf("default ID prefix: got %q", stub.ID)
	}
	if !strings.HasSuffix(stub.ID, checksum) {
		t.Errorf("default ID suffix: got %q want suffix %q", stub.ID, checksum)
	}
	if stub.PsiphonBundleBlobB64 == "" {
		t.Error("blob_b64 not populated")
	}
	decoded, err := base64.StdEncoding.DecodeString(stub.PsiphonBundleBlobB64)
	if err != nil || len(decoded) != 4096 {
		t.Errorf("blob round-trip: len=%d err=%v", len(decoded), err)
	}

	// File written with mode 0600.
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("output mode: %v", info.Mode().Perm())
	}

	// Round-trip through JSON to confirm the shape is parseable.
	body, _ := os.ReadFile(out)
	var parsed PsiphonRouteStub
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed.PsiphonBundleBlobB64 != stub.PsiphonBundleBlobB64 {
		t.Error("re-parsed blob differs")
	}
}

// TestPsiphonBundle_BlobTooSmallRejected — <256 bytes is
// refused by the size envelope.
func TestPsiphonBundle_BlobTooSmallRejected(t *testing.T) {
	dir := t.TempDir()
	in := writeBlobFile(t, dir, "small.bin", 100)
	_, _, err := PsiphonBundle(PsiphonBundleOptions{BlobPath: in})
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("got %v, want 'out of range' error", err)
	}
}

// TestPsiphonBundle_BlobTooLargeRejected — >65536 bytes is
// refused by the size envelope.
func TestPsiphonBundle_BlobTooLargeRejected(t *testing.T) {
	dir := t.TempDir()
	in := writeBlobFile(t, dir, "huge.bin", 70000)
	_, _, err := PsiphonBundle(PsiphonBundleOptions{BlobPath: in})
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("got %v, want 'out of range' error", err)
	}
}

// TestPsiphonBundle_EmergencyScarcityRejected — locked at 3D:
// emergency-scarcity is reserved for the bootstrap pool.
func TestPsiphonBundle_EmergencyScarcityRejected(t *testing.T) {
	dir := t.TempDir()
	in := writeBlobFile(t, dir, "psi.bin", 4096)
	_, _, err := PsiphonBundle(PsiphonBundleOptions{
		BlobPath:      in,
		ScarcityClass: "emergency",
	})
	if err == nil || !strings.Contains(err.Error(), "emergency") {
		t.Errorf("got %v, want emergency-scarcity rejection", err)
	}
}
