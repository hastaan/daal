package embedded

import (
	"testing"
	"time"

	"daal/bundle-go/bundle"
	hbootstrap "daal/core/bootstrap"
)

func TestLoadManifest_Tier1Pointers(t *testing.T) {
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.ProjectRootPub) == 0 {
		t.Fatal("project root pub missing")
	}
	if len(m.PublisherRootPubs) < 1 {
		t.Fatal("expected at least one publisher root")
	}
	if len(m.Tier2Seeds) < 1 {
		t.Fatal("expected at least one tier-2 seed")
	}
	now := time.Now().UTC()
	if err := hbootstrap.VerifyPointerSet(m.PrimaryPointers, m.ProjectRootPub, now); err != nil {
		t.Fatalf("primary pointers must verify: %v", err)
	}
	if err := hbootstrap.VerifyPointerSet(m.FallbackPointers, m.ProjectRootPub, now); err != nil {
		t.Fatalf("fallback pointers must verify: %v", err)
	}
	// Pointers must reference one of the embedded publisher fingerprints.
	for _, p := range m.PrimaryPointers.Pointers {
		if _, ok := m.PublisherRootPubs[p.ExpectedPublisherFingerprintHex]; !ok {
			t.Errorf("primary pointer %s references unknown publisher %s",
				p.URL, p.ExpectedPublisherFingerprintHex)
		}
	}
}

func TestLoadManifest_Tier2SeedsValidUntilCap(t *testing.T) {
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	for i, body := range m.Tier2Seeds {
		parsed, err := bundle.ParseSBP(bytesReaderAt(body), int64(len(body)))
		if err != nil {
			t.Fatalf("seed %d parse: %v", i, err)
		}
		issued, _ := time.Parse(time.RFC3339, parsed.Manifest.Bundle.CreatedAt)
		expires, _ := time.Parse(time.RFC3339, parsed.Manifest.Bundle.ExpiresAt)
		if expires.Sub(issued) > 30*24*time.Hour {
			t.Errorf("seed %d valid_until - issued_at > 30d (%s)", i, expires.Sub(issued))
		}
		// Publisher fingerprint must be in the Tier-1 set.
		fp := bundle.PublisherFingerprint(parsed.PublisherPub).Hex
		if _, ok := m.PublisherRootPubs[fp]; !ok {
			t.Errorf("seed %d signed by unknown publisher %s", i, fp)
		}
	}
}

// minimal io.ReaderAt over a byte slice without pulling in the parent
// package's helpers.
type bra struct{ b []byte }

func (r *bra) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, errEOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, errEOF
	}
	return n, nil
}

func bytesReaderAt(b []byte) *bra { return &bra{b: b} }

type errStr string

func (e errStr) Error() string { return string(e) }

const errEOF = errStr("EOF")
