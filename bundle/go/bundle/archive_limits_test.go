package bundle

import (
	"archive/zip"
	"bytes"
	"errors"
	"runtime"
	"testing"
)

// ParseSBP runs before VerifyBundle — it must, since the signature lives
// inside the archive — so it decompresses on the word of an unverified
// stranger. Every offline intake path in Step 11 (file picker, base64
// paste, QR fountain, LAN pull) ends here.
//
// Before the cap, a 509 KiB zip of zeros cost 1223 MiB of heap and only
// THEN returned "missing manifest.json".
func TestParseSBPRefusesDecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("profiles/bomb.conf")
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for i := 0; i < 1024; i++ { // 1 GiB of zeros
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()

	// The bomb must be small enough on the wire to pass the paste lane's
	// own ceiling, otherwise this test is not modelling the real threat.
	if len(body) > 1<<20 {
		t.Fatalf("bomb is %d bytes on the wire; the paste lane would have "+
			"refused it and this test would prove nothing", len(body))
	}

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_, parseErr := ParseSBP(bytes.NewReader(body), int64(len(body)))
	runtime.ReadMemStats(&m1)

	if !errors.Is(parseErr, ErrBundleTooLarge) {
		t.Fatalf("want ErrBundleTooLarge, got %v", parseErr)
	}
	// The point is not only the error but that the memory was never spent.
	if grew := m1.TotalAlloc - m0.TotalAlloc; grew > 2*MaxArchiveTotalBytes {
		t.Fatalf("refused the bomb but still allocated %d MiB", grew/(1<<20))
	}
}

// A lying zip header must not be a way through: the declared size is
// checked first as a cheap reject, but the read is independently bounded
// so an understated header still cannot smuggle bytes in.
func TestParseSBPBoundsReadEvenIfHeaderLies(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("profiles/big.conf")
	chunk := make([]byte, 1<<20)
	for i := 0; i < 8; i++ {
		_, _ = w.Write(chunk)
	}
	_ = zw.Close()
	body := buf.Bytes()

	// Rewrite every occurrence of the true uncompressed size (8 MiB, LE)
	// in the local header and central directory to a small lie.
	trueSize := []byte{0x00, 0x00, 0x80, 0x00} // 8388608
	lie := []byte{0x10, 0x00, 0x00, 0x00}      // 16
	patched := bytes.ReplaceAll(body, trueSize, lie)
	if bytes.Equal(patched, body) {
		t.Skip("could not locate the size field to falsify")
	}

	_, err := ParseSBP(bytes.NewReader(patched), int64(len(patched)))
	if err == nil {
		t.Fatal("a zip with a falsified size field was accepted")
	}
}

// Many small entries must not add up to what one large entry cannot do.
func TestParseSBPBoundsTotalAndEntryCount(t *testing.T) {
	build := func(n, each int) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		blob := bytes.Repeat([]byte("A"), each)
		for i := 0; i < n; i++ {
			w, _ := zw.CreateHeader(&zip.FileHeader{
				Name:   "profiles/p" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".conf",
				Method: zip.Store, // Store, so this is size not compression
			})
			_, _ = w.Write(blob)
		}
		_ = zw.Close()
		return buf.Bytes()
	}

	t.Run("entry count", func(t *testing.T) {
		body := build(MaxArchiveEntries+1, 1)
		if _, err := ParseSBP(bytes.NewReader(body), int64(len(body))); !errors.Is(err, ErrBundleTooLarge) {
			t.Fatalf("want ErrBundleTooLarge for %d entries, got %v", MaxArchiveEntries+1, err)
		}
	})

	t.Run("total bytes", func(t *testing.T) {
		// 4 entries x 12 MiB = 48 MiB total, each under the per-entry cap.
		body := build(4, 12<<20)
		if _, err := ParseSBP(bytes.NewReader(body), int64(len(body))); !errors.Is(err, ErrBundleTooLarge) {
			t.Fatalf("want ErrBundleTooLarge for an oversized total, got %v", err)
		}
	})
}

// The ceilings must not disturb anything real. A genuine relay pack is
// 1.3–2.6 KB; assert the headroom explicitly so a future tightening that
// would start refusing real bundles fails here instead of on a handset.
func TestArchiveCeilingsLeaveRealBundlesUntouched(t *testing.T) {
	// specs/wasm-transport-v1.md allows 16 MiB of transport modules, and
	// they travel base64 (4/3 expansion) inside manifest.json, so the
	// per-entry cap must clear that or legal bundles stop parsing.
	if MaxArchiveEntryBytes < 16*1024*1024*4/3 {
		t.Fatalf("per-entry cap %d cannot hold a spec-legal manifest", MaxArchiveEntryBytes)
	}
	if MaxArchiveTotalBytes < MaxArchiveEntryBytes {
		t.Fatal("total cap must be at least the per-entry cap")
	}
	if MaxArchiveEntries < 16 {
		t.Fatalf("entry cap %d is below what a multi-profile pack needs", MaxArchiveEntries)
	}
}
