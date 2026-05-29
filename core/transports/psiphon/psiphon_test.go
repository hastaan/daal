package psiphon

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func goodBlob(n int) []byte {
	if n <= 0 {
		n = MinBundleBytes
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i & 0xff)
	}
	return out
}

// TestFamilyIDIsPsiphon — the 3A taxonomy mandates the family
// ID; a constant-string regression keeps it stable.
func TestFamilyIDIsPsiphon(t *testing.T) {
	if FamilyID != "psiphon" {
		t.Fatalf("FamilyID drifted: %q", FamilyID)
	}
}

// TestSizeBoundsLockedAtV1 — `specs/psiphon-route-v1.md`
// locks the [256, 65536] envelope; the constants here are the
// load-bearing copy and must not silently widen.
func TestSizeBoundsLockedAtV1(t *testing.T) {
	if MinBundleBytes != 256 {
		t.Errorf("MinBundleBytes drifted: %d", MinBundleBytes)
	}
	if MaxBundleBytes != 65536 {
		t.Errorf("MaxBundleBytes drifted: %d", MaxBundleBytes)
	}
}

// TestHandler_UnavailableInBuildWithoutPsiphon — `-tags
// no_psiphon` builds pass a nil dialer; Dial returns
// ErrFamilyHandlerUnavailable so the pathmanager filters
// every psiphon route as unbuildable.
func TestHandler_UnavailableInBuildWithoutPsiphon(t *testing.T) {
	h := NewHandler(nil)
	if h.Available() {
		t.Error("Available() should be false with nil dialer")
	}
	_, err := h.Dial(context.Background(), Route{
		RouteID:     "rA",
		PsiphonBlob: goodBlob(0),
	})
	if !errors.Is(err, ErrFamilyHandlerUnavailable) {
		t.Errorf("got %v, want ErrFamilyHandlerUnavailable", err)
	}
}

// TestHandler_DialForwardsBlobVerbatim — the upstream library
// receives the exact bytes the bundle declared. Daal does NOT
// inspect Psiphon bundle bytes (locked posture).
func TestHandler_DialForwardsBlobVerbatim(t *testing.T) {
	want := goodBlob(1024)
	var got []byte
	dialer := func(ctx context.Context, blob []byte) (*Conn, error) {
		got = make([]byte, len(blob))
		copy(got, blob)
		return &Conn{}, nil
	}
	var activeRecorded string
	h := NewHandler(dialer, WithRecordActive(func(rid string) {
		activeRecorded = rid
	}))
	conn, err := h.Dial(context.Background(), Route{
		RouteID:     "ps-1",
		PsiphonBlob: want,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("blob mismatch")
	}
	if conn.RouteID != "ps-1" {
		t.Errorf("conn.RouteID = %q want ps-1", conn.RouteID)
	}
	if activeRecorded != "ps-1" {
		t.Errorf("recordActive got %q want ps-1", activeRecorded)
	}
}

// TestHandler_BundleMissingRejected — a route reaching Dial
// with an empty blob is a programmer error (the bundle parser
// already rejects); we still guard at the engine layer.
func TestHandler_BundleMissingRejected(t *testing.T) {
	h := NewHandler(func(ctx context.Context, blob []byte) (*Conn, error) {
		t.Error("dialer must not run when blob is empty")
		return nil, nil
	})
	_, err := h.Dial(context.Background(), Route{RouteID: "rA"})
	if !errors.Is(err, ErrBundleMissing) {
		t.Errorf("got %v, want ErrBundleMissing", err)
	}
}

// TestHandler_BundleSizeOutOfRangeRejected — defence-in-depth
// against a corrupt routestore row. The bundle parser is the
// canonical validator; the engine guard is a redundant check.
func TestHandler_BundleSizeOutOfRangeRejected(t *testing.T) {
	h := NewHandler(func(ctx context.Context, blob []byte) (*Conn, error) {
		t.Error("dialer must not run when size is out of range")
		return nil, nil
	})
	cases := [][]byte{
		make([]byte, MinBundleBytes-1), // too small
		make([]byte, MaxBundleBytes+1), // too large
	}
	for i, blob := range cases {
		_, err := h.Dial(context.Background(), Route{
			RouteID:     "rA",
			PsiphonBlob: blob,
		})
		if !errors.Is(err, ErrBundleSizeOutOfRange) {
			t.Errorf("case %d: got %v, want ErrBundleSizeOutOfRange", i, err)
		}
	}
}

// TestHandler_DialerErrorsBubble — when the upstream library
// returns an error, the handler returns it verbatim so the
// engine layer can map onto the V0 failure taxonomy.
func TestHandler_DialerErrorsBubble(t *testing.T) {
	want := errors.New("synthetic upstream failure")
	h := NewHandler(func(ctx context.Context, blob []byte) (*Conn, error) {
		return nil, want
	})
	_, err := h.Dial(context.Background(), Route{
		RouteID:     "rA",
		PsiphonBlob: goodBlob(0),
	})
	if !errors.Is(err, want) {
		t.Errorf("got %v, want %v", err, want)
	}
}
