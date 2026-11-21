package envelope

import (
	"bytes"
	"errors"
	"testing"
)

func TestReportRoundTrip(t *testing.T) {
	pub, priv, err := NewReportKey()
	if err != nil {
		t.Fatal(err)
	}
	if p2, _ := ReportPublicKey(priv); p2 != pub {
		t.Fatal("ReportPublicKey does not match NewReportKey")
	}
	msg := []byte(`{"schema_version":2}`)
	ct, err := EncryptReport(msg, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !SniffReportMagic(ct) || SniffMagic(ct) {
		t.Fatal("a sealed report must carry DSBR and never DSBP")
	}
	pt, err := DecryptReport(ct, priv)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("round trip: %v %q", err, pt)
	}
}

// A report is never accepted where a pack is expected, nor a pack where
// a report is.
func TestReportAndPackMagicsDoNotCross(t *testing.T) {
	pub, priv, _ := NewReportKey()
	report, _ := EncryptReport([]byte("r"), pub)
	pack, _ := EncryptForRecipient([]byte("p"), pub)
	if _, err := Decrypt(report, priv); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("pack opener accepted a report: %v", err)
	}
	if _, err := DecryptReport(pack, priv); !errors.Is(err, ErrNotReport) {
		t.Fatalf("report opener accepted a pack: %v", err)
	}
}

func TestReportWrongKey(t *testing.T) {
	pub, _, _ := NewReportKey()
	_, other, _ := NewReportKey()
	ct, _ := EncryptReport([]byte("x"), pub)
	if _, err := DecryptReport(ct, other); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: %v", err)
	}
}
