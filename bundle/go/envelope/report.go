package envelope

// Sealed network-test reports — specs/sealed-report-v1.md.
//
// A field-probe report (specs/field-probe-v2.md) leaves the device only
// as a file the person chose to share, age-encrypted to the publisher's
// report key. The age layer is the SAME one the .sbpx envelope uses
// (EncryptForRecipient); only the 6-byte magic differs, so that no
// import path can ever mistake a report for a relay pack, and a pack
// for a report:
//
//	.sbpx  D S B P 0x00 0x01  ‖ age v1 stream
//	report D S B R 0x00 0x01  ‖ age v1 stream
//
// age gives confidentiality and integrity against everyone who does not
// hold the report key. It gives NO sender authentication: anybody who
// knows the publisher's `daal1…` report address can make a file that
// opens. The opener treats every report as untrusted input.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// ReportMagic is the prefix of a sealed report.
var ReportMagic = []byte{'D', 'S', 'B', 'R', 0x00, 0x01}

// MaxReportBytes caps a sealed report the opener reads. A report is
// padded to a 16 KiB bucket and is a few buckets at most.
const MaxReportBytes = 1 * 1024 * 1024

var (
	// ErrNotReport: the input does not start with ReportMagic.
	ErrNotReport = errors.New("envelope: not a sealed report")
	// ErrReportTooLarge: the input or its plaintext exceeds MaxReportBytes.
	ErrReportTooLarge = errors.New("envelope: sealed report exceeds 1 MiB cap")
)

// SniffReportMagic reports whether head starts with ReportMagic.
func SniffReportMagic(head []byte) bool {
	return len(head) >= len(ReportMagic) && bytes.Equal(head[:len(ReportMagic)], ReportMagic)
}

// EncryptReport seals plaintext (an already padded report) for one
// X25519 recipient: the 32-byte key a `daal1…` address decodes to.
func EncryptReport(plaintext []byte, recipient [32]byte) ([]byte, error) {
	if len(plaintext) > MaxReportBytes {
		return nil, ErrReportTooLarge
	}
	r, err := newX25519Recipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("envelope: build recipient: %w", err)
	}
	var ageBuf bytes.Buffer
	w, err := age.Encrypt(&ageBuf, r)
	if err != nil {
		return nil, fmt.Errorf("envelope: age.Encrypt init: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("envelope: write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("envelope: close age stream: %w", err)
	}
	out := make([]byte, 0, len(ReportMagic)+ageBuf.Len())
	out = append(out, ReportMagic...)
	return append(out, ageBuf.Bytes()...), nil
}

// DecryptReport opens a sealed report with the report key's 32-byte
// X25519 private scalar and returns the (still padded) plaintext.
func DecryptReport(ciphertext []byte, priv [32]byte) ([]byte, error) {
	if len(ciphertext) > MaxReportBytes {
		return nil, ErrReportTooLarge
	}
	if !SniffReportMagic(ciphertext) {
		return nil, ErrNotReport
	}
	id, err := newX25519Identity(priv)
	if err != nil {
		return nil, fmt.Errorf("envelope: build identity: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext[len(ReportMagic):]), id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	out, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrDecrypt, err)
	}
	if len(out) > MaxReportBytes {
		return nil, ErrReportTooLarge
	}
	return out, nil
}

// NewReportKey makes a fresh X25519 report key pair: priv stays with the
// publisher (its keystore, under its backup), pub is what a `daal1…`
// report address encodes.
func NewReportKey() (pub, priv [32]byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return pub, priv, err
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return pub, priv, nil
}

// ReportPublicKey derives the public half of a report key.
func ReportPublicKey(priv [32]byte) ([32]byte, error) {
	var pub [32]byte
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return pub, err
	}
	copy(pub[:], k.PublicKey().Bytes())
	return pub, nil
}
