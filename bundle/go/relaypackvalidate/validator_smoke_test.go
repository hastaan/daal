package relaypackvalidate

import (
	"errors"
	"testing"

	"daal/bundle-go/bundle"
)

// FRP-1 commit-2 smoke test: the validator package compiles, the
// stub Validate returns (empty, nil) for a non-RelayPack bundle,
// and the package-level Code constants are wired correctly.
//
// Commit-3 lands the full rule set (>=25 tests).
func TestValidatePackageCompiles(t *testing.T) {
	b := &bundle.Bundle{
		Manifest: bundle.Manifest{SpecVersion: 3},
	}
	rep, err := Validate(b, ValidateOpts{Phase: PhaseV15})
	if err != nil {
		t.Fatalf("expected nil error from non-RelayPack bundle, got %v", err)
	}
	if len(rep.Warnings) != 0 {
		t.Fatalf("expected empty lint report, got %+v", rep.Warnings)
	}
}

// FRP-1 commit-2 smoke test: nil bundle and missing phase are
// rejected with a typed ValidationError.
func TestValidateRejectsBadInput(t *testing.T) {
	_, err := Validate(nil, ValidateOpts{Phase: PhaseV15})
	if err == nil {
		t.Fatalf("expected error for nil bundle")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	b := &bundle.Bundle{Manifest: bundle.Manifest{SpecVersion: 3}}
	_, err = Validate(b, ValidateOpts{})
	if err == nil {
		t.Fatalf("expected error for missing Phase")
	}
}

// FRP-1 commit-2: lock the codebook constants so future commits
// cannot silently rename them.
func TestCodebookStable(t *testing.T) {
	cases := []struct {
		c    Code
		want string
	}{
		{CodeRP001, "RP001"},
		{CodeRP002, "RP002"},
		{CodeRP003, "RP003"},
		{CodeRP004, "RP004"},
		{CodeRP005, "RP005"},
		{CodeRP013, "RP013"},
		{CodeRP017, "RP017"},
		{CodeRP018, "RP018"},
		{CodeRP019, "RP019"},
		{CodeRP020, "RP020"},
		{CodeRP021, "RP021"},
	}
	for _, tc := range cases {
		if string(tc.c) != tc.want {
			t.Errorf("code %s != %q", tc.c, tc.want)
		}
	}
}

// FRP-1 commit-2: defaultFamilyMatrix() seeds the §11.1.1 row.
func TestDefaultFamilyMatrix(t *testing.T) {
	m := defaultFamilyMatrix()
	if m["vless-reality"] != ExposureYes {
		t.Errorf("vless-reality should be yes, got %s", m["vless-reality"])
	}
	if m["hysteria2"] != ExposureNo {
		t.Errorf("hysteria2 should be no (UDP-only), got %s", m["hysteria2"])
	}
	if m["tuic"] != ExposureNo {
		t.Errorf("tuic should be no (UDP-only), got %s", m["tuic"])
	}
	if m["websocket-tls"] != ExposureYes {
		t.Errorf("websocket-tls should be yes, got %s", m["websocket-tls"])
	}
}
