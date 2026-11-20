package relaypack

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fieldreport"
)

// A pack signed with ReportTo carries `_report_to` on every route,
// inside the signed manifest, and still verifies. Without it the pack
// is byte for byte what it was before the option existed.
func TestBindAndSign_ReportToOnEveryRoute(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	var pub [32]byte
	pub[0] = 7
	addr := fieldreport.EncodeAddress(pub)

	plain, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	opts := defaultOpts()
	opts.ReportTo = "  " + addr + " "
	res, err := BindAndSign(rec, priv, opts)
	if err != nil {
		t.Fatalf("BindAndSign with ReportTo: %v", err)
	}
	if bytes.Equal(plain.SBPBytes, res.SBPBytes) {
		t.Fatal("ReportTo changed nothing")
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if len(parsed.Manifest.Routes) == 0 {
		t.Fatal("no routes")
	}
	for _, r := range parsed.Manifest.Routes {
		var fc map[string]any
		if err := json.Unmarshal(r.FamilySpecificConfig, &fc); err != nil {
			t.Fatalf("route %s: %v", r.ID, err)
		}
		if fc[ReportToKey] != addr {
			t.Fatalf("route %s: _report_to = %v, want %s", r.ID, fc[ReportToKey], addr)
		}
		if _, ok := fc["_relaypack"]; !ok {
			t.Fatalf("route %s lost _relaypack", r.ID)
		}
	}

	// The plain pack has no such key anywhere.
	pp, err := bundle.ParseSBP(bytes.NewReader(plain.SBPBytes), int64(len(plain.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pp.Manifest.Routes {
		if bytes.Contains(r.FamilySpecificConfig, []byte(ReportToKey)) {
			t.Fatalf("route %s carries _report_to without ReportTo", r.ID)
		}
	}
}

func TestBindAndSign_RefusesABadReportTo(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	opts := defaultOpts()
	opts.ReportTo = "daal1notanaddress"
	if _, err := BindAndSign(rec, priv, opts); !errors.Is(err, ErrBadReportTo) {
		t.Fatalf("err = %v, want ErrBadReportTo", err)
	}
}
