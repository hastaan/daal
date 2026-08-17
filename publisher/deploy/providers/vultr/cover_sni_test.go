package vultr

import (
	"context"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/sni"
)

// Vultr's cloud-init still carries a placeholder sing-box config rather
// than a real one, so nothing is templated on the box yet. The record
// must carry the cover host anyway: the binder is provider-agnostic and
// reads OperatorRecord.CoverSNI, so a Vultr relay that left it empty
// would mint a pack that falls back to the fleet-wide constant.
func TestProvision_RecordCarriesCoverSNI(t *testing.T) {
	rec, err := New(newFake()).Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI == "" {
		t.Fatal("Vultr record has no cover SNI")
	}
	if rec.CoverSNI == sni.LegacyCoverSNI {
		t.Fatalf("Vultr record carries the fleet-wide constant %q", rec.CoverSNI)
	}
	// fra is eu-central.
	inZone := false
	for _, e := range sni.InZone(sni.ZoneEUCentral) {
		if e.Host == rec.CoverSNI {
			inZone = true
		}
	}
	if !inZone {
		t.Errorf("fra relay got %q, which is not in eu-central", rec.CoverSNI)
	}
}

func TestReprovision_MovesCoverSNI(t *testing.T) {
	p := New(newFake())
	opts := mkOpts()
	opts.DryRun = false
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	before := rec.CoverSNI
	if before == "" {
		t.Fatal("no cover SNI to rotate away from")
	}
	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{}); err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI == before {
		t.Errorf("re-provision kept the burned cover host %q", before)
	}
}
