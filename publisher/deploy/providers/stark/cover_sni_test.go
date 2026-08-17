package stark

import (
	"context"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/sni"
)

// Stark's cloud-init still carries a placeholder sing-box config rather
// than a real one, so nothing is templated on the box yet. The record
// must carry the cover host anyway: the binder is provider-agnostic and
// reads OperatorRecord.CoverSNI, so a Stark relay that left it empty
// would mint a pack that falls back to the fleet-wide constant.
func TestProvision_RecordCarriesCoverSNI(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	rec, err := p.Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI == "" {
		t.Fatal("Stark record has no cover SNI")
	}
	if rec.CoverSNI == sni.LegacyCoverSNI {
		t.Fatalf("Stark record carries the fleet-wide constant %q", rec.CoverSNI)
	}
	if err := sni.ValidHost(rec.CoverSNI); err != nil {
		t.Errorf("chosen host is not admissible: %v", err)
	}
	// vno is eu-north; the pick must respect the neighbourhood.
	inZone := false
	for _, e := range sni.InZone(sni.ZoneEUNorth) {
		if e.Host == rec.CoverSNI {
			inZone = true
		}
	}
	if !inZone {
		t.Errorf("vno relay got %q, which is not in eu-north", rec.CoverSNI)
	}
}

func TestReprovision_MovesCoverSNI(t *testing.T) {
	p, _, cleanup := mkProvider(t, "tok")
	defer cleanup()
	rec, err := p.Provision(context.Background(), mkOpts())
	if err != nil {
		t.Fatal(err)
	}
	before := rec.CoverSNI
	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{}); err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI == before {
		t.Errorf("re-provision kept the burned cover host %q", before)
	}
}
