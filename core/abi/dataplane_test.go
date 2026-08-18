package abi

import (
	"errors"
	"path/filepath"
	"testing"

	"daal/core/engine"
)

// A build with no data plane must refuse to activate a route rather
// than let engine.Stub publish a "Connected" event nothing produced.
//
// This is the regression for the desktop's most dangerous failure
// mode: `daal build` and both AppVeyor desktop jobs compile
// ./cmd/libdaalcore with `-tags cshared` and no `singbox`, so the
// shipped desktop binary took this exact path and the GUI rendered
// "Connected · Routing" with traffic in the clear.
func TestSetRoute_FailsClosedWithoutDataPlane(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	verdict, _ := ImportSBP(filepath.Join(samplesDir, "signed-A.sbp"))
	fp := extractField(verdict, "Fingerprint")
	if fp == "" {
		t.Fatalf("could not parse fingerprint from verdict: %s", verdict)
	}
	if _, err := ResolveTrustPrompt(fp, 0); err != nil {
		t.Fatalf("resolve trust: %v", err)
	}

	dataPlaneLinked = false
	t.Cleanup(func() { dataPlaneLinked = true })

	err := SetRoute("sample-route-1")
	if !errors.Is(err, ErrNoDataPlane) {
		t.Fatalf("SetRoute on a no-data-plane build = %v, want ErrNoDataPlane", err)
	}

	// The posture axis is what every GUI maps to the connection badge
	// (client-ui postureToConnState treats ImportedActive as
	// "connected"). It must not have moved.
	if got := loadedCore().pm.Posture(); string(got) != "NoRoute" {
		t.Fatalf("posture after refused SetRoute = %s, want NoRoute", got)
	}
	// And the driver must not think it is up either.
	if stub, ok := loadedCore().driver.(*engine.Stub); ok && stub.Connected() {
		t.Fatal("driver reports connected after a refused SetRoute")
	}
	// data_plane must say so out loud in diagnostics.
	if got := DataPlaneKind(); got != "none" {
		t.Fatalf("DataPlaneKind() = %q, want \"none\"", got)
	}
}

// The diagnostics blob must always carry data_plane so a GUI can warn
// before the user presses Connect rather than only on the refusal.
func TestExportDiagnostics_CarriesDataPlane(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if !contains(body, `"data_plane"`) {
		t.Fatalf("diagnostics export has no data_plane field: %s", body)
	}
}
