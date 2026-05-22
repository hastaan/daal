package cloudflare

import (
	"context"
	"strings"
	"testing"
)

// TestRotatePublicPath_DrivesScriptUploadAndRouteRebind locks
// FRP-9's commit 1/8: a public-path rotation re-uploads the
// rewrite worker (carrying the new public path) and rebinds the
// route. Hostname is unchanged; origin path is unchanged.
//
// The caller (wizard) is then responsible for re-signing the
// RelayPack and re-publishing the freshness JSON document; that
// step is exercised by the v1-6-public-surface-rotation soak
// scenario (FRP-9 commit 4/8).
func TestRotatePublicPath_DrivesScriptUploadAndRouteRebind(t *testing.T) {
	cf := &MockCFClient{
		BindRouteID:       "route-NEW",
		RotatePathRouteID: "route-NEW",
	}
	p := NewProvider(cf)
	rec := &FrontRecord{
		Hostname:      "momsroute.example.com",
		ZoneID:        "zone-example.com",
		PublicPath:    "/r/old1234",
		OriginPath:    "/ws",
		WorkerRouteID: "route-OLD",
	}
	newPath, newRouteID, err := p.RotatePublicPath(context.Background(), []byte("token"), "account-example.com", rec, "/r/newAB12")
	if err != nil {
		t.Fatalf("RotatePublicPath: %v", err)
	}
	if newPath != "/r/newAB12" {
		t.Errorf("newPath=%q want /r/newAB12", newPath)
	}
	if newRouteID != "route-NEW" {
		t.Errorf("newRouteID=%q want route-NEW", newRouteID)
	}
	if rec.PublicPath != "/r/newAB12" {
		t.Errorf("rec.PublicPath=%q (not mutated)", rec.PublicPath)
	}
	if rec.WorkerRouteID != "route-NEW" {
		t.Errorf("rec.WorkerRouteID=%q (not mutated)", rec.WorkerRouteID)
	}
	if rec.OriginPath != "/ws" {
		t.Errorf("origin path mutated: %q", rec.OriginPath)
	}
	// Hostname unchanged is the §14.4 invariant for a public-path
	// rotation: only the visible path moves.
	if rec.Hostname != "momsroute.example.com" {
		t.Errorf("hostname mutated: %q", rec.Hostname)
	}
	// Verify both UploadWorkerScript AND RotatePublicPath were
	// called against the CFClient.
	var sawUpload, sawRotate bool
	for _, c := range cf.Calls {
		if strings.HasPrefix(c, "UploadWorkerScript(") {
			sawUpload = true
		}
		if strings.HasPrefix(c, "RotatePublicPath(") {
			sawRotate = true
		}
	}
	if !sawUpload {
		t.Errorf("UploadWorkerScript not called: %v", cf.Calls)
	}
	if !sawRotate {
		t.Errorf("RotatePublicPath not called: %v", cf.Calls)
	}
}

// TestRotatePublicPath_RandomWhenEmpty asserts the §11.7
// auto-generation path: empty newPublicPath produces a /r/<hex>
// path so wizard callers don't accidentally land an empty path.
func TestRotatePublicPath_RandomWhenEmpty(t *testing.T) {
	cf := &MockCFClient{RotatePathRouteID: "route-X"}
	p := NewProvider(cf)
	rec := &FrontRecord{Hostname: "front.example.com", ZoneID: "z", PublicPath: "/r/old", OriginPath: "/ws", WorkerRouteID: "route-OLD"}
	newPath, _, err := p.RotatePublicPath(context.Background(), []byte("t"), "acc", rec, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(newPath, "/r/") {
		t.Errorf("auto-path = %q want /r/...", newPath)
	}
	if newPath == "/r/old" {
		t.Errorf("auto-path collided with old: %q", newPath)
	}
}

// TestRotateHostname_ReResolvesZoneAndRebinds locks the
// hostname-rotation flow: re-lookup the apex zone (potentially
// different zone if the FRP moved domains), ensure proxied DNS
// on the new hostname, re-upload the worker on the new zone,
// rebind the route. Origin path + public path unchanged; the
// caller re-signs the RelayPack afterwards.
func TestRotateHostname_ReResolvesZoneAndRebinds(t *testing.T) {
	cf := &MockCFClient{
		RotateHostnameZoneID:    "zone-NEW.com",
		RotateHostnameAccountID: "account-NEW.com",
		BindRouteID:             "route-NEW",
	}
	p := NewProvider(cf)
	rec := &FrontRecord{
		Hostname:      "momsroute.example.com",
		ZoneID:        "zone-example.com",
		PublicPath:    "/r/abcdef01",
		OriginPath:    "/ws",
		WorkerRouteID: "route-OLD",
	}
	newZoneID, newRouteID, err := p.RotateHostname(context.Background(), []byte("token"), rec, "frontB.newdomain.com", "5.75.9.9", "")
	if err != nil {
		t.Fatalf("RotateHostname: %v", err)
	}
	if newZoneID != "zone-NEW.com" {
		t.Errorf("newZoneID=%q", newZoneID)
	}
	if newRouteID != "route-NEW" {
		t.Errorf("newRouteID=%q", newRouteID)
	}
	if rec.Hostname != "frontB.newdomain.com" {
		t.Errorf("hostname not rotated: %q", rec.Hostname)
	}
	if rec.ZoneID != "zone-NEW.com" {
		t.Errorf("zone not rotated: %q", rec.ZoneID)
	}
	if rec.PublicPath != "/r/abcdef01" {
		t.Errorf("public path mutated: %q", rec.PublicPath)
	}
	if rec.OriginPath != "/ws" {
		t.Errorf("origin path mutated: %q", rec.OriginPath)
	}
}

// TestRotateOrigin_OriginOnlyInvisible locks the §14.4 origin-only
// invariant: the origin IP changes; hostname, public path, origin
// path, and the FrontRecord shape that drives the
// `_cdn_attestation` blob are byte-identical before and after.
// The caller MUST NOT re-sign the RelayPack — this test asserts
// the Provider does not mutate any of the public-surface fields.
func TestRotateOrigin_OriginOnlyInvisible(t *testing.T) {
	cf := &MockCFClient{}
	p := NewProvider(cf)
	rec := &FrontRecord{
		Hostname:            "momsroute.example.com",
		ZoneID:              "zone-example.com",
		PublicPath:          "/r/abcdef01",
		OriginPath:          "/ws",
		WorkerRouteID:       "route-1",
		OriginCAFingerprint: "ababababababababababababababababababababababababababababababab",
		AOPEnabled:          true,
		FirewallID:          "fw-1",
	}
	before := *rec
	if err := p.RotateOrigin(context.Background(), []byte("token"), rec, "5.75.99.99", "2a01:4f8::99"); err != nil {
		t.Fatalf("RotateOrigin: %v", err)
	}
	// Public-surface fields must be untouched (§14.4 origin-only).
	if rec.Hostname != before.Hostname {
		t.Errorf("hostname mutated: %q", rec.Hostname)
	}
	if rec.ZoneID != before.ZoneID {
		t.Errorf("zone mutated: %q", rec.ZoneID)
	}
	if rec.PublicPath != before.PublicPath {
		t.Errorf("public path mutated: %q", rec.PublicPath)
	}
	if rec.OriginPath != before.OriginPath {
		t.Errorf("origin path mutated: %q", rec.OriginPath)
	}
	if rec.WorkerRouteID != before.WorkerRouteID {
		t.Errorf("worker route id mutated: %q", rec.WorkerRouteID)
	}
	if rec.OriginCAFingerprint != before.OriginCAFingerprint {
		t.Errorf("OriginCA fingerprint mutated: %q", rec.OriginCAFingerprint)
	}
	if rec.AOPEnabled != before.AOPEnabled {
		t.Errorf("AOP toggled: %v", rec.AOPEnabled)
	}
	if rec.FirewallID != before.FirewallID {
		t.Errorf("firewall ID mutated: %q", rec.FirewallID)
	}
	// CFClient must have been called with RotateOrigin and the
	// new IPs.
	var saw bool
	for _, c := range cf.Calls {
		if strings.Contains(c, "RotateOrigin(") && strings.Contains(c, "5.75.99.99") {
			saw = true
		}
	}
	if !saw {
		t.Errorf("CFClient.RotateOrigin not called with new IPs: %v", cf.Calls)
	}
}

// TestRotateOrigin_RejectsEmptyIP guards against a wizard bug
// landing an empty origin IP and silently bringing the front down.
func TestRotateOrigin_RejectsEmptyIP(t *testing.T) {
	cf := &MockCFClient{}
	p := NewProvider(cf)
	rec := &FrontRecord{Hostname: "f.example.com", ZoneID: "z"}
	if err := p.RotateOrigin(context.Background(), []byte("t"), rec, "", ""); err == nil {
		t.Fatal("RotateOrigin did not reject empty IPv4")
	}
}

// TestRotateHostname_RejectsMissingFields belt-and-braces guard
// for a wizard bug landing an empty hostname or origin IP.
func TestRotateHostname_RejectsMissingFields(t *testing.T) {
	cf := &MockCFClient{}
	p := NewProvider(cf)
	rec := &FrontRecord{Hostname: "f.example.com", ZoneID: "z", PublicPath: "/r/x", OriginPath: "/ws"}
	if _, _, err := p.RotateHostname(context.Background(), []byte("t"), rec, "", "5.75.1.2", ""); err == nil {
		t.Error("RotateHostname accepted empty newHostname")
	}
	if _, _, err := p.RotateHostname(context.Background(), []byte("t"), rec, "new.example.com", "", ""); err == nil {
		t.Error("RotateHostname accepted empty IPv4")
	}
}
