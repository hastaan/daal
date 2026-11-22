package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relaypack"
)

// cdn-provision records the ranges it opened the provider firewall to:
// the door sends them to the relay and the binder takes its seeds from
// them.
func TestCDNProvisionVerb_RecordsTheRanges(t *testing.T) {
	_, _, dir := withCDNFakes(t)
	rc, out, errOut := cdnRunCLI(t, cdnProvisionArgs(dir)...)
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errOut)
	}
	var rec cloudflare.FrontRecord
	_ = json.Unmarshal([]byte(out), &rec)
	if strings.Join(rec.EdgeRanges, ",") != "173.245.48.0/20,2400:cb00::/32" {
		t.Fatalf("edge ranges = %v", rec.EdgeRanges)
	}
}

type doorCall struct {
	action, callerIP string
	front            *cloudflare.FrontRecord
	rec              *provider.OperatorRecord
}

// withDoorFakes stubs the two door calls and the provider, and writes
// an operator record, a key and a front record.
func withDoorFakes(t *testing.T, answer func(action string) (*mgmt.CDNDoorResp, error)) (calls *[]doorCall, recFile, keyFile, frontFile, hzFile string) {
	t.Helper()
	var got []doorCall
	oldE, oldD := cdnDoorEnable, cdnDoorDisable
	cdnDoorEnable = func(_ context.Context, _ provider.Provider, rec *provider.OperatorRecord, priv ed25519.PrivateKey, ip string, f *cloudflare.FrontRecord) (*mgmt.CDNDoorResp, error) {
		if len(priv) != ed25519.PrivateKeySize {
			t.Errorf("enable got a %d-byte key", len(priv))
		}
		got = append(got, doorCall{"enable", ip, f, rec})
		return answer("enable")
	}
	cdnDoorDisable = func(_ context.Context, _ provider.Provider, rec *provider.OperatorRecord, _ ed25519.PrivateKey, ip string) (*mgmt.CDNDoorResp, error) {
		got = append(got, doorCall{"disable", ip, nil, rec})
		return answer("disable")
	}
	t.Cleanup(func() { cdnDoorEnable, cdnDoorDisable = oldE, oldD })
	withFakeProvider(t, &captureProvisionProvider{})
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	keyFile = writeTemp(t, "priv", priv)
	rb, _ := json.Marshal(provider.OperatorRecord{Provider: "hetzner", ServerID: "4242", MgmtPort: 9443, MgmtTLSFingerprint: strings.Repeat("ab", 32)})
	recFile = writeTemp(t, "rec.json", rb)
	fb, _ := json.Marshal(cloudflare.FrontRecord{Hostname: "door.example.org", ZoneID: "z1", OriginPath: "/p", EdgeRanges: []string{"173.245.48.0/20"}})
	frontFile = writeTemp(t, "front.json", fb)
	hzFile = filepath.Join(dir, "hz")
	_ = os.WriteFile(hzFile, []byte(cdnTestHZToken), 0o600)
	return &got, recFile, keyFile, frontFile, hzFile
}

func TestCDNDoorVerb(t *testing.T) {
	unsupported, nobody := false, false
	calls, recFile, keyFile, frontFile, hzFile := withDoorFakes(t, func(action string) (*mgmt.CDNDoorResp, error) {
		if unsupported {
			return nil, mgmt.ErrCDNDoorUnsupported
		}
		if nobody {
			return nil, fmt.Errorf("%w (relay: no recipient on this relay yet)", mgmt.ErrCDNDoorNoRecipient)
		}
		return &mgmt.CDNDoorResp{Action: action, Enabled: action == "enable", Port: 8448, WSPath: "/p", Users: 2, BoxFirewallRules: 1}, nil
	})
	args := func(action string) []string {
		return []string{"cdn-door", "--record-file", frontFile, "--operator-record", recFile, "--token-file", hzFile,
			"--action", action, "--priv-key", keyFile, "--helper-ip", "1.2.3.4"}
	}
	rc, out, errs := cdnRunCLI(t, args("enable")...)
	if rc != 0 || !strings.Contains(out, `"enabled": true`) || !strings.Contains(out, `"box_firewall_rules": 1`) {
		t.Fatalf("enable rc=%d out=%s err=%s", rc, out, errs)
	}
	c := (*calls)[0]
	if c.action != "enable" || c.callerIP != "1.2.3.4" || c.front.Hostname != "door.example.org" || c.rec.ServerID != "4242" {
		t.Fatalf("call = %+v", c)
	}
	if rc, out, _ := cdnRunCLI(t, args("disable")...); rc != 0 || !strings.Contains(out, `"enabled": false`) {
		t.Fatalf("disable rc=%d out=%s", rc, out)
	}
	nobody = true
	if rc, _, errs := cdnRunCLI(t, args("enable")...); rc != exitCDNDoorNoRecipient || !strings.Contains(errs, "nobody on it yet") {
		t.Fatalf("a relay with nobody on it: rc=%d err=%s, want %d", rc, errs, exitCDNDoorNoRecipient)
	}
	nobody = false
	unsupported = true
	if rc, _, _ := cdnRunCLI(t, args("enable")...); rc != 3 {
		t.Fatalf("an old relay: rc=%d, want 3 (needs a rebuild)", rc)
	}
	if rc, _, _ := cdnRunCLI(t, args("open")...); rc != 2 {
		t.Fatalf("a bad action: rc=%d", rc)
	}
	if rc, _, _ := cdnRunCLI(t, "cdn-door", "--record-file", frontFile, "--action", "enable"); rc != 2 {
		t.Fatalf("missing flags: rc=%d", rc)
	}
}

// cdn-remove with the relay's record and key closes the door first and
// says so; without them the step is skipped and named.
func TestCDNRemoveVerb_ClosesTheDoor(t *testing.T) {
	_, _, dir := withCDNFakes(t)
	failDoor := false
	calls, recFile, keyFile, _, _ := withDoorFakes(t, func(string) (*mgmt.CDNDoorResp, error) {
		if failDoor {
			return nil, errors.New("no answer")
		}
		return &mgmt.CDNDoorResp{Action: "disable"}, nil
	})
	rc, out, errOut := cdnRunCLI(t, cdnProvisionArgs(dir)...)
	if rc != 0 {
		t.Fatalf("provision rc=%d %s", rc, errOut)
	}
	frontFile := writeTemp(t, "front-prov.json", []byte(out))
	base := []string{"cdn-remove", "--record-file", frontFile, "--token-file", filepath.Join(dir, "cf"), "--hetzner-token-file", filepath.Join(dir, "hz")}
	door := []string{"--operator-record", recFile, "--priv-key", keyFile, "--helper-ip", "1.2.3.4"}
	rc, out, errOut = cdnRunCLI(t, append(base, door...)...)
	if rc != 0 || len(*calls) != 1 || (*calls)[0].action != "disable" {
		t.Fatalf("rc=%d calls=%v out=%s err=%s", rc, *calls, out, errOut)
	}
	var rep struct {
		Steps []cloudflare.RemoveStep `json:"steps"`
	}
	_ = json.Unmarshal([]byte(out), &rep)
	found := false
	for _, s := range rep.Steps {
		if s.Name == "relay_door" {
			found = s.State == "done"
		}
	}
	if !found {
		t.Fatalf("relay_door not done: %s", out)
	}
	// Half the door flags is a usage error.
	if rc, _, _ := cdnRunCLI(t, append(base, "--operator-record", recFile)...); rc != 2 {
		t.Fatalf("door flags without the key: rc=%d", rc)
	}
	// A door that does not answer is a failed step (exit 4), and the
	// Cloudflare side still goes.
	_, _, dir2 := withCDNFakes(t)
	_, out, _ = cdnRunCLI(t, cdnProvisionArgs(dir2)...)
	frontFile = writeTemp(t, "front-prov2.json", []byte(out))
	failDoor = true
	rc, out, _ = cdnRunCLI(t, "cdn-remove", "--record-file", frontFile, "--token-file", filepath.Join(dir2, "cf"),
		"--hetzner-token-file", filepath.Join(dir2, "hz"), "--operator-record", recFile, "--priv-key", keyFile, "--helper-ip", "1.2.3.4")
	if rc != exitCDNRefused || !strings.Contains(out, `"relay_door"`) || !strings.Contains(out, `"failed"`) {
		t.Fatalf("failed door: rc=%d out=%s", rc, out)
	}
}

// The record's own cdn_front member (what the app keeps while the way in
// is live) signs the CDN route with no --cdn-* flag: seeds from the
// ranges cdn-provision read, the roots the app ships.
func TestBindAndSign_RecordMemberSignsTheCDNRoute(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	_ = json.Unmarshal(raw, &rec)
	rec["cdn_front"] = map[string]any{
		"hostname": "door.example.org", "zone": "example.org", "zone_id": "z1",
		"origin_path": "/0123456789abcdef0123456789abcdef", "firewall_id": "4711",
		"origin_ca_fingerprint": strings.Repeat("ab", 32), "aop_enabled": true,
		"ech":            map[string]any{"zone_setting": "on", "published": true, "config_list_b64": "AAT+DQAA", "public_name": "cloudflare-ech.com"},
		"edge_ranges":    []string{"173.245.48.0/20", "104.16.0.0/13", "2400:cb00::/32"},
		"plain_fallback": true,
	}
	rb, _ := json.Marshal(rec)
	withFront := writeTemp(t, "rec-cdn.json", rb)
	out := filepath.Join(t.TempDir(), "rp.sbp")
	rc, _, errs := runG(t, "bind-and-sign", "--operator-record", withFront, "--priv-key", privPath, "--output", out,
		"--phase", string(relaypackvalidate.PhaseV16), "--now-unix", "1746115200")
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errs)
	}
	body, _ := os.ReadFile(out)
	b, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	last := b.Manifest.Routes[len(b.Manifest.Routes)-1]
	ep, err := bundle.ParseCDNEndpoint(last.TransportFamily, last.FamilySpecificConfig)
	if err != nil {
		t.Fatalf("no CDN route signed from the record member: %v", err)
	}
	if strings.Join(ep.EdgeSeeds, ",") != "104.16.0.0/13,173.245.48.0/20,2400:cb00::/32" {
		t.Errorf("seeds = %v (widest v4 first, then v6)", ep.EdgeSeeds)
	}
	if strings.Join(ep.TLSRootsSHA256, ",") != strings.Join(relaypack.CDNShippedRootDigests(), ",") {
		t.Errorf("roots = %v, want the shipped set", ep.TLSRootsSHA256)
	}
	if !ep.PlainFallback {
		t.Error("the record's plain_fallback was not signed")
	}
	// A record without the member signs no CDN route.
	rc, _, errs = runG(t, "bind-and-sign", "--operator-record", recPath, "--priv-key", privPath, "--output", out,
		"--phase", string(relaypackvalidate.PhaseV16), "--now-unix", "1746115200")
	if rc != 0 {
		t.Fatalf("plain rc=%d %s", rc, errs)
	}
	body, _ = os.ReadFile(out)
	b, _ = bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	for _, r := range b.Manifest.Routes {
		if _, err := bundle.ParseCDNEndpoint(r.TransportFamily, r.FamilySpecificConfig); err == nil {
			t.Fatal("a CDN route signed without a front")
		}
	}
}
