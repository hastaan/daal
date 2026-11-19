package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// --- PA-3: decommission exits 7 when another server keeps the name ---

func TestDecommission_NamedServerRemainsExits7(t *testing.T) {
	rep := provider.NewDecommissionReport("hetzner", "12345")
	rep.NamedServer = &provider.NamedServer{ID: "777", Name: "daal-fsn1-abcd"}
	rep.Preserve("server:777")
	rep.Warnf("the recorded server is already gone, but your hosting account still has another server with this relay's name")
	fake := &fakeReleasingProvider{report: rep, err: fmt.Errorf("hetzner: %w: 777", provider.ErrNamedServerRemains)}
	withFakeProvider(t, fake)
	recordFile, tokenFile := writeRecordWithFIP(t, "fip-1")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile, "--json", "--release-addresses"}, &stdout, &stderr)
	if rc != 7 {
		t.Fatalf("rc=%d, want 7; stderr=%s", rc, stderr.String())
	}
	var got provider.DecommissionReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ServerDeleted || got.NamedServer == nil || got.NamedServer.ID != "777" || got.NamedServer.Name != "daal-fsn1-abcd" {
		t.Fatalf("report = %s", stdout.String())
	}
	if fake.releaseCalls != 0 {
		t.Fatal("addresses were released while a server with this relay's name remains")
	}
	// Any other error still exits 1.
	fake.err = fmt.Errorf("hetzner: look up server: 503")
	stdout.Reset()
	if rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr); rc != 1 {
		t.Fatalf("plain error rc=%d, want 1", rc)
	}
}

// --- PA-1: release-address ---

type fakeOneAddressProvider struct {
	providerFace
	out   provider.AddressOutcome
	asked []string
}

func (f *fakeOneAddressProvider) ReleaseOneAddress(_ context.Context, _ *provider.OperatorRecord, idOrIP string) provider.AddressOutcome {
	f.asked = append(f.asked, idOrIP)
	return f.out
}

func TestReleaseAddress_ExitCodesAndOneOutcome(t *testing.T) {
	for code, wantRC := range map[string]int{
		provider.AddrReleased:      0,
		provider.AddrNotDaal:       0,
		provider.AddrStillAttached: 0,
		provider.AddrInUse:         0,
		provider.AddrReleaseFailed: 6,
	} {
		t.Run(code, func(t *testing.T) {
			fake := &fakeOneAddressProvider{out: provider.AddressOutcome{ID: "fip-9", IP: "198.51.100.9",
				Released: code == provider.AddrReleased, Code: code}}
			withFakeProvider(t, fake)
			recordFile, tokenFile := writeDecommissionFixture(t)
			var stdout, stderr bytes.Buffer
			rc := Run([]string{"release-address", "--record-file", recordFile, "--token-file", tokenFile, "--address", "fip-9", "--json"}, &stdout, &stderr)
			if rc != wantRC {
				t.Fatalf("rc=%d, want %d; stderr=%s", rc, wantRC, stderr.String())
			}
			if len(fake.asked) != 1 || fake.asked[0] != "fip-9" {
				t.Fatalf("asked = %v", fake.asked)
			}
			var o provider.AddressOutcome
			dec := json.NewDecoder(&stdout)
			if err := dec.Decode(&o); err != nil {
				t.Fatal(err)
			}
			if dec.More() {
				t.Fatal("stdout carries more than one outcome")
			}
			if o.Code != code || o.ID != "fip-9" || o.IP != "198.51.100.9" {
				t.Fatalf("outcome = %+v", o)
			}
			if strings.Contains(stdout.String()+stderr.String(), "dummy-token") {
				t.Fatal("the token reached the output")
			}
		})
	}
}

func TestReleaseAddress_UnsupportedProviderExits3(t *testing.T) {
	withFakeProvider(t, &fakeTeardownProvider{})
	recordFile, tokenFile := writeDecommissionFixture(t)
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"release-address", "--record-file", recordFile, "--token-file", tokenFile, "--address", "203.0.113.4"}, &stdout, &stderr); rc != 3 {
		t.Fatalf("rc=%d, want 3", rc)
	}
	var o provider.AddressOutcome
	if err := json.Unmarshal(stdout.Bytes(), &o); err != nil || o.Code != provider.AddrReleaseFailed || o.IP != "203.0.113.4" {
		t.Fatalf("outcome = %s (%v)", stdout.String(), err)
	}
}

func TestReleaseAddress_FlagAndReadErrors(t *testing.T) {
	recordFile, tokenFile := writeDecommissionFixture(t)
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"release-address", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr); rc != 2 {
		t.Fatalf("missing --address rc=%d, want 2", rc)
	}
	if rc := Run([]string{"release-address", "--bogus"}, &stdout, &stderr); rc != 2 {
		t.Fatalf("unknown flag rc=%d, want 2", rc)
	}
	missing := filepath.Join(t.TempDir(), "nope.json")
	if rc := Run([]string{"release-address", "--record-file", missing, "--token-file", tokenFile, "--address", "x"}, &stdout, &stderr); rc != 1 {
		t.Fatalf("unreadable record rc=%d, want 1", rc)
	}
	// The real provider builder with an unreadable token file: fails
	// before any network call.
	if rc := Run([]string{"release-address", "--record-file", recordFile, "--token-file", missing, "--address", "x"}, &stdout, &stderr); rc != 1 {
		t.Fatalf("unreadable token rc=%d, want 1", rc)
	}
}
