package hetzner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/sni"
	"gopkg.in/yaml.v3"
)

// seededOpts is liveOpts with a deterministic publisher key, so a test
// can talk about "relay N" and get the same cover host every run. The
// key is what derivedServerName — and therefore the cover-SNI seed — is
// derived from.
func seededOpts(seedByte byte) provider.ProvisionOpts {
	pub := make([]byte, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = seedByte
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	return provider.ProvisionOpts{
		PublisherPubKey: pub,
		Region:          "fsn1",
		ServerType:      "cx22",
		ToolboxProfile:  "iran-default",
		HelperIP:        net.ParseIP("1.2.3.4"),
		EphemeralSSHKey: priv,
	}
}

// singBoxFromCloudInit pulls /etc/sing-box/config.json back out of the
// rendered cloud-init. Parsing the real artefact — rather than asserting
// on the string that went in — is the point: this is the file the box
// boots with.
func singBoxFromCloudInit(t *testing.T, userData string) map[string]any {
	t.Helper()
	var doc struct {
		WriteFiles []struct {
			Path    string `yaml:"path"`
			Content string `yaml:"content"`
		} `yaml:"write_files"`
	}
	if err := yaml.Unmarshal([]byte(userData), &doc); err != nil {
		t.Fatalf("cloud-init is not valid YAML: %v", err)
	}
	for _, wf := range doc.WriteFiles {
		if wf.Path != "/etc/sing-box/config.json" {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(wf.Content), &cfg); err != nil {
			t.Fatalf("embedded sing-box config is not valid JSON: %v", err)
		}
		return cfg
	}
	t.Fatal("cloud-init has no /etc/sing-box/config.json")
	return nil
}

func fileFromCloudInit(t *testing.T, userData, path string) (string, bool) {
	t.Helper()
	var doc struct {
		WriteFiles []struct {
			Path    string `yaml:"path"`
			Content string `yaml:"content"`
		} `yaml:"write_files"`
	}
	if err := yaml.Unmarshal([]byte(userData), &doc); err != nil {
		t.Fatalf("cloud-init is not valid YAML: %v", err)
	}
	for _, wf := range doc.WriteFiles {
		if wf.Path == path {
			return strings.TrimSpace(wf.Content), true
		}
	}
	return "", false
}

// realityCover returns (server_name, handshake.server) of the first
// REALITY inbound in a parsed sing-box config.
func realityCover(t *testing.T, cfg map[string]any) (string, string) {
	t.Helper()
	inbounds, _ := cfg["inbounds"].([]any)
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		tls, _ := in["tls"].(map[string]any)
		if tls == nil {
			continue
		}
		reality, _ := tls["reality"].(map[string]any)
		if reality == nil {
			continue
		}
		if enabled, _ := reality["enabled"].(bool); !enabled {
			continue
		}
		name, _ := tls["server_name"].(string)
		hs, _ := reality["handshake"].(map[string]any)
		dest := ""
		if hs != nil {
			dest, _ = hs["server"].(string)
		}
		return name, dest
	}
	t.Fatal("no REALITY inbound in the sing-box config")
	return "", ""
}

// TestProvision_CloudInitCoverSNIMatchesItself is the Wave-4 DONE test's
// unit-level half: the box that boots from this cloud-init advertises
// the same name it falls back to. Until Wave 2 both were the hard-coded
// constant, so they agreed by accident; now that the value is per-relay
// and rotatable, the agreement is what has to be proven.
func TestProvision_CloudInitCoverSNIMatchesItself(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, err := p.Provision(context.Background(), seededOpts(0x11))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	cfg := singBoxFromCloudInit(t, f.lastUserData)
	name, dest := realityCover(t, cfg)

	if name == "" {
		t.Fatal("cloud-init shipped an empty tls.server_name")
	}
	if name != dest {
		t.Errorf("tls.server_name = %q but reality.handshake.server = %q — a prober gets the wrong site's cert", name, dest)
	}
	if rec.CoverSNI != name {
		t.Errorf("OperatorRecord.CoverSNI = %q but the box serves %q; the binder would mint a pack the relay cannot answer", rec.CoverSNI, name)
	}
	if name == sni.LegacyCoverSNI {
		t.Errorf("a freshly provisioned relay still advertises the fleet-wide constant %q", name)
	}
	if err := sni.ValidHost(name); err != nil {
		t.Errorf("chosen cover host is not admissible: %v", err)
	}
	// The box states its own cover host so /rotate-tls has something to
	// rewrite and an operator has something to read.
	declared, ok := fileFromCloudInit(t, f.lastUserData, "/etc/daal/cover-sni")
	if !ok {
		t.Fatal("cloud-init does not write /etc/daal/cover-sni")
	}
	if declared != name {
		t.Errorf("/etc/daal/cover-sni = %q, config serves %q", declared, name)
	}
}

// TestProvision_TwoRelaysGetDifferentCoverSNI. The whole point: one
// censor action must not be able to reach the whole fleet.
func TestProvision_TwoRelaysGetDifferentCoverSNI(t *testing.T) {
	seen := map[string]int{}
	for b := byte(1); b <= 12; b++ {
		f := newFake()
		rec, err := New(f).Provision(context.Background(), seededOpts(b))
		if err != nil {
			t.Fatalf("Provision(%d): %v", b, err)
		}
		if rec.CoverSNI == "" {
			t.Fatalf("Provision(%d) produced no cover SNI", b)
		}
		seen[rec.CoverSNI]++
	}
	if len(seen) < 2 {
		t.Fatalf("12 relays all landed on one cover host: %v", seen)
	}
}

// TestProvision_SameRelayIsStable. Re-running provisioning for the same
// relay must not silently move a live box's SNI.
func TestProvision_SameRelayIsStable(t *testing.T) {
	first, err := New(newFake()).Provision(context.Background(), seededOpts(0x22))
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(newFake()).Provision(context.Background(), seededOpts(0x22))
	if err != nil {
		t.Fatal(err)
	}
	if first.CoverSNI != second.CoverSNI {
		t.Errorf("same relay got %q then %q", first.CoverSNI, second.CoverSNI)
	}
}

// TestProvision_HonoursPersistedCoverSNI. A rebuild or retry must keep
// serving the name the already-distributed packs expect.
func TestProvision_HonoursPersistedCoverSNI(t *testing.T) {
	const persisted = "mirror.init7.net"
	f := newFake()
	opts := seededOpts(0x33)
	opts.CoverSNI = persisted
	rec, err := New(f).Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI != persisted {
		t.Errorf("CoverSNI = %q, want the persisted %q", rec.CoverSNI, persisted)
	}
	name, dest := realityCover(t, singBoxFromCloudInit(t, f.lastUserData))
	if name != persisted || dest != persisted {
		t.Errorf("cloud-init serves (%q, %q), want both %q", name, dest, persisted)
	}
}

// TestProvision_RejectsImplausibleCoverSNI: an operator (or a stale
// record) must not be able to hand a relay a CDN-fronted cover host and
// re-create the fleet-wide correlation by hand.
func TestProvision_RejectsImplausibleCoverSNI(t *testing.T) {
	opts := seededOpts(0x34)
	opts.CoverSNI = "assets.cloudflare.com"
	if _, err := New(newFake()).Provision(context.Background(), opts); err == nil {
		t.Fatal("Provision accepted a Cloudflare-fronted cover host")
	}
}

// TestProvision_LegacyRecordStillProvisions. A record minted before the
// cover_sni field exists must not panic, must not be rejected, and must
// be described truthfully: the box out there really is advertising the
// old constant until somebody rotates it.
func TestProvision_LegacyRecordStillProvisions(t *testing.T) {
	f := newFake()
	p := New(f)
	// Build the box the way the old code would have.
	first, err := p.Provision(context.Background(), seededOpts(0x44))
	if err != nil {
		t.Fatal(err)
	}
	// Now re-run provisioning the way a pre-Wave-2 record would: mgmt
	// port persisted, cover SNI absent.
	legacy := seededOpts(0x44)
	legacy.MgmtPort = first.MgmtPort
	legacy.CoverSNI = "" // the field did not exist when this record was written
	if _, err := p.Provision(context.Background(), legacy); err == nil {
		t.Fatal("adopting an existing box with no stated cover host must fail, " +
			"not invent one — the record is what the pack minter and the " +
			"rotation exclusion both read")
	}
	// The operator states what that pre-Wave-2 box really serves, and
	// the record then says so.
	legacy.CoverSNI = sni.LegacyCoverSNI
	rec, err := p.Provision(context.Background(), legacy)
	if err != nil {
		t.Fatalf("legacy record with an explicit cover host failed: %v", err)
	}
	if rec.CoverSNI != sni.LegacyCoverSNI {
		t.Errorf("adopted legacy box reports CoverSNI %q, want the truth (%q)", rec.CoverSNI, sni.LegacyCoverSNI)
	}
	// And the box it adopted is NOT re-picked onto a pool host: the
	// config out there was never rewritten.
	if rec.CoverSNI == first.CoverSNI {
		t.Errorf("adopt path claimed the pool host %q for a box built before it", rec.CoverSNI)
	}
}

// TestProvision_LegacyConstantIsUpgradedOnRebuild. A record that still
// carries the constant must NOT be honoured when a box is actually being
// built — that would mint a brand-new relay into the fleet-wide bet.
func TestProvision_LegacyConstantIsUpgradedOnRebuild(t *testing.T) {
	f := newFake()
	opts := seededOpts(0x55)
	opts.CoverSNI = sni.LegacyCoverSNI
	rec, err := New(f).Provision(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI == sni.LegacyCoverSNI {
		t.Fatal("a newly built box was born on the fleet-wide constant")
	}
	name, dest := realityCover(t, singBoxFromCloudInit(t, f.lastUserData))
	if name != rec.CoverSNI || dest != rec.CoverSNI {
		t.Errorf("cloud-init serves (%q, %q), record says %q", name, dest, rec.CoverSNI)
	}
}

// TestReprovision_PicksAFreshCoverSNI. Re-provisioning is how a burned
// relay is replaced; handing it back the burned name is not a rotation.
func TestReprovision_PicksAFreshCoverSNI(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, err := p.Provision(context.Background(), seededOpts(0x66))
	if err != nil {
		t.Fatal(err)
	}
	before := rec.CoverSNI
	if before == "" {
		t.Fatal("no cover SNI to rotate away from")
	}
	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{}); err != nil {
		t.Fatalf("Reprovision: %v", err)
	}
	if rec.CoverSNI == before {
		t.Errorf("re-provision kept the burned cover host %q", before)
	}
	if err := sni.ValidHost(rec.CoverSNI); err != nil {
		t.Errorf("re-provision chose an inadmissible host: %v", err)
	}
	// And the fresh value must survive into the box the caller builds
	// next, which is how the wizard composes Reprovision + Provision.
	next := seededOpts(0x66)
	next.CoverSNI = rec.CoverSNI
	rebuilt, err := p.Provision(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.CoverSNI != rec.CoverSNI {
		t.Errorf("rebuilt box serves %q, record says %q", rebuilt.CoverSNI, rec.CoverSNI)
	}
	name, dest := realityCover(t, singBoxFromCloudInit(t, f.lastUserData))
	if name != rec.CoverSNI || dest != rec.CoverSNI {
		t.Errorf("rebuilt cloud-init serves (%q, %q), want %q", name, dest, rec.CoverSNI)
	}
}

// TestReprovision_HonoursExplicitNewSNI is rung L2's explicit form.
func TestReprovision_HonoursExplicitNewSNI(t *testing.T) {
	p := New(newFake())
	rec, err := p.Provision(context.Background(), seededOpts(0x77))
	if err != nil {
		t.Fatal(err)
	}
	const want = "mirror.dogado.de"
	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{NewSNI: want}); err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI != want {
		t.Errorf("CoverSNI = %q, want %q", rec.CoverSNI, want)
	}
}

// TestReprovision_RejectsBadSNIWithoutDeleting: resolution happens
// before the destructive call, so a typo does not cost the operator a
// server.
func TestReprovision_RejectsBadSNIWithoutDeleting(t *testing.T) {
	f := newFake()
	p := New(f)
	rec, err := p.Provision(context.Background(), seededOpts(0x88))
	if err != nil {
		t.Fatal(err)
	}
	id := rec.ServerID
	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{NewSNI: "www.cloudflare.com"}); err == nil {
		t.Fatal("Reprovision accepted a blanket-blocked cover host")
	}
	if _, err := f.ServerByID(context.Background(), id); err != nil {
		t.Errorf("the server was deleted despite the rejected rotation: %v", err)
	}
}

// TestNextCoverSNI_KeepsMovingAcrossRotations. Successive rotations of
// the same relay must not oscillate between two hosts, which a
// time-independent seed would do.
func TestNextCoverSNI_KeepsMovingAcrossRotations(t *testing.T) {
	rec := &provider.OperatorRecord{ServerID: "4242", Region: "fsn1"}
	rec.CoverSNI = sni.Pick("seed", "fsn1")
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	seen := map[string]bool{rec.CoverSNI: true}
	for i := 0; i < 8; i++ {
		next, err := provider.NextCoverSNI(rec, "", now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if next == rec.CoverSNI {
			t.Fatalf("rotation %d returned the current host %q", i, next)
		}
		rec.CoverSNI = next
		seen[next] = true
	}
	if len(seen) < 3 {
		t.Errorf("8 rotations visited only %d hosts: %v", len(seen), seen)
	}
}
