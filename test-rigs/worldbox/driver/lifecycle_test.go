package main

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every op `--ops lifecycle` names must exist, or a renamed file would
// silently drop a whole stage of the lifecycle from the run.
func TestLifecycleOpsAreRegistered(t *testing.T) {
	for _, name := range LifecycleOps {
		if _, ok := Ops[name]; !ok {
			t.Errorf("LifecycleOps names %q but no ops_*.go registers it", name)
		}
	}
	if _, ok := Ops["lifecycle"]; !ok {
		t.Error(`the "lifecycle" op is not registered`)
	}
	// caps judges what the other ops observed: it must come after them.
	if LifecycleOps[len(LifecycleOps)-1] != "caps" {
		t.Errorf("caps must run last, got order %v", LifecycleOps)
	}
}

// The capability tokens the rig can judge must be exactly the tokens the
// PRODUCT's publisher knows (publisher/deploy/mgmt). A token added to
// the product with no proof here would be advertised by relays and
// examined by nothing; one removed from the product would leave a proof
// that can never fire.
func TestCapProofsCoverEveryProductToken(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(repo, "publisher", "deploy", "mgmt", "*.go"))
	re := regexp.MustCompile(`(?m)^\s*(?:const\s+)?Cap[A-Za-z0-9]+\s*=\s*"([^"]+)"`)
	product := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			product[m[1]] = true
		}
	}
	if len(product) == 0 {
		t.Fatal("found no capability tokens in publisher/deploy/mgmt — did the constants move?")
	}
	rig := map[string]bool{}
	for _, p := range capProofs {
		if rig[p.Token] {
			t.Errorf("capProofs lists %q twice", p.Token)
		}
		rig[p.Token] = true
	}
	var missing, stale []string
	for tok := range product {
		if !rig[tok] {
			missing = append(missing, tok)
		}
	}
	for tok := range rig {
		if !product[tok] {
			stale = append(stale, tok)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("the product defines capability tokens the rig has no proof for (add a capProof in ops_caps.go): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("ops_caps.go has proofs for tokens the product no longer defines: %v", stale)
	}
}

// The lab's floating-IP pool must sit on the relay's public segment (so
// the insider reaches it through the censor exactly as it reaches the
// primary address) and must not contain the primary address itself.
func TestFloatingIPPoolIsOnTheRelaySegment(t *testing.T) {
	_, segment, _ := net.ParseCIDR(Relay1IP + "/24")
	seen := map[string]bool{}
	for _, a := range FloatingIPPool {
		ip := net.ParseIP(a)
		if ip == nil || !segment.Contains(ip) {
			t.Errorf("pool address %s is not on the relay's segment %s", a, segment)
		}
		if a == Relay1IP || a == CensorRelayIP {
			t.Errorf("pool address %s collides with a fixed address", a)
		}
		if seen[a] {
			t.Errorf("pool address %s listed twice", a)
		}
		seen[a] = true
	}
	if !strings.Contains(RelayPublicAddrSet(), Relay1IP) || !strings.Contains(RelayPublicAddrSet(), FloatingIPPool[0]) {
		t.Errorf("RelayPublicAddrSet() = %s must name the primary address and the pool", RelayPublicAddrSet())
	}
}

// The freshness op's three public names must be distinct hosts on
// distinct registrable domains: the product refuses a mirror set whose
// members share a provider, and a pack URL on a mirror's host would let
// one blocked name take both away.
func TestFreshnessNamesAreDistinct(t *testing.T) {
	host := func(u string) string { return strings.SplitN(strings.TrimPrefix(u, "https://"), "/", 2)[0] }
	hosts := []string{host(freshMirrorR2), host(freshMirrorGH), host(freshPackURL)}
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h] || !strings.Contains(h, ".") || net.ParseIP(h) != nil {
			t.Errorf("freshness host %q must be a unique domain name", h)
		}
		seen[h] = true
	}
}
