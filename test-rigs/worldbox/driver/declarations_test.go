package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The declarations are data three people edit at once. These tests make a
// bad one fail in seconds, without building a world.

func rigDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "test-rigs", "worldbox")
}

// Every family the product's toolbox profile can provision has a
// declaration, and nothing is declared that the product does not know.
// Adding a family to the product without telling the rig fails here.
func TestFamiliesMatchTheProductProfile(t *testing.T) {
	fams, names, err := LoadFamilies(rigDir(t))
	if err != nil {
		t.Fatal(err)
	}
	all, defaults, err := ProfileFamilies(repoRoot(t), ToolboxProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(defaults) < 2 {
		t.Fatalf("profile %s enables %d families by default; a pack needs at least two candidates", ToolboxProfile, len(defaults))
	}
	sort.Strings(all)
	if strings.Join(all, ",") != strings.Join(names, ",") {
		t.Fatalf("families/*.json = %v\nprofile %s  = %v\ndeclare (or remove) the difference", names, ToolboxProfile, all)
	}
	seen := map[string]string{}
	for _, n := range names {
		f := fams[n]
		if f.Endpoint.Port <= 0 || (f.Endpoint.Proto != "tcp" && f.Endpoint.Proto != "udp") {
			t.Errorf("families/%s.json: endpoint %d/%q is not a port + tcp|udp", n, f.Endpoint.Port, f.Endpoint.Proto)
		}
		key := f.Endpoint.Proto + "/" + itoa(f.Endpoint.Port)
		if other, dup := seen[key]; dup {
			t.Errorf("families %s and %s both claim %s", other, n, key)
		}
		seen[key] = n
		if f.UDP != "" && f.UDP != Pass && f.UDP != Blocked {
			t.Errorf("families/%s.json: udp=%q, want pass|blocked|\"\"", n, f.UDP)
		}
		if f.DNS != "" && f.DNS != Pass && f.DNS != Blocked {
			t.Errorf("families/%s.json: dns=%q, want pass|blocked|\"\"", n, f.DNS)
		}
		// A family with no declared secret has no wrong-credential
		// control, and a pass without its negative control proves less
		// than it looks like.
		if len(f.Secrets) == 0 {
			t.Errorf("families/%s.json declares no secrets: name the credential field(s) that authenticate a recipient on it", n)
		}
		if f.Needs != "" && f.Needs != "cronet" {
			t.Errorf("families/%s.json: needs=%q is not something the rig can provide (see resolveNeeds)", n, f.Needs)
		}
	}
}

// Every scenario loads, and says what it expects of every family.
func TestScenariosDeclareAnExpectationForEveryFamily(t *testing.T) {
	rig := rigDir(t)
	_, fams, err := LoadFamilies(rig)
	if err != nil {
		t.Fatal(err)
	}
	scenarios := listNames(rig, "scenarios")
	if !contains(scenarios, "clean") {
		t.Fatal("scenarios/clean.json is the baseline and must exist")
	}
	for _, name := range scenarios {
		s, err := LoadScenario(rig, name)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if strings.TrimSpace(s.Description) == "" {
			t.Errorf("scenario %s has no description", name)
		}
		for _, f := range fams {
			if _, err := s.ExpectFor(f); err != nil {
				t.Errorf("%v", err)
			}
		}
		for f := range s.Expect {
			if f != "*" && !contains(fams, f) {
				t.Errorf("scenario %s expects something of %q, which is not a declared family", name, f)
			}
		}
		for _, line := range append(append([]string{}, s.Censor.NFT...), s.Censor.NFTRaw...) {
			for _, tok := range strings.Fields(line) {
				if strings.HasPrefix(tok, "$") {
					if _, ok := scenarioVars("x")[strings.Trim(tok[1:], "{},;")]; !ok {
						t.Errorf("scenario %s uses %s, which is not a substitution variable (see censor.go)", name, tok)
					}
				}
			}
		}
	}
}

func TestNftAllows(t *testing.T) {
	dump := `table inet wb_ufw {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		tcp dport 443 accept
		udp dport { 443, 8443 } accept
		ip saddr 198.18.0.2 tcp dport 22 accept
		ip saddr { 0.0.0.0/0 } tcp dport 8000-8100 accept
	}
}`
	cases := []struct {
		proto string
		port  int
		want  bool
	}{
		{"tcp", 443, true}, {"udp", 443, true}, {"udp", 8443, true}, {"tcp", 8443, false},
		{"tcp", 22, true}, {"tcp", 8050, true}, {"tcp", 8101, false}, {"udp", 53, false},
	}
	for _, c := range cases {
		if got := nftAllows(dump, c.proto, c.port); got != c.want {
			t.Errorf("nftAllows(%s/%d) = %v, want %v", c.proto, c.port, got, c.want)
		}
	}
}

func TestBlobIsDeterministic(t *testing.T) {
	if blobSum(42, 4096) != blobSum(42, 4096) || blobSum(42, 4096) == blobSum(43, 4096) {
		t.Fatal("blob() must be a pure function of (seed, size)")
	}
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
