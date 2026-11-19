package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Family is one transport family as the RIG sees it: how to ask the
// relay to serve it, where it listens, and what the client side is
// expected to be able to do. One file per family in families/<name>.json.
// It does not describe the protocol — the product does that; this only
// declares what to assert.
type Family struct {
	// Name is the family string, identical in the toolbox profile
	// (--families), the pack, and the engine's route list.
	Name string `json:"name"`
	// Endpoint is where the relay must be listening for it.
	Endpoint struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"` // tcp | udp
	} `json:"endpoint"`
	// Experimental: the client needs the experimental-families gate on.
	Experimental bool `json:"experimental,omitempty"`
	// UDP: whether an app's UDP datagrams (a small one and a 1400-byte
	// one) are expected to round-trip through this family ("pass" |
	// "blocked" | "" = do not assert).
	UDP string `json:"udp,omitempty"`
	// DNS: whether an app's name lookup — plain UDP/53 to the resolvers
	// the VpnService configures — is expected to be answered through this
	// family ("pass" | "blocked" | "" = do not assert).
	DNS string `json:"dns,omitempty"`
	// Secrets are the fields of the relay's credential reply
	// (/users/provision → creds-<name>.json) that authenticate a recipient
	// on this family. The wrong-credential control forges each ONE of
	// them, alone, in an otherwise genuine pack, and the family must then
	// carry nothing. A family with no secrets declared has no such
	// control, and declarations_test.go refuses that.
	Secrets []string `json:"secrets,omitempty"`
	// Pins are the fields of the same reply that identify the RELAY to
	// the client (a certificate pin, the REALITY public key). The
	// wrong-server control forges each one alone: the genuine relay then
	// no longer matches what the pack says, and the client must refuse to
	// talk to it. This is the insider's protection against an impostor in
	// the path, and nothing else in the rig would notice if a family
	// stopped enforcing it. Empty for a family whose only authenticator
	// is a shared key (the secret already covers both directions).
	Pins []string `json:"pins,omitempty"`
	// Needs names something outside the engine binary the client side
	// depends on ("cronet"). When it is not available the family is
	// SKIPPED with the reason, at run time, instead of failing.
	Needs string `json:"needs,omitempty"`
	// Skip, when non-empty, means the family cannot be exercised by this
	// rig; the reason is reported on every run. Never delete a family
	// file to make a matrix green.
	Skip string `json:"skip,omitempty"`
	Note string `json:"note,omitempty"`
}

// Scenario is one censor behaviour: the rules the censor namespace
// applies and what each family is expected to do under them. One file per
// scenario in scenarios/<name>.json.
type Scenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Censor      struct {
		// NFT: rule lines placed, in order, in the censor's forward
		// chain (table inet wb_censor, hook forward, policy accept).
		NFT []string `json:"nft,omitempty"`
		// NFTRaw: a complete nft file for anything a forward chain
		// cannot express (other hooks, sets, flowtables).
		NFTRaw []string `json:"nft_raw,omitempty"`
		// TC: `tc qdisc replace dev <dev> root <args>`.
		TC []struct {
			Dev  string `json:"dev"`
			Args string `json:"args"`
		} `json:"tc,omitempty"`
		// DPI: payload rules run by `wb dpi` over NFQUEUE, for what a
		// static rule cannot express (TLS SNI, first data packet,
		// forged RSTs). See censor_dpi.go.
		DPI []DPIRule `json:"dpi,omitempty"`
	} `json:"censor"`
	// Analogue: the documented real-world behaviour this models, and
	// where the model stops. Required.
	Analogue string `json:"analogue"`
	// Prove: raw probes, independent of Daal, that show each rule bites
	// and that an innocent neighbour is spared. See censor.go.
	Prove []Proof `json:"prove,omitempty"`
	// Expect maps family name → pass|blocked. "*" is the default. A
	// family with no entry and no "*" is an error, not an assumption.
	Expect map[string]string `json:"expect"`
	// Category maps family name (or "*") → the failure category from
	// specs/failure-taxonomy-v1.md that describes what this censor does
	// to that family. Required for every family expected to be blocked.
	Category map[string]string `json:"category,omitempty"`
	// Established maps family name (or "*") → "pass": although the family
	// is expected "blocked", it must first be shown to have CONNECTED AND
	// AUTHENTICATED — a nonce round trip through the tunnel that the
	// target saw arrive from the relay — before the payload is allowed to
	// run out of budget. Required wherever a blocked expectation comes
	// from the probe's budget and not from a rule the client can name
	// (category none | unasserted): there "blocked" alone is what a dead
	// family looks like too. Ignored for a family expected to pass (its
	// tunnel check already demands more).
	Established map[string]string `json:"established,omitempty"`
	// ProbePatienceMs is added to the raw probes' own timeouts (a SYN
	// answered within 2 s, a first flight within 2.5 s). Only for a
	// scenario that delays packets by more than those: there the probe's
	// impatience, not the censor, would be what "blocks".
	ProbePatienceMs int `json:"probe_patience_ms,omitempty"`
	// RandomLoss: the censor drops a share of the packets at random
	// instead of by a rule a packet either matches or does not. The wire
	// tap sits BEFORE the censor's filter and counts what each side SENT
	// (wire.go), so under such a censor "the relay sent a payload's worth
	// of bytes" no longer means the client received the payload: some of
	// them were dropped after being counted, and every retransmission is
	// counted again. For a session whose probe did not receive its
	// payload the wire check then asserts what the tap can still witness
	// — the family's own endpoint was tried, and nothing else was — and
	// not the byte count. See wireUnderRandomLoss.
	RandomLoss bool `json:"random_loss,omitempty"`
}

// MustEstablish: the scenario claims this family still connects, and only
// then fails to move the payload.
func (s Scenario) MustEstablish(family string) bool {
	if e, _ := s.ExpectFor(family); e != Blocked {
		return false
	}
	if v, ok := s.Established[family]; ok {
		return v == Pass
	}
	return s.Established["*"] == Pass
}

func (s Scenario) ExpectFor(family string) (string, error) {
	if v, ok := s.Expect[family]; ok {
		return v, nil
	}
	if v, ok := s.Expect["*"]; ok {
		return v, nil
	}
	return "", fmt.Errorf("scenario %q declares no expectation for family %q (and no \"*\" default)", s.Name, family)
}

func loadJSON(path string, v any) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields() // a typo in a declaration must not silently mean "default"
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func LoadScenario(rig, name string) (Scenario, error) {
	var s Scenario
	if err := loadJSON(filepath.Join(rig, "scenarios", name+".json"), &s); err != nil {
		return s, err
	}
	if s.Name != name {
		return s, fmt.Errorf("scenarios/%s.json declares name %q", name, s.Name)
	}
	for f, v := range s.Expect {
		if v != Pass && v != Blocked {
			return s, fmt.Errorf("scenario %q: expect[%q]=%q, want pass|blocked", name, f, v)
		}
	}
	return s, nil
}

func LoadFamilies(rig string) (map[string]Family, []string, error) {
	paths, _ := filepath.Glob(filepath.Join(rig, "families", "*.json"))
	out := map[string]Family{}
	var names []string
	for _, p := range paths {
		var f Family
		if err := loadJSON(p, &f); err != nil {
			return nil, nil, err
		}
		if f.Name != strings.TrimSuffix(filepath.Base(p), ".json") {
			return nil, nil, fmt.Errorf("%s declares name %q", p, f.Name)
		}
		out[f.Name] = f
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return out, names, nil
}

func listNames(rig, dir string) []string {
	paths, _ := filepath.Glob(filepath.Join(rig, dir, "*.json"))
	var out []string
	for _, p := range paths {
		out = append(out, strings.TrimSuffix(filepath.Base(p), ".json"))
	}
	sort.Strings(out)
	return out
}

func cmdList(args []string) int {
	rig := "."
	if len(args) > 0 {
		rig = args[0]
	}
	fmt.Println("scenarios:", strings.Join(listNames(rig, "scenarios"), " "))
	fmt.Println("families: ", strings.Join(listNames(rig, "families"), " "))
	var ops []string
	for name := range Ops {
		ops = append(ops, name)
	}
	sort.Strings(ops)
	fmt.Println("ops:      ", strings.Join(ops, " "))
	return 0
}

// ProfileFamilies reads the PRODUCT's toolbox profile (the same JSON the
// provisioner embeds) and returns every family it knows and the subset it
// enables by default. The rig never keeps its own copy of that list.
func ProfileFamilies(repo, profile string) (all, defaults []string, err error) {
	var doc struct {
		Candidates []struct {
			Family         string `json:"family"`
			DefaultEnabled bool   `json:"default_enabled"`
		} `json:"candidates"`
	}
	body, err := os.ReadFile(filepath.Join(repo, "publisher", "deploy", "profiles", profile+".json"))
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, err
	}
	for _, c := range doc.Candidates {
		all = append(all, c.Family)
		if c.DefaultEnabled {
			defaults = append(defaults, c.Family)
		}
	}
	if len(all) == 0 {
		return nil, nil, fmt.Errorf("profile %s lists no candidate families", profile)
	}
	return all, defaults, nil
}
