package cloudinit

import (
	"reflect"
	"testing"

	"daal/publisher/deploy/profiles"
)

func pinnedMgmtSha(t *testing.T) string {
	t.Helper()
	for _, a := range V2Artifacts.Artefacts {
		if a.InstallAs == "daal-relay-mgmt" {
			return a.Sha256
		}
	}
	t.Fatal("V2Artifacts pins no daal-relay-mgmt")
	return ""
}

// The gate and the pin move together or not at all. The artefact at
// mgmtPinBeforeOptInFamilies serves none of shadowsocks, anytls, tuic
// (finding F-002: the end-to-end rig, `clean anytls vless-reality` on the pinned
// box — nothing listens on 8447, the route is dropped from the pack), so
// while it is pinned nothing may offer those families as if they worked.
// And once the pin moves, leaving the gate shut would hide a working
// feature for ever.
func TestPinnedMgmtOptInGateMatchesThePin(t *testing.T) {
	stale := pinnedMgmtSha(t) == mgmtPinBeforeOptInFamilies
	switch {
	case stale && PinnedMgmtServesOptInFamilies:
		t.Fatalf("PinnedMgmtServesOptInFamilies is true but V2Artifacts still pins daal-relay-mgmt %s, "+
			"which predates shadowsocks/anytls/tuic. The wizard and `provision --families` would promise "+
			"families the relay cannot serve. Bump Sha256+SigHex to the re-released artefact in the same commit.",
			mgmtPinBeforeOptInFamilies[:12])
	case !stale && !PinnedMgmtServesOptInFamilies:
		t.Fatalf("the daal-relay-mgmt pin moved off %s but PinnedMgmtServesOptInFamilies is still false. "+
			"If the new artefact was built from a tree with cmd/daal-relay-mgmt/families.go (check with the rig: "+
			"`./daal e2e full`, world release.all-families), set it to true here AND "+
			"RELEASED_RELAY_SERVES_EXTRA_FAMILIES in client-ui/src/publisher/extraFamilies.ts.",
			mgmtPinBeforeOptInFamilies[:12])
	}
}

func TestNotServedByPinnedMgmt(t *testing.T) {
	asked := []string{"vless-reality", "websocket-tls", "naive", "hysteria2", "anytls", "tuic"}
	if got, want := notServedBy(false, asked), []string{"anytls", "tuic"}; !reflect.DeepEqual(got, want) {
		t.Errorf("gate shut: got %v, want %v", got, want)
	}
	if got := notServedBy(true, asked); got != nil {
		t.Errorf("gate open: got %v, want nil", got)
	}
	if got := notServedBy(false, []string{"vless-reality", "websocket-tls", "naive", "hysteria2"}); got != nil {
		t.Errorf("the default families are served by the pinned release; got %v", got)
	}
	if got, want := NotServedByPinnedMgmt(asked), notServedBy(PinnedMgmtServesOptInFamilies, asked); !reflect.DeepEqual(got, want) {
		t.Errorf("NotServedByPinnedMgmt does not read the constant: got %v, want %v", got, want)
	}
}

// The gate covers exactly the families a shipped profile offers but
// does not enable by default: a new opt-in family added to a profile
// without a decision here would be offered with no gate at all.
func TestOptInFamiliesOfMgmtAreTheProfilesOptInFamilies(t *testing.T) {
	gated := map[string]bool{}
	for _, f := range OptInFamiliesOfMgmt {
		gated[f] = true
	}
	seen := map[string]bool{}
	for _, slug := range profiles.Slugs() {
		p, err := profiles.ByName(slug)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range p.Candidates {
			if c.DefaultEnabled {
				if gated[c.Family] {
					t.Errorf("profile %q enables %q by default, but the pinned mgmt gate lists it as unserved", slug, c.Family)
				}
				continue
			}
			seen[c.Family] = true
			if !gated[c.Family] {
				t.Errorf("profile %q offers opt-in family %q, which OptInFamiliesOfMgmt does not name: "+
					"decide whether the pinned daal-relay-mgmt serves it", slug, c.Family)
			}
		}
	}
	for f := range gated {
		if !seen[f] {
			t.Errorf("OptInFamiliesOfMgmt names %q, which no shipped profile offers as opt-in", f)
		}
	}
}
