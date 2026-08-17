package relaypackvalidate

import (
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/phase"
)

// TestPhaseIsAliasOfCanonicalEnum: this package's Phase is an ALIAS of
// daal/bundle-go/phase.Phase, not a second `type Phase string`. If
// someone re-declares it, the assignments below stop compiling — which
// is the point. Three packages used to declare their own, with two
// spellings of PostV2, compared as strings.
func TestPhaseIsAliasOfCanonicalEnum(t *testing.T) {
	var p Phase = phase.Current
	var q phase.Phase = CurrentPhase
	if p != q {
		t.Fatalf("alias broken: %q != %q", p, q)
	}
	for name, pair := range map[string][2]Phase{
		"V15":    {PhaseV15, phase.V15},
		"V16":    {PhaseV16, phase.V16},
		"PostV2": {PhasePostV2, phase.PostV2},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: %q != %q", name, pair[0], pair[1])
		}
	}
	if PhasePostV2 != "PostV2" {
		t.Errorf("PostV2 spelling regressed to %q", PhasePostV2)
	}
}

// TestCurrentPhaseOpensTheFRP8Gates pins the whole point of the
// collapse: the shipped phase must be one where RP004 (cdn_fronted)
// and RP021 (freshness_url) no longer fire. If someone sets Current
// back to V1.5, this fails before any downstream test does.
func TestCurrentPhaseOpensTheFRP8Gates(t *testing.T) {
	if CurrentPhase == PhaseV15 {
		t.Fatalf("CurrentPhase = %q: RP004 and RP021 are shut", CurrentPhase)
	}
	if !CurrentPhase.Known() {
		t.Fatalf("CurrentPhase %q is not an enum member", CurrentPhase)
	}
}

// TestValidate_UnknownPhaseFailsClosed: every phase gate in the
// validator is written as "reject at V15 (and V16)", so a phase value
// the validator has no rule-set for would match no gate and land on
// the MOST PERMISSIVE branch — cdn_fronted, serverless_external,
// modifiers[] and cell_scope all waved through. Reject instead.
//
// `V2` is the live instance of this: it is a real member of the enum
// (the selector's explanation vocabulary uses it) but the validator
// has no V2 rules.
func TestValidate_UnknownPhaseFailsClosed(t *testing.T) {
	b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
	for _, p := range []Phase{phase.V2, Phase("V99"), Phase("v1.6")} {
		if _, err := Validate(b, ValidateOpts{Phase: p}); err == nil {
			t.Errorf("Validate at phase %q returned nil error; must fail closed", p)
		}
	}
	// The supported three still work.
	for _, p := range []Phase{PhaseV15, PhaseV16, PhasePostV2} {
		if _, err := Validate(b, ValidateOpts{Phase: p}); err != nil {
			t.Errorf("Validate at supported phase %q: %v", p, err)
		}
	}
}

// TestValidate_ServerlessExternalStillRejectedAtCurrentPhase is the
// other half of the safety argument for moving the importer forward:
// V1.6 lifts cdn_fronted, and ONLY cdn_fronted. serverless_external
// is still reserved.
func TestValidate_ServerlessExternalStillRejectedAtCurrentPhase(t *testing.T) {
	e := minimalDirectVPS()
	e.ExposureMode = "serverless_external"
	b := twoRouteBundle(t, minimalDirectVPS(), e)
	expectError(t, b, ValidateOpts{Phase: CurrentPhase}, CodeRP003)
}

// TestValidate_ModifiersStillRejectedAtCurrentPhase: likewise RP013.
func TestValidate_ModifiersStillRejectedAtCurrentPhase(t *testing.T) {
	e := minimalDirectVPS()
	e.Modifiers = []bundle.Modifier{{Kind: "tls_fragment"}}
	b := twoRouteBundle(t, minimalDirectVPS(), e)
	expectError(t, b, ValidateOpts{Phase: CurrentPhase}, CodeRP013)
}

// TestValidate_CellScopeStillRejectedAtCurrentPhase: RP016 spans every
// pre-V2 phase, not just V1.5. Cells are an FRP-11 feature and the
// chain walker that would verify a cell claim (core/trust
// VerifyCellChain) has no production caller, so a cell_scope that gets
// past this rule is neither rejected nor verified. If someone rewrites
// the gate as `== PhaseV15` again, this fails.
func TestValidate_CellScopeStillRejectedAtCurrentPhase(t *testing.T) {
	e := minimalDirectVPS()
	e.CellScope = &bundle.CellScope{
		CellID:       "moms-extended-family",
		CellJoinFP:   "9f3a",
		CellMaxDepth: 5,
	}
	b := twoRouteBundle(t, minimalDirectVPS(), e)
	expectError(t, b, ValidateOpts{Phase: CurrentPhase}, CodeRP016)
	// And at every other pre-V2 phase the validator supports.
	expectError(t, b, ValidateOpts{Phase: PhaseV15}, CodeRP016)
}

// TestValidate_FreshnessURLShapeAtCurrentPhase: V1.6 lifts the blanket
// RP021 rejection, so the shape check is now the ONLY thing standing
// between an attacker-authored bundle and a URL this device persists
// on every route row and will later poll. The check is syntactic on
// purpose — the validator cannot know which host an FRP controls — but
// "https, real hostname, no credentials" is decidable and is what the
// spec says.
func TestValidate_FreshnessURLShapeAtCurrentPhase(t *testing.T) {
	withURL := func(u string) *bundle.Bundle {
		b := twoRouteBundle(t, minimalDirectVPS(), minimalDirectVPS())
		b.Manifest.RelayPack.FreshnessURL = u
		return b
	}

	// The spec's shape: an FRP-controlled https endpoint.
	expectOK(t, withURL("https://frp.example.com/relaypack.json"), ValidateOpts{Phase: CurrentPhase})

	for _, bad := range []string{
		"http://beacon.attacker.example/v?id=1", // cleartext beacon
		"ftp://frp.example.com/x",               // not https
		"//frp.example.com/x",                   // scheme-relative
		"https://user:pw@frp.example.com/x",     // embedded credentials
		"https://198.51.100.9/x",                // IP literal: no name to authenticate
		"https://127.0.0.1/x",                   // poll ourselves
		"https://localhost/x",                   // ditto
		"https://intranet/x",                    // not fully qualified
		"https://frp.example.com/x ",            // trailing whitespace
	} {
		expectError(t, withURL(bad), ValidateOpts{Phase: CurrentPhase}, CodeRP021)
	}

	// Length bound: the bundle is attacker-controlled bytes.
	long := "https://frp.example.com/" + strings.Repeat("a", maxFreshnessURLLen)
	expectError(t, withURL(long), ValidateOpts{Phase: CurrentPhase}, CodeRP021)

	// V1.5 still rejects any non-empty value outright.
	expectError(t, withURL("https://frp.example.com/relaypack.json"),
		ValidateOpts{Phase: PhaseV15}, CodeRP021)
}

func TestPhaseParse(t *testing.T) {
	// Empty means "whatever this build ships" — never the most
	// permissive rule-set.
	if got, err := phase.Parse(""); err != nil || got != phase.Current {
		t.Errorf("Parse(\"\") = %q, %v; want %q, nil", got, err, phase.Current)
	}
	// The dead selection-package spelling still round-trips.
	if got, err := phase.Parse("post-V2"); err != nil || got != phase.PostV2 {
		t.Errorf("Parse(\"post-V2\") = %q, %v; want %q, nil", got, err, phase.PostV2)
	}
	if _, err := phase.Parse("V1.7"); err == nil {
		t.Error("Parse(\"V1.7\") must error, not silently default")
	}
}
