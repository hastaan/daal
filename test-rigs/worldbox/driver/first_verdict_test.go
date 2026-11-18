package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The retry must not be able to turn the first phone's failure green:
// the session that connected on its second phone is the exact shape that
// went unnoticed under throttle-56k (connect_attempts=2, exit 0).
func TestFirstVerdictIsTheFirstPhoneNotTheOneThatConnected(t *testing.T) {
	failed := ConnectAttempt{Phone: 1, Stage: StageProof, Error: "proof: abi: the route started but carried no traffic",
		Category: "tls_handshake_failed", Posture: "Recovery", SetRouteMs: float64(8022),
		Explained: "Last attempt failed; cooling down. Reason: tls_handshake_failed on r3; cooldown 30m0s."}
	ok := ConnectAttempt{Phone: 2, Connected: true, SetRouteMs: float64(2145)}

	got, detail := firstVerdict([]ConnectAttempt{failed, ok})
	if got != "failed:tls_handshake_failed" {
		t.Fatalf("first verdict = %q; a second, fresh phone that connected must not hide what the first was told", got)
	}
	for _, want := range []string{"tls_handshake_failed", "Recovery", "cooldown 30m0s", "phone 2 of 2"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the detail does not carry %q: %s", want, detail)
		}
	}

	if got, detail := firstVerdict([]ConnectAttempt{ok}); got != FirstConnected || detail != "" {
		t.Fatalf("a first phone that connected: %q %q", got, detail)
	}
	if got, _ := firstVerdict([]ConnectAttempt{failed, failed}); got != "failed:tls_handshake_failed" {
		t.Fatalf("no phone connected: %q", got)
	}
	if got, _ := firstVerdict(nil); got == FirstConnected {
		t.Fatal("a session with no connect attempt read as connected")
	}
	if got, _ := firstVerdict([]ConnectAttempt{{Phone: 1, Error: "timeout"}}); got != "failed:uncategorised" {
		t.Fatalf("a failure the engine did not categorise: %q", got)
	}
}

// For one connect exactly one answer is right, outside a narrow band:
// the declaration is not an either-way.
func TestSlowCategoryIsDecidedByTheConnectTime(t *testing.T) {
	for _, c := range []struct {
		ms       int64
		want     string
		slowOK   bool
		noneOK   bool
		whatItIs string
	}{
		{1631, "none", false, true, "naive, under the threshold: the proof cannot have been slow"},
		{2000, "none", false, true, "exactly the threshold"},
		{2100, "path_too_slow|none", true, true, "inside the overhead band"},
		{2151, "path_too_slow", true, false, "just over the band"},
		{5534, "path_too_slow", true, false, "websocket-tls as found: \"Connected\" after 5.5 s"},
	} {
		got := slowCategoryFor(CategorySlow, c.ms)
		if got != c.want {
			t.Errorf("%d ms (%s): expectation %q, want %q", c.ms, c.whatItIs, got, c.want)
		}
		if categoryAllows(got, CategorySlow) != c.slowOK || categoryAllows(got, CategoryNone) != c.noneOK {
			t.Errorf("%d ms (%s): %q allows slow=%v none=%v, want %v %v", c.ms, c.whatItIs, got,
				categoryAllows(got, CategorySlow), categoryAllows(got, CategoryNone), c.slowOK, c.noneOK)
		}
		for _, dead := range []string{"tls_handshake_failed", "unknown", "tcp_connect_timeout"} {
			if categoryAllows(got, dead) {
				t.Errorf("%d ms: %q allows the failure %s", c.ms, got, dead)
			}
		}
	}
	// Nothing but path_too_slow is rewritten, and an unmeasured connect
	// keeps the declaration.
	if got := slowCategoryFor("tcp_reset", 9000); got != "tcp_reset" {
		t.Errorf("another category was rewritten to %q", got)
	}
	if got := slowCategoryFor(CategorySlow, -1); got != CategorySlow {
		t.Errorf("an unmeasured connect: %q", got)
	}
}

func TestRawFaceOfASlowPathIsNothingBlocked(t *testing.T) {
	for in, want := range map[string]string{"path_too_slow": "none", "tcp_reset": "tcp_reset", "none": "none", "tcp_reset|path_too_slow": "tcp_reset|none"} {
		if got := rawFace(in); got != want {
			t.Errorf("rawFace(%q) = %q, want %q", in, got, want)
		}
	}
}

// throttle-56k must declare the slow path and nothing else: the
// alternation "path_too_slow|none" let the engine say either.
func TestNoScenarioDeclaresAnEitherWayCategory(t *testing.T) {
	rig, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(rig, "scenarios", "*.json"))
	if len(files) == 0 {
		t.Fatal("no scenarios found")
	}
	sawSlow := false
	for _, f := range files {
		var s Scenario
		if err := loadJSON(f, &s); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for fam, cat := range s.Category {
			if strings.Contains(cat, "|") {
				t.Errorf("%s: category[%q]=%q is an alternation: say what decides between them in the driver (see slowCategoryFor), do not accept either", filepath.Base(f), fam, cat)
			}
			if cat == CategorySlow {
				sawSlow = true
				probe := fam
				if probe == "*" {
					probe = "vless-reality"
				}
				if !s.MustEstablish(probe) {
					t.Errorf("%s: declares path_too_slow for %q without \"established\"", filepath.Base(f), fam)
				}
			}
		}
	}
	if !sawSlow {
		t.Error("no scenario declares path_too_slow any more: the taxonomy spec names throttle-56k as its coverage")
	}
}

// EngineSlowAfterMs restates a product default; hold the two together.
func TestEngineSlowAfterMatchesTheProductDefault(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "core", "engine", "proof.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`SlowAfter:\s+(\d+) \* time\.Second,`).FindSubmatch(body)
	if m == nil {
		t.Fatal("DefaultProofConfig().SlowAfter not found in core/engine/proof.go in the form `N * time.Second`; update this test with it")
	}
	if string(m[1])+"000" != "2000" || EngineSlowAfterMs != 2000 {
		t.Fatalf("the engine's default slow_after is %ss and the rig's EngineSlowAfterMs is %d", m[1], EngineSlowAfterMs)
	}
}

func TestQdiscBacklogIsRead(t *testing.T) {
	// Both forms tc prints: plain bytes, and bytes with a unit.
	for out, want := range map[string]string{
		"qdisc netem 8001: root refcnt 2 limit 1000 delay 50ms rate 56Kbit\n Sent 123 bytes 4 pkt (dropped 0, overlimits 0 requeues 0)\n backlog 0b 0p requeues 0\n":                  "0",
		"qdisc netem 8163: root refcnt 17 limit 1000 delay 50ms rate 56Kbit seed 77\n Sent 202695 bytes 229 pkt (dropped 0, overlimits 0 requeues 0)\n backlog 43Kb 22p requeues 0\n": "22",
	} {
		m := qdiscBacklog.FindStringSubmatch(out)
		if m == nil || m[1] != want {
			t.Fatalf("backlog not read from tc output %q: %v, want %s packets", out, m, want)
		}
	}
}
