package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The censor namespace is the client's ISP and the national border in
// one box. A scenario (scenarios/<name>.json) is a named, documented set
// of things it does to traffic, in three mechanisms:
//
//	nft   static rules in the forward chain            (addresses, ports, protocols, header shapes)
//	tc    a qdisc on an interface                      (delay, loss, rate)
//	dpi   payload rules run by `wb dpi` over NFQUEUE   (TLS SNI, first data packet, forged RSTs)
//
// and three kinds of claim the run then checks:
//
//	prove     raw probes that know nothing about Daal: each rule bites, and an innocent neighbour is spared
//	expect    per family: does the real engine carry bytes through it (pass | blocked)
//	category  per blocked family: the failure category (specs/failure-taxonomy-v1.md) that
//	          describes what the network really does — checked against a raw differential
//	          probe (truth.category) and against what the engine itself reports (engine.category)

const (
	NSElsewhere   = "elsewhere"
	ElsewhereIP   = "198.19.0.2" // an unblocked host beyond the same censor
	CensorElseIP  = "198.19.0.1"
	CensorDevElse = "to-else"
	dpiQueue      = 0
	controlSNI    = "www.wb-control.example" // a name no scenario blocks
	CategoryNone  = "none"
	// CategoryUnasserted: the scenario blocks the family but which
	// failure the client sees is not deterministic (random loss: a
	// different handshake step times out each run). Declared explicitly;
	// truth.category and engine.category are then recorded as skipped.
	CategoryUnasserted = "unasserted"
	ProbeBlobBytes     = 256 << 10 // what `wb probe` fetches by default (probe.go --size)
	taxonomySpecPath   = "specs/failure-taxonomy-v1.md"
)

// Proof is one raw probe a scenario runs to show its rules do what the
// description says. Every blocking rule should come with at least one
// probe it blocks and one neighbour it must NOT block.
type Proof struct {
	Name  string `json:"name"`            // stable id: the check is censor/prove.<name>
	Probe string `json:"probe"`           // tcp | tls | bytes | udp | tcp_burst | bulk   (see censor_probe.go)
	To    string `json:"to"`              // relay | elsewhere (the unblocked control host) | gateway (the censor's own client-side address)
	Port  int    `json:"port"`            //
	SNI   string `json:"sni,omitempty"`   // tls: server_name ("" = none); variables allowed
	Split bool   `json:"split,omitempty"` // tls: ClientHello in two TCP segments
	Shape string `json:"shape,omitempty"` // udp: plain | quic
	// ECH: tls / exchange: offer the world's ECH configuration
	// (ech_lab.go) with SNI as the inner name; the wire shows the outer
	// name cloudflare-ech.com. TLS 1.3 only, as ECH is.
	ECH bool `json:"ech,omitempty"`
	// Expect: the observation. tcp: ok|connect_timeout|connect_reset|unreachable;
	// tls: ok|reset_after_hello|timeout_after_hello|connect_*;
	// bytes: answered|reset_after_data|silent|connect_*; udp: delivered|dropped.
	Expect string `json:"expect"`
}

var proofOutcomes = map[string][]string{
	"tcp":   {"ok", "connect_timeout", "connect_reset", "unreachable"},
	"tls":   {"ok", "reset_after_hello", "timeout_after_hello", "connect_timeout", "connect_reset", "unreachable"},
	"bytes": {"answered", "reset_after_data", "silent", "connect_timeout", "connect_reset", "unreachable"},
	"udp":   {"delivered", "dropped"},
	// statistical probes, for censors that degrade instead of block
	"tcp_burst": {"all", "some", "none"},
	// exchange: a TLS session (SNI, optionally ECH) carrying twelve
	// request/answer round trips, each its own client packet — a flow
	// longer than a "grey" address's packet budget (budget rule)
	"exchange": {"ok", "cut", "reset_after_hello", "timeout_after_hello", "connect_timeout", "connect_reset", "unreachable"},
	"bulk":      {"fast", "slow", "connect_timeout", "connect_reset", "unreachable"},
}

// CategoryFor is the failure category the scenario declares for a family:
// "none" when the family is expected to pass, otherwise the entry for the
// family (or "*"). A blocked family without one is an error.
func (s Scenario) CategoryFor(family string) (string, error) {
	exp, err := s.ExpectFor(family)
	if err != nil {
		return "", err
	}
	if exp == Pass {
		return CategoryNone, nil
	}
	if v, ok := s.Category[family]; ok {
		return v, nil
	}
	if v, ok := s.Category["*"]; ok {
		return v, nil
	}
	return "", fmt.Errorf("scenario %q blocks family %q but declares no failure category for it (\"category\": {…})", s.Name, family)
}

// A declared category may be an alternation, "a|b": the scenario does
// something whose visible face is legitimately one of several.
// categoryAllows reports whether got is one of the declared alternatives.
//
// No scenario file uses one today, and one that does must say what
// decides between the alternatives: throttle-56k once declared
// "path_too_slow|none" and was green whichever the engine said. It now
// declares path_too_slow, and the alternative is derived per connect from
// the time the connect took (first_verdict.go: slowCategoryFor).
func categoryAllows(declared, got string) bool {
	for _, d := range strings.Split(declared, "|") {
		if d == got {
			return true
		}
	}
	return false
}

// categoryExpect is the expectation to RECORD for a check: what was got
// when the declaration allows it (so an alternation does not read as a
// mismatch), the declaration itself otherwise.
func categoryExpect(declared, got string) string {
	if categoryAllows(declared, got) {
		return got
	}
	return declared
}

// TaxonomyCategories reads the closed category list out of the product's
// own spec, so a declared category can never drift from it.
func TaxonomyCategories(repo string) (map[string]bool, error) {
	body, err := os.ReadFile(filepath.Join(repo, taxonomySpecPath))
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\|").FindAllStringSubmatch(string(body), -1) {
		out[m[1]] = true
	}
	if len(out) < 10 {
		return nil, fmt.Errorf("%s: found only %d categories; the table format changed", taxonomySpecPath, len(out))
	}
	return out, nil
}

// ValidateScenario checks everything about a declaration that can be
// checked without building a world.
func ValidateScenario(s Scenario, families []string, taxonomy map[string]bool) []error {
	var errs []error
	bad := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("scenario %s: "+format, append([]any{s.Name}, a...)...))
	}
	if strings.TrimSpace(s.Analogue) == "" {
		bad("no \"analogue\": say which documented real-world behaviour this models")
	}
	for _, w := range s.World {
		if w != "storage" && w != "cdn" && w != "google" {
			bad("world %q, want storage|cdn|google", w)
		}
	}
	if s.CDN != nil && s.CDN.Expect != Pass && s.CDN.Expect != Blocked {
		bad("cdn.expect=%q, want pass|blocked", s.CDN.Expect)
	}
	switch s.GoogleExpect {
	case "", "recovered", "unreachable", "refused":
	default:
		bad("google_expect=%q, want recovered|unreachable|refused", s.GoogleExpect)
	}
	for _, r := range s.Censor.DPI {
		if err := r.validate(); err != nil {
			bad("%v", err)
		}
	}
	for preset, m := range s.Desync {
		if !contains(desyncPresets, preset) {
			bad("desync preset %q is not one of %v", preset, desyncPresets)
		}
		for f, v := range m {
			if f != "*" && !contains(families, f) {
				bad("desync[%q] for %q, which is not a declared family", preset, f)
			}
			if v != Pass && v != Blocked {
				bad("desync[%q][%q]=%q, want pass|blocked", preset, f, v)
			}
		}
	}
	for f, c := range s.Category {
		if f != "*" && !contains(families, f) {
			bad("category for %q, which is not a declared family", f)
		}
		for _, one := range strings.Split(c, "|") {
			if !taxonomy[one] && one != CategoryNone && one != CategoryUnasserted {
				bad("category[%q]=%q: %q is not in %s", f, c, one, taxonomySpecPath)
			}
		}
		if strings.Contains(c, "|") && strings.Contains(c, CategoryUnasserted) {
			bad("category[%q]=%q: \"unasserted\" cannot be one alternative of several", f, c)
		}
	}
	for f, v := range s.Established {
		if f != "*" && !contains(families, f) {
			bad("established for %q, which is not a declared family", f)
		}
		if v != Pass {
			bad("established[%q]=%q: the only claim is \"pass\" (leave the family out to claim nothing)", f, v)
		}
	}
	blocks := false
	for _, f := range families {
		cat, err := s.CategoryFor(f)
		if err != nil {
			errs = append(errs, err)
		}
		// Blocked, and by nothing the client could name: the family is
		// not stopped by a rule, it merely runs out of the probe's
		// budget. A family that never connected at all produces the very
		// same "blocked" — so the declaration must also claim, and the
		// run then check, that it did connect (family/established).
		if e, _ := s.ExpectFor(f); e == Blocked && err == nil && (categoryAllows(rawFace(cat), CategoryNone) || cat == CategoryUnasserted) && !s.MustEstablish(f) {
			bad("family %q is expected blocked with category %q — blocked by the probe's budget, not by a rule — so a dead family would pass too: declare \"established\": {%q: \"pass\"} (or \"*\")", f, cat, f)
		}
		if e, _ := s.ExpectFor(f); e == Blocked {
			blocks = true
		}
	}
	seen := map[string]bool{}
	bites, spares := false, false
	for _, pr := range s.Prove {
		if pr.Name == "" || seen[pr.Name] {
			bad("prove entries need unique names (%q)", pr.Name)
		}
		seen[pr.Name] = true
		if _, ok := proofTargets[pr.To]; !ok {
			bad("prove %s: to=%q, want one of %s", pr.Name, pr.To, strings.Join(proofTargetNames(), "|"))
		}
		if pr.ECH && pr.Probe != "tls" && pr.Probe != "exchange" {
			bad("prove %s: ech applies to tls and exchange probes only", pr.Name)
		}
		if !contains(proofOutcomes[pr.Probe], pr.Expect) {
			bad("prove %s: probe %q cannot observe %q (want one of %v)", pr.Name, pr.Probe, pr.Expect, proofOutcomes[pr.Probe])
		}
		if pr.Port <= 0 {
			bad("prove %s: no port", pr.Name)
		}
		switch {
		case pr.Expect == "ok", pr.Expect == "answered", pr.Expect == "delivered", pr.Expect == "all", pr.Expect == "fast":
			spares = true
		case pr.To == "gateway" && pr.Expect == "connect_reset":
			// The client's own gateway refusing a closed port: the link is
			// up. The only neighbour a total blackout leaves.
			spares = true
		default:
			bites = true
		}
	}
	rules := len(s.Censor.NFT)+len(s.Censor.NFTRaw)+len(s.Censor.DPI) > 0
	if (rules || blocks) && !(bites && spares) {
		bad("it has blocking rules, so \"prove\" needs at least one probe the rules stop AND one they let through (a block nobody proved is a guess; a block with no spared neighbour may be a dead link)")
	}
	return errs
}

// scenarioVars is the complete substitution vocabulary for scenario files.
func scenarioVars(coverSNI string) map[string]string {
	host := func(u string) string { return strings.SplitN(strings.TrimPrefix(u, "https://"), "/", 2)[0] }
	return map[string]string{
		"CLIENT_IP":    ClientIP,
		"RELAY_IP":     Relay1IP,
		"ELSEWHERE_IP": ElsewhereIP,
		"DEV_CLIENT":   CensorDevClient,
		"DEV_RELAY":    CensorDevRelay,
		"COVER_SNI":    coverSNI,
		// The add-ons' outside world (addons_net.go).
		"EDGE_A": CDNEdgeA, "EDGE_B": CDNEdgeB, "EDGE_C": CDNEdgeC, "EDGE_D": CDNEdgeD,
		"EDGE_NET_A": CDNPublishedV4[0], "EDGE_NET_B": CDNPublishedV4[1], "EDGE_NET_C": CDNPublishedV4[2], "EDGE_NET_D": CDNPublishedV4[3],
		"EDGE_NET":   CDNEdgeNet,
		"CDN_HOST":   CDNHost,
		"ECH_OUTER":  ECHPublicName,
		"STORAGE_IP": StorageIP,
		"R2_SNI":     host(freshMirrorR2), "GH_SNI": host(freshMirrorGH), "PACK_SNI": host(freshPackURL),
		"GFE_IP": GoogleFrontIP, "GFE2_IP": GoogleFront2IP, "GSCRIPT_IP": GoogleScriptIP, "GUSER_IP": GoogleUserCntIP,
		"GOOGLE_NET": GoogleNet,
	}
}

// proofTargets: where a scenario's raw probes may be aimed ("to"), and
// which part of the world must be up for it (ApplyScenario brings it up).
var proofTargets = map[string]struct{ addr, world string }{
	"relay":     {Relay1IP, ""},
	"elsewhere": {ElsewhereIP, ""},
	"gateway":   {CensorClientIP, ""},
	"storage":   {StorageIP, "storage"},
	"edge-a":    {CDNEdgeA, "cdn"}, "edge-b": {CDNEdgeB, "cdn"}, "edge-c": {CDNEdgeC, "cdn"}, "edge-d": {CDNEdgeD, "cdn"},
	"gfe":        {GoogleFrontIP, "google"},
	"gfe2":       {GoogleFront2IP, "google"},
	"gscript":    {GoogleScriptIP, "google"},
	"guser":      {GoogleUserCntIP, "google"},
}

func proofTargetNames() []string {
	var out []string
	for k := range proofTargets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func substVars(line string, vars map[string]string) string {
	// Longest name first: $EDGE_NET must not eat the front of $EDGE_NET_A.
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) || len(keys[i]) == len(keys[j]) && keys[i] < keys[j] })
	for _, k := range keys {
		line = strings.ReplaceAll(line, "$"+k, vars[k])
	}
	return line
}

// bringUpElsewhere adds the control host: one more network behind the
// censor, with a TLS and an echo listener. Traffic to it crosses the same
// forward chain as traffic to the relay.
func bringUpElsewhere(ctx context.Context, p Paths) error {
	steps := [][]string{
		{"ip", "netns", "add", NSElsewhere},
		inNS(NSElsewhere, "ip", "link", "set", "lo", "up"),
		{"ip", "link", "add", CensorDevElse, "netns", NSCensor, "type", "veth", "peer", "name", "eth0", "netns", NSElsewhere},
		inNS(NSCensor, "ip", "addr", "add", CensorElseIP+"/24", "dev", CensorDevElse),
		inNS(NSCensor, "ip", "link", "set", CensorDevElse, "up"),
		inNS(NSElsewhere, "ip", "addr", "add", ElsewhereIP+"/24", "dev", "eth0"),
		inNS(NSElsewhere, "ip", "link", "set", "eth0", "up"),
		inNS(NSElsewhere, "ip", "route", "add", "default", "via", CensorElseIP),
	}
	for _, s := range steps {
		if _, err := sh(ctx, s...); err != nil {
			return err
		}
	}
	if _, err := Spawn(p, "elsewhere", nil, inNS(NSElsewhere, filepath.Join(p.Bin, "wb"), "elsewhere")...); err != nil {
		return err
	}
	up := waitFor(ctx, 5*time.Second, func() bool {
		_, err := sh(ctx, inNS(NSCensor, "timeout", "1", "bash", "-c", "exec 3<>/dev/tcp/"+ElsewhereIP+"/443")...)
		return err == nil
	})
	if !up {
		return fmt.Errorf("the control host (%s) did not come up; see logs/elsewhere.log", ElsewhereIP)
	}
	return nil
}

// ApplyScenario installs a scenario in the censor namespace: the control
// host, the DPI box if the scenario has payload rules, the nft ruleset
// (scenario rules, then the queue to the DPI box, then a tap that counts
// what actually left toward the far side), and the qdiscs. Variables are
// substituted as $NAME; the set is fixed (see scenarioVars).
func ApplyScenario(ctx context.Context, p Paths, s Scenario, vars map[string]string) error {
	if err := bringUpElsewhere(ctx, p); err != nil {
		return fmt.Errorf("scenario %q: %w", s.Name, err)
	}
	if len(s.Censor.DPI) > 0 {
		rules := make([]DPIRule, len(s.Censor.DPI))
		for i, r := range s.Censor.DPI {
			r.Dst = substVars(r.Dst, vars)
			r.SNI = append([]string{}, r.SNI...)
			for j := range r.SNI {
				r.SNI[j] = substVars(r.SNI[j], vars)
			}
			rules[i] = r
		}
		body, _ := json.MarshalIndent(rules, "", "  ")
		rulesPath, ready := filepath.Join(p.Run, "dpi-rules.json"), filepath.Join(p.Run, "dpi.ready")
		if err := os.WriteFile(rulesPath, body, 0o644); err != nil {
			return err
		}
		if _, err := Spawn(p, "dpi", nil, inNS(NSCensor, filepath.Join(p.Bin, "wb"), "dpi", "--rules", rulesPath,
			"--queue", strconv.Itoa(dpiQueue), "--events", filepath.Join(p.Run, "dpi-events.jsonl"), "--ready", ready)...); err != nil {
			return err
		}
		if !waitFor(ctx, 5*time.Second, func() bool { _, err := os.Stat(ready); return err == nil }) {
			return fmt.Errorf("scenario %q: the DPI box did not bind its queue; see logs/dpi.log", s.Name)
		}
	}

	var b strings.Builder
	b.WriteString("add table inet wb_censor\ndelete table inet wb_censor\n")
	b.WriteString("table inet wb_censor {\n  chain forward { type filter hook forward priority 0; policy accept;\n")
	for _, l := range s.Censor.NFT {
		b.WriteString("    " + substVars(l, vars) + "\n")
	}
	if len(s.Censor.DPI) > 0 {
		// Everything the client sends over TCP that the static rules let
		// through goes to the DPI box. No `bypass`: a dead box blocks.
		fmt.Fprintf(&b, "    ip saddr %s meta l4proto tcp queue num %d\n", ClientIP, dpiQueue)
	}
	b.WriteString("  }\n}\n")
	for _, l := range s.Censor.NFTRaw {
		b.WriteString(substVars(l, vars) + "\n")
	}
	// The tap: what the censor actually forwarded from the client, counted
	// AFTER its rules (priority 20 > wb_censor 0, wb_isp 10). UDP probes
	// have no answer to wait for, so this is how "delivered" is observed.
	fmt.Fprintf(&b, "add table inet wb_tap\ndelete table inet wb_tap\ntable inet wb_tap {\n  counter plain { }\n  counter quic { }\n"+
		"  chain forward { type filter hook forward priority 20; policy accept;\n"+
		"    iifname %q udp sport %d counter name plain\n    iifname %q udp sport %d counter name quic\n  }\n}\n",
		CensorDevClient, tapSportPlain, CensorDevClient, tapSportQUIC)
	_ = os.WriteFile(filepath.Join(p.Run, "censor.nft"), []byte(b.String()), 0o644)
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", NSCensor, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scenario %q: nft: %v: %s", s.Name, err, out)
	}
	for _, t := range s.Censor.TC {
		argv := inNS(NSCensor, append([]string{"tc", "qdisc", "replace", "dev", substVars(t.Dev, vars), "root"}, strings.Fields(substVars(t.Args, vars))...)...)
		if _, err := sh(ctx, argv...); err != nil {
			return fmt.Errorf("scenario %q: %w", s.Name, err)
		}
	}
	return nil
}

// ---- raw probes from the client's seat ----------------------------------

var tapPackets = regexp.MustCompile(`packets (\d+)`)

func tapRead(ctx context.Context, name string) int {
	out, _ := sh(ctx, inNS(NSCensor, "nft", "reset", "counter", "inet", "wb_tap", name)...)
	if m := tapPackets.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return -1
}

// RawProbeRun runs one raw probe in the client namespace. For UDP the
// observation is read off the censor's tap: delivered | dropped.
func RawProbeRun(ctx context.Context, p Paths, q RawProbe) RawProbe {
	args := []string{filepath.Join(p.Bin, "wb"), "rawprobe", "--kind", q.Kind, "--addr", q.Addr, "--port", strconv.Itoa(q.Port)}
	if q.SNI != "" {
		args = append(args, "--sni", q.SNI)
	}
	if q.Split {
		args = append(args, "--split")
	}
	if q.ECH {
		args = append(args, "--ech-config", filepath.Join(p.Run, echConfigFile))
	}
	if rawPatience > 0 {
		args = append(args, "--patience-ms", strconv.FormatInt(rawPatience.Milliseconds(), 10))
	}
	counter := "plain"
	if q.Kind == "udp" {
		if q.Shape == "quic" {
			counter = "quic"
		}
		args = append(args, "--shape", counter)
		tapRead(ctx, counter)
	}
	argv := inNS(NSClient, args...)
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	res := q
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		res.Result, res.Error = "error", fmt.Sprintf("rawprobe produced no result: %v / %v", err, jerr)
		return res
	}
	if q.Kind == "udp" && res.Result == "sent" {
		// Wait for the datagram to cross the censor rather than for a
		// fixed time: "delivered" as soon as the tap has counted it,
		// "dropped" only when it still has not after half a second (on an
		// unshaped path it crosses in microseconds; the margin is for a
		// machine running eight worlds at once).
		n := 0
		for deadline := time.Now().Add(500 * time.Millisecond); ; time.Sleep(10 * time.Millisecond) {
			k := tapRead(ctx, counter) // reads AND resets, so the reads add up
			if k < 0 {
				n = -1
				break
			}
			if n += k; n > 0 || time.Now().After(deadline) {
				break
			}
		}
		switch {
		case n > 0:
			res.Result = "delivered"
		case n == 0:
			res.Result = "dropped"
		default:
			res.Result, res.Error = "error", "could not read the censor's tap counter"
		}
	}
	return res
}

func (rc *RunCtx) proofAddr(to string) string {
	if t, ok := proofTargets[to]; ok {
		return t.addr
	}
	return Relay1IP
}

// ProveCensor runs right after the scenario is applied and before any
// Daal session: first the scenario's own raw probes (does each rule bite,
// is the neighbour spared), then — for every family the scenario claims
// to block — a raw differential probe at that family's endpoint whose
// result must equal the failure category the scenario declares.
func (rc *RunCtx) ProveCensor() {
	r := rc.R
	fmt.Fprintf(r.human, "phase: censor (raw probes, no Daal: does %q do what it says?)\n", rc.Scn.Name)
	vars := scenarioVars(rc.Rec.CoverSNI)
	for _, pr := range rc.Scn.Prove {
		// A TCP probe at a relay port this relay was not provisioned to
		// serve proves nothing about the censor; it is asserted closed
		// instead (prove_unserved.go).
		if rc.proveUnservedRelayPort(pr, vars) {
			continue
		}
		t0 := time.Now()
		obs := RawProbeRun(rc.Ctx, rc.P, RawProbe{Kind: pr.Probe, Addr: rc.proofAddr(pr.To), Port: pr.Port,
			SNI: substVars(pr.SNI, vars), Split: pr.Split, Shape: pr.Shape, ECH: pr.ECH})
		r.Add("", "censor", "prove."+pr.Name, Pass, got(obs.Result == pr.Expect, Pass, Fail),
			got(obs.Result == pr.Expect, "", fmt.Sprintf("the censor was declared to make this probe see %q; it saw %q (%s)", pr.Expect, obs.Result, obs.Error)),
			map[string]any{"probe": pr.Probe, "to": pr.To, "addr": obs.Addr, "port": pr.Port, "sni": obs.SNI, "split": pr.Split, "shape": pr.Shape, "ech": pr.ECH,
				"declared": pr.Expect, "observed": obs.Result, "error": obs.Error, "probe_ms": obs.Ms}, t0)
	}
	for _, name := range rc.Want {
		f := rc.Fams[name]
		if exp, _ := rc.Scn.ExpectFor(name); exp != Blocked || f.Skip != "" {
			continue
		}
		t0 := time.Now()
		declared, _ := rc.Scn.CategoryFor(name)
		if declared == CategoryUnasserted {
			r.Add(name, "censor", "truth.category", Skipped, Skipped, "the scenario declares this family's failure category as not deterministic", nil, t0)
			continue
		}
		observed, ev := rc.truthCategory(f)
		if ev != nil {
			ev["declared"] = declared
		}
		// The raw ladder sees packets, not speed: a declared
		// path_too_slow is confirmed as "none" (every handshake
		// completes); see rawFace.
		face := rawFace(declared)
		r.Add(name, "censor", "truth.category", categoryExpect(face, observed), observed,
			got(categoryAllows(face, observed), "", fmt.Sprintf("the scenario declares %s for this family, but a raw probe of its endpoint observes %s", declared, observed)), ev, t0)
	}
}

// wireShape is what a family puts on the wire first, read from the pack
// the insider was handed (the only place that knows the cover SNI).
type wireShape struct {
	TLS   bool   // the first flight is a TLS ClientHello
	SNI   string // its server_name ("" = none: Go and uTLS send no SNI for an IP literal)
	Large bool   // a ClientHello that spans two TCP segments
	Known bool   // the pack had a profile for this family
}

func packWireShape(pack, family string) wireShape {
	zr, err := zip.OpenReader(pack)
	if err != nil {
		return wireShape{}
	}
	defer zr.Close()
	read := func(name string) []byte {
		for _, f := range zr.File {
			if f.Name == name {
				rd, err := f.Open()
				if err != nil {
					return nil
				}
				defer rd.Close()
				b, _ := io.ReadAll(io.LimitReader(rd, 4<<20))
				return b
			}
		}
		return nil
	}
	var man struct {
		Routes []struct {
			ConfigPath string `json:"config_path"`
			Family     string `json:"transport_family"`
		} `json:"routes"`
	}
	_ = json.Unmarshal(read("manifest.json"), &man)
	for _, rt := range man.Routes {
		if rt.Family != family {
			continue
		}
		var prof struct {
			TLS struct {
				Enabled    bool   `json:"enabled"`
				ServerName string `json:"server_name"`
			} `json:"tls"`
		}
		if json.Unmarshal(read(rt.ConfigPath), &prof) != nil {
			return wireShape{}
		}
		// Large stays false: the engine's uTLS-chrome ClientHello was
		// measured on this wire at 600 bytes in ONE segment (dpi-events:
		// data_packet=1), so the family-shaped probe is single-segment too.
		ws := wireShape{TLS: prof.TLS.Enabled, Known: true}
		if net.ParseIP(prof.TLS.ServerName) == nil {
			ws.SNI = prof.TLS.ServerName
		}
		return ws
	}
	return wireShape{}
}

// truthCategory answers, WITHOUT Daal: what does the network do to
// something shaped like this family's first flight, at this family's
// endpoint — in the product's own failure vocabulary. It is a
// differential probe, because a single observation is ambiguous (a reset
// after the ClientHello is an SNI block only if another name is spared).
//
//	TCP endpoint
//	  SYN unanswered                                   tcp_connect_timeout
//	  SYN reset                                        tcp_reset
//	  reset after an opaque first flight               tcp_reset if the censor's DPI log shows it fired on the flow, else none
//	  reset after a TLS first flight
//	      … and after a ClientHello with another name  tcp_reset
//	      … but another name is answered               tls_sni_or_cert_block_suspected
//	  first flight (TLS) never answered                tls_handshake_failed
//	UDP endpoint
//	  plain datagram dropped
//	      … but delivered to the control host          udp_address_blocked
//	      … dropped there too, delivered on another port   udp_port_blocked
//	      … dropped there on that port as well         udp_unavailable
//	  plain delivered, QUIC-Initial-shaped dropped     quic_unavailable
//	otherwise                                          none
func (rc *RunCtx) truthCategory(f Family) (string, map[string]any) {
	ws := packWireShape(rc.Pack, f.Name)
	ev := map[string]any{"endpoint": fmt.Sprintf("%s:%d/%s", Relay1IP, f.Endpoint.Port, f.Endpoint.Proto),
		"first_flight": got(ws.TLS, "tls", "opaque"), "sni": ws.SNI, "split_hello": ws.Large, "shape_from_pack": ws.Known}
	run := func(label string, q RawProbe) RawProbe {
		res := RawProbeRun(rc.Ctx, rc.P, q)
		ev[label] = res.Result
		if res.Error != "" {
			ev[label+"_error"] = res.Error
		}
		return res
	}
	port := f.Endpoint.Port
	if f.Endpoint.Proto == "udp" {
		if run("udp_plain", RawProbe{Kind: "udp", Addr: Relay1IP, Port: port, Shape: "plain"}).Result != "delivered" {
			if run("udp_plain_control", RawProbe{Kind: "udp", Addr: ElsewhereIP, Port: port, Shape: "plain"}).Result == "delivered" {
				// Another host, same port, gets the datagram: it is this
				// ADDRESS that is cut off.
				return "udp_address_blocked", ev
			}
			other := 443
			if port == other {
				other = 8443
			}
			ev["other_port"] = other
			if run("udp_plain_control_other_port", RawProbe{Kind: "udp", Addr: ElsewhereIP, Port: other, Shape: "plain"}).Result == "delivered" {
				// The same host on another port gets it: it is this PORT.
				return "udp_port_blocked", ev
			}
			return "udp_unavailable", ev
		}
		if run("udp_quic", RawProbe{Kind: "udp", Addr: Relay1IP, Port: port, Shape: "quic"}).Result != "delivered" {
			return "quic_unavailable", ev
		}
		return CategoryNone, ev
	}
	kind := "bytes"
	if ws.TLS || !ws.Known {
		kind = "tls"
	}
	first := run("first_flight_result", RawProbe{Kind: kind, Addr: Relay1IP, Port: port, SNI: ws.SNI, Split: ws.Large})
	if first.Error != "" && first.Result != "ok" {
		// Not an assertion, a data point: what the PRODUCT's classifier
		// makes of the plain Go error this failure produces. (The engine
		// never shows its classifier a dial error — see engine.category —
		// so this is the best case it could reach if it did.)
		ev["product_classify_of_that_error"] = productClassify(rc.Ctx, rc.P, first.Error)
	}
	switch first.Result {
	case "connect_timeout":
		return "tcp_connect_timeout", ev
	case "connect_reset":
		return "tcp_reset", ev
	case "unreachable":
		return "network_offline", ev
	case "reset_after_data":
		// An opaque first flight has no "other name" to try, and the far
		// end may reset garbage itself (the relay's shadowsocks inbound
		// does, within milliseconds — FINDINGS CEN-O1). The tie-breaker is the
		// censor's own log: did its DPI box fire on this very flow?
		// The DPI box writes its event after it has issued the verdict;
		// wait for the line, not for a fixed time.
		if waitFor(rc.Ctx, 500*time.Millisecond, func() bool { return dpiFiredOn(rc.P, first.Local) }) {
			return "tcp_reset", ev
		}
		ev["reset_came_from"] = "the far end, not the censor: no DPI rule fired on " + first.Local
		return CategoryNone, ev
	case "reset_after_hello":
		other := run("other_sni_result", RawProbe{Kind: "tls", Addr: Relay1IP, Port: port, SNI: controlSNI, Split: ws.Large})
		if other.Result == "reset_after_hello" {
			return "tcp_reset", ev
		}
		return "tls_sni_or_cert_block_suspected", ev
	case "timeout_after_hello":
		return "tls_handshake_failed", ev
	}
	return CategoryNone, ev
}

// ---- what the engine says about it --------------------------------------

// EngineCategory records what the ENGINE reported for one finished
// session against what the scenario declares the network did. The
// engine's report is read from the product's own diagnostics surface
// (abi.DiagnosticsExplain → failures[].classification), captured by
// wb-client while the route was still active; "none" means the engine
// reported no failure for the route.
func (rc *RunCtx) EngineCategory(f Family, phase string, c *Client, bye map[string]any) {
	if phase != "family" {
		return // ops assert their own things; the scenario's category is about the matrix
	}
	t0 := time.Now()
	declared, err := rc.Scn.CategoryFor(f.Name)
	if err != nil || declared == CategoryUnasserted {
		return
	}
	routeID := ""
	var connectMs any
	if ev := c.Event("connected"); ev != nil {
		routeID, _ = ev["route_id"].(string)
		connectMs = ev["set_route_ms"]
	}
	src := bye
	if src == nil {
		// The engine did not connect: its own account of the attempt is
		// on the error event (wb-client takes it right after set_route
		// returned).
		if src = c.Event("error"); src != nil && routeID == "" {
			routeID, _ = src["route_id"].(string)
		}
	}
	reported := CategoryNone
	evidence := map[string]any{"declared": declared, "route_id": routeID}
	if connectMs != nil {
		evidence["set_route_ms"] = connectMs
	}
	if src != nil {
		if exp, ok := src["explain"].(map[string]any); ok {
			evidence["explain_reason"] = exp["reason"]
			evidence["network_signals"] = exp["network_signals"]
			if fails, ok := exp["failures"].([]any); ok {
				for _, x := range fails {
					fr, _ := x.(map[string]any)
					if fr == nil {
						continue
					}
					if id, _ := fr["route_id"].(string); routeID == "" || id == routeID {
						if cl, _ := fr["classification"].(string); cl != "" {
							reported = cl
						}
					}
				}
			}
			// A route that connected but whose proof was a DEGRADED
			// outcome (path_too_slow) is not in failures[] — it did not
			// fail — and is the engine naming what it saw all the same.
			if deg, ok := exp["degraded"].([]any); ok && reported == CategoryNone {
				for _, x := range deg {
					dr, _ := x.(map[string]any)
					if dr == nil {
						continue
					}
					if id, _ := dr["route_id"].(string); routeID == "" || id == routeID {
						if cl, _ := dr["classification"].(string); cl != "" {
							reported = cl
							evidence["degraded_not_failed"] = true
						}
					}
				}
			}
		} else {
			evidence["explain"] = "wb-client did not capture abi.DiagnosticsExplain()"
		}
		if diag, ok := src["diag"].(map[string]any); ok {
			evidence["posture"], evidence["why"] = diag["posture"], diag["why"]
			evidence["route_check"] = diag["route_check"]
		}
		if ms, ok := src["set_route_ms"]; ok {
			evidence["set_route_ms"] = ms
		}
		if routes, ok := src["routes_after"].(map[string]any); ok {
			if list, ok := routes["routes"].([]any); ok {
				for _, x := range list {
					if rt, _ := x.(map[string]any); rt != nil && rt["route_id"] == routeID {
						evidence["proven_after"], evidence["health_pct_after"], evidence["in_cooldown_after"] = rt["proven"], rt["health_pct"], rt["in_cooldown"]
					}
				}
			}
		}
	}
	for _, ev := range c.Events("engine") {
		if ee, _ := ev["engine_event"].(map[string]any); ee != nil && ee["type"] == "failure" {
			evidence["engine_failure_event"] = ee
			if cat, _ := ee["category"].(string); cat != "" && reported == CategoryNone {
				reported = cat
			}
		}
	}
	// A slow path is declared as path_too_slow and nothing else; which
	// of "slow" and "nothing" the engine must have said for THIS connect
	// is decided by how long the connect took (first_verdict.go:
	// slowCategoryFor), never left open.
	if declared == CategorySlow && bye != nil {
		ms := msOf(evidence["set_route_ms"])
		declared = slowCategoryFor(declared, ms)
		evidence["declared_for_this_connect"] = declared
		evidence["engine_slow_after_ms"] = EngineSlowAfterMs
	}
	detail := ""
	if !categoryAllows(declared, reported) {
		detail = fmt.Sprintf("the network did %s to this route (see censor/truth.category); the engine reported %s — posture=%v why=%q proven_after=%v",
			evidence["declared"], reported, evidence["posture"], evidence["why"], evidence["proven_after"])
		if evidence["declared_for_this_connect"] != nil {
			detail += fmt.Sprintf(" — this connect took %v ms against the engine's slow threshold of %d ms, so the engine must have reported %s",
				evidence["set_route_ms"], EngineSlowAfterMs, declared)
		}
	}
	rc.R.Add(f.Name, phase, "engine.category", categoryExpect(declared, reported), reported, detail, evidence, t0)

	// A connect that failed leaves posture=Recovery and
	// route_check=failed — exactly what a connected route that is being
	// retried reads. `route_running` is what lets the app tell "Could
	// not connect on this route" from "Connection lost. Trying again…";
	// without it every blocked session here read "Connecting…" for good.
	// The engine tore the instance down, so it must say false.
	if bye == nil && src != nil {
		if diag, ok := src["diag"].(map[string]any); ok && diag["route_check"] == "failed" {
			gotRunning := "missing"
			if v, ok := diag["route_running"].(bool); ok {
				gotRunning = fmt.Sprintf("%v", v)
			}
			d := ""
			if gotRunning != "false" {
				d = fmt.Sprintf("after a failed connect the diagnostics blob says route_running=%s (posture=%v, route_check=failed): the app cannot tell this from a connection that is being retried and would show \"Connecting…\" with nothing running",
					gotRunning, diag["posture"])
			}
			rc.R.Add(f.Name, phase, "engine.failed_connect_not_running", "false", gotRunning, d,
				map[string]any{"posture": diag["posture"], "route_check": diag["route_check"], "route_running": diag["route_running"]}, t0)
		}
	}
}

// Events returns every recorded event with the given name.
func (c *Client) Events(name string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, ev := range c.seen {
		if ev["event"] == name {
			out = append(out, ev)
		}
	}
	return out
}

// productClassify runs the product's own classifier
// (core/diagnostics.Classify, linked into wb-client) over an error text.
func productClassify(ctx context.Context, p Paths, text string) string {
	cmd := exec.CommandContext(ctx, filepath.Join(p.Bin, "wb-client"), "--classify")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(text, "\n", " ") + "\n")
	out, err := cmd.Output()
	var res struct {
		Category string `json:"category"`
	}
	if err != nil || json.Unmarshal(out, &res) != nil {
		return "(classifier not available: " + errStr(err) + ")"
	}
	return res.Category
}

// dpiFiredOn reports whether the DPI box logged a fired rule for the flow
// whose client end is local ("ip:port").
func dpiFiredOn(p Paths, local string) bool {
	if local == "" {
		return false
	}
	body, _ := os.ReadFile(filepath.Join(p.Run, "dpi-events.jsonl"))
	return strings.Contains(string(body), `"flow":"`+local+`\u003e`) || strings.Contains(string(body), `"flow":"`+local+`>`)
}
