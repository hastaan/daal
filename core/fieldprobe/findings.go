package fieldprobe

import (
	"daal/bundle-go/fieldreport"
)

// Findings — the questions the publisher reads first (specs/field-probe-v2.md §4).
// A finding is emitted only when at least one probe it rests on ran;
// "unclear" when they ran and do not decide it.

func okish(res string) bool { return res == "ok" || res == "ok_carried" }

// counted: the probe ran and said something about the network. A
// local_error is the device refusing the socket: as if not run.
func counted(res string) bool { return res != "" && res != "skipped" && res != "local_error" }

func failed(res string) bool { return counted(res) && !okish(res) }

// probeResults indexes results by id (a list: some ids repeat).
func probeResults(ps []ProbeRecord) map[string][]ProbeRecord {
	m := map[string][]ProbeRecord{}
	for _, p := range ps {
		m[p.ID] = append(m[p.ID], p)
	}
	return m
}

func ran(ps []ProbeRecord) bool {
	for _, p := range ps {
		if counted(p.Result) {
			return true
		}
	}
	return false
}

func anyOK(ps []ProbeRecord) bool {
	for _, p := range ps {
		if okish(p.Result) {
			return true
		}
	}
	return false
}

func allFailed(ps []ProbeRecord) bool {
	n := 0
	for _, p := range ps {
		if !counted(p.Result) {
			continue
		}
		if !failed(p.Result) {
			return false
		}
		n++
	}
	return n > 0
}

func first(ps []ProbeRecord) string {
	for _, p := range ps {
		if counted(p.Result) {
			return p.Result
		}
	}
	return ""
}

func firstRec(ps []ProbeRecord) (ProbeRecord, bool) {
	for _, p := range ps {
		if counted(p.Result) {
			return p, true
		}
	}
	return ProbeRecord{}, false
}

// relayPathPassed: for C4–C6, the hello got through the path. REALITY
// hands a hello it does not own to the cover site, and the cover origin
// often answers a foreign name with an alert, a small 4xx or a close
// after its flight — each of which proves the hello was not stopped on
// the way. Only a reset, a silence or a stall is the path's doing.
func relayPathPassed(p ProbeRecord) bool {
	switch {
	case okish(p.Result), p.Result == "tls_alert":
		return true
	case p.tcp != nil && p.tcp.FirstEvent == "bytes" && p.tcp.HandshakeEnd == "fin":
		return true
	}
	return false
}

// Findings derives the findings of a run.
func Findings(res *Result) []fieldreport.Finding {
	m := probeResults(res.Probes)
	var out []fieldreport.Finding
	add := func(q, v, answer string, basis ...string) {
		out = append(out, fieldreport.Finding{Question: q, Variant: v, Answer: answer, Basis: basis})
	}
	yesNo := func(yes, no bool) string {
		switch {
		case yes:
			return "yes"
		case no:
			return "no"
		}
		return "unclear"
	}

	if ran(m["C2"]) {
		add("reality_443_works", "", yesNo(anyOK(m["C2"]), allFailed(m["C2"])), "C2")
	}
	if ran(m["C2"]) && ran(m["C3"]) {
		c2fail, c3ok := allFailed(m["C2"]), anyOK(m["C3"])
		add("split_hello_helps", "", yesNo(c2fail && c3ok, (c2fail && allFailed(m["C3"])) || (anyOK(m["C2"]) && c3ok)), "C2", "C3")
	}
	if w, ok := firstRec(m["C4"]); ok {
		if c, ok := firstRec(m["C5"]); ok {
			wp, cp := relayPathPassed(w), relayPathPassed(c)
			add("white_name_helps_on_relay_ip", "", yesNo(wp && !cp, wp == cp), "C4", "C5", "C6")
		}
	}
	if ran(m["B5"]) {
		b5 := first(m["B5"])
		add("white_name_uncapped_on_cdn_ip", "", yesNo(b5 == "ok_carried", b5 == "flow_capped_suspected"), "B5")
	}
	if ran(m["B6"]) {
		b6 := first(m["B6"])
		add("grey_cap_seen_on_cdn_ip", "", yesNo(b6 == "flow_capped_suspected", b6 == "ok_carried"), "B6")
	}
	{
		var basis []string
		injected, resets := false, false
		for _, p := range res.Probes {
			switch p.Result {
			case "reset_injected_likely":
				injected, resets = true, true
				basis = appendOnce(basis, p.ID)
			case "reset":
				resets = true
				basis = appendOnce(basis, p.ID)
			}
		}
		if len(basis) > 0 || len(res.Probes) > 0 {
			ans := "no"
			switch {
			case injected:
				ans = "yes"
			case resets:
				ans = "unclear"
			}
			if basis == nil {
				basis = []string{}
			}
			add("reset_looks_injected", "", ans, basis...)
		}
	}
	if cf := append(append(append([]ProbeRecord{}, m["B6"]...), m["B7"]...), m["B8"]...); ran(cf) {
		add("cloudflare_edge_reachable", "", yesNo(anyOK(cf), allFailed(cf)), "B6", "B7", "B8")
	}
	if ran(m["B7"]) {
		add("ech_passes", "", yesNo(res.ECHEncrypted, allFailed(m["B7"]) && anyOK(m["B8"])), "B7", "B8")
	}
	if ran(m["B2"]) {
		b2 := m["B2"][0]
		pass := okish(b2.Result) && (b2.Signals.HTTPStatusClass == "2xx" || b2.Signals.HTTPStatusClass == "3xx")
		add("google_front_passes", "", yesNo(pass, failed(b2.Result) && anyOK(m["B1"])), "B1", "B2", "B3")
	}
	if ran(m["B4"]) {
		b4 := m["B4"][0]
		add("github_feed_fetchable", "", yesNo(okish(b4.Result) && b4.Signals.HTTPStatusClass == "2xx", failed(b4.Result)), "B4")
	}
	for _, p := range m["A4"] {
		if !counted(p.Result) {
			continue
		}
		add("resolver_recurses_foreign_zone", p.Variant, yesNo(p.Result == "ok", p.Result != "ok"), "A4")
	}
	for _, p := range m["A6"] {
		if p.Variant != "calibration" || !counted(p.Result) {
			continue
		}
		// 1.1.1.1 never answers its own DoH name with a sinkhole: a
		// bogon here was written on the path. A public address outside
		// Cloudflare's blocks (dns_unlisted) decides nothing: Cloudflare
		// may have added a range since the list was signed.
		add("dns_injection_on_path", "", yesNo(p.Result == "bogon", p.Result == "ok"), "A5", "A6")
	}
	if ran(m["B9"]) {
		add("quic_443_alive", "", yesNo(anyOK(m["B9"]), allFailed(m["B9"])), "B9")
	}
	if ran(m["C7"]) {
		add("relay_alt_ports_open", "", yesNo(anyOK(m["C7"]), allFailed(m["C7"])), "C7")
	}
	if ran(m["C2"]) && ran(m["C9"]) {
		c2, c9 := first(m["C2"]), first(m["C9"])
		add("test_changed_outcome", "", yesNo(okish(c2) && failed(c9), okish(c2) == okish(c9)), "C2", "C9")
	}
	if out == nil {
		out = []fieldreport.Finding{}
	}
	return out
}

func appendOnce(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// Failures is the v1 failure tally of a run.
func Failures(res *Result) []fieldreport.Failure {
	counts := map[string]int{}
	var order []string
	for _, p := range res.Probes {
		c := failureCategory(p.Result, p.Phase, p.udp)
		if c == "" {
			continue
		}
		if counts[c] == 0 {
			order = append(order, c)
		}
		counts[c]++
	}
	out := []fieldreport.Failure{}
	for _, c := range order {
		out = append(out, fieldreport.Failure{Category: c, CountBucket: fieldreport.CountBucket(counts[c])})
	}
	return out
}

// Summary keys — the plain lines shown before sending. They are i18n
// KEYS (client-ui d2-extra.{en,fa}.json "netTest.summary.*"), never
// engine prose; the page renders them in order. 5–8 lines, the privacy
// line always last.
const (
	SumRelayConnects      = "netTest.summary.relayConnects"
	SumRelayCutAtStart    = "netTest.summary.relayCutAtStart"
	SumRelayNoAnswer      = "netTest.summary.relayNoAnswer"
	SumRelayNotTested     = "netTest.summary.relayNotTested"
	SumSplitHelps         = "netTest.summary.splitHelloHelps"
	SumWhiteNameHelps     = "netTest.summary.whiteNameHelps"
	SumGoogleGithubOpen   = "netTest.summary.googleGithubOpen"
	SumGoogleGithubClosed = "netTest.summary.googleGithubClosed"
	SumSomeForeignOpen    = "netTest.summary.someForeignOpen"
	SumDNSWrongAddresses  = "netTest.summary.dnsWrongAddresses"
	SumCloudflareClosed   = "netTest.summary.cloudflareClosed"
	SumCDNSlowsAfterStart = "netTest.summary.cdnSlowsAfterStart"
	SumQUICClosed         = "netTest.summary.quicClosed"
	SumBlackout           = "netTest.summary.blackout"
	SumLocalBlocked       = "netTest.summary.localBlocked"
	SumIncomplete         = "netTest.summary.incomplete"
	SumPrivacy            = "netTest.summary.privacy"
)

// One of Google and GitHub was checked, the other could not be (no
// usable address, an answer that decides nothing, or the run stopped
// first): never read as "does not open".
const (
	SumGoogleOpenGithubUnchecked   = "netTest.summary.googleOpenGithubUnchecked"
	SumGoogleClosedGithubUnchecked = "netTest.summary.googleClosedGithubUnchecked"
	SumGithubOpenGoogleUnchecked   = "netTest.summary.githubOpenGoogleUnchecked"
	SumGithubClosedGoogleUnchecked = "netTest.summary.githubClosedGoogleUnchecked"
)

// Summary picks the lines for a run.
func Summary(res *Result, fs []fieldreport.Finding) []string {
	ans := map[string]string{}
	for _, f := range fs {
		if f.Variant == "" {
			ans[f.Question] = f.Answer
		}
	}
	m := probeResults(res.Probes)
	var out []string
	if res.AbortReason == "local_blocked" {
		// Nothing was sent: the phone itself keeps the test in.
		return []string{SumLocalBlocked, SumPrivacy}
	}
	if res.Blackout {
		out = append(out, SumBlackout)
	}
	switch ans["reality_443_works"] {
	case "yes":
		out = append(out, SumRelayConnects)
	case "no", "unclear":
		switch first(m["C2"]) {
		case "reset", "reset_injected_likely", "closed", "refused":
			out = append(out, SumRelayCutAtStart)
		default:
			out = append(out, SumRelayNoAnswer)
		}
	default:
		out = append(out, SumRelayNotTested)
	}
	if ans["split_hello_helps"] == "yes" {
		out = append(out, SumSplitHelps)
	}
	if ans["white_name_helps_on_relay_ip"] == "yes" {
		out = append(out, SumWhiteNameHelps)
	}
	if line := foreignLine(googleState(m), githubState(m, ans)); line != "" {
		out = append(out, line)
	}
	if dnsWrong(m, ans) {
		out = append(out, SumDNSWrongAddresses)
	}
	if ans["cloudflare_edge_reachable"] == "no" {
		out = append(out, SumCloudflareClosed)
	}
	if ans["grey_cap_seen_on_cdn_ip"] == "yes" {
		out = append(out, SumCDNSlowsAfterStart)
	}
	if ans["quic_443_alive"] == "no" {
		out = append(out, SumQUICClosed)
	}
	if !res.Complete || res.TimeReserve {
		out = append(out, SumIncomplete)
	}
	if len(out) > 7 {
		out = out[:7]
	}
	return append(out, SumPrivacy)
}

// Whether a site opened: a probe skipped for want of a usable address,
// or one whose answer decides nothing, is "unchecked", never "closed".
const (
	siteUnchecked = iota
	siteOpen
	siteClosed
)

func googleState(m map[string][]ProbeRecord) int {
	switch {
	case anyOK(m["B1"]):
		return siteOpen
	case allFailed(m["B1"]):
		return siteClosed
	}
	return siteUnchecked
}

func githubState(m map[string][]ProbeRecord, ans map[string]string) int {
	switch ans["github_feed_fetchable"] {
	case "yes":
		return siteOpen
	case "no":
		return siteClosed
	}
	return siteUnchecked
}

func foreignLine(g, gh int) string {
	switch {
	case g == siteOpen && gh == siteOpen:
		return SumGoogleGithubOpen
	case g == siteClosed && gh == siteClosed:
		return SumGoogleGithubClosed
	case g != siteUnchecked && gh != siteUnchecked:
		return SumSomeForeignOpen
	case g == siteOpen:
		return SumGoogleOpenGithubUnchecked
	case g == siteClosed:
		return SumGoogleClosedGithubUnchecked
	case gh == siteOpen:
		return SumGithubOpenGoogleUnchecked
	case gh == siteClosed:
		return SumGithubClosedGoogleUnchecked
	}
	return ""
}

// dnsWrong: the summary says DNS gave wrong addresses only on evidence —
// a sinkhole or private answer from the link resolver (A1–A3), an
// answer written on the path to 1.1.1.1 (dns_injection_on_path), a link
// answer outside the blocks that 1.1.1.1 contradicted
// (dns_wrong_public), or an address both resolvers agreed on that then
// showed a certificate not valid for the name. An answer that is merely
// outside the list (dns_unlisted) is not evidence: a big service moves
// into new ranges before the list is re-signed.
func dnsWrong(m map[string][]ProbeRecord, ans map[string]string) bool {
	if ans["dns_injection_on_path"] == "yes" {
		return true
	}
	for _, id := range []string{"A1", "A2", "A3"} {
		for _, p := range m[id] {
			if p.Result == "bogon" || p.Result == "dns_wrong_public" {
				return true
			}
		}
	}
	for _, id := range []string{"B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8"} {
		for _, p := range m[id] {
			if p.Result == "cert_invalid" && p.Variant == "addr_agreed" {
				return true
			}
		}
	}
	return false
}
