// account-audit / account-reclaim — the operator's way out of a
// half-done provision or rotation.
//
// # WHY THIS IS A CLI VERB AND NOT A SCREEN IN THE APP
//
// The decision was made against the failure this exists for, not
// against convenience.
//
//  1. THE APP DOES NOT HAVE THE INPUT. The wizard persists an
//     OperatorRecord only on a SUCCESSFUL provision. The orphan is born
//     in exactly the window where that write never happened — so at the
//     moment the operator needs this most, the app's own database holds
//     nothing about the server that is billing. A screen driven by the
//     app's rows would be blind to the one resource it was opened to
//     find. This verb takes zero records and still works; that is the
//     whole point, and it is not a shape a record-driven UI can take.
//
//  2. THE SCOPE IS THE ACCOUNT, NOT THE RELAY. Every screen in the
//     wizard is scoped to one relay the operator is managing. The audit
//     has to reason about relays it does NOT manage — the sibling
//     running out of the same Hetzner account is the thing most of its
//     guards exist to protect. Putting an account-wide destructive verb
//     inside a per-relay flow invites exactly the mistake the guards
//     are for.
//
//  3. THE OUTPUT IS EVIDENCE, NOT A DASHBOARD. What an operator does
//     with this is cross-check it against the provider console: ids,
//     names, regions, reasons. That is text, it wants to be pasted into
//     a support ticket or a terminal beside `hcloud server list`, and
//     `--json` makes it diffable between runs. A rendered card loses
//     the half that makes it usable.
//
//  4. THE HONEST BLOCKER: the app is the surface the operator actually
//     opens, and a CLI verb they never hear about is a fix nobody runs.
//     That is a real cost and it is not paid here. It is paid by the
//     places that already hand out CLI invocations in their own words —
//     Decommission's floating-IP notice, and the audit's own Hint
//     fields, which name the next command for every finding. Wiring a
//     surface into the app means Farsi and English copy in four files
//     and belongs to whoever owns the UI in this wave, not to a
//     bolted-on panel written blind.
//
// Two verbs rather than one with a --delete flag, deliberately. The
// read-only one and the destructive one should not be one typo apart.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"daal/publisher/deploy/provider"
)

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// auditorFor resolves an adapter that can enumerate an account.
//
// The type assertion is the whole reason AccountAuditor is optional
// rather than part of Provider: an adapter that cannot enumerate must
// say so, because an empty list from a half-built adapter reads
// exactly like a clean account, and "clean" is the one answer this
// tool must never give by accident.
func auditorFor(providerName, tokenFile string) (provider.AccountAuditor, error) {
	prov, err := buildProviderFn(providerName, tokenFile, false)
	if err != nil {
		return nil, err
	}
	aud, ok := prov.(provider.AccountAuditor)
	if !ok {
		return nil, fmt.Errorf("the %s adapter cannot audit an account yet: it has no way to list every reserved address, "+
			"SSH key and firewall, and reporting \"nothing found\" from an adapter that cannot look would be a lie about "+
			"resources that are still billing. Check the %s console by hand", providerName, providerName)
	}
	return aud, nil
}

// readRecords loads zero or more OperatorRecords.
//
// Zero is supported and is the case this verb was built for: the
// orphan that costs the most is the one whose record was never
// written. A record that will not parse is fatal rather than skipped —
// running the audit while silently ignoring one of the operator's
// relays is how a live relay's resources get classified as unclaimed.
func readRecords(paths []string) ([]*provider.OperatorRecord, error) {
	var out []*provider.OperatorRecord
	for _, p := range paths {
		rec, err := readRecord(p)
		if err != nil {
			return nil, fmt.Errorf("read record-file %s: %w", p, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func runAccountAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("account-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	providerName := fs.String("provider", "hetzner", "cloud provider (hetzner, vultr)")
	tokenFile := fs.String("token-file", "", "API token file")
	asJSON := fs.Bool("json", false, "emit the full audit as JSON instead of prose")
	var records stringList
	fs.Var(&records, "record-file", "OperatorRecord JSON path (REPEATABLE; optional — the audit works with none)")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	recs, err := readRecords(records)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	aud, err := auditorFor(*providerName, *tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	report, err := aud.AuditAccount(ctx, recs)
	if err != nil {
		fmt.Fprintf(stderr, "account-audit: %v\n", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "marshal: %v\n", err)
			return 1
		}
	} else {
		printAudit(stdout, report)
	}
	// Exit 0 either way. This is a read-only report, and a non-zero
	// exit for "you have an orphan" would make it useless in a script
	// that runs it before every provision — which is exactly where it
	// belongs.
	return 0
}

// printAudit renders the report the way an operator reads it: the
// things that cost money and need a human decision first, the
// automatic fixes second, the untouched majority last.
func printAudit(w io.Writer, a *provider.AccountAudit) {
	fmt.Fprintf(w, "account audit — %s — %s\n", a.Provider, a.CheckedAt.Format("2006-01-02 15:04:05 MST"))
	if !a.ServerListComplete {
		fmt.Fprintln(w, "\n  !! the account's server list could not be read.")
		fmt.Fprintln(w, "     Nothing below is proven: \"no server is behind this\" is a claim about that list.")
		fmt.Fprintln(w, "     account-reclaim will refuse until this is fixed.")
	}
	if len(a.Known) > 0 {
		fmt.Fprintln(w, "\nrecords you supplied:")
		for _, k := range a.Known {
			live := k.LiveServerID
			if live == "" {
				live = "(no server by that name)"
			}
			fmt.Fprintf(w, "  %s  record says %q, account says %s\n", k.Relay, k.RecordServerID, live)
			if k.Note != "" {
				fmt.Fprintf(w, "      %s\n", k.Note)
			}
		}
	}

	byVerdict := map[provider.AuditVerdict][]provider.AuditedResource{}
	for _, r := range a.Resources {
		byVerdict[r.Verdict] = append(byVerdict[r.Verdict], r)
	}
	sections := []struct {
		v      provider.AuditVerdict
		header string
	}{
		{provider.VerdictUnclaimed, "NEEDS YOUR DECISION — daal built these, nothing you supplied claims them:"},
		{provider.VerdictUnproven, "COULD NOT BE PROVEN — reported so you can check by hand; nothing will be deleted:"},
		{provider.VerdictOrphan, "PROVEN ORPHANED — `daal-deploy account-reclaim` removes these:"},
		{provider.VerdictInUse, "in use — left alone:"},
	}
	for _, s := range sections {
		rs := byVerdict[s.v]
		if len(rs) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", s.header)
		for _, r := range rs {
			bill := ""
			if r.Billing {
				bill = "  [billing]"
			}
			name := r.Name
			if name != "" {
				name = " " + name
			}
			fmt.Fprintf(w, "  %-12s %s%s%s\n", r.Kind, r.ID, name, bill)
			fmt.Fprintf(w, "      %s\n", r.Reason)
			if r.Hint != "" {
				fmt.Fprintf(w, "      -> %s\n", r.Hint)
			}
		}
	}
	if len(a.Warnings) > 0 {
		fmt.Fprintln(w, "\nwarnings:")
		for _, warn := range a.Warnings {
			fmt.Fprintf(w, "  - %s\n", warn)
		}
	}
	if !a.NeedsAttention() {
		fmt.Fprintln(w, "\nnothing is orphaned and nothing is unaccounted for.")
	}
}

// parseRef turns "kind:id" into a ResourceRef.
func parseRef(s string) (provider.ResourceRef, error) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return provider.ResourceRef{}, fmt.Errorf("--only %q: want \"<kind>:<id>\", e.g. %q", s, provider.KindFloatingIP+":12345")
	}
	kind := s[:i]
	switch kind {
	case provider.KindFloatingIP, provider.KindSSHKey, provider.KindFirewall, provider.KindServer:
	default:
		return provider.ResourceRef{}, fmt.Errorf("--only %q: unknown kind %q (server, floating-ip, ssh-key, firewall)", s, kind)
	}
	return provider.ResourceRef{Kind: kind, ID: s[i+1:]}, nil
}

func runAccountReclaim(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("account-reclaim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	providerName := fs.String("provider", "hetzner", "cloud provider (hetzner, vultr)")
	tokenFile := fs.String("token-file", "", "API token file")
	asJSON := fs.Bool("json", false, "emit the reclaim report as JSON")
	// --yes and not --force. This deletes cloud resources, and a verb
	// that deletes must not be reachable by a bare invocation that
	// looks like the read-only one with a typo in it.
	yes := fs.Bool("yes", false, "actually delete; without it this prints what WOULD be reclaimed and stops")
	var records stringList
	var only stringList
	fs.Var(&records, "record-file", "OperatorRecord JSON path (REPEATABLE; a record protects everything it names)")
	fs.Var(&only, "only", "restrict to \"<kind>:<id>\" (REPEATABLE); default is every proven orphan")
	if rc := parseFlags(fs, args); rc >= 0 {
		return rc
	}
	if err := requireAll(stderr, map[string]string{"--token-file": *tokenFile}); err != nil {
		return 2
	}
	refs := make([]provider.ResourceRef, 0, len(only))
	for _, s := range only {
		r, err := parseRef(s)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		refs = append(refs, r)
	}
	recs, err := readRecords(records)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	aud, err := auditorFor(*providerName, *tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	// Dry run first, always, and it is the DEFAULT. The audit is cheap
	// and read-only, so there is no reason an operator should ever
	// have to run the destructive verb to find out what it would do.
	if !*yes {
		report, err := aud.AuditAccount(ctx, recs)
		if err != nil {
			fmt.Fprintf(stderr, "account-reclaim: %v\n", err)
			return 1
		}
		printReclaimPlan(stdout, report, refs)
		return 0
	}

	rep, err := aud.ReclaimOrphans(ctx, recs, refs)
	if err != nil {
		// The report still prints: a refusal that names what it
		// refused is more useful than an error alone.
		printReclaim(stderr, rep)
		fmt.Fprintf(stderr, "account-reclaim: %v\n", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "marshal: %v\n", err)
			return 1
		}
		return 0
	}
	printReclaim(stdout, rep)
	// A refusal is not a failure of this command — it is the command
	// working. Exit 0, and let the report say what survived.
	return 0
}

func printReclaimPlan(w io.Writer, a *provider.AccountAudit, only []provider.ResourceRef) {
	want := map[provider.ResourceRef]bool{}
	for _, r := range only {
		want[r] = true
	}
	var plan []provider.AuditedResource
	for _, r := range a.Resources {
		if !r.Reclaimable {
			continue
		}
		if len(want) > 0 && !want[r.Ref()] {
			continue
		}
		plan = append(plan, r)
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].Kind < plan[j].Kind })
	if !a.ServerListComplete {
		fmt.Fprintln(w, "the account's server list could not be read, so nothing can be proven orphaned.")
		fmt.Fprintln(w, "account-reclaim would refuse. Fix API access and re-run `daal-deploy account-audit`.")
		return
	}
	if len(plan) == 0 {
		fmt.Fprintln(w, "nothing is provably orphaned; --yes would delete nothing.")
		fmt.Fprintln(w, "run `daal-deploy account-audit` to see what was left alone and why.")
		return
	}
	fmt.Fprintf(w, "would delete %d resource(s). Re-run with --yes to do it:\n\n", len(plan))
	for _, r := range plan {
		fmt.Fprintf(w, "  %-12s %s %s\n      %s\n", r.Kind, r.ID, r.Name, r.Reason)
	}
	fmt.Fprintln(w, "\nnothing else is touched. Servers are never deleted by this verb.")
}

func printReclaim(w io.Writer, rep *provider.ReclaimReport) {
	if rep == nil {
		return
	}
	deleted := rep.Deleted()
	fmt.Fprintf(w, "account reclaim — %s — %d deleted, %d left alone\n", rep.Provider, deleted, len(rep.Outcomes)-deleted)
	for _, o := range rep.Outcomes {
		mark := "kept "
		if o.Deleted {
			mark = "gone "
		}
		fmt.Fprintf(w, "  %s %-12s %s %s\n      %s\n", mark, o.Kind, o.ID, o.Name, o.Reason)
	}
	for _, warn := range rep.Warnings {
		fmt.Fprintf(w, "  ! %s\n", warn)
	}
}
