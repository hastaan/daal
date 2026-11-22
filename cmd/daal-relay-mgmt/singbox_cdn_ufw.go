// The box-side half of "only Cloudflare reaches the CDN door"
// (add-on 2): /cdn enable opens ws-cdn-in's port at the box firewall
// (ufw) to the Cloudflare ranges the publisher sends with the door, and
// /cdn disable closes exactly those rules again.
//
// Why here and not in cloud-init. ufw at first boot is written once,
// so a rule laid down there needs Cloudflare's ranges at provision
// time: every provision would contact Cloudflare whether or not the
// publisher ever asks for the way in through Cloudflare, and a relay
// built without them would need a rebuild to gain it. The door is the
// one moment the publisher has said "yes, through Cloudflare", and it
// is the one call that already carries what Cloudflare published (the
// publisher fetched the list abroad to write the provider firewall).
//
// The rules are this box's to own: the ranges applied are kept in
// /etc/daal/cdn/edge_ranges.json, a later enable replaces the set (adds
// the new, removes the gone), and disable removes every one of them.
// Every range is parsed as a CIDR and re-printed from the parse, so
// nothing but an address and a prefix length reaches ufw's argv (argv,
// never a shell).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// maxCDNEdgeRanges bounds the door's range list. Cloudflare publishes
// about two dozen prefixes; mirrors publisher/deploy/cloudinit.
const maxCDNEdgeRanges = 64

func cdnRangesPath() string { return filepath.Join(cdnDir, "edge_ranges.json") }

// cdnUFW runs one ufw command. A variable so tests record instead of
// running it.
var cdnUFW = func(args ...string) error {
	out, err := exec.Command("ufw", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// canonicalCDNRanges checks the request's ranges and returns them in
// canonical form, each once, in the order sent.
func canonicalCDNRanges(in []string) ([]string, error) {
	if len(in) > maxCDNEdgeRanges {
		return nil, fmt.Errorf("edge_ranges: %d ranges, more than Cloudflare publishes", len(in))
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, r := range in {
		_, n, err := net.ParseCIDR(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("edge_ranges: %q is not a CIDR", r)
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("edge_ranges: %q is everyone, not a Cloudflare range", r)
		}
		c := n.String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

func cdnRuleArgs(cidr string) []string {
	return []string{"from", cidr, "to", "any", "port", strconv.Itoa(cdnListenPort), "proto", "tcp"}
}

func cdnAllow(cidr string) error {
	return cdnUFW(append([]string{"allow"}, cdnRuleArgs(cidr)...)...)
}

func cdnDeny(cidr string) error {
	return cdnUFW(append([]string{"--force", "delete", "allow"}, cdnRuleArgs(cidr)...)...)
}

// loadCDNRanges reads the ranges this box opened for the door.
func loadCDNRanges() []string {
	b, err := os.ReadFile(cdnRangesPath())
	if err != nil {
		return nil
	}
	var rs []string
	if json.Unmarshal(b, &rs) != nil {
		return nil
	}
	return rs
}

func saveCDNRanges(rs []string) error {
	if len(rs) == 0 {
		if err := os.Remove(cdnRangesPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(cdnDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(rs)
	return writeFileAtomic(cdnRangesPath(), b, 0o600)
}

// openCDNRanges adds the rules for want that the box does not hold yet
// and returns them, for undoCDNRanges if what follows fails. Nothing is
// removed here: the gone ones go in settleCDNRanges, once the door is up.
func openCDNRanges(want []string) (added []string, err error) {
	have := map[string]bool{}
	for _, r := range loadCDNRanges() {
		have[r] = true
	}
	for _, r := range want {
		if have[r] {
			continue
		}
		if err := cdnAllow(r); err != nil {
			undoCDNRanges(added)
			return nil, err
		}
		added = append(added, r)
	}
	return added, nil
}

func undoCDNRanges(added []string) {
	for _, r := range added {
		_ = cdnDeny(r)
	}
}

// settleCDNRanges removes the rules for ranges no longer wanted and
// records want as the box's set. A rule that would not go is kept in
// the record, so the next enable or disable tries it again.
func settleCDNRanges(want []string) error {
	keep := map[string]bool{}
	for _, r := range want {
		keep[r] = true
	}
	rec := append([]string{}, want...)
	var errs []string
	for _, r := range loadCDNRanges() {
		if keep[r] {
			continue
		}
		if err := cdnDeny(r); err != nil {
			rec = append(rec, r)
			errs = append(errs, err.Error())
		}
	}
	if err := saveCDNRanges(rec); err != nil {
		errs = append(errs, "record the door's firewall rules: "+err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// closeCDNRanges removes every rule this box opened for the door and
// returns how many are left (rules ufw would not remove).
func closeCDNRanges() int {
	var left []string
	for _, r := range loadCDNRanges() {
		if err := cdnDeny(r); err != nil {
			left = append(left, r)
		}
	}
	_ = saveCDNRanges(left)
	return len(left)
}
