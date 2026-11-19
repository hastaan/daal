package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() { Ops["l3"] = opL3 }

// opL3: rotation rung L3 — the relay moves to a new ADDRESS and keeps
// everything else (`assign-fip`, then `floating-ip release`).
//
// The swap has a cloud half and a box half. The cloud half here is the
// lab's (fakecloud_fip.go): it reserves an address from a pool and
// "routes" it to the server, and — like a real provider — does nothing
// to the server itself. The box half is the product's and is the point:
// daal-deploy must tell the REAL daal-relay-mgmt, over the real signed
// mgmt API, to put the address on its interface (/bind-address), prove
// from outside that the relay answers there, and only then commit the
// record. Later it must take the address off again (/unbind-address)
// before giving it back.
//
//  1. the new address answers NOBODY yet               → blocked (control)
//  2. `assign-fip`                                     (reserve → attach → bind → probe → commit)
//  3. the record moved to the new address, in both places it names one
//  4. the box holds the address on its public NIC, has a persistence
//     record for it and the boot unit that re-applies it
//  5. re-sign + re-mint r1's file against the moved record
//  6. the OLD file still connects                       → pass  (the swap's safety
//     property: the relay answers on both until the old address is given up)
//  7. the censor blocks the OLD address
//  8. the OLD file                                      → blocked
//  9. the NEW file                                      → pass  (proves the new
//     address serves — and that it is the bind that made it serve, see 1 and 13)
//     9b. NO NEW FILE: a phone holding a file minted BEFORE the move polls
//     the freshness mirrors, where the publisher has put nothing but
//     the re-signed, credential-less pack, and connects — with the old
//     address still blocked                              → pass
//     9c. AFTER AN L2 (only when op l2 ran earlier in this world): the
//     cover host moved, then the address did. naive is the one family
//     that puts a name from the relay's certificate on the wire once
//     the address is not in it, so:
//     - the NEW file's naive route verifies — and presents — the
//     CURRENT cover host, not the one the relay was provisioned
//     with;
//     - a phone that holds a file from before BOTH rotations, and is
//     handed nothing, still connects on every family     → pass
//  10. the censor's block is lifted
//  11. `floating-ip release`                             (detach → unbind → release)
//  12. the record is back on the primary address; the box no longer holds
//     the released address, nor a persistence record for it
//  13. the file minted for the released address         → blocked
//  14. the original file                                 → pass
//
// The world is left as it was found (relay on its primary address, r1's
// original file valid), so other ops can follow.
//
// What this does NOT cover: a real provider's routing, action locking,
// billing, and the survival of the bind across a real reboot (the boot
// unit's presence is asserted; it is not booted).
func opL3(rc *RunCtx) {
	const phase = "op:l3"
	fams := rc.liveFamilies(phase)
	oldIP := rc.Rec.PublicIP
	oldPack := rc.Pack
	candidate := FloatingIPPool[0] // the pool issues in order; asserted against the record below

	// 0. Does this relay say it can do it? The verb refuses before it
	// reserves anything when it does not, and that refusal is the
	// product working — but then there is nothing here to exercise.
	caps, _, _, _ := rc.Health()
	if !contains(caps, "bind-address") {
		t0 := time.Now()
		v := rc.Pub.AssignFIP(rc.Ctx)
		rc.MgmtWindowClosed(phase)
		reserved := 0
		for _, q := range CloudRequests(rc.P) {
			if q.Method == "POST" && q.Path == "/v1/floating_ips" {
				reserved++
			}
		}
		rc.R.Add("", phase, "refused_before_reserving", Refused, got(v.RC == 3 && reserved == 0, Refused, Fail), v.Tail(),
			map[string]any{"rc": v.RC, "addresses_reserved": reserved, "relay_capabilities": caps}, t0)
		rc.R.Add("", phase, "address_move", Skipped, Skipped,
			"this relay's daal-relay-mgmt does not advertise bind-address, so an L3 swap cannot be performed on it (run with --mgmt=tree); the refusal itself is asserted above", nil, t0)
		return
	}

	// 9b is armed here, before the move: r1's file as it is in the
	// field, with a mirror set in it.
	fc, heldPack, armed := rc.armNoNewFile(phase, "l3")

	// 1. control: nothing answers on the address the pool will issue.
	t0 := time.Now()
	rc.R.Add("", phase, "new_address_dead_before_swap", Blocked, got(rc.tcpFromClient(candidate, 443), Pass, Blocked), "",
		map[string]any{"address": candidate}, t0)

	// 2. the swap.
	t0 = time.Now()
	v := rc.Pub.AssignFIP(rc.Ctx)
	okSwap := rc.R.Add("", phase, "verb.assign-fip", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"rc": v.RC}, t0)
	rc.MgmtWindowClosed(phase)
	if !okSwap {
		rc.l3Leftovers(phase, oldIP)
		return
	}
	if warn := strings.Count(v.Stderr, "warning:"); warn > 0 {
		rc.R.Add("", phase, "assign-fip.no_warnings", Pass, Fail, v.Tail(), nil, t0)
	}

	// 3. the record.
	t0 = time.Now()
	rec, err := rc.Pub.Record()
	if err != nil {
		rc.R.Add("", phase, "record.address_moved", Pass, Fail, err.Error(), nil, t0)
		return
	}
	recMap := rc.Pub.RecordMap()
	fipID, _ := recMap["floating_ip_id"].(string)
	newIP := rec.PublicIP
	var problems []string
	if newIP == oldIP || newIP == "" {
		problems = append(problems, "public_ip did not move (still "+newIP+")")
	}
	if newIP != candidate {
		problems = append(problems, fmt.Sprintf("public_ip is %s, the cloud issued %s", newIP, candidate))
	}
	if fipID == "" {
		problems = append(problems, "floating_ip_id is empty")
	}
	if body, _ := os.ReadFile(rc.Pub.Path("record.json")); strings.Contains(string(body), "public_ip:"+oldIP) {
		problems = append(problems, "a candidate's public_ip:* tag still names the old address "+oldIP)
	}
	rc.R.Add("", phase, "record.address_moved", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"previous": oldIP, "now": newIP, "floating_ip_id": fipID}, t0)
	rc.Rec = rec

	// 4. the box.
	t0 = time.Now()
	problems = nil
	addrs := rc.relayAddrs()
	if !contains(addrs, newIP) {
		problems = append(problems, "the relay's public NIC does not hold "+newIP)
	}
	if !contains(addrs, oldIP) {
		problems = append(problems, "the relay's public NIC lost its primary address "+oldIP)
	}
	boundDir := filepath.Join(rc.P.Box(rec.ServerID), "etc-upper", "daal", "bound-addresses")
	records, _ := os.ReadDir(boundDir)
	var recNames []string
	for _, e := range records {
		recNames = append(recNames, e.Name())
	}
	if len(recNames) != 1 {
		problems = append(problems, fmt.Sprintf("expected exactly one persistence record in /etc/daal/bound-addresses, found %v", recNames))
	}
	unit, uerr := rc.BoxFile("systemd/system/daal-bound-addresses.service")
	if uerr != nil || !strings.Contains(unit, "-reapply-addresses") {
		problems = append(problems, "no boot unit that re-applies the address after a reboot")
	}
	rc.R.Add("", phase, "box.address_bound_and_persisted", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"nic_addresses": addrs, "persistence_records": recNames}, t0)

	// 5. the replacement file: re-sign against the moved record, re-mint
	// with r1's unchanged credentials.
	t0 = time.Now()
	bv := rc.Pub.BindAndSign(rc.Ctx, "base-l3.sbp")
	if !rc.R.Add("", phase, "verb.bind-and-sign.moved", Pass, got(bv.OK(), Pass, Fail), bv.Tail(), nil, t0) {
		rc.l3Leftovers(phase, oldIP)
		return
	}
	pv := rc.Pub.PackSBP(rc.Ctx, "base-l3.sbp", "creds-r1.json", "pack-r1-l3.sbp")
	if !rc.R.Add("", phase, "verb.users-pack-sbp.moved", Pass, got(pv.OK() && !strings.Contains(pv.Stderr, "NOT connectable"), Pass, Fail), pv.Tail(), nil, t0) {
		rc.l3Leftovers(phase, oldIP)
		return
	}
	newPack := rc.Pub.Path("pack-r1-l3.sbp")

	// 6. both addresses serve.
	for _, f := range fams {
		rc.sub(f, phase, "old-file.grace", oldPack, Pass)
	}

	// 7–9. the censor burns the old address.
	t0 = time.Now()
	block := "add table inet wb_op_l3; add chain inet wb_op_l3 forward { type filter hook forward priority -5; }; " +
		"add rule inet wb_op_l3 forward ip daddr " + oldIP + " drop; add rule inet wb_op_l3 forward ip saddr " + oldIP + " drop"
	_, berr := sh(rc.Ctx, inNS(NSCensor, "nft", block)...)
	stillOpen := rc.tcpFromClient(oldIP, 443)
	if !rc.R.Add("", phase, "censor.blocks_old_address", Blocked, got(berr == nil && !stillOpen, Blocked, Fail), errStr(berr),
		map[string]any{"address": oldIP}, t0) {
		_, _ = sh(rc.Ctx, inNS(NSCensor, "nft", "delete", "table", "inet", "wb_op_l3")...)
		rc.l3Leftovers(phase, oldIP)
		return
	}
	for _, f := range fams {
		rc.sub(f, phase, "old-file.address-blocked", oldPack, Blocked)
		rc.sub(f, phase, "new-file.address-blocked", newPack, Pass)
	}

	// 9b. no new file. L3 touched no credential, so the signed endpoint
	// is all a phone is missing — and that is public.
	if armed {
		fc.noNewFile("l3", "address-blocked", fams, heldPack)
	}

	// 9c. the cover host moved before the address did.
	if rc.PreL2.Pack != "" {
		hasNaive := false
		for _, f := range fams {
			hasNaive = hasNaive || f.Name == "naive"
		}
		if hasNaive {
			t0 = time.Now()
			name, cert, perr := packNaive(newPack)
			problems = nil
			switch {
			case perr != nil:
				problems = append(problems, perr.Error())
			default:
				if name != rc.Rec.CoverSNI {
					problems = append(problems, fmt.Sprintf("the new file's naive route verifies and presents %q; the relay's cover host is %q", name, rc.Rec.CoverSNI))
				}
				if name == rc.PreL2.CoverSNI {
					problems = append(problems, "that is the cover host the operator rotated AWAY from")
				}
				if contains(cert.IPs, newIP) {
					problems = append(problems, "fixture: the certificate names the new address, so no name is on the wire and this check proves nothing")
				}
			}
			rc.R.Add("naive", phase, "after-l2.new-file.presents_current_cover_host", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
				map[string]any{"server_name": name, "cover_host_now": rc.Rec.CoverSNI, "cover_host_before_l2": rc.PreL2.CoverSNI, "certificate_dns": cert.DNS}, t0)
		}
		if armed {
			fc.noNewFile("l3-pre-l2", "after-l2.address-blocked", fams, rc.PreL2.Pack)
		}
	}

	// 10. lift the block: what follows is about the box, not the censor.
	_, _ = sh(rc.Ctx, inNS(NSCensor, "nft", "delete", "table", "inet", "wb_op_l3")...)

	// 11. give the address back.
	t0 = time.Now()
	rv := rc.Pub.ReleaseFIP(rc.Ctx)
	okRel := rc.R.Add("", phase, "verb.floating-ip-release", Pass, got(rv.OK(), Pass, Fail), rv.Tail(), map[string]any{"rc": rv.RC}, t0)
	rc.MgmtWindowClosed(phase)
	if rec2, err := rc.Pub.Record(); err == nil {
		rc.Rec = rec2
	}
	if !okRel {
		return
	}

	// 12. record and box are back where they started.
	t0 = time.Now()
	problems = nil
	if rc.Rec.PublicIP != oldIP {
		problems = append(problems, fmt.Sprintf("record public_ip is %s, expected the primary address %s", rc.Rec.PublicIP, oldIP))
	}
	if id, _ := rc.Pub.RecordMap()["floating_ip_id"].(string); id != "" {
		problems = append(problems, "record still carries floating_ip_id "+id)
	}
	if body, _ := os.ReadFile(rc.Pub.Path("record.json")); strings.Contains(string(body), "public_ip:"+newIP) {
		problems = append(problems, "a candidate's public_ip:* tag still names the released address "+newIP)
	}
	addrs = rc.relayAddrs()
	if contains(addrs, newIP) {
		problems = append(problems, "the relay's public NIC STILL holds the released address "+newIP)
	}
	if !contains(addrs, oldIP) {
		problems = append(problems, "the relay's public NIC lost its primary address "+oldIP)
	}
	if left, _ := os.ReadDir(boundDir); len(left) != 0 {
		problems = append(problems, fmt.Sprintf("%d persistence record(s) left in /etc/daal/bound-addresses: the address would come back at the next reboot", len(left)))
	}
	leftInCloud := 0
	for _, q := range CloudRequests(rc.P) {
		switch {
		case q.Method == "POST" && q.Path == "/v1/floating_ips" && q.Status == 201:
			leftInCloud++
		case q.Method == "DELETE" && strings.HasPrefix(q.Path, "/v1/floating_ips/") && q.Status == 204:
			leftInCloud--
		}
	}
	if leftInCloud != 0 {
		problems = append(problems, fmt.Sprintf("%d reserved address(es) left on the cloud account (still billing)", leftInCloud))
	}
	rc.R.Add("", phase, "released.record_box_and_account_clean", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"nic_addresses": addrs, "record_public_ip": rc.Rec.PublicIP}, t0)

	// 13–14. the insider's view of the release.
	for _, f := range fams {
		rc.sub(f, phase, "released-address-file", newPack, Blocked)
		rc.sub(f, phase, "original-file", oldPack, Pass)
	}
	t0 = time.Now()
	notModelled := 0
	for _, q := range CloudRequests(rc.P) {
		if q.Status == 501 {
			notModelled++
		}
	}
	rc.R.Add("", phase, "cloud.api_fully_modelled", Pass, got(notModelled == 0, Pass, Fail),
		fmt.Sprintf("%d cloud API calls hit an endpoint the lab does not model (grep 501 cloud-requests.jsonl)", notModelled), nil, t0)
}

// l3Leftovers reports what a FAILED swap left behind. A failed L3 must
// leave the record on the working address and nothing extra configured
// or reserved; that is the verb's stated rollback contract.
func (rc *RunCtx) l3Leftovers(phase, oldIP string) {
	t0 := time.Now()
	var problems []string
	if rec, err := rc.Pub.Record(); err == nil {
		if rec.PublicIP != oldIP {
			problems = append(problems, "record public_ip is "+rec.PublicIP+" after a failed swap")
		}
		rc.Rec = rec
	}
	addrs := rc.relayAddrs()
	for _, a := range addrs {
		if contains(FloatingIPPool, a) {
			problems = append(problems, "the relay still holds "+a)
		}
	}
	reserved := 0
	for _, q := range CloudRequests(rc.P) {
		switch {
		case q.Method == "POST" && q.Path == "/v1/floating_ips" && q.Status == 201:
			reserved++
		case q.Method == "DELETE" && strings.HasPrefix(q.Path, "/v1/floating_ips/") && q.Status == 204:
			reserved--
		}
	}
	if reserved != 0 {
		problems = append(problems, fmt.Sprintf("%d address(es) still reserved on the cloud account", reserved))
	}
	rc.R.Add("", phase, "failed_swap_left_nothing_behind", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"nic_addresses": addrs}, t0)
}
