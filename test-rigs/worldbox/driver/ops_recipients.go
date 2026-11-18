package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func init() { Ops["recipients"] = opRecipients }

// recipientNames are the extra recipients this op provisions. With r1
// (minted by the run itself) that is four people on one relay.
var recipientNames = []string{"r11", "r12", "r13"}

// opRecipients: several recipients on one relay, each with their own
// credentials, all connected.
//
//  1. `users-provision` + `users-pack-sbp` for r11, r12, r13
//  2. every per-user secret differs between all four recipients; the
//     box-wide material (REALITY public key, TLS pin, cover host) is the
//     same for all four                              (the publisher's view)
//  3. `users-list` names exactly the recipients that exist
//  4. every inbound the relay serves carries a row for each of them
//     (the box's view)
//  5. each recipient's pack connects and carries verified bytes, on
//     every family under test                        (the insider's view)
//
// The control for 5 is the session's own (no tunnel ⇒ no path) plus the
// `revoke` and `wrongcreds` ops, which show that a recipient whose row is
// absent, or whose secret is wrong, does NOT connect — so "all four
// connect" is four separate facts, not one open door.
func opRecipients(rc *RunCtx) {
	const phase = "op:recipients"
	packs := map[string]string{"r1": rc.Pack}
	for _, name := range recipientNames {
		pack, ok := rc.MintRecipient(name, phase)
		if !ok {
			return
		}
		packs[name] = pack
	}
	rc.MgmtWindowClosed(phase)

	// 2. distinct per-user secrets, shared box-wide material.
	t0 := time.Now()
	names := append([]string{"r1"}, recipientNames...)
	creds := map[string]Creds{}
	for _, n := range names {
		c, err := rc.Pub.ReadCreds("creds-" + n + ".json")
		if err != nil {
			rc.R.Add("", phase, "creds.distinct", Pass, Fail, err.Error(), nil, t0)
			return
		}
		creds[n] = c
	}
	var problems, compared []string
	for _, field := range perUserSecrets {
		seen := map[string]string{}
		present := 0
		for _, n := range names {
			v := secretOf(creds[n], field)
			if v == "" {
				continue
			}
			present++
			if other, dup := seen[v]; dup {
				problems = append(problems, fmt.Sprintf("%s: %s and %s hold the same value", field, other, n))
			}
			seen[v] = n
		}
		switch {
		case present == len(names):
			compared = append(compared, field)
		case present != 0:
			problems = append(problems, fmt.Sprintf("%s: present for %d of %d recipients", field, present, len(names)))
		}
	}
	rc.R.Add("", phase, "creds.distinct", Pass, got(len(problems) == 0 && len(compared) > 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"recipients": names, "fields_compared": compared}, t0)

	t0 = time.Now()
	problems = nil
	for _, field := range boxWideMaterial {
		for _, n := range names[1:] {
			if creds[n].Str(field) != creds["r1"].Str(field) {
				problems = append(problems, fmt.Sprintf("%s differs between r1 and %s", field, n))
			}
		}
	}
	rc.R.Add("", phase, "creds.box_material_shared", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"fields": boxWideMaterial}, t0)

	// 3. the box's own roster.
	t0 = time.Now()
	lv := rc.Pub.UsersList(rc.Ctx)
	var missing []string
	for _, n := range names {
		if !strings.Contains(lv.Stdout, `"`+n+`"`) {
			missing = append(missing, n)
		}
	}
	rc.R.Add("", phase, "users-list.all_present", Pass, got(lv.OK() && len(missing) == 0, Pass, Fail),
		got(len(missing) == 0, lv.Tail(), "users-list does not name: "+strings.Join(missing, ", ")), map[string]any{"stdout": strings.TrimSpace(lv.Stdout)}, t0)
	rc.MgmtWindowClosed(phase)

	// 4. every user-carrying inbound has a row per recipient.
	t0 = time.Now()
	problems = nil
	inbounds := rc.boxInbounds()
	var tags []string
	for tag, users := range inbounds {
		if len(users) == 0 {
			continue // not a per-user inbound
		}
		tags = append(tags, tag)
		for _, n := range names {
			if !contains(users, n) {
				problems = append(problems, fmt.Sprintf("inbound %s has no row for %s (has: %s)", tag, n, strings.Join(users, ",")))
			}
		}
	}
	sort.Strings(tags)
	rc.R.Add("", phase, "box.row_per_recipient_per_inbound", Pass, got(len(problems) == 0 && len(tags) > 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"inbounds": tags}, t0)

	// 5. everybody connects.
	for _, f := range rc.liveFamilies(phase) {
		for _, n := range recipientNames {
			rc.sub(f, phase, n, packs[n], Pass)
		}
	}
}
