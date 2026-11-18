package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func init() { Ops["l1"] = opL1 }

// opL1: rotation rung L1 — `rotate-credentials --name <one recipient>`.
// The product's claim is "a targeted revocation": ONE recipient's
// secrets are re-minted on every inbound, nobody else is touched, and no
// box-wide key moves.
//
//  1. provision r21 (to be rotated) and r22 (a bystander); r1 is a
//     second bystander
//  2. r21's pack connects                            → pass  (it was good)
//  3. `rotate-credentials --name r21`
//  4. the verb's answer: every per-user secret changed, the box-wide
//     material did not, and the relay names every inbound it rewrote
//  5. the box: none of r21's old secrets is anywhere in the live config;
//     r22's and r1's rows are byte-identical to before
//  6. r21's OLD pack                                 → blocked
//  7. r21's NEW pack (users-pack-sbp from the answer) → pass
//  8. r22's and r1's untouched packs                 → pass
//
// 6 is the control for 7 and 8 is the control for 6: without 8, "the old
// pack stopped working" would also be true of a rotation that broke the
// relay.
func opL1(rc *RunCtx) {
	const phase = "op:l1"
	const victim, bystander = "r21", "r22"
	oldPack, ok := rc.MintRecipient(victim, phase)
	if !ok {
		return
	}
	byPack, ok := rc.MintRecipient(bystander, phase)
	if !ok {
		return
	}
	fams := rc.liveFamilies(phase)
	for _, f := range fams {
		rc.sub(f, phase, "before", oldPack, Pass)
	}
	rowsBefore := rc.userRows()

	t0 := time.Now()
	v := rc.Pub.RotateCredentials(rc.Ctx, victim, "creds-"+victim+"-rotated.json")
	if !rc.R.Add("", phase, "verb.rotate-credentials."+victim, Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"rc": v.RC}, t0) {
		rc.MgmtWindowClosed(phase)
		return
	}
	rc.MgmtWindowClosed(phase)

	// 4. the answer.
	t0 = time.Now()
	before, err1 := rc.Pub.ReadCreds("creds-" + victim + ".json")
	after, err2 := rc.Pub.ReadCreds("creds-" + victim + "-rotated.json")
	if err1 != nil || err2 != nil {
		rc.R.Add("", phase, "answer.every_secret_changed", Pass, Fail, fmt.Sprint(err1, err2), nil, t0)
		return
	}
	var problems, rotated, oldSecrets []string
	for _, field := range perUserSecrets {
		o, n := secretOf(before, field), secretOf(after, field)
		switch {
		case o == "" && n == "":
		case n == "":
			problems = append(problems, field+": present before, missing from the rotation answer")
		case o == n:
			problems = append(problems, field+": unchanged by the rotation")
		default:
			rotated = append(rotated, field)
			oldSecrets = append(oldSecrets, o)
		}
	}
	rc.R.Add("", phase, "answer.every_secret_changed", Pass, got(len(problems) == 0 && len(rotated) > 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"rotated": rotated}, t0)

	problems = nil
	for _, field := range boxWideMaterial {
		if before.Str(field) != after.Str(field) {
			problems = append(problems, fmt.Sprintf("%s moved (%q → %q)", field, before.Str(field), after.Str(field)))
		}
	}
	if b, _ := after["box_keys_rotated"].(bool); b {
		problems = append(problems, "box_keys_rotated=true")
	}
	rc.R.Add("", phase, "answer.box_material_unmoved", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"fields": boxWideMaterial}, t0)

	// The relay must NAME what it rewrote, and that must be every
	// inbound that carries per-user rows: a rotation that reached five
	// of six inbounds leaves the leaked credential live on the sixth.
	var updated []string
	if raw, ok := after["updated_inbounds"].([]any); ok {
		for _, x := range raw {
			if s, _ := x.(string); s != "" {
				updated = append(updated, s)
			}
		}
	}
	var notRewritten []string
	for tag, users := range rc.boxInbounds() {
		if contains(users, victim) && !contains(updated, tag) {
			notRewritten = append(notRewritten, tag)
		}
	}
	var warnings []any
	if w, ok := after["warnings"].([]any); ok {
		warnings = w
	}
	rc.R.Add("", phase, "answer.names_every_inbound", Pass, got(len(updated) > 0 && len(notRewritten) == 0 && len(warnings) == 0, Pass, Fail),
		got(len(notRewritten) == 0, fmt.Sprint(warnings...), "inbounds that carry "+victim+" but were not reported as rewritten: "+strings.Join(notRewritten, ", ")),
		map[string]any{"updated_inbounds": updated, "warnings": warnings}, t0)

	// 5. the box.
	t0 = time.Now()
	cfg := rc.BoxSingboxConfig()
	var still []string
	for i, s := range oldSecrets {
		if strings.Contains(cfg, s) {
			still = append(still, rotated[i])
		}
	}
	rc.R.Add("", phase, "box.old_secrets_gone", Pass, got(cfg != "" && len(still) == 0, Pass, Fail),
		got(len(still) == 0, "", "the live sing-box config still contains the OLD value of: "+strings.Join(still, ", ")), nil, t0)

	rowsAfter := rc.userRows()
	problems = nil
	untouched := 0
	for key, row := range rowsBefore {
		if strings.HasSuffix(key, "/"+victim) {
			if rowsAfter[key] == row {
				problems = append(problems, key+": row unchanged")
			}
			continue
		}
		untouched++
		if rowsAfter[key] != row {
			problems = append(problems, key+": a bystander's row changed")
		}
	}
	rc.R.Add("", phase, "box.only_the_named_recipient_changed", Pass, got(len(problems) == 0 && untouched > 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"bystander_rows_compared": untouched}, t0)

	// 7. the replacement file, minted from the verb's own answer.
	t0 = time.Now()
	pv := rc.Pub.PackSBP(rc.Ctx, "base.sbp", "creds-"+victim+"-rotated.json", "pack-"+victim+"-rotated.sbp")
	if !rc.R.Add("", phase, "verb.users-pack-sbp."+victim+".rotated", Pass, got(pv.OK() && !strings.Contains(pv.Stderr, "NOT connectable"), Pass, Fail), pv.Tail(), nil, t0) {
		return
	}
	newPack := rc.Pub.Path("pack-" + victim + "-rotated.sbp")

	for _, f := range fams {
		rc.sub(f, phase, "old", oldPack, Blocked)
		rc.sub(f, phase, "new", newPack, Pass)
		rc.sub(f, phase, "bystander", byPack, Pass)
		rc.sub(f, phase, "bystander-r1", rc.Pack, Pass)
	}
}

// userRows returns "<inbound tag>/<user name>" → that user's row in the
// live sing-box config, canonically encoded.
func (rc *RunCtx) userRows() map[string]string {
	var doc struct {
		Inbounds []struct {
			Tag   string           `json:"tag"`
			Users []map[string]any `json:"users"`
		} `json:"inbounds"`
	}
	_ = json.Unmarshal([]byte(rc.BoxSingboxConfig()), &doc)
	out := map[string]string{}
	for _, in := range doc.Inbounds {
		for _, u := range in.Users {
			name, _ := u["name"].(string)
			if name == "" {
				name, _ = u["username"].(string)
			}
			row, _ := json.Marshal(u)
			out[in.Tag+"/"+name] = string(row)
		}
	}
	return out
}
