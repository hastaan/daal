package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func init() { Ops["l2"] = opL2 }

// l2OldPackExpect is what an ALREADY-DISTRIBUTED pack does after the
// relay's cover identity moved, per family. Anything not listed keeps
// working.
//
// vless-reality is the family the rotation is FOR: the relay answers a
// REALITY handshake only for the server name it currently advertises, so
// a pack that still names the old cover host is handed to the cover site
// like any stranger. Every other family authenticates the relay by its
// pinned certificate and its own per-user secret, neither of which L2
// touches.
var l2OldPackExpect = map[string]string{
	"vless-reality": Blocked,
}

// opL2: rotation rung L2 — `rotate-tls`. The relay's cover identity
// (advertised SNI + REALITY handshake destination) moves; no key and no
// recipient credential does.
//
//  1. provision r31; its pack connects                → pass
//  2. `rotate-tls` (no --new-sni: the publisher picks, as in the app)
//  3. the record was rewritten to the new cover host; the box's live
//     config agrees with it in BOTH places (tls.server_name and
//     reality.handshake.server); REALITY keypair and every user row are
//     byte-identical
//  4. the pack minted BEFORE the rotation, per family → l2OldPackExpect
//  5. "Rebuild" r31 the way the app does (revoke → provision → pack);
//     the re-minted pack connects on every family      → pass
//  6. the re-minted pack names the NEW cover host
//  7. NO NEW FILE: a phone that holds a file minted BEFORE the rotation
//     polls the freshness mirrors — where the publisher has put nothing
//     but the re-signed, credential-less pack — and connects on every
//     family                                          → pass
//
// Afterwards r1's file is re-issued too and becomes the run's pack: L2's
// documented cost is that every distributed pack must be replaced.
func opL2(rc *RunCtx) {
	const phase = "op:l2"
	const name = "r31"
	oldPack, ok := rc.MintRecipient(name, phase)
	if !ok {
		return
	}
	fams := rc.liveFamilies(phase)
	for _, f := range fams {
		rc.sub(f, phase, "before", oldPack, Pass)
	}
	// 7 is armed here, before the rotation: r1's file as it is in the
	// field, with a mirror set in it.
	fc, heldPack, armed := rc.armNoNewFile(phase, "l2")
	oldSNI := rc.Rec.CoverSNI
	rowsBefore := rc.userRows()
	realityBefore := rc.realityState()

	t0 := time.Now()
	v := rc.Pub.RotateTLS(rc.Ctx)
	var ans map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &ans)
	if !rc.R.Add("", phase, "verb.rotate-tls", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"rc": v.RC, "answer": ans}, t0) {
		rc.MgmtWindowClosed(phase)
		return
	}
	rc.MgmtWindowClosed(phase)

	// 3. record ↔ box agreement.
	t0 = time.Now()
	rec, err := rc.Pub.Record()
	if err != nil {
		rc.R.Add("", phase, "record.cover_host_moved", Pass, Fail, err.Error(), nil, t0)
		return
	}
	newSNI := rec.CoverSNI
	applied, _ := ans["applied_sni"].(string)
	rc.R.Add("", phase, "record.cover_host_moved", Pass, got(newSNI != "" && newSNI != oldSNI && applied == newSNI, Pass, Fail),
		fmt.Sprintf("record cover_sni %q → %q; the relay says it applied %q", oldSNI, newSNI, applied),
		map[string]any{"previous": oldSNI, "now": newSNI, "applied_sni": applied, "applied_handshake": ans["applied_handshake"]}, t0)
	rc.Rec = rec

	after := rc.realityState()
	var problems []string
	if after.ServerName != newSNI {
		problems = append(problems, fmt.Sprintf("vless-in tls.server_name is %q, the record says %q", after.ServerName, newSNI))
	}
	if after.HandshakeServer != newSNI {
		problems = append(problems, fmt.Sprintf("vless-in reality.handshake.server is %q, the record says %q", after.HandshakeServer, newSNI))
	}
	if strings.Contains(rc.BoxSingboxConfig(), `"`+oldSNI+`"`) {
		problems = append(problems, "the old cover host "+oldSNI+" is still somewhere in the live sing-box config")
	}
	if onDisk, _ := rc.BoxFile("daal/cover-sni"); strings.TrimSpace(onDisk) != "" && strings.TrimSpace(onDisk) != newSNI {
		problems = append(problems, fmt.Sprintf("/etc/daal/cover-sni on the box says %q", strings.TrimSpace(onDisk)))
	}
	rc.R.Add("", phase, "box.cover_host_agrees_with_record", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"server_name": after.ServerName, "handshake_server": after.HandshakeServer}, t0)

	problems = nil
	if after.PrivateKey != realityBefore.PrivateKey || after.PrivateKey == "" {
		problems = append(problems, "the REALITY private key changed")
	}
	rowsAfter := rc.userRows()
	if len(rowsAfter) != len(rowsBefore) {
		problems = append(problems, fmt.Sprintf("user rows: %d before, %d after", len(rowsBefore), len(rowsAfter)))
	}
	for k, row := range rowsBefore {
		if rowsAfter[k] != row {
			problems = append(problems, k+": user row changed")
		}
	}
	rc.R.Add("", phase, "box.no_key_no_credential_moved", Pass, got(len(problems) == 0, Pass, Fail), strings.Join(problems, "; "),
		map[string]any{"user_rows_compared": len(rowsBefore)}, t0)

	// 4. what the rotation did to files already in people's hands.
	for _, f := range fams {
		expect := l2OldPackExpect[f.Name]
		if expect == "" {
			expect = Pass
		}
		rc.sub(f, phase, "old-pack", oldPack, expect)
	}

	// 7. no new file. L2 touched no credential, so the signed endpoint
	// is all a phone is missing — and that is public.
	if armed {
		fc.noNewFile("l2", "cover-host-moved", fams, heldPack)
	}

	// 5. the app's Rebuild, against the rewritten record. The base pack
	// is re-signed first: its signed endpoints name the cover host.
	if !rc.Resign(phase) {
		return
	}
	newPack, ok := rc.Rebuild(name, phase, "base.sbp", "after-l2")
	rc.MgmtWindowClosed(phase)
	if !ok {
		return
	}
	t0 = time.Now()
	creds, _ := rc.Pub.ReadCreds("creds-" + name + ".json")
	rc.R.Add("", phase, "rebuild.names_new_cover_host", Pass, got(creds.Str("cover_sni") == newSNI, Pass, Fail),
		fmt.Sprintf("the relay's credential answer names cover host %q; the record says %q", creds.Str("cover_sni"), newSNI), nil, t0)
	for _, f := range fams {
		rc.sub(f, phase, "rebuilt", newPack, Pass)
	}

	// r1's file from before the rotation names the old cover host.
	// Re-issue it so the ops that follow start from a relay whose first
	// recipient can connect without a poll.
	if p1, ok := rc.Rebuild("r1", phase, "base.sbp", "after-l2"); ok {
		rc.Pack = p1
	}
	rc.MgmtWindowClosed(phase)
}

type realityState struct {
	ServerName, HandshakeServer, PrivateKey string
}

// realityState reads the cover identity off the relay's live vless-in.
func (rc *RunCtx) realityState() realityState {
	var doc struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			TLS struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					PrivateKey string `json:"private_key"`
					Handshake  struct {
						Server string `json:"server"`
					} `json:"handshake"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	_ = json.Unmarshal([]byte(rc.BoxSingboxConfig()), &doc)
	for _, in := range doc.Inbounds {
		if in.Tag == "vless-in" {
			return realityState{in.TLS.ServerName, in.TLS.Reality.Handshake.Server, in.TLS.Reality.PrivateKey}
		}
	}
	return realityState{}
}
