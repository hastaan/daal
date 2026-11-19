package main

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

func init() { Ops["l2"] = opL2 }

// l2Bystander is a recipient provisioned before the rotation whom
// nobody re-provisions afterwards.
const l2Bystander = "r32"

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
//  8. the relay re-issued its TLS certificate for the new cover host:
//     the SAME key (no pin moves), the new cover host as the first DNS
//     name, every name it had before still in it. That is what lets
//     naive present the CURRENT cover host after a later address move
//     (op l3 asserts it when it runs after this op), and why step 4's
//     naive file keeps working.
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
	// And one more file from before the rotation, for a recipient this
	// op never rebuilds (it rebuilds r31 and r1 at the end): the phone
	// that is handed nothing through this rotation AND whatever follows
	// it (op l3, after-l2).
	bystander := ""
	if armed && rc.provisionRecipient(l2Bystander, phase) {
		t0 := time.Now()
		out := "pack-" + l2Bystander + "-l2-before.sbp"
		pv := rc.Pub.PackSBP(rc.Ctx, "base-l2-before.sbp", "creds-"+l2Bystander+".json", out)
		if rc.R.Add("", phase, "verb.users-pack-sbp."+l2Bystander, Pass, got(pv.OK() && !strings.Contains(pv.Stderr, "NOT connectable"), Pass, Fail), pv.Tail(), nil, t0) {
			bystander = rc.Pub.Path(out)
		}
	}
	oldSNI := rc.Rec.CoverSNI
	rowsBefore := rc.userRows()
	realityBefore := rc.realityState()
	certBefore := rc.boxCert()

	t0 := time.Now()
	v := rc.Pub.RotateTLS(rc.Ctx)
	var ans map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &ans)
	if !rc.R.Add("", phase, "verb.rotate-tls", Pass, got(v.OK(), Pass, Fail), v.Tail(), map[string]any{"rc": v.RC, "answer": ans}, t0) {
		rc.MgmtWindowClosed(phase)
		return
	}
	rc.MgmtWindowClosed(phase)

	// The verb must not tell the operator that everyone needs a new
	// file. The old-pack sessions below measure what is true — only the
	// route that carries the cover host stops — and for a long time the
	// verb's standing warning said the opposite (FINDINGS LC-O1).
	t0 = time.Now()
	said := strings.ToLower(v.Stdout + "\n" + v.Stderr)
	claims := strings.Contains(said, "every recipient needs") || strings.Contains(said, "everyone needs")
	next, _ := ans["next_step"].(string)
	rc.R.Add("", phase, "rotate-tls.does_not_claim_everyone_needs_a_file", Pass,
		got(!claims && strings.Contains(next, "vless-reality"), Pass, Fail),
		got(!claims, "", "the verb still says every recipient needs a new file: ")+oneLine(v.Tail(), 300),
		map[string]any{"warnings": ans["warnings"], "next_step": next}, t0)

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

	// 8. the certificate followed the cover host, on the same key.
	t0 = time.Now()
	certAfter := rc.boxCert()
	problems = nil
	switch {
	case certBefore.Err != "" || certAfter.Err != "":
		problems = append(problems, "could not read the relay's certificate: "+certBefore.Err+" "+certAfter.Err)
	default:
		if certAfter.SPKI != certBefore.SPKI {
			problems = append(problems, "the certificate's KEY changed: every pinned pack in the field is dead")
		}
		if len(certAfter.DNS) == 0 || certAfter.DNS[0] != newSNI {
			problems = append(problems, fmt.Sprintf("the certificate's first DNS name is %v, the cover host is now %q", certAfter.DNS, newSNI))
		}
		for _, n := range certBefore.DNS {
			if !contains(certAfter.DNS, n) {
				problems = append(problems, "the certificate dropped "+n+", which files already handed out verify against")
			}
		}
		for _, ip := range certBefore.IPs {
			if !contains(certAfter.IPs, ip) {
				problems = append(problems, "the certificate dropped the address "+ip)
			}
		}
		if spki, _ := rc.BoxFile("daal/tls-spki-sha256.b64"); strings.TrimSpace(spki) != "" && strings.TrimSpace(spki) != certAfter.SPKI {
			problems = append(problems, "/etc/daal/tls-spki-sha256.b64 no longer matches the certificate")
		}
	}
	// A relay whose mgmt daemon predates the re-issue keeps its
	// certificate; said by the daemon itself, in the verb's answer.
	reissued := false
	if ch, _ := ans["changed"].([]any); ch != nil {
		for _, c := range ch {
			reissued = reissued || c == "tls_certificate"
		}
	}
	rc.R.Add("", phase, "box.certificate_follows_cover_host", Pass, got(len(problems) == 0 && reissued, Pass, Fail),
		got(reissued, strings.Join(problems, "; "), "rotate-tls did not report a re-issued certificate (\"tls_certificate\" is not in changed): "+strings.Join(problems, "; ")),
		map[string]any{"dns_before": certBefore.DNS, "dns_after": certAfter.DNS, "ips_after": certAfter.IPs, "same_key": certAfter.SPKI == certBefore.SPKI}, t0)
	rc.PreL2.Pack, rc.PreL2.CoverSNI = bystander, oldSNI

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

// boxCertInfo is what the relay's data-plane certificate says.
type boxCertInfo struct {
	SPKI string // base64 SHA-256 of the SubjectPublicKeyInfo: the pin
	DNS  []string
	IPs  []string
	Err  string
}

// boxCert reads /etc/daal/tls-cert.pem off the box.
func (rc *RunCtx) boxCert() boxCertInfo {
	raw, err := rc.BoxFile("daal/tls-cert.pem")
	if err != nil {
		return boxCertInfo{Err: err.Error()}
	}
	return parseCertInfo(raw)
}

func parseCertInfo(pemText string) boxCertInfo {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return boxCertInfo{Err: "no certificate"}
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return boxCertInfo{Err: err.Error()}
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	out := boxCertInfo{SPKI: base64.StdEncoding.EncodeToString(sum[:]), DNS: c.DNSNames}
	for _, ip := range c.IPAddresses {
		out.IPs = append(out.IPs, ip.String())
	}
	return out
}

// packNaive reads the naive outbound out of a pack file: the TLS name
// it verifies (and presents), and the certificate it trusts.
func packNaive(path string) (serverName string, cert boxCertInfo, err error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", boxCertInfo{}, err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "profiles/") {
			continue
		}
		r, err := f.Open()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(r)
		r.Close()
		var ob struct {
			Type string `json:"type"`
			TLS  struct {
				ServerName  string `json:"server_name"`
				Certificate any    `json:"certificate"`
			} `json:"tls"`
		}
		if json.Unmarshal(raw, &ob) != nil || ob.Type != "naive" {
			continue
		}
		pemText := ""
		switch c := ob.TLS.Certificate.(type) {
		case string:
			pemText = c
		case []any:
			if len(c) > 0 {
				pemText, _ = c[0].(string)
			}
		}
		return ob.TLS.ServerName, parseCertInfo(pemText), nil
	}
	return "", boxCertInfo{}, fmt.Errorf("no naive outbound in %s", filepath.Base(path))
}
