package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// tamperTrust is the rest of op:tamper (ops_tamper.go): the negative
// controls for the three things an insider or a publisher takes on trust
// and every other phase only ever sees succeed.
//
//	the pack's signature
//	  control.repacked.import     the rig's zip rewrite, changing nothing,
//	                              still imports — otherwise every "refused"
//	                              here could be a malformed archive
//	  control.rig-signs-as-the-product-does
//	                              signing the manifest with the PUBLISHER's
//	                              key through the product's canonicalisation
//	                              reproduces manifest.sig byte for byte
//	                              (Ed25519 is deterministic) — so the forged
//	                              signature below differs from a valid one
//	                              in the key and in nothing else
//	  stranger-signature.import   the untouched manifest, validly signed by
//	                              a key the publisher never held;
//	                              publisher.pub kept
//	  stranger-key.import         the same with publisher.pub replaced too:
//	                              the signature now verifies, and what must
//	                              stop it is the manifest naming the real
//	                              publisher's fingerprint
//	(one altered byte under the ORIGINAL signature is ops_tamper.go's
//	manifest_rewrite_refused)
//
//	the pack's expiry
//	  expired.import              a pack the REAL verbs minted 40 days ago
//	                              with a 30-day window, under the
//	                              publisher's own signature
//	  control.aged.import         minted the same way 20 days ago: imports
//
//	the mgmt TLS pin (what daal-deploy must refuse to talk to)
//	  mgmt-pin.*                  one hex digit of mgmt_tls_fingerprint
//	                              flipped in a COPY of the operator record:
//	                              to the verbs the real box is an impostor
//
// A refusal counts only when it is the refusal the row is about: each row
// names the reason the product must give (bundle/go/importer's
// Verdict.Reason, or the mgmt client's error), so a pack that is turned
// away for some other cause is red as well. None of these rows is listed
// in known-findings.json, and none may be: F-004 is about profiles only.
func tamperTrust(rc *RunCtx, phase string, src []byte) {
	trustSignature(rc, phase, src)
	trustExpiry(rc, phase)
	trustMgmtPin(rc, phase)
}

// replaceEntries copies a pack entry by entry, substituting the bodies
// named in repl.
func replaceEntries(src []byte, repl map[string][]byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, err
		}
		if b, ok := repl[f.Name]; ok {
			body = b
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method, Modified: f.Modified})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// trustImport hands a pack to a fresh engine — a phone that has never
// seen this publisher — and reports what the IMPORTER decided: Pass
// (taken, routes listed), Refused (its verdict was "rejected"; reason is
// the verdict's own), or Fail (anything else: a client that could not
// start, died or timed out is not a refusal).
func trustImport(rc *RunCtx, label, pack string) (outcome, reason string, ev map[string]any) {
	c, err := StartClient(rc.P, label, ClientOpts{Pack: pack, ImportOnly: true})
	if err != nil {
		return Fail, "", map[string]any{"client": err.Error()}
	}
	_, werr := c.Wait(rc.Ctx, 15*time.Second, "routes")
	c.Stop()
	imp, trust := c.Event("import"), c.Event("trust")
	ev = map[string]any{"import": verdictKind(imp), "trust": verdictKind(trust)}
	if werr == nil {
		return Pass, "", ev
	}
	ev["client"] = oneLine(werr.Error(), 200)
	for _, e := range []map[string]any{imp, trust} {
		if verdictKind(e) == "rejected" {
			reason, _ = e["reason"].(string)
			ev["reason"] = reason
			return Refused, reason, ev
		}
	}
	return Fail, "", ev
}

// mustRefuse: the pack must be refused at import, and for wantReason.
func mustRefuse(rc *RunCtx, phase, check, label, pack, wantReason, ifAccepted string, extra map[string]any, t0 time.Time) {
	outcome, reason, ev := trustImport(rc, label, pack)
	for k, v := range extra {
		ev[k] = v
	}
	ev["want_reason"] = wantReason
	detail := ""
	switch {
	case outcome == Pass:
		detail = ifAccepted
	case outcome == Fail:
		detail = fmt.Sprintf("the import neither succeeded nor was rejected by the importer: %v", ev["client"])
	case reason != wantReason:
		outcome = Fail
		detail = fmt.Sprintf("the pack was turned away, but as %q, not %q: this row no longer exercises the check it is named for", reason, wantReason)
	}
	rc.R.Add("", phase, check, Refused, outcome, detail, ev, t0)
}

// mustImport is the positive control of the rows around it.
func mustImport(rc *RunCtx, phase, check, label, pack string, extra map[string]any, t0 time.Time) bool {
	outcome, _, ev := trustImport(rc, label, pack)
	for k, v := range extra {
		ev[k] = v
	}
	return rc.R.Add("", phase, check, Pass, outcome,
		got(outcome == Pass, "", "a pack that differs from a good one in nothing the engine should mind was not imported — the refusals beside this row prove nothing until it is green"), ev, t0)
}

// ---- the signature ------------------------------------------------------

func trustSignature(rc *RunCtx, phase string, src []byte) {
	const sigReason = "bundle_signature_invalid"
	write := func(name string, repl map[string][]byte) (string, error) {
		out, err := replaceEntries(src, repl)
		if err != nil {
			return "", err
		}
		p := rc.Pub.Path(name)
		return p, os.WriteFile(p, out, 0o644)
	}

	t0 := time.Now()
	same, err := write("pack-repacked.sbp", nil)
	if err != nil {
		rc.R.Add("", phase, "control.repacked.import", Pass, Fail, err.Error(), nil, t0)
		return
	}
	if !mustImport(rc, phase, "control.repacked.import", "repacked", same, map[string]any{"changed": "nothing"}, t0) {
		return
	}

	t0 = time.Now()
	const signs = "control.rig-signs-as-the-product-does"
	b, err := bundle.ParseSBP(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		rc.R.Add("", phase, signs, Pass, Fail, "the rig could not parse the pack: "+err.Error(), nil, t0)
		return
	}
	privRaw, _ := os.ReadFile(rc.Pub.Path("publisher.priv"))
	if len(privRaw) != ed25519.PrivateKeySize {
		rc.R.Add("", phase, signs, Pass, Fail, "publisher.priv is not an Ed25519 private key", nil, t0)
		return
	}
	own, err := bundle.SignManifest(b.Manifest, ed25519.PrivateKey(privRaw))
	if !rc.R.Add("", phase, signs, Pass, got(err == nil && bytes.Equal(own, b.Signature), Pass, Fail),
		got(err != nil, errStr(err), got(bytes.Equal(own, b.Signature), "", "re-signing the manifest with the publisher's key did not reproduce manifest.sig")), nil, t0) {
		return
	}
	strangerPub, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, err := bundle.SignManifest(b.Manifest, strangerPriv)
	if err != nil {
		rc.R.Add("", phase, "stranger-signature.import", Refused, Fail, err.Error(), nil, t0)
		return
	}

	t0 = time.Now()
	if p, err := write("pack-stranger-signature.sbp", map[string][]byte{"manifest.sig": forged}); err != nil {
		rc.R.Add("", phase, "stranger-signature.import", Refused, Fail, err.Error(), nil, t0)
	} else {
		mustRefuse(rc, phase, "stranger-signature.import", "stranger-signature", p, sigReason,
			"the engine imported a pack signed by a key that is not the publisher's, under the publisher's fingerprint: manifest.sig is not being checked against publisher.pub",
			map[string]any{"manifest": "untouched", "publisher.pub": "untouched", "signed_by": "a key generated for this check"}, t0)
	}

	t0 = time.Now()
	if p, err := write("pack-stranger-key.sbp", map[string][]byte{"manifest.sig": forged, "publisher.pub": strangerPub}); err != nil {
		rc.R.Add("", phase, "stranger-key.import", Refused, Fail, err.Error(), nil, t0)
	} else {
		mustRefuse(rc, phase, "stranger-key.import", "stranger-key", p, "publisher_key_changed",
			"the engine imported a pack that names one publisher in its manifest and carries another's key and signature",
			map[string]any{"manifest": "untouched", "publisher.pub": "the stranger's", "signed_by": "the stranger"}, t0)
	}
}

// ---- expiry -------------------------------------------------------------

// trustExpiry: nothing is forged here. The publisher's own verbs mint the
// pack with their clock set back (bind-and-sign --now-unix, the flag for
// deterministic builds): a file that was good once and has been lying in
// a chat history for 40 days.
func trustExpiry(rc *RunCtx, phase string) {
	const window = 30
	mintAt := func(tag string, daysAgo int) (string, bool) {
		t0 := time.Now()
		base, out := "base-"+tag+".sbp", "pack-"+tag+".sbp"
		at := time.Now().Add(-time.Duration(daysAgo) * 24 * time.Hour).Unix()
		v := rc.Pub.Deploy(rc.Ctx, "bind-and-sign", "--operator-record", rc.Pub.Path("record.json"),
			"--priv-key", rc.Pub.Path("publisher.priv"), "--output", rc.Pub.Path(base),
			"--publisher-name", "Worldbox Publisher", "--now-unix", strconv.FormatInt(at, 10), "--expiry-days", strconv.Itoa(window))
		if v.OK() {
			v = rc.Pub.PackSBP(rc.Ctx, base, "creds-r1.json", out)
		}
		return rc.Pub.Path(out), rc.R.Add("", phase, "verb.mint-"+tag, Pass, got(v.OK(), Pass, Fail), v.Tail(),
			map[string]any{"minted_days_ago": daysAgo, "window_days": window}, t0)
	}
	// control: setting the clock back does not, by itself, spoil a pack.
	p, ok := mintAt("aged", 20)
	if !ok {
		return
	}
	if !mustImport(rc, phase, "control.aged.import", "aged", p, map[string]any{"minted_days_ago": 20, "window_days": window}, time.Now()) {
		return
	}
	if p, ok = mintAt("expired", 40); ok {
		mustRefuse(rc, phase, "expired.import", "expired", p, "route_expired",
			"the engine imported a pack whose validity window ended 10 days ago",
			map[string]any{"minted_days_ago": 40, "window_days": window, "signature": "the publisher's own"}, time.Now())
	}
}

// ---- the mgmt TLS pin ---------------------------------------------------

var recordPin = regexp.MustCompile(`"mgmt_tls_fingerprint"\s*:\s*"([0-9a-f]{64})"`)

// trustMgmtPin: the operator record pins the box's mgmt certificate by
// SHA-256. Instead of standing up a second box, the rig does the
// equivalent from the other side: a COPY of the record whose pin is one
// hex digit off. Through that record the genuine box presents "the wrong
// certificate", exactly as an impostor on its address would.
//
// One of the verbs aimed at it is a MUTATING one (users-provision), so
// that "nothing was sent" is observable on the box and not only in the
// verb's own words: the recipient must not exist afterwards.
func trustMgmtPin(rc *RunCtx, phase string) {
	const ghost = "r999"                        // the box only accepts r[0-9]{1,12}; no other op uses this one
	const mismatch = "TLS fingerprint mismatch" // publisher/deploy/mgmt.ErrFingerprintMismatch
	const hexDigits = "0123456789abcdef"
	t0 := time.Now()
	body, err := os.ReadFile(rc.Pub.Path("record.json"))
	m := recordPin.FindSubmatchIndex(body)
	if err != nil || m == nil {
		rc.R.Add("", phase, "mgmt-pin.record", Pass, Fail, "record.json carries no mgmt_tls_fingerprint to alter "+errStr(err), nil, t0)
		return
	}
	bad := append([]byte(nil), body...)
	bad[m[2]] = hexDigits[(strings.IndexByte(hexDigits, body[m[2]])+1)%16]
	wrong := rc.Pub.Path("record-wrong-pin.json")
	if err := os.WriteFile(wrong, bad, 0o600); err != nil {
		rc.R.Add("", phase, "mgmt-pin.record", Pass, Fail, err.Error(), nil, t0)
		return
	}
	verb := func(record string, args ...string) Verb {
		return rc.Pub.Deploy(rc.Ctx, append(args, "--record-file", record,
			"--priv-key", rc.Pub.Path("publisher.priv"), "--token-file", rc.Pub.Path("cloud.token"),
			"--helper-ip", PublisherIP)...)
	}
	refused := func(check string, v Verb, t0 time.Time) {
		outcome, detail := Refused, ""
		switch {
		case v.OK():
			outcome, detail = Pass, "daal-deploy completed a verb against a mgmt endpoint whose certificate does not match the pinned fingerprint: the pin is not enforced, and that endpoint was handed a signed publisher token"
		case !strings.Contains(v.Stderr, mismatch):
			outcome, detail = Fail, "the verb failed, but not with the fingerprint-mismatch error — this row no longer exercises the pin: "+v.Tail()
		}
		rc.R.Add("", phase, check, Refused, outcome, detail,
			map[string]any{"rc": v.RC, "pin_hex_digits_changed": 1, "stderr": oneLine(v.Tail(), 300)}, t0)
	}

	// control: with the true pin the same verb, at the same moment, works.
	good := verb(rc.Pub.Path("record.json"), "users-list")
	if !rc.R.Add("", phase, "mgmt-pin.control.true-pin.users-list", Pass, got(good.OK(), Pass, Fail), good.Tail(), nil, t0) {
		return
	}
	t0 = time.Now()
	refused("mgmt-pin.wrong-pin.users-list", verb(wrong, "users-list"), t0)
	t0 = time.Now()
	refused("mgmt-pin.wrong-pin.users-provision", verb(wrong, "users-provision", "--name", ghost), t0)

	// …and the box never heard of it.
	t0 = time.Now()
	after := verb(rc.Pub.Path("record.json"), "users-list")
	created := strings.Contains(after.Stdout, `"`+ghost+`"`) || strings.Contains(rc.BoxSingboxConfig(), `"`+ghost+`"`)
	detail := after.Tail()
	if after.OK() {
		detail = got(created, "recipient "+ghost+" exists on the relay: a request went to an endpoint that failed the pin", "")
	}
	rc.R.Add("", phase, "mgmt-pin.wrong-pin.nothing_reached_the_box", Pass, got(after.OK() && !created, Pass, Fail), detail,
		map[string]any{"users": strings.TrimSpace(after.Stdout)}, t0)
	rc.MgmtWindowClosed(phase)
}
