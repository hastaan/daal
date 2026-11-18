package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func init() { Ops["tamper"] = opTamper }

// opTamper: a pack altered by someone who does NOT hold the publisher key
// must be refused at import. Two alterations, each a plain zip rewrite
// with no key material, manifest.sig copied through untouched:
//
//  1. CONTROL — the signed part. manifest.json's bundle expiry is pushed
//     a thousand years out. This must be refused, and refused by the
//     importer's own verdict (not by the client dying of something else).
//     It is what proves the signature is being checked at all.
//  2. the one an on-path adversary wants: every route's `server` in
//     profiles/ is rewritten to an address of the attacker's choosing.
//     Expectation: refused. See FINDINGS.md F-004 for what is observed.
//
// The second check's evidence carries the outcome of the first. That is
// the signature known-findings.json pins F-004 to: "a profile rewrite is
// accepted WHILE a manifest rewrite is refused". If signature
// verification is ever lost, the control is an unexpected red and the
// profile check no longer matches F-004 either — it is not counted as
// the old finding.
func opTamper(rc *RunCtx) {
	const phase = "op:tamper"
	t0 := time.Now()
	src, err := os.ReadFile(rc.Pack)
	if err != nil {
		rc.R.Add("", phase, "rewrite", Pass, Fail, err.Error(), nil, t0)
		return
	}

	// --- 1. control: the manifest (signed) is altered.
	const was, now = `"expires_at":"2`, `"expires_at":"3`
	edits := 0
	manifestPack, err := rewritePack(src, func(name string, body []byte) []byte {
		if name == "manifest.json" && bytes.Contains(body, []byte(was)) {
			edits++
			return bytes.Replace(body, []byte(was), []byte(now), 1)
		}
		return body
	})
	control := Fail
	if err != nil || edits != 1 {
		rc.R.Add("", phase, "manifest_rewrite_refused", Refused, Fail, fmt.Sprintf("could not produce a manifest-tampered pack (edits=%d, err=%v)", edits, err), nil, t0)
	} else {
		path := rc.Pub.Path("pack-tampered-manifest.sbp")
		if err := os.WriteFile(path, manifestPack, 0o644); err != nil {
			rc.R.Add("", phase, "manifest_rewrite_refused", Refused, Fail, err.Error(), nil, t0)
		} else {
			var ev map[string]any
			var detail string
			control, ev, detail = importOutcome(rc, "tampered-manifest", path)
			ev["rewritten"] = "manifest.json: bundle.expires_at +1000 years"
			ev["keys_used"] = "none"
			rc.R.Add("", phase, "manifest_rewrite_refused", Refused, control,
				got(control == Refused, "", "a pack whose SIGNED manifest was altered without the publisher key was not rejected by the importer: "+detail), ev, t0)
		}
	}

	// --- 2. the profiles (unsigned, F-004) are altered.
	t0 = time.Now()
	const attacker = "198.51.100.66"
	rewritten := 0
	out, err := rewritePack(src, func(name string, body []byte) []byte {
		if strings.HasPrefix(name, "profiles/") {
			var prof map[string]any
			if json.Unmarshal(body, &prof) == nil {
				if _, ok := prof["server"]; ok {
					prof["server"] = attacker
					body, _ = json.Marshal(prof)
					rewritten++
				}
			}
		}
		return body
	})
	tampered := rc.Pub.Path("pack-tampered.sbp")
	if err == nil {
		err = os.WriteFile(tampered, out, 0o644)
	}
	if err != nil || rewritten == 0 {
		rc.R.Add("", phase, "rewrite", Pass, Fail, "could not produce a tampered pack", nil, t0)
		return
	}
	rc.R.Add("", phase, "rewrite", Pass, Pass, "", map[string]any{"profiles_rewritten": rewritten, "server_now": attacker, "keys_used": "none"}, t0)

	t0 = time.Now()
	outcome, ev, detail := importOutcome(rc, "tampered", tampered)
	ev["rewritten"] = "profiles"
	ev["manifest_rewrite"] = control // the control above: is the signature checked at all?
	rc.R.Add("", phase, "import_of_tampered_pack", Refused, outcome,
		got(outcome == Refused, "", got(outcome == Pass,
			"the engine imported a pack whose outbound servers were rewritten without the publisher key, under the publisher's own fingerprint (FINDINGS.md F-004)",
			"the import neither succeeded nor was rejected by the importer: "+detail)),
		ev, t0)

	// --- 3. everything else taken on trust: a stranger's signature, an
	// expired pack, an impostor mgmt endpoint (ops_tamper_trust.go).
	tamperTrust(rc, phase, src)
}

// rewritePack copies a .sbp entry by entry, passing each body through
// edit. No key is involved.
func rewritePack(src []byte, edit func(name string, body []byte) []byte) ([]byte, error) {
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
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method, Modified: f.Modified})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(edit(f.Name, body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// importOutcome imports a pack into a fresh engine and says what the
// IMPORTER decided:
//
//	pass     it was accepted and its routes are listed
//	refused  the importer's verdict was "rejected" (at import or at the
//	         trust step) — the product said no
//	fail     neither: the client could not start, died or timed out. That
//	         is not a refusal and is never reported as one.
func importOutcome(rc *RunCtx, label, pack string) (string, map[string]any, string) {
	c, err := StartClient(rc.P, label, ClientOpts{Pack: pack, ImportOnly: true})
	if err != nil {
		return Fail, map[string]any{}, err.Error()
	}
	_, werr := c.Wait(rc.Ctx, 15*time.Second, "routes")
	c.Stop()
	imp, trust := c.Event("import"), c.Event("trust")
	ev := map[string]any{"import": verdictKind(imp), "trust": verdictKind(trust), "fingerprint_words": fingerprintWords(imp)}
	reason := func(e map[string]any) string {
		if e == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(e["reason"]) + " " + fmt.Sprint(e["error"]))
	}
	switch {
	case werr == nil:
		return Pass, ev, "accepted; routes listed"
	case verdictKind(imp) == "rejected":
		ev["reason"] = reason(imp)
		return Refused, ev, reason(imp)
	case verdictKind(trust) == "rejected":
		ev["reason"] = reason(trust)
		return Refused, ev, reason(trust)
	}
	return Fail, ev, werr.Error()
}

func fingerprintWords(ev map[string]any) any {
	if ev == nil {
		return nil
	}
	if v, ok := ev["verdict"].(map[string]any); ok {
		return v["HexEN"]
	}
	return nil
}
