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
// must be refused at import. Every alteration is a plain zip rewrite with
// no key material, manifest.sig copied through untouched:
//
//  1. CONTROL — the signed part. manifest.json's bundle expiry is pushed
//     a thousand years out. This must be refused, and refused by the
//     importer's own verdict (not by the client dying of something else).
//     It is what proves the signature is being checked at all.
//  2. the one an on-path adversary wants: every route's `server` in
//     profiles/ is rewritten to an address of the attacker's choosing.
//     Refused, with the reason the product gives a pack whose outbound
//     no longer matches the endpoint its publisher signed.
//  3. the same for everything else that says WHERE a route points or
//     WHAT proves the relay is the relay, one field at a time: the port,
//     the TLS key pin, the REALITY public key, the trusted certificate
//     (naive), the shadowsocks server key. Each must be refused.
//  4. the commitment itself stripped out of the signed manifest (so that
//     nothing is left to disagree with): refused as a signature failure.
//  5. a CREDENTIAL rewritten — which nothing signs, by design: the pack
//     imports, and the session reaches the genuine relay and carries
//     nothing. A forged credential can only fail to connect.
//
// (2)'s evidence carries the outcome of (1): a profile rewrite refused
// while the manifest control is NOT refused would mean the reason is
// something else.
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

	// --- 2. every profile's server is rewritten.
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
		got(outcome == Refused && ev["reason_code"] == endpointMismatch, "", got(outcome == Pass,
			"the engine imported a pack whose outbound servers were rewritten without the publisher key, under the publisher's own fingerprint",
			"the pack was not refused as an endpoint mismatch: "+detail)),
		ev, t0)

	// --- 2b. the same file in the hands of somebody who taps Connect.
	// The import check above runs the engine in import-only mode, where
	// nothing could dial whatever the importer decided. Here the phone
	// is an ordinary one, told to connect: the refusal must come at
	// import, with no route listed, the engine never started and no
	// connection check begun — nothing that could be filed as an
	// attempt on the route, and no packet towards the rewritten address.
	tamperConnect(rc, phase, tampered)

	// --- 3. one field at a time.
	tamperEndpointFields(rc, phase, src)

	// --- 4. the commitment stripped from the signed manifest.
	t0 = time.Now()
	stripped := 0
	strippedPack, err := rewritePack(src, func(name string, body []byte) []byte {
		if name != "manifest.json" {
			return body
		}
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return body
		}
		routes, _ := m["routes"].([]any)
		for _, r := range routes {
			rm, _ := r.(map[string]any)
			fsc, _ := rm["family_specific_config"].(map[string]any)
			if _, ok := fsc["_endpoint"]; ok {
				delete(fsc, "_endpoint")
				stripped++
			}
		}
		if out, err := json.Marshal(m); err == nil {
			return out
		}
		return body
	})
	if err != nil || stripped == 0 {
		rc.R.Add("", phase, "commitment_stripped.import", Refused, Fail,
			fmt.Sprintf("could not strip the endpoint commitments (stripped=%d, err=%v): the signed manifest carries none?", stripped, err), nil, t0)
	} else if p, werr := writeTampered(rc, "pack-commitment-stripped.sbp", strippedPack); werr != nil {
		rc.R.Add("", phase, "commitment_stripped.import", Refused, Fail, werr.Error(), nil, t0)
	} else {
		o, ev, d := importOutcome(rc, "commitment-stripped", p)
		ev["commitments_stripped"] = stripped
		rc.R.Add("", phase, "commitment_stripped.import", Refused, o,
			got(o == Refused, "", "a pack whose signed endpoint commitments were removed was not rejected: "+d), ev, t0)
	}

	// --- 5. a credential is NOT signed, and does not need to be.
	tamperCredential(rc, phase, src)

	// --- 6. everything else taken on trust: a stranger's signature, an
	// expired pack, an impostor mgmt endpoint (ops_tamper_trust.go).
	tamperTrust(rc, phase, src)

	// --- 7. a bundle with no signed endpoints must not replace routes
	// that have them (ops_tamper_downgrade.go).
	tamperDowngrade(rc, phase, src)
}

// endpointMismatch is the importer's reason for a pack whose outbound
// disagrees with its signed endpoint (bundle/go/importer).
const endpointMismatch = "endpoint_mismatch"

func writeTampered(rc *RunCtx, name string, body []byte) (string, error) {
	p := rc.Pub.Path(name)
	return p, os.WriteFile(p, body, 0o644)
}

// endpointRewrite is one way to change where a route points or what
// authenticates the relay. apply returns false when the profile has no
// such field (the rewrite does not apply to that family).
type endpointRewrite struct {
	name  string
	what  string
	apply func(prof map[string]any) bool
}

func tlsOf(prof map[string]any) map[string]any {
	t, _ := prof["tls"].(map[string]any)
	return t
}

var endpointRewrites = []endpointRewrite{
	{"port", "server_port → 4443", func(p map[string]any) bool {
		if _, ok := p["server_port"]; !ok {
			return false
		}
		p["server_port"] = 4443
		return true
	}},
	{"tls_pin", "tls.certificate_public_key_sha256 → another key", func(p map[string]any) bool {
		t := tlsOf(p)
		if _, ok := t["certificate_public_key_sha256"]; !ok {
			return false
		}
		t["certificate_public_key_sha256"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		return true
	}},
	{"reality_public_key", "tls.reality.public_key → another key", func(p map[string]any) bool {
		r, _ := tlsOf(p)["reality"].(map[string]any)
		s, _ := r["public_key"].(string)
		if s == "" {
			return false
		}
		r["public_key"] = flipChars(s, 0, 8)
		return true
	}},
	{"trusted_certificate", "tls.certificate → a certificate with a key the relay does not hold", func(p map[string]any) bool {
		t := tlsOf(p)
		list, _ := t["certificate"].([]any)
		if len(list) == 0 {
			return false
		}
		orig, _ := list[0].(string)
		other, err := otherCertPEM(orig)
		if err != nil {
			return false
		}
		t["certificate"] = []any{other}
		return true
	}},
	{"tls_insecure", "tls.insecure → true", func(p map[string]any) bool {
		t := tlsOf(p)
		if t == nil {
			return false
		}
		t["insecure"] = true
		return true
	}},
	// The signed server stays exactly where it was. A second member is
	// added whose name sing-box reads as `server` too (U+017F, long s,
	// case-folds to s) and which comes later, so it is the one that
	// would be dialled. Every equality the endpoint check tests still
	// holds; only the rule about member NAMES refuses it.
	{"folded_key", "a second spelling of `server` (\"\u017ferver\") → 198.51.100.66, the signed one left in place", func(p map[string]any) bool {
		if s, _ := p["server"].(string); s == "" {
			return false
		}
		p["\u017ferver"] = "198.51.100.66"
		return true
	}},
	{"shadowsocks_server_key", "the box-wide half of the shadowsocks key → another key", func(p map[string]any) bool {
		if t, _ := p["type"].(string); t != "shadowsocks" {
			return false
		}
		s, _ := p["password"].(string)
		i := strings.Index(s, ":")
		if i <= 0 {
			return false
		}
		p["password"] = flipChars(s[:i], 0, 8) + s[i:]
		return true
	}},
}

// tamperEndpointFields rewrites ONE endpoint field in every profile that
// has it, per rewrite, and requires each resulting pack to be refused as
// an endpoint mismatch. A rewrite that applies to no profile of this
// pack is reported skipped, by name, so the row can never read as
// coverage it does not have.
func tamperEndpointFields(rc *RunCtx, phase string, src []byte) {
	for _, rw := range endpointRewrites {
		t0 := time.Now()
		check := "import_of_tampered_pack." + rw.name
		touched := []string{}
		out, err := rewritePack(src, func(name string, body []byte) []byte {
			if !strings.HasPrefix(name, "profiles/") {
				return body
			}
			var prof map[string]any
			if json.Unmarshal(body, &prof) != nil || !rw.apply(prof) {
				return body
			}
			touched = append(touched, name)
			nb, _ := json.Marshal(prof)
			return nb
		})
		if err != nil {
			rc.R.Add("", phase, check, Refused, Fail, err.Error(), nil, t0)
			continue
		}
		if len(touched) == 0 {
			rc.R.Add("", phase, check, Skipped, Skipped,
				"no route in this pack has that field (it belongs to a family not under test)", map[string]any{"rewrite": rw.what}, t0)
			continue
		}
		p, err := writeTampered(rc, "pack-tampered-"+rw.name+".sbp", out)
		if err != nil {
			rc.R.Add("", phase, check, Refused, Fail, err.Error(), nil, t0)
			continue
		}
		o, ev, d := importOutcome(rc, "tampered-"+rw.name, p)
		ev["rewritten"], ev["profiles"], ev["keys_used"] = rw.what, touched, "none"
		rc.R.Add("", phase, check, Refused, o,
			got(o == Refused && ev["reason_code"] == endpointMismatch, "", got(o == Pass,
				"the engine imported a pack in which "+rw.what+" was rewritten without the publisher key",
				"the pack was not refused as an endpoint mismatch: "+d)), ev, t0)
	}
}

// tamperCredential is the other half of the argument for leaving
// credentials unsigned. One recipient credential is rewritten in the
// pack — no key needed, and nothing detects it at import, by design.
// The pack must then (a) import, and (b) carry nothing: the session goes
// to the GENUINE relay (the wire tap sees the family's port on the
// relay's address and nothing else) and is refused there.
func tamperCredential(rc *RunCtx, phase string, src []byte) {
	var fam Family
	found := false
	for _, f := range rc.activeFamilies() {
		if scn, _ := rc.Scn.ExpectFor(f.Name); scn != Blocked {
			fam, found = f, true
			break
		}
	}
	t0 := time.Now()
	if !found {
		rc.R.Add("", phase, "credential_rewrite", Skipped, Skipped, "no family under test is reachable under this scenario", nil, t0)
		return
	}
	v, err := ReadPack(rc.Pack)
	if err != nil {
		rc.R.Add("", phase, "credential_rewrite.import", Pass, Fail, err.Error(), nil, t0)
		return
	}
	var target string
	for _, r := range v.Routes {
		if r.Family == fam.Name {
			target = "profiles/" + r.ID + ".json"
		}
	}
	field := ""
	out, err := rewritePack(src, func(name string, body []byte) []byte {
		if name != target {
			return body
		}
		var prof map[string]any
		if json.Unmarshal(body, &prof) != nil {
			return body
		}
		for _, k := range []string{"uuid", "password"} {
			s, _ := prof[k].(string)
			if s == "" {
				continue
			}
			switch {
			case k == "uuid":
				prof[k] = uuidTail.ReplaceAllString(s, "000000000bad")
			case strings.Contains(s, ":"): // shadowsocks: only the recipient half is a credential
				i := strings.LastIndex(s, ":")
				prof[k] = s[:i+1] + flipChars(s[i+1:], 0, 8)
			default:
				prof[k] = flipChars(s, len(s)-4, len(s))
			}
			field = k
			break
		}
		nb, _ := json.Marshal(prof)
		return nb
	})
	if err != nil || field == "" {
		rc.R.Add("", phase, "credential_rewrite.import", Pass, Fail, fmt.Sprintf("could not rewrite a credential in %s (err=%v)", target, err), nil, t0)
		return
	}
	p, err := writeTampered(rc, "pack-tampered-credential.sbp", out)
	if err != nil {
		rc.R.Add("", phase, "credential_rewrite.import", Pass, Fail, err.Error(), nil, t0)
		return
	}
	o, ev, d := importOutcome(rc, "tampered-credential", p)
	ev["rewritten"], ev["family"] = target+": "+field, fam.Name
	if !rc.R.Add(fam.Name, phase, "credential_rewrite.import", Pass, o, got(o == Pass, "",
		"a pack with one rewritten credential did not import — credentials are not signed, so this is either a new check or an accident: "+d), ev, t0) {
		return
	}
	// The session: must reach the genuine relay's endpoint for this
	// family and carry nothing.
	gotOut, detail, w, _ := rc.attempt(fam, phase, "credential_rewrite", "tampered-credential-session", p, 4*time.Second, true)
	sev := map[string]any{"field": field}
	reached := w != nil && w[fam.Name+".in"].Packets > 0
	if w != nil {
		sev["wire"] = w.Evidence()
	}
	rc.R.Add(fam.Name, phase, "credential_rewrite.carries_nothing", Blocked, gotOut, got(gotOut == Blocked, "",
		"a pack with a rewritten credential carried traffic: "+oneLine(detail, 200)), sev, t0)
	rc.R.Add(fam.Name, phase, "credential_rewrite.went_to_the_genuine_relay", Pass, got(reached, Pass, Fail),
		got(reached, "", "the session with the rewritten credential never reached the relay's "+fam.Name+" endpoint, so its failure proves nothing about where the credential went"), sev, t0)
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
		ev["reason"], ev["reason_code"] = reason(imp), verdictReason(imp)
		return Refused, ev, reason(imp)
	case verdictKind(trust) == "rejected":
		ev["reason"], ev["reason_code"] = reason(trust), verdictReason(trust)
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

// verdictReason is the importer's own reason code for a rejection.
func verdictReason(ev map[string]any) string {
	if ev == nil {
		return ""
	}
	if s, _ := ev["reason"].(string); s != "" {
		return s
	}
	if v, ok := ev["verdict"].(map[string]any); ok {
		s, _ := v["Reason"].(string)
		return s
	}
	return ""
}

// tamperConnect hands a tampered pack to a phone that is asked to
// connect, and says where the session stopped.
//
//	refused  at import: no route listed, no engine event, never connected
//	pass     it connected (the tampered pack was used)
//	blocked  it got as far as starting a route and failed there — the
//	         pack was NOT refused before a connection attempt
func tamperConnect(rc *RunCtx, phase, pack string) {
	fam := ""
	for _, name := range rc.Want {
		if f, ok := rc.Fams[name]; ok && f.Skip == "" {
			fam = name
			break
		}
	}
	if fam == "" {
		return
	}
	t0 := time.Now()
	c, err := StartClient(rc.P, "tampered-connect", ClientOpts{Pack: pack, Family: fam})
	if err != nil {
		rc.R.Add("", phase, "tampered_pack.connect", Refused, Fail, err.Error(), nil, t0)
		return
	}
	last, werr := c.Wait(rc.Ctx, 20*time.Second, "connected")
	c.Stop()
	stage, _ := last["stage"].(string)
	ev := map[string]any{"family": fam, "stopped_at": stage, "import": verdictKind(c.Event("import")),
		"routes_listed": c.Event("routes") != nil, "engine_started": c.Event("engine") != nil, "client_dir": c.Dir}
	outcome, detail := Fail, ""
	switch {
	case werr == nil:
		outcome, detail = Pass, "a phone connected on "+fam+" with a pack whose outbound servers were rewritten without the publisher key"
	case stage == "import" && c.Event("routes") == nil && c.Event("engine") == nil:
		outcome = Refused
	case stage == "set_route" || stage == StageProof:
		outcome, detail = Blocked, "the tampered pack was imported and only stopped at "+stage+": "+werr.Error()
	default:
		detail = "the session neither connected nor was refused at import: " + werr.Error()
	}
	rc.R.Add("", phase, "tampered_pack.connect", Refused, outcome, detail, ev, t0)
}
