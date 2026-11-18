package main

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Everything the rig asserts PER FAMILY beyond the session itself:
//
//	pack.route      the minted pack carries exactly one connectable route
//	                for every family the relay serves (and says so in the
//	                manifest the client verifies)
//	not_served      a family the relay was NOT provisioned with is out of
//	                reach and absent from the pack — "default-off" is a
//	                claim too, and enabling a family proves nothing unless
//	                not enabling it leaves it off
//	wire            the session's bytes crossed the censor on THIS family's
//	                endpoint and the client opened nothing else (wire.go)
//	wrongcreds      each credential field that authenticates a recipient on
//	                this family, forged alone in an otherwise genuine pack,
//	                stops it
//	wrongserver     each field that identifies the RELAY to the client,
//	                forged alone, makes the client refuse the genuine relay
//
// The session (run.go) supplies tunnel / udp / dns and the direct-path
// controls.

// resolveNeeds turns a family whose run-time dependency is missing into a
// SKIPPED family with the reason, before anything is provisioned.
func resolveNeeds(p Paths, fams map[string]Family) {
	for name, f := range fams {
		if f.Skip != "" || f.Needs == "" {
			continue
		}
		switch f.Needs {
		case "cronet":
			if _, err := os.Stat(filepath.Join(p.Bin, "libcronet.so")); err != nil {
				why, _ := os.ReadFile(filepath.Join(p.Bin, "cronet.missing"))
				f.Skip = "client side not dialable here: the naive outbound is Cronet, loaded at run time, and " +
					strings.TrimSpace(string(why)) + ". The RELAY side is still asserted (provisioned, listening, both firewalls open)."
			}
		default:
			f.Skip = fmt.Sprintf("families/%s.json needs %q, which this rig does not know how to provide", name, f.Needs)
		}
		fams[name] = f
	}
}

// ---- the pack, as the insider's app will read it ----------------------

// PackView is what the rig reads out of a minted .sbp. It never verifies
// anything — the engine does that; this is for asserting what was minted.
type PackView struct {
	SpecVersion int
	Routes      []PackRoute
}

type PackRoute struct {
	ID          string
	Family      string
	Port        int    // manifest: family_specific_config.port
	Type        string // profile: sing-box outbound type ("" = not connectable)
	Server      string
	ServerPort  int
	Unavailable string // the minter's reason when it dropped the route
}

func ReadPack(path string) (PackView, error) {
	var v PackView
	zr, err := zip.OpenReader(path)
	if err != nil {
		return v, err
	}
	defer zr.Close()
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return v, err
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return v, err
		}
		files[f.Name] = body
	}
	var man struct {
		SpecVersion int `json:"spec_version"`
		Routes      []struct {
			ID     string `json:"id"`
			Family string `json:"transport_family"`
			Config string `json:"config_path"`
			FSC    struct {
				Port int `json:"port"`
			} `json:"family_specific_config"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		return v, fmt.Errorf("manifest.json: %w", err)
	}
	v.SpecVersion = man.SpecVersion
	for _, r := range man.Routes {
		pr := PackRoute{ID: r.ID, Family: r.Family, Port: r.FSC.Port}
		var prof struct {
			Type        string `json:"type"`
			Server      string `json:"server"`
			ServerPort  int    `json:"server_port"`
			Unavailable *struct {
				Reason string `json:"reason"`
			} `json:"_daal_unavailable"`
		}
		if body, ok := files[r.Config]; ok {
			_ = json.Unmarshal(body, &prof)
		}
		pr.Type, pr.Server, pr.ServerPort = prof.Type, prof.Server, prof.ServerPort
		if prof.Unavailable != nil {
			pr.Unavailable = prof.Unavailable.Reason
			if pr.Unavailable == "" {
				pr.Unavailable = "marked unavailable by the minter"
			}
		}
		v.Routes = append(v.Routes, pr)
	}
	return v, nil
}

// anytlsSpecVersion is the pack format version a pack naming anytls must
// declare (bundle.SpecVersionAnyTLS). Older clients reject the family
// outright, so the version is what tells them to refuse the pack cleanly.
const anytlsSpecVersion = 5

// packChecks asserts what the minted pack offers, family by family.
func (rc *RunCtx) packChecks(phase, pack string) {
	t0 := time.Now()
	v, err := ReadPack(pack)
	if err != nil {
		rc.R.Add("", phase, "pack.readable", Pass, Fail, err.Error(), nil, t0)
		return
	}
	byFam := map[string][]PackRoute{}
	for _, r := range v.Routes {
		byFam[r.Family] = append(byFam[r.Family], r)
	}
	for _, name := range rc.Serve {
		f := rc.Fams[name]
		rs := byFam[name]
		var problem string
		switch {
		case len(rs) == 0:
			problem = "the relay serves this family but the pack has no route for it"
		case len(rs) > 1:
			problem = fmt.Sprintf("%d routes for one family on one relay", len(rs))
		case rs[0].Unavailable != "":
			problem = "the minter dropped this route: " + rs[0].Unavailable
		case rs[0].Type == "":
			problem = "the route's profile has no outbound type: it cannot be dialled"
		case rs[0].Server != rc.Rec.PublicIP || rs[0].ServerPort != f.Endpoint.Port:
			problem = fmt.Sprintf("the profile dials %s:%d; the relay is %s and families/%s.json says port %d", rs[0].Server, rs[0].ServerPort, rc.Rec.PublicIP, name, f.Endpoint.Port)
		case rs[0].Port != f.Endpoint.Port:
			problem = fmt.Sprintf("the signed manifest says port %d, the profile dials %d", rs[0].Port, rs[0].ServerPort)
		}
		ev := map[string]any{}
		if len(rs) > 0 {
			ev = map[string]any{"route_id": rs[0].ID, "outbound_type": rs[0].Type, "server_port": rs[0].ServerPort}
		}
		rc.R.Add(name, phase, "pack.route", Pass, got(problem == "", Pass, Fail), problem, ev, t0)
	}
	// The format version follows the pack's CONTENT: anytls forces 5, and a
	// pack without anytls must not claim it (clients that predate 5 would
	// refuse a pack they could have used).
	want := "<" + strconv.Itoa(anytlsSpecVersion)
	okVer := v.SpecVersion >= 1 && v.SpecVersion < anytlsSpecVersion
	if len(byFam["anytls"]) > 0 {
		want, okVer = strconv.Itoa(anytlsSpecVersion), v.SpecVersion == anytlsSpecVersion
	}
	rc.R.Add("", phase, "pack.spec_version", Pass, got(okVer, Pass, Fail),
		got(okVer, "", fmt.Sprintf("spec_version=%d, want %s (anytls in pack: %v)", v.SpecVersion, want, len(byFam["anytls"]) > 0)),
		map[string]any{"spec_version": v.SpecVersion, "anytls_in_pack": len(byFam["anytls"]) > 0}, t0)

	// Families the relay was NOT provisioned with.
	listen, _ := sh(rc.Ctx, inNS(NSRelay1, "ss", "-Hltnu")...)
	ufw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_ufw")...)
	cfw, _ := sh(rc.Ctx, inNS(NSRelay1, "nft", "list", "table", "inet", "wb_cloudfw")...)
	var names []string
	for name := range rc.Fams {
		if !contains(rc.Serve, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		f := rc.Fams[name]
		boxOpen, cloudOpen := nftAllows(ufw, f.Endpoint.Proto, f.Endpoint.Port), nftAllows(cfw, f.Endpoint.Proto, f.Endpoint.Port)
		listening := socketBound(listen, f.Endpoint.Proto, f.Endpoint.Port)
		var problems []string
		if boxOpen || cloudOpen {
			problems = append(problems, fmt.Sprintf("a firewall admits %d/%s (box ufw=%v, cloud=%v)", f.Endpoint.Port, f.Endpoint.Proto, boxOpen, cloudOpen))
		}
		if n := len(byFam[name]); n > 0 {
			problems = append(problems, fmt.Sprintf("the pack offers %d route(s) for it", n))
		}
		// A listener behind two shut firewalls is not reachable, so it does
		// not fail this check — but it is recorded: see FINDINGS O-3.
		rc.R.Add(name, phase, "not_served", Blocked, got(len(problems) == 0, Blocked, Pass), strings.Join(problems, "; "),
			map[string]any{"box_ufw_open": boxOpen, "cloud_firewall_open": cloudOpen, "listener_on_box": listening, "routes_in_pack": len(byFam[name])}, t0)
	}
}

// socketBound reports whether an `ss -Hltnu` dump has proto bound to port.
func socketBound(dump, proto string, port int) bool {
	p := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(dump, "\n") {
		fld := strings.Fields(line)
		if len(fld) >= 5 && fld[0] == proto && strings.HasSuffix(fld[4], p) {
			return true
		}
	}
	return false
}

// ---- wire ---------------------------------------------------------------

// wireCheck records where the session's packets went. expect is the
// tunnel's expectation; minDown the payload the session claims to have
// downloaded.
func (rc *RunCtx) wireCheck(f Family, phase, expect string, w WireSample, werr error, minDown int64, t0 time.Time) {
	if werr != nil {
		rc.R.Add(f.Name, phase, "wire", expect, Fail, werr.Error(), nil, t0)
		return
	}
	verdict, detail := w.Verdict(f.Name, minDown)
	if verdict == "silent" {
		// Nothing was even attempted on the family's endpoint. Under a
		// scenario that expects "blocked" that is not what was claimed
		// either: blocked means tried and stopped.
		verdict = Fail
	}
	rc.R.Add(f.Name, phase, "wire", expect, verdict, detail, w.Evidence(), t0)
}

// ---- wrong credentials --------------------------------------------------

var (
	uuidTail = regexp.MustCompile(`[0-9a-f]{12}$`)
	hexOnly  = regexp.MustCompile(`^[0-9a-f]+$`)
)

// forgeField returns creds with ONE field replaced by a value of the same
// shape that the relay never issued. Same shape matters: a value the
// client's config parser rejects would stop the session before it reached
// the relay and prove nothing about the relay.
func forgeField(creds map[string]any, field string) (map[string]any, error) {
	s, _ := creds[field].(string)
	if s == "" {
		return nil, fmt.Errorf("the relay's credential reply has no %q", field)
	}
	out := map[string]any{}
	for k, v := range creds {
		out[k] = v
	}
	var forged string
	switch {
	case strings.HasSuffix(field, "_uuid"):
		forged = uuidTail.ReplaceAllString(s, "000000000bad")
	case field == "ss_password":
		// "<box iPSK>:<recipient uPSK>", both base64 16-byte keys: another
		// valid key in the recipient half.
		i := strings.LastIndex(s, ":")
		forged = s[:i+1] + flipChars(s[i+1:], 0, 8)
	case field == "tls_cert_pem":
		// Another certificate entirely: same name, same shape, a key the
		// relay does not hold.
		pem, err := otherCertPEM(s)
		if err != nil {
			return nil, err
		}
		out[field] = pem
		return out, nil
	case field == "tls_cert_sha256" || field == "reality_public_key":
		// 32 bytes, base64: change the leading characters (the trailing one
		// carries padding bits a strict decoder checks).
		forged = flipChars(s, 0, 8)
	case field == "ws_path":
		forged = flipChars(s, len(s)-4, len(s))
	case hexOnly.MatchString(s):
		forged = strings.Map(func(r rune) rune {
			if r == '0' {
				return '1'
			}
			return '0'
		}, s)
	default: // base64url secrets
		forged = flipChars(s, len(s)-4, len(s))
	}
	if forged == s || len(forged) != len(s) {
		return nil, fmt.Errorf("could not forge %q", field)
	}
	out[field] = forged
	return out, nil
}

func flipChars(s string, from, to int) string {
	b := []byte(s)
	if from < 0 {
		from = 0
	}
	for i := from; i < to && i < len(b); i++ {
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
	}
	return string(b)
}

// attempt is one bare insider session: connect with pack, try the TCP
// round trip, disconnect. It reports the outcome in the session
// vocabulary and what the censor saw.
//
// An engine PROCESS that dies during it is not a refusal: died is true,
// the outcome is Fail, a red `<check>.engine.survived` carrying the crash
// signature is recorded and the dead VPN's routing is reaped, exactly as
// Session does (run.go). The caller repeats the attempt once.
func (rc *RunCtx) attempt(f Family, phase, check, label, pack string, budget time.Duration, retry bool) (outcome, detail string, w WireSample, died bool) {
	t0 := time.Now()
	_, _ = WireReset(rc.Ctx)
	c, err := StartClient(rc.P, f.Name+"-"+label, ClientOpts{Pack: pack, Family: f.Name, Experimental: f.Experimental})
	if err != nil {
		return Fail, err.Error(), nil, false
	}
	dead := func() bool {
		if !c.Died() {
			return false
		}
		sig := c.CrashSignature()
		rc.R.Add(f.Name, phase, check+".engine.survived", Pass, Fail,
			"the engine process died mid-session: "+sig+got(retry, " — the attempt is repeated once", " — second death in a row"),
			map[string]any{"client_dir": c.Dir, "stderr": filepath.Join(c.Dir, "stderr.log"), "signature": sig}, t0)
		ReapDeadVPN(rc.Ctx)
		detail = "the engine process died: " + sig
		return true
	}
	ev, err := c.Wait(rc.Ctx, 20*time.Second, "connected")
	if err != nil && dead() {
		w, _ = WireReset(rc.Ctx)
		return Fail, detail, w, true
	}
	if c.Event("routes") == nil {
		c.Stop()
		return Refused, "pack not imported: " + errStr(err), nil, false
	}
	if err != nil {
		c.Stop()
		w, _ = WireReset(rc.Ctx)
		if stage, _ := ev["stage"].(string); stage == "pick" || stage == "set_route" {
			return Refused, "the client refused the route before dialling: " + err.Error(), w, false
		}
		return Blocked, err.Error(), w, false
	}
	pr := Probe(rc.Ctx, rc.P, false, budget)
	w, _ = WireReset(rc.Ctx)
	if dead() {
		return Fail, detail, w, true
	}
	c.Stop()
	if pr.OK {
		return Pass, "", w, false
	}
	return Blocked, pr.Error, w, false
}

// wrongCreds is the wrong-credential control for one family. For each
// declared secret it mints — with the real users-pack-sbp — a pack that
// is genuine in every respect except that one field, and requires that
// the session reaches the family's endpoint and carries nothing.
//
// It only runs after the genuine pack passed: a family that is down
// anyway would "pass" this control without proving anything.
func (rc *RunCtx) wrongCreds(f Family, phase, expect, outcome string) {
	rc.forgedControl(f, phase, "wrongcreds", f.Secrets, expect, outcome,
		"that field does not authenticate anything on "+f.Name,
		"families/"+f.Name+".json declares no secrets: there is no wrong-credential control for this family")
}

// wrongServer is the mirror image: the pack's idea of WHO the relay is
// (certificate pin, REALITY public key) is forged, one field at a time.
// The relay is the genuine one, so it now fails to match the pack, and
// the client must refuse it — that refusal is all that stands between an
// insider and an impostor relay in the path.
//
// Who the relay is, is SIGNED: a pack cannot name another key unless the
// publisher signed that key into its manifest (a rewrite without the key
// is refused at import — op:tamper). So this control has the publisher
// sign a pack for the forged identity (bind-and-sign against a relay
// reply carrying the forged value) and mints from that. What it then
// proves is the data plane's half: handed a correctly signed pack for a
// relay with ANOTHER key, the client does not accept the one it meets.
func (rc *RunCtx) wrongServer(f Family, phase, expect, outcome string) {
	if len(f.Pins) == 0 && f.Skip == "" {
		rc.R.Add(f.Name, phase, "wrongserver", Skipped, Skipped,
			"no server pin on this family: its shared key authenticates both ends, and wrongcreds already forges it", nil, time.Now())
		return
	}
	rc.forgedControl(f, phase, "wrongserver", f.Pins, expect, outcome,
		"the client does not check that field: it would accept an impostor relay", "")
}

func (rc *RunCtx) forgedControl(f Family, phase, check string, fields []string, expect, outcome, meaningIfPass, ifNone string) {
	t0 := time.Now()
	if f.Skip != "" {
		return
	}
	if expect != Pass || outcome != Pass {
		rc.R.Add(f.Name, phase, check, Skipped, Skipped,
			"not run: the genuine pack did not carry traffic here ("+outcome+"), so a forged pack failing would prove nothing", nil, t0)
		return
	}
	if len(fields) == 0 {
		rc.R.Add(f.Name, phase, check, Blocked, Fail, ifNone, nil, t0)
		return
	}
	body, err := os.ReadFile(rc.Pub.Path("creds-r1.json"))
	var creds map[string]any
	if err == nil {
		err = json.Unmarshal(body, &creds)
	}
	if err != nil {
		rc.R.Add(f.Name, phase, check, Blocked, Fail, "cannot read r1's credentials: "+err.Error(), nil, t0)
		return
	}
	ev := map[string]any{}
	worst, details := Blocked, []string{}
	for _, field := range fields {
		one := map[string]any{}
		ev[field] = one
		forged, err := forgeField(creds, field)
		if err != nil {
			worst = Fail
			details = append(details, field+": "+err.Error())
			continue
		}
		stem := "forged-" + f.Name + "-" + field
		fb, _ := json.Marshal(forged)
		if err := os.WriteFile(rc.Pub.Path("creds-"+stem+".json"), fb, 0o600); err != nil {
			worst = Fail
			details = append(details, field+": "+err.Error())
			continue
		}
		base := "base.sbp"
		if check == "wrongserver" {
			// The forged identity has to be signed (see wrongServer).
			// The relay's TLS identity is ONE key with two spellings in
			// its reply — the pin (tls_cert_sha256) and the certificate
			// naive trusts (tls_cert_pem). Forging one and not the other
			// describes a relay that contradicts itself, which the
			// minter refuses; so the forged identity is another KEY, in
			// both spellings, whichever field this row is named for.
			if field == "tls_cert_pem" || field == "tls_cert_sha256" {
				if orig, _ := creds["tls_cert_pem"].(string); orig != "" {
					if other, cerr := otherCertPEM(orig); cerr == nil {
						if pin, perr := spkiPin(other); perr == nil {
							forged["tls_cert_pem"], forged["tls_cert_sha256"] = other, pin
							fb, _ = json.Marshal(forged)
							_ = os.WriteFile(rc.Pub.Path("creds-"+stem+".json"), fb, 0o600)
							one["forged_identity"] = "another key: certificate and pin together"
						}
					}
				}
			}
			base = "base-" + stem + ".sbp"
			if bv := rc.Pub.BindAndSignFor(rc.Ctx, base, "creds-"+stem+".json"); !bv.OK() {
				worst = Fail
				details = append(details, field+": bind-and-sign refused the forged identity: "+oneLine(bv.Tail(), 200))
				continue
			}
			one["signed_for_the_forged_identity"] = true
		}
		v := rc.Pub.PackSBP(rc.Ctx, base, "creds-"+stem+".json", "pack-"+stem+".sbp")
		if !v.OK() {
			worst = Fail
			details = append(details, field+": users-pack-sbp refused the forged value: "+oneLine(v.Tail(), 200))
			continue
		}
		id := check + "." + field
		got, detail, w, died := rc.attempt(f, phase, id, "forged-"+field, rc.Pub.Path("pack-"+stem+".sbp"), 4*time.Second, true)
		if died {
			// One crash costs one red engine.survived; the control itself
			// is decided by a second, living attempt.
			one["died_first"] = oneLine(detail, 200)
			got, detail, w, died = rc.attempt(f, phase, id, "forged-"+field+"-again", rc.Pub.Path("pack-"+stem+".sbp"), 4*time.Second, false)
		}
		one["outcome"], one["error"] = got, oneLine(detail, 200)
		if w != nil {
			one["wire"] = w.Evidence()
		}
		switch {
		case got == Pass:
			worst = Pass
			details = append(details, fmt.Sprintf("%s: a pack with a forged %s CARRIED TRAFFIC — %s", field, field, meaningIfPass))
		case died:
			if worst != Pass {
				worst = Fail
			}
			details = append(details, fmt.Sprintf("%s: %s — a dead engine carries nothing, but that is a crash, not a refusal of the forged value", field, oneLine(detail, 160)))
		case got != Blocked:
			if worst != Pass {
				worst = got
			}
			details = append(details, fmt.Sprintf("%s: %s (%s) — the forged pack never got as far as the relay, so this proves nothing", field, got, oneLine(detail, 160)))
		case w == nil || w[f.Name+".in"].Packets == 0:
			if worst != Pass {
				worst = Fail
			}
			details = append(details, field+": blocked, but the client never sent a packet to the family's endpoint — not a refusal of the forged value")
		}
	}
	rc.R.Add(f.Name, phase, check, Blocked, worst, strings.Join(details, "; "), map[string]any{"forged_alone": fields, "per_field": ev}, t0)
}

// spkiPin is the base64 SHA-256 of a PEM certificate's
// SubjectPublicKeyInfo — the form the relay reports as tls_cert_sha256.
func spkiPin(pemText any) (string, error) {
	s, _ := pemText.(string)
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return "", fmt.Errorf("not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// otherCertPEM returns a fresh self-signed certificate with the same
// subject and names as the one in pemIn and a new key.
func otherCertPEM(pemIn string) (string, error) {
	blk, _ := pem.Decode([]byte(pemIn))
	if blk == nil {
		return "", fmt.Errorf("tls_cert_pem is not PEM")
	}
	orig, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      orig.Subject,
		NotBefore:    orig.NotBefore,
		NotAfter:     orig.NotAfter,
		KeyUsage:     orig.KeyUsage,
		ExtKeyUsage:  orig.ExtKeyUsage,
		DNSNames:     orig.DNSNames,
		IPAddresses:  orig.IPAddresses,
		IsCA:         orig.IsCA, BasicConstraintsValid: orig.BasicConstraintsValid,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
