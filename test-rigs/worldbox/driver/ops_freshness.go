package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() { Ops["freshness"] = opFreshness }

// The freshness path: a recipient learns that their pack was replaced
// WITHOUT anybody handing them a file. The publisher signs a small
// document ("the pack is now <digest>, fetch it at <url>") and puts it
// on N static hosts named inside the signed pack; the engine polls them
// from its scheduler tick, verifies, fetches the new pack and swaps it
// in.
//
// Every product hop is real: `bind-and-sign --freshness-mirror` (the
// mirror set goes into the signed pack), `users-pack-sbp` (must carry it
// through), `publish-freshness` (builds and signs the document),
// abi.SchedulerTick → core/refresh (poll, verify, fetch, apply), and
// then an ordinary connect. What stands in: the storage itself
// (storage.go) and the upload to it — `publish-freshness`'s R2/GitHub
// uploaders need those providers' APIs, so the rig copies the signed
// document onto the lab's static host instead.
//
// Names. The mirrors and the pack URL are ordinary hostnames the phone
// resolves and reaches directly, through the censor, with no tunnel:
const (
	freshMirrorR2  = "https://pub-worldbox.r2.dev/freshness/relay.json"
	freshMirrorGH  = "https://worldbox-pages.github.io/freshness/relay.json"
	freshPackURL   = "https://packs.worldbox-cdn.net/relay.sbp"
	freshFamily    = "vless-reality" // the family an L2 rotation invalidates
	freshRecipient = "r51"
)

// freshChannel is the publisher's side of the freshness channel for one
// op: packs signed with a mirror set, documents signed and "uploaded",
// files put where a phone can fetch them. Every product hop is a real
// verb; what stands in is the storage and the upload to it (storage.go).
type freshChannel struct {
	rc     *RunCtx
	phase  string
	root   string // the static host's document root
	hosts  string // the /etc/hosts a phone sees
	pubHex string
	// the pack ids this channel has announced, newest last: a document
	// for a re-signed pack must name the ids it replaces, because the id
	// is a hash of exactly the fields a rotation changes.
	announced []string
}

// freshSeq is the last document sequence published in this run. One
// counter for the whole run, as the wizard keeps one per relay.
var freshSeq uint64

var freshMirrorFlags = []string{"--freshness-mirror", "r2=" + freshMirrorR2, "--freshness-mirror", "ghpages=" + freshMirrorGH}

// freshChannel brings up the public internet a phone can reach without
// a tunnel and returns the publisher's handle on it.
func (rc *RunCtx) freshChannel(phase string) (*freshChannel, bool) {
	t0 := time.Now()
	root := filepath.Join(rc.P.Run, "storage")
	hosts, err := rc.bringUpStorage(root)
	if !rc.R.Add("", phase, "storage.up", Pass, got(err == nil, Pass, Fail), errStr(err), map[string]any{"address": StorageIP}, t0) {
		return nil, false
	}
	pubRaw, _ := os.ReadFile(rc.Pub.Path("publisher.pub"))
	return &freshChannel{rc: rc, phase: phase, root: root, hosts: hosts, pubHex: hex.EncodeToString(pubRaw),
		announced: append([]string(nil), rc.FreshAnnounced...)}, true
}

func (fc *freshChannel) put(url string, body []byte) error {
	rest := strings.TrimPrefix(url, "https://")
	path := filepath.Join(fc.root, filepath.FromSlash(rest))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func (fc *freshChannel) serveDoc(doc []byte) error {
	return firstErr(fc.put(freshMirrorR2, doc), fc.put(freshMirrorGH, doc))
}

func (fc *freshChannel) phoneOpts(fam Family, pack string) ClientOpts {
	return ClientOpts{Pack: pack, Idle: true, Experimental: fam.Experimental, Hosts: fc.hosts, CAFile: fc.rc.P.CA()}
}

// sign runs bind-and-sign with the mirror set, against record.json as
// it is now. Its output is the SIGNED, CREDENTIAL-LESS pack.
func (fc *freshChannel) sign(out string) (map[string]any, bool) {
	rc := fc.rc
	// The app asks the relay who it is before it signs (the cover host
	// in particular may have moved since the last answer).
	if rc.Pub.identityFile != "" {
		rc.askRelay(fc.phase, "before-sign."+out)
	}
	t0 := time.Now()
	v := rc.Pub.BindAndSign(rc.Ctx, out, freshMirrorFlags...)
	var ans map[string]any
	_ = json.Unmarshal([]byte(v.Stdout), &ans)
	n, _ := ans["freshness_mirrors"].(float64)
	return ans, rc.R.Add("", fc.phase, "verb.bind-and-sign."+out, Pass, got(v.OK() && n == 2, Pass, Fail), v.Tail(),
		map[string]any{"relay_pack_id": ans["relay_pack_id"], "freshness_mirrors": n}, t0)
}

// publish signs a freshness document with publish-freshness.
func (fc *freshChannel) publish(label, packID, sha, privFile string, supersedes []string) ([]byte, bool) {
	rc := fc.rc
	t0 := time.Now()
	args := []string{"publish-freshness", "--relay-pack-id", packID, "--current-bundle-sha256", sha,
		"--current-signed-url", freshPackURL, "--publisher-pub-hex", fc.pubHex, "--root-priv-file", privFile,
		"--mirror", "r2=" + freshMirrorR2, "--mirror", "ghpages=" + freshMirrorGH,
		"--out-file", rc.Pub.Path("freshness-" + label + ".json")}
	if freshSeq > 0 {
		args = append(args, "--min-sequence", fmt.Sprint(freshSeq), "--sequence", fmt.Sprint(freshSeq+1))
	}
	for _, s := range supersedes {
		args = append(args, "--supersedes", s)
	}
	v := rc.Pub.Deploy(rc.Ctx, args...)
	var ans struct {
		Sequence uint64 `json:"sequence"`
	}
	_ = json.Unmarshal([]byte(v.Stdout), &ans)
	doc, rerr := os.ReadFile(rc.Pub.Path("freshness-" + label + ".json"))
	ok := rc.R.Add("", fc.phase, "verb.publish-freshness."+label, Pass, got(v.OK() && rerr == nil && len(doc) > 0, Pass, Fail), v.Tail(),
		map[string]any{"sequence": ans.Sequence, "relay_pack_id": packID, "bundle_sha256": sha, "document_bytes": len(doc)}, t0)
	if ok && ans.Sequence > freshSeq {
		freshSeq = ans.Sequence
	}
	return doc, ok
}

// announce is what the app does after it signs: bind-and-sign against
// the record as it is now, publish a document naming THAT file's digest
// (the value the wizard stores as signed_sbp_sha256), and put that same
// file at the pack URL. The file is the signed skeleton: it holds no
// recipient's credentials — asserted here, because it is public — and
// it does not need to: a phone merges its signed endpoints into the
// credentials it already has.
func (fc *freshChannel) announce(tag string) (signed map[string]any, ok bool) {
	rc := fc.rc
	out := "base-" + tag + ".sbp"
	signed, ok = fc.sign(out)
	if !ok {
		return nil, false
	}
	packID, _ := signed["relay_pack_id"].(string)
	sha, _ := signed["sbp_sha256"].(string)
	var supersedes []string
	for i := len(fc.announced) - 1; i >= 0; i-- {
		if fc.announced[i] != packID && !contains(supersedes, fc.announced[i]) {
			supersedes = append(supersedes, fc.announced[i])
		}
	}
	doc, ok := fc.publish(tag, packID, sha, rc.Pub.Path("publisher.priv"), supersedes)
	if !ok {
		return nil, false
	}
	body, _ := os.ReadFile(rc.Pub.Path(out))
	t0 := time.Now()
	leaks := skeletonLeaks(rc, body)
	rc.R.Add("", fc.phase, "published."+tag+".holds_no_credentials", Pass, got(len(leaks) == 0, Pass, Fail),
		strings.Join(leaks, "; "), map[string]any{"file": out, "bytes": len(body)}, t0)
	if err := firstErr(fc.serveDoc(doc), fc.put(freshPackURL, body)); err != nil {
		rc.R.Add("", fc.phase, "storage.put", Pass, Fail, err.Error(), nil, time.Now())
		return nil, false
	}
	fc.announced = append(fc.announced, packID)
	rc.FreshAnnounced = append(rc.FreshAnnounced, packID)
	return signed, true
}

// skeletonLeaks lists what the file about to be made PUBLIC must not
// contain: an outbound, or any per-recipient secret of any recipient the
// publisher has provisioned in this run.
func skeletonLeaks(rc *RunCtx, body []byte) []string {
	var leaks []string
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return []string{"not a zip: " + err.Error()}
	}
	var secrets []string
	files, _ := filepath.Glob(rc.Pub.Path("creds-*.json"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var c Creds
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		for _, k := range perUserSecrets {
			if v := secretOf(c, k); len(v) >= 6 {
				secrets = append(secrets, v)
			}
		}
		// The box-wide shadowsocks key is a secret too: it may be
		// published only as a digest.
		if ss := c.Str("ss_password"); strings.Contains(ss, ":") {
			secrets = append(secrets, strings.SplitN(ss, ":", 2)[0])
		}
	}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			continue
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		if strings.HasPrefix(f.Name, "profiles/") {
			var prof map[string]any
			if json.Unmarshal(buf.Bytes(), &prof) == nil {
				if t, _ := prof["type"].(string); t != "" {
					leaks = append(leaks, f.Name+" carries an outbound ("+t+")")
				}
			}
		}
		for _, s := range secrets {
			if bytes.Contains(buf.Bytes(), []byte(s)) {
				leaks = append(leaks, f.Name+" contains a recipient secret ("+s[:4]+"…)")
				break
			}
		}
	}
	return leaks
}

// armNoNewFile prepares the proof that a rotation needs NO new file:
// it signs a mirror-carrying pack against the relay as it is BEFORE the
// rotation, mints r1's file from it and announces it. The returned file
// is what a recipient holds when the rotation happens.
func (rc *RunCtx) armNoNewFile(phase, tag string) (*freshChannel, string, bool) {
	fc, ok := rc.freshChannel(phase)
	if !ok {
		return nil, "", false
	}
	if _, ok := fc.announce(tag + "-before"); !ok {
		return nil, "", false
	}
	t0 := time.Now()
	out := "pack-r1-" + tag + "-before.sbp"
	v := rc.Pub.PackSBP(rc.Ctx, "base-"+tag+"-before.sbp", "creds-r1.json", out)
	if !rc.R.Add("", phase, "verb.users-pack-sbp."+tag+"-before", Pass, got(v.OK() && !strings.Contains(v.Stderr, "NOT connectable"), Pass, Fail), v.Tail(), nil, t0) {
		return nil, "", false
	}
	return fc, rc.Pub.Path(out), true
}

// noNewFile is the proof itself, after the rotation: the publisher
// re-signs and announces (no recipient is re-provisioned, no file is
// minted for anyone), and a phone holding the PRE-rotation file ticks
// once with the VPN off and then connects. label says under which
// conditions (e.g. "address-blocked").
func (fc *freshChannel) noNewFile(tag, label string, fams []Family, heldPack string) {
	rc := fc.rc
	if _, ok := fc.announce(tag + "-after"); !ok {
		return
	}
	for _, f := range fams {
		run := rc.phone(f, fc.phase, "no-new-file-"+f.Name, fc.phoneOpts(f, heldPack), true)
		rc.R.Add(f.Name, fc.phase, "no-new-file."+label+".polled", Pass, got(run.docFetches > 0 && run.packFetches > 0 && run.fromClient, Pass, Fail),
			fmt.Sprintf("document fetches=%d pack fetches=%d; tick error: %s", run.docFetches, run.packFetches, run.tickErr),
			map[string]any{"scheduler": run.scheduler}, run.t0)
		rc.R.Add(f.Name, fc.phase, "no-new-file."+label+".tunnel", Pass, run.outcome, got(run.outcome == Pass, "",
			"a phone holding the pre-rotation file polled the freshness mirrors after the rotation and still cannot connect on "+f.Name+": "+run.detail),
			map[string]any{"routes_before_poll": run.routesBefore, "routes_after_poll": run.routesAfter, "client_dir": run.dir}, run.t0)
		// The route this phone is on was never in a file it was handed:
		// its address came from the merge. The engine must have PROVED
		// it — a round trip through its own outbound — before saying
		// Connected, exactly as for a route from a file. "The merge was
		// accepted" and "the fetch above worked" are not that statement;
		// only the engine's own route_check is.
		proved := run.outcome == Pass && (run.routeCheck == "ok" || run.routeCheck == "degraded")
		rc.R.Add(f.Name, fc.phase, "no-new-file."+label+".route_checked", Pass, got(proved, Pass, Fail), got(proved, "",
			fmt.Sprintf("the merged %s route did not come out of the engine's connection check as carrying: route_check=%q, tunnel=%s", f.Name, run.routeCheck, run.outcome)),
			map[string]any{"route_check": run.routeCheck}, run.t0)
	}
}

// opFreshness asks two questions and keeps them apart.
//
// A. NOTHING CHANGED. The publisher has published what the app
// publishes after signing: a document naming the digest of the SIGNED
// pack (`bind-and-sign`'s output — the value the wizard stores as
// signed_sbp_sha256 and passes to publish-freshness), with that same
// file at the pack URL. It is the credential-less skeleton. A recipient
// holding a working pack polls:
//
//	A1  the signed pack is hosted (the only file whose digest matches)
//	      the phone polled the mirrors directly, with no tunnel
//	      the phone merged it and still connects             → pass
//	      every route it had, it still has                    → pass
//	A2  the recipient's connectable pack is hosted instead
//	    (digest does not match the document)
//	      the engine refuses the download and the phone
//	      still connects                                      → pass
//	A3  a phone that holds NOTHING is handed the signed pack
//	    as a file                                             → refused
//
// B. THE RELAY ROTATED (L2: its cover host moved, which kills
// vless-reality for every pack in the field). The publisher re-signs
// and announces. Nobody is re-provisioned and no file is minted.
//
//	B1  a phone with the old pack that does NOT poll           → blocked (control)
//	B2  a phone with the old pack, mirrors serving a document
//	    signed by SOMEBODY ELSE's key, polls                   → blocked, pack untouched
//	B3  a phone with the old pack polls the real document      → pass, with no new file
//
// B1 gives B3 its meaning; B2 shows the swap is not "whatever the mirror
// says".
func opFreshness(rc *RunCtx) {
	const phase = "op:freshness"
	fam, ok := rc.Fams[freshFamily]
	if !ok || fam.Skip != "" || !contains(rc.Want, freshFamily) {
		rc.R.Add("", phase, "freshness", Skipped, Skipped, "needs "+freshFamily+" under test (it is the family an L2 rotation invalidates)", nil, time.Now())
		return
	}
	if scn, _ := rc.Scn.ExpectFor(freshFamily); scn == Blocked {
		rc.R.Add("", phase, "freshness", Skipped, Skipped, "the scenario blocks "+freshFamily+", so nothing here could be told apart from the censor", nil, time.Now())
		return
	}
	fc, ok := rc.freshChannel(phase)
	if !ok {
		return
	}

	// ---- a recipient, and the pack the publisher signs and announces --
	t0 := time.Now()
	uv := rc.Pub.UsersProvision(rc.Ctx, freshRecipient)
	if !rc.R.Add("", phase, "verb.users-provision."+freshRecipient, Pass, got(uv.OK(), Pass, Fail), uv.Tail(), nil, t0) {
		return
	}
	signed1, ok := fc.announce("fresh1")
	if !ok {
		return
	}
	pv := rc.Pub.PackSBP(rc.Ctx, "base-fresh1.sbp", "creds-"+freshRecipient+".json", "pack-fresh1.sbp")
	if !rc.R.Add("", phase, "verb.users-pack-sbp.fresh1", Pass, got(pv.OK(), Pass, Fail), pv.Tail(), nil, t0) {
		return
	}
	rc.MgmtWindowClosed(phase)
	pack1 := rc.Pub.Path("pack-fresh1.sbp")

	// The recipient's file must still carry the mirror set the signed
	// pack had: users-pack-sbp rewrites the archive.
	t0 = time.Now()
	entry1, entryPack := zipEntryNames(rc.Pub.Path("base-fresh1.sbp")), zipEntryNames(pack1)
	var mirrorEntry string
	for _, n := range entry1 {
		if strings.Contains(n, "mirror") {
			mirrorEntry = n
		}
	}
	rc.R.Add("", phase, "pack.carries_mirror_set", Pass, got(mirrorEntry != "" && contains(entryPack, mirrorEntry), Pass, Fail),
		fmt.Sprintf("signed pack entries %v; recipient's pack entries %v", entry1, entryPack), map[string]any{"entry": mirrorEntry}, t0)

	// ================= A. nothing changed ==============================
	a := rc.phone(fam, phase, "unchanged.signed-pack-hosted", fc.phoneOpts(fam, pack1), true)
	rc.R.Add(fam.Name, phase, "unchanged.polled_mirrors_directly", Pass, got(a.docFetches > 0 && a.fromClient, Pass, Fail),
		fmt.Sprintf("document fetches=%d pack fetches=%d, all from the phone's own address=%v; tick error: %s", a.docFetches, a.packFetches, a.fromClient, a.tickErr),
		map[string]any{"scheduler": a.scheduler}, a.t0)
	rc.R.Add(fam.Name, phase, "unchanged.signed-pack-hosted.tunnel", Pass, a.outcome, got(a.outcome == Pass, "",
		"a recipient with a WORKING pack polled the freshness mirrors while nothing had changed, and can no longer connect: "+a.detail),
		map[string]any{"routes_before_poll": a.routesBefore, "routes_after_poll": a.routesAfter, "pack_fetches": a.packFetches, "client_dir": a.dir}, a.t0)
	// The merge must not cost the phone a route either: what it could
	// select before the poll, it can select after it.
	rc.R.Add(fam.Name, phase, "unchanged.signed-pack-hosted.routes_kept", Pass,
		got(a.routesBefore != nil && fmt.Sprint(a.routesBefore) == fmt.Sprint(a.routesAfter), Pass, Fail),
		fmt.Sprintf("routes before the poll %v, after %v", a.routesBefore, a.routesAfter), nil, a.t0)

	// A2, the other thing the operator could put at the pack URL: the
	// recipient's CONNECTABLE file. Its digest is not the one the
	// document names, so the engine must refuse it and leave the phone as
	// it was.
	signedBody, _ := os.ReadFile(rc.Pub.Path("base-fresh1.sbp"))
	pack1Body, _ := os.ReadFile(pack1)
	if err := fc.put(freshPackURL, pack1Body); err == nil {
		a2 := rc.phone(fam, phase, "unchanged.recipient-pack-hosted", fc.phoneOpts(fam, pack1), true)
		rc.R.Add(fam.Name, phase, "unchanged.recipient-pack-hosted.tunnel", Pass, a2.outcome, a2.detail,
			map[string]any{"pack_fetches": a2.packFetches, "tick_error": a2.tickErr, "freshness_audit": a2.audit, "client_dir": a2.dir}, a2.t0)
		rc.R.Add(fam.Name, phase, "unchanged.recipient-pack-hosted.digest_mismatch_refused", Pass,
			got(a2.packFetches > 0 && fmt.Sprint(a2.routesBefore) == fmt.Sprint(a2.routesAfter) && a2.outcome == Pass, Pass, Fail),
			fmt.Sprintf("pack fetches=%d; routes before %v, after %v", a2.packFetches, a2.routesBefore, a2.routesAfter), nil, a2.t0)
	}
	_ = fc.put(freshPackURL, signedBody)

	// A3. The signed pack handed over AS A FILE to a phone that holds
	// nothing. It carries nobody's credentials, so it must be refused —
	// by the importer, with a reason — not imported as a list of routes
	// that cannot connect.
	t0 = time.Now()
	outcome, ev, detail := importOutcome(rc, "fresh-skeleton-alone", rc.Pub.Path("base-fresh1.sbp"))
	rc.R.Add("", phase, "signed-pack-alone.import", Refused, outcome,
		got(outcome == Refused, "", "a phone with no credentials imported the publisher's credential-less signed pack: "+detail), ev, t0)

	// ================= B. the relay rotated ============================
	t0 = time.Now()
	oldSNI := rc.Rec.CoverSNI
	rv := rc.Pub.RotateTLS(rc.Ctx)
	rec, rerr := rc.Pub.Record()
	rotated := rv.OK() && rerr == nil && rec.CoverSNI != oldSNI
	if rerr == nil {
		rc.Rec = rec
	}
	rc.MgmtWindowClosed(phase)
	if !rc.R.Add("", phase, "verb.rotate-tls", Pass, got(rotated, Pass, Fail), rv.Tail(), map[string]any{"previous": oldSNI, "now": rc.Rec.CoverSNI}, t0) {
		return
	}
	// r1's file is stale after L2 as well; re-sign and re-issue it for
	// whatever runs next.
	defer func() {
		if rc.Resign(phase) {
			if p1, ok := rc.Rebuild("r1", phase, "base.sbp", "after-freshness"); ok {
				rc.Pack = p1
			}
		}
		rc.MgmtWindowClosed(phase)
	}()

	// B1. no poll, old pack.
	b1 := rc.phone(fam, phase, "rotated.no-poll", fc.phoneOpts(fam, pack1), false)
	rc.R.Add(fam.Name, phase, "rotated.no-poll.tunnel", Blocked, b1.outcome, b1.detail, map[string]any{"client_dir": b1.dir}, b1.t0)

	// The publisher re-signs against the rotated record. This is the
	// file that will be announced; nothing is minted for the recipient.
	signed2, ok := fc.sign("base-fresh2.sbp")
	if !ok {
		return
	}
	body2, _ := os.ReadFile(rc.Pub.Path("base-fresh2.sbp"))
	sum2 := sha256.Sum256(body2)
	packID1, _ := signed1["relay_pack_id"].(string)
	packID2, _ := signed2["relay_pack_id"].(string)
	var supersedes []string
	if packID2 != packID1 {
		supersedes = []string{packID1}
	}

	// B2. a forged document: right shape, right pack, wrong key.
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	strangerFile := rc.Pub.Path("stranger.priv")
	_ = os.WriteFile(strangerFile, strangerPriv, 0o600)
	savedSeq := freshSeq
	forged, ok := fc.publish("forged", packID2, hex.EncodeToString(sum2[:]), strangerFile, supersedes)
	freshSeq = savedSeq
	if ok {
		if err := firstErr(fc.serveDoc(forged), fc.put(freshPackURL, body2)); err == nil {
			b2 := rc.phone(fam, phase, "rotated.forged-document", fc.phoneOpts(fam, pack1), true)
			rc.R.Add(fam.Name, phase, "rotated.forged-document.tunnel", Blocked, b2.outcome,
				got(b2.outcome == Blocked, b2.detail, "a freshness document signed by a key that is NOT the publisher's replaced the recipient's pack"),
				map[string]any{"doc_fetches": b2.docFetches, "pack_fetches": b2.packFetches, "tick_error": b2.tickErr, "client_dir": b2.dir}, b2.t0)
			rc.R.Add(fam.Name, phase, "rotated.forged-document.pack_not_fetched", Pass, got(b2.docFetches > 0 && b2.packFetches == 0, Pass, Fail),
				fmt.Sprintf("document fetches=%d pack fetches=%d (a refused document must not lead to a pack download)", b2.docFetches, b2.packFetches), nil, b2.t0)
		}
	}

	// B3. the real document, naming the signed pack.
	docB, ok := fc.publish("b", packID2, hex.EncodeToString(sum2[:]), rc.Pub.Path("publisher.priv"), supersedes)
	if !ok {
		return
	}
	t0 = time.Now()
	leaks := skeletonLeaks(rc, body2)
	rc.R.Add("", phase, "published.fresh2.holds_no_credentials", Pass, got(len(leaks) == 0, Pass, Fail), strings.Join(leaks, "; "), nil, t0)
	if err := firstErr(fc.serveDoc(docB), fc.put(freshPackURL, body2)); err != nil {
		rc.R.Add("", phase, "storage.put", Pass, Fail, err.Error(), nil, time.Now())
		return
	}
	b3 := rc.phone(fam, phase, "rotated.polled", fc.phoneOpts(fam, pack1), true)
	rc.R.Add(fam.Name, phase, "rotated.polled.fetched_new_pack", Pass, got(b3.docFetches > 0 && b3.packFetches > 0 && b3.fromClient, Pass, Fail),
		fmt.Sprintf("document fetches=%d pack fetches=%d; tick error: %s", b3.docFetches, b3.packFetches, b3.tickErr), map[string]any{"scheduler": b3.scheduler}, b3.t0)
	rc.R.Add(fam.Name, phase, "rotated.polled.tunnel", Pass, b3.outcome, got(b3.outcome == Pass, "",
		"the phone polled the mirrors after the rotation and still cannot connect: "+b3.detail),
		map[string]any{"routes_before_poll": b3.routesBefore, "routes_after_poll": b3.routesAfter, "client_dir": b3.dir}, b3.t0)

	// B4. The replay. The signed pack from BEFORE the rotation is public
	// (it sat on the mirrors), so anybody can keep it and hand it to a
	// recipient as a file. A phone that has already moved to the rotated
	// relay must refuse it and stay where it is: a file only ever moves
	// a route forward.
	rc.staleSignedPackByFile(fam, phase, fc.phoneOpts(fam, pack1), rc.Pub.Path("base-fresh1.sbp"))
}

// staleSignedPackByFile is a phone that polled its way onto the current
// signed pack and is then handed an OLDER signed pack as a file.
func (rc *RunCtx) staleSignedPackByFile(f Family, phase string, o ClientOpts, stale string) {
	const label = "rotated.stale-signed-pack-by-file"
	t0 := time.Now()
	c, err := StartClient(rc.P, "fresh-"+label, o)
	if err != nil {
		rc.R.Add(f.Name, phase, label+".not_merged", Pass, Fail, err.Error(), nil, t0)
		return
	}
	defer c.Stop()
	if _, err := c.Wait(rc.Ctx, 20*time.Second, "idle"); err != nil {
		rc.R.Add(f.Name, phase, label+".not_merged", Pass, Fail, "pack not imported: "+err.Error(), nil, t0)
		return
	}
	_ = c.Send("tick")
	tick, err := c.Wait(rc.Ctx, 90*time.Second, "tick")
	if err != nil {
		rc.R.Add(f.Name, phase, label+".not_merged", Pass, Fail, "scheduler tick did not return: "+err.Error(), nil, t0)
		return
	}
	held := routeSummary(tick["routes"])
	_ = c.Send("import " + stale)
	ev, err := c.Wait(rc.Ctx, 20*time.Second, "reimport")
	if err != nil {
		rc.R.Add(f.Name, phase, label+".not_merged", Pass, Fail, "the import did not return: "+err.Error(), nil, t0)
		return
	}
	// Either the whole file is refused as older (every route it signs
	// changed since), or it is taken for the routes it changes nothing
	// on and THIS route — the one the rotation moved — is named as older
	// and left alone. What must not happen is a merge of this route.
	kind, _ := ev["kind"].(string)
	reason, _ := ev["reason"].(string)
	var routeReason string
	if v, ok := ev["verdict"].(map[string]any); ok {
		rows, _ := v["Unavailable"].([]any)
		for _, row := range rows {
			if m, _ := row.(map[string]any); m["Family"] == f.Name {
				routeReason, _ = m["Reason"].(string)
			}
		}
	}
	held0 := (kind == "rejected" && reason == "pack_is_older") || routeReason == "older_than_device"
	rc.R.Add(f.Name, phase, label+".not_merged", Pass, got(held0, Pass, Fail),
		got(held0, "", "a phone on the rotated relay merged the signed pack from BEFORE the rotation, handed over as a file: ")+
			fmt.Sprintf("verdict kind=%s reason=%q; this route: %q", kind, reason, routeReason),
		map[string]any{"kind": kind, "reason_code": reason, "verdict": ev["verdict"], "client_dir": c.Dir}, t0)
	after := routeSummary(ev["routes"])
	rc.R.Add(f.Name, phase, label+".routes_kept", Pass, got(held != nil && fmt.Sprint(held) == fmt.Sprint(after), Pass, Fail),
		fmt.Sprintf("routes before the file %v, after %v", held, after), nil, t0)

	// And the phone is still on the relay as it is NOW.
	t0 = time.Now()
	_ = c.Send("connect " + f.Name)
	if cev, err := c.Wait(rc.Ctx, 20*time.Second, "connected"); err != nil {
		rc.R.Add(f.Name, phase, label+".tunnel", Pass, Blocked,
			"after being handed the old signed pack the phone cannot connect: "+err.Error(), map[string]any{"error_event": cev}, t0)
		return
	}
	pr := Probe(rc.Ctx, rc.P, false, 6*time.Second)
	rc.R.Add(f.Name, phase, label+".tunnel", Pass, got(pr.OK && pr.Remote == Relay1EgressIP, Pass, Blocked),
		got(pr.OK, "the target saw "+pr.Remote, pr.Error), nil, t0)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func zipEntryNames(path string) []string {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

// bringUpStorage adds the static host behind the censor and returns the
// /etc/hosts the phone should see. Idempotent within a run.
func (rc *RunCtx) bringUpStorage(root string) (string, error) {
	hosts := filepath.Join(rc.P.Run, "hosts-phone")
	if _, err := os.Stat(hosts); err == nil {
		return hosts, nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	steps := [][]string{
		{"ip", "netns", "add", NSStorage},
		inNS(NSStorage, "ip", "link", "set", "lo", "up"),
		{"ip", "link", "add", CensorDevStore, "netns", NSCensor, "type", "veth", "peer", "name", "eth0", "netns", NSStorage},
		inNS(NSCensor, "ip", "addr", "add", CensorStorageIP+"/24", "dev", CensorDevStore),
		inNS(NSCensor, "ip", "link", "set", CensorDevStore, "up"),
		inNS(NSStorage, "ip", "addr", "add", StorageIP+"/24", "dev", "eth0"),
		inNS(NSStorage, "ip", "link", "set", "eth0", "up"),
		inNS(NSStorage, "ip", "route", "add", "default", "via", CensorStorageIP),
	}
	for _, s := range steps {
		if _, err := sh(rc.Ctx, s...); err != nil {
			return "", err
		}
	}
	if _, err := Spawn(rc.P, "storage", nil, inNS(NSStorage, filepath.Join(rc.P.Bin, "wb"), "storage", "--run-dir", rc.P.Run, "--dir", root)...); err != nil {
		return "", err
	}
	if !waitFor(rc.Ctx, 5*time.Second, func() bool { return rc.tcpFromClient(StorageIP, 443) }) {
		return "", fmt.Errorf("the static host (%s) is not reachable from the client namespace; see logs/storage.log", StorageIP)
	}
	base, _ := os.ReadFile("/etc/hosts")
	var b strings.Builder
	b.WriteString(strings.TrimRight(string(base), "\n") + "\n")
	for _, u := range []string{freshMirrorR2, freshMirrorGH, freshPackURL} {
		host := strings.SplitN(strings.TrimPrefix(u, "https://"), "/", 2)[0]
		fmt.Fprintf(&b, "%s %s\n", StorageIP, host)
	}
	return hosts, os.WriteFile(hosts, []byte(b.String()), 0o644)
}

// phoneRun is what one idle-then-connect phone did.
type phoneRun struct {
	t0                        time.Time
	outcome, detail, tickErr  string
	docFetches, packFetches   int
	fromClient                bool
	routesBefore, routesAfter any
	scheduler                 any
	audit                     any
	dir                       string
	// routeCheck is the engine's own route_check for the route this
	// phone connected on ("ok" once its connection check has carried a
	// round trip; see core/abi/route_check.go), read while connected.
	routeCheck string
}

// phone is one device: it imports the pack with the VPN off, optionally
// runs ONE scheduler tick (the product's own background entry point),
// then connects on the family and fetches the target.
func (rc *RunCtx) phone(f Family, phase, label string, o ClientOpts, tick bool) phoneRun {
	run := phoneRun{t0: time.Now(), outcome: Fail}
	reqBefore := len(StorageRequests(rc.P))
	c, err := StartClient(rc.P, "fresh-"+label, o)
	if err != nil {
		run.detail = err.Error()
		return run
	}
	run.dir = c.Dir
	defer c.Stop()
	if _, err := c.Wait(rc.Ctx, 20*time.Second, "idle"); err != nil {
		run.outcome, run.detail = Refused, "pack not imported: "+err.Error()
		return run
	}
	if ev := c.Event("routes"); ev != nil {
		run.routesBefore = routeSummary(ev["routes"])
	}
	if tick {
		_ = c.Send("tick")
		ev, err := c.Wait(rc.Ctx, 90*time.Second, "tick")
		if err != nil {
			run.detail = "scheduler tick did not return: " + err.Error()
			return run
		}
		run.tickErr, _ = ev["error"].(string)
		run.routesAfter = routeSummary(ev["routes"])
		run.scheduler = ev["scheduler"]
	}
	run.fromClient = true
	for _, q := range StorageRequests(rc.P)[reqBefore:] {
		if q.From != ClientIP {
			run.fromClient = false
		}
		switch {
		case strings.HasSuffix(q.Path, ".json"):
			run.docFetches++
		case strings.HasSuffix(q.Path, ".sbp") && q.Status == 200:
			run.packFetches++
		}
	}
	_ = c.Send("connect " + f.Name)
	ev, err := c.Wait(rc.Ctx, 20*time.Second, "connected")
	if err != nil {
		run.outcome = Blocked
		if stage, _ := ev["stage"].(string); stage == "pick" || stage == "set_route" {
			run.outcome = Refused
		}
		run.detail = "engine did not connect: " + err.Error()
		return run
	}
	_ = c.Send("diag")
	if dv, err := c.Wait(rc.Ctx, 5*time.Second, "diag"); err == nil {
		if d, ok := dv["diag"].(map[string]any); ok {
			run.routeCheck, _ = d["route_check"].(string)
		}
	}
	pr := Probe(rc.Ctx, rc.P, false, 6*time.Second)
	switch {
	case pr.OK && pr.Remote == Relay1EgressIP:
		run.outcome = Pass
	case pr.OK:
		run.outcome, run.detail = Fail, "fetch succeeded but the target saw "+pr.Remote+": this is not the tunnel"
	default:
		run.outcome, run.detail = Blocked, pr.Error
	}
	return run
}

// routeSummary boils the engine's route list down to what a reader needs.
func routeSummary(v any) any {
	doc, _ := v.(map[string]any)
	routes, _ := doc["routes"].([]any)
	var out []string
	for _, r := range routes {
		m, _ := r.(map[string]any)
		fam, _ := m["transport_family"].(string)
		if fam == "" {
			fam, _ = m["family"].(string)
		}
		out = append(out, fmt.Sprintf("%v:%s", m["route_id"], fam))
	}
	return out
}
