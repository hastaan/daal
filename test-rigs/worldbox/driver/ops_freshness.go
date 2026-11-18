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

// opFreshness asks two questions and keeps them apart.
//
// A. NOTHING CHANGED. The publisher has published what the app
// publishes after signing: a document naming the digest of the SIGNED
// pack (`bind-and-sign`'s output — the value the wizard stores as
// signed_sbp_sha256 and passes to publish-freshness). A recipient
// holding a working pack polls. Two phones, one per file the operator
// could have put at the pack URL:
//
//	A1  the signed pack itself (the only file whose digest matches)
//	      the phone polled the mirrors directly, with no tunnel
//	      the phone still connects                            → pass
//	A2  the recipient's connectable pack (digest does not match)
//	      the engine refuses the download and the phone
//	      still connects                                      → pass
//
// B. THE RELAY ROTATED (L2: its cover host moved, which kills
// vless-reality for every pack in the field). The publisher re-issues the
// recipient's pack and publishes its digest.
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

	// ---- the public internet the phone can reach without a tunnel -----
	t0 := time.Now()
	root := filepath.Join(rc.P.Run, "storage")
	hosts, err := rc.bringUpStorage(root)
	if !rc.R.Add("", phase, "storage.up", Pass, got(err == nil, Pass, Fail), errStr(err), map[string]any{"address": StorageIP}, t0) {
		return
	}
	put := func(url string, body []byte) error {
		rest := strings.TrimPrefix(url, "https://")
		path := filepath.Join(root, filepath.FromSlash(rest))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, body, 0o644)
	}
	phoneOpts := func(pack string) ClientOpts {
		return ClientOpts{Pack: pack, Idle: true, Experimental: fam.Experimental, Hosts: hosts, CAFile: rc.P.CA()}
	}

	// ---- the publisher signs a pack that names its mirrors ------------
	mirrorFlags := []string{"--freshness-mirror", "r2=" + freshMirrorR2, "--freshness-mirror", "ghpages=" + freshMirrorGH}
	sign := func(out string) (map[string]any, bool) {
		t0 := time.Now()
		v := rc.Pub.Deploy(rc.Ctx, append([]string{"bind-and-sign", "--operator-record", rc.Pub.Path("record.json"),
			"--priv-key", rc.Pub.Path("publisher.priv"), "--output", rc.Pub.Path(out), "--publisher-name", "Worldbox Publisher"}, mirrorFlags...)...)
		var ans map[string]any
		_ = json.Unmarshal([]byte(v.Stdout), &ans)
		n, _ := ans["freshness_mirrors"].(float64)
		return ans, rc.R.Add("", phase, "verb.bind-and-sign."+out, Pass, got(v.OK() && n == 2, Pass, Fail), v.Tail(),
			map[string]any{"relay_pack_id": ans["relay_pack_id"], "freshness_mirrors": n}, t0)
	}
	signed1, ok := sign("base-fresh1.sbp")
	if !ok {
		return
	}
	t0 = time.Now()
	uv := rc.Pub.UsersProvision(rc.Ctx, freshRecipient)
	if !rc.R.Add("", phase, "verb.users-provision."+freshRecipient, Pass, got(uv.OK(), Pass, Fail), uv.Tail(), nil, t0) {
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

	pubRaw, _ := os.ReadFile(rc.Pub.Path("publisher.pub"))
	pubHex := hex.EncodeToString(pubRaw)
	var lastSeq uint64
	publish := func(label, packID, sha, privFile string, supersedes []string) ([]byte, bool) {
		t0 := time.Now()
		args := []string{"publish-freshness", "--relay-pack-id", packID, "--current-bundle-sha256", sha,
			"--current-signed-url", freshPackURL, "--publisher-pub-hex", pubHex, "--root-priv-file", privFile,
			"--mirror", "r2=" + freshMirrorR2, "--mirror", "ghpages=" + freshMirrorGH,
			"--out-file", rc.Pub.Path("freshness-" + label + ".json")}
		if lastSeq > 0 {
			args = append(args, "--min-sequence", fmt.Sprint(lastSeq), "--sequence", fmt.Sprint(lastSeq+1))
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
		ok := rc.R.Add("", phase, "verb.publish-freshness."+label, Pass, got(v.OK() && rerr == nil && len(doc) > 0, Pass, Fail), v.Tail(),
			map[string]any{"sequence": ans.Sequence, "relay_pack_id": packID, "bundle_sha256": sha, "document_bytes": len(doc)}, t0)
		if ok && ans.Sequence > lastSeq {
			lastSeq = ans.Sequence
		}
		return doc, ok
	}
	serveDoc := func(doc []byte) error {
		if err := put(freshMirrorR2, doc); err != nil {
			return err
		}
		return put(freshMirrorGH, doc)
	}

	// ================= A. nothing changed ==============================
	packID1, _ := signed1["relay_pack_id"].(string)
	sha1, _ := signed1["sbp_sha256"].(string)
	docA, ok := publish("a", packID1, sha1, rc.Pub.Path("publisher.priv"), nil)
	if !ok {
		return
	}
	signedBody, _ := os.ReadFile(rc.Pub.Path("base-fresh1.sbp"))
	if err := firstErr(serveDoc(docA), put(freshPackURL, signedBody)); err != nil {
		rc.R.Add("", phase, "storage.put", Pass, Fail, err.Error(), nil, time.Now())
		return
	}
	a := rc.phone(fam, phase, "unchanged.signed-pack-hosted", phoneOpts(pack1), true)
	rc.R.Add(fam.Name, phase, "unchanged.polled_mirrors_directly", Pass, got(a.docFetches > 0 && a.fromClient, Pass, Fail),
		fmt.Sprintf("document fetches=%d pack fetches=%d, all from the phone's own address=%v; tick error: %s", a.docFetches, a.packFetches, a.fromClient, a.tickErr),
		map[string]any{"scheduler": a.scheduler}, a.t0)
	rc.R.Add(fam.Name, phase, "unchanged.signed-pack-hosted.tunnel", Pass, a.outcome, got(a.outcome == Pass, "",
		"a recipient with a WORKING pack polled the freshness mirrors while nothing had changed, and can no longer connect (FINDINGS.md LC-2): "+a.detail),
		map[string]any{"routes_before_poll": a.routesBefore, "routes_after_poll": a.routesAfter, "pack_fetches": a.packFetches, "client_dir": a.dir}, a.t0)

	// A', the other thing the operator could put at the pack URL: the
	// recipient's CONNECTABLE file. Its digest is not the one the
	// document names, so the engine must refuse it and leave the phone as
	// it was — which also means the document, as published, can never
	// deliver it.
	pack1Body, _ := os.ReadFile(pack1)
	if err := put(freshPackURL, pack1Body); err == nil {
		a2 := rc.phone(fam, phase, "unchanged.recipient-pack-hosted", phoneOpts(pack1), true)
		rc.R.Add(fam.Name, phase, "unchanged.recipient-pack-hosted.tunnel", Pass, a2.outcome, a2.detail,
			map[string]any{"pack_fetches": a2.packFetches, "tick_error": a2.tickErr, "freshness_audit": a2.audit, "client_dir": a2.dir}, a2.t0)
		rc.R.Add(fam.Name, phase, "unchanged.recipient-pack-hosted.digest_mismatch_refused", Pass,
			got(a2.packFetches > 0 && fmt.Sprint(a2.routesBefore) == fmt.Sprint(a2.routesAfter) && a2.outcome == Pass, Pass, Fail),
			fmt.Sprintf("pack fetches=%d; routes before %v, after %v", a2.packFetches, a2.routesBefore, a2.routesAfter), nil, a2.t0)
	}

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
	signed2, ok := sign("base-fresh2.sbp")
	if !ok {
		return
	}
	pack2, ok := rc.Rebuild(freshRecipient, phase, "base-fresh2.sbp", "fresh2")
	rc.MgmtWindowClosed(phase)
	if !ok {
		return
	}
	// r1's file is stale after L2 as well; re-issue it for whatever runs next.
	defer func() {
		if p1, ok := rc.Rebuild("r1", phase, "base.sbp", "after-freshness"); ok {
			rc.Pack = p1
		}
		rc.MgmtWindowClosed(phase)
	}()

	// B1. no poll, old pack.
	b1 := rc.phone(fam, phase, "rotated.no-poll", phoneOpts(pack1), false)
	rc.R.Add(fam.Name, phase, "rotated.no-poll.tunnel", Blocked, b1.outcome, b1.detail, map[string]any{"client_dir": b1.dir}, b1.t0)

	// The publisher publishes the replacement: the recipient's re-issued,
	// CONNECTABLE pack, by its own digest.
	body2, _ := os.ReadFile(pack2)
	sum2 := sha256.Sum256(body2)
	packID2, _ := signed2["relay_pack_id"].(string)
	var supersedes []string
	if packID2 != packID1 {
		supersedes = []string{packID1}
	}

	// B2. a forged document: right shape, right pack, wrong key.
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	strangerFile := rc.Pub.Path("stranger.priv")
	_ = os.WriteFile(strangerFile, strangerPriv, 0o600)
	savedSeq := lastSeq
	forged, ok := publish("forged", packID2, hex.EncodeToString(sum2[:]), strangerFile, supersedes)
	lastSeq = savedSeq
	if ok {
		if err := firstErr(serveDoc(forged), put(freshPackURL, body2)); err == nil {
			b2 := rc.phone(fam, phase, "rotated.forged-document", phoneOpts(pack1), true)
			rc.R.Add(fam.Name, phase, "rotated.forged-document.tunnel", Blocked, b2.outcome,
				got(b2.outcome == Blocked, b2.detail, "a freshness document signed by a key that is NOT the publisher's replaced the recipient's pack"),
				map[string]any{"doc_fetches": b2.docFetches, "pack_fetches": b2.packFetches, "tick_error": b2.tickErr, "client_dir": b2.dir}, b2.t0)
			rc.R.Add(fam.Name, phase, "rotated.forged-document.pack_not_fetched", Pass, got(b2.docFetches > 0 && b2.packFetches == 0, Pass, Fail),
				fmt.Sprintf("document fetches=%d pack fetches=%d (a refused document must not lead to a pack download)", b2.docFetches, b2.packFetches), nil, b2.t0)
		}
	}

	// B3. the real document.
	docB, ok := publish("b", packID2, hex.EncodeToString(sum2[:]), rc.Pub.Path("publisher.priv"), supersedes)
	if !ok {
		return
	}
	if err := firstErr(serveDoc(docB), put(freshPackURL, body2)); err != nil {
		rc.R.Add("", phase, "storage.put", Pass, Fail, err.Error(), nil, time.Now())
		return
	}
	b3 := rc.phone(fam, phase, "rotated.polled", phoneOpts(pack1), true)
	rc.R.Add(fam.Name, phase, "rotated.polled.fetched_new_pack", Pass, got(b3.docFetches > 0 && b3.packFetches > 0 && b3.fromClient, Pass, Fail),
		fmt.Sprintf("document fetches=%d pack fetches=%d; tick error: %s", b3.docFetches, b3.packFetches, b3.tickErr), map[string]any{"scheduler": b3.scheduler}, b3.t0)
	rc.R.Add(fam.Name, phase, "rotated.polled.tunnel", Pass, b3.outcome, got(b3.outcome == Pass, "",
		"the phone polled the mirrors after the rotation and still cannot connect: "+b3.detail),
		map[string]any{"routes_before_poll": b3.routesBefore, "routes_after_poll": b3.routesAfter, "client_dir": b3.dir}, b3.t0)
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
