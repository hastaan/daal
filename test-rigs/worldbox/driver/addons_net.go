package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The outside world the three publisher add-ons need
// (docs/optional-addons-plan.md; specs/optional-addons-v1.md), added to
// the world only when an op or a scenario asks for it:
//
//	[client] ── [censor] ──┬── 198.19.10.0/30 ── [cdn]    198.19.8.0/24  every address answers (Cloudflare's anycast)
//	                       │                        │ eth1 198.18.8.0/30 ── [internet]   (the edge → origin side)
//	                       ├── 198.19.10.4/30 ── [google] 198.19.9.0/24  the Google front, script hosts, the Apps Script API
//	                       │                        │ eth1 198.18.9.0/30 ── [internet]   (the publisher reaches Google from abroad)
//	                       └── 198.19.10.8/30 ── [stranger] 203.0.113.20/32 (op standby-stale only: whoever gets a released address)
//	[internet] 192.0.2.25  api.cloudflare.com, www.cloudflare.com (ips-v4), cloudflare-dns.com + dns.google (DoH)
//
// The CDN and Google namespaces each have two sides, as the real ones
// do: recipients reach them through the censor; the publisher abroad
// (and, for the CDN, the edge's own pull from the origin) through the
// lab's internet. The edge pulls from the relay from 198.19.8.250, an
// address inside the ranges Cloudflare "publishes" here, which is what
// the relay's firewall rule lets in.
//
// Nothing here is reachable from the client except through the censor,
// so every scenario rule applies to it.
const (
	NSCDN      = "cdn"
	NSGoogle   = "google"
	NSStranger = "stranger"

	CDNEdgeNet     = "198.19.8.0/24"
	CDNOriginPull  = "198.19.8.250" // the edge's source address toward the origin
	CDNLinkCensor  = "198.19.10.1"
	CDNLinkCDN     = "198.19.10.2"
	CDNLinkInet    = "198.18.8.1"
	CDNLinkInetCDN = "198.18.8.2"
	CensorDevCDN   = "to-cdn"

	GoogleNet         = "198.19.9.0/24"
	GoogleFrontIP     = "198.19.9.10" // www.google.com
	GoogleFront2IP    = "198.19.9.11" // a second front address (the shipped list)
	GoogleScriptIP    = "198.19.9.12" // script.google.com
	GoogleUserCntIP   = "198.19.9.13" // script.googleusercontent.com
	GoogleAPIIP       = "198.19.9.20" // script.googleapis.com, oauth2.googleapis.com
	GoogleLinkCensor  = "198.19.10.5"
	GoogleLinkGoogle  = "198.19.10.6"
	GoogleLinkInet    = "198.18.9.1"
	GoogleLinkInetGgl = "198.18.9.2"
	CensorDevGoogle   = "to-google"

	StrangerLinkCensor = "198.19.10.9"
	StrangerLinkHost   = "198.19.10.10"
	CensorDevStranger  = "to-stranger"

	CFAPIIP = "192.0.2.25" // api.cloudflare.com and friends, in the lab's internet

	// ECHPublicName is the outer name every ECH hello to the edge shows
	// (Cloudflare's shared name, plan §2.1).
	ECHPublicName = "cloudflare-ech.com"
)

// CDN edge addresses: one per published /26, so a scenario can open some
// prefixes and not others (cdn-edge-allowlist) or put a packet budget on
// one (cdn-grey-budget).
var (
	CDNPublishedV4 = []string{"198.19.8.0/26", "198.19.8.64/26", "198.19.8.128/26", "198.19.8.192/26"}
	CDNEdgeA       = "198.19.8.10"
	CDNEdgeB       = "198.19.8.70"
	CDNEdgeC       = "198.19.8.130"
	CDNEdgeD       = "198.19.8.200"
)

// CDNZone and CDNHost are the publisher's zone and the route's host name
// in this world. Fixed (cdn-provision --hostname), so a scenario can put
// the name on a blocklist.
const (
	CDNZone = "wbfront.example"
	CDNHost = "door7.wbfront.example"
)

// The names each side of the world resolves through /etc/hosts.
func cfHosts() []string {
	return []string{CFAPIIP + " api.cloudflare.com", CFAPIIP + " www.cloudflare.com",
		CFAPIIP + " cloudflare-dns.com", CFAPIIP + " dns.google"}
}

func googleHosts() []string {
	return []string{GoogleFrontIP + " www.google.com", GoogleScriptIP + " script.google.com",
		GoogleUserCntIP + " script.googleusercontent.com", GoogleAPIIP + " script.googleapis.com",
		GoogleAPIIP + " oauth2.googleapis.com"}
}

// appendHosts adds lines to a hosts file once.
func appendHosts(path string, lines []string) error {
	have, _ := os.ReadFile(path)
	var b strings.Builder
	b.Write(have)
	if len(have) > 0 && have[len(have)-1] != '\n' {
		b.WriteByte('\n')
	}
	for _, l := range lines {
		if !strings.Contains("\n"+string(have), "\n"+l+"\n") {
			b.WriteString(l + "\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func nsExists(ns string) bool {
	_, err := os.Stat(filepath.Join("/run/netns", ns))
	return err == nil
}

// runSteps runs namespace plumbing in order; the first failure names its command.
func (rc *RunCtx) runSteps(steps [][]string) error {
	for _, s := range steps {
		if _, err := sh(rc.Ctx, s...); err != nil {
			return err
		}
	}
	return nil
}

// twoSidedNS builds a namespace with a link to the censor (the
// recipients' side) and one to the lab's internet (the publisher's
// side), and makes every address of anyNet local to it (AnyIP: one
// listener on 0.0.0.0 answers on all of them, as an anycast front does).
func (rc *RunCtx) twoSidedNS(ns, censorDev, linkCensor, linkHere, inetDev, linkInet, linkInetHere, anyNet string) error {
	return rc.runSteps([][]string{
		{"ip", "netns", "add", ns},
		inNS(ns, "ip", "link", "set", "lo", "up"),
		{"ip", "link", "add", censorDev, "netns", NSCensor, "type", "veth", "peer", "name", "eth0", "netns", ns},
		inNS(NSCensor, "ip", "addr", "add", linkCensor+"/30", "dev", censorDev),
		inNS(NSCensor, "ip", "link", "set", censorDev, "up"),
		inNS(NSCensor, "ip", "route", "add", anyNet, "via", linkHere),
		inNS(ns, "ip", "addr", "add", linkHere+"/30", "dev", "eth0"),
		inNS(ns, "ip", "link", "set", "eth0", "up"),
		{"ip", "link", "add", inetDev, "netns", NSInternet, "type", "veth", "peer", "name", "eth1", "netns", ns},
		inNS(NSInternet, "ip", "addr", "add", linkInet+"/30", "dev", inetDev),
		inNS(NSInternet, "ip", "link", "set", inetDev, "up"),
		inNS(NSInternet, "ip", "route", "add", anyNet, "via", linkInetHere),
		inNS(ns, "ip", "addr", "add", linkInetHere+"/30", "dev", "eth1"),
		inNS(ns, "ip", "link", "set", "eth1", "up"),
		inNS(ns, "ip", "route", "add", "local", anyNet, "dev", "lo"),
		// Recipients are behind the censor; everything else (the
		// publisher, the relay) is in the lab's internet.
		inNS(ns, "ip", "route", "add", "198.51.100.0/24", "via", linkCensor),
		inNS(ns, "ip", "route", "add", "default", "via", linkInet),
	})
}

// BringUpCDN starts the Cloudflare stand-ins: the API (with the published
// ranges and DoH) in the lab's internet, and the edge namespace. Once
// per world; later calls return at once.
func (rc *RunCtx) BringUpCDN() error {
	if nsExists(NSCDN) {
		return nil
	}
	if err := WriteLabECH(rc.P.Run); err != nil {
		return err
	}
	if _, err := sh(rc.Ctx, inNS(NSInternet, "ip", "addr", "add", CFAPIIP+"/24", "dev", "r1")...); err != nil {
		return err
	}
	wb := filepath.Join(rc.P.Bin, "wb")
	if _, err := Spawn(rc.P, "fakecf", nil, inNS(NSInternet, wb, "fakecf", "--run-dir", rc.P.Run, "--listen", CFAPIIP)...); err != nil {
		return err
	}
	if err := rc.twoSidedNS(NSCDN, CensorDevCDN, CDNLinkCensor, CDNLinkCDN, "cdn", CDNLinkInet, CDNLinkInetCDN, CDNEdgeNet); err != nil {
		return err
	}
	if _, err := Spawn(rc.P, "fakecdn", nil, inNS(NSCDN, wb, "fakecdn", "--run-dir", rc.P.Run, "--pull-from", CDNOriginPull)...); err != nil {
		return err
	}
	if err := appendHosts(rc.P.Hosts(), cfHosts()); err != nil {
		return err
	}
	if !waitFor(rc.Ctx, 10*time.Second, func() bool {
		return rc.tcpFrom(NSPublisher, CFAPIIP, 443) && rc.tcpFrom(NSCensor, CDNEdgeA, 443)
	}) {
		return fmt.Errorf("the Cloudflare stand-ins did not come up; see logs/fakecf.log and logs/fakecdn.log")
	}
	return nil
}

// BringUpGoogle starts the Google stand-in (front, script hosts, Apps
// Script API, OAuth) in its own namespace. Once per world.
func (rc *RunCtx) BringUpGoogle() error {
	if nsExists(NSGoogle) {
		return nil
	}
	if err := rc.twoSidedNS(NSGoogle, CensorDevGoogle, GoogleLinkCensor, GoogleLinkGoogle, "google", GoogleLinkInet, GoogleLinkInetGgl, GoogleNet); err != nil {
		return err
	}
	wb := filepath.Join(rc.P.Bin, "wb")
	if _, err := Spawn(rc.P, "fakegoogle", nil, inNS(NSGoogle, wb, "fakegoogle", "--run-dir", rc.P.Run)...); err != nil {
		return err
	}
	if err := appendHosts(rc.P.Hosts(), googleHosts()); err != nil {
		return err
	}
	if !waitFor(rc.Ctx, 10*time.Second, func() bool {
		return rc.tcpFrom(NSPublisher, GoogleAPIIP, 443) && rc.tcpFrom(NSCensor, GoogleFrontIP, 443)
	}) {
		return fmt.Errorf("the Google stand-in did not come up; see logs/fakegoogle.log")
	}
	return nil
}

// BringUpStranger puts somebody else's server on addr: what a released
// Floating IP becomes once the provider hands it to another customer.
// The censor routes that one address there instead of to the relay's
// segment. A TLS listener with its own certificate on 443, echo on 80
// and 8443 (the control host's program, `wb elsewhere`).
func (rc *RunCtx) BringUpStranger(addr string) error {
	if !nsExists(NSStranger) {
		if err := rc.runSteps([][]string{
			{"ip", "netns", "add", NSStranger},
			inNS(NSStranger, "ip", "link", "set", "lo", "up"),
			{"ip", "link", "add", CensorDevStranger, "netns", NSCensor, "type", "veth", "peer", "name", "eth0", "netns", NSStranger},
			inNS(NSCensor, "ip", "addr", "add", StrangerLinkCensor+"/30", "dev", CensorDevStranger),
			inNS(NSCensor, "ip", "link", "set", CensorDevStranger, "up"),
			inNS(NSStranger, "ip", "addr", "add", StrangerLinkHost+"/30", "dev", "eth0"),
			inNS(NSStranger, "ip", "link", "set", "eth0", "up"),
			inNS(NSStranger, "ip", "route", "add", "default", "via", StrangerLinkCensor),
		}); err != nil {
			return err
		}
	}
	if err := rc.runSteps([][]string{
		inNS(NSStranger, "ip", "addr", "add", addr+"/32", "dev", "lo"),
		inNS(NSCensor, "ip", "route", "replace", addr+"/32", "via", StrangerLinkHost),
	}); err != nil {
		return err
	}
	if _, err := Spawn(rc.P, "stranger", nil, inNS(NSStranger, filepath.Join(rc.P.Bin, "wb"), "elsewhere", "--listen", addr)...); err != nil {
		return err
	}
	if !waitFor(rc.Ctx, 5*time.Second, func() bool { return rc.tcpFrom(NSCensor, addr, 443) }) {
		return fmt.Errorf("the stranger at %s did not come up; see logs/stranger.log", addr)
	}
	return nil
}

// RemoveStranger gives the address back to the relay's segment.
func (rc *RunCtx) RemoveStranger(addr string) {
	_, _ = sh(rc.Ctx, inNS(NSCensor, "ip", "route", "del", addr+"/32")...)
	_, _ = sh(rc.Ctx, inNS(NSStranger, "ip", "addr", "del", addr+"/32", "dev", "lo")...)
}

// phoneHostsWithGoogle is the phone's /etc/hosts with the Google names
// added (the phone's resolver finds www.google.com as it would anywhere).
func (rc *RunCtx) phoneHostsWithGoogle(base string) (string, error) {
	out := filepath.Join(rc.P.Run, "hosts-phone-google")
	body, err := os.ReadFile(base)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(out, body, 0o644); err != nil {
		return "", err
	}
	return out, appendHosts(out, googleHosts())
}

// ---- work that lands in other lanes ------------------------------------

// Prereq is code another lane is building in this wave (add-ons wave 2).
// An op or check that needs it runs for real the moment the code is in
// the tree, and until then records one SKIPPED line that says exactly
// what it waits on: never a pass, never a red that hides the rest.
//
// Detection reads the tree the rig was built from (non-test Go files
// only), so a lane that lands its work turns these checks on without
// anybody editing the rig. It is a cheap signal, not a proof: once the
// code is there the checks themselves decide.
type Prereq struct {
	Lane, Item, What string
	Dir              string         // relative to the repository
	Files            string         // glob inside Dir ("*.go")
	Pattern          *regexp.Regexp // must match in some file
	MinHits          int            // …on at least this many lines (0 = 1)
}

var (
	PreStandbyStore = Prereq{Lane: "L-ladder", Item: "SaveImport standby",
		What: "core/trust SaveImport writes RouteInput.Standby to standby:<route>",
		Dir:  "core/trust", Files: "*.go", Pattern: regexp.MustCompile(`StandbyStoreKey`)}
	PreStandbyKey = Prereq{Lane: "L-ladder", Item: "S7 engine_standby_key",
		What: "core/abi exports func StandbyKey(relayPackID, key string) (string, error) — the Go side of engine_standby_key",
		Dir:  "core/abi", Files: "*.go", Pattern: regexp.MustCompile(`(?m)^func StandbyKey\(`)}
	PreStandbyVariant = Prereq{Lane: "L-ladder", Item: "S7 address variant",
		What: "the connect ladder tries the standby address after an address-shaped stop (routeStandbyAddress in core/abi/connect_*.go)",
		Dir:  "core/abi", Files: "connect_*.go", Pattern: regexp.MustCompile(`routeStandbyAddress\(`)}
	PreGoogleMirror = Prereq{Lane: "L-fetch", Item: "G5",
		What: "core/refresh fetches appsscript mirrors through the Google front and applies the daal-refresh-v1 container",
		Dir:  "core/refresh", Files: "*.go", Pattern: regexp.MustCompile(`(?i)appsscript|daal-refresh-v1`)}
	PreFrontFetch = Prereq{Lane: "L-fetch", Item: "G4",
		What: "core/bootstrap front fetcher (SNI www.google.com, authority script.google.com, one redirect)",
		Dir:  "core/bootstrap", Files: "*.go", Pattern: regexp.MustCompile(`script\.googleusercontent\.com`)}
	PreCDNMint = Prereq{Lane: "L-ladder", Item: "B-4 outbound",
		What: "relaypack RewriteProfilesForRecipient renders a cdn_fronted route (WrapCDNOutbound)",
		Dir:  "publisher/deploy/relaypack", Files: "client_pack.go", Pattern: regexp.MustCompile(`WrapCDNOutbound\(`)}
	PreCDNBind = Prereq{Lane: "L-glue", Item: "B-4 binder",
		What: "bind-and-sign --cdn-front <cdn-provision output> --cdn-edge-seeds --cdn-roots-file adds the cdn_fronted websocket-tls route with _cdn_endpoint",
		Dir:  "publisher/deploy/cli", Files: "cli.go", Pattern: regexp.MustCompile(`fs\.String\("cdn-front"`)}
	PreCDNLabRoots = Prereq{Lane: "L-ladder", Item: "B-4 outbound roots",
		What: "users-pack-sbp installs the roots the commitment signs (from --cdn-roots-file), not only the app's shipped set: the lab's edge chains to the lab CA",
		Dir:  "publisher/deploy/cli", Files: "*.go", Pattern: regexp.MustCompile(`fs\.String\("cdn-roots-file"`), MinHits: 2}
	PreCDNDoorCall = Prereq{Lane: "L-glue (unowned: publisher/deploy/cli/cli_addon_cdn.go)", Item: "mgmt /cdn from a verb",
		What: "cdn-provision opens the relay's CDN door (mgmt.Client.CDNDoorEnable exists; no daal-deploy verb calls it yet)",
		Dir:  "publisher/deploy/cli", Files: "*.go", Pattern: regexp.MustCompile(`CDNDoorEnable\(`)}
	PreEdgePick = Prereq{Lane: "L-ladder", Item: "B-6",
		What: "core/edgepick picks an edge address from the signed seeds",
		Dir:  "core/edgepick", Files: "*.go", Pattern: regexp.MustCompile(`(?m)^package edgepick`)}
	PreCDNLadder = Prereq{Lane: "L-ladder", Item: "B-6b",
		What: "the connect ladder tries the CDN route last: ECH, then ECH with a split hello, then stop",
		Dir:  "core/abi", Files: "connect_*.go", Pattern: regexp.MustCompile(`cdn_fronted|CDNEndpoint`)}
)

// Present reports whether the prerequisite's code is in the tree.
func (q Prereq) Present(repo string) bool {
	paths, _ := filepath.Glob(filepath.Join(repo, q.Dir, q.Files))
	want, hits := q.MinHits, 0
	if want < 1 {
		want = 1
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if q.Pattern.MatchString(sc.Text()) {
				hits++
			}
		}
		f.Close()
		if hits >= want {
			return true
		}
	}
	return false
}

func (q Prereq) String() string { return q.Lane + " " + q.Item + ": " + q.What }

// waitsOn records one SKIPPED check naming every missing prerequisite
// and returns true when any is missing.
func (rc *RunCtx) waitsOn(phase, check string, qs ...Prereq) bool {
	var missing []string
	for _, q := range qs {
		if !q.Present(rc.P.Repo) {
			missing = append(missing, q.String())
		}
	}
	if len(missing) == 0 {
		return false
	}
	rc.R.Add("", phase, check, Skipped, Skipped, "WAITS ON "+strings.Join(missing, "; WAITS ON "),
		map[string]any{"waits_on": missing}, time.Now())
	return true
}

// clientFeatures is what this wb-client was built with (`wb-client
// --features`): build-tag-gated host calls that need engine code
// another lane is adding (labclient/standby_key*.go).
func (rc *RunCtx) clientFeatures() []string {
	out, err := exec.CommandContext(rc.Ctx, filepath.Join(rc.P.Bin, "wb-client"), "--features").Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

// scenarioWorld brings up what the scenario's World and probe targets
// name, before its rules go in.
func (rc *RunCtx) scenarioWorld() error {
	need := map[string]bool{}
	for _, w := range rc.Scn.World {
		need[w] = true
	}
	for _, pr := range rc.Scn.Prove {
		if t, ok := proofTargets[pr.To]; ok && t.world != "" {
			need[t.world] = true
		}
	}
	if need["storage"] {
		if _, err := rc.bringUpStorage(filepath.Join(rc.P.Run, "storage")); err != nil {
			return err
		}
	}
	if need["cdn"] {
		if err := rc.BringUpCDN(); err != nil {
			return err
		}
	}
	if need["google"] {
		if err := rc.BringUpGoogle(); err != nil {
			return err
		}
	}
	return nil
}

// provisionKnowsFlag: the tree's daal-deploy provision takes --name (the
// CDN door's ranges at first boot landed in add-ons wave 2, L-glue).
func provisionKnowsFlag(p Paths, name string) bool {
	return (Prereq{Dir: "publisher/deploy/cli", Files: "cli.go", Pattern: regexp.MustCompile(`fs\.Bool\("` + regexp.QuoteMeta(name) + `"`)}).Present(p.Repo)
}
