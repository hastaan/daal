package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"daal/bundle-go/envelope"
	"daal/bundle-go/fieldreport"
	"daal/core/engine"
	"daal/core/fieldprobe"
	"daal/core/routestore"
)

// The network test's ABI (fieldprobe.go): who may start it, the run on
// the Stub's side instance, sealing, the kept result, the wipe.

const fpRelayIP = "198.51.100.7"
const fpCover = "cover.example"

// refusingNet answers every connection like a closed port and every
// datagram socket with an error: nothing leaves the test process.
type refusingNet struct{}

func (refusingNet) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}
func (refusingNet) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("test: no udp")
}
func (refusingNet) ListenUDP(context.Context) (net.PacketConn, error) {
	return nil, errors.New("test: no udp")
}

// nxDNS answers NXDOMAIN to everything: the network "works" but holds
// no name, so the run is not a blackout and goes through Stage C.
type nxDNS struct{}

func (nxDNS) Query(context.Context, netip.AddrPort, string, uint16) (fieldprobe.DNSAnswer, error) {
	return fieldprobe.DNSAnswer{Rcode: 3}, nil
}

type fpRig struct {
	c       *Core
	stub    *engine.Stub
	priv    [32]byte
	address string
	cfgs    chan engine.ProofConfig
}

func newFieldProbeRig(t *testing.T, withKey bool) *fpRig {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "daal-state")
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	c := mustCore()
	stub, ok := c.driver.(*engine.Stub)
	if !ok {
		t.Skipf("driver is %T, not the stub", c.driver)
	}
	pub, priv, _ := envelope.NewReportKey()
	r := &fpRig{c: c, stub: stub, priv: priv, address: fieldreport.EncodeAddress(pub), cfgs: make(chan engine.ProofConfig, 32)}
	fam := `{}`
	if withKey {
		fam = `{"_report_to":"` + r.address + `"}`
	}
	seed := func(id, family, profile string) {
		seedAutoRoute(t, c, id, family, profile)
		row, err := c.store.GetRoute(id)
		if err != nil {
			t.Fatal(err)
		}
		row.FamilySpecificConfigJSON = fam
		// No RelayPackID: a RelayPack row needs a stored endpoint
		// commitment (endpoint_guard.go) this rig does not make.
		if err := c.store.UpsertRoute(row); err != nil {
			t.Fatal(err)
		}
	}
	seed("fp-main", "vless-reality", `{"type":"vless","server":"`+fpRelayIP+`","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"`+fpCover+`","reality":{"enabled":true,"public_key":"k","short_id":"ab"}}}`)
	seed("fp-alt", "websocket-tls", `{"type":"vless","server":"`+fpRelayIP+`","server_port":8444,"uuid":"00000000-0000-4000-8000-000000000002","tls":{"enabled":true,"server_name":"own.example"}}`)
	seed("fp-hy2", "hysteria2", `{"type":"hysteria2","server":"`+fpRelayIP+`","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"own.example"}}`)
	stub.SetSideProbeHook(func(ctx context.Context, _ []byte, cfg engine.ProofConfig) (engine.ProofResult, error) {
		select {
		case r.cfgs <- cfg:
		default:
		}
		return engine.ProofResult{OK: true, Attempts: 1}, nil
	})
	globalFieldProbe.mu.Lock()
	globalFieldProbe.envHook = func(env *fieldprobe.Env) {
		env.Net = refusingNet{}
		env.DNS = nxDNS{}
		env.Gap = func(byte) time.Duration { return 0 }
		env.Timeouts = fieldprobe.Timeouts{Connect: 200 * time.Millisecond, Handshake: 200 * time.Millisecond,
			Carry: 200 * time.Millisecond, DNS: 100 * time.Millisecond, QUIC: 100 * time.Millisecond, Relay: time.Second}
		env.Resolvers = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}
	}
	globalFieldProbe.mu.Unlock()
	t.Cleanup(func() {
		globalFieldProbe.mu.Lock()
		globalFieldProbe.envHook = nil
		globalFieldProbe.mu.Unlock()
	})
	return r
}

func fpStart(t *testing.T, opts string) map[string]any {
	t.Helper()
	body, err := FieldProbeStart(opts)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func fpStatus(t *testing.T) map[string]any {
	t.Helper()
	body, err := FieldProbeStatus()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func fpWait(t *testing.T) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st := fpStatus(t); st["state"] != FieldProbeRunning {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the run did not finish")
	return nil
}

const fpOK = `{"network_label":"home_internet","consent_version":1,"private_dns":"auto","dns_servers":["192.0.2.53"]}`

func TestFieldProbe_Refusals(t *testing.T) {
	newFieldProbeRig(t, false)
	if got := fpStart(t, `{"consent_version":0}`)["refused"]; got != "consent_required" {
		t.Fatalf("no consent: %v", got)
	}
	if got := fpStart(t, `{"consent_version":1,"vpn_active":true}`)["refused"]; got != "vpn_active" {
		t.Fatalf("another VPN: %v", got)
	}
	if got := fpStart(t, fpOK)["refused"]; got != "no_report_key" {
		t.Fatalf("no report address: %v", got)
	}
}

func TestFieldProbe_RefusesWhileConnected(t *testing.T) {
	r := newFieldProbeRig(t, true)
	r.c.mu.Lock()
	r.c.activeRoute = "fp-main"
	r.c.mu.Unlock()
	defer func() { r.c.mu.Lock(); r.c.activeRoute = ""; r.c.mu.Unlock() }()
	if got := fpStart(t, fpOK)["refused"]; got != "connected" {
		t.Fatalf("connected: %v", got)
	}
}

func TestFieldProbe_RunSealOpenDiscard(t *testing.T) {
	r := newFieldProbeRig(t, true)
	if st := fpStatus(t); st["state"] != FieldProbeIdle {
		t.Fatalf("before a run: %v", st["state"])
	}
	if m := fpStart(t, fpOK); m["started"] != true {
		t.Fatalf("start: %v", m)
	}
	st := fpWait(t)
	if st["state"] != FieldProbeDone {
		t.Fatalf("after the run: %v", st)
	}
	sum, _ := st["summary"].([]any)
	if len(sum) == 0 || sum[len(sum)-1] != fieldprobe.SumPrivacy {
		t.Fatalf("summary %v", sum)
	}
	// One attempt per side probe, never an extended one.
	close(r.cfgs)
	n := 0
	for cfg := range r.cfgs {
		n++
		if cfg.Attempts != 1 || cfg.SlowBudget > time.Millisecond {
			t.Fatalf("side probe config %+v", cfg)
		}
	}
	if n == 0 {
		t.Fatal("the Test relay was never proved")
	}
	if _, had := engine.RouteDesyncChoice("fp-main"); had {
		t.Fatal("the route's desync choice was not put back")
	}
	// The allowance.
	if got := fpStart(t, fpOK)["refused"]; got != "rate_limited" {
		t.Fatalf("second run at once: %v", got)
	}

	out := t.TempDir()
	// A page-supplied path is ignored for a share: the engine writes it
	// inside the state directory.
	body, err := FieldProbeSeal(`{"notes":"from home","out_path":"` + out + `","transient":true}`)
	if err != nil {
		t.Fatal(err)
	}
	var sealed struct {
		Sealed   bool   `json:"sealed"`
		Path     string `json:"path"`
		FileName string `json:"file_name"`
	}
	_ = json.Unmarshal([]byte(body), &sealed)
	if !sealed.Sealed || !regexp.MustCompile(`^net-[a-z0-9]{8}\.dat$`).MatchString(sealed.FileName) {
		t.Fatalf("seal: %s", body)
	}
	if filepath.Dir(sealed.Path) != filepath.Join(r.c.stateDir, fieldProbeOutDirName) {
		t.Fatalf("a transient file outside the state directory: %s", sealed.Path)
	}
	raw, err := os.ReadFile(sealed.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(sealed.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("sealed file mode %v", fi.Mode())
	}
	rep, err := fieldreport.Open(raw, r.priv)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Notes != "from home" || rep.RelayRef != "none" {
		t.Fatalf("opened report: notes=%q relay_ref=%q", rep.Notes, rep.RelayRef)
	}
	js, _ := json.Marshal(rep)
	for _, bad := range []string{fpRelayIP, fpCover, "192.0.2.53", "fp-main", "pack-fieldprobe-test"} {
		if strings.Contains(string(js), bad) {
			t.Fatalf("the report carries %q", bad)
		}
	}
	// Nothing in the state directory holds the result in clear.
	if hits := grepDir(t, r.c.stateDir, `"probes"`); len(hits) > 0 {
		t.Fatalf("a report in clear in %v", hits)
	}
	if n, err := FieldProbeDiscard(); err != nil || n != 1 {
		t.Fatalf("discard: %d %v", n, err)
	}
	if _, err := os.Stat(sealed.Path); !os.IsNotExist(err) {
		t.Fatal("the transient sealed file outlived the discard")
	}
	if st := fpStatus(t); st["state"] != FieldProbeIdle {
		t.Fatalf("after discard: %v", st["state"])
	}
	if got, _ := FieldProbeSeal(`{"out_path":"` + out + `"}`); !strings.Contains(got, "no_result") {
		t.Fatalf("seal with nothing kept: %s", got)
	}
}

func TestFieldProbe_ShutdownStopsTheRun(t *testing.T) {
	newFieldProbeRig(t, true)
	globalFieldProbe.mu.Lock()
	prev := globalFieldProbe.envHook
	globalFieldProbe.envHook = func(env *fieldprobe.Env) {
		prev(env)
		env.Gap = func(byte) time.Duration { return 2 * time.Second }
	}
	globalFieldProbe.mu.Unlock()
	if m := fpStart(t, fpOK); m["started"] != true {
		t.Fatalf("start: %v", m)
	}
	time.Sleep(50 * time.Millisecond)
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}
	globalFieldProbe.mu.Lock()
	running := globalFieldProbe.running
	globalFieldProbe.mu.Unlock()
	if running {
		t.Fatal("Shutdown left the network test running")
	}
	_ = routestore.RouteRow{}
}

// fpSeed adds one more held route to the rig's store.
func fpSeed(t *testing.T, c *Core, id, family, profile, fam, trust string) {
	t.Helper()
	seedAutoRoute(t, c, id, family, profile)
	row, err := c.store.GetRoute(id)
	if err != nil {
		t.Fatal(err)
	}
	row.FamilySpecificConfigJSON = fam
	if trust != "" {
		row.TrustState = trust
	}
	if err := c.store.UpsertRoute(row); err != nil {
		t.Fatal(err)
	}
}

func fpVless(addr string, port int, reality bool) string {
	tls := `{"enabled":true,"server_name":"own.example"}`
	if reality {
		tls = `{"enabled":true,"server_name":"` + fpCover + `","reality":{"enabled":true,"public_key":"k","short_id":"ab"}}`
	}
	return fmt.Sprintf(`{"type":"vless","server":"%s","server_port":%d,"uuid":"00000000-0000-4000-8000-00000000000%d","tls":%s}`, addr, port, port%10, tls)
}

// H1: after a disconnect the host's protect() refuses every socket; with
// no TUN and no route that refusal is not fatal.
func TestFieldProbe_ProtectRefusalOnlyMattersBesideATunnel(t *testing.T) {
	if protectCallsHost {
		t.Skip("singbox+cgo build: the protect hook would call the fake address")
	}
	r := newFieldProbeRig(t, true)
	if _, err := RegisterProtectCallback(0x1); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = RegisterProtectCallback(0) }()
	if engine.ProtectFD(3) == nil {
		t.Skip("this build's ProtectFD accepts a registered callback")
	}
	protect := fieldProbeProtect(r.c)
	if err := protect(3); err != nil {
		t.Fatalf("no tunnel, no route: %v", err)
	}
	r.c.mu.Lock()
	r.c.activeRoute = "fp-main"
	r.c.mu.Unlock()
	defer func() { r.c.mu.Lock(); r.c.activeRoute = ""; r.c.mu.Unlock() }()
	if protect(3) == nil {
		t.Fatal("a refusal beside a route was let through")
	}
}

// M1: another VPN, or Daal connecting, mid-run stops the run at once.
func TestFieldProbe_StopsWhenAVPNComesUp(t *testing.T) {
	for _, how := range []string{"vpn", "connect"} {
		t.Run(how, func(t *testing.T) {
			r := newFieldProbeRig(t, true)
			globalFieldProbe.mu.Lock()
			prev := globalFieldProbe.envHook
			globalFieldProbe.envHook = func(env *fieldprobe.Env) {
				prev(env)
				env.Gap = func(byte) time.Duration { return 400 * time.Millisecond }
			}
			globalFieldProbe.mu.Unlock()
			if m := fpStart(t, fpOK); m["started"] != true {
				t.Fatalf("start: %v", m)
			}
			time.Sleep(100 * time.Millisecond)
			want := "vpn_active"
			if how == "vpn" {
				if _, err := NetworkFacts(NetKindVPN, "", 1, 0); err != nil {
					t.Fatal(err)
				}
			} else {
				want = "connected"
				r.c.mu.Lock()
				r.c.activeRoute = "fp-main"
				r.c.mu.Unlock()
				defer func() { r.c.mu.Lock(); r.c.activeRoute = ""; r.c.mu.Unlock() }()
			}
			t0 := time.Now()
			st := fpWait(t)
			if st["state"] != FieldProbeAborted || st["abort_reason"] != want {
				t.Fatalf("state=%v abort=%v", st["state"], st["abort_reason"])
			}
			if time.Since(t0) > 2*time.Second {
				t.Fatal("the run was not stopped promptly")
			}
		})
	}
}

// M2: the report is sealed to the main route's own address; an
// untrusted route is not a Test relay.
func TestFieldProbe_ReportKeyIsTheMainRoutes(t *testing.T) {
	r := newFieldProbeRig(t, true)
	otherPub, _, _ := envelope.NewReportKey()
	other := fieldreport.EncodeAddress(otherPub)
	fpSeed(t, r.c, "aa-other", "websocket-tls", fpVless("198.51.100.99", 8443, false), `{"_report_to":"`+other+`"}`, "")
	rel, code := r.c.findTestRelay()
	if code != "" || rel.reportTo != r.address || rel.target.Main != "fp-main" {
		t.Fatalf("code=%q main=%q sealed to the main route: %v", code, rel.target.Main, rel.reportTo == r.address)
	}
	row, _ := r.c.store.GetRoute("fp-main")
	row.TrustState = "changed_key"
	if err := r.c.store.UpsertRoute(row); err != nil {
		t.Fatal(err)
	}
	if got := fpStart(t, fpOK)["refused"]; got != "no_test_relay" {
		t.Fatalf("an untrusted main route: %v", got)
	}
}

// M3: the Test relay may not share its address with a daily route, and
// may not be a private address.
func TestFieldProbe_TestRelayMustBeSeparateAndPublic(t *testing.T) {
	r := newFieldProbeRig(t, true)
	fpSeed(t, r.c, "daily", "vless-reality", fpVless(fpRelayIP, 443, true), `{}`, "")
	if got := fpStart(t, fpOK)["refused"]; got != "test_relay_shared" {
		t.Fatalf("shared address: %v", got)
	}
	_ = r.c.store.DeleteRoute("daily")
	if err := r.c.store.PutSecret("route:fp-main", []byte(fpVless("192.168.1.5", 443, true))); err != nil {
		t.Fatal(err)
	}
	if got := fpStart(t, fpOK)["refused"]; got != "no_test_relay" {
		t.Fatalf("private relay address: %v", got)
	}
}

func TestFieldProbe_LockdownRefused(t *testing.T) {
	newFieldProbeRig(t, true)
	if got := fpStart(t, `{"consent_version":1,"blocked":true}`)["refused"]; got != "local_blocked" {
		t.Fatalf("blocked: %v", got)
	}
}

// M4: a transient file a dead process left behind goes at the next
// process's first call.
func TestFieldProbe_StaleTransientSwept(t *testing.T) {
	r := newFieldProbeRig(t, true)
	dir := filepath.Join(r.c.stateDir, fieldProbeOutDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	left := filepath.Join(dir, "net-abcdefgh.dat")
	if err := os.WriteFile(left, []byte("DSBR"), 0o600); err != nil {
		t.Fatal(err)
	}
	globalFieldProbe.mu.Lock()
	globalFieldProbe.sweptFor = nil
	globalFieldProbe.mu.Unlock()
	fpStatus(t)
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatal("a sealed file from a dead process survived")
	}
}

// The page offers the test only when a trusted held route carries a
// report address: idle status says so, and whose route it is.
func TestFieldProbe_StatusSaysWhetherATestRelayIsHeld(t *testing.T) {
	newFieldProbeRig(t, false)
	st := fpStatus(t)
	if st["state"] != FieldProbeIdle || st["has_test_relay"] != false || st["publisher_id"] != "" {
		t.Fatalf("no report address held: %v", st)
	}
	_ = Shutdown()
	newFieldProbeRig(t, true)
	st = fpStatus(t)
	if st["has_test_relay"] != true {
		t.Fatalf("a report address held: %v", st)
	}
	if id, _ := st["publisher_id"].(string); id == "" {
		t.Fatalf("no publisher_id: %v", st)
	}
}

// One result is kept: a new run replaces a result kept for another
// network kind (the page shows, sends and deletes one, so a second would
// be deleted unseen), and the kept result's status carries the plan, so
// "Run again" can show what is tested.
func TestFieldProbe_OneResultKeptAndItsStatusHasThePlan(t *testing.T) {
	r := newFieldProbeRig(t, true)
	other := fieldProbeResultPrefix + "zz-other-kind"
	if err := r.c.store.PutSecret(other, []byte(`{"at":1}`)); err != nil {
		t.Fatal(err)
	}
	if m := fpStart(t, fpOK); m["started"] != true {
		t.Fatalf("start: %v", m)
	}
	st := fpWait(t)
	if st["state"] != FieldProbeDone {
		t.Fatalf("after the run: %v", st)
	}
	keys, err := r.c.store.ListSecretKeys(fieldProbeResultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] == other {
		t.Fatalf("kept results after a new run: %v", keys)
	}
	plan, _ := st["plan"].(map[string]any)
	if plan == nil || plan["consent_version"] == nil {
		t.Fatalf("a kept result's status without the plan: %v", st)
	}
	if names, _ := plan["names"].([]any); len(names) == 0 {
		t.Fatalf("plan without names: %v", plan)
	}
}
