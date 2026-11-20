package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"daal/bundle-go/fieldreport"
	"daal/core/desync"
	"daal/core/engine"
	"daal/core/fieldprobe"
	"daal/core/routestore"
)

// The network test — engine_field_probe_{start,status,cancel,seal,discard}.
//
// Spec: specs/field-probe-v2.md. The probing itself is core/fieldprobe;
// this file decides whether a run may happen, gives it its sockets
// (protect()ed: engine.ProtectFD), the Test relay (the driver's side
// instance), its storage, and its way out (a sealed file, made only when
// the person asks).
//
// WHO MAY RUN IT, WHEN. Start refuses — with a closed code, never by
// running anyway — while:
//
//	running          a run is already going
//	connected        Daal has a route up, or an automatic connect is
//	                 trying one. "VPN off" means no VPN at all.
//	vpn_active       the host says another VPN is up (TRANSPORT_VPN), or
//	                 the network the engine was told about is a VPN
//	no_network       the host says there is no network
//	consent_required the page did not pass the consent version it showed
//	local_blocked    the host says the device blocks connections outside
//	                 a VPN (Android lockdown: onBlockedStatusChanged)
//	no_report_key    no trusted held route carries a report address
//	                 (_report_to)
//	no_test_relay    the routes that carry one have no route this test
//	                 can prove (a REALITY/TCP route on 443, at a public
//	                 address)
//	test_relay_shared the Test relay's address is also the address of a
//	                 route the family uses every day (one without
//	                 _report_to): the test's plain hellos and three
//	                 names to one address could burn it. The Test relay
//	                 must be a separate address.
//	rate_limited     one run per network per 6 h, three a day
//
// WHAT IS KEPT. The last result per network kind, in the route store's
// age-encrypted secrets table (so inside the state directory, so gone
// with engine_panic_wipe), with the report address it is to be sealed
// to; for 7 days (fieldProbeSweep), and until engine_field_probe_discard.
// The run history behind the allowance is kept the same way. Times are
// kept to the hour. Nothing is written anywhere else, except the sealed
// file, when the person asks: a share goes in <state_dir>/fieldprobe-out
// (so panic wipe takes it), a saved file where the SHELL's save dialog
// says. A file saved, or shared into a messenger, is then outside the
// engine's reach: the send screen says so.
//
// WHAT IS LOGGED (logcat on Android, stderr with DAAL_ENGINE_LOG
// elsewhere; never in the diagnostics export): one start line, one end
// line, refusals by code — closed words and counts. No per-step lines,
// never a name, an address or the report.

const (
	fieldProbeConsentVersion = 1
	fieldProbeResultPrefix   = "fieldprobe/result/"
	fieldProbeHistoryKey     = "fieldprobe/history"
	fieldProbeShutdownWait   = 5 * time.Second
)

// Field-probe states.
const (
	FieldProbeIdle    = "idle"
	FieldProbeRunning = "running"
	FieldProbeDone    = "done"
	FieldProbeAborted = "aborted"
)

// FieldProbeStartOpts is engine_field_probe_start's argument.
type FieldProbeStartOpts struct {
	NetworkLabel string `json:"network_label"`
	// DNSServers: the link's DNS servers (Android LinkProperties
	// .getDnsServers). Used in memory for this run only; never stored,
	// logged or reported (the report gets their coarse class).
	DNSServers     []string `json:"dns_servers"`
	PrivateDNS     string   `json:"private_dns"`
	ConsentVersion int      `json:"consent_version"`
	// VPNActive: the host sees TRANSPORT_VPN on the default network.
	VPNActive  bool `json:"vpn_active"`
	IPv6Global bool `json:"ipv6_global"`
	// Blocked: the host's ConnectivityManager says this app's traffic
	// is blocked (NetworkCallback.onBlockedStatusChanged — "block
	// connections without VPN" with Daal's VPN down).
	Blocked bool `json:"blocked"`
}

// storedResult is what one finished (or stopped) run leaves behind.
type storedResult struct {
	At       int64               `json:"at"`
	NetKind  string              `json:"net_kind"`
	ReportTo string              `json:"report_to"`
	Report   *fieldreport.Report `json:"report"`
	Summary  []string            `json:"summary"`
}

type fieldProbeState struct {
	mu        sync.Mutex
	running   bool
	step, of  int
	cancel    context.CancelCauseFunc
	done      chan struct{}
	transient []string
	// outDir: where transient sealed files go (inside the state
	// directory, so panic wipe takes them); sweptFor: the core whose
	// outDir was swept of files a dead process left behind.
	outDir   string
	sweptFor *Core
	// test seams
	envHook func(*fieldprobe.Env)
}

var globalFieldProbe = &fieldProbeState{}

func fieldProbeJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fieldProbeRefuse(code string, extra map[string]any) string {
	out := map[string]any{"started": false, "refused": code}
	for k, v := range extra {
		out[k] = v
	}
	engine.LogInfo("fieldprobe refused code=" + code)
	return fieldProbeJSON(out)
}

// fieldProbeRelay is the Test relay as found in the store.
type fieldProbeRelay struct {
	target   fieldprobe.RelayTarget
	reportTo string
}

// fieldProbeTrusted: the trust states a Test relay may be in. A route
// whose publisher key changed, or whose trust is unknown, is not one.
func fieldProbeTrusted(state string) bool { return state == "trusted" || state == "tofu" }

// findTestRelay looks through the held routes for the ones that carry a
// report address (family_specific_config._report_to — the publisher
// signs it into the Test pack), and among them for the route this test
// proves. It answers the relay, or a start refusal code:
//
//   - the main route is the first trusted vless REALITY route on 443 at
//     a public address that carries a report address; the report is
//     sealed to THAT route's own address, never another pack's;
//   - C7 / C8 routes come only from the same pack (RelayPackID) and the
//     same address;
//   - the Test relay's address must not be the address of any held
//     route without a report address (the family's daily relay).
func (c *Core) findTestRelay() (fieldProbeRelay, string) {
	rows, err := c.store.ListRoutes()
	if err != nil {
		return fieldProbeRelay{}, "no_report_key"
	}
	type cand struct {
		row  routestore.RouteRow
		ob   activeOutbound
		body []byte
		to   string
	}
	var cands []cand
	var daily []routestore.RouteRow
	anyKey := false
	for _, row := range rows {
		to := reportToOf(row.FamilySpecificConfigJSON)
		if to == "" {
			daily = append(daily, row)
			continue
		}
		if !fieldProbeTrusted(row.TrustState) {
			continue
		}
		anyKey = true
		c.mu.Lock()
		_, body, err := c.prepareRouteOpts(row.RouteID, false, true)
		c.mu.Unlock()
		if err != nil {
			continue
		}
		ob, ok := parseActiveOutbound(body)
		if !ok {
			continue
		}
		cands = append(cands, cand{row, ob, body, to})
	}
	if !anyKey {
		return fieldProbeRelay{}, "no_report_key"
	}
	var main *cand
	for i := range cands {
		cd := &cands[i]
		if cd.ob.typ == "vless" && cd.ob.reality && cd.ob.port == 443 && fieldprobe.IsPublicAddr(cd.ob.addr) &&
			engine.SideProbeable(cd.body) {
			main = cd
			break
		}
	}
	if main == nil {
		return fieldProbeRelay{}, "no_test_relay"
	}
	for _, row := range daily {
		if a, ok := c.routeAddr(row); ok && a == main.ob.addr {
			return fieldProbeRelay{}, "test_relay_shared"
		}
	}
	t := fieldprobe.RelayTarget{
		Addr: main.ob.addr, Port: main.ob.port, CoverName: main.ob.sni, PackID: main.row.RelayPackID,
		Main: main.row.RouteID, DesyncAvailable: c.fieldProbeCanDesync(main.row),
	}
	if _, err := engine.PackDesyncOffer(main.row); err == nil {
		t.DesyncOffer = true
	}
	for _, cd := range cands {
		if cd.row.RouteID == main.row.RouteID || cd.row.RelayPackID != main.row.RelayPackID ||
			cd.ob.addr != main.ob.addr || !engine.SideProbeable(cd.body) {
			continue
		}
		switch cd.ob.typ {
		case "hysteria2", "hysteria", "tuic":
			if t.QUIC == "" {
				t.QUIC = cd.row.RouteID
			}
		default:
			if cd.ob.port != 443 && len(t.Alt) < 2 {
				t.Alt = append(t.Alt, cd.row.RouteID)
			}
		}
	}
	return fieldProbeRelay{target: t, reportTo: main.to}, ""
}

// routeAddr is the address a held route dials (its built config's active
// outbound), whatever its cooldown or trust: only for comparing.
func (c *Core) routeAddr(row routestore.RouteRow) (netip.Addr, bool) {
	profile, err := c.store.GetSecret("route:" + row.RouteID)
	if err != nil {
		return netip.Addr{}, false
	}
	cfg, err := engine.BuildSingBoxConfig(row, profile)
	if err != nil {
		return netip.Addr{}, false
	}
	body, err := engine.MarshalSingBox(cfg)
	if err != nil {
		return netip.Addr{}, false
	}
	ob, ok := parseActiveOutbound(body)
	return ob.addr, ok
}

// fieldProbeCanDesync: may the route's hello be split at all?
func (c *Core) fieldProbeCanDesync(row routestore.RouteRow) bool {
	profile, err := c.store.GetSecret("route:" + row.RouteID)
	if err != nil {
		return false
	}
	return engine.RouteCanDesync(row, profile)
}

// activeOutbound is the part of a route's engine config the test reads:
// where the relay is and how it is spoken to. It stays in memory.
type activeOutbound struct {
	typ     string
	addr    netip.Addr
	port    uint16
	sni     string
	reality bool
}

// parseActiveOutbound reads the "active" outbound of an engine config.
// A server that is a name, not an address, is not used: the test does
// not resolve the relay.
func parseActiveOutbound(body []byte) (activeOutbound, bool) {
	var cfg struct {
		Outbounds []struct {
			Tag        string `json:"tag"`
			Type       string `json:"type"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			TLS        *struct {
				ServerName string `json:"server_name"`
				Reality    *struct {
					Enabled bool `json:"enabled"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(body, &cfg) != nil {
		return activeOutbound{}, false
	}
	for _, ob := range cfg.Outbounds {
		if ob.Tag != "active" {
			continue
		}
		a, err := netip.ParseAddr(ob.Server)
		if err != nil || ob.ServerPort <= 0 || ob.ServerPort > 65535 {
			return activeOutbound{}, false
		}
		out := activeOutbound{typ: ob.Type, addr: a.Unmap(), port: uint16(ob.ServerPort)}
		if ob.TLS != nil {
			out.sni = ob.TLS.ServerName
			out.reality = ob.TLS.Reality != nil && ob.TLS.Reality.Enabled
		}
		return out, true
	}
	return activeOutbound{}, false
}

// reportToOf reads _report_to from a route's family-specific config, and
// returns it only when it is a valid daal1… address.
func reportToOf(familyJSON string) string {
	if familyJSON == "" {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(familyJSON), &m) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(m["_report_to"], &s) != nil {
		return ""
	}
	if _, err := fieldreport.DecodeAddress(s); err != nil {
		return ""
	}
	return s
}

// ---- verbs --------------------------------------------------------------

// FieldProbeStart is engine_field_probe_start. It returns at once: the
// run goes on in the background and is read with FieldProbeStatus.
//
// Returns {"started":true,"of":N} or {"started":false,"refused":code,…}
// (rate_limited adds "retry_after_min"). The error is non-nil only for
// an engine that is not initialised or an argument that is not JSON.
func FieldProbeStart(optsJSON string) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	var o FieldProbeStartOpts
	if strings.TrimSpace(optsJSON) != "" {
		if err := json.Unmarshal([]byte(optsJSON), &o); err != nil {
			return "", fmt.Errorf("abi: field probe options: %w", err)
		}
	}
	fp := globalFieldProbe
	fp.mu.Lock()
	running := fp.running
	fp.mu.Unlock()
	if running {
		return fieldProbeRefuse("running", nil), nil
	}
	c.mu.Lock()
	shutting := c.shuttingDown
	c.mu.Unlock()
	if shutting {
		return "", errors.New("abi: shutting down")
	}
	sweepFieldProbeOut(c, false)
	if fieldProbeDaalBusy(c) {
		return fieldProbeRefuse("connected", nil), nil
	}
	facts := hostFacts()
	if o.VPNActive || (facts.seen && facts.kind == NetKindVPN) {
		return fieldProbeRefuse("vpn_active", nil), nil
	}
	if facts.noNetwork() {
		return fieldProbeRefuse("no_network", nil), nil
	}
	if o.Blocked {
		return fieldProbeRefuse("local_blocked", nil), nil
	}
	if o.ConsentVersion != fieldProbeConsentVersion {
		return fieldProbeRefuse("consent_required", map[string]any{"consent_version": fieldProbeConsentVersion}), nil
	}
	targets, err := fieldprobe.DefaultTargets()
	if err != nil {
		return "", err
	}
	relay, code := c.findTestRelay()
	if code != "" {
		return fieldProbeRefuse(code, nil), nil
	}
	netID := activeNetworkID()
	if ok, wait := loadFieldProbeHistory(c.store).Allow(netID, nowUTC()); !ok {
		return fieldProbeRefuse("rate_limited", map[string]any{"retry_after_min": int(wait.Minutes()) + 1}), nil
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	fp.mu.Lock()
	if fp.running {
		fp.mu.Unlock()
		cancel(nil)
		return fieldProbeRefuse("running", nil), nil
	}
	fp.running, fp.step, fp.of, fp.cancel, fp.done = true, 0, 0, cancel, make(chan struct{})
	done := fp.done
	hook := fp.envHook
	fp.mu.Unlock()

	resolvers := fieldprobe.ParseResolvers(o.DNSServers)
	if len(resolvers) == 0 {
		resolvers = fieldprobe.SystemResolvers()
	}
	dnsStrings := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		dnsStrings = append(dnsStrings, r.Addr().String())
	}
	kind := facts.kind
	if !facts.seen || kind == "" {
		kind = "unknown"
	}
	// What would make the run's measurements not this network's, without
	// a VPN: checked before every step and, between steps, by the watch
	// below, which cancels the step in flight.
	check := func() {
		switch {
		case fieldProbeDaalBusy(c):
			cancel(fieldprobe.ErrConnecting)
		case func() bool { f := hostFacts(); return f.seen && f.kind == NetKindVPN }():
			cancel(fieldprobe.ErrVPNActive)
		case activeNetworkID() != netID || hostFacts().noNetwork():
			cancel(fieldprobe.ErrNetworkChanged)
		}
	}
	env := fieldprobe.Env{
		Net:              fieldprobe.SysNet{Protect: fieldProbeProtect(c)},
		Relay:            &abiRelay{c: c, target: relay.target},
		Targets:          targets,
		Resolvers:        resolvers,
		PrivateDNSStrict: o.PrivateDNS == "strict",
		// No per-step lines: on Android they would go to logcat, which
		// says a network test ran. Start, end and refusals are logged.
		Log: nil,
		// The allowance is charged when the first packet goes out, not
		// when the page asked: a run that stops before then costs
		// nothing.
		OnFirstSend: func() {
			h := loadFieldProbeHistory(c.store)
			h.Note(netID, nowUTC())
			saveFieldProbeJSON(c.store, fieldProbeHistoryKey, h)
		},
	}
	env.Progress = func(step, of int) {
		fp.mu.Lock()
		fp.step, fp.of = step, of
		fp.mu.Unlock()
		check()
	}
	if hook != nil {
		hook(&env)
	}
	engine.LogInfo(fmt.Sprintf("fieldprobe start kind=%s label=%s resolvers=%d", kind, fieldProbeLogWord(o.NetworkLabel), len(resolvers)))

	go func() {
		t := time.NewTicker(fieldProbeWatchEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				check()
			}
		}
	}()
	go func() {
		defer close(done)
		defer cancel(nil)
		res := fieldprobe.Run(ctx, env)
		r, err := fieldprobe.BuildReport(res, fieldprobe.Meta{
			Platform: fieldProbePlatform(), NetKind: kind, Validated: facts.validated, Metered: facts.metered,
			IPv6Global: o.IPv6Global, PrivateDNS: o.PrivateDNS, Resolvers: dnsStrings,
			NetworkLabel: o.NetworkLabel, Build: fieldProbeBuild(), Targets: targets, Now: nowUTC(),
		})
		dnsStrings = nil
		if err != nil {
			engine.LogInfo("fieldprobe report not built: " + fieldProbeErrClass(err))
		} else {
			sr := storedResult{At: nowUTC().Truncate(time.Hour).Unix(), NetKind: kind, ReportTo: relay.reportTo, Report: r,
				Summary: fieldprobe.Summary(res, r.Findings)}
			// Filed even while Shutdown waits for this goroutine: the
			// store is closed only after it has returned.
			saveFieldProbeJSON(c.store, fieldProbeResultPrefix+kind, sr)
			engine.LogInfo(fmt.Sprintf("fieldprobe end complete=%t abort=%s steps=%d conns=%d",
				res.Complete, fieldProbeLogWord(res.AbortReason), res.StepsRun, res.Conns))
		}
		fp.mu.Lock()
		fp.running = false
		fp.cancel = nil
		fp.mu.Unlock()
	}()
	return fieldProbeJSON(map[string]any{"started": true, "of": 0}), nil
}

// fieldProbeWatchEvery is how often a running test looks at Daal's own
// state and the host's network facts between its own checks.
var fieldProbeWatchEvery = 250 * time.Millisecond

// fieldProbeDaalBusy: Daal has a route up, or is connecting one.
func fieldProbeDaalBusy(c *Core) bool {
	c.mu.Lock()
	active := c.activeRoute
	c.mu.Unlock()
	as, _ := c.auto.snapshot()
	return active != "" || as == AutoStateTrying
}

// fieldProbeProtect is the run's protect(): engine.ProtectFD, the
// callback sing-box's sockets go through. A refusal matters only while
// a Daal tunnel could take the socket: on Android the callback stays
// registered after a disconnect, and the host's protect then refuses
// every socket (its VpnService is gone), although with no TUN there is
// nothing to bypass. Treating that refusal as fatal made every probe
// fail on the device — the exact "VPN off, then run" flow. So: refused
// with no TUN and no route = fine; refused otherwise = the socket is
// not sent (local_error).
func fieldProbeProtect(c *Core) func(fd int) error {
	return func(fd int) error {
		err := engine.ProtectFD(fd)
		if err == nil {
			return nil
		}
		c.mu.Lock()
		active := c.activeRoute
		c.mu.Unlock()
		if engine.CurrentTunFD() < 0 && active == "" {
			return nil
		}
		return err
	}
}

// fieldProbeOffered: does any trusted held route carry a report address
// (the page offers the test only then), and whose is the first such
// route (its publisher_id, so the page can say whose test relay it is
// in the words it already uses for that publisher). Cheap: no route is
// prepared, nothing is proved — start still decides everything.
func (c *Core) fieldProbeOffered() (bool, string) {
	rows, err := c.store.ListRoutes()
	if err != nil {
		return false, ""
	}
	for _, row := range rows {
		if fieldProbeTrusted(row.TrustState) && reportToOf(row.FamilySpecificConfigJSON) != "" {
			return true, row.PublisherID
		}
	}
	return false, ""
}

// FieldProbeStatus is engine_field_probe_status.
//
//	{"state":"running","step":7,"of":24}
//	{"state":"done"|"aborted","net_kind":"wifi","report":{…v2…},
//	 "summary":["netTest.summary.…",…],"complete":bool,"abort_reason":"…",
//	 "has_test_relay":bool,"publisher_id":"…"}
//	{"state":"idle","plan":{…what is tested…},"has_test_relay":bool,"publisher_id":"…"}
//
// done/aborted is the most recent kept result (any network kind), so the
// "a result is ready" row can be shown after the next connect.
// has_test_relay: a trusted held route carries a report address; the page
// offers the test only then. publisher_id: that route's publisher ("" when
// none).
func FieldProbeStatus() (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	fp := globalFieldProbe
	fp.mu.Lock()
	running, step, of := fp.running, fp.step, fp.of
	fp.mu.Unlock()
	if running {
		return fieldProbeJSON(map[string]any{"state": FieldProbeRunning, "step": step, "of": of}), nil
	}
	fieldProbeSweep(c.store, nowUTC())
	sweepFieldProbeOut(c, false)
	offered, publisherID := c.fieldProbeOffered()
	if sr, ok := latestFieldProbeResult(c.store); ok {
		state := FieldProbeDone
		if !sr.Report.Run.Complete {
			state = FieldProbeAborted
		}
		return fieldProbeJSON(map[string]any{
			"state": state, "net_kind": sr.NetKind, "report": sr.Report, "summary": sr.Summary,
			"complete": sr.Report.Run.Complete, "abort_reason": sr.Report.Run.AbortReason,
			"has_test_relay": offered, "publisher_id": publisherID,
		}), nil
	}
	t, err := fieldprobe.DefaultTargets()
	if err != nil {
		return "", err
	}
	resolver, _, _ := strings.Cut(t.PublicResolver, ":")
	return fieldProbeJSON(map[string]any{"state": FieldProbeIdle, "plan": map[string]any{
		"steps": fieldprobe.MaxSteps, "max_connections": fieldprobe.DefaultMaxConns,
		"max_relay_connections": fieldprobe.MaxRelayFlows, "minutes": 4,
		"consent_version": fieldProbeConsentVersion, "targets_version": t.Version,
		"names": fieldProbeUnique(t.Names()), "public_resolver": resolver,
	}, "has_test_relay": offered, "publisher_id": publisherID}), nil
}

// FieldProbeCancel is engine_field_probe_cancel. reason: "" (the person
// cancelled), "backgrounded", "network_changed", "vpn_active" (the
// host's NetworkCallback saw TRANSPORT_VPN), "connecting". The partial
// result is kept. Returns whether a run was going.
func FieldProbeCancel(reason string) bool {
	fp := globalFieldProbe
	fp.mu.Lock()
	cancel := fp.cancel
	fp.mu.Unlock()
	if cancel == nil {
		return false
	}
	cause := fieldprobe.ErrCancelled
	switch reason {
	case "backgrounded":
		cause = fieldprobe.ErrBackgrounded
	case "network_changed":
		cause = fieldprobe.ErrNetworkChanged
	case "vpn_active":
		cause = fieldprobe.ErrVPNActive
	case "connecting":
		cause = fieldprobe.ErrConnecting
	}
	cancel(cause)
	return true
}

// FieldProbeSealOpts is engine_field_probe_seal's argument.
type FieldProbeSealOpts struct {
	Notes string `json:"notes"`
	// Transient: the file exists only for a share. The ENGINE picks
	// where: <state_dir>/fieldprobe-out/, so engine_panic_wipe takes it
	// with everything else even if the process dies between the share
	// and the discard; out_path is ignored. Deleted on discard, at
	// shutdown, and by the first network-test call of the next process.
	// (Android: the shell's FileProvider must expose that folder.)
	Transient bool `json:"transient"`
	// OutPath, for a non-transient file only: a directory (the file gets
	// its neutral name there) or a full file path, chosen by the SHELL
	// (a save dialog), never taken from the page.
	OutPath string `json:"out_path"`
	// NetKind picks a kept result; "" = the most recent.
	NetKind string `json:"net_kind"`
}

// FieldProbeSeal is engine_field_probe_seal: the kept result, with the
// person's note, validated, padded and sealed to the report address; the
// file is written with mode 0600. Returns {"sealed":true,"path","file_name",
// "bytes"} or {"sealed":false,"refused":"no_result"|"notes_too_long"|"running"}.
func FieldProbeSeal(optsJSON string) (string, error) {
	c := loadedCore()
	if c == nil {
		return "", errors.New("abi: not initialized")
	}
	var o FieldProbeSealOpts
	if err := json.Unmarshal([]byte(optsJSON), &o); err != nil {
		return "", fmt.Errorf("abi: field probe seal options: %w", err)
	}
	if !o.Transient && o.OutPath == "" {
		return "", errors.New("abi: field probe seal: out_path is required unless transient")
	}
	refuse := func(code string) (string, error) {
		return fieldProbeJSON(map[string]any{"sealed": false, "refused": code}), nil
	}
	fp := globalFieldProbe
	fp.mu.Lock()
	running := fp.running
	fp.mu.Unlock()
	if running {
		return refuse("running")
	}
	fieldProbeSweep(c.store, nowUTC())
	var sr storedResult
	var ok bool
	if o.NetKind != "" {
		ok = loadFieldProbeJSON(c.store, fieldProbeResultPrefix+o.NetKind, &sr) && sr.Report != nil
	} else {
		sr, ok = latestFieldProbeResult(c.store)
	}
	if !ok {
		return refuse("no_result")
	}
	if len([]rune(o.Notes)) > fieldreport.MaxNotes {
		return refuse("notes_too_long")
	}
	r := *sr.Report
	r.Notes = strings.TrimSpace(o.Notes)
	sealed, err := fieldreport.Seal(&r, sr.ReportTo)
	if err != nil {
		return "", fmt.Errorf("abi: field probe seal: %s", fieldProbeErrClass(err))
	}
	path := o.OutPath
	if o.Transient {
		dir, err := fieldProbeOutDir(c)
		if err != nil {
			return "", fmt.Errorf("abi: field probe seal: %s", fieldProbeErrClass(err))
		}
		path = dir
	}
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		path = filepath.Join(path, fieldreport.SealedFileName())
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return "", fmt.Errorf("abi: field probe seal: write: %s", fieldProbeErrClass(err))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("abi: field probe seal: write: %s", fieldProbeErrClass(err))
	}
	if o.Transient {
		fp.mu.Lock()
		fp.transient = append(fp.transient, path)
		fp.mu.Unlock()
	}
	engine.LogInfo(fmt.Sprintf("fieldprobe sealed bytes=%d transient=%t", len(sealed), o.Transient))
	return fieldProbeJSON(map[string]any{"sealed": true, "path": path, "file_name": filepath.Base(path), "bytes": len(sealed)}), nil
}

// FieldProbeDiscard is engine_field_probe_discard: every kept result and
// every transient sealed file is deleted. A run in progress is
// cancelled first. Returns how many results were deleted.
func FieldProbeDiscard() (int, error) {
	c := loadedCore()
	if c == nil {
		return 0, errors.New("abi: not initialized")
	}
	waitFieldProbe(fieldprobe.ErrCancelled, fieldProbeShutdownWait)
	removeTransientFieldProbeFiles()
	sweepFieldProbeOut(c, true)
	keys, _ := c.store.ListSecretKeys(fieldProbeResultPrefix)
	for _, k := range keys {
		_ = c.store.DeleteSecret(k)
	}
	engine.LogInfo(fmt.Sprintf("fieldprobe discarded results=%d", len(keys)))
	return len(keys), nil
}

// resetFieldProbeForShutdown: Shutdown (and so PanicWipe, which deletes
// the state directory the results live in right after) stops a run in
// progress — its partial result is still filed while the store is open
// — and deletes every transient sealed file.
func resetFieldProbeForShutdown() {
	waitFieldProbe(fieldprobe.ErrShutdown, fieldProbeShutdownWait)
	removeTransientFieldProbeFiles()
}

func waitFieldProbe(cause error, max time.Duration) {
	fp := globalFieldProbe
	fp.mu.Lock()
	cancel, done := fp.cancel, fp.done
	fp.mu.Unlock()
	if cancel == nil || done == nil {
		return
	}
	cancel(cause)
	select {
	case <-done:
	case <-time.After(max):
	}
}

func removeTransientFieldProbeFiles() {
	fp := globalFieldProbe
	fp.mu.Lock()
	files, dir := fp.transient, fp.outDir
	fp.transient = nil
	fp.mu.Unlock()
	for _, f := range files {
		_ = os.Remove(f)
	}
	if dir != "" {
		removeFieldProbeOut(dir, 0)
	}
}

// fieldProbeOutDirName is the folder of transient sealed files, inside
// the state directory.
const fieldProbeOutDirName = "fieldprobe-out"

// fieldProbeOutStale: a transient file older than this is no longer
// being shared; status sweeps it.
const fieldProbeOutStale = time.Hour

func fieldProbeOutDir(c *Core) (string, error) {
	dir := filepath.Join(c.stateDir, fieldProbeOutDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fp := globalFieldProbe
	fp.mu.Lock()
	fp.outDir = dir
	fp.mu.Unlock()
	return dir, nil
}

// sweepFieldProbeOut: the first network-test call of a process deletes
// every transient file a previous process left (it died between the
// share and the discard); later calls delete the stale ones.
func sweepFieldProbeOut(c *Core, all bool) {
	if c.stateDir == "" {
		return
	}
	dir := filepath.Join(c.stateDir, fieldProbeOutDirName)
	fp := globalFieldProbe
	fp.mu.Lock()
	first := fp.sweptFor != c
	fp.sweptFor = c
	fp.mu.Unlock()
	switch {
	case all || first:
		removeFieldProbeOut(dir, 0)
	default:
		removeFieldProbeOut(dir, fieldProbeOutStale)
	}
}

// removeFieldProbeOut deletes the sealed files in dir older than age (0:
// all of them). Only files this engine writes there are touched.
func removeFieldProbeOut(dir string, age time.Duration) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "net-") || !(strings.HasSuffix(name, ".dat") || strings.HasSuffix(name, ".dat.part")) {
			continue
		}
		if age > 0 {
			if fi, err := e.Info(); err != nil || now.Sub(fi.ModTime()) < age {
				continue
			}
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// fieldProbeSweep deletes kept results older than fieldprobe.ResultTTL.
// Run on every status/seal; the scheduler's hourly sweep can call it too.
func fieldProbeSweep(s *routestore.Store, now time.Time) {
	keys, err := s.ListSecretKeys(fieldProbeResultPrefix)
	if err != nil {
		return
	}
	for _, k := range keys {
		var sr storedResult
		if !loadFieldProbeJSON(s, k, &sr) || now.Sub(time.Unix(sr.At, 0)) > fieldprobe.ResultTTL {
			_ = s.DeleteSecret(k)
		}
	}
}

func latestFieldProbeResult(s *routestore.Store) (storedResult, bool) {
	keys, err := s.ListSecretKeys(fieldProbeResultPrefix)
	if err != nil {
		return storedResult{}, false
	}
	var best storedResult
	found := false
	for _, k := range keys {
		var sr storedResult
		if loadFieldProbeJSON(s, k, &sr) && sr.Report != nil && (!found || sr.At > best.At) {
			best, found = sr, true
		}
	}
	return best, found
}

func loadFieldProbeHistory(s *routestore.Store) fieldprobe.History {
	var h fieldprobe.History
	_ = loadFieldProbeJSON(s, fieldProbeHistoryKey, &h)
	return h
}

func loadFieldProbeJSON(s *routestore.Store, key string, v any) bool {
	b, err := s.GetSecret(key)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

func saveFieldProbeJSON(s *routestore.Store, key string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	if err := s.PutSecret(key, b); err != nil {
		engine.LogInfo("fieldprobe store write failed: " + fieldProbeErrClass(err))
	}
}

// ---- the Test relay through the side instance ----------------------------

// abiRelay proves the Test relay's routes in the driver's side
// instance. Each proof's hello split is handed to THAT config build
// (engine.BuildSingBoxConfigWithDesync): nothing remembered for the
// route is changed, so a connect racing the test (or a test cut short)
// never inherits a split the test was trying.
type abiRelay struct {
	c      *Core
	target fieldprobe.RelayTarget
}

func (r *abiRelay) Target() (fieldprobe.RelayTarget, bool) { return r.target, r.target.Main != "" }

func (r *abiRelay) Prove(ctx context.Context, handle, how string) fieldprobe.RelayOutcome {
	c := r.c
	// The refusals a connect would meet (revoked, expired, endpoint
	// guard) still apply; the cooldown does not — this is one proof.
	c.mu.Lock()
	row, _, err := c.prepareRouteOpts(handle, false, true)
	cfg := c.proofCfg
	prober := c.sideProber()
	c.mu.Unlock()
	if err != nil || prober == nil {
		return fieldprobe.RelayOutcome{Unsupported: true}
	}
	var st desync.Strategy
	switch how {
	case "off", "":
		st = desync.Off
	case "pack":
		o, err := engine.PackDesyncOffer(row)
		if err != nil {
			return fieldprobe.RelayOutcome{Unsupported: true}
		}
		st = o.StrategyValue()
	default:
		st = desync.Strategy{Preset: how}
	}
	profile, err := c.store.GetSecret("route:" + handle)
	if err != nil {
		return fieldprobe.RelayOutcome{Unsupported: true}
	}
	sbc, err := engine.BuildSingBoxConfigWithDesync(row, profile, st)
	if err != nil {
		return fieldprobe.RelayOutcome{Unsupported: true}
	}
	body, err := engine.MarshalSingBox(sbc)
	if err != nil || !prober.CanSideProbe(body) {
		return fieldprobe.RelayOutcome{Unsupported: true}
	}
	// One attempt, 12 s, no slow-path extension: the test never retries.
	cfg.Attempts = 1
	cfg.AttemptTimeout = 12 * time.Second
	cfg.SlowBudget = time.Nanosecond
	cfg.StopAtUnreachedRelay = true
	res, perr := prober.SideProbe(ctx, body, cfg)
	if perr != nil {
		return fieldprobe.RelayOutcome{Unsupported: true}
	}
	return fieldprobe.RelayOutcome{OK: res.OK, Cancelled: res.Cancelled, Obs: res.Observation}
}

// Restore: nothing to put back (see abiRelay).
func (r *abiRelay) Restore() {}

// ---- small helpers --------------------------------------------------------

func fieldProbePlatform() string {
	switch runtime.GOOS {
	case "android", "linux", "windows", "ios":
		return runtime.GOOS
	case "darwin":
		return "macos"
	}
	return "unknown"
}

func fieldProbeBuild() string {
	return strings.NewReplacer(" ", "-").Replace(Version)
}

// logLabel keeps a log field to the closed shape of a label or code.
func fieldProbeLogWord(s string) string {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c == '_' || c >= '0' && c <= '9') {
			return "other"
		}
	}
	if s == "" {
		return "none"
	}
	return s
}

// errorClass is the Go type of the innermost error: never its text,
// which can carry a path or an address.
func fieldProbeErrClass(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return fmt.Sprintf("%T", err)
		}
		err = inner
	}
}

func fieldProbeUnique(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
