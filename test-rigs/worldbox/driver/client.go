package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is one INSIDER session: a wb-client process (the real engine
// plus the lab's VpnService) in the client namespace, with a fresh state
// directory — a phone that has never seen this pack before.
type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	events chan map[string]any
	mu     sync.Mutex
	seen   []map[string]any
	done   chan struct{}
	Dir    string
	// stopping: Stop was called. An exit before that is a death.
	stopping bool
	// exit: how the process ended ("exit status 2", "signal: killed",
	// "exit status 0"), set before done closes. A death that leaves
	// stderr empty is otherwise unexplained (seen 2026-11-19).
	exit string
}

type ClientOpts struct {
	Pack         string
	Family       string
	Experimental bool
	ImportOnly   bool
	// Idle: import, then wait for commands (Client.Send) instead of
	// connecting — a phone that holds a pack with the VPN off.
	Idle bool
	// Auto: import, then wait for commands and connect the way the main
	// screen's one button does (labclient/auto.go): `auto`, no route named.
	Auto bool
	// LivenessS / RecheckS: the engine's liveness clocks for this phone
	// (seconds; 0 = the production 180 s / 30 s), through the engine's own
	// configuration file.
	LivenessS, RecheckS int
	// Hosts / CAFile: the phone's view of the public internet for names
	// the lab hosts itself (ops_freshness.go): an /etc/hosts to see
	// instead of the laptop's, and the lab CA as the system trust store.
	// Neither touches any product trust decision.
	Hosts  string
	CAFile string
	// EngineLog: the engine's own log lines (already scrubbed by the
	// engine) go to the phone's stderr.log (DAAL_ENGINE_LOG, the engine's
	// switch for exactly that off Android).
	EngineLog bool
	// Desync: a core/desync strategy (JSON) the phone's selection ladder
	// has turned on for the route it connects — wb-client hands it to
	// the engine (engine.SetRouteDesync) before SetRoute, which is all
	// the ladder will do. Empty: off, as on every phone today.
	Desync string
}

var clientSeq int

// ProofTargets is what the engine's connection check dials through the
// tunnel in this world: the "every other website" host and the release
// mirror, both TLS on 443 on the lab's internet. Two, so the engine's
// "try a different target before calling the route dead" is exercised.
var ProofTargets = CoverIP + ":443," + MirrorIP + ":443"

// StageProof is the stage of a wb-client error event when the engine
// started the route, tried a round trip through it and got none: it
// dialled and was stopped, which is "blocked", not "refused".
const StageProof = "proof"

// StartClient launches the session. It returns as soon as the process is
// running; use Wait for the outcome.
func StartClient(p Paths, label string, o ClientOpts) (*Client, error) {
	clientSeq++
	dir := filepath.Join(p.Run, "clients", fmt.Sprintf("%02d-%s", clientSeq, label))
	// The engine's state directory lives in memory (the world's private
	// /run): the engine fsyncs its way through init and import, a session
	// is a fresh phone every time, and on a laptop SSD those fsyncs were
	// most of a session's wall time (0.5 s of 0.6) — a third of the whole
	// quick matrix. WB_STATE_ON_DISK=1 keeps it under the evidence
	// directory instead, for when the state itself is what you are after.
	state := filepath.Join("/run", "wb-state", filepath.Base(dir))
	if os.Getenv("WB_STATE_ON_DISK") != "" {
		state = filepath.Join(dir, "state")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	args := []string{filepath.Join(p.Bin, "wb-client"), "--state-dir", state, "--pack", o.Pack,
		// The engine's connection check must reach a host beyond the
		// relay; in this world that is the lab's own internet (two TLS
		// sites the relay can reach), named through the engine's ordinary
		// configuration file. See labclient --proof-targets.
		"--proof-targets", ProofTargets}
	if o.Family != "" {
		args = append(args, "--family", o.Family)
	}
	if o.Experimental {
		args = append(args, "--experimental")
	}
	if o.ImportOnly {
		args = append(args, "--import-only")
	}
	if o.Idle {
		args = append(args, "--idle")
	}
	if o.Auto {
		args = append(args, "--auto")
	}
	if o.LivenessS > 0 {
		args = append(args, "--liveness-s", strconv.Itoa(o.LivenessS))
	}
	if o.RecheckS > 0 {
		args = append(args, "--recheck-s", strconv.Itoa(o.RecheckS))
	}
	if o.Desync != "" {
		args = append(args, "--desync", o.Desync)
	}
	if o.Hosts != "" {
		args = append([]string{"unshare", "--mount", "--propagation", "private", "sh", "-c",
			`mount --bind "$WB_HOSTS" /etc/hosts && exec "$@"`, "sh"}, args...)
	}
	argv := inNS(NSClient, args...)
	cmd := exec.Command(argv[0], argv[1:]...)
	if o.Hosts != "" || o.CAFile != "" || o.EngineLog {
		cmd.Env = os.Environ()
		if o.EngineLog {
			cmd.Env = append(cmd.Env, "DAAL_ENGINE_LOG=1")
		}
		if o.Hosts != "" {
			cmd.Env = append(cmd.Env, "WB_HOSTS="+o.Hosts)
		}
		if o.CAFile != "" {
			cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+o.CAFile)
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	errf, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		return nil, err
	}
	cmd.Stderr = errf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	errf.Close()
	c := &Client{cmd: cmd, stdin: stdin, events: make(chan map[string]any, 256), done: make(chan struct{}), Dir: dir}
	evf, _ := os.Create(filepath.Join(dir, "events.jsonl"))
	go func() {
		// events closes AFTER done (defers run last-in first-out): whoever
		// learns of the exit from the closed events channel (Wait) must
		// already find Died() true, not race it.
		defer close(c.events)
		defer close(c.done)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<16), 8<<20)
		for sc.Scan() {
			if evf != nil {
				evf.Write(append(append([]byte{}, sc.Bytes()...), '\n'))
			}
			var ev map[string]any
			if json.Unmarshal(sc.Bytes(), &ev) != nil {
				continue
			}
			c.mu.Lock()
			c.seen = append(c.seen, ev)
			c.mu.Unlock()
			c.events <- ev
		}
		if evf != nil {
			evf.Close()
		}
		werr := cmd.Wait()
		c.mu.Lock()
		if werr != nil {
			c.exit = werr.Error()
		} else {
			c.exit = "exit status 0"
		}
		c.mu.Unlock()
	}()
	return c, nil
}

// Wait blocks until an event named one of `want` arrives, an "error"
// event arrives, the process exits, or the timeout passes.
func (c *Client) Wait(ctx context.Context, d time.Duration, want ...string) (map[string]any, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-c.events:
			if !ok {
				return nil, fmt.Errorf("client exited before %v", want)
			}
			name, _ := ev["event"].(string)
			if name == "error" {
				return ev, fmt.Errorf("%v: %v", ev["stage"], ev["error"])
			}
			for _, w := range want {
				if name == w {
					return ev, nil
				}
			}
		case <-timer.C:
			return nil, fmt.Errorf("timeout after %s waiting for %v", d, want)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Event returns the first recorded event with the given name.
func (c *Client) Event(name string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.seen {
		if ev["event"] == name {
			return ev
		}
	}
	return nil
}

// Send writes one command line to the session (see wb-client --idle).
func (c *Client) Send(line string) error {
	_, err := io.WriteString(c.stdin, line+"\n")
	return err
}

// Stop asks the session to disconnect cleanly and waits for it.
func (c *Client) Stop() map[string]any {
	c.mu.Lock()
	c.stopping = true
	c.mu.Unlock()
	_, _ = io.WriteString(c.stdin, "stop\n")
	_ = c.stdin.Close()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	return c.Event("disconnected")
}

// Died reports whether the engine process is gone although nobody asked
// it to stop: a crash. (A session the engine REFUSES ends with an error
// event and a clean exit only after Stop.)
//
// The client gives up on a session it cannot carry by saying why (an
// "error" event) and leaving with status 1 at once, without waiting for
// Stop. The driver learns of the refusal from the event and usually asks
// Died() before the process is gone; on a busy machine the exit can win
// that race. That is still a refusal, not a death: a crash leaves by a
// signal or with the Go runtime's status 2 and says nothing in an
// "error" event. (Seen 2026-11-19: two quick runs red on
// `wrongserver…engine.survived` with an empty stderr.)
func (c *Client) Died() bool {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.stopping {
			return false
		}
		return !gaveUpCleanly(c.exit, c.seen)
	default:
		return false
	}
}

// gaveUpCleanly: the process left with status 1 after an "error" event.
func gaveUpCleanly(exit string, seen []map[string]any) bool {
	if exit != "exit status 1" {
		return false
	}
	for _, ev := range seen {
		if ev["event"] == "error" {
			return true
		}
	}
	return false
}

// CrashSignature condenses the dead process's stderr into one line: the
// runtime's own headline and the first frames that name who was running.
func (c *Client) CrashSignature() string {
	body, _ := os.ReadFile(filepath.Join(c.Dir, "stderr.log"))
	lines := strings.Split(string(body), "\n")
	var sig []string
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "/") || strings.HasPrefix(l, "PC=") {
			continue
		}
		if i < 4 && !strings.HasPrefix(l, "goroutine ") { // SIGSEGV: … / signal arrived during cgo execution / panic: …
			sig = append(sig, l)
			continue
		}
		if strings.Contains(l, "(") && (strings.Contains(l, "cronet") || strings.Contains(l, "sing-box") || strings.Contains(l, "daal/")) {
			sig = append(sig, l[:strings.LastIndex(l, "(")]) // drop the argument list, keep "(*T).Method"
			if len(sig) >= 6 {
				break
			}
		}
		if i > 60 {
			break
		}
	}
	c.mu.Lock()
	exit := c.exit
	c.mu.Unlock()
	if exit != "" {
		exit = " (" + exit + ")"
	}
	if len(sig) == 0 {
		return "the process exited without a word on stderr" + exit
	}
	return strings.Join(sig, " | ") + exit
}

// StderrTail is what the engine process itself last complained about:
// the native network stack (Cronet) logs there and nowhere else. It is
// appended to a failed session's red checks, so a failure carries its
// cause instead of only its symptom ("EOF").
func (c *Client) StderrTail() string {
	body, _ := os.ReadFile(filepath.Join(c.Dir, "stderr.log"))
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, "] "); strings.HasPrefix(l, "[") && i > 0 { // Chromium's "[MMDD/HHMMSS.uuuuuu:ERROR:file.cc:123] "
			l = l[i+2:]
		}
		if l != "" && (len(keep) == 0 || keep[len(keep)-1] != l) {
			keep = append(keep, l)
		}
	}
	if len(keep) > 2 {
		keep = keep[len(keep)-2:]
	}
	return oneLine(strings.Join(keep, " / "), 300)
}

// ReapDeadVPN does what Android does when a VPN app dies: the routing
// that sent every app into its tunnel goes away with it. wb-client
// removes its own rule on a clean exit (labclient/vpnservice.go); a
// crashed one cannot, and the next session would find the rule in place.
func ReapDeadVPN(ctx context.Context) {
	_, _ = sh(ctx, inNS(NSClient, "ip", "rule", "del", "priority", "200")...)
	_, _ = sh(ctx, inNS(NSClient, "ip", "route", "flush", "table", "51820")...)
}

// AppUID is the uid the probe runs as inside the client namespace: an
// ordinary app, as opposed to the VPN app (wb-client, uid 0). The lab's
// VpnService routes by uid exactly as Android does.
const AppUID = 10100

// Probe runs the app-on-the-phone probe in the client namespace: the TCP
// round trip, plus UDP when udp is set.
func Probe(ctx context.Context, p Paths, udp bool, timeout time.Duration) ProbeResult {
	return ProbeApp(ctx, p, udp, false, 0, timeout)
}

// SessionBurst is how many connections a session opens at once on top of
// the payload legs: a phone's apps all reconnect the moment the VPN is up.
const SessionBurst = 32

// ProbeApp is Probe with every leg selectable: UDP datagrams, the phone's
// name resolution, and a burst of simultaneous connections.
func ProbeApp(ctx context.Context, p Paths, udp, dns bool, burst int, timeout time.Duration) ProbeResult {
	args := []string{filepath.Join(p.Bin, "wb"), "probe", "--uid", strconv.Itoa(AppUID), "--timeout", timeout.String()}
	if udp {
		args = append(args, "--udp")
	}
	if dns {
		args = append(args, "--dns")
	}
	if burst > 0 {
		args = append(args, "--burst", strconv.Itoa(burst))
	}
	argv := inNS(NSClient, args...)
	return runProbeCmd(ctx, argv)
}

// ProbeWhoami is the app's smallest possible exchange: one fresh nonce to
// the target and back, and the address the target saw it come from.
func ProbeWhoami(ctx context.Context, p Paths, timeout time.Duration) ProbeResult {
	return runProbeCmd(ctx, inNS(NSClient, filepath.Join(p.Bin, "wb"), "probe", "--uid", strconv.Itoa(AppUID),
		"--whoami-only", "--timeout", timeout.String()))
}

func parseProbe(out []byte, err error) ProbeResult {
	var res ProbeResult
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		res.Error = fmt.Sprintf("probe produced no result: %v / %v", err, jerr)
	}
	return res
}
