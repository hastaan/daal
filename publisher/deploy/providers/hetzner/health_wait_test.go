package hetzner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

type progressLine struct {
	step, msg string
	extra     map[string]any
}

type progressLog struct {
	mu    sync.Mutex
	lines []progressLine
}

func (l *progressLog) data(step, msg string, extra map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, progressLine{step, msg, extra})
}

func (l *progressLog) plain(step, msg string) { l.data(step, msg, nil) }

func (l *progressLog) steps(step string) []progressLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []progressLine
	for _, ln := range l.lines {
		if ln.step == step {
			out = append(out, ln)
		}
	}
	return out
}

// fastHealthWait runs the real wait loop in milliseconds against port
// on 127.0.0.1, and restores the package knobs afterwards.
func fastHealthWait(t *testing.T, port int, attempts int, up443 bool) {
	t.Helper()
	oldMax, oldIv, oldPort, oldAfter, oldRe, old443 := healthMaxAttempts, healthInterval, healthPollPort, notAnsweringAfter, notAnsweringRecheck, relay443Up
	t.Cleanup(func() {
		healthMaxAttempts, healthInterval, healthPollPort, notAnsweringAfter, notAnsweringRecheck, relay443Up = oldMax, oldIv, oldPort, oldAfter, oldRe, old443
	})
	healthMaxAttempts = attempts
	healthInterval = 2 * time.Millisecond
	healthPollPort = port
	notAnsweringAfter = 0
	notAnsweringRecheck = 0
	relay443Up = func(context.Context, net.IP) bool { return up443 }
}

// closedPort returns a local port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func waitRec() (*provider.OperatorRecord, *ServerInfo) {
	return &provider.OperatorRecord{ServerID: "srv-1", PublicIP: net.ParseIP("127.0.0.1")}, &ServerInfo{ID: "srv-1"}
}

// The wait says, on every try, which try it is, how long it has been
// and which address the firewall window was opened for: the address
// is what showed the 5G bug (a window for the phone's IPv6 address
// while the box was reached over IPv4).
func TestWaitForHealthyLiveLineNamesTryAndWindow(t *testing.T) {
	fastHealthWait(t, closedPort(t), 4, false)
	p := New(newFake())
	rec, srv := waitRec()
	log := &progressLog{}
	opts := provider.ProvisionOpts{HelperIP: net.ParseIP("90.1.2.3"), OnProgressData: log.data}

	err := p.waitForHealthy(context.Background(), rec, srv, "tok", opts, log.plain)
	if err == nil || !strings.Contains(err.Error(), "timed out after 4 attempts") {
		t.Fatalf("err = %v, want the timeout", err)
	}
	waits := log.steps("provision_health_wait")
	if len(waits) != 4 {
		t.Fatalf("%d live lines, want one per try (4)", len(waits))
	}
	for i, w := range waits {
		if got := w.extra["attempt"]; got != i+1 {
			t.Errorf("line %d attempt = %v", i, got)
		}
		if w.extra["max_attempts"] != 4 || w.extra["helper_ip"] != "90.1.2.3" {
			t.Errorf("line %d extra = %v", i, w.extra)
		}
		want := "(try " + strconv.Itoa(i+1) + " of 4, "
		if !strings.Contains(w.msg, want) || !strings.Contains(w.msg, "window open for 90.1.2.3") {
			t.Errorf("line %d = %q", i, w.msg)
		}
	}
	var sawWindow bool
	for _, fw := range log.steps("provision_cloud_firewall") {
		if fw.extra["port"] == healthPort && strings.Contains(fw.msg, "for 90.1.2.3") {
			sawWindow = true
		}
		if fw.extra["port"] == 22 && !strings.HasPrefix(fw.msg, optionalLogViewer) {
			t.Errorf("SSH window line is not marked optional: %q", fw.msg)
		}
	}
	if !sawWindow {
		t.Error("no line names the address the health window was opened for")
	}
	// Port 443 is shut here: a box that is not up is not "up but not
	// answering".
	if n := len(log.steps("provision_health_unreachable")); n != 0 {
		t.Errorf("%d unreachable lines for a box whose 443 is shut", n)
	}
	for _, ln := range log.steps("provision_ssh_debug") {
		if !strings.HasPrefix(ln.msg, optionalLogViewer) {
			t.Errorf("SSH observer line not marked optional: %q", ln.msg)
		}
	}
}

// Never answered, 443 up: said once, and the wait still runs to its
// limit.
func TestWaitForHealthySaysUpButNotAnsweringOnce(t *testing.T) {
	fastHealthWait(t, closedPort(t), 5, true)
	p := New(newFake())
	rec, srv := waitRec()
	log := &progressLog{}
	opts := provider.ProvisionOpts{HelperIP: net.ParseIP("90.1.2.3"), OnProgressData: log.data}

	if err := p.waitForHealthy(context.Background(), rec, srv, "tok", opts, log.plain); err == nil {
		t.Fatal("want the timeout")
	}
	un := log.steps("provision_health_unreachable")
	if len(un) != 1 {
		t.Fatalf("%d unreachable lines, want exactly 1", len(un))
	}
	if !strings.Contains(un[0].msg, "port 443 answers") || un[0].extra["box_ip"] != "127.0.0.1" {
		t.Errorf("line = %q %v", un[0].msg, un[0].extra)
	}
	if n := len(log.steps("provision_health_wait")); n != 5 {
		t.Errorf("the wait stopped early: %d tries of 5", n)
	}
}

// Any HTTP reply is an answer: a box still booting (503) is not "not
// answering this device".
func TestWaitForHealthyAnAnswerIsNotUnreachable(t *testing.T) {
	srv503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv503.Close()
	port := srv503.Listener.Addr().(*net.TCPAddr).Port
	fastHealthWait(t, port, 3, true)
	p := New(newFake())
	rec, srv := waitRec()
	log := &progressLog{}
	opts := provider.ProvisionOpts{HelperIP: net.ParseIP("90.1.2.3"), OnProgressData: log.data}

	if err := p.waitForHealthy(context.Background(), rec, srv, "tok", opts, log.plain); err == nil {
		t.Fatal("want the timeout")
	}
	if n := len(log.steps("provision_health_unreachable")); n != 0 {
		t.Errorf("%d unreachable lines for a box that answered", n)
	}
}

// Without OnProgressData the lines still reach the plain callback.
func TestWaitForHealthyPlainProgressStillGetsTheLine(t *testing.T) {
	fastHealthWait(t, closedPort(t), 2, false)
	p := New(newFake())
	rec, srv := waitRec()
	log := &progressLog{}
	opts := provider.ProvisionOpts{HelperIP: net.ParseIP("90.1.2.3")}
	_ = p.waitForHealthy(context.Background(), rec, srv, "tok", opts, log.plain)
	if n := len(log.steps("provision_health_wait")); n != 2 {
		t.Errorf("%d live lines on the plain callback, want 2", n)
	}
}

func TestHealthWaitLineAndClock(t *testing.T) {
	msg, extra := healthWaitLine(12, 60, 190*time.Second, "178.1.2.3", "90.4.5.6")
	want := "Waiting for the relay to answer at 178.1.2.3:9876 (try 12 of 60, 3:10 so far, window open for 90.4.5.6)"
	if msg != want {
		t.Errorf("line = %q\nwant  %q", msg, want)
	}
	if extra["elapsed_s"] != 190 || extra["attempt"] != 12 {
		t.Errorf("extra = %v", extra)
	}
	if msg, _ := healthWaitLine(1, 60, 0, "178.1.2.3", ""); !strings.Contains(msg, "no cloud firewall window") {
		t.Errorf("no-window line = %q", msg)
	}
	if !healthAnswered(nil) || !healthAnswered(errors.New("health poll: status 503")) {
		t.Error("a reply counts as an answer")
	}
}

// Cancel once the server exists: the rollback runs now (not after the
// health wait), the server is deleted, and the rollback says what it
// removed, marked as a cancel.
func TestProvisionCancelledAfterCreateRollsBack(t *testing.T) {
	f := newFake()
	p := New(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the run: the create still completes, then rolls back
	waited := false
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
		waited = true
		return nil
	})
	log := &progressLog{}
	opts := liveOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true
	opts.OnProgress = log.plain
	opts.OnProgressData = log.data

	_, err := p.Provision(ctx, opts)
	if err == nil {
		t.Fatal("a cancelled provision returned a relay")
	}
	if code, _ := provider.ProvisionErrorCode(err); code != provider.CodeCancelled {
		t.Errorf("code = %q, want cancelled (%v)", code, err)
	}
	if waited {
		t.Error("the health wait ran after the cancel")
	}
	if len(f.servers) != 0 {
		t.Errorf("%d server(s) left billing after a cancel", len(f.servers))
	}
	var done *progressLine
	for _, ln := range log.steps("provision_rollback") {
		ln := ln
		if ln.extra["rollback"] == "done" {
			done = &ln
		}
		if ln.extra["cancelled"] != true {
			t.Errorf("rollback line not marked as a cancel: %q %v", ln.msg, ln.extra)
		}
	}
	if done == nil || done.extra["server_deleted"] != true {
		t.Fatalf("no rollback line saying the server was deleted: %+v", log.steps("provision_rollback"))
	}
	if steps := log.steps("provision_cloud_firewall"); len(steps) != 0 {
		t.Errorf("firewall attach ran after the cancel: %v", steps)
	}
}

// A cancel during the health wait: the waiter's context error is a
// cancel, and the server is rolled back.
func TestProvisionCancelledDuringHealthWaitRollsBack(t *testing.T) {
	f := newFake()
	p := New(f)
	ctx, cancel := context.WithCancel(context.Background())
	p.setHealthWaiter(func(c context.Context, _ *provider.OperatorRecord, _ *ServerInfo, _ string, _ provider.ProvisionOpts, _ func(string, string)) error {
		cancel()
		<-c.Done()
		return c.Err()
	})
	opts := liveOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true
	_, err := p.Provision(ctx, opts)
	if code, _ := provider.ProvisionErrorCode(err); code != provider.CodeCancelled {
		t.Errorf("code = %q, want cancelled (%v)", code, err)
	}
	if len(f.servers) != 0 {
		t.Errorf("%d server(s) left billing after a cancel", len(f.servers))
	}
}
