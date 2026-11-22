package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"daal/publisher/deploy/provider"
)

// healthPort is the provisioning health endpoint cloud-init opens on a
// new box (health.Poller's default).
const healthPort = 9876

// optionalLogViewer prefixes every line about the SSH observer. It
// only reads cloud-init's log while the box boots; a build never
// depends on it, so its waiting lines must not read as the problem.
const optionalLogViewer = "(optional log viewer)"

// The health wait's shape. Variables so tests can run the real loop in
// milliseconds against a local listener.
var (
	healthMaxAttempts = 60
	healthInterval    = 5 * time.Second
	// healthPollPort is the port the poller dials; 0 is healthPort.
	healthPollPort = 0
	// notAnsweringAfter: how long the health endpoint may stay silent,
	// while the relay's port 443 is up, before the wait says that the
	// relay is up but not answering this device.
	notAnsweringAfter = 6 * time.Minute
	// notAnsweringRecheck: how often port 443 is tried after that.
	notAnsweringRecheck = time.Minute
	// relay443Up reports whether the relay's port 443 takes a TCP
	// connection. A seam for tests.
	relay443Up = func(ctx context.Context, ip net.IP) bool {
		if ip == nil {
			return false
		}
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
)

// healthTryCeiling is the most one try of the health wait spends
// besides its interval: the SSH observer (3 s dial plus the log read),
// the health poll (health.Poller's 5 s default), the 3 s port-443
// probe, with room for a slow handshake.
const healthTryCeiling = 30 * time.Second

// healthWindowMargin keeps the temporary windows open a little past
// the slowest wait, for the reads that follow it (reality.pub, the
// TLS pin over the same SSH window).
const healthWindowMargin = 5 * time.Minute

// healthWaitBudget is the longest the health wait can run: every try
// at its slowest. With the defaults (60 tries, 5 s apart) it is 35
// minutes; a real wait that never answers runs about 20.
func healthWaitBudget() time.Duration {
	return time.Duration(healthMaxAttempts) * (healthInterval + healthTryCeiling)
}

// healthWindowTTL is the expiry the temporary health and SSH firewall
// windows are opened with. It is sized to the wait so the window
// outlives it; the old 10 minutes ran out half way through a slow
// wait. The windows are still removed as soon as the wait returns.
func healthWindowTTL() time.Duration {
	return healthWaitBudget() + healthWindowMargin
}

// detailedProgress is where milestones with machine-readable detail go:
// the caller's OnProgressData when it set one, else the plain progress
// callback with the detail dropped.
func detailedProgress(opts provider.ProvisionOpts, progress func(step, message string)) func(step, message string, extra map[string]any) {
	if opts.OnProgressData != nil {
		return opts.OnProgressData
	}
	if progress == nil {
		return func(string, string, map[string]any) {}
	}
	return func(step, message string, _ map[string]any) { progress(step, message) }
}

// healthWaitLine is the one live status line of the health wait: which
// try this is, how long it has been, and the address the firewall
// window was opened for ("" when the server has no cloud firewall).
func healthWaitLine(attempt, maxAttempts int, elapsed time.Duration, boxIP, windowFor string) (string, map[string]any) {
	window := "no cloud firewall window"
	if windowFor != "" {
		window = "window open for " + windowFor
	}
	msg := fmt.Sprintf("Waiting for the relay to answer at %s (try %d of %d, %s so far, %s)",
		net.JoinHostPort(boxIP, strconv.Itoa(healthPort)), attempt, maxAttempts, clockDuration(elapsed), window)
	return msg, map[string]any{
		"attempt":      attempt,
		"max_attempts": maxAttempts,
		"elapsed_s":    int(elapsed.Seconds()),
		"box_ip":       boxIP,
		"port":         healthPort,
		"helper_ip":    windowFor,
	}
}

// healthAnswered: the poll got an HTTP reply of any kind. A transport
// failure (refused, timed out, unreachable) comes back from the HTTP
// client as a *url.Error; everything else (a status, a body that does
// not decode, a refusal by the box) means something answered.
func healthAnswered(err error) bool {
	if err == nil {
		return true
	}
	var ue *url.Error
	return !errors.As(err, &ue)
}

// clockDuration renders a wait as m:ss.
func clockDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
