package health

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Poller is the Helper-side client that hits the box's /healthz
// endpoint. The wizard (FRP-5) calls Wait() during the 60-second
// provisioning window to confirm the box came up cleanly.
//
// Endpoint shape: http://<box_ip>:9876/healthz/<PathToken(Token)>.
// Plain HTTP: the box has no certificate the publisher could verify
// yet — this exchange is where it learns one. The path between the
// two is NOT trusted (the ufw rule limits who may ask, not who may
// answer), so Token itself is never sent, and the one value later
// trust rests on, the management-TLS fingerprint, is accepted only
// with a MAC under Token (bootstrap.go). Every other Status field is
// a progress hint and must not be used for a security decision.
type Poller struct {
	BoxIP net.IP
	Port  int
	// Token is the health token the publisher put in the box's
	// cloud-init user-data. A shared secret; it stays on this side.
	Token   string
	Timeout time.Duration // per-request timeout; default 5 s
}

// refusalPatience is how long a run of 404 answers must last before a
// wait ends early on it. One 404 is not enough: on a rebuild the
// machine's previous install can answer for a moment before the
// re-image takes it down. It is a duration, not a count, because a
// caller's loop may spend most of a minute between polls.
var refusalPatience = 10 * time.Second

// RefusalCounter tells a retry loop when a run of ErrBootstrapRefused
// answers has lasted long enough to stop on. The zero value is ready.
type RefusalCounter struct{ since time.Time }

// Final reports whether err extends a run of refusals past
// refusalPatience. Any other outcome ends the run.
func (c *RefusalCounter) Final(err error) bool {
	if !errors.Is(err, ErrBootstrapRefused) {
		c.since = time.Time{}
		return false
	}
	if c.since.IsZero() {
		c.since = time.Now()
		return false
	}
	return time.Since(c.since) >= refusalPatience
}

// Wait polls the box up to maxAttempts times, waiting interval
// between failed attempts, until it returns Status{Healthy:true}.
// Returns the final Status on success or the last error on failure.
func (p *Poller) Wait(ctx context.Context, maxAttempts int, interval time.Duration) (*Status, error) {
	if p.Timeout == 0 {
		p.Timeout = 5 * time.Second
	}
	if maxAttempts <= 0 {
		maxAttempts = 12 // 12 * 5 s = 60 s default
	}
	if interval == 0 {
		interval = 5 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		st, err := p.poll(ctx)
		if err == nil && st.Healthy {
			return st, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("box never reported healthy")
	}
	return nil, lastErr
}

// WaitForMgmtFingerprint polls until the box is healthy and the
// bootstrap endpoint has published the V2 mgmt-plane TLS
// fingerprint. This intentionally waits for both conditions:
// daal-relay-health can become healthy a few seconds before
// daal-relay-mgmt has generated its self-signed leaf.
func WaitForMgmtFingerprint(ctx context.Context, boxIP net.IP, token string, maxAttempts int, interval time.Duration) (string, error) {
	return (&Poller{BoxIP: boxIP, Token: token}).WaitForMgmtFingerprint(ctx, maxAttempts, interval)
}

// WaitForMgmtFingerprint is the Poller-bound form used by tests
// and any caller that needs a non-default health endpoint port.
func (p *Poller) WaitForMgmtFingerprint(ctx context.Context, maxAttempts int, interval time.Duration) (string, error) {
	if p.Timeout == 0 {
		p.Timeout = 5 * time.Second
	}
	if maxAttempts <= 0 {
		maxAttempts = 12
	}
	if interval == 0 {
		interval = 5 * time.Second
	}
	var lastErr error
	var refused RefusalCounter
	for attempt := 0; attempt < maxAttempts; attempt++ {
		st, err := p.poll(ctx)
		if refused.Final(err) {
			return "", err
		}
		if err == nil && st.Healthy {
			// poll has already verified the MAC on a non-empty
			// fingerprint; this is only the shape check.
			fp := strings.ToLower(strings.TrimSpace(st.MgmtTLSFingerprint))
			raw, decErr := hex.DecodeString(fp)
			if decErr == nil && len(raw) == 32 {
				return fp, nil
			}
			lastErr = fmt.Errorf("mgmt_tls_fingerprint not ready")
		} else if err != nil {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("box never reported mgmt_tls_fingerprint")
	}
	return "", lastErr
}

// PollOnce makes a single health check request and returns the
// status. Exported so callers can implement their own retry loop
// with progress callbacks.
//
// A Status it returns either has no MgmtTLSFingerprint or has one
// whose MAC verified; a reply with an unauthenticated fingerprint is
// ErrFingerprintUnauthenticated and no Status at all.
func (p *Poller) PollOnce(ctx context.Context) (*Status, error) {
	if p.Timeout == 0 {
		p.Timeout = 5 * time.Second
	}
	return p.poll(ctx)
}

func (p *Poller) poll(ctx context.Context) (*Status, error) {
	if p.BoxIP == nil {
		return nil, errors.New("poller: BoxIP unset")
	}
	if p.Token == "" {
		return nil, errors.New("poller: Token unset")
	}
	port := p.Port
	if port == 0 {
		port = 9876
	}
	url := fmt.Sprintf("http://%s/healthz/%s", net.JoinHostPort(p.BoxIP.String(), strconv.Itoa(port)), PathToken(p.Token))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: p.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrBootstrapRefused
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health poll: status %d", resp.StatusCode)
	}
	var st Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return nil, err
	}
	// The fingerprint is what the publisher pins and then believes
	// every later reply on. One a machine on the path could have
	// written never leaves this function.
	if strings.TrimSpace(st.MgmtTLSFingerprint) != "" &&
		!VerifyFingerprintMAC(p.Token, st.MgmtTLSFingerprint, st.MgmtTLSFingerprintMAC) {
		return nil, ErrFingerprintUnauthenticated
	}
	return &st, nil
}
