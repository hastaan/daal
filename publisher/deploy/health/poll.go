package health

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Poller is the Helper-side client that hits the box's /healthz
// endpoint. The wizard (FRP-5) calls Wait() during the 60-second
// provisioning window to confirm the box came up cleanly.
//
// Endpoint shape: http://<box_ip>:9876/healthz/<token>. We do NOT
// use HTTPS at V1.5 because the only client is us, the network path
// is the IP-bound ufw rule we just opened, and FRP-7 will swap in
// a sealed-channel verifier shim (out of FRP-4a scope).
type Poller struct {
	BoxIP   net.IP
	Port    int
	Token   string
	Timeout time.Duration // per-request timeout; default 5 s
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
	for attempt := 0; attempt < maxAttempts; attempt++ {
		st, err := p.poll(ctx)
		if err == nil && st.Healthy {
			fp := strings.ToLower(strings.TrimSpace(st.MgmtTLSFingerprint))
			raw, decErr := hex.DecodeString(fp)
			if decErr == nil && len(raw) == 32 {
				return fp, nil
			}
			lastErr = fmt.Errorf("mgmt_tls_fingerprint not ready")
		} else {
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
	url := fmt.Sprintf("http://%s:%d/healthz/%s", p.BoxIP.String(), port, p.Token)
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health poll: status %d", resp.StatusCode)
	}
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}
