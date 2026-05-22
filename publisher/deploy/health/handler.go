package health

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// Status is the JSON body returned by GET /healthz/<token>. The
// schema is locked at FRP-4a and consumed by the Helper-side
// poller in poll.go and (later) by FRP-5's wizard for the
// "Helper is up" indicator.
type Status struct {
	Healthy            bool      `json:"healthy"`
	BoxBootedAt        time.Time `json:"box_booted_at"`
	SingBoxRunning     bool      `json:"singbox_running"`
	DaalVersion        string    `json:"daal_version"`
	UptimeSec          int64     `json:"uptime_sec"`
	MgmtTLSFingerprint string    `json:"mgmt_tls_fingerprint,omitempty"`
}

// Probe is the box-local hook the handler calls to compute the
// current Status. cmd/daal-relay-health binds it to systemd /
// process probes; tests pass an in-memory implementation.
type Probe interface {
	Snapshot(ctx context.Context) (Status, error)
}

// HandlerConfig is the input to NewHandler. Token is the one-time
// secret cloud-init wrote to /etc/daal/health-token; the handler
// rejects every request whose path token does not match this
// constant-time.
type HandlerConfig struct {
	Token           string
	AllowedClientIP net.IP // optional; nil disables binary-level IP check
	Probe           Probe
}

// NewHandler returns the box-side http.Handler for the health
// endpoint. The single route is GET /healthz/<token>; everything
// else returns 404 (NOT 401, to avoid leaking that a token-shaped
// route is the right path).
func NewHandler(cfg HandlerConfig) (http.Handler, error) {
	if cfg.Token == "" {
		return nil, errors.New("health: empty token")
	}
	if cfg.Probe == nil {
		return nil, errors.New("health: nil probe")
	}
	return &handler{cfg: cfg}, nil
}

type handler struct {
	cfg HandlerConfig
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if !allowedRemoteIP(r.RemoteAddr, h.cfg.AllowedClientIP) {
		http.NotFound(w, r)
		return
	}
	const prefix = "/healthz/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	got := r.URL.Path[len(prefix):]
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.cfg.Token)) != 1 {
		http.NotFound(w, r)
		return
	}
	st, err := h.cfg.Probe.Snapshot(r.Context())
	if err != nil {
		http.Error(w, "probe failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func allowedRemoteIP(remoteAddr string, allowed net.IP) bool {
	if allowed == nil {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	got := net.ParseIP(host)
	return got != nil && got.Equal(allowed)
}
