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

// Status is the JSON body returned by GET /healthz/<path token>. It
// is consumed by the Helper-side poller in poll.go.
//
// The reply travels over plain HTTP. MgmtTLSFingerprint is the one
// field anything is later trusted on, and it is believed only with
// MgmtTLSFingerprintMAC (bootstrap.go). Every other field is a
// progress hint a machine on the path could have written.
type Status struct {
	Healthy            bool      `json:"healthy"`
	BoxBootedAt        time.Time `json:"box_booted_at"`
	SingBoxRunning     bool      `json:"singbox_running"`
	DaalVersion        string    `json:"daal_version"`
	UptimeSec          int64     `json:"uptime_sec"`
	MgmtTLSFingerprint string    `json:"mgmt_tls_fingerprint,omitempty"`
	// MgmtTLSFingerprintMAC is FingerprintMAC(health token,
	// MgmtTLSFingerprint). The handler fills it; a Probe does not.
	MgmtTLSFingerprintMAC string `json:"mgmt_tls_fingerprint_mac,omitempty"`
	DebugLog              string `json:"debug_log,omitempty"`
}

// Probe is the box-local hook the handler calls to compute the
// current Status. cmd/daal-relay-health binds it to systemd /
// process probes; tests pass an in-memory implementation.
type Probe interface {
	Snapshot(ctx context.Context) (Status, error)
}

// HandlerConfig is the input to NewHandler. Token is the one-time
// secret cloud-init wrote into the health config. It is never sent on
// the wire: the handler answers only the path token derived from it
// (PathToken, compared in constant time) and uses it to authenticate
// the management-TLS fingerprint it returns (FingerprintMAC).
type HandlerConfig struct {
	Token           string
	AllowedClientIP net.IP // optional; nil disables binary-level IP check
	Probe           Probe
}

// NewHandler returns the box-side http.Handler for the health
// endpoint. The single route is GET /healthz/<PathToken(token)>;
// everything else — the raw token included — returns 404 (NOT 401, to
// avoid leaking that a token-shaped route is the right path).
func NewHandler(cfg HandlerConfig) (http.Handler, error) {
	if cfg.Token == "" {
		return nil, errors.New("health: empty token")
	}
	if cfg.Probe == nil {
		return nil, errors.New("health: nil probe")
	}
	return &handler{cfg: cfg, pathToken: PathToken(cfg.Token)}, nil
}

type handler struct {
	cfg       HandlerConfig
	pathToken string
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
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.pathToken)) != 1 {
		http.NotFound(w, r)
		return
	}
	st, err := h.cfg.Probe.Snapshot(r.Context())
	if err != nil {
		http.Error(w, "probe failed", http.StatusInternalServerError)
		return
	}
	// The MAC is the handler's to make, whatever the probe returned.
	st.MgmtTLSFingerprintMAC = ""
	if fp := canonicalFingerprint(st.MgmtTLSFingerprint); fp != "" {
		st.MgmtTLSFingerprint = fp
		st.MgmtTLSFingerprintMAC = FingerprintMAC(h.cfg.Token, fp)
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
