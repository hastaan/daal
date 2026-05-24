// daal-relay-health is the box-side health endpoint binary
// installed at /usr/local/bin/daal-relay-health by cloud-init.
//
// It listens on 0.0.0.0:9876 and serves a single route:
//
//	GET /healthz/<one_time_token>
//
// where <one_time_token> is the value cloud-init wrote to
// /etc/daal/health-token at boot. Anything else returns 404.
//
// During the 60-second provisioning window the box's ufw rules
// allow only the Helper's IP through; once the window closes
// cloud-init systemctl stops this service. Position B is preserved:
// the service has no outbound connections at all.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"daal/publisher/deploy/health"
)

var (
	flagAddr    = flag.String("addr", ":9876", "listen address")
	flagConfig  = flag.String("config", "", "JSON config path written by cloud-init")
	flagToken   = flag.String("token-file", "/etc/daal/health-token", "path to one-time token")
	flagSingBox = flag.String("singbox-unit", "sing-box.service", "systemd unit name")
	flagVersion = flag.String("daal-version", "0.9.0+v3-share", "daal-relay version string")
)

func main() {
	flag.Parse()

	cfg, err := loadRuntimeConfig(*flagConfig, *flagToken)
	if err != nil {
		log.Fatal(err)
	}

	booted := time.Now().UTC()
	probe := &systemdProbe{
		bootedAt:            booted,
		unit:                *flagSingBox,
		version:             *flagVersion,
		mgmtFingerprintPath: cfg.MgmtFingerprintPath,
	}

	h, err := health.NewHandler(health.HandlerConfig{
		Token:           cfg.Token,
		AllowedClientIP: cfg.AllowedClientIP,
		Probe:           probe,
	})
	if err != nil {
		log.Fatalf("NewHandler: %v", err)
	}

	srv := &http.Server{
		Addr:              *flagAddr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("daal-relay-health: listening on %s", *flagAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	// Wait for SIGTERM (cloud-init self-destruct sends this after
	// the 60-second window), or self-close after the configured
	// deadline as a belt-and-braces guard if systemd stop fails.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	timer := time.NewTimer(cfg.AutoCloseAfter)
	defer timer.Stop()
	select {
	case <-sigCh:
	case <-timer.C:
		log.Printf("daal-relay-health: auto-close after %s", cfg.AutoCloseAfter)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

type runtimeConfig struct {
	Token               string
	AllowedClientIP     net.IP
	AutoCloseAfter      time.Duration
	MgmtFingerprintPath string
}

type fileConfig struct {
	OneTimeToken               string `json:"one_time_token"`
	AllowedClientIP            string `json:"allowed_client_ip"`
	AutoCloseAfterSeconds      int    `json:"auto_close_after_seconds"`
	PublishMgmtFingerprintPath string `json:"publish_mgmt_fingerprint_path"`
}

func loadRuntimeConfig(configPath, tokenPath string) (runtimeConfig, error) {
	cfg := runtimeConfig{AutoCloseAfter: 300 * time.Second}
	if configPath != "" {
		body, err := os.ReadFile(configPath)
		if err != nil {
			return runtimeConfig{}, err
		}
		var fc fileConfig
		if err := json.Unmarshal(body, &fc); err != nil {
			return runtimeConfig{}, err
		}
		cfg.Token = strings.TrimSpace(fc.OneTimeToken)
		if fc.AllowedClientIP != "" {
			cfg.AllowedClientIP = net.ParseIP(fc.AllowedClientIP)
			if cfg.AllowedClientIP == nil {
				return runtimeConfig{}, fmt.Errorf("invalid allowed_client_ip %q", fc.AllowedClientIP)
			}
		}
		if fc.AutoCloseAfterSeconds > 0 {
			cfg.AutoCloseAfter = time.Duration(fc.AutoCloseAfterSeconds) * time.Second
		}
		cfg.MgmtFingerprintPath = strings.TrimSpace(fc.PublishMgmtFingerprintPath)
	} else {
		tokenBytes, err := os.ReadFile(tokenPath)
		if err != nil {
			return runtimeConfig{}, err
		}
		cfg.Token = strings.TrimSpace(string(tokenBytes))
	}
	if cfg.Token == "" {
		return runtimeConfig{}, fmt.Errorf("health token is empty")
	}
	return cfg, nil
}

// systemdProbe asks systemctl whether the given unit is in the
// "active" state. Used as the box-side Probe by the health
// handler. Calls only the local systemd dbus / cli, never network.
type systemdProbe struct {
	bootedAt            time.Time
	unit                string
	version             string
	mgmtFingerprintPath string
}

func (p *systemdProbe) Snapshot(ctx context.Context) (health.Status, error) {
	st := health.Status{
		Healthy:        true,
		BoxBootedAt:    p.bootedAt,
		DaalVersion:    p.version,
		UptimeSec:      int64(time.Since(p.bootedAt).Seconds()),
		SingBoxRunning: isUnitActive(ctx, p.unit),
	}
	if !st.SingBoxRunning {
		st.Healthy = false
	}
	if p.mgmtFingerprintPath != "" {
		if body, err := os.ReadFile(p.mgmtFingerprintPath); err == nil {
			st.MgmtTLSFingerprint = strings.TrimSpace(string(body))
		}
	}
	return st, nil
}

// isUnitActive shells out to systemctl is-active <unit>. Returns
// true iff the command succeeds with output "active". Anything else
// is treated as not-running.
func isUnitActive(ctx context.Context, unit string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
