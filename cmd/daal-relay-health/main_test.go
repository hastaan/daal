package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRuntimeConfig_FromCloudInitJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := []byte(`{
  "one_time_token": "changeme-test-token",
  "allowed_client_ip": "203.0.113.10",
  "auto_close_after_seconds": 7,
  "publish_mgmt_fingerprint_path": "/var/log/daal/mgmt-tls.fpr"
}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRuntimeConfig(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "changeme-test-token" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.AllowedClientIP == nil || cfg.AllowedClientIP.String() != "203.0.113.10" {
		t.Errorf("AllowedClientIP = %v", cfg.AllowedClientIP)
	}
	if cfg.AutoCloseAfter != 7*time.Second {
		t.Errorf("AutoCloseAfter = %s", cfg.AutoCloseAfter)
	}
	if cfg.MgmtFingerprintPath != "/var/log/daal/mgmt-tls.fpr" {
		t.Errorf("MgmtFingerprintPath = %q", cfg.MgmtFingerprintPath)
	}
}

func TestLoadRuntimeConfig_FromTokenFileFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("fallback-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRuntimeConfig("", path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "fallback-token" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.AutoCloseAfter != 300*time.Second {
		t.Errorf("default AutoCloseAfter = %s", cfg.AutoCloseAfter)
	}
}

func TestLoadRuntimeConfig_RejectsBadAllowedIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := []byte(`{"one_time_token":"t","allowed_client_ip":"not-an-ip"}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeConfig(path, ""); err == nil {
		t.Fatal("expected bad allowed_client_ip error")
	}
}

func TestSystemdProbePublishesMgmtFingerprint(t *testing.T) {
	dir := t.TempDir()
	fpPath := filepath.Join(dir, "mgmt-tls.fpr")
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(fpPath, []byte(fp+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &systemdProbe{
		bootedAt:            time.Now().UTC(),
		unit:                "definitely-not-active.service",
		version:             "test",
		mgmtFingerprintPath: fpPath,
	}
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.MgmtTLSFingerprint != fp {
		t.Fatalf("MgmtTLSFingerprint = %q want %q", st.MgmtTLSFingerprint, fp)
	}
}
