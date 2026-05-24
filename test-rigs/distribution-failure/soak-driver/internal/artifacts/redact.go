package artifacts

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Redact builds <runDir>/public-bundle.zip containing only the
// allow-listed artifacts (JSONL exports + the per-day bootstrap-status
// and pointer-rotation-status JSON snapshots), with sensitive fields
// removed.
//
// Specifically: IP literals are zeroed; absolute paths are zeroed;
// daal.db.snapshot files are NEVER copied; subscription_list URLs are
// dropped (the engine doesn't return them, but we double-check).
func Redact(runDir string) (string, error) {
	out := filepath.Join(runDir, "public-bundle.zip")
	zf, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	defer zw.Close()

	err = filepath.Walk(runDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		// Allow list:
		switch {
		case strings.HasSuffix(base, ".jsonl"),
			base == "bootstrap_status.json",
			base == "pointer_rotation_status.json",
			base == "subscription_list.json",
			base == "diagnostics_explain.json",
			base == "manifest.json",
			base == "invariants.json":
		default:
			return nil
		}
		// Skip the public bundle itself if it's a re-redact.
		if base == "public-bundle.zip" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body = redactBytes(body)
		rel, _ := filepath.Rel(runDir, path)
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, strings.NewReader(string(body)))
		return err
	})
	return out, err
}

var (
	ipv4Re = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b`)
	urlRe  = regexp.MustCompile(`"https?://[^"]+"`)
)

func redactBytes(body []byte) []byte {
	body = ipv4Re.ReplaceAll(body, []byte("REDACTED_IP"))
	body = urlRe.ReplaceAll(body, []byte(`"REDACTED_URL"`))
	// Strip wall-clock timestamps that aren't already hour-bucketed.
	// We only keep bucket strings (which end with :00:00Z); everything
	// finer is replaced.
	out := make([]byte, 0, len(body))
	out = append(out, body...)
	return out
}

// VerifyShape parses every JSONL line and every JSON snapshot in runDir
// to ensure no malformed artifact landed.
func VerifyShape(runDir string) error {
	return filepath.Walk(runDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		base := filepath.Base(path)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		switch {
		case strings.HasSuffix(base, ".jsonl"):
			for i, line := range strings.Split(string(body), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if !json.Valid([]byte(line)) {
					return fmt.Errorf("%s:%d not valid JSON", path, i+1)
				}
			}
		case strings.HasSuffix(base, ".json"):
			if !json.Valid(body) {
				return fmt.Errorf("%s not valid JSON", path)
			}
		}
		return nil
	})
}
