// Package artifacts writes per-simulated-day rig output: JSONL exports
// (refresh_audit, diagnostics_explain), JSON snapshots (bootstrap,
// pointer-rotation), and a sqlite snapshot of daal.db.
//
// The redact subcommand reuses this package to filter out fields that
// must not appear in a public release-announcement bundle.
package artifacts

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Writer is created per simulated day per client. It owns its
// directory; callers append rows or write whole files.
type Writer struct {
	dir string
}

// New creates the directory <root>/day-NNN/<client>/ if missing.
func New(root string, day int, client string) (*Writer, error) {
	p := filepath.Join(root, fmt.Sprintf("day-%03d", day), client)
	if err := os.MkdirAll(p, 0o755); err != nil {
		return nil, err
	}
	return &Writer{dir: p}, nil
}

// Dir returns the directory absolute path.
func (w *Writer) Dir() string { return w.dir }

// AppendJSONL appends a single JSON value as a line in <name>.jsonl.
func (w *Writer) AppendJSONL(name string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(w.dir, name+".jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	body = append(body, '\n')
	_, err = f.Write(body)
	return err
}

// WriteJSON writes a complete JSON document under <name>.json.
func (w *Writer) WriteJSON(name string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.dir, name+".json"), body, 0o644)
}

// CopyFile copies a file (e.g. daal.db.snapshot) into the writer's
// directory.
func (w *Writer) CopyFile(srcPath, dstName string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(filepath.Join(w.dir, dstName))
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// Manifest is the top-level run manifest written once per run.
type Manifest struct {
	RunID         string   `json:"run_id"`
	StartedAt     string   `json:"started_at"`
	SimulatedDays int      `json:"simulated_days"`
	Scenarios     []string `json:"scenarios"`
	Clients       []string `json:"clients"`
	EngineLib     string   `json:"engine_lib"`
	EngineVersion string   `json:"engine_version"`
}

// WriteManifest writes <root>/manifest.json.
func WriteManifest(root string, m Manifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "manifest.json"), body, 0o644)
}
