package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/bundle-go/fieldreport"
)

func TestReportKeygenAndOpen(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "report.key")
	var out, errb bytes.Buffer
	if rc := runReportKeygen(context.Background(), []string{"--out", keyPath}, &out, &errb); rc != 0 {
		t.Fatalf("keygen rc=%d %s", rc, errb.String())
	}
	var kg struct {
		ReportTo string `json:"report_to"`
	}
	if err := json.Unmarshal(out.Bytes(), &kg); err != nil || !strings.HasPrefix(kg.ReportTo, "daal1") {
		t.Fatalf("keygen output %q", out.String())
	}
	if fi, _ := os.Stat(keyPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode())
	}
	// A second keygen never overwrites the key.
	if rc := runReportKeygen(context.Background(), []string{"--out", keyPath}, &out, &errb); rc == 0 {
		t.Fatal("keygen overwrote an existing key")
	}

	sample, err := os.ReadFile(filepath.Join("..", "..", "..", "test-rigs", "field-probe", "sample-report-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := fieldreport.Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := fieldreport.Seal(r, kg.ReportTo)
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "net-abcdefgh.dat")
	if err := os.WriteFile(in, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if rc := runReportOpen(context.Background(), []string{"--in", in, "--key", keyPath}, strings.NewReader(""), &out, &errb); rc != 0 {
		t.Fatalf("open rc=%d %s", rc, errb.String())
	}
	if _, err := fieldreport.Parse(out.Bytes()); err != nil {
		t.Fatalf("open printed something that is not a v2 report: %v", err)
	}
	out.Reset()
	key, _ := os.ReadFile(keyPath)
	if rc := runReportOpen(context.Background(), []string{"--in", in, "--findings"}, bytes.NewReader(key), &out, &errb); rc != 0 {
		t.Fatalf("open --findings rc=%d %s", rc, errb.String())
	}
	if !strings.Contains(out.String(), "reality_443_works") {
		t.Fatalf("findings output %q", out.String())
	}
	// A pack is not a report.
	if err := os.WriteFile(in, append([]byte("DSBP\x00\x01"), sealed[6:]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := runReportOpen(context.Background(), []string{"--in", in, "--key", keyPath}, strings.NewReader(""), &out, &errb); rc == 0 {
		t.Fatal("a .sbpx-magic file was opened as a report")
	}
}

// `--out -` is the app's path: the key comes back in the JSON and no
// file is written; the address is the key's own.
func TestReportKeygenToStdout(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if rc := runReportKeygen(context.Background(), []string{"--out", "-"}, &out, &errb); rc != 0 {
		t.Fatalf("keygen rc=%d %s", rc, errb.String())
	}
	var kg struct {
		ReportTo      string `json:"report_to"`
		PrivateKeyHex string `json:"private_key_hex"`
		KeyPath       string `json:"key_path"`
	}
	if err := json.Unmarshal(out.Bytes(), &kg); err != nil {
		t.Fatalf("keygen output %q: %v", out.String(), err)
	}
	if !strings.HasPrefix(kg.ReportTo, "daal1") || len(kg.PrivateKeyHex) != 64 || kg.KeyPath != "" {
		t.Fatalf("keygen output %q", out.String())
	}
	if _, err := os.Stat("-"); err == nil {
		t.Fatal("a file named - was written")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("files written: %v", entries)
	}

	// A report sealed to the printed address opens with the printed key.
	sample, err := os.ReadFile(filepath.Join("..", "..", "..", "test-rigs", "field-probe", "sample-report-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := fieldreport.Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := fieldreport.Seal(r, kg.ReportTo)
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "net-abcdefgh.dat")
	if err := os.WriteFile(in, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if rc := runReportOpen(context.Background(), []string{"--in", in}, strings.NewReader(kg.PrivateKeyHex+"\n"), &out, &errb); rc != 0 {
		t.Fatalf("open rc=%d %s", rc, errb.String())
	}
	if _, err := fieldreport.Parse(out.Bytes()); err != nil {
		t.Fatalf("open printed something that is not a v2 report: %v", err)
	}
}
