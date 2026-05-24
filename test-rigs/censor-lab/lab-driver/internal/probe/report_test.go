package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSampleReportPassesPrivacy(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/probe -> ../../.. -> lab-driver -> ../.. -> censor-lab -> ../field-probe
	path := filepath.Clean(filepath.Join(wd, "..", "..", "..", "..", "field-probe", "sample-report.json"))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}
	if err := CheckPrivacy(json.RawMessage(body)); err != nil {
		t.Fatalf("sample report violates privacy: %v", err)
	}
}

func TestForbiddenFieldRejected(t *testing.T) {
	body := []byte(`{"schema_version":1,"public_ip":"1.2.3.4"}`)
	if err := CheckPrivacy(body); err == nil {
		t.Fatal("expected forbidden field rejection")
	}
}

func TestNestedForbiddenFieldRejected(t *testing.T) {
	body := []byte(`{"a":{"b":{"ssid":"home"}}}`)
	if err := CheckPrivacy(body); err == nil {
		t.Fatal("expected nested forbidden field rejection")
	}
}
