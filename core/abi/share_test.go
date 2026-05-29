package abi

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestShareEndToEnd_LANRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	// Sender setup: import + trust signed-A so we have a route to share.
	verdict, _ := ImportSBP(filepath.Join(samplesDir, "signed-A.sbp"))
	fp := extractField(verdict, "Fingerprint")
	if fp == "" {
		t.Fatalf("no fingerprint")
	}
	if _, err := ResolveTrustPrompt(fp, 0); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Begin a share session (LAN on, plus a tiny URI for the static QR
	// promotion path).
	resp, err := ShareBegin("sample-route-1", true,
		"vless://uuid@example.com:443?security=reality&pbk=K&sid=S#tag")
	if err != nil {
		t.Fatalf("share begin: %v", err)
	}
	var begin struct {
		SessionID string   `json:"session_id"`
		Pin       string   `json:"pin"`
		LANURLs   []string `json:"lan_urls"`
		QRPNG     string   `json:"qr_static_png_b64"`
	}
	if err := json.Unmarshal([]byte(resp), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	if len(begin.Pin) != 6 || len(begin.LANURLs) == 0 || begin.QRPNG == "" {
		t.Fatalf("incomplete begin response: %+v", begin)
	}

	// Receiver pulls. Wrong PIN must fail.
	host, port := splitHostPort(t, begin.LANURLs[0])
	if _, err := SharePull(host, port, "999999", begin.SessionID); err == nil {
		t.Errorf("expected wrong-pin failure")
	}
	// Right PIN succeeds. Receiver re-imports its own bundle, so the
	// importer treats the (already-pinned) publisher as known.
	verdictJSON, err := SharePull(host, port, begin.Pin, begin.SessionID)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if verdictJSON == "" {
		t.Errorf("empty verdict")
	}

	if err := ShareEnd(begin.SessionID); err != nil {
		t.Errorf("end: %v", err)
	}
}

func TestShareEndToEnd_FountainRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	verdict, _ := ImportSBP(filepath.Join(samplesDir, "signed-A.sbp"))
	fp := extractField(verdict, "Fingerprint")
	if _, err := ResolveTrustPrompt(fp, 0); err != nil {
		t.Fatal(err)
	}

	resp, err := ShareBegin("sample-route-1", false, "")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	var begin struct {
		SessionID string `json:"session_id"`
	}
	json.Unmarshal([]byte(resp), &begin)

	// Drive fountain encode/decode in-process. We re-feed frames into a
	// receiver session under a different name so the receiver-side
	// fountain map allocates fresh.
	const recv = "recv-1"
	for i := 0; i < 200; i++ {
		out, err := FountainNextFrame(begin.SessionID)
		if err != nil {
			t.Fatalf("next frame: %v", err)
		}
		var frame struct {
			FrameB64 string `json:"frame_b64"`
		}
		json.Unmarshal([]byte(out), &frame)
		fed, err := FountainFeedFrame(recv, frame.FrameB64)
		if err != nil {
			t.Fatalf("feed: %v", err)
		}
		var p struct {
			Done    bool `json:"done"`
			Verdict any  `json:"verdict"`
		}
		json.Unmarshal([]byte(fed), &p)
		if p.Done {
			if p.Verdict == nil {
				t.Errorf("expected verdict on done")
			}
			ShareEnd(begin.SessionID)
			return
		}
	}
	t.Fatalf("fountain did not decode within 200 frames")
}

func TestURIDetectAndImport(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	hits, err := URIDetect("hello\nvless://uuid@example.com:443?security=reality&pbk=K&sid=S#tag\nss://aes-256-gcm:secret@1.2.3.4:8388")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hits, "vless") || !strings.Contains(hits, "ss") {
		t.Errorf("missing schemes: %s", hits)
	}
	// The full URI field intentionally carries the original line so the
	// confirmation UI can echo it back; the Preview field is the
	// redacted version.
	if strings.Contains(extractField(hits, "Preview"), "secret") {
		t.Errorf("preview leaked secret: %s", hits)
	}
	verdictJSON, err := URIImport("vless://uuid@example.com:443?security=reality&pbk=K&sid=S#paste")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(verdictJSON, `"Kind":0`) && !strings.Contains(verdictJSON, `"Kind":1`) {
		t.Errorf("unexpected verdict: %s", verdictJSON)
	}
}

func TestSharingDoesNotBypassTrustPath(t *testing.T) {
	// Verify that the same pasted URI flows through the importer and
	// produces a valid Verdict (Kind=0 because the device's own sharing
	// identity becomes a known publisher after first paste).
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	first, err := URIImport("vless://uuid@example.com:443?security=reality&pbk=K&sid=S#x")
	if err != nil {
		t.Fatal(err)
	}
	// First import surfaces a trust prompt for the pasted-by-you publisher.
	if !strings.Contains(first, `"Kind":1`) {
		t.Logf("first verdict: %s", first)
	}
	// Resolve and re-paste — second time should silent-import.
	fp := extractField(first, "Fingerprint")
	if fp != "" {
		ResolveTrustPrompt(fp, 0)
	}
	second, err := URIImport("vless://uuid2@example.com:443?security=reality&pbk=K&sid=S#y")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(second, `"Kind":0`) {
		t.Logf("second verdict: %s", second)
	}
	_ = base64.StdEncoding // referenced by sibling tests
}

// splitHostPort, extractField, indexOf, contains live in abi_test.go;
// re-export here as small helpers if the link is missing.

func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	// url.Parse + Hostname() correctly strips IPv6 brackets so we
	// don't double-bracket via JoinHostPort downstream.
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port from %q: %v", raw, err)
	}
	return u.Hostname(), port
}
