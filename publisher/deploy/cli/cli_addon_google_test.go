package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/freshness/backends/appsscript"
	"daal/publisher/deploy/freshness/backends/appsscript/appsscripttest"
)

const gToken = "AAAAAAAAAAAAAAAAAAAAAA"

// withFakeGoogle points the verbs at a fake Google for one test.
func withFakeGoogle(t *testing.T) *appsscripttest.Fake {
	t.Helper()
	f := appsscripttest.New()
	oldN, oldE := appsScriptNetwork, appsScriptEndpoints
	appsScriptNetwork = f.Network()
	appsScriptEndpoints = f.Endpoints
	t.Cleanup(func() {
		appsScriptNetwork, appsScriptEndpoints = oldN, oldE
		f.Close()
	})
	return f
}

func gKeyFile(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return writeTemp(t, "write.key", []byte(hex.EncodeToString(k)+"\n")), k
}

func runG(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Run(argv, &out, &errb)
	return rc, out.String(), errb.String()
}

// signedDocAndPack runs the real publish-freshness (sign only) for a
// pack whose only mirror is the Google channel (D-3).
func signedDocAndPack(t *testing.T, mirrorURL string) (docPath, packPath string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := writeTemp(t, "root.key", priv)
	pack := []byte("signed credential-less pack, as bind-and-sign wrote it")
	packPath = writeTemp(t, "rp.sbp", pack)
	sum := sha256.Sum256(pack)
	docPath = filepath.Join(t.TempDir(), "doc.json")
	rc, _, errs := runG(t, "publish-freshness",
		"--relay-pack-id", "rp-google-1",
		"--current-bundle-sha256", hex.EncodeToString(sum[:]),
		"--current-signed-url", "https://packs.example.com/rp.sbp",
		"--publisher-pub-hex", hex.EncodeToString(pub),
		"--root-priv-file", privPath,
		"--mirror", "appsscript="+mirrorURL,
		"--out-file", docPath)
	if rc != 0 {
		t.Fatalf("publish-freshness rc=%d: %s", rc, errs)
	}
	return docPath, packPath
}

func TestAppsScriptPathBThroughTheVerbs(t *testing.T) {
	f := withFakeGoogle(t)
	keyPath, _ := gKeyFile(t)

	rc, out, errs := runG(t, "appsscript-script", "--write-key-file", keyPath, "--path-token", gToken)
	if rc != 0 {
		t.Fatalf("script rc=%d %s", rc, errs)
	}
	var s struct {
		Code     string `json:"code_gs"`
		Manifest string `json:"manifest_json"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil || !strings.Contains(s.Code, "function doPost") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(errs, "WRITE_KEY") {
		t.Fatal("the script went to stderr")
	}
	shown, err := f.DeployByHand(s.Code)
	if err != nil {
		t.Fatal(err)
	}
	url, err := appsscript.NormalizeExecURL(shown, gToken)
	if err != nil {
		t.Fatal(err)
	}

	docPath, packPath := signedDocAndPack(t, url)
	rc, out, errs = runG(t, "appsscript-check", "--url", url, "--write-key-file", keyPath,
		"--freshness-file", docPath, "--pack-file", packPath)
	if rc != 0 {
		t.Fatalf("check rc=%d %s", rc, errs)
	}
	var r struct {
		appsscript.CheckResult
		PackIncluded bool `json:"pack_included"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || !r.OK || !r.Posted || !r.ViaFront || !r.PackIncluded {
		t.Fatalf("%s %v", out, err)
	}
	// What the script holds verifies as the document that was signed.
	id, _, _ := freshness.ValidateAppsScriptURL(url)
	_, blob, _ := f.Stored(id)
	parts, err := appsscript.Parse([]byte(blob))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := os.ReadFile(docPath)
	if !bytes.Equal(parts.Freshness, doc) {
		t.Fatal("the stored document is not the signed one")
	}

	// Fetch only, against the hash just reported.
	rc, out, _ = runG(t, "appsscript-check", "--url", url, "--expect-sha256", r.SHA256)
	if rc != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("fetch-only: %d %s", rc, out)
	}
	// Removal: the empty container, numbered past the document.
	seq, _ := appsscript.DocSequence(doc)
	rc, out, _ = runG(t, "appsscript-clear", "--url", url, "--write-key-file", keyPath,
		"--seq", strconvU(seq+1))
	if rc != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("clear: %d %s", rc, out)
	}
	_, blob, _ = f.Stored(id)
	if blob != string(appsscript.Empty()) {
		t.Fatalf("after clear the script holds %.80s", blob)
	}
	// A check that finds trouble still exits 0 and says why.
	rc, out, _ = runG(t, "appsscript-clear", "--url", url, "--write-key-file", keyPath, "--seq", "1")
	if rc != 0 || !strings.Contains(out, `"reason":"stale"`) {
		t.Fatalf("stale clear: %d %s", rc, out)
	}
}

func strconvU(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func runDeploy(t *testing.T, stdin string, argv ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := runAppsScriptDeploy(context.Background(), argv, strings.NewReader(stdin), &out, &errb)
	return rc, out.String(), errb.String()
}

func TestAppsScriptPathAThroughTheVerbs(t *testing.T) {
	f := withFakeGoogle(t)
	keyPath, _ := gKeyFile(t)

	rc, out, errs := runDeploy(t, `{"access_token":"`+f.AcceptedToken+`"}`,
		"--write-key-file", keyPath, "--path-token", gToken)
	if rc != 0 {
		t.Fatalf("deploy rc=%d %s", rc, errs)
	}
	if strings.Contains(out+errs, f.AcceptedToken) {
		t.Fatal("the token was printed")
	}
	var d struct {
		ScriptID string `json:"script_id"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil || !strings.HasSuffix(d.URL, "?k="+gToken) {
		t.Fatalf("%s %v", out, err)
	}
	if len(f.Revoked) != 1 {
		t.Fatal("the token was not revoked")
	}
	// The same POST and fetch-back as Path B.
	rc, out, _ = runG(t, "appsscript-check", "--url", d.URL, "--write-key-file", keyPath, "--seq", "7")
	if rc != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("check: %s", out)
	}

	// Desktop: the code and verifier from the loopback sign-in.
	verifier := strings.Repeat("v", 43)
	f.ExpectCode("4/desk", verifier)
	in, _ := json.Marshal(map[string]string{"code": "4/desk", "code_verifier": verifier,
		"redirect_uri": "http://127.0.0.1:41234", "client_id": "cid.apps.googleusercontent.com", "client_secret": "not-secret"})
	if rc, _, errs := runDeploy(t, string(in), "--write-key-file", keyPath, "--path-token", gToken); rc != 0 {
		t.Fatalf("desktop deploy: %s", errs)
	}
}

func TestAppsScriptDeployFailures(t *testing.T) {
	f := withFakeGoogle(t)
	keyPath, _ := gKeyFile(t)
	tok := `{"access_token":"` + f.AcceptedToken + `"}`

	f.APIDisabled = true
	rc, _, errs := runDeploy(t, tok, "--write-key-file", keyPath, "--path-token", gToken)
	if rc != 1 || !strings.HasPrefix(errs, "E_GOOGLE_API_NOT_ENABLED: ") {
		t.Fatalf("%d %s", rc, errs)
	}
	f.APIDisabled = false

	f.FailStage = appsscript.StageVersion
	rc, _, errs = runDeploy(t, tok, "--write-key-file", keyPath, "--path-token", gToken)
	if rc != 1 || !strings.HasPrefix(errs, "E_GOOGLE_PARTIAL: script_id=") {
		t.Fatalf("%d %s", rc, errs)
	}
	id := strings.Fields(strings.TrimPrefix(errs, "E_GOOGLE_PARTIAL: script_id="))[0]
	rc, out, errs := runDeploy(t, tok, "--write-key-file", keyPath, "--path-token", gToken, "--script-id", id)
	if rc != 0 || !strings.Contains(out, `"script_id":"`+id+`"`) || f.Projects() != 1 {
		t.Fatalf("resume: %d %s %s", rc, out, errs)
	}

	rc, _, errs = runDeploy(t, `{"access_token":"ya29.wrong"}`, "--write-key-file", keyPath, "--path-token", gToken)
	if rc != 1 || !strings.HasPrefix(errs, "E_GOOGLE_UNAUTHORIZED: ") || strings.Contains(errs, "ya29") {
		t.Fatalf("%d %s", rc, errs)
	}
	if rc, _, _ := runDeploy(t, "not json", "--write-key-file", keyPath, "--path-token", gToken); rc != 2 {
		t.Fatal("bad stdin")
	}
}

func TestAppsScriptVerbUsage(t *testing.T) {
	for _, argv := range [][]string{
		{"appsscript-script"},
		{"appsscript-check"},
		{"appsscript-clear", "--url", "x", "--write-key-file", "y"},
	} {
		if rc, _, _ := runG(t, argv...); rc != 2 {
			t.Errorf("%v: rc=%d", argv, rc)
		}
	}
	bad := writeTemp(t, "bad.key", []byte("not hex"))
	if rc, _, errs := runG(t, "appsscript-script", "--write-key-file", bad, "--path-token", gToken); rc != 2 || strings.Contains(errs, "not hex") {
		t.Errorf("bad key: %d %s", rc, errs)
	}
}

func TestAppsScriptFreshnessTarget(t *testing.T) {
	f := withFakeGoogle(t)
	keyPath, key := gKeyFile(t)
	code, _, _ := appsscript.Script(key, gToken)
	shown, _ := f.DeployByHand(code)
	url, _ := appsscript.NormalizeExecURL(shown, gToken)
	docPath, packPath := signedDocAndPack(t, url)
	target, wipe, err := appsScriptFreshnessTarget(url, keyPath, packPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer wipe()
	doc, _ := os.ReadFile(docPath)
	res, err := freshness.PublishAll(context.Background(), doc, []freshness.Target{target})
	if err != nil || !res[0].OK {
		t.Fatalf("%+v %v", res, err)
	}
}
