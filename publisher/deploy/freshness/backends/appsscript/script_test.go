package appsscript

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testToken = "AAAAAAAAAAAAAAAAAAAAAA"

func TestScriptPutsInTheKeyAndToken(t *testing.T) {
	code, manifest, err := Script(testKey(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(code, "__DAAL_") {
		t.Fatal("a placeholder was left in the script")
	}
	if !strings.Contains(code, "var WRITE_KEY_B64 = '"+base64.StdEncoding.EncodeToString(testKey())+"';") ||
		!strings.Contains(code, "var PATH_TOKEN = '"+testToken+"';") {
		t.Fatal("key or token not in the script")
	}
	var m struct {
		RuntimeVersion string `json:"runtimeVersion"`
		Webapp         struct {
			Access    string `json:"access"`
			ExecuteAs string `json:"executeAs"`
		} `json:"webapp"`
		OAuthScopes []string `json:"oauthScopes"`
	}
	if err := json.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatal(err)
	}
	if m.Webapp.Access != "ANYONE_ANONYMOUS" || m.Webapp.ExecuteAs != "USER_DEPLOYING" || m.RuntimeVersion != "V8" {
		t.Fatalf("manifest %+v", m)
	}
	if _, _, err := Script([]byte("short"), testToken); err == nil {
		t.Error("short key accepted")
	}
	if _, _, err := Script(testKey(), "has'quote'aaaaaaaaaaaaa"); err == nil {
		t.Error("token outside the alphabet accepted")
	}
}

// The script uses ContentService, PropertiesService and Utilities and
// nothing else: no UrlFetchApp (no external-request permission, and
// Google never sees the script fetch the relay), no other service.
func TestScriptUsesOnlyThreeServices(t *testing.T) {
	if strings.Contains(stripComments(codeTemplate), "UrlFetchApp") {
		t.Fatal("the script must never fetch")
	}
	allowed := map[string]bool{"ContentService": true, "PropertiesService": true, "Utilities": true}
	re := regexp.MustCompile(`\b([A-Z][A-Za-z]*(?:Service|App)|Utilities|Session|Logger|LockService|CacheService)\b`)
	for _, m := range re.FindAllString(stripComments(codeTemplate), -1) {
		if !allowed[m] {
			t.Errorf("the script uses %s", m)
		}
	}
}

func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func TestPathTokenAndWriteKeyShapes(t *testing.T) {
	tok, err := NewPathToken()
	if err != nil || !ValidPathToken(tok) {
		t.Fatalf("%q %v", tok, err)
	}
	k, err := NewWriteKey()
	if err != nil || len(k) != WriteKeySize {
		t.Fatal(err)
	}
}

// Run the real Code.gs under node with stand-ins for the three Apps
// Script services, and drive it with updates built here: the MAC, the
// seq rule, the chunking and the path token, in the script itself.
func TestCodeGsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	code, _, err := Script(testKey(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	small := `{"kind":"daal-refresh-v1","freshness":"e30="}`
	large := `{"kind":"daal-refresh-v1","freshness":"` + strings.Repeat("QUJD", 4000) + `"}` // > 3 chunks
	body := func(seq uint64, blob string, key []byte) string {
		b, err := UpdateBody(key, seq, []byte(blob))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	other := make([]byte, 32)
	cases := []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Arg  string `json:"arg"`
		Want string `json:"want"`
	}{
		{"get before any update", "get", testToken, `{"kind":"daal-refresh-v1"}`},
		{"get without k", "get", "", "Nothing here."},
		{"post good", "post", body(10, small, testKey()), `{"ok":true,"seq":10}`},
		{"get after", "get", testToken, small},
		{"get wrong k", "get", "BBBBBBBBBBBBBBBBBBBBBB", "Nothing here."},
		{"post same again", "post", body(10, small, testKey()), `{"ok":true,"seq":10}`},
		{"post same seq other blob", "post", body(10, large, testKey()), `{"ok":false,"error":"stale","seq":10}`},
		{"post older", "post", body(9, small, testKey()), `{"ok":false,"error":"stale","seq":10}`},
		{"post other key", "post", body(11, large, other), `{"ok":false,"error":"refused"}`},
		{"post bad mac", "post", strings.Replace(body(11, large, testKey()), `"mac":"`, `"mac":"0`, 1), `{"ok":false,"error":"refused"}`},
		{"post malformed", "post", `not json`, `{"ok":false,"error":"malformed"}`},
		{"post seq string", "post", `{"seq":"11","blob":"x","mac":"00"}`, `{"ok":false,"error":"malformed"}`},
		{"post large", "post", body(11, large, testKey()), `{"ok":true,"seq":11}`},
		{"get large", "get", testToken, large},
		{"post empty after large", "post", body(12, `{"kind":"daal-refresh-v1"}`, testKey()), `{"ok":true,"seq":12}`},
		{"get empty", "get", testToken, `{"kind":"daal-refresh-v1"}`},
	}
	harness := `
const fs = require('fs');
const crypto = require('crypto');
const store = {};
let lastSetAll = null;
global.PropertiesService = { getScriptProperties: () => ({
  getProperties: () => Object.assign({}, store),
  setProperties: (o, deleteAll) => {
    if (deleteAll) for (const k of Object.keys(store)) delete store[k];
    for (const k of Object.keys(o)) {
      if (typeof o[k] !== 'string') throw new Error('non-string property');
      if (Buffer.byteLength(o[k], 'utf8') > 9 * 1024) throw new Error('property over 9 KB');
      store[k] = o[k];
    }
  },
})};
global.ContentService = {
  MimeType: { TEXT: 'text', JSON: 'json' },
  createTextOutput: (s) => ({ s, setMimeType() { return this; } }),
};
const signed = (buf) => Array.from(buf).map((b) => (b > 127 ? b - 256 : b));
global.Utilities = {
  newBlob: (s) => ({ getBytes: () => signed(Buffer.from(s, 'utf8')) }),
  base64Decode: (s) => signed(Buffer.from(s, 'base64')),
  computeHmacSha256Signature: (msg, key) =>
    signed(crypto.createHmac('sha256', Buffer.from(key.map((b) => (b + 256) % 256)))
      .update(Buffer.from(msg.map((b) => (b + 256) % 256))).digest()),
};
eval(fs.readFileSync(process.argv[2], 'utf8'));
const cases = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const out = [];
for (const c of cases) {
  const r = c.kind === 'get' ? doGet({ parameter: c.arg ? { k: c.arg } : {} })
                             : doPost({ postData: { contents: c.arg } });
  out.push(r.s);
}
console.log(JSON.stringify(out));
`
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "h.js"), harness)
	writeFile(t, filepath.Join(dir, "Code.gs"), code)
	cj, _ := json.Marshal(cases)
	writeFile(t, filepath.Join(dir, "cases.json"), string(cj))
	out, err := exec.Command(node, filepath.Join(dir, "h.js"), filepath.Join(dir, "Code.gs"), filepath.Join(dir, "cases.json")).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("%.500s", out)
	}
	for i, c := range cases {
		if got[i] != c.Want {
			t.Errorf("%s: got %.120s, want %.120s", c.Name, got[i], c.Want)
		}
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
