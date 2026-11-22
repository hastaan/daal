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

// The read token of slot "AAAAAAAAAAA" under testKey() (bytes 0..31),
// computed outside Go (Python's hmac) from the spec's formula and shared with the Rust side
// (daal-wizard addon_google tests) and the core recipient tests.
const (
	testSlot      = "AAAAAAAAAAA"
	testSlotToken = "IE3eTuAK8S6tNOQQlH44VQ"
)

func TestScriptPutsInTheKey(t *testing.T) {
	code, manifest, err := Script(testKey())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(code, "__DAAL_") {
		t.Fatal("a placeholder was left in the script")
	}
	if !strings.Contains(code, "var WRITE_KEY_B64 = '"+base64.StdEncoding.EncodeToString(testKey())+"';") {
		t.Fatal("key not in the script")
	}
	if strings.Contains(code, "PATH_TOKEN") {
		t.Fatal("the account's script has no per-relay token")
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
	if _, _, err := Script([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}

func TestReadTokenAndSlotURL(t *testing.T) {
	if got := ReadToken(testKey(), testSlot); got != testSlotToken {
		t.Fatalf("read token %q, want %q", got, testSlotToken)
	}
	if ReadToken(testKey(), "BAAAAAAAAAA") == testSlotToken {
		t.Fatal("another slot, the same token")
	}
	other := testKey()
	other[0] ^= 1
	if ReadToken(other, testSlot) == testSlotToken {
		t.Fatal("another key, the same token")
	}
	base := "https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec"
	u, err := SlotURL(base, testKey(), testSlot)
	if err != nil || u != base+"?s="+testSlot+"&k="+testSlotToken {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []struct{ base, slot string }{
		{base + "?k=x", testSlot},
		{base, "short"},
		{base, "has/slash00"},
		{"https://evil.example/macros/s/AKfycbx0123456789abcdefghij/exec", testSlot},
	} {
		if _, err := SlotURL(bad.base, testKey(), bad.slot); err == nil {
			t.Errorf("accepted %+v", bad)
		}
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

func TestSlotAndWriteKeyShapes(t *testing.T) {
	slot, err := NewSlot()
	if err != nil || !ValidSlot(slot) || slot == TestSlot {
		t.Fatalf("%q %v", slot, err)
	}
	if !ValidSlot(TestSlot) || !ValidReadToken(ReadToken(testKey(), slot)) {
		t.Fatal("shapes")
	}
	k, err := NewWriteKey()
	if err != nil || len(k) != WriteKeySize {
		t.Fatal(err)
	}
}

// Run the real Code.gs under node with stand-ins for the three Apps
// Script services, and drive it with updates built here: the slots and
// their read tokens, the MAC (which covers the slot), the per-slot seq
// rule, the chunking, and the bland answer, in the script itself.
func TestCodeGsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	code, _, err := Script(testKey())
	if err != nil {
		t.Fatal(err)
	}
	const slotB = "BBBBBBBBBBB"
	tokB := ReadToken(testKey(), slotB)
	small := `{"kind":"daal-refresh-v2","slot":"` + testSlot + `","freshness":"e30="}`
	large := `{"kind":"daal-refresh-v2","slot":"` + testSlot + `","freshness":"` + strings.Repeat("QUJD", 4000) + `"}` // > 3 chunks
	smallB := `{"kind":"daal-refresh-v2","slot":"` + slotB + `","freshness":"e30="}`
	body := func(slot string, seq uint64, blob string, key []byte) string {
		b, err := UpdateBody(key, slot, seq, []byte(blob))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// A body whose MAC was made for another slot than it names.
	moved := strings.Replace(body(testSlot, 30, small, testKey()), `"slot":"`+testSlot+`"`, `"slot":"`+slotB+`"`, 1)
	other := make([]byte, 32)
	cases := []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Arg  string `json:"arg"`
		S    string `json:"s"`
		Want string `json:"want"`
	}{
		{"get before any update", "get", testSlotToken, testSlot, "Nothing here."},
		{"get without k", "get", "", testSlot, "Nothing here."},
		{"get without slot", "get", testSlotToken, "", "Nothing here."},
		{"post good", "post", body(testSlot, 10, small, testKey()), "", `{"ok":true,"seq":10}`},
		{"get after", "get", testSlotToken, testSlot, small},
		{"get wrong k", "get", "BBBBBBBBBBBBBBBBBBBBBB", testSlot, "Nothing here."},
		{"get another slot's k", "get", tokB, testSlot, "Nothing here."},
		{"get another slot", "get", tokB, slotB, "Nothing here."},
		{"post same again", "post", body(testSlot, 10, small, testKey()), "", `{"ok":true,"seq":10}`},
		{"post same seq other blob", "post", body(testSlot, 10, large, testKey()), "", `{"ok":false,"error":"stale","seq":10}`},
		{"post older", "post", body(testSlot, 9, small, testKey()), "", `{"ok":false,"error":"stale","seq":10}`},
		{"post other key", "post", body(testSlot, 11, large, other), "", `{"ok":false,"error":"refused"}`},
		{"post bad mac", "post", strings.Replace(body(testSlot, 11, large, testKey()), `"mac":"`, `"mac":"0`, 1), "", `{"ok":false,"error":"refused"}`},
		{"post mac for another slot", "post", moved, "", `{"ok":false,"error":"refused"}`},
		{"post malformed", "post", `not json`, "", `{"ok":false,"error":"malformed"}`},
		{"post seq string", "post", `{"slot":"AAAAAAAAAAA","seq":"11","blob":"x","mac":"00"}`, "", `{"ok":false,"error":"malformed"}`},
		{"post no slot", "post", `{"seq":11,"blob":"x","mac":"00"}`, "", `{"ok":false,"error":"malformed"}`},
		{"post bad slot", "post", `{"slot":"a/b","seq":11,"blob":"x","mac":"00"}`, "", `{"ok":false,"error":"malformed"}`},
		// Another slot keeps its own number: 1 is fine there.
		{"post other slot, low seq", "post", body(slotB, 1, smallB, testKey()), "", `{"ok":true,"seq":1}`},
		{"get other slot", "get", tokB, slotB, smallB},
		{"post large", "post", body(testSlot, 11, large, testKey()), "", `{"ok":true,"seq":11}`},
		{"get large", "get", testSlotToken, testSlot, large},
		{"other slot untouched", "get", tokB, slotB, smallB},
		{"post empty after large", "post", body(testSlot, 12, string(Empty(testSlot)), testKey()), "", `{"ok":true,"seq":12}`},
		{"get empty", "get", testSlotToken, testSlot, string(Empty(testSlot))},
		{"full store", "post", body(slotB, 2, smallB+" ", testKey()), "", `{"ok":false,"error":"full"}`},
		{"other slot after a full store", "get", tokB, slotB, smallB},
	}
	harness := `
const fs = require('fs');
const crypto = require('crypto');
const store = {};
let full = false;
global.PropertiesService = { getScriptProperties: () => ({
  getProperties: () => Object.assign({}, store),
  setProperties: (o, deleteAll) => {
    if (full) throw new Error('quota');
    if (deleteAll) throw new Error('the script must never wipe other slots');
    for (const k of Object.keys(o)) {
      if (typeof o[k] !== 'string') throw new Error('non-string property');
      if (Buffer.byteLength(o[k], 'utf8') > 9 * 1024) throw new Error('property over 9 KB');
      store[k] = o[k];
    }
  },
  deleteProperty: (k) => { delete store[k]; },
})};
global.ContentService = {
  MimeType: { TEXT: 'text', JSON: 'json' },
  createTextOutput: (s) => ({ s, setMimeType() { return this; } }),
};
const signed = (buf) => Array.from(buf).map((b) => (b > 127 ? b - 256 : b));
const unsigned = (a) => Buffer.from(a.map((b) => (b + 256) % 256));
global.Utilities = {
  newBlob: (s) => ({ getBytes: () => signed(Buffer.from(s, 'utf8')) }),
  base64Decode: (s) => signed(Buffer.from(s, 'base64')),
  base64EncodeWebSafe: (a) => unsigned(a).toString('base64').replace(/\+/g, '-').replace(/\//g, '_'),
  computeHmacSha256Signature: (msg, key) =>
    signed(crypto.createHmac('sha256', unsigned(key)).update(unsigned(msg)).digest()),
};
eval(fs.readFileSync(process.argv[2], 'utf8'));
const cases = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const out = [];
for (const c of cases) {
  if (c.name === 'full store') full = true;
  const p = {};
  if (c.arg) p.k = c.arg;
  if (c.s) p.s = c.s;
  const r = c.kind === 'get' ? doGet({ parameter: p })
                             : doPost({ postData: { contents: c.arg } });
  out.push(r.s);
}
// Chunks of an earlier, longer text are gone once a shorter one is in.
const left = Object.keys(store).filter((k) => k.startsWith('s.AAAAAAAAAAA.c')).length;
out.push(String(left));
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
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases)+1 {
		t.Fatalf("%.500s", out)
	}
	for i, c := range cases {
		if got[i] != c.Want {
			t.Errorf("%s: got %.120s, want %.120s", c.Name, got[i], c.Want)
		}
	}
	if got[len(cases)] != "1" {
		t.Errorf("chunks left for the slot after the empty container: %s, want 1", got[len(cases)])
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
