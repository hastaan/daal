package fieldreport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"daal/bundle-go/envelope"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(here), "..", "..", "..", rel)
}

func sample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(repoFile(t, "test-rigs/field-probe/sample-report-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSampleV2IsValid(t *testing.T) {
	if _, err := Parse(sample(t)); err != nil {
		t.Fatal(err)
	}
}

func TestAddressGoldenVectors(t *testing.T) {
	b, err := os.ReadFile(repoFile(t, "specs/test-vectors/recipient-address-v1/golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		PubHex  string `json:"pub_hex"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) == 0 {
		t.Fatalf("golden: %v", err)
	}
	for _, v := range vs {
		raw, _ := hex.DecodeString(v.PubHex)
		var pub [32]byte
		copy(pub[:], raw)
		if got := EncodeAddress(pub); got != v.Address {
			t.Fatalf("encode %s = %s, want %s", v.PubHex, got, v.Address)
		}
		if back, err := DecodeAddress(v.Address); err != nil || back != pub {
			t.Fatalf("decode %s: %v", v.Address, err)
		}
	}
	if _, err := DecodeAddress("daal1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrkckuu"); err == nil {
		t.Fatal("bad checksum accepted")
	}
}

func TestSealOpenRoundTripAndPadding(t *testing.T) {
	r, err := Parse(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := envelope.NewReportKey()
	sealed, err := Seal(r, EncodeAddress(pub))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := envelope.DecryptReport(sealed, priv)
	if len(plain)%PadBucket != 0 {
		t.Fatalf("plaintext %d bytes is not padded to %d", len(plain), PadBucket)
	}
	got, err := Open(sealed, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReportID != r.ReportID || len(got.Probes) != len(r.Probes) {
		t.Fatal("round trip changed the report")
	}
	_, other, _ := envelope.NewReportKey()
	if _, err := Open(sealed, other); !errors.Is(err, envelope.ErrDecrypt) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestParseRefusesUnknownFieldsAndBadEnums(t *testing.T) {
	base := string(sample(t))
	for name, mut := range map[string]string{
		"unknown top field": strings.Replace(base, `"notes": ""`, `"notes": "", "ip": "x"`, 1),
		"unknown signal":    strings.Replace(base, `"dns_rcode": "noerror" } },`, `"dns_rcode": "noerror", "addr": "x" } },`, 1),
		"variant with dot":  strings.Replace(base, `"variant": "a",`, `"variant": "example.com",`, 1),
		"name mismatch":     strings.Replace(base, `"name": "tls_baseline"`, `"name": "github_feed"`, 1),
		"bad result":        strings.Replace(base, `"result": "bogon"`, `"result": "blocked"`, 1),
		"v1 schema":         strings.Replace(base, `"schema_version": 2`, `"schema_version": 1`, 1),
		"minute time":       strings.Replace(base, `T19:00Z`, `T19:07Z`, 1),
	} {
		if mut == base {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := Parse([]byte(mut)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestReportIDIsRandomAndShaped(t *testing.T) {
	a, _ := NewReportID()
	b, _ := NewReportID()
	if a == b || !reReportID.MatchString(a) {
		t.Fatalf("ids %q %q", a, b)
	}
	if !regexp.MustCompile(`^net-[a-z0-9]{8}\.dat$`).MatchString(SealedFileName()) {
		t.Fatal("sealed file name shape")
	}
}

// The JSON Schema and this package's closed sets are the same lists.
func TestSchemaFileMatchesGoEnums(t *testing.T) {
	b, err := os.ReadFile(repoFile(t, "test-rigs/field-probe/schema/probe-report-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	top := s["properties"].(map[string]any)
	props := top
	enumAt := func(path ...string) []string {
		var cur any = props
		for _, p := range path {
			m := cur.(map[string]any)
			if next, ok := m[p]; ok {
				cur = next
				continue
			}
			cur = m["properties"].(map[string]any)[p]
		}
		var out []string
		for _, v := range cur.(map[string]any)["enum"].([]any) {
			out = append(out, v.(string))
		}
		sort.Strings(out)
		return out
	}
	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	items := func(name string) map[string]any {
		return top[name].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	}
	probeProps := items("probes")
	check := func(label string, got []string, want map[string]bool) {
		if strings.Join(got, ",") != strings.Join(keys(want), ",") {
			t.Errorf("%s: schema %v, Go %v", label, got, keys(want))
		}
	}
	check("platform", enumAt("platform"), Platforms)
	check("network_label", enumAt("network_label"), NetworkLabels)
	check("net.kind", enumAt("net", "kind"), NetKinds)
	check("app.hello_fp", enumAt("app", "hello_fp"), HelloFPs)
	check("run.abort_reason", enumAt("run", "abort_reason"), AbortReasons)
	props = probeProps
	check("probes.result", enumAt("result"), Results)
	check("probes.target_role", enumAt("target_role"), TargetRoles)
	check("probes.phase", enumAt("phase"), Phases)
	check("signals.rx", enumAt("signals", "rx_bytes_bucket"), RxBuckets)
	check("signals.rtt", enumAt("signals", "connect_rtt_bucket_ms"), RTTBuckets)
	check("signals.handshake_end", enumAt("signals", "handshake_end"), HSEnds)
	check("signals.hello_fp", enumAt("signals", "hello_fp"), ProbeFPs)
	ids := map[string]bool{}
	for k := range ProbeNames {
		ids[k] = true
	}
	check("probes.id", enumAt("id"), ids)
	props = items("findings")
	check("findings.question", enumAt("question"), Questions)
	props = items("failures")
	check("failures.category", enumAt("category"), FailureCategories)
}
