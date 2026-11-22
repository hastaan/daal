package bundle

import (
	"archive/zip"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestUpdateCarriers_RoundTrip(t *testing.T) {
	c := UpdateCarriers{GitTag: &GitTagCarrier{Owner: "quiet-owner", Repo: "notes.v2"}, DNS: &DNSCarrier{Zone: "n.example.org"}}
	raw, err := MarshalUpdateCarriers(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"v":1,"gittag":{"owner":"quiet-owner","repo":"notes.v2"},"dns":{"zone":"n.example.org"}}` {
		t.Fatalf("%s", raw)
	}
	got, err := ParseUpdateCarriersJSON(raw)
	if err != nil || *got.GitTag != *c.GitTag || *got.DNS != *c.DNS {
		t.Fatalf("%+v %v", got, err)
	}
	only, err := ParseUpdateCarriersJSON([]byte(`{"v":1}`))
	if err != nil || !only.Empty() {
		t.Fatalf("empty: %+v %v", only, err)
	}
	if again, _ := MarshalUpdateCarriers(*only); string(again) != `{"v":1}` {
		t.Fatalf("%s", again)
	}
}

func TestUpdateCarriers_Strict(t *testing.T) {
	for _, bad := range []string{
		``, `null`, `[]`, `{}`, `{"v":2}`, `{"v":"1"}`, `{"v":1,"x":1}`, `{"v":1,"v":1}`,
		`{"v":1}{}`, `{"v":1,"gittag":null}`, `{"v":1,"gittag":{"owner":"a"}}`,
		`{"v":1,"gittag":{"owner":"a","repo":"b","x":1}}`, `{"v":1,"gittag":{"owner":"a","repo":"b","owner":"c"}}`,
		`{"v":1,"gittag":{"owner":"-a","repo":"b"}}`, `{"v":1,"gittag":{"owner":"a--b","repo":"b"}}`,
		`{"v":1,"gittag":{"owner":"a/b","repo":"b"}}`, `{"v":1,"gittag":{"owner":"a","repo":".b"}}`,
		`{"v":1,"gittag":{"owner":"a","repo":"b.git"}}`, `{"v":1,"gittag":{"owner":"a","repo":"b?x"}}`,
		`{"v":1,"gittag":{"owner":"a","repo":"b%2f"}}`, `{"v":1,"gittag":{"owner":"` + strings.Repeat("a", 40) + `","repo":"b"}}`,
		`{"v":1,"dns":{"zone":"Example.org"}}`, `{"v":1,"dns":{"zone":"example.org."}}`, `{"v":1,"dns":{"zone":"org"}}`,
		`{"v":1,"dns":{"zone":"1.2.3.4"}}`, `{"v":1,"dns":{"zone":"-a.example.org"}}`, `{"v":1,"dns":{"zone":"a_b.example.org"}}`,
		`{"v":1,"dns":{"zone":"a..org"}}`, `{"v":1,"dns":{}}`, `{"v":1,"dns":{"zone":"` + strings.Repeat("a", 78) + `.org"}}`,
		`{"v":1,"pad":"` + strings.Repeat("x", 1100) + `"}`,
	} {
		if _, err := ParseUpdateCarriersJSON([]byte(bad)); !errors.Is(err, ErrUpdateCarriersMalformed) {
			t.Fatalf("accepted %q (%v)", bad, err)
		}
	}
	if _, err := MarshalUpdateCarriers(UpdateCarriers{DNS: &DNSCarrier{Zone: "x"}}); err == nil {
		t.Fatal("marshal of a bad zone")
	}
	if _, err := ParseUpdateCarriersJSON([]byte(`{"v":1,"dns":{"zone":"xn--mgba3a4f16a.xn--mgba3a4f16a"}}`)); err != nil {
		t.Fatalf("punycode: %v", err)
	}
}

func TestReadUpdateCarriers(t *testing.T) {
	mk := func(members map[string]string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for n, d := range members {
			w, _ := zw.Create(n)
			w.Write([]byte(d))
		}
		zw.Close()
		return buf.Bytes()
	}
	if _, err := ReadUpdateCarriers(mk(map[string]string{"manifest.json": "{}"})); !errors.Is(err, ErrNoUpdateCarriers) {
		t.Fatal(err)
	}
	if _, err := ReadUpdateCarriers(mk(map[string]string{UpdateCarriersPath: `{"v":9}`})); !errors.Is(err, ErrUpdateCarriersMalformed) {
		t.Fatal(err)
	}
	c, err := ReadUpdateCarriers(mk(map[string]string{UpdateCarriersPath: `{"v":1,"dns":{"zone":"n.example.org"}}`}))
	if err != nil || c.DNS.Zone != "n.example.org" || c.GitTag != nil {
		t.Fatal(err)
	}
	if _, err := ReadUpdateCarriers(mk(map[string]string{UpdateCarriersPath: strings.Repeat(" ", 2000)})); !errors.Is(err, ErrUpdateCarriersMalformed) {
		t.Fatal(err)
	}
}
