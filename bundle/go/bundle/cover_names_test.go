package bundle

import (
	"errors"
	"testing"
)

func TestCoverNames_ParsesTheSignedList(t *testing.T) {
	fsc := []byte(`{"_endpoint":{"v":1},"_cover_names":{"v":1,"names":[
		{"id":3,"name":"www.example.com","class":"foreign"},
		{"id":1,"name":"static.example.net","class":"cdn","cdn":"fastly"},
		{"id":7,"name":"mirror.example.org","class":"mirror","reality":true}]}}`)
	cn, err := CoverNamesFromFamilyConfig(fsc)
	if err != nil {
		t.Fatal(err)
	}
	if len(cn.Names) != 3 || cn.Names[0].Name != "www.example.com" || cn.Names[1].Cdn != "fastly" || !cn.Names[2].Reality {
		t.Fatalf("got %+v", cn)
	}
	if e, ok := cn.ByID(7); !ok || e.Name != "mirror.example.org" {
		t.Fatalf("ByID(7) = %+v %v", e, ok)
	}
	if _, ok := cn.ByID(2); ok {
		t.Fatal("ByID found an id the list does not hold")
	}
}

func TestCoverNames_AbsentIsNoList(t *testing.T) {
	for _, fsc := range []string{"", `{}`, `{"_desync":{"v":1}}`} {
		if _, err := CoverNamesFromFamilyConfig([]byte(fsc)); !errors.Is(err, ErrNoCoverNames) {
			t.Fatalf("%q: err = %v, want ErrNoCoverNames", fsc, err)
		}
	}
}

// Domestic names are refused at parse time, and the whole list with
// them: none of its names is ever offered.
func TestCoverNames_DomesticNamesAreRefused(t *testing.T) {
	for _, name := range []string{"www.example.ir", "ir.", "WWW.Example.IR", "shop.digikala.com", "aparat.com", "cdn.arvancloud.com",
		"x.arvancdn.com", "zarinpal.com", "www.tasnimnews.com", "xn--mgba3a4f16a", "a.xn--mgba3a4f16a"} {
		raw := []byte(`{"v":1,"names":[{"id":1,"name":"good.example.com","class":"foreign"},{"id":2,"name":"` + name + `","class":"foreign"}]}`)
		_, err := ParseCoverNames(raw)
		if !errors.Is(err, ErrCoverNameDomestic) {
			t.Fatalf("%s: err = %v, want ErrCoverNameDomestic", name, err)
		}
		if err != nil && contains(err.Error(), name) {
			t.Fatalf("the error names the name: %v", err)
		}
	}
	if _, err := ParseCoverNames([]byte(`{"v":1,"names":[{"id":1,"name":"good.example.com","class":"domestic"}]}`)); !errors.Is(err, ErrCoverNameDomestic) {
		t.Fatalf("class domestic: %v", err)
	}
	// Not domestic: a foreign name that merely contains the letters.
	if IsDomesticName("irving.example.com") || IsDomesticName("notaparat.com") {
		t.Fatal("false positive")
	}
}

func TestCoverNames_MalformedIsRefused(t *testing.T) {
	for _, raw := range []string{
		`{"v":2,"names":[{"id":1,"name":"a.example.com","class":"foreign"}]}`,
		`{"v":1,"names":[]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"foreign","extra":1}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"weird"}]}`,
		`{"v":1,"names":[{"id":1,"name":"192.0.2.1","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":1,"name":"localhost","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a_b.example.com","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"foreign"},{"id":2,"name":"a.example.com","class":"mirror"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"foreign"}],"x":1}`,
		// Not canonical: refused, never normalised.
		`{"v":1,"names":[{"id":1,"name":"A.example.com","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com.","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":1,"name":" a.example.com","class":"foreign"}]}`,
		// Ids: missing, out of range, used twice.
		`{"v":1,"names":[{"name":"a.example.com","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":0,"name":"a.example.com","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":10000,"name":"a.example.com","class":"foreign"}]}`,
		`{"v":1,"names":[{"id":2,"name":"a.example.com","class":"foreign"},{"id":2,"name":"b.example.com","class":"foreign"}]}`,
		// The cdn word: [a-z0-9-]{1,32}, on cdn entries and only there.
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"cdn","cdn":"Fast\u00e9"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"cdn","cdn":"a/b"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"cdn"}]}`,
		`{"v":1,"names":[{"id":1,"name":"a.example.com","class":"foreign","cdn":"fastly"}]}`,
	} {
		if _, err := ParseCoverNames([]byte(raw)); !errors.Is(err, ErrCoverNamesMalformed) {
			t.Fatalf("%s: err = %v, want ErrCoverNamesMalformed", raw, err)
		}
	}
	nine := `{"v":1,"names":[`
	for i := 0; i < CoverNamesMax+1; i++ {
		if i > 0 {
			nine += ","
		}
		nine += `{"id":` + string(rune('1'+i)) + `,"name":"n` + string(rune('a'+i)) + `.example.com","class":"foreign"}`
	}
	nine += `]}`
	if _, err := ParseCoverNames([]byte(nine)); !errors.Is(err, ErrCoverNamesMalformed) {
		t.Fatalf("over the cap: %v", err)
	}
}
