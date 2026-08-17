package refresh

import (
	"strings"
	"testing"
)

func TestParseFreshnessEndpoints_Encodings(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "https://a.example.com/f.json", []string{"https://a.example.com/f.json"}},
		{"json array",
			`["https://a.example.com/f.json","https://b.example.com/f.json"]`,
			[]string{"https://a.example.com/f.json", "https://b.example.com/f.json"}},
		{"space separated",
			"https://a.example.com/f.json https://b.example.com/f.json",
			[]string{"https://a.example.com/f.json", "https://b.example.com/f.json"}},
		{"comma separated",
			"https://a.example.com/f.json,https://b.example.com/f.json",
			[]string{"https://a.example.com/f.json", "https://b.example.com/f.json"}},
	}
	for _, c := range cases {
		got := ParseFreshnessEndpoints(c.in)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// Two URLs on one host are one provider wearing two costumes. Counting
// them as two would inflate N without buying any of the independence N
// is for.
func TestParseFreshnessEndpoints_DeduplicatesByHost(t *testing.T) {
	got := ParseFreshnessEndpoints(
		"https://a.example.com/1.json https://a.example.com/2.json https://b.example.net/1.json")
	if len(got) != 2 {
		t.Fatalf("got %v, want one URL per host", got)
	}
	if DistinctProviders(got) != 2 {
		t.Fatalf("provider count %d", DistinctProviders(got))
	}
}

// The count the UI renders as "providers" must not treat two
// subdomains of one registrable domain as two providers. They are one
// DNS zone, one account and one takedown, and telling an operator they
// have two-way redundancy there is the same lie as telling them one
// endpoint is a set.
func TestDistinctProviders_GroupsSubdomainsOfOneDomain(t *testing.T) {
	eps := ParseFreshnessEndpoints(
		"https://a.example.com/f.json https://b.example.com/f.json")
	if len(eps) != 2 {
		t.Fatalf("both URLs should survive as endpoints: %v", eps)
	}
	if n := DistinctProviders(eps); n != 1 {
		t.Fatalf("DistinctProviders = %d, want 1 — a.example.com and b.example.com "+
			"share a zone, an account and a takedown", n)
	}
	mixed := ParseFreshnessEndpoints(
		"https://a.example.com/f.json https://b.example.net/f.json https://c.example.org/f.json")
	if n := DistinctProviders(mixed); n != 3 {
		t.Fatalf("DistinctProviders = %d, want 3", n)
	}
}

// Each of these is either unfetchable by the raw-TLS fetcher or an
// own-goal (credentials inside a redistributable signed pack; an IP
// literal that cannot be re-pointed and is the cheapest possible
// blocklist entry; loopback, which would make the device poll itself).
func TestParseFreshnessEndpoints_DropsUnusable(t *testing.T) {
	bad := []string{
		"http://a.example.com/f.json",
		"https://user:pw@a.example.com/f.json",
		"https://192.0.2.7/f.json",
		"https://[2001:db8::1]/f.json",
		"https://localhost/f.json",
		"https://singlelabel/f.json",
		"ftp://a.example.com/f.json",
		"not a url at all",
	}
	for _, b := range bad {
		if got := ParseFreshnessEndpoints(b); len(got) != 0 {
			t.Errorf("%q was accepted as %v", b, got)
		}
	}
}

func TestParseFreshnessEndpoints_CapsCount(t *testing.T) {
	var parts []string
	for i := 0; i < 20; i++ {
		parts = append(parts, "https://h"+string(rune('a'+i))+".example.com/f.json")
	}
	got := ParseFreshnessEndpoints(strings.Join(parts, " "))
	if len(got) != maxFreshnessEndpoints {
		t.Fatalf("got %d endpoints, want the cap of %d", len(got), maxFreshnessEndpoints)
	}
}

// The shuffle must not lose or duplicate members — a "randomisation"
// that silently drops an endpoint would remove a provider from the set
// without anyone noticing.
func TestShuffleEndpoints_IsAPermutation(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e"}
	for i := 0; i < 50; i++ {
		got := ShuffleEndpoints(in)
		if len(got) != len(in) {
			t.Fatalf("length changed: %v", got)
		}
		seen := map[string]int{}
		for _, g := range got {
			seen[g]++
		}
		for _, want := range in {
			if seen[want] != 1 {
				t.Fatalf("%q appears %d times in %v", want, seen[want], got)
			}
		}
	}
	// And it must not mutate the caller's slice: the pack's own order
	// is used elsewhere (the scalar is the manifest-signed one).
	if strings.Join(in, "") != "abcde" {
		t.Fatalf("input was mutated: %v", in)
	}
}

func TestShuffleEndpoints_ActuallyReorders(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e", "f"}
	same := 0
	for i := 0; i < 40; i++ {
		if strings.Join(ShuffleEndpoints(in), "") == "abcdef" {
			same++
		}
	}
	// 1/720 per draw; 40 draws all identical would mean no shuffle.
	if same > 5 {
		t.Fatalf("%d/40 draws were the identity permutation", same)
	}
}
