package cloudflare

import (
	"strings"
	"testing"
)

func TestEdgeSeedsFromRanges(t *testing.T) {
	published := []string{"173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13", "2400:cb00::/32",
		"172.64.0.0/13", "bad", "0.0.0.0/0", "104.16.0.1/13", "104.16.0.0/13", "131.0.72.0/22"}
	got := EdgeSeedsFromRanges(published, 4)
	want := "104.16.0.0/13,172.64.0.0/13,173.245.48.0/20,103.21.244.0/22"
	if strings.Join(got, ",") != want {
		t.Fatalf("seeds = %v, want %s", got, want)
	}
	if got := EdgeSeedsFromRanges(published, 8); got[len(got)-1] != "2400:cb00::/32" || len(got) != 6 {
		t.Fatalf("seeds = %v: v6 after every v4, junk dropped", got)
	}
	if len(EdgeSeedsFromRanges(nil, 8)) != 0 {
		t.Fatal("seeds from nothing")
	}
}
