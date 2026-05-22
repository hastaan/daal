package cloudflare

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeFetcher struct {
	v4, v6  []string
	v4Err   error
	v6Err   error
	v4Calls int
	v6Calls int
}

func (f *fakeFetcher) FetchV4(_ context.Context) ([]string, error) {
	f.v4Calls++
	return f.v4, f.v4Err
}
func (f *fakeFetcher) FetchV6(_ context.Context) ([]string, error) {
	f.v6Calls++
	return f.v6, f.v6Err
}

type fakeApplier struct {
	gotID     string
	gotRanges *EdgeRanges
	returnID  string
	err       error
}

func (a *fakeApplier) ApplyCloudflareRule(_ context.Context, id string, r *EdgeRanges) (string, error) {
	a.gotID = id
	a.gotRanges = r
	if a.err != nil {
		return "", a.err
	}
	if a.returnID != "" {
		return a.returnID, nil
	}
	return id + "-applied", nil
}

func TestParseRangesBody_StripsCommentsAndBlanks(t *testing.T) {
	body := []byte("173.245.48.0/20\n# a comment\n\n103.21.244.0/22\n")
	got := parseRangesBody(body)
	want := []string{"173.245.48.0/20", "103.21.244.0/22"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parseRangesBody = %v, want %v", got, want)
	}
}

func TestFetchEdgeRanges_HappyPath(t *testing.T) {
	f := &fakeFetcher{
		v4: []string{"173.245.48.0/20"},
		v6: []string{"2400:cb00::/32"},
	}
	pinned := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	er, err := FetchEdgeRanges(context.Background(), f, func() time.Time { return pinned })
	if err != nil {
		t.Fatal(err)
	}
	if len(er.V4) != 1 || er.V4[0] != "173.245.48.0/20" {
		t.Errorf("v4 = %v", er.V4)
	}
	if len(er.V6) != 1 || er.V6[0] != "2400:cb00::/32" {
		t.Errorf("v6 = %v", er.V6)
	}
	if !er.FetchedAt.Equal(pinned) {
		t.Errorf("FetchedAt = %v, want %v", er.FetchedAt, pinned)
	}
	if f.v4Calls != 1 || f.v6Calls != 1 {
		t.Errorf("calls = (%d,%d), want (1,1)", f.v4Calls, f.v6Calls)
	}
}

func TestFetchEdgeRanges_RequiresFetcher(t *testing.T) {
	_, err := FetchEdgeRanges(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("want error when fetcher is nil")
	}
}

func TestFetchEdgeRanges_PropagatesV4Error(t *testing.T) {
	f := &fakeFetcher{v4Err: errors.New("502 bad gateway")}
	_, err := FetchEdgeRanges(context.Background(), f, nil)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestFetchEdgeRanges_PropagatesV6Error(t *testing.T) {
	f := &fakeFetcher{v4: []string{"x"}, v6Err: errors.New("timeout")}
	_, err := FetchEdgeRanges(context.Background(), f, nil)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestRefreshFirewall_Plumbing(t *testing.T) {
	f := &fakeFetcher{v4: []string{"1.2.3.0/24"}, v6: []string{"::/0"}}
	a := &fakeApplier{returnID: "fw-99"}
	id, ranges, err := RefreshFirewall(context.Background(), f, a, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if id != "fw-99" {
		t.Errorf("id = %q", id)
	}
	if a.gotID != "" {
		t.Errorf("applier got firewallID %q, want empty (create-new)", a.gotID)
	}
	if a.gotRanges == nil || len(a.gotRanges.V4) != 1 {
		t.Errorf("applier got ranges = %v", a.gotRanges)
	}
	if ranges == nil {
		t.Errorf("returned ranges nil")
	}
}

func TestRefreshFirewall_PropagatesFetchError(t *testing.T) {
	f := &fakeFetcher{v4Err: errors.New("net")}
	a := &fakeApplier{}
	_, _, err := RefreshFirewall(context.Background(), f, a, "fw-1", nil)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestRefreshFirewall_PropagatesApplyError(t *testing.T) {
	f := &fakeFetcher{v4: []string{"1.2.3.0/24"}}
	a := &fakeApplier{err: errors.New("hetzner 401")}
	_, _, err := RefreshFirewall(context.Background(), f, a, "fw-1", nil)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestHTTPSEdgeRangeFetcher_RejectsNonHTTPSURL(t *testing.T) {
	f := &HTTPSEdgeRangeFetcher{V4URL: "http://insecure.example", V6URL: "http://insecure.example"}
	if _, err := f.FetchV4(context.Background()); err == nil {
		t.Error("want error on http:// URL")
	}
	if _, err := f.FetchV6(context.Background()); err == nil {
		t.Error("want error on http:// URL")
	}
}

func TestNewHTTPSEdgeRangeFetcher_DefaultsAreCanonical(t *testing.T) {
	f := NewHTTPSEdgeRangeFetcher()
	if f.V4URL != CloudflareEdgeRangesV4URL {
		t.Errorf("V4URL = %q", f.V4URL)
	}
	if f.V6URL != CloudflareEdgeRangesV6URL {
		t.Errorf("V6URL = %q", f.V6URL)
	}
	if f.Timeout < time.Second {
		t.Errorf("Timeout too small: %v", f.Timeout)
	}
}
