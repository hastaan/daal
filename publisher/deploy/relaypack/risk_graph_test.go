package relaypack

import (
	"reflect"
	"testing"

	"daal/bundle-go/bundle"
)

func TestBuildSharedRiskGraph_TwoCandidatesShareIPTag(t *testing.T) {
	ids := []string{"r1", "r2"}
	entries := []bundle.RelayPackEntry{
		{PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:tcp443"}},
		{PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:udp443"}},
	}
	got := BuildSharedRiskGraph(ids, entries)
	want := []bundle.SharedRiskEdge{
		{Tag: "public_ip:5.75.0.1", Members: []string{"r1", "r2"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestBuildSharedRiskGraph_SingletonTagsDropped(t *testing.T) {
	ids := []string{"r1", "r2"}
	entries := []bundle.RelayPackEntry{
		{PublicRiskTags: []string{"public_ip:5.75.0.1", "sni:cover.example.com"}},
		{PublicRiskTags: []string{"public_ip:5.75.0.1", "sni:other.example.com"}},
	}
	got := BuildSharedRiskGraph(ids, entries)
	if len(got) != 1 {
		t.Fatalf("expected 1 edge (only public_ip shared), got %d: %+v", len(got), got)
	}
	if got[0].Tag != "public_ip:5.75.0.1" {
		t.Fatalf("unexpected tag %q", got[0].Tag)
	}
}

func TestBuildSharedRiskGraph_OutputSortedByTag(t *testing.T) {
	ids := []string{"r1", "r2"}
	entries := []bundle.RelayPackEntry{
		{PublicRiskTags: []string{"public_ip:5.75.0.1", "public_provider:hetzner"}},
		{PublicRiskTags: []string{"public_ip:5.75.0.1", "public_provider:hetzner"}},
	}
	got := BuildSharedRiskGraph(ids, entries)
	if len(got) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(got))
	}
	if got[0].Tag != "public_ip:5.75.0.1" || got[1].Tag != "public_provider:hetzner" {
		t.Fatalf("output not sorted by tag: %+v", got)
	}
}

func TestBuildSharedRiskGraph_MembersSorted(t *testing.T) {
	ids := []string{"r3", "r1", "r2"}
	entries := []bundle.RelayPackEntry{
		{PublicRiskTags: []string{"x"}},
		{PublicRiskTags: []string{"x"}},
		{PublicRiskTags: []string{"x"}},
	}
	got := BuildSharedRiskGraph(ids, entries)
	if len(got) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(got))
	}
	want := []string{"r1", "r2", "r3"}
	if !reflect.DeepEqual(got[0].Members, want) {
		t.Fatalf("members not sorted: %+v want %+v", got[0].Members, want)
	}
}

func TestBuildSharedRiskGraph_EmptyInput(t *testing.T) {
	got := BuildSharedRiskGraph(nil, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

func TestBuildSharedRiskGraph_MismatchedSlicesReturnsNil(t *testing.T) {
	got := BuildSharedRiskGraph([]string{"r1"}, []bundle.RelayPackEntry{})
	if got != nil {
		t.Fatalf("expected nil on parallel-slice mismatch, got %+v", got)
	}
}
