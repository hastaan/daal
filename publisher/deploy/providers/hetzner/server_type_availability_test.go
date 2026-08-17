package hetzner

import (
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// serverTypeAvailableInLocation is the guard that keeps the wizard from
// auto-selecting a retired Hetzner server type whose pricing entry still
// lingers for a location — the cause of "create server: unsupported
// location for server type (invalid_input)" at provision time.
func TestServerTypeAvailableInLocation(t *testing.T) {
	fsn1 := &hcloud.Location{Name: "fsn1"}
	nbg1 := &hcloud.Location{Name: "nbg1"}

	avail := hcloud.ServerTypeLocation{Location: fsn1, Available: true}
	unavail := hcloud.ServerTypeLocation{Location: fsn1, Available: false}
	otherLoc := hcloud.ServerTypeLocation{Location: nbg1, Available: true}

	cases := []struct {
		name   string
		st     *hcloud.ServerType
		region string
		want   bool
	}{
		// Fixture type names are synthetic — this exercises the
		// availability-in-region logic, not Hetzner's catalogue. They are
		// still kept current so nobody reads a retired type as a live one:
		// verified 2026-08-17 against /v1/server_types that cpx12 exists and
		// is not deprecated, and that cx11/cx22 no longer exist at all
		// (cx22 is why a real provision failed with "server type 104 is
		// deprecated"), which is what makes it the right retired example.
		{
			name:   "available in region",
			st:     &hcloud.ServerType{Name: "cpx12", Locations: []hcloud.ServerTypeLocation{avail}},
			region: "fsn1",
			want:   true,
		},
		{
			name:   "present but unavailable in region (retired type)",
			st:     &hcloud.ServerType{Name: "cx22", Locations: []hcloud.ServerTypeLocation{unavail}},
			region: "fsn1",
			want:   false,
		},
		{
			name:   "available only in another region",
			st:     &hcloud.ServerType{Name: "cpx12", Locations: []hcloud.ServerTypeLocation{otherLoc}},
			region: "fsn1",
			want:   false,
		},
		{
			name:   "no per-location list, not deprecated -> fall back to allowed",
			st:     &hcloud.ServerType{Name: "cpx12"},
			region: "fsn1",
			want:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverTypeAvailableInLocation(tc.st, tc.region); got != tc.want {
				t.Fatalf("serverTypeAvailableInLocation(%s, %q) = %v, want %v",
					tc.st.Name, tc.region, got, tc.want)
			}
		})
	}
}
