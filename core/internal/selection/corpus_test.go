package selection

import (
	"testing"
	"time"

	"daal/core/routestore"
)

// TestCorpus_SelectorBindings binds the FRP-3 selector against the
// 7 FRP-2 corpus vectors that produce importable RelayPack rows. We
// don't re-parse the .sbp/.expected.json from disk here (that's the
// importer's job — covered by FRP-2 tests). Instead we replay the
// canonical RouteRows the importer would have produced and assert
// the selector's pure-function outputs (pick / shortlist / hard cdn
// rule).
//
// The 7 selector-path vectors:
//  1. direct-vps-minimal               (2 vps, no diversity)  V1.5
//  2. direct-vps-with-sni               (2 vps, sni diversity) V1.5
//  3. cdn-fronted-minimal               (1 cdn)                V1.6
//  4. cdn-fronted-with-origin           (1 cdn + origin tags)  V1.6
//  5. mixed-relaypack-direct-only       (2 vps + 1 vps)        V1.5
//  6. mixed-relaypack-direct-and-cdn    (1 vps + 1 cdn)        V1.6
//  7. legacy-non-relaypack              (legacy schema)         V1.5
//
// The other 9 corpus vectors model importer-rejection paths and
// produce no RouteRows; the selector never sees them.
type corpusCase struct {
	name     string
	rows     []routestore.RouteRow
	phase    Phase
	wantPick string
	wantSize int
}

func TestCorpus_SelectorBindings(t *testing.T) {
	cases := []corpusCase{
		{
			name: "direct-vps-minimal",
			rows: []routestore.RouteRow{
				makeRow("rp001-r1", "vless-reality", "direct_vps", "public_ip:5.75.0.1", "public_port:tcp443"),
				makeRow("rp001-r2", "vless-reality", "direct_vps", "public_ip:5.75.0.1", "public_port:tcp443"),
			},
			phase: PhaseV15, wantPick: "rp001-r1", wantSize: 2,
		},
		{
			name: "direct-vps-with-sni",
			rows: []routestore.RouteRow{
				makeRow("rp002-r1", "vless-reality", "direct_vps", "public_ip:5.75.0.1", "sni:www.bing.com"),
				makeRow("rp002-r2", "vless-reality", "direct_vps", "public_ip:5.75.0.1", "sni:www.example.com"),
			},
			phase: PhaseV15, wantPick: "rp002-r1", wantSize: 2,
		},
		{
			name: "cdn-fronted-minimal",
			rows: []routestore.RouteRow{
				makeRow("rp003-r1", "websocket-tls", "cdn_fronted", "cdn:cloudflare", "public_domain:e.example"),
			},
			phase: PhaseV16, wantPick: "rp003-r1", wantSize: 1,
		},
		{
			name: "cdn-fronted-with-origin",
			rows: func() []routestore.RouteRow {
				r := makeRow("rp004-r1", "websocket-tls", "cdn_fronted",
					"cdn:cloudflare", "public_domain:e.example")
				r.OriginRiskTags = []string{"origin_ip:5.75.0.1", "origin_asn:24940"}
				return []routestore.RouteRow{r}
			}(),
			phase: PhaseV16, wantPick: "rp004-r1", wantSize: 1,
		},
		{
			name: "mixed-relaypack-direct-only",
			rows: []routestore.RouteRow{
				makeRow("rp005-r1", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
				makeRow("rp005-r2", "vless-reality", "direct_vps", "public_ip:5.75.0.2"),
				makeRow("rp005-r3", "naive", "direct_vps", "public_ip:5.75.0.3"),
			},
			phase: PhaseV15, wantPick: "rp005-r1", wantSize: 3,
		},
		{
			name: "mixed-relaypack-direct-and-cdn",
			rows: []routestore.RouteRow{
				makeRow("rp006-r1", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
				makeRow("rp006-r2", "websocket-tls", "cdn_fronted", "cdn:cloudflare", "public_domain:e.example"),
			},
			phase: PhaseV16, wantPick: "rp006-r1", wantSize: 2,
		},
		{
			name: "legacy-non-relaypack",
			rows: []routestore.RouteRow{
				{
					RouteID:             "legacy-r1",
					TransportFamily:     "vless-reality",
					ScarcityClass:       "normal",
					SharedRiskGraphJSON: "[]",
				},
			},
			phase: PhaseV15, wantPick: "legacy-r1", wantSize: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Decide(Input{
				Routes: tc.rows, Phase: tc.phase, Mode: ModeNormal,
				Now:        time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
				DecisionID: "corpus-" + tc.name,
			})
			if out.Pick == nil {
				t.Fatalf("%s: expected pick", tc.name)
			}
			if out.Pick.RouteID != tc.wantPick {
				t.Errorf("%s: pick = %s; want %s", tc.name, out.Pick.RouteID, tc.wantPick)
			}
			if len(out.Shortlist) != tc.wantSize {
				t.Errorf("%s: shortlist size = %d; want %d", tc.name, len(out.Shortlist), tc.wantSize)
			}
		})
	}
}
