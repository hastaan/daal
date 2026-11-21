// Code frozen from commit 079ef96 (2026-11-20). DO NOT EDIT the frozen
// parts; see endpoint_frozen.go. This file holds the small pieces of the
// old importer and bundle packages that plan_frozen.go reaches for, and
// one exported entry point for the test.

// Package oldrules is the route-planning half of the importer AS IT
// SHIPPED before the optional add-ons (S1, S2, B-4) put new data into
// packs: the endpoint commitment parser and checker, the import plan
// that refuses or keeps each route, the engine-config allowlist and the
// list of transport families a build understands. Signature, expiry and
// revocation checks are not copied: they did not change, and the test
// runs the current bundle.VerifyBundle (which is what proves the new
// members are covered by the signature) and the current
// relaypackvalidate.Validate (untouched by those items) before handing
// the pack to these rules.
//
// Test-only: internal to bundle/go/importer, imported by nothing but
// compat_old_test.go.
package oldrules

import (
	"bytes"
	"encoding/json"

	"daal/bundle-go/bundle"
)

// Transport family names, as endpoint_frozen.go spells them.
const (
	TransportVLESSReality = "vless-reality"
	TransportWebSocketTLS = "websocket-tls"
	TransportHysteria2    = "hysteria2"
	TransportTUIC         = "tuic"
	TransportAnyTLS       = "anytls"
	TransportNaive        = "naive"
	TransportShadowsocks  = "shadowsocks"
)

// State is the part of importer.State the plan touches: none of its
// methods, only the optional interfaces below by type assertion.
type State interface{}

// validTransport is bundle.validTransport at 079ef96.
func validTransport(value string) bool {
	switch value {
	case "vless-reality", "naive", "websocket-tls", "hysteria2", "tuic",
		"snowflake", "webtunnel", "masque", "shadowsocks", "tor-bridge",
		"wireguard", "amneziawg", "psiphon", "conjure", "transport_module",
		"lifeline_relay", "anytls", "other":
		return true
	}
	return false
}

// UsableRoutes is bundle.UsableRoutes at 079ef96.
func UsableRoutes(b *bundle.Bundle) []bundle.RouteManifestEntry {
	if b == nil {
		return nil
	}
	out := make([]bundle.RouteManifestEntry, 0, len(b.Manifest.Routes))
	for _, r := range b.Manifest.Routes {
		if validTransport(r.TransportFamily) {
			out = append(out, r)
		}
	}
	return out
}

// EngineFamilyConfigKeys and EngineFamilyConfig are bundle's at 079ef96.
var EngineFamilyConfigKeys = []string{"_desync", "_cover_names", "_report_to"}

func EngineFamilyConfig(familySpecificConfig json.RawMessage) string {
	if len(bytes.TrimSpace(familySpecificConfig)) == 0 {
		return ""
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &all); err != nil {
		return ""
	}
	kept := map[string]json.RawMessage{}
	for _, k := range EngineFamilyConfigKeys {
		if v, ok := all[k]; ok {
			kept[k] = v
		}
	}
	if len(kept) == 0 {
		return ""
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return ""
	}
	return string(out)
}

// rawMember is importer.rawMember at 079ef96.
func rawMember(object json.RawMessage, key string) ([]byte, bool) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(object, &probe) != nil {
		return nil, false
	}
	raw, ok := probe[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), raw...), true
}

// equalHex is importer.equalHex at 079ef96.
func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// ---- not frozen: the test's way in ------------------------------------

// StoredRoute is one route the old rules would store.
type StoredRoute struct {
	RouteID      string
	Family       string
	Profile      []byte
	Endpoint     []byte
	EngineConfig string
	Merged       bool
}

// Outcome is what the old importer would have done with a pack that
// had already passed signature and RelayPack validation.
type Outcome struct {
	Refused     bool
	Reason      string
	Err         error
	Stored      []StoredRoute
	Unavailable []UnavailableRoute
	Merged      int
}

// Plan runs the frozen planRoutes and the frozen persistence rule for
// the engine-config row (importer.go at 079ef96: EngineConfig is set
// for every route stored with a commitment).
func Plan(parsed *bundle.Bundle, st State, fingerprintHex string, continuity bool) Outcome {
	plan, reason, err := planRoutes(parsed, st, fingerprintHex, continuity)
	if err != nil {
		return Outcome{Refused: true, Reason: reason, Err: err}
	}
	out := Outcome{Unavailable: plan.unavailable, Merged: plan.merged}
	for _, pr := range plan.routes {
		sr := StoredRoute{RouteID: pr.route.ID, Family: pr.route.TransportFamily,
			Profile: pr.profile, Endpoint: pr.endpoint, Merged: pr.merged}
		if len(pr.endpoint) > 0 {
			sr.EngineConfig = EngineFamilyConfig(pr.route.FamilySpecificConfig)
		}
		out.Stored = append(out.Stored, sr)
	}
	return out
}
