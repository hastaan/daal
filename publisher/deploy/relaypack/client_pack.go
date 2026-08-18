package relaypack

// client_pack.go — FRP-14 Tier-2: rewrite a signed operator `.sbp`'s
// per-route profiles with real client sing-box outbounds for one
// recipient, WITHOUT re-signing.
//
// Profiles are not covered by the manifest signature (VerifyBundle only
// checks that each route's ConfigPath exists in the archive — see
// bundle.validateRoute), so we can swap `profiles/<id>.json` freely and
// re-emit the bundle with the original manifest bytes + signature. The
// per-recipient .sbpx age envelope provides the in-transit integrity for
// the rewritten profiles.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/relayports"
)

// SkippedRoute records one route this rewrite could not make
// connectable, and why. Returned rather than swallowed: the operator
// has to be told, because the recipient's pack really is one tier
// smaller than the manifest claims.
type SkippedRoute struct {
	RouteID string
	Family  string
	Reason  string
}

// unavailableMarkerKey is stamped into a skipped route's profile.
//
// The manifest is SIGNED and re-emitted verbatim, so a route cannot be
// removed here — only its profile can be replaced. The marker leaves
// the profile without an outbound `type`, which is what makes the route
// fail closed at set-route on the client instead of dialling something
// wrong, and it names the family and reason so a human opening the pack
// (or a support conversation) gets the answer immediately rather than
// "outbound type missing".
const unavailableMarkerKey = "_daal_unavailable"

// RewriteProfilesForRecipient parses a signed operator `.sbp`, replaces
// each route's profile with a concrete client outbound built from
// `params` + the route's family/port, and re-emits the `.sbp` with the
// original manifest and signature.
//
// DEGRADES PER ROUTE, FAILS ONLY WHEN NOTHING RENDERS — the Wave-5
// repair. This used to return the FIRST renderer error, which meant one
// absent credential cost the recipient the entire pack. That is not
// hypothetical: a relay whose toolbox profile enabled tuic (or
// shadowsocks, or anytls) but whose pinned `daal-relay-mgmt` artifact
// predates the family reports the credential empty — the deliberate
// fail-closed signal described in mgmt/users.go — and the old code
// turned that signal into "no recipient can be added to this relay at
// all", losing vless-reality, hysteria2, naive and websocket-tls with
// it. The blast radius of the old behaviour was strictly worse than the
// problem it was protecting against.
//
// So: a route whose credential is missing is SKIPPED and reported; the
// routes that can be rendered are rendered. A pack with zero renderable
// routes is still an error, because that pack is not a pack.
//
// The skipped list is not decoration. Callers MUST surface it — an
// operator who is not told has shipped a pack one tier smaller than the
// one they think they shipped, which is the same silent-shrink failure
// this wave spent a lane removing elsewhere.
func RewriteProfilesForRecipient(sbp []byte, params ClientConnParams) ([]byte, []SkippedRoute, error) {
	b, err := bundle.ParseSBP(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return nil, nil, fmt.Errorf("rewrite: parse sbp: %w", err)
	}

	// Read every raw archive member so all side-files (manifest.sig,
	// publisher.pub, revocation.json, trust/*.json, cell/*, …) are
	// preserved verbatim. manifest.json is re-emitted by
	// BuildUnsignedBundle from b.Manifest, so we drop it here.
	files, err := rawArchiveFiles(sbp)
	if err != nil {
		return nil, nil, fmt.Errorf("rewrite: read archive: %w", err)
	}
	delete(files, "manifest.json")

	var skipped []SkippedRoute
	rendered := 0
	for _, route := range b.Manifest.Routes {
		port := portFromProfile(b.Profiles[route.ConfigPath])
		if port == 0 {
			port = defaultClientPort(route.TransportFamily)
		}
		ob, err := ClientOutboundForFamily(route.TransportFamily, port, params)
		if err != nil {
			skipped = append(skipped, SkippedRoute{
				RouteID: route.ID,
				Family:  route.TransportFamily,
				Reason:  err.Error(),
			})
			files[route.ConfigPath] = markUnavailable(
				b.Profiles[route.ConfigPath], route.TransportFamily, err)
			continue
		}
		files[route.ConfigPath] = ob
		rendered++
	}
	if rendered == 0 {
		return nil, skipped, fmt.Errorf(
			"rewrite: not one of the %d route(s) in this pack could be made connectable "+
				"(first: %s); check the relay's creds payload and its daal-relay-mgmt artifact pin",
			len(b.Manifest.Routes), firstReason(skipped))
	}

	// Re-emit with the ORIGINAL manifest. Profiles are not signed, so
	// the signature (carried in files["manifest.sig"]) stays valid; the
	// manifest re-marshals canonically to the same bytes it was signed
	// over.
	out, err := bundle.BuildUnsignedBundle(b.Manifest, files)
	if err != nil {
		return nil, skipped, fmt.Errorf("rewrite: rebuild sbp: %w", err)
	}
	return out, skipped, nil
}

// markUnavailable returns the profile bytes for a route that could not
// be rendered: the original family-specific config (so `port` and
// `_relaypack` survive for anything that reads them) plus a marker
// naming the family and the reason. Deliberately still carries NO
// outbound `type`, so the client refuses the route rather than dialling
// a half-built one.
func markUnavailable(orig []byte, family string, cause error) []byte {
	doc := map[string]any{}
	if len(orig) > 0 {
		_ = json.Unmarshal(orig, &doc)
	}
	doc[unavailableMarkerKey] = map[string]any{
		"family": family,
		"reason": cause.Error(),
	}
	out, err := json.Marshal(doc)
	if err != nil {
		// Cannot happen for a map of strings; if it somehow does, an
		// empty object is still type-less and still fails closed.
		return []byte(`{"` + unavailableMarkerKey + `":{"family":"` + family + `"}}`)
	}
	return out
}

func firstReason(s []SkippedRoute) string {
	if len(s) == 0 {
		return "no reason recorded"
	}
	return s[0].Family + ": " + s[0].Reason
}

// rawArchiveFiles returns every zip member of the .sbp as name→bytes.
func rawArchiveFiles(sbp []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		out[f.Name] = data
	}
	return out, nil
}

// portFromProfile extracts the "port" field from a metadata-style
// profile ({"port":443,"_relaypack":{…}}); 0 if absent/unparseable.
func portFromProfile(profile []byte) int {
	if len(profile) == 0 {
		return 0
	}
	var m struct {
		Port int `json:"port"`
	}
	if json.Unmarshal(profile, &m) != nil {
		return 0
	}
	return m.Port
}

// defaultClientPort is the fallback when a pack's profile metadata
// carries no explicit "port". It defers to relayports, which is the one
// place a family's port is decided — the old hard-coded 443 was right
// for every family that existed then and silently wrong for tuic, whose
// inbound moved to 8443/udp when BUG-14 was fixed (443/udp is
// hysteria2's; two UDP inbounds on one port is a relay that does not
// boot). A fallback that disagrees with the box is a route that mints
// and cannot be dialled.
func defaultClientPort(family string) int {
	return relayports.For(family).Port
}
