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
)

// RewriteProfilesForRecipient parses a signed operator `.sbp`, replaces
// each route's profile with a concrete client outbound built from
// `params` + the route's family/port, and re-emits the `.sbp` with the
// original manifest and signature. Routes whose family has no client
// renderer, or that are missing a required cred, cause an error (fail
// closed — a pack must not ship a route that can't connect).
func RewriteProfilesForRecipient(sbp []byte, params ClientConnParams) ([]byte, error) {
	b, err := bundle.ParseSBP(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		return nil, fmt.Errorf("rewrite: parse sbp: %w", err)
	}

	// Read every raw archive member so all side-files (manifest.sig,
	// publisher.pub, revocation.json, trust/*.json, cell/*, …) are
	// preserved verbatim. manifest.json is re-emitted by
	// BuildUnsignedBundle from b.Manifest, so we drop it here.
	files, err := rawArchiveFiles(sbp)
	if err != nil {
		return nil, fmt.Errorf("rewrite: read archive: %w", err)
	}
	delete(files, "manifest.json")

	for _, route := range b.Manifest.Routes {
		port := portFromProfile(b.Profiles[route.ConfigPath])
		if port == 0 {
			port = defaultClientPort(route.TransportFamily)
		}
		ob, err := ClientOutboundForFamily(route.TransportFamily, port, params)
		if err != nil {
			return nil, fmt.Errorf("rewrite: route %s (%s): %w",
				route.ID, route.TransportFamily, err)
		}
		files[route.ConfigPath] = ob
	}

	// Re-emit with the ORIGINAL manifest. Profiles are not signed, so
	// the signature (carried in files["manifest.sig"]) stays valid; the
	// manifest re-marshals canonically to the same bytes it was signed
	// over.
	out, err := bundle.BuildUnsignedBundle(b.Manifest, files)
	if err != nil {
		return nil, fmt.Errorf("rewrite: rebuild sbp: %w", err)
	}
	return out, nil
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

func defaultClientPort(family string) int {
	switch family {
	case "hysteria2", "tuic":
		return 443
	default:
		return 443
	}
}
