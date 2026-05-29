package publisher

// Phase 3C. Helpers for the `daal-publish masque-bridge`
// subcommand. The CLI surface is documented in
// specs/publisher-cli-v1.md "Phase 3C" and
// specs/masque-ladder-v1.md.
//
// daal-publish never opens a network socket. The masque-bridge
// subcommand takes a publisher's MASQUE upstream endpoint URL
// and emits a `route stub` manifest fragment that the operator
// can splice into a full manifest.json before running
// `daal-publish bundle`. Because a publisher will typically
// publish multiple routes from a single bundle, we do not
// produce a full bundle here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// MasqueBridgeOptions are the inputs to the masque-bridge
// subcommand. Only the endpoint URL is mandatory; everything
// else has a documented default.
type MasqueBridgeOptions struct {
	Endpoint                     string        // https://host[:port]/path  (RFC 9298 / RFC 9484 endpoint)
	RouteID                      string        // optional; default derives from the endpoint host
	Validity                     time.Duration // optional; default 7d
	CaveatFAIR                   string        // optional; default empty (family default applies)
	ExperimentalMinEngineVersion string        // optional; default empty
	OutPath                      string        // path to write the route-stub JSON
}

// MasqueRouteStub is the JSON shape written to disk. It is a
// single route entry in the same shape as `manifest.routes[]`,
// ready to be spliced into a full manifest. The stub carries
// the new 3C `masque_endpoint` field (per
// specs/route-object-v1.md "Phase 3C") plus an empty
// `family_specific_config` object reserved for future per-route
// knobs (e.g. SNI / ALPN selection at the H2 rung).
type MasqueRouteStub struct {
	ID                           string          `json:"id"`
	ScarcityClass                string          `json:"scarcity_class"`
	TransportFamily              string          `json:"transport_family"`
	ConfigPath                   string          `json:"config_path"`
	ValidFrom                    string          `json:"valid_from"`
	ValidUntil                   string          `json:"valid_until"`
	MasqueEndpoint               string          `json:"masque_endpoint"`
	FamilySpecificConfig         json.RawMessage `json:"family_specific_config"`
	CaveatFAIR                   string          `json:"caveat_fa_ir,omitempty"`
	ExperimentalMinEngineVersion string          `json:"experimental_min_engine_version,omitempty"`
}

// MasqueBridge generates a route stub from a MASQUE endpoint
// URL. Returns the rendered stub (also written to OutPath if
// set) plus the derived URL host (so the CLI can echo a
// confirmation line).
func MasqueBridge(opts MasqueBridgeOptions) (*MasqueRouteStub, string, error) {
	if strings.TrimSpace(opts.Endpoint) == "" {
		return nil, "", errors.New("masque-bridge: --endpoint is required")
	}
	u, err := url.Parse(opts.Endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("masque-bridge: parse endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return nil, "", errors.New("masque-bridge: --endpoint must be https://")
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", errors.New("masque-bridge: --endpoint must have a host")
	}
	if u.EscapedPath() == "" || u.EscapedPath() == "/" {
		return nil, "", errors.New("masque-bridge: --endpoint must include a non-empty path")
	}

	id := opts.RouteID
	if id == "" {
		id = "mq-" + sanitizeHostForID(host)
	}
	validity := opts.Validity
	if validity == 0 {
		validity = 7 * 24 * time.Hour
	}

	now := time.Now().UTC()
	stub := &MasqueRouteStub{
		ID:                           id,
		ScarcityClass:                "experimental",
		TransportFamily:              string(bundle.TransportMASQUE),
		ConfigPath:                   "profiles/" + id + ".json",
		ValidFrom:                    now.Format(time.RFC3339),
		ValidUntil:                   now.Add(validity).Format(time.RFC3339),
		MasqueEndpoint:               opts.Endpoint,
		FamilySpecificConfig:         json.RawMessage(`{}`),
		CaveatFAIR:                   opts.CaveatFAIR,
		ExperimentalMinEngineVersion: opts.ExperimentalMinEngineVersion,
	}

	if opts.OutPath != "" {
		body, err := json.MarshalIndent(stub, "", "  ")
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(opts.OutPath, append(body, '\n'), 0o600); err != nil {
			return nil, "", fmt.Errorf("masque-bridge: write %s: %w", opts.OutPath, err)
		}
	}
	return stub, host, nil
}
