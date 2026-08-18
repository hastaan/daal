package publisher

// DORMANT (Wave 5) — a route-stub emitter with no dialer behind
// it, and re-scoped downward besides. Kept, not deleted, because
// `bundle/go/cmd/daal-publish` still registers the
// `webtunnel-bridge` verb; that verb now prints the caveat below
// so the operator learns it at the point of use rather than from
// a spec.
//
// NOTHING DIALS THE STUB THIS EMITS. The route it writes declares
// `transport_family: "webtunnel"`. sing-box 1.13.12 registers no
// webtunnel outbound (its outbound registry is direct, block,
// selector, urltest, socks, http, shadowsocks, vmess, trojan,
// naive, tor, ssh, shadowtls, vless, anytls, plus the with_quic
// set), so a recipient importing this stub gets a route that
// imports cleanly, renders in the route list, and cannot connect.
// A family that mints but cannot be dialled is worse than no
// family — it is a route the user selects and loses.
//
// WHERE WEBTUNNEL ACTUALLY LIVES. It is a Tor pluggable
// transport. The reachable path is the `tor` outbound plus a
// torrc `Bridge webtunnel ...` line, not a first-class family
// with its own dialer; sing-box's `option/tor.go` takes
// `extra_args`, which is how multiple Bridge lines get expressed.
// Nothing publisher-side needs to mint it in that world — the
// bridge line is the artefact.
//
// AND IT IS THE WRONG COUNTRY. WebTunnel is field-effective in
// China and FAILS in Iran, which is this project's stated primary
// target. Older prose in this repo has it the other way round.
// Do not present webtunnel to an Iranian user as a recommended
// family; `caveat_fa_ir` exists on the stub for exactly this and
// is empty by default.
//
// ---- Original Phase 3A doc, retained verbatim ----
//
// Phase 3A. Helpers for the `daal-publish webtunnel-bridge`
// subcommand. The CLI surface is documented in
// specs/publisher-cli-v1.md and specs/webtunnel-route-v1.md.
//
// daal-publish never opens a network socket. The webtunnel-bridge
// subcommand takes a WebTunnel bridge endpoint description (URL,
// SNI, optional ALPN) and emits a `route stub` manifest fragment
// that the operator can splice into a full manifest.json before
// running `daal-publish bundle`. We do not produce a full bundle
// here because the same manifest typically holds multiple routes.

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

// WebTunnelBridgeOptions are the inputs to the webtunnel-bridge
// subcommand. Only the URL is mandatory; everything else has a
// documented default.
type WebTunnelBridgeOptions struct {
	URL                          string        // bridge URL: https://host[:port]/secret/path
	RouteID                      string        // optional; default derives from the URL host
	Validity                     time.Duration // optional; default 7d
	ALPN                         []string      // optional; default ["http/1.1"]
	CaveatFAIR                   string        // optional; default empty (family default applies)
	ExperimentalMinEngineVersion string        // optional; default empty
	OutPath                      string        // path to write the route-stub JSON
}

// WebTunnelRouteStub is the JSON shape written to disk. It is a
// single route entry in the same shape as
// `manifest.routes[]`, ready to be spliced into a full manifest.
// We deliberately produce the object without surrounding
// `routes:` wrapping so it can be splice-edited or programmed by
// upstream tooling.
type WebTunnelRouteStub struct {
	ID                           string          `json:"id"`
	ScarcityClass                string          `json:"scarcity_class"`
	TransportFamily              string          `json:"transport_family"`
	ConfigPath                   string          `json:"config_path"`
	ValidFrom                    string          `json:"valid_from"`
	ValidUntil                   string          `json:"valid_until"`
	FamilySpecificConfig         json.RawMessage `json:"family_specific_config"`
	CaveatFAIR                   string          `json:"caveat_fa_ir,omitempty"`
	ExperimentalMinEngineVersion string          `json:"experimental_min_engine_version,omitempty"`
}

// WebTunnelFamilyConfig captures the WebTunnel-specific knobs.
// See specs/webtunnel-route-v1.md.
type WebTunnelFamilyConfig struct {
	WebTunnelSecretPath string   `json:"webtunnel_secret_path"`
	WebTunnelSNI        string   `json:"webtunnel_sni"`
	WebTunnelALPN       []string `json:"webtunnel_alpn"`
}

// WebTunnelBridge generates a route stub from a bridge URL.
// Returns the rendered stub (also written to OutPath if set) plus
// the derived URL host (so the CLI can echo a confirmation line).
func WebTunnelBridge(opts WebTunnelBridgeOptions) (*WebTunnelRouteStub, string, error) {
	if strings.TrimSpace(opts.URL) == "" {
		return nil, "", errors.New("webtunnel-bridge: --url is required")
	}
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, "", fmt.Errorf("webtunnel-bridge: parse url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, "", errors.New("webtunnel-bridge: --url must be https://")
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", errors.New("webtunnel-bridge: --url must have a host")
	}
	secretPath := u.EscapedPath()
	if secretPath == "" || secretPath == "/" {
		return nil, "", errors.New("webtunnel-bridge: --url must include a non-empty secret path")
	}

	id := opts.RouteID
	if id == "" {
		id = "wt-" + sanitizeHostForID(host)
	}
	validity := opts.Validity
	if validity == 0 {
		validity = 7 * 24 * time.Hour
	}
	alpn := opts.ALPN
	if len(alpn) == 0 {
		alpn = []string{"http/1.1"}
	}

	now := time.Now().UTC()
	cfg := WebTunnelFamilyConfig{
		WebTunnelSecretPath: secretPath,
		WebTunnelSNI:        host,
		WebTunnelALPN:       alpn,
	}
	cfgJSON, err := json.Marshal(&cfg)
	if err != nil {
		return nil, "", fmt.Errorf("webtunnel-bridge: marshal config: %w", err)
	}

	stub := &WebTunnelRouteStub{
		ID:                           id,
		ScarcityClass:                "experimental",
		TransportFamily:              string(bundle.TransportWebTunnel),
		ConfigPath:                   "profiles/" + id + ".json",
		ValidFrom:                    now.Format(time.RFC3339),
		ValidUntil:                   now.Add(validity).Format(time.RFC3339),
		FamilySpecificConfig:         cfgJSON,
		CaveatFAIR:                   opts.CaveatFAIR,
		ExperimentalMinEngineVersion: opts.ExperimentalMinEngineVersion,
	}

	if opts.OutPath != "" {
		body, err := json.MarshalIndent(stub, "", "  ")
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(opts.OutPath, append(body, '\n'), 0o600); err != nil {
			return nil, "", fmt.Errorf("webtunnel-bridge: write %s: %w", opts.OutPath, err)
		}
	}
	return stub, host, nil
}

func sanitizeHostForID(host string) string {
	// Lowercase and replace dots to keep route IDs URL-safe and
	// stable under route-store collation.
	out := make([]byte, 0, len(host))
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c == '.' || c == ':' {
			c = '-'
		}
		out = append(out, c)
	}
	return string(out)
}
