package publisher

// Phase 3D. Helpers for the `daal-publish conjure-bridge`
// subcommand. The CLI surface is documented in
// specs/publisher-cli-v1.md "Phase 3D" and
// specs/conjure-route-v1.md.
//
// daal-publish never opens a network socket. The
// conjure-bridge subcommand emits a `routes[]` entry stub for
// a Conjure Tap-Dance station + a phantom-pool selection.
// It validates phantom-subnet prefix-length floors (locked at
// /24 IPv4 and /32 IPv6 per the spec) and station pubkey
// length (32 bytes hex = 64 hex chars).

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// ConjureBridgeOptions are the inputs to the conjure-bridge
// subcommand.
type ConjureBridgeOptions struct {
	StationPubkey                string        // 32 bytes hex (64 hex chars). REQUIRED.
	PhantomSubnets               []string      // CIDR list, mixed v4/v6 OK. REQUIRED, non-empty.
	DecoyPool                    []string      // optional RFC 1123 hostnames.
	RouteID                      string        // optional; default cj-<station-fp-prefix>.
	Validity                     time.Duration // optional; default 7d.
	ScarcityClass                string        // optional; default "experimental".
	CaveatFAIR                   string        // optional.
	ExperimentalMinEngineVersion string        // optional.
	OutPath                      string        // optional output path.
}

// ConjureRouteStub is the JSON shape emitted to disk.
type ConjureRouteStub struct {
	ID                           string          `json:"id"`
	ScarcityClass                string          `json:"scarcity_class"`
	TransportFamily              string          `json:"transport_family"`
	ConfigPath                   string          `json:"config_path"`
	ValidFrom                    string          `json:"valid_from"`
	ValidUntil                   string          `json:"valid_until"`
	ConjurePhantomSubnets        []string        `json:"conjure_phantom_subnets"`
	ConjureStationPubkey         string          `json:"conjure_station_pubkey"`
	ConjureDecoyPool             []string        `json:"conjure_decoy_pool,omitempty"`
	FamilySpecificConfig         json.RawMessage `json:"family_specific_config"`
	CaveatFAIR                   string          `json:"caveat_fa_ir,omitempty"`
	ExperimentalMinEngineVersion string          `json:"experimental_min_engine_version,omitempty"`
}

// ConjureBridge validates inputs and emits a Conjure route
// stub. Returns the stub plus the station-pubkey-prefix used
// in the default route ID.
func ConjureBridge(opts ConjureBridgeOptions) (*ConjureRouteStub, string, error) {
	if len(opts.PhantomSubnets) == 0 {
		return nil, "", errors.New("conjure-bridge: --phantom-subnets is required (non-empty)")
	}
	for _, cidr := range opts.PhantomSubnets {
		if err := validateConjureSubnetPublisher(cidr); err != nil {
			return nil, "", fmt.Errorf("conjure-bridge: phantom subnet %q: %w", cidr, err)
		}
	}
	pkRaw, err := decodePubkeyPublisher(opts.StationPubkey)
	if err != nil {
		return nil, "", fmt.Errorf("conjure-bridge: station pubkey: %w", err)
	}
	for _, host := range opts.DecoyPool {
		if !validRFC1123HostnamePublisher(host) {
			return nil, "", fmt.Errorf("conjure-bridge: decoy host %q malformed", host)
		}
	}

	if opts.ScarcityClass == "" {
		opts.ScarcityClass = "experimental"
	}
	stationFPHex := hex.EncodeToString(pkRaw)
	id := opts.RouteID
	if id == "" {
		id = "cj-" + stationFPHex[:8]
	}
	validity := opts.Validity
	if validity == 0 {
		validity = 7 * 24 * time.Hour
	}

	now := time.Now().UTC()
	stub := &ConjureRouteStub{
		ID:                           id,
		ScarcityClass:                opts.ScarcityClass,
		TransportFamily:              string(bundle.TransportConjure),
		ConfigPath:                   "profiles/" + id + ".json",
		ValidFrom:                    now.Format(time.RFC3339),
		ValidUntil:                   now.Add(validity).Format(time.RFC3339),
		ConjurePhantomSubnets:        opts.PhantomSubnets,
		ConjureStationPubkey:         strings.ToLower(opts.StationPubkey),
		ConjureDecoyPool:             opts.DecoyPool,
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
			return nil, "", fmt.Errorf("conjure-bridge: write %s: %w", opts.OutPath, err)
		}
	}
	return stub, stationFPHex[:8], nil
}

// validateConjureSubnetPublisher applies the locked-at-3D
// /24 IPv4 + /32 IPv6 floors. Public-helper-private-name is
// intentional — the bundle parser has its own validator (kept
// stdlib-net-free for portability); this publisher-side helper
// uses net.ParseCIDR for the cleaner error messages.
func validateConjureSubnetPublisher(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return errors.New("not a parseable CIDR")
	}
	ones, _ := ipnet.Mask.Size()
	if ipnet.IP.To4() != nil {
		if ones < 24 {
			return errors.New("IPv4 prefix length must be >= /24")
		}
	} else {
		if ones < 32 {
			return errors.New("IPv6 prefix length must be >= /32")
		}
	}
	return nil
}

// decodePubkeyPublisher validates the 32-byte hex pubkey shape.
func decodePubkeyPublisher(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, errors.New("must be 64 hex chars (32 bytes)")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("not valid hex")
	}
	return b, nil
}

// validRFC1123HostnamePublisher mirrors the bundle parser's
// hostname check. Kept locally so this package has no
// import-cycle on bundle/.
func validRFC1123HostnamePublisher(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c == '-' ||
				(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9')) {
				return false
			}
		}
	}
	return true
}
