package bundle

// cdn_endpoint.go — the signed commitment of a CDN-fronted route
// (specs/relaypack-v1.md "The CDN-fronted endpoint";
// docs/optional-addons-plan.md §2.2).
//
// A CDN-fronted `websocket-tls` route commits to a HOST NAME and a ROOT
// SET instead of an address and a key pin: the recipient dials an edge
// address inside a signed seed prefix, presents the host name (inside
// ECH), and verifies the edge's certificate against roots whose
// digests are signed.
//
// WHERE IT TRAVELS, AND WHY. Not in `_endpoint`. That member is decoded
// strictly on every build since endpoint commitments (endpoint.go), and
// an unknown member there refuses the WHOLE pack — every other route
// and the freshness merge of the signed skeleton with it. So this
// commitment is its own sibling member, `_cdn_endpoint`, and the route
// carries NO `_endpoint`. The recipient's outbound for the route is
// likewise not at the top of the profile: it is wrapped under
// CDNOutboundKey next to the minter's `_daal_unavailable` marker. An
// earlier build therefore sees a route with no commitment and no
// outbound — "not offered" — skips that one route and uses the rest of
// the pack as before. Proved against a frozen copy of the earlier rules:
// bundle/go/importer/compat_old_test.go.
//
// And the other way round: a `_cdn_endpoint` THIS build cannot read (a
// later version, an unknown member) makes that one route unavailable,
// never the pack. The member is signed, so a shape this build does not
// know is a newer publisher, not tampering; not storing the route is
// the closed reading.
//
// What is checked once the route is in (CheckCDNOutbound) is as strict
// as the direct rule: the outbound can only reach an edge address inside
// a signed prefix, present the signed name (and Host), trust only the
// signed roots, and — unless the signed plain_fallback flag says
// otherwise — only with the signed ECH configuration.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// CDNEndpointKey is the reserved family_specific_config member that
// carries a CDN-fronted route's commitment.
const CDNEndpointKey = "_cdn_endpoint"

// CDNOutboundKey is the member of a CDN-fronted route's PROFILE that
// holds the recipient's outbound. The profile has no top-level `type`
// (and carries the `_daal_unavailable` marker), so builds that predate
// this file see no outbound and skip the route alone.
const CDNOutboundKey = "_daal_cdn_outbound"

// CDNEndpointVersion is the only `_cdn_endpoint` version this build
// reads.
const CDNEndpointVersion = 1

// CDNCloudflare is the only CDN this build knows.
const CDNCloudflare = "cloudflare"

// Limits of the commitment.
const (
	MaxEdgeSeeds     = 8
	MaxTLSRoots      = 8
	MaxECHConfigSize = 512
)

var (
	// ErrNoCDNEndpoint: the config carries no `_cdn_endpoint`.
	ErrNoCDNEndpoint = errors.New("bundle: no _cdn_endpoint in family_specific_config")
	// ErrCDNEndpointMalformed: `_cdn_endpoint` is present and this
	// build cannot use it. The route is unavailable; the pack is not
	// refused for it.
	ErrCDNEndpointMalformed = errors.New("bundle: malformed CDN endpoint commitment")
)

// CDNEndpoint is a CDN-fronted route's signed commitment.
type CDNEndpoint struct {
	V int `json:"v"`
	// Server is the route's host name, never resolved by a recipient.
	Server string `json:"server"`
	Port   int    `json:"port"`
	// ServerName equals Server: the TLS name (inside ECH) and the
	// WebSocket Host.
	ServerName string `json:"server_name"`
	CDN        string `json:"cdn"`
	// EdgeSeeds are 1–8 canonical CIDR prefixes the recipient picks an
	// edge address from.
	EdgeSeeds []string `json:"edge_seeds"`
	// ECHConfig is standard base64 of the ECHConfigList; "" when the
	// zone serves none.
	ECHConfig string `json:"ech_config,omitempty"`
	// TLSRootsSHA256 are 1–8 standard-base64 SHA-256 digests of root
	// certificates' SubjectPublicKeyInfo.
	TLSRootsSHA256 []string `json:"tls_roots_sha256"`
	// PlainFallback is the signed flag of owner decision D-2: a hello
	// without ECH (which shows the zone name) is allowed only when set.
	PlainFallback bool `json:"plain_fallback,omitempty"`
}

// ParseCDNEndpoint reads and validates `_cdn_endpoint` for a route of
// the given family. ErrNoCDNEndpoint when absent; ErrCDNEndpointMalformed
// for anything this build cannot fully enforce.
func ParseCDNEndpoint(family string, familySpecificConfig json.RawMessage) (*CDNEndpoint, error) {
	if len(bytes.TrimSpace(familySpecificConfig)) == 0 {
		return nil, ErrNoCDNEndpoint
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCDNEndpointMalformed, err)
	}
	raw, ok := probe[CDNEndpointKey]
	if !ok {
		return nil, ErrNoCDNEndpoint
	}
	return ParseCDNEndpointJSON(family, raw)
}

// HasCDNEndpoint reports whether the config carries a `_cdn_endpoint`
// member at all, usable or not.
func HasCDNEndpoint(familySpecificConfig json.RawMessage) bool {
	var probe map[string]json.RawMessage
	if json.Unmarshal(familySpecificConfig, &probe) != nil {
		return false
	}
	_, ok := probe[CDNEndpointKey]
	return ok
}

// ParseCDNEndpointJSON parses one `_cdn_endpoint` object — as signed,
// or as a device stored it as the route's commitment — strictly, and
// validates it.
func ParseCDNEndpointJSON(family string, raw []byte) (*CDNEndpoint, error) {
	var ep CDNEndpoint
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ep); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCDNEndpointMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrCDNEndpointMalformed)
	}
	if err := ep.Validate(family); err != nil {
		return nil, err
	}
	return &ep, nil
}

// IsCDNCommitment reports whether a stored commitment (the JSON a
// device keeps beside a route) is a CDN-fronted one. It is the one test
// every reader of a stored commitment uses to choose a parser: a direct
// Endpoint has no `cdn` member and a CDNEndpoint always has one.
func IsCDNCommitment(raw []byte) bool {
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	_, ok := probe["cdn"]
	return ok
}

// Validate checks that the commitment is complete and in canonical
// form. Run by the publisher before signing and by the recipient before
// any comparison.
func (e *CDNEndpoint) Validate(family string) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCDNEndpointMalformed, fmt.Sprintf(format, args...))
	}
	if e == nil {
		return ErrNoCDNEndpoint
	}
	if family != string(TransportWebSocketTLS) {
		return bad("a CDN-fronted route must be websocket-tls, not %q", family)
	}
	if e.V != CDNEndpointVersion {
		return bad("version %d (this build reads %d)", e.V, CDNEndpointVersion)
	}
	if e.CDN != CDNCloudflare {
		return bad("cdn %q", e.CDN)
	}
	if err := checkCoverName(e.Server); err != nil {
		return bad("server: %v", err)
	}
	if IsDomesticName(e.Server) {
		return bad("server is a domestic name")
	}
	if e.ServerName != e.Server {
		return bad("server_name must equal server")
	}
	if e.Port < 1 || e.Port > 65535 {
		return bad("port %d", e.Port)
	}
	if len(e.EdgeSeeds) < 1 || len(e.EdgeSeeds) > MaxEdgeSeeds {
		return bad("%d edge_seeds (want 1..%d)", len(e.EdgeSeeds), MaxEdgeSeeds)
	}
	seen := map[string]bool{}
	for _, s := range e.EdgeSeeds {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Masked() != p || p.String() != s {
			return bad("edge seed %q is not a canonical prefix", s)
		}
		a := p.Addr()
		if !a.IsGlobalUnicast() || a.IsPrivate() || a.Is4In6() {
			return bad("edge seed %q is not a public prefix", s)
		}
		if seen[s] {
			return bad("edge seed %q repeated", s)
		}
		seen[s] = true
	}
	if e.ECHConfig != "" {
		b, err := decodeStdB64(e.ECHConfig)
		if err != nil || len(b) < 2 || len(b) > MaxECHConfigSize ||
			int(binary.BigEndian.Uint16(b[:2])) != len(b)-2 {
			return bad("ech_config is not a base64 ECHConfigList of at most %d bytes", MaxECHConfigSize)
		}
	}
	if len(e.TLSRootsSHA256) < 1 || len(e.TLSRootsSHA256) > MaxTLSRoots {
		return bad("%d tls_roots_sha256 (want 1..%d)", len(e.TLSRootsSHA256), MaxTLSRoots)
	}
	seen = map[string]bool{}
	for _, r := range e.TLSRootsSHA256 {
		b, err := decodeStdB64(r)
		if err != nil || len(b) != sha256.Size {
			return bad("tls_roots_sha256 entry is not standard base64 of 32 bytes")
		}
		if seen[r] {
			return bad("tls_roots_sha256 entry repeated")
		}
		seen[r] = true
	}
	return nil
}

func decodeStdB64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("not canonical")
	}
	return b, nil
}

// EdgeSeedPrefixes returns the parsed seeds (Validate proved they parse).
func (e *CDNEndpoint) EdgeSeedPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(e.EdgeSeeds))
	for _, s := range e.EdgeSeeds {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// InEdgeSeeds reports whether addr is an IP address inside one of the
// signed seed prefixes. A host name is never inside.
func (e *CDNEndpoint) InEdgeSeeds(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	for _, p := range e.EdgeSeedPrefixes() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// FirstEdgeAddress is the first host address of the first seed: the
// deterministic address a merge writes when the device's edge address
// is no longer inside the seeds. The engine's edge pick replaces it.
func (e *CDNEndpoint) FirstEdgeAddress() string {
	ps := e.EdgeSeedPrefixes()
	if len(ps) == 0 {
		return ""
	}
	a := ps[0].Addr().Next()
	if !ps[0].Contains(a) {
		a = ps[0].Addr()
	}
	return a.String()
}

// ECHConfigPEM is the sing-box form of the committed ECH configuration
// (`tls.ech.config`), or nil when none is committed.
func (e *CDNEndpoint) ECHConfigPEM() []string {
	if e.ECHConfig == "" {
		return nil
	}
	b, err := decodeStdB64(e.ECHConfig)
	if err != nil {
		return nil
	}
	text := strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: b})), "\n")
	return strings.Split(text, "\n")
}

// CDNProfileOutbound returns the outbound a CDN-fronted route's profile
// carries: the object under CDNOutboundKey, or the profile itself when
// it is a top-level outbound. nil, false when it holds none (the signed
// skeleton's metadata-only profile).
func CDNProfileOutbound(profile []byte) ([]byte, bool) {
	if ProfileOutboundType(profile) != "" {
		return profile, true
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(profile, &probe) != nil {
		return nil, false
	}
	inner, ok := probe[CDNOutboundKey]
	if !ok || ProfileOutboundType(inner) == "" {
		return nil, false
	}
	return append([]byte(nil), inner...), true
}

// WrapCDNOutbound is the profile a minter writes for a CDN-fronted
// route: the outbound under CDNOutboundKey and the `_daal_unavailable`
// marker, and NO top-level `type`. Builds that predate the CDN route
// read that as "not offered" and keep the rest of the pack; this build
// unwraps it (CDNProfileOutbound).
func WrapCDNOutbound(outbound []byte) ([]byte, error) {
	if ProfileOutboundType(outbound) == "" {
		return nil, errors.New("bundle: WrapCDNOutbound: not an outbound")
	}
	return json.Marshal(map[string]any{
		UnavailableMarkerKey: map[string]string{
			"family": string(TransportWebSocketTLS),
			"reason": "a way in through a CDN; this app is too old for it",
		},
		CDNOutboundKey: json.RawMessage(outbound),
	})
}

// CheckCDNOutbound verifies that an outbound agrees with a CDN-fronted
// route's signed commitment. nil means: this outbound can only reach an
// edge address inside a signed prefix, asking for the signed name, and
// can only accept a certificate chaining to a signed root.
//
// The outbound must be vless over a `ws` transport whose Host is
// server_name; TLS on with tls.server_name = server_name; `server` an IP
// address inside one of edge_seeds and server_port = port; no key pin,
// no REALITY, no tls.insecure, no trust anchor read from the device; at
// least one root installed as tls.certificate, every one of which has a
// listed SubjectPublicKeyInfo digest (so the outbound trusts nothing
// else, whatever the platform's roots); ECH on with exactly the
// committed configuration — or, only when plain_fallback is signed, ECH
// off. The general rules of CheckOutbound (plain member names, no
// detour or bind knobs, no server_ports) apply unchanged, and extend to
// the `transport` and `tls.ech` objects.
func CheckCDNOutbound(ep *CDNEndpoint, profile []byte) error {
	if ep == nil {
		return ErrEndpointUnauthenticated
	}
	if err := ep.Validate(string(TransportWebSocketTLS)); err != nil {
		return err
	}
	var ob map[string]any
	if err := json.Unmarshal(profile, &ob); err != nil {
		return mismatch("profile is not a JSON object")
	}
	if err := plainKeys("outbound", ob); err != nil {
		return err
	}
	tls, _ := ob["tls"].(map[string]any)
	if err := plainKeys("tls", tls); err != nil {
		return err
	}
	if r, has := tls["reality"]; has {
		rm, _ := r.(map[string]any)
		if err := plainKeys("tls.reality", rm); err != nil {
			return err
		}
		if on, _ := rm["enabled"].(bool); on || rm == nil {
			return mismatch("reality on a CDN-fronted route")
		}
	}
	ech, _ := tls["ech"].(map[string]any)
	if err := plainKeys("tls.ech", ech); err != nil {
		return err
	}
	transport, _ := ob["transport"].(map[string]any)
	if err := plainKeys("transport", transport); err != nil {
		return err
	}
	if str(ob["type"]) != "vless" {
		return mismatch("outbound type %q is not vless", str(ob["type"]))
	}
	server := str(ob["server"])
	if !ep.InEdgeSeeds(server) {
		return mismatch("server is not an address inside the signed edge seeds")
	}
	if port, ok := asInt(ob["server_port"]); !ok || port != ep.Port {
		return mismatch("port")
	}
	for _, k := range []string{"detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "netns", "server_ports"} {
		if _, has := ob[k]; has {
			return mismatch("outbound sets %q", k)
		}
	}

	// The WebSocket: Host is the signed name, and is said once.
	if transport == nil || str(transport["type"]) != "ws" {
		return mismatch("transport is not ws")
	}
	headers, _ := transport["headers"].(map[string]any)
	if _, has := transport["headers"]; has && headers == nil {
		return mismatch("ws headers are not an object")
	}
	hosts := 0
	for name, v := range headers {
		if !strings.EqualFold(name, "host") {
			continue
		}
		hosts++
		vals := stringList(v)
		if len(vals) != 1 || vals[0] != ep.ServerName {
			return mismatch("ws Host header")
		}
	}
	if hosts != 1 {
		return mismatch("ws Host header must be set exactly once")
	}

	// TLS: on, the signed name, no knob that widens trust.
	if tls == nil {
		return mismatch("no tls block")
	}
	if on, _ := tls["enabled"].(bool); !on {
		return mismatch("tls is not enabled")
	}
	if v, has := tls["insecure"]; has && v != false {
		return mismatch("tls.insecure is set")
	}
	if v, has := tls["disable_sni"]; has && v != false {
		return mismatch("tls.disable_sni is set")
	}
	for _, k := range []string{"certificate_path", "certificate_directory_path", "certificate_public_key_sha256"} {
		if _, has := tls[k]; has {
			return mismatch("tls sets %q", k)
		}
	}
	if str(tls["server_name"]) != ep.ServerName {
		return mismatch("tls server name")
	}
	pems := stringList(tls["certificate"])
	if len(pems) == 0 {
		return mismatch("CDN-fronted outbound installs no root")
	}
	certs, err := parseCertsPEM(strings.Join(pems, "\n"))
	if err != nil {
		return mismatch("CDN-fronted root: %v", err)
	}
	listed := map[string]bool{}
	for _, r := range ep.TLSRootsSHA256 {
		listed[r] = true
	}
	for _, c := range certs {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		if !listed[base64.StdEncoding.EncodeToString(sum[:])] {
			return mismatch("CDN-fronted outbound installs a root that is not signed")
		}
	}

	// ECH: exactly the signed configuration, never one fetched by a DNS
	// lookup (which would put the zone name in a query) and never one
	// read from the device.
	echOn, _ := ech["enabled"].(bool)
	if _, has := tls["ech"]; has && ech == nil {
		return mismatch("tls.ech is not an object")
	}
	if !echOn {
		if !ep.PlainFallback {
			return mismatch("ECH is off and the signed endpoint allows no plain hello")
		}
		return nil
	}
	for _, k := range []string{"config_path", "query_server_name"} {
		if _, has := ech[k]; has {
			return mismatch("tls.ech sets %q", k)
		}
	}
	if ep.ECHConfig == "" {
		return mismatch("ECH is on and the signed endpoint carries no ECH configuration")
	}
	want, _ := decodeStdB64(ep.ECHConfig)
	block, rest := pem.Decode([]byte(strings.Join(stringList(ech["config"]), "\n")))
	if block == nil || block.Type != "ECH CONFIGS" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, want) {
		return mismatch("tls.ech.config is not the signed ECH configuration")
	}
	return nil
}

// MergeCDNEndpoint applies a CDN-fronted route's new signed commitment
// to the outbound the device already holds for it, keeping that
// outbound's credentials (uuid, ws path). What moves: the edge address
// (kept when it is still inside the seeds, otherwise the first address
// of the first seed; the engine re-picks), the port, the TLS name, the
// ws Host, the ECH configuration. Installed roots that are no longer
// signed are dropped; if none is left the merge fails and the route
// needs a new file. The result is checked by CheckCDNOutbound before it
// is returned.
func MergeCDNEndpoint(ep *CDNEndpoint, deviceProfile []byte) ([]byte, error) {
	if ep == nil {
		return nil, ErrEndpointUnauthenticated
	}
	if err := ep.Validate(string(TransportWebSocketTLS)); err != nil {
		return nil, err
	}
	if ProfileOutboundType(deviceProfile) == "" {
		return nil, ErrNoCredentials
	}
	var ob map[string]any
	if err := json.Unmarshal(deviceProfile, &ob); err != nil {
		return nil, ErrNoCredentials
	}
	if str(ob["type"]) != "vless" {
		return nil, mismatch("device outbound type %q is not vless", str(ob["type"]))
	}
	if !ep.InEdgeSeeds(str(ob["server"])) {
		ob["server"] = ep.FirstEdgeAddress()
	}
	ob["server_port"] = ep.Port

	transport, _ := ob["transport"].(map[string]any)
	if transport == nil || str(transport["type"]) != "ws" {
		return nil, mismatch("device outbound has no ws transport")
	}
	headers, _ := transport["headers"].(map[string]any)
	if headers == nil {
		headers = map[string]any{}
	}
	for name := range headers {
		if strings.EqualFold(name, "host") {
			delete(headers, name)
		}
	}
	headers["Host"] = ep.ServerName
	transport["headers"] = headers

	tls, _ := ob["tls"].(map[string]any)
	if tls == nil {
		return nil, mismatch("device outbound has no tls block")
	}
	tls["server_name"] = ep.ServerName
	listed := map[string]bool{}
	for _, r := range ep.TLSRootsSHA256 {
		listed[r] = true
	}
	var keep []string
	if certs, err := parseCertsPEM(strings.Join(stringList(tls["certificate"]), "\n")); err == nil {
		for _, c := range certs {
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if listed[base64.StdEncoding.EncodeToString(sum[:])] {
				keep = append(keep, strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})), "\n"))
			}
		}
	}
	if len(keep) == 0 {
		return nil, mismatch("none of the device's roots is signed any more")
	}
	tls["certificate"] = keep
	if cfg := ep.ECHConfigPEM(); cfg != nil {
		tls["ech"] = map[string]any{"enabled": true, "config": cfg}
	} else {
		delete(tls, "ech")
	}
	out, err := json.Marshal(ob)
	if err != nil {
		return nil, err
	}
	if err := CheckCDNOutbound(ep, out); err != nil {
		return nil, err
	}
	return out, nil
}
