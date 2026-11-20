// Code frozen from commit 079ef96 (2026-11-20), the last build before the
// optional add-ons carried new data in a pack. DO NOT EDIT: this file is
// what phones already in the field run, kept so a test can feed today's
// packs to yesterday's rules (bundle/go/importer/compat_old_test.go).
// Only the package clause and the qualifiers of identifiers that moved
// packages were changed.

package oldrules

// endpoint.go — the SIGNED ENDPOINT COMMITMENT (specs/relaypack-v1.md
// "Endpoint commitment", specs/sbp-v1.md "What the signature covers").
//
// THE PROBLEM THIS CLOSES. manifest.sig covers manifest.json. It does
// not cover profiles/<id>.json — the sing-box outbound a route actually
// dials — because a RelayPack's profiles are rewritten per recipient
// AFTER signing (publisher/deploy/relaypack.RewriteProfilesForRecipient).
// Before this file existed that meant anyone who could touch a pack in
// transit could point every route at a server of their choosing, under
// the genuine publisher's fingerprint words, and the trust prompt would
// be answered against the genuine key.
//
// THE SHAPE OF THE FIX: "signed endpoint, local credential".
//
// Everything about a route that is NOT a per-recipient secret is known
// when the publisher signs: where the relay is, which port, and what
// proves the thing answering there is the relay (TLS key pin, REALITY
// public key, shadowsocks server key digest). That goes into the signed
// manifest, per route, under the reserved `_endpoint` key of
// family_specific_config — the same opaque, signed object that already
// carries `port` and `_relaypack`. No manifest struct changes, so the
// canonical bytes of every existing field are untouched.
//
// The per-recipient credentials (uuid, passwords, short id, ws path)
// stay in the unsigned profile. That is safe, and the argument is the
// whole design, so here it is in full:
//
//	The client refuses to dial a route whose outbound disagrees with
//	the commitment on server, port or server-authentication material.
//	So the only thing left for an attacker to change is a credential.
//	A changed credential is presented to the COMMITTED server, over a
//	channel authenticated by the COMMITTED key. The genuine relay does
//	not know it and refuses; nobody else can complete the handshake to
//	receive it. A tampered credential can therefore only fail to
//	connect. It can never be sent somewhere else, and it can never make
//	some other server look like the relay.
//
// One family is weaker and it is said here rather than discovered:
// shadowsocks has no server authentication that is independent of the
// shared key. The commitment pins the address, the port, the method and
// a digest of the box-wide server key (iPSK), so a stranger cannot
// substitute a key. Someone who is BOTH a recipient of the same relay
// (knows the iPSK) AND on the network path can still impersonate it to
// another recipient whose per-user key they rewrote. That is a property
// of a shared-key protocol, not of this format.
//
// The same commitment is what makes the freshness channel safe to use
// (MergeEndpoint): a publisher can publish the credential-less signed
// skeleton, and a device applies the NEW signed endpoint to the
// credentials it ALREADY holds.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
)

// EndpointKey is the reserved key inside a route's (signed)
// family_specific_config that carries its Endpoint.
const EndpointKey = "_endpoint"

// EndpointVersion is the only commitment version this build reads.
const EndpointVersion = 1

// UnavailableMarkerKey is stamped into the PROFILE of a route the pack
// minter could not make connectable for this recipient (see
// publisher/deploy/relaypack.RewriteProfilesForRecipient). The manifest
// is signed, so a route cannot be removed; its profile is replaced by
// this marker instead. A profile carrying it has no outbound.
const UnavailableMarkerKey = "_daal_unavailable"

// Endpoint is one route's signed endpoint commitment.
//
// Which fields a family uses:
//
//	vless-reality   server port server_name reality_public_key
//	websocket-tls   server port tls_spki_sha256 [server_name]
//	hysteria2       server port tls_spki_sha256 [server_name]
//	tuic            server port tls_spki_sha256 [server_name]
//	anytls          server port tls_spki_sha256 [server_name]
//	naive           server port tls_spki_sha256
//	shadowsocks     server port ss_method ss_server_key_sha256
type Endpoint struct {
	V      int    `json:"v"`
	Server string `json:"server"`
	Port   int    `json:"port"`

	// ServerName is the TLS name the outbound must present. Required
	// for vless-reality (it is the cover host, and REALITY fails
	// without it). Optional elsewhere: where the server is
	// authenticated by a key pin the name proves nothing, but when the
	// publisher commits one the outbound must carry exactly it — a
	// rewritten SNI is a way to make a recipient's traffic conspicuous.
	//
	// Never set for naive: its verification name is a function of the
	// address and the certificate (NaiveVerificationName), so it can be
	// recomputed on both sides and survives an address change without a
	// new signature over a name.
	ServerName string `json:"server_name,omitempty"`

	// TLSSPKISHA256 is the base64 (std) SHA-256 of the relay's TLS
	// leaf SubjectPublicKeyInfo. For the pinned families the outbound's
	// certificate_public_key_sha256 must equal it. For naive, which
	// trusts a certificate rather than a pin, every certificate the
	// outbound installs as a root must carry this key.
	TLSSPKISHA256 string `json:"tls_spki_sha256,omitempty"`

	// RealityPublicKey is the relay's REALITY x25519 public key
	// (base64url, as sing-box spells it).
	RealityPublicKey string `json:"reality_public_key,omitempty"`

	// SSMethod is the shadowsocks method the relay serves.
	SSMethod string `json:"ss_method,omitempty"`
	// SSServerKeySHA256 is SSServerKeyDigest of the box-wide key
	// (the iPSK half of "<iPSK>:<uPSK>"). A digest, because this
	// object is published on the freshness mirrors and the key itself
	// must not be.
	SSServerKeySHA256 string `json:"ss_server_key_sha256,omitempty"`
}

var (
	// ErrNoEndpoint: the route's family_specific_config carries no
	// `_endpoint`. Not a parse error.
	ErrNoEndpoint = errors.New("no _endpoint commitment in family_specific_config")
	// ErrEndpointMalformed: an `_endpoint` is present and unusable.
	ErrEndpointMalformed = errors.New("malformed endpoint commitment")
	// ErrEndpointMismatch: a profile's outbound disagrees with its
	// route's signed commitment. The pack was altered after signing,
	// or minted against a relay that has since moved.
	ErrEndpointMismatch = errors.New("outbound does not match its signed endpoint")
	// ErrEndpointUnauthenticated: a profile carries an outbound and its
	// route carries no commitment at all.
	ErrEndpointUnauthenticated = errors.New("outbound has no signed endpoint")
	// ErrNoCredentials: MergeEndpoint was handed a profile that holds
	// no outbound, so there is nothing to keep.
	ErrNoCredentials = errors.New("profile holds no credentials")
)

// ParseEndpoint extracts the `_endpoint` commitment from a route's
// family_specific_config. ErrNoEndpoint when absent.
func ParseEndpoint(familySpecificConfig json.RawMessage) (*Endpoint, error) {
	if len(familySpecificConfig) == 0 {
		return nil, ErrNoEndpoint
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEndpointMalformed, err)
	}
	raw, ok := probe[EndpointKey]
	if !ok {
		return nil, ErrNoEndpoint
	}
	var ep Endpoint
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Strict: an unknown member is a commitment this build would
	// silently not enforce. Refusing is the only safe reading.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ep); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEndpointMalformed, err)
	}
	return &ep, nil
}

// endpointFamily describes what one family's commitment must carry.
type endpointFamily struct {
	outboundType string
	needSNI      bool
	needPin      bool
	needReality  bool
	needSS       bool
}

var endpointFamilies = map[string]endpointFamily{
	string(TransportVLESSReality): {outboundType: "vless", needSNI: true, needReality: true},
	string(TransportWebSocketTLS): {outboundType: "vless", needPin: true},
	string(TransportHysteria2):    {outboundType: "hysteria2", needPin: true},
	string(TransportTUIC):         {outboundType: "tuic", needPin: true},
	string(TransportAnyTLS):       {outboundType: "anytls", needPin: true},
	string(TransportNaive):        {outboundType: "naive", needPin: true},
	string(TransportShadowsocks):  {outboundType: "shadowsocks", needSS: true},
}

// EndpointFamilySupported reports whether this build knows how to
// commit to, and check, an endpoint of the given family.
func EndpointFamilySupported(family string) bool {
	_, ok := endpointFamilies[family]
	return ok
}

// Validate checks that the commitment is complete for its family. It is
// run by the publisher before signing and by the recipient before any
// comparison, so a half-filled commitment can never be "matched" by an
// outbound that simply omits the same thing.
func (e *Endpoint) Validate(family string) error {
	if e == nil {
		return ErrNoEndpoint
	}
	fam, ok := endpointFamilies[family]
	if !ok {
		return fmt.Errorf("%w: no endpoint rule for family %q", ErrEndpointMalformed, family)
	}
	if e.V != EndpointVersion {
		return fmt.Errorf("%w: version %d (this build reads %d)", ErrEndpointMalformed, e.V, EndpointVersion)
	}
	if strings.TrimSpace(e.Server) == "" || e.Server != strings.TrimSpace(e.Server) {
		return fmt.Errorf("%w: empty server", ErrEndpointMalformed)
	}
	if e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("%w: port %d", ErrEndpointMalformed, e.Port)
	}
	if fam.needSNI && e.ServerName == "" {
		return fmt.Errorf("%w: %s needs server_name", ErrEndpointMalformed, family)
	}
	if family == string(TransportNaive) && e.ServerName != "" {
		return fmt.Errorf("%w: naive derives its verification name; server_name must be absent", ErrEndpointMalformed)
	}
	if fam.needPin {
		if _, err := decodePin(e.TLSSPKISHA256); err != nil {
			return fmt.Errorf("%w: %s needs tls_spki_sha256: %v", ErrEndpointMalformed, family, err)
		}
	} else if e.TLSSPKISHA256 != "" {
		return fmt.Errorf("%w: %s takes no tls_spki_sha256", ErrEndpointMalformed, family)
	}
	if fam.needReality {
		if e.RealityPublicKey == "" {
			return fmt.Errorf("%w: %s needs reality_public_key", ErrEndpointMalformed, family)
		}
	} else if e.RealityPublicKey != "" {
		return fmt.Errorf("%w: %s takes no reality_public_key", ErrEndpointMalformed, family)
	}
	if fam.needSS {
		if e.SSMethod == "" || len(e.SSServerKeySHA256) != sha256.Size*2 {
			return fmt.Errorf("%w: %s needs ss_method and ss_server_key_sha256", ErrEndpointMalformed, family)
		}
		if _, err := hex.DecodeString(e.SSServerKeySHA256); err != nil {
			return fmt.Errorf("%w: ss_server_key_sha256 is not hex", ErrEndpointMalformed)
		}
	} else if e.SSMethod != "" || e.SSServerKeySHA256 != "" {
		return fmt.Errorf("%w: %s takes no shadowsocks fields", ErrEndpointMalformed, family)
	}
	return nil
}

// SSServerKeyDigest is the committed form of a shadowsocks box-wide
// key: hex SHA-256 over a domain separator and the key exactly as it
// appears before the ':' in the outbound's password.
func SSServerKeyDigest(serverKey string) string {
	sum := sha256.Sum256([]byte("daal/ss-server-key/v1\x00" + serverKey))
	return hex.EncodeToString(sum[:])
}

// SSServerKey returns the box-wide half of a shadowsocks-2022
// multi-user password ("<iPSK>:<uPSK>"), or "" when the password is
// not of that shape. A single-key password has no half that is common
// to the relay's recipients, so there is nothing to commit to.
func SSServerKey(password string) string {
	i := strings.Index(password, ":")
	if i <= 0 || i == len(password)-1 {
		return ""
	}
	return password[:i]
}

// SPKIPinFromCertPEM returns the base64 SHA-256 of the
// SubjectPublicKeyInfo of the first certificate in pemText.
func SPKIPinFromCertPEM(pemText string) (string, error) {
	certs, err := parseCertsPEM(pemText)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// NaiveVerificationName is the TLS name a naive outbound must verify
// the relay's certificate against, given the address it dials.
//
// naive rides Chromium's network stack, which does real name
// verification and offers no key pin. The relay's certificate names the
// address it had at first boot (an iPAddress SAN) and, on relays
// provisioned since this rule, one stable DNS name. So:
//
//   - the dialled address is in the certificate → verify against the
//     address (no SNI goes on the wire, as before);
//   - otherwise, and the certificate carries a DNS name → verify
//     against that name. This is the case after the relay's address was
//     moved (L3): the certificate cannot follow the address, the name
//     can.
//   - otherwise → the address. It will not verify; nothing would.
//
// It is a pure function of (server, certificate) so the publisher, the
// importer and the freshness merge all arrive at the same answer
// without the name itself having to be signed.
func NaiveVerificationName(server string, certPEMs []string) string {
	certs, err := parseCertsPEM(strings.Join(certPEMs, "\n"))
	if err != nil {
		return server
	}
	if ip := net.ParseIP(server); ip != nil {
		for _, c := range certs {
			for _, san := range c.IPAddresses {
				if san.Equal(ip) {
					return server
				}
			}
		}
	} else {
		for _, c := range certs {
			if c.VerifyHostname(server) == nil {
				return server
			}
		}
	}
	for _, c := range certs {
		for _, name := range c.DNSNames {
			if name != "" {
				return name
			}
		}
	}
	return server
}

// ProfileOutboundType returns the sing-box outbound `type` a profile
// declares, or "" when the profile holds no outbound: the signed
// skeleton's metadata-only profile, a route the minter marked
// unavailable, or anything that is not a JSON object.
func ProfileOutboundType(profile []byte) string {
	var probe struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(profile, &probe) != nil {
		return ""
	}
	return strings.TrimSpace(probe.Type)
}

// ProfileUnavailable reports whether the pack minter marked this
// profile as one it could not make connectable for the recipient.
func ProfileUnavailable(profile []byte) bool {
	var probe map[string]json.RawMessage
	if json.Unmarshal(profile, &probe) != nil {
		return false
	}
	_, ok := probe[UnavailableMarkerKey]
	return ok
}

// CheckOutbound verifies that a profile's outbound agrees with the
// route's signed commitment on everything the commitment covers. nil
// means: this outbound can only ever talk to the committed relay.
//
// It is deliberately a refusal list around a small set of equalities,
// not a schema: the credentials and tuning knobs around them are the
// recipient's and are not this function's business. What it refuses is
// every knob that would let the SAME equalities hold while the traffic
// goes, or the trust comes from, somewhere else.
func CheckOutbound(family string, ep *Endpoint, profile []byte) error {
	if ep == nil {
		return ErrEndpointUnauthenticated
	}
	if err := ep.Validate(family); err != nil {
		return err
	}
	fam := endpointFamilies[family]
	var ob map[string]any
	if err := json.Unmarshal(profile, &ob); err != nil {
		return mismatch("profile is not a JSON object")
	}
	// Before any equality: every key this function reads, or requires
	// to be absent, must be spelled the one way it is spelled here.
	// See plainKeys for why that is not a formality.
	if err := plainKeys("outbound", ob); err != nil {
		return err
	}
	tlsBlock, _ := ob["tls"].(map[string]any)
	if err := plainKeys("tls", tlsBlock); err != nil {
		return err
	}
	realityBlock, _ := tlsBlock["reality"].(map[string]any)
	if err := plainKeys("tls.reality", realityBlock); err != nil {
		return err
	}
	if str(ob["type"]) != fam.outboundType {
		return mismatch("outbound type %q is not %s's %q", str(ob["type"]), family, fam.outboundType)
	}
	if !sameHost(str(ob["server"]), ep.Server) {
		return mismatch("server")
	}
	if port, ok := asInt(ob["server_port"]); !ok || port != ep.Port {
		return mismatch("port")
	}
	// A detour sends the connection through some other outbound first,
	// and bind/route knobs choose where it leaves from. None of them is
	// something a pack has a reason to say.
	for _, k := range []string{"detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "netns"} {
		if _, has := ob[k]; has {
			return mismatch("outbound sets %q", k)
		}
	}
	// hysteria2's port-hopping list replaces server_port when present
	// (sing-box dials a port drawn from it), so with it the equality
	// above would hold while the connection goes to a port nobody
	// signed. No pack is minted with it.
	if _, has := ob["server_ports"]; has {
		return mismatch("outbound sets %q", "server_ports")
	}

	if fam.needSS {
		if _, has := ob["tls"]; has {
			return mismatch("shadowsocks outbound carries a tls block")
		}
		if _, has := ob["plugin"]; has {
			return mismatch("shadowsocks outbound sets a plugin")
		}
		if str(ob["method"]) != ep.SSMethod {
			return mismatch("shadowsocks method")
		}
		key := SSServerKey(str(ob["password"]))
		if key == "" || !strings.EqualFold(SSServerKeyDigest(key), ep.SSServerKeySHA256) {
			return mismatch("shadowsocks server key")
		}
		return nil
	}

	tls := tlsBlock
	if tls == nil {
		return mismatch("no tls block")
	}
	if on, _ := tls["enabled"].(bool); !on {
		return mismatch("tls is not enabled")
	}
	if v, has := tls["insecure"]; has && v != false {
		return mismatch("tls.insecure is set")
	}
	// Trust anchors read from the device's filesystem are not in the
	// pack and cannot have been checked against anything.
	for _, k := range []string{"certificate_path", "certificate_directory_path"} {
		if _, has := tls[k]; has {
			return mismatch("tls sets %q", k)
		}
	}
	if ep.ServerName != "" && str(tls["server_name"]) != ep.ServerName {
		return mismatch("tls server name")
	}
	if v, has := tls["disable_sni"]; has && v != false && fam.needSNI {
		return mismatch("tls.disable_sni is set")
	}

	reality := realityBlock
	realityOn, _ := reality["enabled"].(bool)
	if fam.needReality {
		if !realityOn {
			return mismatch("reality is not enabled")
		}
		if str(reality["public_key"]) != ep.RealityPublicKey {
			return mismatch("reality public key")
		}
		return nil
	}
	if realityOn {
		return mismatch("reality is enabled on a %s route", family)
	}

	want, _ := decodePin(ep.TLSSPKISHA256) // Validate proved it decodes
	if family == string(TransportNaive) {
		// naive authenticates by trusting the certificates the pack
		// installs as roots. Each one must carry the committed key:
		// one extra root is one extra party who can be the relay.
		pems := stringList(tls["certificate"])
		if len(pems) == 0 {
			return mismatch("naive outbound installs no trusted certificate")
		}
		certs, err := parseCertsPEM(strings.Join(pems, "\n"))
		if err != nil {
			return mismatch("naive trusted certificate: %v", err)
		}
		for _, c := range certs {
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if !bytes.Equal(sum[:], want) {
				return mismatch("naive trusted certificate key")
			}
		}
		if _, has := tls["certificate_public_key_sha256"]; has {
			return mismatch("naive outbound sets a key pin it cannot honour")
		}
		// The name Chromium verifies against is a function of the
		// committed address and those certificates, so it is checked
		// rather than left free: whether the installed roots REPLACE
		// the platform's or are added to them is Cronet's business,
		// and a free name is only harmless in the first case. An
		// absent name means the address (sing-box's own default).
		name := str(tls["server_name"])
		if name == "" {
			name = str(ob["server"])
		}
		if !sameHost(name, NaiveVerificationName(ep.Server, pems)) {
			return mismatch("naive verification name")
		}
		return nil
	}
	if _, has := tls["certificate"]; has {
		return mismatch("pinned outbound also installs a trusted certificate")
	}
	pins := stringList(tls["certificate_public_key_sha256"])
	if len(pins) == 0 {
		return mismatch("no tls key pin")
	}
	for _, p := range pins {
		got, err := decodePin(p)
		if err != nil || !bytes.Equal(got, want) {
			return mismatch("tls key pin")
		}
	}
	return nil
}

// MergeEndpoint applies a route's signed endpoint to an outbound the
// device already holds, keeping that outbound's credentials. It is the
// freshness path's swap primitive: the published file is the
// credential-less signed skeleton, and this is how a device turns
// "the relay is now HERE, with THIS key" into a profile it can dial
// without anybody handing it a file.
//
// What moves: server, port, the TLS name, the key pin, the REALITY
// public key, the shadowsocks method. What stays: everything else.
//
// The result is checked against the commitment before it is returned,
// so a merge either yields an outbound CheckOutbound accepts or an
// error. It errors, in particular, when the credentials the device
// holds cannot belong to the committed relay any more: a naive
// certificate that does not carry the committed key, or a shadowsocks
// password whose server half is not the committed one. Those routes
// need a new file and the caller must leave the old profile alone.
func MergeEndpoint(family string, ep *Endpoint, deviceProfile []byte) ([]byte, error) {
	if ep == nil {
		return nil, ErrEndpointUnauthenticated
	}
	if err := ep.Validate(family); err != nil {
		return nil, err
	}
	fam := endpointFamilies[family]
	if ProfileOutboundType(deviceProfile) == "" {
		return nil, ErrNoCredentials
	}
	var ob map[string]any
	if err := json.Unmarshal(deviceProfile, &ob); err != nil {
		return nil, ErrNoCredentials
	}
	if str(ob["type"]) != fam.outboundType {
		return nil, mismatch("device outbound type %q is not %s's %q", str(ob["type"]), family, fam.outboundType)
	}
	oldServer := str(ob["server"])
	ob["server"] = ep.Server
	ob["server_port"] = ep.Port

	switch {
	case fam.needSS:
		ob["method"] = ep.SSMethod
	default:
		tls, _ := ob["tls"].(map[string]any)
		if tls == nil {
			return nil, mismatch("device outbound has no tls block")
		}
		switch {
		case family == string(TransportNaive):
			tls["server_name"] = NaiveVerificationName(ep.Server, stringList(tls["certificate"]))
		case ep.ServerName != "":
			tls["server_name"] = ep.ServerName
		case str(tls["server_name"]) == oldServer:
			// "the name is the server itself" is how the pinned
			// families are minted; it has to follow the address.
			tls["server_name"] = ep.Server
		}
		if fam.needReality {
			reality, _ := tls["reality"].(map[string]any)
			if reality == nil {
				return nil, mismatch("device outbound has no reality block")
			}
			reality["public_key"] = ep.RealityPublicKey
		} else if family != string(TransportNaive) {
			tls["certificate_public_key_sha256"] = ep.TLSSPKISHA256
		}
	}
	out, err := json.Marshal(ob)
	if err != nil {
		return nil, err
	}
	if err := CheckOutbound(family, ep, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- helpers ----------------------------------------------------------

// plainKeys refuses an object that has any member whose name is not
// plain lower-case ASCII: one or more of a-z, 0-9 and '_'.
//
// CheckOutbound reads a profile as a map and looks its members up by
// their exact names. The engine hands the same bytes to sing-box, whose
// decoder matches a member to a field WITHOUT regard to case, using
// Unicode simple case folding: "Server", "SERVER" and "\u017ferver"
// (U+017F, long s) are all `server` to it, and "public_\u212aey"
// (U+212A, Kelvin sign) is `public_key`. When two members fold onto one
// field the later one wins, and the engine re-marshals the profile with
// its keys in byte order, so a non-ASCII spelling always comes after
// the genuine one. A profile could therefore keep "server" exactly as
// signed, add a second spelling of it, and pass every equality here
// while sing-box dialled the second.
//
// The same trick defeats every "must be absent" rule ("Insecure",
// "Detour", "Server_Ports"). So the rule is not a list of spellings to
// look for. It is: in the three objects whose members decide where an
// outbound goes and what proves who answered — the outbound itself, its
// `tls` block and `tls.reality` — a name that is not plain lower-case
// ASCII does not exist in this format. Every sing-box field name is
// plain lower-case ASCII, case folding maps nothing else onto those
// characters except their own upper case, 'ſ' and 'K', and all of
// those are refused here; what is left can only match a field by being
// exactly its name, which is what the equalities test.
//
// Deeper objects (transport, multiplex, …) are not walked: nothing in
// them is covered by the commitment, and `transport.headers` carries
// HTTP header names, which are legitimately mixed-case.
func plainKeys(where string, obj map[string]any) error {
	for k := range obj {
		if !plainKey(k) {
			return mismatch("%s has a member whose name is not plain lower-case: %q", where, k)
		}
	}
	return nil
}

func plainKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func mismatch(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEndpointMismatch, fmt.Sprintf(format, args...))
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// stringList reads a sing-box "listable" string: one string or a list.
// Anything else — including a list with a non-string in it — is empty,
// which every caller treats as "absent" and refuses.
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil
			}
			out = append(out, s)
		}
		return out
	case []string:
		return t
	}
	return nil
}

// sameHost compares two server addresses: as IPs when both are, so
// "::1" and "0:0:0:0:0:0:0:1" are one address; byte-for-byte lowercase
// otherwise.
func sameHost(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia != nil || ib != nil {
		return ia != nil && ib != nil && ia.Equal(ib)
	}
	return strings.EqualFold(a, b)
}

// decodePin reads a SHA-256 pin: base64 (std, padded or not) as
// sing-box spells it, or 64 hex characters.
func decodePin(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty pin")
	}
	if len(s) == sha256.Size*2 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == sha256.Size {
			return b, nil
		}
	}
	return nil, errors.New("not a SHA-256 pin")
}

func parseCertsPEM(pemText string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate in PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after certificate PEM")
	}
	return out, nil
}
