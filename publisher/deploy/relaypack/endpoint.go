package relaypack

// endpoint.go — the publisher half of the signed endpoint commitment
// (bundle/go/bundle/endpoint.go has the format and the argument for it;
// specs/relaypack-v1.md "Endpoint commitment" is the contract).
//
// At bind-and-sign time the relay exists. Everything about each route
// that is not a per-recipient secret is therefore known, and this file
// turns it into the per-route `_endpoint` object that goes into the
// SIGNED manifest. What the recipient's client then refuses to do is
// dial anything else.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/provider"
)

// EndpointMaterial is the relay-wide, non-secret connection material a
// commitment is built from. None of it identifies a recipient.
type EndpointMaterial struct {
	// Server is the address recipients dial.
	Server string
	// CoverSNI is the REALITY cover host. Empty means "relay
	// provisioned before per-relay cover hosts": the legacy constant
	// the renderer falls back to, so the commitment and the outbound
	// agree by construction.
	CoverSNI string
	// RealityPublicKey is the relay's REALITY x25519 public key.
	RealityPublicKey string
	// TLSSPKISHA256 pins the relay's data-plane TLS key (base64
	// SHA-256 of the leaf SubjectPublicKeyInfo).
	TLSSPKISHA256 string
	// TLSCertPEM is the relay's data-plane certificate. Used only to
	// derive TLSSPKISHA256 when that is empty.
	TLSCertPEM string
	// SSMethod / SSServerKey are the shadowsocks method and the
	// box-wide half of the key. The key is NOT written to the pack;
	// only its digest is.
	SSMethod    string
	SSServerKey string
	// SSServerKeySHA256 is bundle.SSServerKeyDigest of the box-wide
	// key, for a source that states the digest and not the key — the
	// relay's own identity (mgmt GET /identity). When set it is what
	// the endpoint carries and SSServerKey is not consulted.
	SSServerKeySHA256 string
}

// EndpointMaterialFromRecord reads what the OperatorRecord knows.
func EndpointMaterialFromRecord(rec *provider.OperatorRecord) EndpointMaterial {
	var m EndpointMaterial
	if rec == nil {
		return m
	}
	if rec.PublicIP != nil {
		m.Server = rec.PublicIP.String()
	}
	m.CoverSNI = rec.CoverSNI
	m.RealityPublicKey = rec.RealityPublicKey
	m.TLSSPKISHA256 = rec.TLSCertSHA256
	return m
}

// EndpointMaterialFromParams reads the relay-wide fields out of one
// recipient's connection parameters — the shape `users-provision`
// returns. Only the fields every recipient of the relay shares are
// taken; the per-recipient secrets beside them are ignored.
func EndpointMaterialFromParams(p ClientConnParams) EndpointMaterial {
	return EndpointMaterial{
		Server:           p.Server,
		CoverSNI:         p.CoverSNI,
		RealityPublicKey: p.RealityPublicKey,
		TLSSPKISHA256:    p.TLSCertSHA256,
		TLSCertPEM:       p.TLSCertPEM,
		SSMethod:         p.SSMethod,
		SSServerKey:      bundle.SSServerKey(p.SSPassword),
	}
}

// Overlay returns m (the record's view) with every EMPTY field filled
// from live (the relay-wide fields of a reply the relay gave earlier).
//
// The record wins wherever it speaks, the cover host included. That is
// deliberate: the record is the one document every rotation verb
// rewrites (rotate-tls moves CoverSNI, assign-fip moves PublicIP), so it
// is current by construction, whereas a saved reply is a snapshot — a
// reply saved before an L2 still names the OLD cover host, and letting
// it win would sign an endpoint the relay no longer serves. The reply's
// job here is only to supply what the record has no field for.
func (m EndpointMaterial) Overlay(live EndpointMaterial) EndpointMaterial {
	out := m
	fill := func(dst *string, src string) {
		if strings.TrimSpace(*dst) == "" {
			*dst = src
		}
	}
	fill(&out.Server, live.Server)
	fill(&out.CoverSNI, live.CoverSNI)
	fill(&out.RealityPublicKey, live.RealityPublicKey)
	fill(&out.TLSSPKISHA256, live.TLSSPKISHA256)
	fill(&out.TLSCertPEM, live.TLSCertPEM)
	fill(&out.SSMethod, live.SSMethod)
	fill(&out.SSServerKey, live.SSServerKey)
	fill(&out.SSServerKeySHA256, live.SSServerKeySHA256)
	return out
}

// EndpointMaterialFromIdentity reads the relay's own statement of its
// identity (mgmt GET /identity). It carries no address: the relay does
// not know which address recipients dial (a floating IP is routed to it
// by the provider), so Server stays with the record.
func EndpointMaterialFromIdentity(id *mgmt.RelayIdentity) EndpointMaterial {
	if id == nil {
		return EndpointMaterial{}
	}
	return EndpointMaterial{
		CoverSNI:          id.CoverSNI,
		RealityPublicKey:  id.RealityPublicKey,
		TLSSPKISHA256:     id.TLSCertSHA256,
		SSMethod:          id.SSMethod,
		SSServerKeySHA256: id.SSServerKeySHA256,
	}
}

// PreferRelay returns m (the record's view) with every field the relay
// itself STATED replacing the record's.
//
// This is the opposite precedence to Overlay, for a different kind of
// source. Overlay's second argument is a reply somebody saved earlier —
// a snapshot, which the record outranks because every rotation verb
// rewrites the record. PreferRelay's argument is the relay answering
// "who are you" just before the signature: for the keys and the cover
// host there is no better authority than the box that holds them, and a
// record that disagrees with it (an SSH read that went stale, a
// rotate-tls whose record write was lost) is the one that is wrong.
//
// The address is the exception and stays the record's: see
// EndpointMaterialFromIdentity. A field the relay left empty is left
// alone, so a relay that does not serve a family takes nothing away.
func (m EndpointMaterial) PreferRelay(relay EndpointMaterial) EndpointMaterial {
	out := m
	take := func(dst *string, src string) {
		if strings.TrimSpace(src) != "" {
			*dst = src
		}
	}
	take(&out.CoverSNI, relay.CoverSNI)
	take(&out.RealityPublicKey, relay.RealityPublicKey)
	if strings.TrimSpace(relay.TLSSPKISHA256) != "" {
		out.TLSSPKISHA256 = relay.TLSSPKISHA256
		// A certificate from the older source can only have been there
		// to derive the pin the relay has now stated.
		out.TLSCertPEM = ""
	}
	if strings.TrimSpace(relay.SSServerKeySHA256) != "" || strings.TrimSpace(relay.SSServerKey) != "" {
		out.SSMethod = relay.SSMethod
		out.SSServerKey = relay.SSServerKey
		out.SSServerKeySHA256 = relay.SSServerKeySHA256
	}
	return out
}

// ErrNoEndpointMaterial is returned by BindAndSign when the record
// names routes Daal can serve and NOT ONE of them could be given a
// signed endpoint. Such a pack would be refused by every recipient, so
// it is not signed.
var ErrNoEndpointMaterial = errors.New(
	"relaypack: no route could be given a signed endpoint — the OperatorRecord carries neither " +
		"the relay's REALITY public key nor its TLS key pin; pass the relay's own connection " +
		"material (bind-and-sign --relay-identity <the relay's own identity>, or " +
		"--endpoint-creds <a users-provision reply>)")

// endpointFor builds one route's commitment. A nil endpoint with a
// reason means the material this family needs is missing: the route is
// signed WITHOUT a commitment, which the recipient's client treats as
// "cannot be made connectable", and the caller must say so out loud.
func endpointFor(family string, port int, m EndpointMaterial) (*bundle.Endpoint, string) {
	if !bundle.EndpointFamilySupported(family) {
		return nil, "no endpoint rule for this family"
	}
	server := strings.TrimSpace(m.Server)
	if server == "" {
		return nil, "the relay's address is unknown"
	}
	ep := &bundle.Endpoint{V: bundle.EndpointVersion, Server: server, Port: port}
	switch family {
	case string(bundle.TransportVLESSReality):
		if m.RealityPublicKey == "" {
			return nil, "the relay's REALITY public key is unknown"
		}
		ep.RealityPublicKey = strings.TrimSpace(m.RealityPublicKey)
		// The same fallback the renderer applies, so the two agree.
		ep.ServerName = ClientConnParams{CoverSNI: m.CoverSNI}.coverSNI()
	case string(bundle.TransportShadowsocks):
		digest := strings.TrimSpace(m.SSServerKeySHA256)
		if digest == "" && m.SSServerKey != "" {
			digest = bundle.SSServerKeyDigest(m.SSServerKey)
		}
		if m.SSMethod == "" || digest == "" {
			return nil, "the relay's shadowsocks method and server key are unknown " +
				"(the relay makes that key together with its first recipient; sign again after adding one)"
		}
		ep.SSMethod = m.SSMethod
		ep.SSServerKeySHA256 = digest
	default:
		pin := strings.TrimSpace(m.TLSSPKISHA256)
		if pin == "" && m.TLSCertPEM != "" {
			if p, err := bundle.SPKIPinFromCertPEM(m.TLSCertPEM); err == nil {
				pin = p
			}
		}
		if pin == "" {
			return nil, "the relay's TLS key pin is unknown"
		}
		ep.TLSSPKISHA256 = pin
		if family != string(bundle.TransportNaive) {
			// The pinned families are minted with the address as the
			// TLS name (pinnedTLSOpts); commit to it so a rewritten SNI
			// is refused too.
			ep.ServerName = server
		}
	}
	if err := ep.Validate(family); err != nil {
		return nil, err.Error()
	}
	return ep, ""
}

// UncommittedWarning is the operator-facing sentence for one route that
// was signed without an endpoint.
func UncommittedWarning(s SkippedRoute) string {
	return fmt.Sprintf("route %s (%s) was signed WITHOUT an endpoint and no recipient can connect on it: %s",
		s.RouteID, s.Family, s.Reason)
}

// EndpointFor is endpointFor for callers outside this package that
// build signed packs by hand (the test-vector generator). A nil
// endpoint comes with the reason.
func EndpointFor(family string, port int, m EndpointMaterial) (*bundle.Endpoint, string) {
	return endpointFor(family, port, m)
}

// CommittedIdentity is the relay identity a signed pack commits its
// routes to, in the vocabulary the relay uses for the same values
// (mgmt.RelayIdentity, the users-provision reply). Nothing in it is a
// secret: all of it is in the signed manifest, which is published.
type CommittedIdentity struct {
	// Server is the address the routes dial.
	Server string `json:"server"`
	// CoverSNI is the REALITY cover host ("" when no vless-reality
	// route was committed).
	CoverSNI         string `json:"cover_sni"`
	RealityPublicKey string `json:"reality_public_key"`
	// TLSCertSHA256 is the data-plane SPKI pin.
	TLSCertSHA256     string `json:"tls_cert_sha256"`
	SSMethod          string `json:"ss_method"`
	SSServerKeySHA256 string `json:"ss_server_key_sha256"`
	// Families lists every family that has a signed endpoint, sorted.
	Families []string `json:"families"`
}

// committedIdentity reads the identity back out of the routes that are
// about to be signed — what the pack says, not what the signer meant.
func committedIdentity(routes []bundle.RouteManifestEntry) CommittedIdentity {
	out := CommittedIdentity{Families: []string{}}
	seen := map[string]bool{}
	for _, r := range routes {
		ep, err := bundle.ParseEndpoint(r.FamilySpecificConfig)
		if err != nil || ep == nil {
			continue
		}
		if !seen[r.TransportFamily] {
			seen[r.TransportFamily] = true
			out.Families = append(out.Families, r.TransportFamily)
		}
		if out.Server == "" {
			out.Server = ep.Server
		}
		if ep.RealityPublicKey != "" {
			out.RealityPublicKey = ep.RealityPublicKey
			out.CoverSNI = ep.ServerName
		}
		if ep.TLSSPKISHA256 != "" {
			out.TLSCertSHA256 = ep.TLSSPKISHA256
		}
		if ep.SSServerKeySHA256 != "" {
			out.SSMethod = ep.SSMethod
			out.SSServerKeySHA256 = ep.SSServerKeySHA256
		}
	}
	sort.Strings(out.Families)
	return out
}
