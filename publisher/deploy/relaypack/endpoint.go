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
	"strings"

	"daal/bundle-go/bundle"
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
	return out
}

// ErrNoEndpointMaterial is returned by BindAndSign when the record
// names routes Daal can serve and NOT ONE of them could be given a
// signed endpoint. Such a pack would be refused by every recipient, so
// it is not signed.
var ErrNoEndpointMaterial = errors.New(
	"relaypack: no route could be given a signed endpoint — the OperatorRecord carries neither " +
		"the relay's REALITY public key nor its TLS key pin; pass the relay's own connection " +
		"material (bind-and-sign --endpoint-creds <a users-provision reply>)")

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
		if m.SSMethod == "" || m.SSServerKey == "" {
			return nil, "the relay's shadowsocks method and server key are unknown"
		}
		ep.SSMethod = m.SSMethod
		ep.SSServerKeySHA256 = bundle.SSServerKeyDigest(m.SSServerKey)
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
