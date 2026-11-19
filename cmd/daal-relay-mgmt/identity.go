// GET /identity — the relay states who it is.
//
// WHY THIS ROUTE EXISTS. A RelayPack commits every route to a signed
// endpoint: where it points, and what proves the far end is this relay
// (specs/relaypack-v1.md "Endpoint commitment"). The publisher signs
// that pack BEFORE any recipient exists, so it needs the relay's side
// of the commitment — the REALITY public key, the data-plane TLS key
// pin, the cover host, the shadowsocks server key's digest — without
// provisioning anybody. Until this route, the only places that material
// came from were a provider-specific SSH read at provision time (which
// one provider adapter does and another does not) and the box-wide
// fields of a /users/provision reply (which needs a recipient). A
// publisher on the wrong provider could not sign at all.
//
// Nothing here is a secret: every value is either visible on the wire
// to anyone who connects, or is carried in every pack the publisher
// hands out. The shadowsocks server key is the one exception to
// "visible", so it is NOT sent — its digest is, which is exactly what a
// signed endpoint carries (bundle.SSServerKeyDigest).
//
// It is authenticated anyway, in both directions. The REPLY is what the
// publisher is about to sign, so it has to come from this box: it does,
// over the fingerprint-pinned management TLS session every other reply
// rides. The REQUEST carries an op-bound publisher token like every
// route except /health, so the answer — which families this address
// serves, on which ports — is not handed to whoever finds the port.
//
// Read-only. It takes no lock that a mutating verb waits on, changes
// nothing, and reloads nothing.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
)

// identityVersion is the shape version of the /identity reply. A
// publisher refuses a version it does not know rather than guess at
// what a field means: this document becomes a signature.
const identityVersion = 1

// identityOp is the token op for GET /identity. Mirrors
// mgmt.OpIdentity; the route and the op are the same word.
const identityOp = "identity"

// ssServerKeyDigestPrefix domain-separates the shadowsocks server-key
// digest. It is a wire contract with bundle.SSServerKeyDigest
// (bundle/go/bundle/endpoint.go): the publisher puts this box's digest
// into a signed endpoint, and the recipient's client recomputes it from
// the outbound it was handed. The two modules share no symbol, so
// TestIdentitySSDigestMatchesTheSignedEndpointRule pins the bytes.
const ssServerKeyDigestPrefix = "daal/ss-server-key/v1\x00"

func ssServerKeyDigest(serverKey string) string {
	sum := sha256.Sum256([]byte(ssServerKeyDigestPrefix + serverKey))
	return hex.EncodeToString(sum[:])
}

// identityFamily is one transport family this relay serves.
type identityFamily struct {
	Family string `json:"family"`
	// Port is where the family listens — read from the live inbound when
	// there is one, otherwise the port this binary will create it on.
	Port int `json:"port"`
	// Listening is false for a family the relay was provisioned to
	// serve whose inbound does not exist yet. Four inbounds are created
	// with the first recipient, because sing-box refuses them with an
	// empty user table.
	Listening bool `json:"listening"`
}

// relayIdentity is the reply. Field names and encodings are the ones
// /users/provision already uses for the same values, so a publisher has
// one vocabulary for the relay's material wherever it came from.
type relayIdentity struct {
	IdentityVersion int `json:"identity_version"`

	// RealityPublicKey — base64 x25519 public key of the REALITY
	// keypair. Empty when the relay does not serve vless-reality.
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	// TLSCertSHA256 — base64 SHA-256 of the data-plane certificate's
	// SubjectPublicKeyInfo (the pin, not a certificate digest; the name
	// is historical and shared with /users/provision).
	TLSCertSHA256 string `json:"tls_cert_sha256,omitempty"`
	// CoverSNI — the REALITY cover host, from the live config.
	CoverSNI string `json:"cover_sni,omitempty"`
	// SSMethod / SSServerKeySHA256 — the shadowsocks method and the
	// digest of the box-wide key. Both empty until the key exists; see
	// PendingFamilies.
	SSMethod          string `json:"ss_method,omitempty"`
	SSServerKeySHA256 string `json:"ss_server_key_sha256,omitempty"`

	// Families is every family this relay serves, sorted by name.
	Families []identityFamily `json:"families"`
	// PendingFamilies names the served families whose IDENTITY material
	// does not exist yet. Today that can only be shadowsocks: its
	// box-wide key is minted together with the first recipient. A
	// publisher that signs now cannot commit that route, and must sign
	// again once the list is empty. Always present, possibly empty.
	PendingFamilies []string `json:"pending_families"`

	GeneratedAtUnix int64 `json:"generated_at_unix"`
}

// identityInbounds maps each family to the inbound that serves it and
// the port this binary creates that inbound on when it is the one that
// creates it (0: cloud-init writes it, so there is no fallback port).
var identityInbounds = []struct {
	family, tag string
	createPort  int
}{
	{famVLESSReality, tagVLESS, 0},
	{famHysteria2, tagHy2, 0},
	{famNaive, tagNaive, naiveListenPort},
	{famWebSocketTLS, tagWS, wsListenPort},
	{famTUIC, tagTUIC, 0},
	{famShadowsocks, tagSS, ssListenPort},
	{famAnyTLS, tagAnyTLS, anytlsListenPort},
}

// inboundListenPort reads an inbound's listen_port (JSON numbers decode
// as float64).
func inboundListenPort(in map[string]any) int {
	switch v := in["listen_port"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

// buildIdentity assembles the reply from what is on disk right now.
// Everything is read, never remembered: the config is what the relay
// serves, and /rotate-tls can move the cover host under a cached copy.
func (s *server) buildIdentity() (relayIdentity, error) {
	id := relayIdentity{
		IdentityVersion: identityVersion,
		Families:        []identityFamily{},
		PendingFamilies: []string{},
		GeneratedAtUnix: s.now().Unix(),
	}
	doc, err := loadSingboxDoc(s.singboxConfig)
	if err != nil {
		return id, err
	}
	fams, err := readFamilySet(s.familiesPath)
	if err != nil {
		return id, err
	}

	served := map[string]bool{}
	for _, ib := range identityInbounds {
		in := findInboundByTag(doc, ib.tag)
		switch {
		case in != nil:
			// A live inbound is served whatever the declaration says:
			// this document describes the relay, not the intention.
			id.Families = append(id.Families, identityFamily{
				Family: ib.family, Port: inboundListenPort(in), Listening: true,
			})
			served[ib.family] = true
		case fams != nil && fams[ib.family] && ib.createPort != 0:
			// Declared, and this binary creates it with the first
			// recipient. (An UNDECLARED relay creates every such family
			// on first use too, but nothing says which of them its
			// packs carry, so only what is live is claimed.)
			id.Families = append(id.Families, identityFamily{
				Family: ib.family, Port: ib.createPort, Listening: false,
			})
			served[ib.family] = true
		}
	}
	sort.Slice(id.Families, func(i, j int) bool { return id.Families[i].Family < id.Families[j].Family })

	if served[famVLESSReality] {
		id.RealityPublicKey = s.readRealityPub()
		id.CoverSNI = coverSNI(doc)
	}
	// One certificate serves every TLS family on the box.
	for _, f := range []string{famHysteria2, famNaive, famWebSocketTLS, famTUIC, famAnyTLS} {
		if served[f] {
			id.TLSCertSHA256 = s.readTLSCertSHA256()
			break
		}
	}
	if served[famShadowsocks] {
		if key := ssInboundPSK(doc); key != "" {
			id.SSMethod = ssMethod
			id.SSServerKeySHA256 = ssServerKeyDigest(key)
		} else {
			id.PendingFamilies = append(id.PendingFamilies, famShadowsocks)
		}
	}
	return id, nil
}

// handleIdentity serves GET /identity.
func (s *server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id, err := s.buildIdentity()
	if err != nil {
		// A relay that cannot read its own config must not answer with
		// a partial identity: the publisher would sign it.
		http.Error(w, "identity: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(id)
}
