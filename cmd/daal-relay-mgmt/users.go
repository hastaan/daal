// FRP-14: per-recipient credentials API.
//
// Adds three routes to the in-box mgmt plane:
//
//	POST /users/provision  — append a fresh per-recipient user row
//	                          to every sing-box inbound; return creds.
//	POST /users/revoke     — remove a user row, run kick wrapper,
//	                          reload sing-box.
//	GET  /users/list       — list active user names.
//
// See specs/per-recipient-credentials-v1.md for the wire format
// and on-box invariants. The surgical sing-box rewriter lives in
// singbox_users.go to keep the routing surface here readable.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// MaxRecipientsPerServer is the hard cap from FRP-14 invariant 7.
// Each recipient adds one row to each of the four inbounds — VLESS,
// Hy2, Naive and the single shared ws-in. This is a cap on RECIPIENTS,
// not on inbounds: there is exactly one WS inbound and all recipients
// share its `transport.path` (see singbox_users.go's package comment).
// The cap bounds reload time and config size.
const MaxRecipientsPerServer = 128

// nameRegex matches the recipient names the wizard emits:
// `r<digits>`, 1..12 digits, e.g. "r17", "r420". The on-box
// service does not interpret the digits; they map back to the
// wizard's `recipients.id` PK.
var nameRegex = regexp.MustCompile(`^r[0-9]{1,12}$`)

// userCreds is the JSON returned by /users/provision and is also
// the shape persisted in the publisher app's operator_recipients
// table. Fields match per-recipient-credentials-v1.md §3.1.
type userCreds struct {
	Name              string `json:"name"`
	VLESSUUID         string `json:"vless_uuid"`
	RealityShortID    string `json:"reality_short_id"` // 8 hex chars
	Hy2Password       string `json:"hy2_password"`     // 22 b64-url chars
	NaivePassword     string `json:"naive_password"`   // 22 b64-url chars
	WSPath            string `json:"ws_path"`          // /r<id>/<8 hex>
	ProvisionedAtUnix int64  `json:"provisioned_at_unix"`

	// FRP-14 Tier-2: box-wide (not per-user) connection material the
	// publisher needs to assemble a working client sing-box outbound.
	// Same value for every recipient on this box; echoed in each
	// provision response so the publisher never has to SSH the box.
	//   RealityPublicKey — base64 x25519 pubkey of the vless-in
	//     REALITY keypair (from /etc/daal/reality.pub, written at
	//     cloud-init first boot). Empty if the file is absent (e.g.
	//     a pre-Tier-2 box) — the publisher then can't build a
	//     vless-reality outbound and must surface that.
	//   TLSCertSHA256 — hex SHA-256 of the DER of the box's
	//     self-signed leaf cert used by the ws/hy2/naive inbounds,
	//     for client-side certificate pinning on a bare-IP VPS with
	//     no CA-issued cert. Empty when those transports aren't shipped.
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	TLSCertSHA256    string `json:"tls_cert_sha256,omitempty"`
	//   TLSCertPEM — the full data-plane leaf cert (PEM). naive/Cronet
	//     verifies against a trusted-root set rather than an SPKI pin, so
	//     the publisher installs this as the recipient's naive trusted
	//     root. Empty when the data-plane cert is absent.
	TLSCertPEM string `json:"tls_cert_pem,omitempty"`
	//   CoverSNI — the REALITY cover host this box advertises, read from
	//     the live vless-in inbound. The client outbound's
	//     tls.server_name must equal it exactly or REALITY fails, so the
	//     publisher takes it from here rather than from a compile-time
	//     constant: the whole fleet sharing one cover host is one free
	//     string match away from being burned at once, and /rotate-tls
	//     can move this value at any time. Empty on a box provisioned
	//     before the cover host was templated — the publisher then falls
	//     back to the legacy constant for that relay only.
	CoverSNI string `json:"cover_sni,omitempty"`
	//   MuxInbound — this box's vless-family inbounds carry a
	//     `multiplex` block, so a pack minted against it MAY emit the
	//     matching outbound one. The direction is not symmetric and
	//     that is the whole reason this field exists: a mux inbound
	//     still serves non-mux clients (sing-box hands a connection to
	//     the mux service only when its destination equals the mux
	//     sentinel), but a mux CLIENT against a relay without the block
	//     routes to that sentinel host and fails hard. So the box may
	//     turn mux on unilaterally — and does, on every provision —
	//     while the publisher must wait to be told.
	//
	//     Read from the live config, not from what this binary intended
	//     to write, so an operator who hand-edited the block out is
	//     believed.
	MuxInbound bool `json:"mux_inbound"`
}

type userMeta struct {
	Name              string `json:"name"`
	ProvisionedAtUnix int64  `json:"provisioned_at_unix"`
}

type provisionReq struct {
	Name string `json:"name"`
}

type revokeReq struct {
	Name string `json:"name"`
}

type listResp struct {
	Users []userMeta `json:"users"`
}

func (s *server) handleUsersProvision(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.usersProvCnt.Add(1)
	var req provisionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !nameRegex.MatchString(req.Name) {
		http.Error(w, "name must match r[0-9]{1,12}", http.StatusBadRequest)
		return
	}

	// Serialized against the other three mutating endpoints; see cfgMu.
	// The duplicate check, the append and the reload are one critical
	// section — two concurrent provisions would otherwise both pass
	// userExists and the second rename would drop the first recipient.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	count, err := countUsers(s.singboxConfig)
	if err != nil {
		http.Error(w, "count users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if count >= MaxRecipientsPerServer {
		http.Error(w, fmt.Sprintf("max recipients (%d) reached on this server", MaxRecipientsPerServer), http.StatusConflict)
		return
	}
	exists, err := userExists(s.singboxConfig, req.Name)
	if err != nil {
		http.Error(w, "check duplicate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, fmt.Sprintf("user %q already exists", req.Name), http.StatusConflict)
		return
	}

	creds, err := mintCreds(req.Name, s.now().Unix())
	if err != nil {
		http.Error(w, "mint creds: "+err.Error(), http.StatusInternalServerError)
		return
	}
	effectiveWSPath, err := addUserToSingbox(s.singboxConfig, creds, s.singboxCheck)
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// The shared ws-in inbound fixes one ws path for all recipients; hand
	// the client the path it actually has to dial (the first recipient's,
	// reused thereafter), not the fresh one mintCreds just generated.
	creds.WSPath = effectiveWSPath
	if err := s.singboxControl("reload"); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Attach the box-wide connection material so the publisher can
	// assemble a working client outbound without SSHing the box.
	// Best-effort: a pre-Tier-2 box has no reality.pub/tls-cert.pem and
	// the publisher surfaces the resulting empty fields.
	creds.RealityPublicKey = s.readRealityPub()
	creds.TLSCertSHA256 = s.readTLSCertSHA256()
	creds.TLSCertPEM = s.readTLSCertPEM()
	creds.CoverSNI = readCoverSNI(s.singboxConfig)
	creds.MuxInbound = readMuxInbound(s.singboxConfig)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

// readRealityPub returns the base64 x25519 REALITY public key written
// to realityPubPath at cloud-init first boot, or "" if unreadable.
func (s *server) readRealityPub() string {
	if s.realityPubPath == "" {
		return ""
	}
	b, err := os.ReadFile(s.realityPubPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readTLSCertSHA256 returns the base64 SHA-256 of the box's self-signed
// leaf cert's SubjectPublicKeyInfo (SPKI), or "" if unreadable/malformed.
// This is exactly what sing-box's client TLS `certificate_public_key_
// sha256` pin compares against, so the publisher can drop it into the
// client outbound verbatim. Pinning the public key (not the whole cert)
// lets the box rotate the cert with the same key without re-issuing packs.
func (s *server) readTLSCertSHA256() string {
	if s.tlsCertPath == "" {
		return ""
	}
	pemBytes, err := os.ReadFile(s.tlsCertPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// readTLSCertPEM returns the box's self-signed data-plane leaf cert as
// PEM, or "" if unreadable. The naive client outbound needs the full
// cert (not just the SPKI pin): naive rides Cronet, which verifies via a
// trusted-root set (there is no CA), so the publisher installs this PEM
// as the recipient's trusted root. ws/hy2 pin by SPKI and don't need it.
func (s *server) readTLSCertPEM() string {
	if s.tlsCertPath == "" {
		return ""
	}
	pemBytes, err := os.ReadFile(s.tlsCertPath)
	if err != nil {
		return ""
	}
	if block, _ := pem.Decode(pemBytes); block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	return string(pemBytes)
}

func (s *server) handleUsersRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.usersRevokeCnt.Add(1)
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !nameRegex.MatchString(req.Name) {
		http.Error(w, "name must match r[0-9]{1,12}", http.StatusBadRequest)
		return
	}
	// Serialized against the other three mutating endpoints; see cfgMu.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	removed, err := removeUserFromSingbox(s.singboxConfig, req.Name, s.singboxCheck)
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, fmt.Sprintf("user %q not found", req.Name), http.StatusNotFound)
		return
	}
	// Force-kick first (SIGUSR2 + reload via the wrapper script),
	// then a plain reload to settle config. Both are best-effort:
	// even if the wrapper fails (e.g., sing-box version doesn't
	// honor SIGUSR2 on this build), the user row is gone from the
	// config and new connections fail auth.
	if err := s.singboxKick(); err != nil {
		// Soft-fail: the revoke succeeded at the config level.
		// Log but don't bubble — old-version-singbox boxes still
		// get correct semantics on next idle/reconnect.
		// Caller can still inspect counts.
	}
	if err := s.singboxControl("reload"); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{
		"revoked_at_unix": s.now().Unix(),
	})
}

func (s *server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.usersListCnt.Add(1)
	users, err := listUsers(s.singboxConfig)
	if err != nil {
		http.Error(w, "list users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listResp{Users: users})
}

// mintCreds generates fresh per-recipient credentials. All fields
// use crypto/rand.
func mintCreds(name string, nowUnix int64) (userCreds, error) {
	uuid, err := genUUID()
	if err != nil {
		return userCreds{}, err
	}
	var shortID [4]byte
	if _, err := rand.Read(shortID[:]); err != nil {
		return userCreds{}, err
	}
	var hy2Raw, naiveRaw, wsPathRaw [16]byte
	if _, err := rand.Read(hy2Raw[:]); err != nil {
		return userCreds{}, err
	}
	if _, err := rand.Read(naiveRaw[:]); err != nil {
		return userCreds{}, err
	}
	if _, err := rand.Read(wsPathRaw[:]); err != nil {
		return userCreds{}, err
	}
	// WS path uses 4 random bytes hex-encoded (8 chars), so it
	// stays URL-safe and short.
	return userCreds{
		Name:              name,
		VLESSUUID:         uuid,
		RealityShortID:    hex.EncodeToString(shortID[:]),
		Hy2Password:       base64.RawURLEncoding.EncodeToString(hy2Raw[:]),
		NaivePassword:     base64.RawURLEncoding.EncodeToString(naiveRaw[:]),
		WSPath:            fmt.Sprintf("/%s/%s", name, hex.EncodeToString(wsPathRaw[:4])),
		ProvisionedAtUnix: nowUnix,
	}, nil
}
