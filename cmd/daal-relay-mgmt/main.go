// Command daal-relay-mgmt is the V2 in-box management plane
// service introduced in FRP-10. It listens on the per-deploy port
// stamped into OperatorRecord.MgmtPort, gated by the cloud-provider
// firewall (the Helper opens an ephemeral allowlist via
// Provider.SetEphemeralFirewallRule before each call).
//
// The API surface is intentionally narrow (FRP-10 invariant 29 +
// FRP-14 extension):
//
//	POST /rotate-credentials  — L1 (~5 s); regenerate EVERY recipient's
//	                             VLESS UUID across every vless-family
//	                             inbound + the box REALITY keypair;
//	                             restart sing-box; return new
//	                             credentials.
//	POST /rotate-tls          — L2 (~20 s); move the cover identity —
//	                             advertised SNI and REALITY handshake
//	                             dest together — plus the shared ws
//	                             path; reload sing-box.
//	GET  /health              — liveness probe (no auth).
//	POST /users/provision     — FRP-14; append fresh per-recipient
//	                             credentials (UUID + short_id +
//	                             passwords + WS path) to sing-box
//	                             config; reload; return creds.
//	POST /users/revoke        — FRP-14; remove a recipient, run
//	                             SIGUSR2 + reload kick wrapper,
//	                             effective for live sessions ≤10 s.
//	GET  /users/list          — FRP-14; return active user names.
//	GET|POST /whoami          — echo the source IP the box observes
//	                             for this connection, so the
//	                             publisher's ephemeral-firewall
//	                             allowlist can be verified against
//	                             ground truth instead of a
//	                             third-party echo service.
//
// Adding an eighth route requires a supplement amendment; the
// invariant is enforced by TestExactlyNRoutes (n=7) in main_test.go.
//
// Auth: every state-changing endpoint requires a per-request
// Ed25519 signature in the Authorization: Daal-Mgmt-Token header,
// verified against the per-deploy mgmt-plane public key persisted
// at /etc/daal/mgmt/pubkey by cloud-init.
//
// TLS: self-signed leaf cert generated at first boot; the SHA-256
// fingerprint of the DER bytes is exposed via the (still-running,
// IP-pinned) daal-relay-health endpoint during the bootstrap
// window so the Helper can pin it into OperatorRecord.MgmtTLSFingerprint.
// FRP-10 invariant 26.
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	minMgmtPort = 10000
	maxMgmtPort = 65000
)

// configPaths defines the on-box file layout. Cloud-init writes
// these at provision time; this binary reads them at startup.
type configPaths struct {
	pubkey      string // ed25519 verification key (publisher-issued)
	port        string // file containing the port chosen by wizard
	certPEM     string // generated at first boot
	keyPEM      string
	fingerprint string // hex-lowercase SHA-256 of cert DER; published for Helper pickup
	singboxConf string // path the rotation handlers rewrite
}

func defaultPaths() configPaths {
	return configPaths{
		pubkey:      "/etc/daal/mgmt/pubkey",
		port:        "/etc/daal/mgmt/port",
		certPEM:     "/etc/daal/mgmt/cert.pem",
		keyPEM:      "/etc/daal/mgmt/key.pem",
		fingerprint: "/var/log/daal/mgmt-tls.fpr",
		singboxConf: "/etc/sing-box/config.json",
	}
}

func main() {
	if err := run(defaultPaths()); err != nil {
		log.Fatalf("daal-relay-mgmt: %v", err)
	}
}

func run(paths configPaths) error {
	port, err := readPort(paths.port)
	if err != nil {
		return fmt.Errorf("read port: %w", err)
	}
	pubkey, err := readPubkey(paths.pubkey)
	if err != nil {
		return fmt.Errorf("read pubkey: %w", err)
	}
	cert, err := ensureSelfSignedCert(paths.certPEM, paths.keyPEM, paths.fingerprint)
	if err != nil {
		return fmt.Errorf("ensure cert: %w", err)
	}

	srv := newServer(pubkey, paths.singboxConf)
	httpSrv := &http.Server{
		Addr:      ":" + strconv.Itoa(port),
		Handler:   srv.routes(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
	}
	log.Printf("daal-relay-mgmt listening on :%d", port)
	return httpSrv.ListenAndServeTLS("", "")
}

// server is the routing + auth state.
type server struct {
	pubkey         ed25519.PublicKey
	singboxConfig  string
	realityPubPath string // /etc/daal/reality.pub (FRP-14 Tier-2)
	tlsCertPath    string // /etc/daal/tls-cert.pem (self-signed leaf, ws/hy2/naive)
	coverSNIPath   string // /etc/daal/cover-sni (the box's own statement of its cover host)
	rotateCredCnt  atomic.Int64
	rotateTLSCnt   atomic.Int64
	healthCnt      atomic.Int64
	usersProvCnt   atomic.Int64
	usersRevokeCnt atomic.Int64
	usersListCnt   atomic.Int64
	whoamiCnt      atomic.Int64
	now            func() time.Time
	singboxControl func(action string) error // injectable for tests
	singboxKick    func() error              // injectable for tests
	singboxCheck   func(path string) error   // injectable for tests
}

func newServer(pubkey ed25519.PublicKey, singboxConfig string) *server {
	return &server{
		pubkey:         pubkey,
		singboxConfig:  singboxConfig,
		realityPubPath: "/etc/daal/reality.pub",
		tlsCertPath:    "/etc/daal/tls-cert.pem",
		coverSNIPath:   "/etc/daal/cover-sni",
		now:            time.Now,
		singboxControl: defaultSingboxControl,
		singboxKick:    defaultSingboxKick,
		singboxCheck:   defaultSingboxCheck,
	}
}

// singboxBinary is where cloud-init installs the data-plane binary.
const singboxBinary = "/usr/local/bin/sing-box"

// defaultSingboxCheck runs `sing-box check -c <path>` so a rewritten
// config is proven loadable BEFORE it replaces the live one.
//
// This exists because sing-box's config parser is strict — an unknown
// field, or a private key in the wrong encoding, is a FATAL at startup,
// not a warning — and this service's whole job is to rewrite that file
// on a box nobody can SSH into. Two shipped bugs in this file each
// produced a config that `check` rejects (a `reality.server_names` key
// that does not exist in 1.13, and a hex-encoded REALITY private key
// where base64url is required); both would have bricked the relay on
// the restart that follows the rewrite, with no way back. Validating a
// temp file and only then renaming turns "unreachable box" into "500,
// config untouched".
//
// A box whose binary is missing or too old to support `check` must not
// be wedged shut by that: an exec failure (as opposed to a non-zero
// exit) is treated as "cannot validate here" and lets the write
// proceed, which is the pre-existing behaviour.
func defaultSingboxCheck(path string) error {
	if _, err := os.Stat(singboxBinary); err != nil {
		return nil // no validator available on this box; not a config fault
	}
	out, err := exec.Command(singboxBinary, "check", "-c", path).CombinedOutput()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return nil // could not run the validator at all
	}
	return fmt.Errorf("sing-box check rejected the rewritten config: %s", strings.TrimSpace(string(out)))
}

// defaultSingboxControl runs `systemctl <action> sing-box.service`,
// EXCEPT for "reload": sing-box's systemd unit ships without an
// ExecReload= directive (sing-box has no SIGHUP-driven config
// reload upstream), so `systemctl reload` fails with
//
//	Job type reload is not applicable for unit sing-box.service.
//
// Route reload through the cloud-init kick wrapper, which knows the
// graceful pattern: SIGUSR2 (drop new inbounds) → settle → `reload
// || restart`. Other actions (start/stop/restart/status) still go
// straight to systemctl.
func defaultSingboxControl(action string) error {
	if action == "reload" {
		return defaultSingboxKick()
	}
	cmd := exec.Command("systemctl", action, "sing-box.service")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w (%s)", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// defaultSingboxKick runs the on-box kick wrapper installed by
// cloud-init: /usr/local/lib/daal/singbox-kick.sh. The wrapper
// sends SIGUSR2 to sing-box (graceful inbound drop) and then
// reloads. Used by /users/revoke to evict live sessions within
// ≤ 10 s.
func defaultSingboxKick() error {
	cmd := exec.Command("/usr/local/lib/daal/singbox-kick.sh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("singbox-kick: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// routes wires the exactly-seven endpoint surface (FRP-10 invariant
// 29 lifted at FRP-14 to add three per-recipient user routes; see
// specs/per-recipient-credentials-v1.md; lifted again for /whoami).
// Adding an eighth route requires a supplement amendment.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/rotate-credentials", s.requireAuth(s.handleRotateCreds))
	mux.HandleFunc("/rotate-tls", s.requireAuth(s.handleRotateTLS))
	mux.HandleFunc("/users/provision", s.requireAuth(s.handleUsersProvision))
	mux.HandleFunc("/users/revoke", s.requireAuth(s.handleUsersRevoke))
	mux.HandleFunc("/users/list", s.requireAuth(s.handleUsersList))
	// /whoami echoes the source IP the box actually sees for this
	// connection. The publisher's own idea of its public IP comes from
	// third-party echo services and can be wrong behind CGNAT,
	// split-horizon NAT or a captive proxy, which silently produces a
	// firewall allowlist entry for an address the box never sees. This
	// is the only authoritative answer. It cannot *bootstrap* the
	// allowlist — the endpoint is itself behind that firewall, so it
	// can only be reached from an address that already works — it
	// confirms a working IP so the client can store a verified value
	// and stop re-detecting.
	mux.HandleFunc("/whoami", s.requireAuth(s.handleWhoAmI))
	return mux
}

// routeNames returns the exact set of HTTP paths registered. Used
// by main_test.go to enforce TestExactlyNRoutes (n=7).
func (s *server) routeNames() []string {
	return []string{
		"/health",
		"/rotate-credentials",
		"/rotate-tls",
		"/users/provision",
		"/users/revoke",
		"/users/list",
		"/whoami",
	}
}

// requireAuth verifies the Authorization: Daal-Mgmt-Token header.
// The token format is "<nonce>:<ts>:<op>:<base64-sig>" where the
// signature covers "<nonce>:<ts>:<op>".
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Daal-Mgmt-Token ") {
			http.Error(w, "unauthorized: missing Daal-Mgmt-Token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(hdr, "Daal-Mgmt-Token ")
		if err := s.verifyToken(token, opFromPath(r.URL.Path)); err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func opFromPath(p string) string {
	switch p {
	case "/rotate-credentials":
		return "rotate-credentials"
	case "/rotate-tls":
		return "rotate-tls"
	case "/users/provision":
		return "users-provision"
	case "/users/revoke":
		return "users-revoke"
	case "/users/list":
		return "users-list"
	case "/whoami":
		return "whoami"
	default:
		return ""
	}
}

// verifyToken decodes "<nonce>:<ts>:<op>:<sig>" and verifies the
// Ed25519 signature against s.pubkey. Reject tokens older than 5
// minutes to bound replay window.
func (s *server) verifyToken(token, expectedOp string) error {
	parts := strings.Split(token, ":")
	if len(parts) != 4 {
		return errors.New("malformed token (need nonce:ts:op:sig)")
	}
	nonce, tsStr, op, sigB64 := parts[0], parts[1], parts[2], parts[3]
	if op != expectedOp {
		return fmt.Errorf("op %q does not match endpoint %q", op, expectedOp)
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("bad ts %q: %w", tsStr, err)
	}
	now := s.now().Unix()
	if ts < now-300 || ts > now+60 {
		return fmt.Errorf("token timestamp out of window (now=%d, ts=%d)", now, ts)
	}
	sig, err := decodeBase64(sigB64)
	if err != nil {
		return fmt.Errorf("bad sig: %w", err)
	}
	msg := []byte(nonce + ":" + tsStr + ":" + op)
	if !ed25519.Verify(s.pubkey, msg, sig) {
		return errors.New("signature verification failed")
	}
	_ = nonce // server does not deduplicate (cloud-firewall narrows the window enough)
	return nil
}

// decodeBase64 accepts both standard and URL-safe base64.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// --- handlers ---

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.healthCnt.Add(1)
	_, _ = io.WriteString(w, `{"ok":true}`)
}

// rotateCredentialsResp is the JSON returned to the Helper.
//
// ENCODING — RealityPrivKey is base64 (raw URL alphabet), NOT hex. It
// used to be hex, and that was a box-bricking bug rather than a
// cosmetic one: sing-box decodes `reality.private_key` with
// base64.RawURLEncoding, so a 64-char hex string decodes to 48 bytes
// and the inbound FATALs "invalid private key" on the restart this
// handler performs. Verified against sing-box 1.13.12. The endpoint has
// no callers yet (the ladder is wired in a later wave), so nothing is
// depending on the old spelling.
//
// Users maps recipient name → new UUID. A box carries one row per
// recipient in both vless-in and ws-in; UUID alone (the first row) can
// only ever describe one of them, and is kept for wire compatibility.
type rotateCredentialsResp struct {
	UUID            string            `json:"uuid"`
	Users           map[string]string `json:"users,omitempty"`
	RealityPrivKey  string            `json:"reality_private_key"`
	RealityPubKey   string            `json:"reality_public_key"`
	GeneratedAtUnix int64             `json:"generated_at_unix"`
}

// handleRotateCreds rotates BOTH per-recipient UUIDs and the box-wide
// REALITY keypair.
//
// Conflating those two is a known wart: rotating the keypair invalidates
// the pinned public key in EVERY distributed pack, so it can only be
// used together with a redistribution path, whereas rotating one
// recipient's UUID is a targeted revocation. Splitting them into
// separate operations belongs to the rotation-ladder work; what is
// fixed here is that the handler no longer leaves the box in a state
// that cannot boot or that revokes nobody.
func (s *server) handleRotateCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.rotateCredCnt.Add(1)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, "reality key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	privB64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	assigned, order, err := s.rewriteSingboxCreds(s.singboxConfig, genUUID, privB64)
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Persist the public half next to the private one. /users/provision
	// reads this file to tell the publisher which key to pin; without
	// this write a rotation silently makes every subsequently minted
	// pack unusable, because it would carry the retired public key.
	if s.realityPubPath != "" {
		if err := os.WriteFile(s.realityPubPath, []byte(pubB64+"\n"), 0o644); err != nil {
			http.Error(w, "persist reality pubkey: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := s.singboxControl("restart"); err != nil {
		http.Error(w, "singbox restart: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Named recipients only: the synthetic keys surgicalSetUUIDs invents
	// for unnamed legacy rows are an internal detail, not something a
	// caller can act on.
	users := map[string]string{}
	for name, uuid := range assigned {
		if nameRegex.MatchString(name) {
			users[name] = uuid
		}
	}
	first := ""
	if len(order) > 0 {
		first = assigned[order[0]]
	}
	resp := rotateCredentialsResp{
		UUID:            first,
		Users:           users,
		RealityPrivKey:  privB64,
		RealityPubKey:   pubB64,
		GeneratedAtUnix: s.now().Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// rotateTLSReq accepts a new cover identity from the Helper.
//
// NewSNI is the cover host the box advertises and the client's outbound
// must send. NewDests[0] is the REALITY handshake dest ("host" or
// "host:port") that has to corroborate it — normally the same host on
// 443. The field stays plural for wire compatibility with the existing
// publisher client; sing-box 1.13 accepts exactly one handshake dest,
// so entries past the first are ignored rather than silently mangled
// into a config key that does not exist (see surgicalSetSNI).
type rotateTLSReq struct {
	NewSNI    string   `json:"new_sni"`
	NewDests  []string `json:"new_dests"`
	NewWSPath string   `json:"new_ws_path,omitempty"`
}

// rotateTLSResp echoes what was actually applied so the caller can
// verify the two names moved TOGETHER instead of trusting a bare 200.
// Additive fields: an older client decoding only applied_at_unix is
// unaffected.
type rotateTLSResp struct {
	AppliedAtUnix    int64  `json:"applied_at_unix"`
	AppliedSNI       string `json:"applied_sni"`
	AppliedHandshake string `json:"applied_handshake"`
}

func (s *server) handleRotateTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.rotateTLSCnt.Add(1)
	var req rotateTLSReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.NewSNI == "" || len(req.NewDests) == 0 {
		http.Error(w, "new_sni and new_dests required", http.StatusBadRequest)
		return
	}
	if err := s.rewriteSingboxTLS(s.singboxConfig, req.NewSNI, req.NewDests, req.NewWSPath); err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.singboxControl("reload"); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	host, port := splitDest(strings.TrimSpace(req.NewDests[0]))
	// Keep /etc/daal/cover-sni in step with the config we just wrote.
	// cloud-init writes that file once at first boot, and its stated
	// purpose is to be the box's own answer to "what do you advertise?"
	// — a file that goes stale on the one operation that changes the
	// answer is worse than no file, because a human debugging a dead
	// tier reads it and concludes the rotation never happened.
	//
	// Best-effort on purpose: the config rename already succeeded and
	// sing-box already reloaded, so failing the request here would
	// report a rotation that in fact applied. The config is the source
	// of truth (readCoverSNI parses it); this file is a convenience.
	if s.coverSNIPath != "" {
		_ = os.WriteFile(s.coverSNIPath, []byte(req.NewSNI+"\n"), 0o644)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rotateTLSResp{
		AppliedAtUnix:    s.now().Unix(),
		AppliedSNI:       req.NewSNI,
		AppliedHandshake: net.JoinHostPort(host, strconv.Itoa(port)),
	})
}

// whoAmIResp is the JSON returned to the Helper. Deliberately tiny:
// the only load-bearing field is source_ip. api_version exists so a
// future shape change is detectable by a client that must also keep
// working against boxes that predate this endpoint entirely (a 404 /
// 405 / connection error from an older box means "no answer", never
// "failure" — see specs feature-detection note).
type whoAmIResp struct {
	SourceIP       string `json:"source_ip"`
	ServerTimeUnix int64  `json:"server_time_unix"`
	APIVersion     int    `json:"api_version"`
}

// whoAmIAPIVersion is bumped only if the response shape changes.
const whoAmIAPIVersion = 1

func (s *server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	// GET is the natural verb; POST is accepted too because the Helper's
	// signed-request path is POST-shaped for every other authenticated
	// endpoint and piggybacking /whoami on it should not need a special
	// case. Anything else is a client bug, not an older/newer box.
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.whoamiCnt.Add(1)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(whoAmIResp{
		SourceIP:       observedSourceIP(r.RemoteAddr),
		ServerTimeUnix: s.now().Unix(),
		APIVersion:     whoAmIAPIVersion,
	})
}

// observedSourceIP extracts the peer address of the actual TCP
// connection.
//
// X-Forwarded-For / X-Real-IP / Forwarded are deliberately NOT
// consulted. Nothing in this deployment establishes a trusted proxy:
// cloud-init runs this binary as a systemd unit listening directly on
// the per-deploy mgmt port with its own TLS, there is no nginx/caddy
// in front of it, and the one other place in the tree that makes a
// decision from a client address (publisher/deploy/health/handler.go
// allowedRemoteIP) also reads r.RemoteAddr alone. Honouring a
// client-supplied header here would let any caller dictate the value
// this endpoint exists to *verify*, and that value is written straight
// into a cloud-firewall allowlist — a spoofable source IP would turn a
// verification source into a remote allowlist-injection primitive. If
// a reverse proxy is ever introduced, this function must gain an
// explicit trusted-proxy check, not a bare header read.
//
// The value is returned as observed, never invented: a RemoteAddr the
// stdlib can't split (malformed, or empty as in a synthesised request)
// yields the raw string — possibly "" — so a client sees what the box
// saw and can reject it, rather than being handed a plausible-looking
// wrong answer.
func observedSourceIP(remoteAddr string) string {
	addr := strings.TrimSpace(remoteAddr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		// SplitHostPort already strips the brackets of an IPv6
		// "[::1]:443" form; a zone ("fe80::1%eth0") is left intact
		// because dropping it would fabricate a different address.
		return strings.TrimSpace(host)
	}
	// No port at all is the common non-error case here (some proxying
	// listeners and test harnesses set a bare literal); accept the
	// bracketed IPv6 spelling of it too.
	return strings.TrimSpace(strings.Trim(addr, "[]"))
}

// --- crypto helpers ---

// ensureSelfSignedCert returns a TLS keypair, generating one if
// the on-disk files are missing. The fingerprint file (hex SHA-256
// of cert DER) is written so the bootstrap relay can publish it.
func ensureSelfSignedCert(certPath, keyPath, fpPath string) (tls.Certificate, error) {
	if _, err := os.Stat(certPath); err == nil {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "daal-relay-mgmt"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return tls.Certificate{}, err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return tls.Certificate{}, err
	}
	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])
	_ = os.MkdirAll(dirOf(fpPath), 0o755)
	if err := os.WriteFile(fpPath, []byte(fp+"\n"), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func writePEM(path, blockType string, body []byte) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: body})
	return os.WriteFile(path, out, 0o600)
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// --- file readers ---

func readPort(path string) (int, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if env := os.Getenv("DAAL_MGMT_PORT"); env != "" {
			return parseMgmtPort(env)
		}
		return 0, err
	}
	return parseMgmtPort(string(body))
}

func parseMgmtPort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if port < minMgmtPort || port > maxMgmtPort {
		return 0, fmt.Errorf("mgmt port %d outside [%d, %d]", port, minMgmtPort, maxMgmtPort)
	}
	return port, nil
}

func readPubkey(path string) (ed25519.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hexed := strings.TrimSpace(string(body))
	raw, err := hex.DecodeString(hexed)
	if err != nil {
		return nil, fmt.Errorf("pubkey not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey wrong size %d (want %d)", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// --- sing-box config rewriters ---
//
// SINGLE-INDEX RULE — read before adding a surgical* helper.
//
// Every helper below used to reach for `inbounds[0]`, and one of them
// for `users[0]` as well. That assumption is false on every relay this
// service has ever run on:
//
//   - the inbound set is FOUR inbounds (vless-in, hy2-in, ws-in,
//     naive-in), and two of them are created lazily by
//     singbox_users.go — so ordering is a function of provisioning
//     history, not of the template;
//   - the user set is one row PER RECIPIENT, in up to 128 rows, and the
//     same recipient owns a row in BOTH vless-in and ws-in keyed by the
//     same UUID.
//
// The same class has now bitten this codebase three times (the per-user
// ws inbound that collided on 8445, removeVLESSUser truncating
// short_id[] and revoking the wrong recipient, and surgicalSetUUID
// below). So: a surgical helper selects inbounds by TAG or by TYPE and
// then loops. It never indexes. And it never writes a key into an
// inbound whose type does not define it — sing-box's parser is strict,
// so writing `uuid` into a hysteria2 user or `multiplex` into a naive
// inbound is not a no-op, it is a box that will not boot.

// rewriteSingboxCreds patches the vless-family users' UUIDs + the
// REALITY private key. The schema is the standard sing-box JSON; we do
// a narrow surgical edit so non-Daal config sections survive unchanged.
//
// mintUUID is called once per distinct recipient, so a box with N
// recipients ends with N fresh, still-distinct UUIDs — the same value
// applied to that recipient's row in every vless-family inbound.
// Rotating one recipient's identity onto all of them would collapse the
// per-recipient credentials FRP-14 exists to keep apart; rotating only
// row 0 (what this did) left recipients 2..N with live credentials, and
// left EVERY recipient's ws-in row untouched, so the "rotation" revoked
// nothing at all — the recipient just moved to the ws tier.
//
// Returns name→new-UUID for every row rewritten, in config order.
func (s *server) rewriteSingboxCreds(path string, mintUUID func() (string, error), realityKey string) (map[string]string, []string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		body = []byte(`{"inbounds":[{"type":"vless","tag":"` + tagVLESS + `","users":[{"uuid":""}],"tls":{"reality":{"private_key":""}}}]}`)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("singbox config not JSON: %w", err)
	}
	assigned, order, err := surgicalSetUUIDs(doc, mintUUID)
	if err != nil {
		return nil, nil, err
	}
	if err := surgicalSetRealityKey(doc, realityKey); err != nil {
		return nil, nil, err
	}
	if err := s.commitSingboxDoc(path, doc); err != nil {
		return nil, nil, err
	}
	return assigned, order, nil
}

// rewriteSingboxTLS applies a new cover identity to the box: the
// advertised SNI, the REALITY handshake dest that must corroborate it,
// and (optionally) the shared ws path.
func (s *server) rewriteSingboxTLS(path, sni string, dests []string, wsPath string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		body = []byte(`{"inbounds":[{"type":"vless","tag":"` + tagVLESS + `","tls":{"server_name":"","reality":{"handshake":{"server":"","server_port":443}}}}]}`)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("singbox config not JSON: %w", err)
	}
	if err := surgicalSetSNI(doc, sni, dests); err != nil {
		return err
	}
	if wsPath != "" {
		// Not "best effort" any more. This used to be `_ =`, and it always
		// failed: it looked for a transport block on inbounds[0], which is
		// vless-in and has none. A rotation therefore reported success
		// while the ws path never moved — the publisher then minted packs
		// for a path the box does not serve.
		if err := surgicalSetWSPath(doc, wsPath); err != nil {
			return err
		}
	}
	return s.commitSingboxDoc(path, doc)
}

// commitSingboxDoc writes doc to a sibling temp file, proves sing-box
// will load it, and only then renames it over the live config. See
// defaultSingboxCheck for why the validation step is not optional.
func (s *server) commitSingboxDoc(path string, doc map[string]any) error {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if s.singboxCheck != nil {
		if err := s.singboxCheck(tmp); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, path)
}

// vlessFamilyInbounds returns every inbound whose `type` is "vless" —
// on a Daal box that is vless-in (REALITY on 443) and ws-in (VLESS over
// WebSocket). They are the only two whose users are keyed by `uuid` and
// the only two sing-box 1.13 accepts a `multiplex` block on; hy2-in and
// naive-in use different user shapes and reject both keys outright
// (verified: `inbounds[0].multiplex: json: unknown field "multiplex"`).
func vlessFamilyInbounds(doc map[string]any) []map[string]any {
	inbounds, _ := doc["inbounds"].([]any)
	out := make([]map[string]any, 0, len(inbounds))
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if in == nil {
			continue
		}
		if t, _ := in["type"].(string); t == "vless" {
			out = append(out, in)
		}
	}
	return out
}

// surgicalSetUUIDs assigns a fresh UUID to every recipient across every
// vless-family inbound, keeping one recipient's rows consistent with
// each other (vless-in and ws-in must agree — the client uses one UUID
// for both routes).
//
// Rows carrying no `name` are the pre-FRP-14 / bootstrap shape; each
// gets its own UUID keyed by an inbound-scoped synthetic name so two
// unnamed rows never collapse onto one credential.
func surgicalSetUUIDs(doc map[string]any, mintUUID func() (string, error)) (map[string]string, []string, error) {
	ins := vlessFamilyInbounds(doc)
	if len(ins) == 0 {
		return nil, nil, errors.New("singbox config has no vless inbounds")
	}
	assigned := map[string]string{}
	order := []string{}
	rows := 0
	for _, in := range ins {
		tag, _ := in["tag"].(string)
		users, _ := in["users"].([]any)
		for i, raw := range users {
			u, _ := raw.(map[string]any)
			if u == nil {
				continue
			}
			rows++
			key, _ := u["name"].(string)
			if key == "" {
				key = fmt.Sprintf("\x00unnamed:%s:%d", tag, i)
			}
			next, ok := assigned[key]
			if !ok {
				var err error
				next, err = mintUUID()
				if err != nil {
					return nil, nil, err
				}
				assigned[key] = next
				order = append(order, key)
			}
			u["uuid"] = next
		}
	}
	if rows == 0 {
		return nil, nil, errors.New("singbox config vless inbounds have no users")
	}
	return assigned, order, nil
}

// surgicalSetRealityKey sets the REALITY private key on every inbound
// that has a reality block, not just inbounds[0] — the index is a
// function of provisioning order, and if hy2-in ever lands first the
// old code failed the whole rotation with "no reality block".
//
// The caller supplies the key already encoded the way sing-box wants
// it. That is base64 (raw URL alphabet), the format
// `sing-box generate reality-keypair` emits and cloud-init injects;
// common/tls/reality_server.go decodes it with base64.RawURLEncoding
// and FATALs "invalid private key" on anything else.
func surgicalSetRealityKey(doc map[string]any, key string) error {
	found := false
	inbounds, _ := doc["inbounds"].([]any)
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if in == nil {
			continue
		}
		tlsBlock, _ := in["tls"].(map[string]any)
		if tlsBlock == nil {
			continue
		}
		reality, _ := tlsBlock["reality"].(map[string]any)
		if reality == nil {
			continue
		}
		reality["private_key"] = key
		found = true
	}
	if !found {
		return errors.New("singbox config has no inbound with a reality block")
	}
	return nil
}

// surgicalSetSNI moves the box's whole cover identity atomically.
//
// Rotation rung L2 could not work before this, and the reason is worth
// keeping written down. A REALITY inbound has TWO names that must agree:
// `tls.server_name`, the SNI it accepts and the client advertises, and
// `reality.handshake.server`, the real host it proxies an unrecognised
// ClientHello to. This function moved the first and left the second, so
// a rotated box advertised (say) news.example.org while still handing
// every probe to www.cloudflare.com — the IP-to-SNI mismatch that
// REALITY exists to prevent, and the single most cited "trivially
// anomalous" signature in the research corpus.
//
// It also used to write `reality.server_names`. sing-box 1.13's
// InboundRealityOptions has no such field (the accepted SNI set is
// derived from `tls.server_name` alone), and the parser is strict:
// verified, that config is rejected with
//
//	inbounds[0].tls.reality.server_names: json: unknown field "server_names"
//
// i.e. the previous implementation of rung L2 did not merely mismatch,
// it produced a config the box could not boot. Any such key left behind
// by an earlier rotation is deleted here so this call repairs a wedged
// config rather than preserving it.
//
// The advertised name is mirrored onto ws-in as well, because
// appendWSUser deliberately copies vless-in's server_name when it
// creates that inbound; leaving it behind would strand the ws tier on
// the retired cover host. hy2-in and naive-in are untouched on purpose:
// their clients pin the box's own leaf by SPKI (and naive matches the
// literal IP SAN), so rewriting their server_name breaks them.
//
// dests[0] is the handshake dest, "host" or "host:port"; it defaults to
// the new SNI on :443, which is the only configuration that stands up
// to a probe.
func surgicalSetSNI(doc map[string]any, sni string, dests []string) error {
	handshakeHost, handshakePort := sni, 443
	if len(dests) > 0 && strings.TrimSpace(dests[0]) != "" {
		handshakeHost, handshakePort = splitDest(strings.TrimSpace(dests[0]))
	}
	ins := vlessFamilyInbounds(doc)
	if len(ins) == 0 {
		return errors.New("singbox config has no vless inbounds")
	}
	touched := false
	for _, in := range ins {
		tlsBlock, _ := in["tls"].(map[string]any)
		if tlsBlock == nil {
			continue
		}
		tlsBlock["server_name"] = sni
		touched = true
		reality, _ := tlsBlock["reality"].(map[string]any)
		if reality == nil {
			continue
		}
		delete(reality, "server_names") // not a field in sing-box 1.13; see above
		hs, _ := reality["handshake"].(map[string]any)
		if hs == nil {
			hs = map[string]any{}
			reality["handshake"] = hs
		}
		hs["server"] = handshakeHost
		hs["server_port"] = handshakePort
	}
	if !touched {
		return errors.New("singbox config has no vless inbound with a tls block")
	}
	return nil
}

// splitDest parses "host" or "host:port" (including the bracketed IPv6
// spelling) into its parts, defaulting to :443. A garbage port is
// treated as absent rather than propagated into the config, where it
// would be a boot-time FATAL on a box nobody can reach.
func splitDest(dest string) (string, int) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return strings.Trim(dest, "[]"), 443
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return host, 443
	}
	return host, port
}

// surgicalSetWSPath rewrites the shared ws-in path.
//
// It selects the inbound by tag. The old version took inbounds[0] and
// asked for its `transport` block — inbounds[0] is vless-in, which has
// no transport, so this returned an error on every real box, and the
// only caller discarded it. Absence of ws-in is NOT an error (the
// inbound is created lazily by the first recipient), but finding it and
// failing to rewrite it is.
func surgicalSetWSPath(doc map[string]any, p string) error {
	in := findInboundByTag(doc, tagWS)
	if in == nil {
		return nil // no ws recipients yet; nothing to rotate
	}
	tr, _ := in["transport"].(map[string]any)
	if tr == nil {
		return fmt.Errorf("inbound %q has no transport block", tagWS)
	}
	tr["path"] = p
	return nil
}

// --- UUID generator ---

// genUUID generates a v4 UUID without depending on a third-party
// package.
func genUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
