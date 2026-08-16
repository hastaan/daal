// Command daal-relay-mgmt is the V2 in-box management plane
// service introduced in FRP-10. It listens on the per-deploy port
// stamped into OperatorRecord.MgmtPort, gated by the cloud-provider
// firewall (the Helper opens an ephemeral allowlist via
// Provider.SetEphemeralFirewallRule before each call).
//
// The API surface is intentionally narrow (FRP-10 invariant 29 +
// FRP-14 extension):
//
//	POST /rotate-credentials  — L1 (~5 s); regenerate VLESS UUID +
//	                             REALITY private key; restart
//	                             sing-box; return new credentials.
//	POST /rotate-tls          — L2 (~20 s); rotate SNI / dest set;
//	                             update TLS config; restart
//	                             sing-box; return new TLS profile.
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
}

func newServer(pubkey ed25519.PublicKey, singboxConfig string) *server {
	return &server{
		pubkey:         pubkey,
		singboxConfig:  singboxConfig,
		realityPubPath: "/etc/daal/reality.pub",
		tlsCertPath:    "/etc/daal/tls-cert.pem",
		now:            time.Now,
		singboxControl: defaultSingboxControl,
		singboxKick:    defaultSingboxKick,
	}
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
type rotateCredentialsResp struct {
	UUID            string `json:"uuid"`
	RealityPrivKey  string `json:"reality_private_key"` // hex-encoded; 32 bytes
	GeneratedAtUnix int64  `json:"generated_at_unix"`
}

func (s *server) handleRotateCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.rotateCredCnt.Add(1)
	uuid, err := genUUID()
	if err != nil {
		http.Error(w, "uuid: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var realityKey [32]byte
	if _, err := rand.Read(realityKey[:]); err != nil {
		http.Error(w, "reality key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := rewriteSingboxCreds(s.singboxConfig, uuid, realityKey[:]); err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.singboxControl("restart"); err != nil {
		http.Error(w, "singbox restart: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := rotateCredentialsResp{
		UUID:            uuid,
		RealityPrivKey:  hex.EncodeToString(realityKey[:]),
		GeneratedAtUnix: s.now().Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// rotateTLSReq accepts a new SNI + dest set from the Helper.
type rotateTLSReq struct {
	NewSNI    string   `json:"new_sni"`
	NewDests  []string `json:"new_dests"`
	NewWSPath string   `json:"new_ws_path,omitempty"`
}

type rotateTLSResp struct {
	AppliedAtUnix int64 `json:"applied_at_unix"`
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
	if err := rewriteSingboxTLS(s.singboxConfig, req.NewSNI, req.NewDests, req.NewWSPath); err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.singboxControl("reload"); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rotateTLSResp{AppliedAtUnix: s.now().Unix()})
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

// rewriteSingboxCreds patches the inbound's user UUID + the
// REALITY private key. The schema is the standard sing-box JSON;
// we do a narrow surgical edit so non-Daal config sections
// survive unchanged.
func rewriteSingboxCreds(path, uuid string, realityKey []byte) error {
	body, err := os.ReadFile(path)
	if err != nil {
		body = []byte(`{"inbounds":[{"type":"vless","users":[{"uuid":""}],"tls":{"reality":{"private_key":""}}}]}`)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("singbox config not JSON: %w", err)
	}
	if err := surgicalSetUUID(doc, uuid); err != nil {
		return err
	}
	if err := surgicalSetRealityKey(doc, hex.EncodeToString(realityKey)); err != nil {
		return err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func rewriteSingboxTLS(path, sni string, dests []string, wsPath string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		body = []byte(`{"inbounds":[{"type":"vless","tls":{"server_name":"","reality":{"server_names":[]}},"transport":{"path":""}}]}`)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("singbox config not JSON: %w", err)
	}
	if err := surgicalSetSNI(doc, sni, dests); err != nil {
		return err
	}
	if wsPath != "" {
		_ = surgicalSetWSPath(doc, wsPath)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func surgicalSetUUID(doc map[string]any, uuid string) error {
	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) == 0 {
		return errors.New("singbox config has no inbounds")
	}
	in0, _ := inbounds[0].(map[string]any)
	users, _ := in0["users"].([]any)
	if len(users) == 0 {
		return errors.New("singbox config inbound has no users")
	}
	u0, _ := users[0].(map[string]any)
	u0["uuid"] = uuid
	return nil
}

func surgicalSetRealityKey(doc map[string]any, hexKey string) error {
	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) == 0 {
		return errors.New("singbox config has no inbounds")
	}
	in0, _ := inbounds[0].(map[string]any)
	tlsBlock, _ := in0["tls"].(map[string]any)
	if tlsBlock == nil {
		return errors.New("singbox config inbound has no tls block")
	}
	reality, _ := tlsBlock["reality"].(map[string]any)
	if reality == nil {
		return errors.New("singbox config inbound has no reality block")
	}
	reality["private_key"] = hexKey
	return nil
}

func surgicalSetSNI(doc map[string]any, sni string, dests []string) error {
	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) == 0 {
		return errors.New("singbox config has no inbounds")
	}
	in0, _ := inbounds[0].(map[string]any)
	tlsBlock, _ := in0["tls"].(map[string]any)
	if tlsBlock == nil {
		return errors.New("singbox config inbound has no tls block")
	}
	tlsBlock["server_name"] = sni
	if reality, ok := tlsBlock["reality"].(map[string]any); ok {
		conv := make([]any, len(dests))
		for i, d := range dests {
			conv[i] = d
		}
		reality["server_names"] = conv
	}
	return nil
}

func surgicalSetWSPath(doc map[string]any, p string) error {
	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) == 0 {
		return errors.New("singbox config has no inbounds")
	}
	in0, _ := inbounds[0].(map[string]any)
	tr, _ := in0["transport"].(map[string]any)
	if tr == nil {
		return errors.New("singbox config inbound has no transport block")
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
