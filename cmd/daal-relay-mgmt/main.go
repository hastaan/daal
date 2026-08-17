// Command daal-relay-mgmt is the V2 in-box management plane
// service introduced in FRP-10. It listens on the per-deploy port
// stamped into OperatorRecord.MgmtPort, gated by the cloud-provider
// firewall (the Helper opens an ephemeral allowlist via
// Provider.SetEphemeralFirewallRule before each call).
//
// The API surface is intentionally narrow (FRP-10 invariant 29 +
// FRP-14 extension):
//
//	POST /rotate-credentials  — L1 (~5 s); re-mint ONE named recipient's
//	                             per-user credentials across every
//	                             inbound that carries a row for them
//	                             (vless-in, ws-in, hy2-in, naive-in);
//	                             kick + reload sing-box; return the new
//	                             credentials. A missing "name" is an
//	                             ERROR — see rotate.go for why "rotate
//	                             everything" must never be a default.
//	                             Touches no other recipient and no
//	                             box-wide key material.
//	POST /rotate-tls          — L2 (~20 s); move the cover identity —
//	                             advertised SNI and REALITY handshake
//	                             dest together — and/or the shared ws
//	                             path; reload sing-box. Touches no user
//	                             credentials and no REALITY keypair.
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
//	POST /bind-address        — L3; configure a provider-routed
//	                             floating IP on the primary interface,
//	                             idempotently and persisted across
//	                             reboot, so the guest OS actually
//	                             answers on an address the provider
//	                             has merely routed here. See
//	                             address.go for why the API-layer
//	                             attach alone leaves the box silent.
//	POST /unbind-address      — L3; remove an address this service
//	                             bound, live and persisted, so a relay
//	                             never keeps claiming an address the
//	                             provider has handed back to the pool.
//
// Adding a TENTH route requires a supplement amendment; the invariant
// is enforced by TestExactlyNRoutes (n=9) in main_test.go. The two
// address routes were added by the Wave-3c L3 work, which the pinned
// contract requires; specs/daal-relay-mgmt-v1.md §4 needs the matching
// amendment.
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
	"flag"
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
	"sync"
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

// defaultBoundAddrDir holds one file per operator-bound address. See
// address.go for why persistence is a record set plus a systemd oneshot
// rather than a netplan file.
const defaultBoundAddrDir = "/etc/daal/bound-addresses"

func main() {
	// -reapply-addresses is the boot mode. daal-bound-addresses.service
	// (written by address.go on the first successful bind) runs this
	// binary with the flag after network-online.target, under a unit
	// that carries CAP_NET_ADMIN ambiently — which is how the address
	// comes back after a reboot even though the long-running service
	// below is denied that capability.
	//
	// It is the SAME reconciliation code the live path uses, so a
	// record that the API would reject cannot be applied by the reboot
	// either, and there is no shell script to drift out of step.
	reapply := flag.Bool("reapply-addresses", false,
		"re-apply the persisted operator-bound addresses to the primary interface and exit (run by "+bootUnitName+")")
	flag.Parse()
	if *reapply {
		if err := reapplyBoundAddresses(defaultBoundAddrDir, log.Printf); err != nil {
			// Non-zero exit marks the unit failed, which is the only
			// signal a human gets that this relay is not holding an
			// address it is supposed to hold.
			log.Fatalf("daal-relay-mgmt -reapply-addresses: %v", err)
		}
		return
	}
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
	// State the address-binding verdict once, at startup, into the
	// journal. /health carries it too, but the journal is the only
	// record that survives a box the publisher cannot reach, and "this
	// relay cannot do L3, here is why" is the single most useful line a
	// human can find on a relay they have no SSH access to.
	if srv.addrCapability != nil {
		if _, note := srv.addrCapability(); note != "" {
			log.Printf("daal-relay-mgmt: %s", note)
		}
	}
	log.Printf("daal-relay-mgmt listening on :%d", port)
	return httpSrv.ListenAndServeTLS("", "")
}

// server is the routing + auth state.
type server struct {
	pubkey        ed25519.PublicKey
	singboxConfig string
	// cfgMu serializes every read-modify-write of singboxConfig.
	//
	// net/http runs each request on its own goroutine, and all four
	// mutating endpoints (/rotate-credentials, /rotate-tls,
	// /users/provision, /users/revoke) do the same load → mutate →
	// rename over ONE file. Without this lock two overlapping calls both
	// read the pre-call document and the second rename wins wholesale, so
	// one of the two operations is silently discarded — and a discarded
	// ROTATION is the worst case of all: the publisher has already filed
	// it as a completed revocation and handed the operator a rebuilt
	// pack, while the leaked credential is still live in the file the box
	// serves. None of the in-flight guards can catch that, because
	// assertRetiredAbsent and `sing-box check` both validate the
	// in-memory candidate rather than the file being overwritten.
	//
	// Overlap is not hypothetical: ephemeral firewall windows are
	// additive and last 300 s each, so a wizard rotation and a terminal
	// `daal-deploy users-provision` from the same allowlisted IP overlap
	// freely.
	//
	// Held across the reload as well as the write, so the config on disk
	// and the running process cannot be re-crossed by a second writer
	// mid-rollback. One mutex is enough and costs nothing: these calls
	// are seconds apart at worst and all target the same file.
	cfgMu          sync.Mutex
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
	bindAddrCnt    atomic.Int64
	unbindAddrCnt  atomic.Int64
	now            func() time.Time
	singboxControl func(action string) error // injectable for tests
	singboxKick    func() error              // injectable for tests
	singboxCheck   func(path string) error   // injectable for tests

	// --- L3 address binding (address.go) ---

	// addrMu serializes the record set and the interface work.
	//
	// Deliberately NOT cfgMu. /bind-address and /unbind-address do not
	// read or write the sing-box config at all — every inbound already
	// listens on 0.0.0.0, so a new address needs no config change — and
	// funnelling address work through the config lock would queue it
	// behind multi-second rotations for nothing. What does need
	// serializing is different state: the count check, the record write
	// and the apply must not interleave with a concurrent unbind of the
	// same address.
	addrMu       sync.Mutex
	boundAddrDir string // /etc/daal/bound-addresses
	// bootUnitPath / bootUnitWantsPath are the persistence artifacts.
	// Fields rather than constants so tests exercise the real install
	// code against a temp tree instead of /etc.
	bootUnitPath      string
	bootUnitWantsPath string
	// Injectable seams. The list/add/del split matters: LIST needs no
	// capability and is how every apply is VERIFIED, while add/del need
	// CAP_NET_ADMIN and may have to be delegated.
	addrList      func(iface string) ([]net.IP, error)
	addrAdd       func(iface string, ip net.IP) error
	addrDel       func(iface string, ip net.IP) error
	primaryIface  func() (string, error)
	systemdStart  func(unit string) error
	systemdReload func() error
	// addrCapability answers "can this box actually configure an
	// address", which /health advertises and both handlers re-check.
	// See probeAddressBinding for why it is a runtime probe and not a
	// build-time constant.
	addrCapability func() (bool, string)

	// seenAddrNonces makes an address-verb token SINGLE USE. See
	// consumeAddressNonce.
	nonceMu        sync.Mutex
	seenAddrNonces map[string]int64
}

// maxSeenAddrNonces bounds the replay cache.
//
// Entries are recorded only AFTER the signature verifies, so nothing an
// unauthenticated caller sends can grow this map; and the accept window
// is 360 seconds wide (verifyToken), which is pruned on every call. The
// cap is therefore belt-and-braces against a caller stuck in a retry
// loop rather than a defence, and eviction is oldest-first by
// timestamp so the entries that survive are the ones still presentable.
const maxSeenAddrNonces = 4096

// consumeAddressNonce enforces SINGLE USE of a token for the two
// address verbs, and returns false if this nonce has been seen before.
//
// WHY ONLY THESE TWO VERBS. The token signs `nonce:ts:op` and NOT the
// request body, so one captured token authorises any number of calls to
// its route for the rest of the ±window. That was tolerable when the
// bodies named a recipient; it is weaker for a verb whose body chooses
// which address this host configures, where the same token can be
// replayed with a different "ip" each time until the 4-address cap is
// reached — and each of those persists across a reboot. Making the
// token single-use closes the repeat-use half of that without a wire
// change (the publisher already mints a fresh 128-bit random nonce per
// request: mgmt.MintToken).
//
// It is deliberately NOT applied to the other five verbs. GET
// /users/list carries a token on a request net/http's transport is
// allowed to retry on a reused-idle-connection race, and a retried GET
// re-sends the same token; refusing it would turn a transport hiccup
// into a failed rotation. POSTs are not replayable that way (a POST
// with a body is not `isReplayable`), which is what makes it safe here:
// both address verbs are POSTs.
//
// The proper fix — signing sha256(body) into the token — is a wire
// change on both ends and is recorded in the spec (§4.8) as the next
// step; this is the box-local half that needs no coordinated release.
func (s *server) consumeAddressNonce(nonce string, ts int64) bool {
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	if s.seenAddrNonces == nil {
		s.seenAddrNonces = make(map[string]int64)
	}
	// Drop anything that can no longer be presented: a token older than
	// the accept window is refused by the timestamp check anyway, so
	// remembering it buys nothing.
	cutoff := s.now().Unix() - 300
	for k, v := range s.seenAddrNonces {
		if v < cutoff {
			delete(s.seenAddrNonces, k)
		}
	}
	if _, dup := s.seenAddrNonces[nonce]; dup {
		return false
	}
	if len(s.seenAddrNonces) >= maxSeenAddrNonces {
		oldestK, oldestV := "", int64(0)
		for k, v := range s.seenAddrNonces {
			if oldestK == "" || v < oldestV {
				oldestK, oldestV = k, v
			}
		}
		delete(s.seenAddrNonces, oldestK)
	}
	s.seenAddrNonces[nonce] = ts
	return true
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

		boundAddrDir:      defaultBoundAddrDir,
		bootUnitPath:      "/etc/systemd/system/" + bootUnitName,
		bootUnitWantsPath: "/etc/systemd/system/multi-user.target.wants/" + bootUnitName,
		addrList:          defaultAddrList,
		addrAdd:           defaultAddrAdd,
		addrDel:           defaultAddrDel,
		primaryIface:      detectPrimaryInterface,
		systemdStart:      defaultSystemdStart,
		systemdReload:     defaultSystemdReload,
		addrCapability:    probeAddressBinding,
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
	// L3. Both are privileged network configuration driven by a remote
	// request, so both sit behind the same per-request Ed25519
	// signature as every other mutating verb, and address.go adds
	// defence in depth on top of it (public-unicast validation, a bound
	// on how many addresses may be held, argv-only shell-outs, and a
	// record gate that makes it impossible to remove the box's own
	// primary address). Neither touches the sing-box config: every
	// inbound already listens on 0.0.0.0, so holding the address is the
	// entire change.
	mux.HandleFunc("/bind-address", s.requireAuth(s.handleBindAddress))
	mux.HandleFunc("/unbind-address", s.requireAuth(s.handleUnbindAddress))
	return mux
}

// routeNames returns the exact set of HTTP paths registered. Used
// by main_test.go to enforce TestExactlyNRoutes (n=9).
func (s *server) routeNames() []string {
	return []string{
		"/health",
		"/rotate-credentials",
		"/rotate-tls",
		"/users/provision",
		"/users/revoke",
		"/users/list",
		"/whoami",
		"/bind-address",
		"/unbind-address",
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
	// The op string is signed by the publisher and must match the path
	// exactly; mgmt.addressVerb mints "bind-address"/"unbind-address"
	// and POSTs to "/"+op, so path and op are the same word by
	// construction on both ends.
	case "/bind-address":
		return "bind-address"
	case "/unbind-address":
		return "unbind-address"
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
	// The five older verbs do not deduplicate: the cloud-firewall
	// window narrows replay enough for bodies that name a recipient,
	// and GET /users/list is on a request the transport may legitimately
	// retry with the same token. The two ADDRESS verbs do, because
	// their body chooses which address this host configures and the
	// signature does not cover it. See consumeAddressNonce.
	if op == "bind-address" || op == "unbind-address" {
		if !s.consumeAddressNonce(nonce, ts) {
			return errors.New("token already used (address verbs are single-use; mint a fresh one)")
		}
	}
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

// Capability advertisement carried by GET /health.
//
// WHY THE BOX HAS TO SAY THIS OUT LOUD. daal-relay-mgmt ships as a
// hash-pinned artifact (publisher/deploy/cloudinit/artifacts.go), so a
// relay keeps running whatever binary it was born with until a human
// rebuilds, re-signs, re-uploads and bumps the pin. The fleet therefore
// contains both the pre-Step-7 conflated rotator and this one at the
// same time, and the publisher is the only party that can tell them
// apart before it sends anything mutating.
//
// It cannot tell them apart by probing. /rotate-credentials and
// /rotate-tls have been REGISTERED since FRP-10, so an old box answers
// 200 rather than 404 — the route's existence says nothing about its
// semantics. And probing by behaviour is destructive: the old handler
// ignores the body, rotates every recipient AND the box-wide REALITY
// keypair, which invalidates the pinned public key in every pack
// already distributed. A probe whose failure mode is "silently bricked
// the whole relay" is not a probe.
//
// So the signal has to be POSITIVE and it has to come from here. The
// tokens name the SEMANTICS, not the route — the "-scoped" suffix is
// what distinguishes the split, targeted behaviour from the conflated
// one, because the bare route name is true of every box ever shipped.
// An old box answers `{"ok":true}`, which decodes into an empty verb
// set, so "old" falls out of the wire format instead of needing a
// special case, and the publisher fails closed by construction.
//
// These strings are a wire contract with publisher/deploy/mgmt
// (mgmt.CapRotateCredentialsScoped / CapRotateTLSScoped /
// MgmtAPIVersionSplitRotation). Changing one end alone re-breaks the
// interlock silently; TestHealthAdvertisesSplitRotation pins the exact
// literals here so a rename cannot drift unnoticed.
const (
	// capRotateCredentialsScoped: POST /rotate-credentials {"name":"r1"}
	// rotates ONLY that recipient, across every inbound, and touches no
	// REALITY keypair. A missing name is an error, never "rotate all".
	capRotateCredentialsScoped = "rotate-credentials-scoped"

	// capRotateTLSScoped: POST /rotate-tls moves cover SNI / TLS
	// parameters only, leaving keypairs and user credentials alone, and
	// echoes what it applied.
	capRotateTLSScoped = "rotate-tls-scoped"

	// mgmtAPIVersion is the second signal, sufficient on its own so a
	// box that reports a version but not a verb list is still usable.
	// v2 == the Step-7 split-rotation contract.
	mgmtAPIVersion = 2
)

// handleHealth is the liveness probe AND the capability advertisement.
//
// Both live on this route deliberately: /health already exists, needs
// no auth, and mutates nothing, so advertising here costs no new route
// — and specs/daal-relay-mgmt-v1.md §4 pins the surface at seven, with
// an eighth requiring a supplement amendment (TestExactlyNRoutes).
// Extending an existing response with additive fields is compatible in
// both directions: an old publisher reading a new box still sees
// "ok":true and ignores the rest.
// WHY capBindAddress IS CONDITIONAL AND mgmt_api_version DOES NOT MOVE.
//
// The two rotation tokens describe what this BINARY does, so the binary
// can assert them unconditionally and mgmt_api_version=2 is a valid
// second signal for them. Address binding is not like that: it needs
// CAP_NET_ADMIN, which the SERVICE UNIT decides. Relays provisioned
// before Wave 3c's cloud-init run this service with
// `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and
// `NoNewPrivileges=true`, so a box can be running this exact binary and
// still be unable to configure an address.
// Advertising the verb from the version number would make the
// publisher's interlock assert a capability that does not exist and
// move the failure to the middle of a swap, which is the one place the
// whole fail-closed design exists to keep it out of.
//
// So the token is emitted only when probeAddressBinding says this
// process holds the capability it needs for BOTH verbs — one token
// covers bind and unbind, and only the in-process route can remove an
// address — and mgmt_api_version stays at 2. That is not an oversight,
// and the publisher agrees with it from its own side: BoxCapabilities.Has
// gives CapBindAddress NO version fallback at all, so the token is the
// only signal either end consults. publisher/deploy/mgmt still defines
// MgmtAPIVersionAddressBinding=3, but purely as documentation of which
// version the two routes belong to; nothing reads it as permission.
//
// DO NOT bump mgmtAPIVersion to 3 to "finish" the address work. Even
// with no fallback to trip today, a version that implied the capability
// would be a standing invitation to re-add one — and a relay running
// this binary without CAP_NET_ADMIN would then claim a verb it cannot
// perform, moving the failure into the middle of a swap.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.healthCnt.Add(1)
	caps := []string{capRotateCredentialsScoped, capRotateTLSScoped}
	var notes []string
	if s.addrCapability != nil {
		ok, note := s.addrCapability()
		if ok {
			caps = append(caps, capBindAddress)
		}
		if note != "" {
			notes = append(notes, note)
		}
	}
	body := map[string]any{
		"ok":               true,
		"mgmt_api_version": mgmtAPIVersion,
		"capabilities":     caps,
	}
	// capability_notes is diagnostic text for a human who cannot SSH
	// into this box. "Binary too old" and "binary fine, launched
	// without CAP_NET_ADMIN" both present as a missing token but have
	// completely different remedies, and an unexplained absence sends
	// the operator to the wrong one. Additive: a publisher that does
	// not decode it is unaffected.
	if len(notes) > 0 {
		body["capability_notes"] = notes
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// rotateCredsReq names the ONE recipient whose credentials are to be
// re-minted. There is no "all" spelling and no default: see rotate.go.
type rotateCredsReq struct {
	Name string `json:"name"`
}

// rotateCredentialsResp is the JSON returned to the Helper.
//
// It embeds userCreds, so the shape is byte-for-byte the one
// /users/provision already returns — same field names, same semantics,
// including the box-wide material (reality_public_key, tls_cert_sha256,
// tls_cert_pem, cover_sni, mux_inbound). That is deliberate: a rotation's
// entire purpose is to produce a replacement pack, and forcing the publisher
// to follow a rotate with a provision to learn the pinning material is how
// the two ends drift. One call, one complete credential set.
//
// WHAT IS NO LONGER HERE, and why the removal is the point:
//
//	reality_private_key — the box keypair is NOT rotated by this endpoint
//	  any more. Returning a field named after an operation that did not
//	  happen is worse than omitting it. reality_public_key is still
//	  present, carrying the box's CURRENT (unchanged) key, because the
//	  publisher needs it to pin the replacement pack.
//
// BoxKeysRotated is always false today and exists so a caller can assert
// that rather than infer it from a missing field.
//
// UpdatedInbounds is the honesty field: a revocation that reached three of
// four inbounds leaves the leaked credential live on the fourth. The caller
// can and should check that this lists every tier the recipient uses.
//
// UUID and Users are retained for wire compatibility with the pre-Step-7
// publisher client (mgmt.Credentials), which decodes exactly those two.
// Users now carries a single entry — the rotated recipient — which is the
// truthful rendering of the new semantics in the old field.
type rotateCredentialsResp struct {
	userCreds
	UUID            string            `json:"uuid"`
	Users           map[string]string `json:"users,omitempty"`
	UpdatedInbounds []string          `json:"updated_inbounds"`
	Warnings        []string          `json:"warnings,omitempty"`
	BoxKeysRotated  bool              `json:"box_keys_rotated"`
	RotatedAtUnix   int64             `json:"rotated_at_unix"`
	GeneratedAtUnix int64             `json:"generated_at_unix"`
}

// handleRotateCreds re-mints ONE named recipient's per-user credentials.
//
// BLAST RADIUS: exactly one recipient. Every other recipient's rows are
// untouched in every inbound, and no box-wide material (REALITY keypair,
// cover SNI, shared ws path, data-plane cert) moves. Sessions belonging to
// other recipients are dropped by the reload and reconnect on credentials
// that still work; the rotated recipient stays off until they receive the
// pack this response feeds.
//
// A MISSING NAME IS AN ERROR. The pre-Step-7 publisher client posts a nil
// body, which decodes to an empty name and lands here as a 400 — exactly the
// right outcome, because that client believes this endpoint rotates everyone
// and regenerates the box keypair. Failing loudly is how an un-updated caller
// finds out the semantics changed, instead of discovering it from a relay
// that severed every recipient at once.
func (s *server) handleRotateCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.rotateCredCnt.Add(1)
	var req rotateCredsReq
	// An absent body is EOF, not a malformed one; it still fails the name
	// check below, with a message that says what to send.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !nameRegex.MatchString(req.Name) {
		http.Error(w, `"name" is required and must match r[0-9]{1,12}: this endpoint rotates ONE recipient, never all of them`, http.StatusBadRequest)
		return
	}

	// Load → mutate → commit → reload is one critical section; see cfgMu.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	doc, err := loadSingboxDoc(s.singboxConfig)
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fresh, err := mintCreds(req.Name, s.now().Unix())
	if err != nil {
		http.Error(w, "mint creds: "+err.Error(), http.StatusInternalServerError)
		return
	}
	res, err := rotateRecipientCreds(doc, req.Name, fresh)
	if errors.Is(err, errRecipientNotFound) {
		http.Error(w, fmt.Sprintf("user %q not found", req.Name), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "rotate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := assertRetiredAbsent(doc, res.retired); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Validates against the strict parser and only then renames over the
	// live file: a rotation must never be able to leave the box holding a
	// config it cannot start.
	rollback, err := s.commitSingboxDoc(s.singboxConfig, doc)
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// APPLY SEMANTICS — the same pair /users/revoke uses, and for the same
	// reason. Rewriting the file alone would only stop NEW authentications;
	// the seized credential's established session would keep carrying
	// traffic indefinitely. The kick wrapper sends SIGUSR2 (graceful inbound
	// drop) and then reloads, evicting live sessions within ~10 s. Every
	// other recipient is disconnected too and reconnects automatically on
	// credentials that did not change — a few seconds of interruption is the
	// price of the revocation being real.
	//
	// Kick is soft-fail (a box whose sing-box build ignores SIGUSR2 still
	// gets correct semantics on the next reconnect); reload is hard-fail,
	// because without it the box is still serving the pre-rotation user
	// table and reporting success would be a lie.
	//
	// The hard failure ROLLS BACK (applyReload). Without that, the new
	// UUID and passwords would exist only in a file the box is not
	// running and that nobody has a copy of — this response is the one
	// time they leave the box — so the recipient would be cut off at the
	// next unrelated reload with credentials recoverable from nowhere.
	if err := s.singboxKick(); err != nil {
		_ = err // best effort; the config is already the source of truth
	}
	if err := s.applyReload(rollback); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Box-wide connection material, exactly as /users/provision attaches it,
	// so this one response is enough to mint the replacement pack. Read from
	// the live box, not from what this handler intended.
	creds := res.Creds
	creds.RealityPublicKey = s.readRealityPub()
	creds.TLSCertSHA256 = s.readTLSCertSHA256()
	creds.TLSCertPEM = s.readTLSCertPEM()
	creds.CoverSNI = readCoverSNI(s.singboxConfig)
	creds.MuxInbound = readMuxInbound(s.singboxConfig)

	now := s.now().Unix()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rotateCredentialsResp{
		userCreds:       creds,
		UUID:            creds.VLESSUUID,
		Users:           map[string]string{creds.Name: creds.VLESSUUID},
		UpdatedInbounds: res.Inbounds,
		Warnings:        res.Warnings,
		BoxKeysRotated:  false,
		RotatedAtUnix:   now,
		GeneratedAtUnix: now,
	})
}

// rotateTLSReq accepts a new cover identity from the Helper. Every field
// is optional; the pinned contract's `POST /rotate-tls {}` is a valid
// request (see rewriteSingboxTLS for what an empty body does).
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
//
// Changed is the field that keeps an empty-bodied call honest — it names
// the parameters that actually moved, so a caller that sent `{}` and got a
// 200 can still tell the operator that the cover host was NOT replaced.
type rotateTLSResp struct {
	AppliedAtUnix    int64    `json:"applied_at_unix"`
	AppliedSNI       string   `json:"applied_sni"`
	AppliedHandshake string   `json:"applied_handshake"`
	AppliedWSPath    string   `json:"applied_ws_path,omitempty"`
	Changed          []string `json:"changed"`
}

// handleRotateTLS moves the box's cover identity and/or the shared ws path.
//
// BLAST RADIUS: the whole relay. Every recipient's pack pins the advertised
// SNI (and, for the ws tier, the path), so anything this endpoint changes
// invalidates every distributed pack until each recipient is refreshed. It
// does NOT invalidate credentials — no user row and no REALITY keypair is
// touched — so the recipients keep their identities and need only new
// connection parameters.
func (s *server) handleRotateTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.rotateTLSCnt.Add(1)
	var req rotateTLSReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	// A handshake dest without an advertised name is exactly the IP-to-SNI
	// mismatch REALITY exists to prevent, so it is refused rather than
	// half-applied.
	if req.NewSNI == "" && len(req.NewDests) > 0 {
		http.Error(w, "new_dests without new_sni would leave the advertised name and the handshake dest disagreeing", http.StatusBadRequest)
		return
	}
	// The two names must name the same HOST. The port may differ (a cover
	// host reachable on something other than 443 is legitimate); the host
	// may not — a box that advertises one name while handing probes to
	// another is the single most cited "trivially anomalous" signature in
	// the research corpus, and it is the failure L2 shipped with before
	// Wave 2.
	if req.NewSNI != "" && len(req.NewDests) > 0 {
		if host, _ := splitDest(strings.TrimSpace(req.NewDests[0])); host != "" && host != req.NewSNI {
			http.Error(w, fmt.Sprintf("new_dests[0] host %q must equal new_sni %q (only the port may differ)", host, req.NewSNI), http.StatusBadRequest)
			return
		}
	}
	// Load → mutate → commit → reload is one critical section; see cfgMu.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	applied, rollback, err := s.rewriteSingboxTLS(s.singboxConfig, req)
	if errors.Is(err, errNothingToRotate) {
		http.Error(w, "nothing to rotate: supply new_sni (and optionally new_dests/new_ws_path); an empty request rotates only the shared ws path, and this box has no ws inbound", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Cover-identity parameters are inbound-construction material, so the
	// reload rebuilds the inbounds and every live session is dropped. All
	// recipients reconnect only once they hold the new parameters — which is
	// what makes this the heavy operation of the two.
	//
	// Rolls back on failure (applyReload). This is the endpoint where an
	// un-rolled-back commit does the most damage: the publisher treats a
	// failure with no response as "nothing was applied" and keeps the old
	// cover host in its record, so an orphaned config would put the box on
	// a name no pack will ever carry, at whatever unrelated moment
	// something else reloads sing-box.
	if err := s.applyReload(rollback); err != nil {
		http.Error(w, "singbox reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Keep /etc/daal/cover-sni in step with the config we just wrote.
	// cloud-init writes that file once at first boot, and its stated
	// purpose is to be the box's own answer to "what do you advertise?"
	// — a file that goes stale on the one operation that changes the
	// answer is worse than no file, because a human debugging a dead
	// tier reads it and concludes the rotation never happened.
	//
	// Written only when the advertised name actually moved, and from the
	// EFFECTIVE value read back out of the config rather than the request.
	//
	// Best-effort on purpose: the config rename already succeeded and
	// sing-box already reloaded, so failing the request here would
	// report a rotation that in fact applied. The config is the source
	// of truth (readCoverSNI parses it); this file is a convenience.
	if s.coverSNIPath != "" && applied.SNI != "" && contains(applied.Changed, "cover_sni") {
		_ = os.WriteFile(s.coverSNIPath, []byte(applied.SNI+"\n"), 0o644)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rotateTLSResp{
		AppliedAtUnix:    s.now().Unix(),
		AppliedSNI:       applied.SNI,
		AppliedHandshake: applied.Handshake,
		AppliedWSPath:    applied.WSPath,
		Changed:          applied.Changed,
	})
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
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

// The per-recipient credential rotator and the cover-identity rotator both
// live in rotate.go, which is also where the reasoning about their very
// different blast radii is written down. What used to sit here —
// rewriteSingboxCreds, and the surgicalSetUUIDs/surgicalSetRealityKey pair it
// called — rotated EVERY recipient and the box REALITY keypair in one
// unnamed, unconditional action. It had no callers, and no caller could have
// used it safely: there was no way to ask it for a targeted revocation.

// commitSingboxDoc writes doc to a sibling temp file, proves sing-box
// will load it, and only then renames it over the live config. See
// defaultSingboxCheck for why the validation step is not optional.
//
// It returns a rollback closure that puts the PREVIOUS bytes back. The
// caller must invoke it — through applyReload, normally — if the reload
// that activates the new config fails, because otherwise the box is left
// in the one state nothing recovers from on its own: a config on disk
// that leads the running process. Nothing looks wrong at the time (the
// old config is still being served, the caller reports a failure, the
// publisher records "nothing was applied"), and then the NEXT reload
// from any unrelated cause — most plausibly the operator adding a
// recipient — silently activates the orphaned rotation hours later. For
// /rotate-tls that means a cover host the publisher has never recorded,
// i.e. a relay-wide outage of the primary tier attributable to nothing.
func (s *server) commitSingboxDoc(path string, doc map[string]any) (rollback func(), err error) {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, err
	}
	// Snapshot BEFORE the rename, from the file we are about to replace.
	// A read failure is not fatal — a box with no pre-existing config has
	// nothing to roll back to — but it does mean the rollback is a no-op,
	// and applyReload says so in the error it returns.
	prev, prevErr := os.ReadFile(path)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return nil, err
	}
	if s.singboxCheck != nil {
		if err := s.singboxCheck(tmp); err != nil {
			_ = os.Remove(tmp)
			return nil, err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	if prevErr != nil {
		return func() {}, nil
	}
	return func() {
		// Same write-temp-then-rename discipline: a rollback that
		// truncates the live file mid-write is worse than the state it
		// is undoing. No `sing-box check` — these bytes were loadable a
		// moment ago, and refusing to restore them on a validator hiccup
		// would strand the box on the config we are trying to undo.
		back := path + ".rollback"
		if err := os.WriteFile(back, prev, 0o644); err != nil {
			return
		}
		if err := os.Rename(back, path); err != nil {
			_ = os.Remove(back)
		}
	}, nil
}

// applyReload activates a freshly committed config and guarantees that
// the on-disk config never survives a failed activation.
//
// The pairing is the whole point. `commitSingboxDoc` renames first and
// the reload happens second, so between them the box holds a config it
// is not running. If the reload fails — a systemd hiccup, an OOM, a
// kick wrapper missing on an older cloud-init — the only safe move is to
// put the previous bytes back and try once more to reload, so that
// whatever the running process is doing, the file it would next load is
// the pre-operation one. Reporting a 500 over an un-rolled-back config
// is how "the operation failed" turns into an outage nobody can date.
//
// The second reload is best-effort by necessity (if reload is broken,
// reload is broken); its failure is reported alongside the first so the
// operator sees both. Note that on this box `reload` IS the kick wrapper
// (see defaultSingboxControl), so a failure here means the wrapper
// itself failed and the pre-rotation config is almost certainly still
// the one in memory.
func (s *server) applyReload(rollback func()) error {
	err := s.singboxControl("reload")
	if err == nil {
		return nil
	}
	if rollback == nil {
		return fmt.Errorf("%w (the rewritten config is already on disk and will take effect on the next reload)", err)
	}
	rollback()
	if err2 := s.singboxControl("reload"); err2 != nil {
		return fmt.Errorf("%w (config restored to its pre-operation contents, but reloading that failed too: %v — sing-box may be down)", err, err2)
	}
	return fmt.Errorf("%w (no change was applied: the config was restored to its pre-operation contents)", err)
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
