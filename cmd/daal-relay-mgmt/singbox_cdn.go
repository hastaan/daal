// Add-on 2, the way in through Cloudflare: the relay's door
// (docs/optional-addons-plan.md §2.2, item B-1).
//
//	POST /cdn  {"action":"enable", "port":8448, "ws_path":"/…",
//	            "origin_cert_pem":…, "origin_key_pem":…, "aop_ca_pem":…}
//	POST /cdn  {"action":"disable"}
//	POST /cdn  {"action":"status"}
//
// enable installs the Cloudflare Origin CA certificate and key and the
// origin-pull CA under /etc/daal/cdn, and writes ONE inbound, ws-cdn-in:
// VLESS over WebSocket on its own port, serving the Origin CA
// certificate and REQUIRING a client certificate signed by the
// origin-pull CA (`client_authentication: require-and-verify`). Only
// Cloudflare, presenting this zone's origin-pull certificate, completes
// a TLS handshake on it; anyone else who reaches the port — and the
// firewalls already allow only Cloudflare's ranges — is cut off before
// a byte of VLESS is read.
//
// Why a dedicated inbound and not ws-in. ws-in (8445) serves the
// relay's self-signed certificate to direct clients that pin it and
// asks for no client certificate. Cloudflare under Full (strict) needs
// a certificate it trusts (the Origin CA one), and the door must refuse
// everyone but Cloudflare. One inbound cannot do both.
//
// Users. ws-cdn-in carries the same recipients as the relay's other
// VLESS inbounds, keyed by the same UUIDs: enable copies uuid and name
// from vless-in and ws-in (never REALITY's `flow`, which is meaningless
// over WebSocket). Credential rotation already covers it, because
// rotateRecipientCreds rewrites every inbound of type vless. Adding and
// revoking a recipient need the two hooks below (appendCDNUser,
// removeCDNUser) called from singbox_users.go; until they are, a
// recipient revoked after the door opened keeps the door. That wiring
// is outside this file and is reported as required before the door is
// enabled on any relay.
//
// The door's material comes through the management session only,
// never through cloud-init user-data (cloudinit.RenderV2 refuses it):
// user-data is stored at the provider and readable from the metadata
// service by any process on the box.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// tagCDN mirrors publisher/deploy/relayports.CDNInboundTag.
	tagCDN = "ws-cdn-in"

	// cdnListenPort mirrors publisher/deploy/relayports.CDNOrigin.Port.
	// It is the only port both firewalls open to Cloudflare's ranges,
	// so /cdn refuses any other: an inbound on a port nobody can reach
	// would report "enabled" and carry nothing.
	cdnListenPort = 8448

	cdnOp = "cdn"
)

// cdnDir holds the door's files. A variable so tests use a temp tree.
var cdnDir = "/etc/daal/cdn"

func cdnCertPath() string { return filepath.Join(cdnDir, "origin.pem") }
func cdnKeyPath() string  { return filepath.Join(cdnDir, "origin.key") }
func cdnCAPath() string   { return filepath.Join(cdnDir, "aop_ca.pem") }

// cdnReq is the /cdn body. It must agree field for field with
// publisher/deploy/cloudflare.DoorRequest.
type cdnReq struct {
	Action        string `json:"action"`
	Port          int    `json:"port,omitempty"`
	WSPath        string `json:"ws_path,omitempty"`
	OriginCertPEM string `json:"origin_cert_pem,omitempty"`
	OriginKeyPEM  string `json:"origin_key_pem,omitempty"`
	AOPCACertPEM  string `json:"aop_ca_pem,omitempty"`
}

// cdnResp never echoes key material.
type cdnResp struct {
	Action                 string `json:"action"`
	Enabled                bool   `json:"enabled"`
	Changed                bool   `json:"changed"`
	Port                   int    `json:"port,omitempty"`
	WSPath                 string `json:"ws_path,omitempty"`
	Users                  int    `json:"users"`
	OriginCertSHA256       string `json:"origin_cert_sha256,omitempty"`
	OriginCertNotAfterUnix int64  `json:"origin_cert_not_after_unix,omitempty"`
}

var cdnPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,127}$`)

// validateCDNMaterial checks everything enable will write before any of
// it is written. A pair sing-box cannot load fails the reload and takes
// every inbound down with it, not only this one.
func validateCDNMaterial(req cdnReq, now time.Time) (*x509.Certificate, error) {
	if req.Port != cdnListenPort {
		return nil, fmt.Errorf("port must be %d (the only port the firewalls open to Cloudflare)", cdnListenPort)
	}
	if !cdnPathRE.MatchString(req.WSPath) || strings.Contains(req.WSPath, "..") {
		return nil, errors.New("ws_path is not a usable WebSocket path")
	}
	pair, err := tls.X509KeyPair([]byte(req.OriginCertPEM), []byte(req.OriginKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("origin certificate and key: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("origin certificate: %v", err)
	}
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return nil, errors.New("origin certificate is not valid now")
	}
	rest := []byte(req.AOPCACertPEM)
	n := 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("aop_ca_pem holds something other than certificates")
		}
		ca, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("aop_ca_pem: %v", err)
		}
		if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("aop_ca_pem is not a CA certificate")
		}
		n++
	}
	if n == 0 {
		return nil, errors.New("aop_ca_pem holds no certificate")
	}
	return leaf, nil
}

// cdnUsersFrom lists the recipients the door carries: uuid and name of
// every row in vless-in and ws-in, each name once, vless-in first.
func cdnUsersFrom(doc map[string]any) []any {
	seen := map[string]bool{}
	var out []any
	for _, tag := range []string{tagVLESS, tagWS} {
		in := findInboundByTag(doc, tag)
		if in == nil {
			continue
		}
		for _, raw := range asSlice(in["users"]) {
			u, _ := raw.(map[string]any)
			name, _ := u["name"].(string)
			uuid, _ := u["uuid"].(string)
			if name == "" || uuid == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, map[string]any{"uuid": uuid, "name": name})
		}
	}
	return out
}

func cdnInbound(path string, users []any) map[string]any {
	return map[string]any{
		"type":        "vless",
		"tag":         tagCDN,
		"listen":      "0.0.0.0",
		"listen_port": cdnListenPort,
		"users":       users,
		"multiplex":   muxInbound(),
		"transport": map[string]any{
			"type": "ws",
			"path": path,
		},
		"tls": map[string]any{
			"enabled":                 true,
			"certificate_path":        cdnCertPath(),
			"key_path":                cdnKeyPath(),
			"client_authentication":   "require-and-verify",
			"client_certificate_path": []any{cdnCAPath()},
		},
	}
}

// setCDNInbound replaces ws-cdn-in (or appends it). nil removes it.
func setCDNInbound(doc map[string]any, inbound map[string]any) {
	inbounds := asSlice(doc["inbounds"])
	out := make([]any, 0, len(inbounds)+1)
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if t, _ := in["tag"].(string); t == tagCDN {
			continue
		}
		out = append(out, raw)
	}
	if inbound != nil {
		out = append(out, inbound)
	}
	doc["inbounds"] = out
}

// appendCDNUser adds a newly provisioned recipient to ws-cdn-in when
// the door is open. No-op when it is closed. Call it from
// addUserToSingboxFor after the vless rows are written.
func appendCDNUser(doc map[string]any, c userCreds) {
	in := findInboundByTag(doc, tagCDN)
	if in == nil || c.VLESSUUID == "" || c.Name == "" {
		return
	}
	users := asSlice(in["users"])
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		if n, _ := u["name"].(string); n == c.Name {
			return
		}
	}
	in["users"] = append(users, map[string]any{"uuid": c.VLESSUUID, "name": c.Name})
}

// removeCDNUser takes a revoked recipient off ws-cdn-in and reports
// whether a row went. The last recipient leaving closes the door
// (sing-box refuses an inbound with no users); /cdn enable opens it
// again. Call it from removeUserFromSingbox.
func removeCDNUser(doc map[string]any, name string) bool {
	in := findInboundByTag(doc, tagCDN)
	if in == nil {
		return false
	}
	users := asSlice(in["users"])
	kept := make([]any, 0, len(users))
	removed := false
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		if n, _ := u["name"].(string); n == name {
			removed = true
			continue
		}
		kept = append(kept, raw)
	}
	if !removed {
		return false
	}
	if len(kept) == 0 {
		setCDNInbound(doc, nil)
		return true
	}
	in["users"] = kept
	return true
}

// cdnFile is one door file and what was there before, for rollback.
type cdnFile struct {
	path    string
	mode    os.FileMode
	body    []byte
	prev    []byte
	hadPrev bool
}

func writeCDNFiles(files []*cdnFile) (restore func(), err error) {
	if err := os.MkdirAll(cdnDir, 0o700); err != nil {
		return nil, err
	}
	var written []*cdnFile
	restore = func() {
		for _, f := range written {
			if f.hadPrev {
				_ = writeFileAtomic(f.path, f.prev, f.mode)
			} else {
				_ = os.Remove(f.path)
			}
		}
	}
	for _, f := range files {
		if b, err := os.ReadFile(f.path); err == nil {
			f.prev, f.hadPrev = b, true
		}
		if err := writeFileAtomic(f.path, f.body, f.mode); err != nil {
			restore()
			return nil, err
		}
		written = append(written, f)
	}
	return restore, nil
}

func writeFileAtomic(path string, body []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (s *server) handleCDN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req cdnReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	var (
		resp cdnResp
		code int
		err  error
	)
	switch req.Action {
	case "enable":
		resp, code, err = s.cdnEnable(req)
	case "disable":
		resp, code, err = s.cdnDisable()
	case "status":
		resp, code, err = s.cdnStatus()
	default:
		http.Error(w, `action must be "enable", "disable" or "status"`, http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	resp.Action = req.Action
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) cdnEnable(req cdnReq) (cdnResp, int, error) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	leaf, err := validateCDNMaterial(req, now())
	if err != nil {
		return cdnResp{}, http.StatusBadRequest, err
	}
	doc, err := loadSingboxDoc(s.singboxConfig)
	if err != nil {
		return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox config: %v", err)
	}
	users := cdnUsersFrom(doc)
	if len(users) == 0 {
		return cdnResp{}, http.StatusConflict, errors.New("no recipient on this relay yet: the door opens once there is someone to let in (sing-box refuses an inbound with no users)")
	}
	restoreFiles, err := writeCDNFiles([]*cdnFile{
		{path: cdnCertPath(), mode: 0o644, body: []byte(req.OriginCertPEM)},
		{path: cdnKeyPath(), mode: 0o600, body: []byte(req.OriginKeyPEM)},
		{path: cdnCAPath(), mode: 0o644, body: []byte(req.AOPCACertPEM)},
	})
	if err != nil {
		return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("write door files: %v", err)
	}
	setCDNInbound(doc, cdnInbound(req.WSPath, users))
	rollbackCfg, err := s.commitSingboxDoc(s.singboxConfig, doc)
	if err != nil {
		restoreFiles()
		return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox config: %v", err)
	}
	if err := s.applyReload(func() {
		rollbackCfg()
		restoreFiles()
	}); err != nil {
		return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox reload: %v", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	return cdnResp{
		Enabled:                true,
		Changed:                true,
		Port:                   cdnListenPort,
		WSPath:                 req.WSPath,
		Users:                  len(users),
		OriginCertSHA256:       hex.EncodeToString(sum[:]),
		OriginCertNotAfterUnix: leaf.NotAfter.Unix(),
	}, http.StatusOK, nil
}

func (s *server) cdnDisable() (cdnResp, int, error) {
	doc, err := loadSingboxDoc(s.singboxConfig)
	if err != nil {
		return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox config: %v", err)
	}
	changed := findInboundByTag(doc, tagCDN) != nil
	if changed {
		setCDNInbound(doc, nil)
		rollback, err := s.commitSingboxDoc(s.singboxConfig, doc)
		if err != nil {
			return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox config: %v", err)
		}
		if err := s.applyReload(rollback); err != nil {
			return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox reload: %v", err)
		}
	}
	// The inbound that read them is gone; the files go after it, never
	// before (a reload with the inbound and without the files fails).
	for _, p := range []string{cdnCertPath(), cdnKeyPath(), cdnCAPath()} {
		if err := os.Remove(p); err == nil {
			changed = true
		}
	}
	return cdnResp{Enabled: false, Changed: changed}, http.StatusOK, nil
}

func (s *server) cdnStatus() (cdnResp, int, error) {
	doc, err := loadSingboxDoc(s.singboxConfig)
	if err != nil {
		return cdnResp{}, http.StatusInternalServerError, fmt.Errorf("singbox config: %v", err)
	}
	in := findInboundByTag(doc, tagCDN)
	if in == nil {
		return cdnResp{}, http.StatusOK, nil
	}
	resp := cdnResp{Enabled: true, Users: len(asSlice(in["users"]))}
	if p, ok := numericPort(in["listen_port"]); ok {
		resp.Port = p
	}
	if t, _ := in["transport"].(map[string]any); t != nil {
		resp.WSPath, _ = t["path"].(string)
	}
	if b, err := os.ReadFile(cdnCertPath()); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				sum := sha256.Sum256(c.Raw)
				resp.OriginCertSHA256 = hex.EncodeToString(sum[:])
				resp.OriginCertNotAfterUnix = c.NotAfter.Unix()
			}
		}
	}
	return resp, http.StatusOK, nil
}
