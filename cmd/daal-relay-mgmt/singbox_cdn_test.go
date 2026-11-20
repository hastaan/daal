package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type cdnTestMaterial struct {
	certPEM, keyPEM, caPEM string
}

func makeCDNMaterial(t *testing.T, now time.Time) cdnTestMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "*.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "origin pull CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return cdnTestMaterial{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})),
		caPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
	}
}

func newCDNTestServer(t *testing.T) (*server, string, cdnTestMaterial) {
	t.Helper()
	srv, _, _, cfg := newTestServer(t)
	old := cdnDir
	cdnDir = filepath.Join(t.TempDir(), "cdn")
	t.Cleanup(func() { cdnDir = old })
	return srv, cfg, makeCDNMaterial(t, srv.now())
}

func cdnCall(t *testing.T, srv *server, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rr := httptest.NewRecorder()
	srv.handleCDN(rr, httptest.NewRequest(http.MethodPost, "/cdn", bytes.NewReader(b)))
	return rr
}

func enableReq(m cdnTestMaterial) cdnReq {
	return cdnReq{Action: "enable", Port: cdnListenPort, WSPath: "/0123456789abcdef0123456789abcdef",
		OriginCertPEM: m.certPEM, OriginKeyPEM: m.keyPEM, AOPCACertPEM: m.caPEM}
}

func TestCDNEnable_WritesTheDoor(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	rr := cdnCall(t, srv, enableReq(m))
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "PRIVATE KEY") || strings.Contains(rr.Body.String(), "BEGIN") {
		t.Fatal("the response echoes key or certificate material")
	}
	var resp cdnResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.Enabled || resp.Users != 2 || resp.Port != cdnListenPort || resp.OriginCertSHA256 == "" {
		t.Fatalf("resp = %+v", resp)
	}
	doc, err := loadSingboxDoc(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := findInboundByTag(doc, tagCDN)
	if in == nil {
		t.Fatal("no ws-cdn-in")
	}
	if p, _ := numericPort(in["listen_port"]); p != cdnListenPort {
		t.Errorf("listen_port = %v", in["listen_port"])
	}
	tl, _ := in["tls"].(map[string]any)
	if tl["client_authentication"] != "require-and-verify" {
		t.Errorf("client_authentication = %v", tl["client_authentication"])
	}
	if ccp, _ := tl["client_certificate_path"].([]any); len(ccp) != 1 || ccp[0] != cdnCAPath() {
		t.Errorf("client_certificate_path = %v", tl["client_certificate_path"])
	}
	if tl["certificate_path"] != cdnCertPath() || tl["key_path"] != cdnKeyPath() {
		t.Errorf("certificate paths = %v / %v", tl["certificate_path"], tl["key_path"])
	}
	tr, _ := in["transport"].(map[string]any)
	if tr["type"] != "ws" || tr["path"] != "/0123456789abcdef0123456789abcdef" {
		t.Errorf("transport = %v", tr)
	}
	for _, raw := range asSlice(in["users"]) {
		u := raw.(map[string]any)
		if _, has := u["flow"]; has {
			t.Errorf("REALITY flow copied onto the WebSocket door: %v", u)
		}
	}
	// ws-in is untouched: direct clients keep their pinned certificate.
	if ws := findInboundByTag(doc, tagWS); ws == nil || ws["tls"].(map[string]any)["client_authentication"] != nil {
		t.Error("ws-in was changed")
	}
	for p, mode := range map[string]os.FileMode{cdnCertPath(): 0o644, cdnKeyPath(): 0o600, cdnCAPath(): 0o644} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode %o, want %o", p, st.Mode().Perm(), mode)
		}
	}
	// Idempotent re-enable: still exactly one door.
	if rr := cdnCall(t, srv, enableReq(m)); rr.Code != http.StatusOK {
		t.Fatalf("re-enable: %d", rr.Code)
	}
	doc, _ = loadSingboxDoc(cfg)
	n := 0
	for _, raw := range asSlice(doc["inbounds"]) {
		if raw.(map[string]any)["tag"] == tagCDN {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d ws-cdn-in inbounds after re-enable", n)
	}
}

func TestCDNEnable_RefusesBadMaterial(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	before, _ := os.ReadFile(cfg)
	other := makeCDNMaterial(t, srv.now())
	cases := map[string]func(r *cdnReq){
		"port 443":       func(r *cdnReq) { r.Port = 443 },
		"port 8445":      func(r *cdnReq) { r.Port = 8445 },
		"bad path":       func(r *cdnReq) { r.WSPath = "no-slash" },
		"dotdot":         func(r *cdnReq) { r.WSPath = "/a/../b" },
		"key mismatch":   func(r *cdnReq) { r.OriginKeyPEM = other.keyPEM },
		"CA is a leaf":   func(r *cdnReq) { r.AOPCACertPEM = m.certPEM },
		"CA empty":       func(r *cdnReq) { r.AOPCACertPEM = "" },
		"CA holds a key": func(r *cdnReq) { r.AOPCACertPEM = m.caPEM + m.keyPEM },
	}
	for name, mutate := range cases {
		req := enableReq(m)
		mutate(&req)
		if rr := cdnCall(t, srv, req); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rr.Code)
		}
	}
	after, _ := os.ReadFile(cfg)
	if !bytes.Equal(before, after) {
		t.Error("a refused enable changed the config")
	}
	if _, err := os.Stat(cdnDir); err == nil {
		if ents, _ := os.ReadDir(cdnDir); len(ents) != 0 {
			t.Errorf("a refused enable wrote files: %v", ents)
		}
	}
}

func TestCDNEnable_UnknownFieldRefused(t *testing.T) {
	srv, _, _ := newCDNTestServer(t)
	rr := httptest.NewRecorder()
	srv.handleCDN(rr, httptest.NewRequest(http.MethodPost, "/cdn", strings.NewReader(`{"action":"enable","extra":1}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rr.Code)
	}
}

func TestCDNEnable_NoRecipientsYet(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	if err := os.WriteFile(cfg, []byte(`{"inbounds":[{"type":"vless","tag":"vless-in","users":[]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if rr := cdnCall(t, srv, enableReq(m)); rr.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rr.Code)
	}
}

// A failed reload puts the config AND the files back.
func TestCDNEnable_ReloadFailureRollsBack(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	before, _ := os.ReadFile(cfg)
	calls := 0
	srv.singboxControl = func(string) error {
		calls++
		if calls == 1 {
			return errors.New("reload failed")
		}
		return nil
	}
	rr := cdnCall(t, srv, enableReq(m))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rr.Code)
	}
	after, _ := os.ReadFile(cfg)
	if !bytes.Equal(before, after) {
		t.Error("config not restored after a failed reload")
	}
	for _, p := range []string{cdnCertPath(), cdnKeyPath(), cdnCAPath()} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left behind after a failed reload", p)
		}
	}
}

func TestCDNDisable_RemovesInboundThenFiles(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	if rr := cdnCall(t, srv, enableReq(m)); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	rr := cdnCall(t, srv, cdnReq{Action: "disable"})
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	doc, _ := loadSingboxDoc(cfg)
	if findInboundByTag(doc, tagCDN) != nil {
		t.Error("ws-cdn-in still present")
	}
	for _, p := range []string{cdnCertPath(), cdnKeyPath(), cdnCAPath()} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s still present", p)
		}
	}
	// Status says closed.
	var st cdnResp
	_ = json.Unmarshal(cdnCall(t, srv, cdnReq{Action: "status"}).Body.Bytes(), &st)
	if st.Enabled {
		t.Error("status says enabled after disable")
	}
}

func TestCDNUserHooks(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	if rr := cdnCall(t, srv, enableReq(m)); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	doc, _ := loadSingboxDoc(cfg)
	appendCDNUser(doc, userCreds{Name: "r3", VLESSUUID: "uuid-3"})
	appendCDNUser(doc, userCreds{Name: "r3", VLESSUUID: "uuid-3"})
	if n := len(asSlice(findInboundByTag(doc, tagCDN)["users"])); n != 3 {
		t.Fatalf("users after append = %d, want 3", n)
	}
	if !removeCDNUser(doc, "r1") || removeCDNUser(doc, "r1") {
		t.Fatal("remove r1: want true once, then false")
	}
	removeCDNUser(doc, "r2")
	if !removeCDNUser(doc, "r3") {
		t.Fatal("remove r3")
	}
	if findInboundByTag(doc, tagCDN) != nil {
		t.Fatal("the last recipient leaving must close the door (no empty inbound)")
	}
	// Closed door: appending is a no-op, not a new inbound.
	appendCDNUser(doc, userCreds{Name: "r4", VLESSUUID: "uuid-4"})
	if findInboundByTag(doc, tagCDN) != nil {
		t.Fatal("appendCDNUser opened a closed door")
	}
}

// Credential rotation already reaches the door: it rewrites every
// inbound of type vless, and the retired UUID is then nowhere.
func TestCDNDoorIsCoveredByCredentialRotation(t *testing.T) {
	srv, cfg, m := newCDNTestServer(t)
	if rr := cdnCall(t, srv, enableReq(m)); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	doc, _ := loadSingboxDoc(cfg)
	fresh, err := mintCreds("r1", srv.now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateRecipientCreds(doc, "r1", fresh); err != nil {
		t.Fatal(err)
	}
	for _, raw := range asSlice(findInboundByTag(doc, tagCDN)["users"]) {
		u := raw.(map[string]any)
		if u["name"] == "r1" && u["uuid"] != fresh.VLESSUUID {
			t.Fatalf("door kept r1's old uuid %v", u["uuid"])
		}
	}
	if docContainsString(doc, "uuid-1") {
		t.Fatal("retired uuid still in the config")
	}
}

// The wire shape must match publisher/deploy/cloudflare.DoorRequest.
func TestCDNRequestFieldNames(t *testing.T) {
	want := []string{"action", "aop_ca_pem", "origin_cert_pem", "origin_key_pem", "port", "ws_path"}
	var got []string
	rt := reflect.TypeOf(cdnReq{})
	for i := 0; i < rt.NumField(); i++ {
		got = append(got, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cdnReq json names = %v, want %v", got, want)
	}
}
