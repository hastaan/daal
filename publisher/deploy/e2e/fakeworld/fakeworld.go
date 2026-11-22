// Package fakeworld is a hosting company and its servers, in one
// process, for end-to-end tests that run the REAL daal-deploy binary
// built from this tree.
//
//   - The Hetzner Cloud API: the endpoints the product calls, over TLS
//     under a test CA, reached through a CONNECT proxy. The child is
//     pointed at it with HTTPS_PROXY and SSL_CERT_FILE and nothing
//     else; the production binary carries no test hook.
//   - Each server it "boots" is a box on its own loopback address
//     (127.x.y.z), built from the user-data the binary sent: the
//     provisioning health endpoint (the production health.NewHandler
//     with the health token found in that user-data), a management
//     service that checks every signed call with the production
//     mgmt.VerifyToken against the publisher key in that user-data, and
//     one data-plane listener per way it serves.
//
// Loopback is never proxied (net/http's ProxyFromEnvironment), so the
// binary reaches the boxes directly and the cloud only through the
// proxy. A box is re-imaged — new health token, new management
// certificate, empty roster — by a rebuild.
//
// It knows nothing about Daal's decisions. An endpoint that is not
// modelled answers 501 and is listed in State().Unmodelled, so a gap
// is loud.
package fakeworld

import (
	"bufio"
	"context"
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
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud/schema"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/health"
	"daal/publisher/deploy/mgmt"
	"daal/publisher/deploy/relayports"
)

// APIHost is the hosting company's API, the host the proxy tunnels to.
const APIHost = "api.hetzner.cloud"

// CloudflareHost publishes Cloudflare's edge ranges (/ips-v4, /ips-v6),
// the one other host the proxy reaches. It is modelled so a test can
// see whether, and how often, the binary contacted Cloudflare
// (State().CloudflareFetches): building a relay must not.
const CloudflareHost = "www.cloudflare.com"

// CloudflareRangesV4 / V6 are the lists the fake publishes.
var (
	CloudflareRangesV4 = []string{"173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13"}
	CloudflareRangesV6 = []string{"2400:cb00::/32"}
)

// World is one fake hosting account.
type World struct {
	Token string
	// Families the boxes serve (their /identity). TCP families only can
	// be answered here: a test process cannot bind below 1024, so a
	// family on 443 is listed but never answers.
	Families []string

	dir      string
	caFile   string
	apiLn    net.Listener
	proxyLn  net.Listener
	ctlLn    net.Listener
	apiCert  tls.Certificate
	mu       sync.Mutex
	nextID   int64
	servers  map[int64]*server
	sshKeys  map[int64]*schema.SSHKey
	fws      map[int64]*schema.Firewall
	fips     map[int64]*schema.FloatingIP
	ipsInUse map[string]bool

	holdHealth     bool
	failFIPDeletes int
	cfFetches      int
	created        int
	rebuilds       int
	setRules       int
	unmodelled     []string
	requests       []string
}

type server struct {
	schema.Server
	box      *box
	rebuilds int
}

// box is what runs on one server: re-created by every rebuild.
type box struct {
	ip          string
	healthToken string
	mgmtPub     ed25519.PublicKey
	mgmtPort    int
	mgmtFP      string // hex sha256 of the management cert DER
	dataPin     string // base64 sha256 of the data-plane SPKI
	dataCertPEM string
	ssKey       string // the box-wide shadowsocks-2022 key
	families    []string

	mu        sync.Mutex
	users     map[string]int
	gen       int
	writes    []string
	mgmtCalls []string
	lns       []net.Listener
	mgmtLn    net.Listener
	mgmtSrv   *http.Server
}

// New starts a world. dir holds the CA file the child trusts.
func New(dir, token string, families []string) (*World, error) {
	w := &World{
		Token: token, Families: families, dir: dir, nextID: 1000,
		servers: map[int64]*server{}, sshKeys: map[int64]*schema.SSHKey{},
		fws: map[int64]*schema.Firewall{}, fips: map[int64]*schema.FloatingIP{},
		ipsInUse: map[string]bool{},
	}
	caPEM, cert, err := issueAPICert()
	if err != nil {
		return nil, err
	}
	w.apiCert = cert
	w.caFile = filepath.Join(dir, "fakeworld-ca.pem")
	if err := os.WriteFile(w.caFile, caPEM, 0o644); err != nil {
		return nil, err
	}
	if w.apiLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	if w.proxyLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	if w.ctlLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	api := &http.Server{Handler: w.apiHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go func() { _ = api.ServeTLS(w.apiLn, "", "") }()
	go w.serveProxy()
	ctl := &http.Server{Handler: w.controlHandler()}
	go func() { _ = ctl.Serve(w.ctlLn) }()
	return w, nil
}

// Env is what the child needs to reach this world.
func (w *World) Env() []string {
	return []string{"HTTPS_PROXY=http://" + w.proxyLn.Addr().String(), "SSL_CERT_FILE=" + w.caFile}
}

// Endpoints is the one line cmd/fakeworld prints.
type Endpoints struct {
	Proxy   string `json:"proxy"`
	CAFile  string `json:"ca_file"`
	Control string `json:"control"`
}

func (w *World) Endpoints() Endpoints {
	return Endpoints{Proxy: "http://" + w.proxyLn.Addr().String(), CAFile: w.caFile, Control: "http://" + w.ctlLn.Addr().String()}
}

// Close stops every listener.
func (w *World) Close() {
	_ = w.apiLn.Close()
	_ = w.proxyLn.Close()
	_ = w.ctlLn.Close()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.servers {
		s.box.stop()
	}
}

// ---- the CONNECT proxy ----------------------------------------------

func (w *World) serveProxy() {
	for {
		c, err := w.proxyLn.Accept()
		if err != nil {
			return
		}
		go w.proxyConn(c)
	}
}

func (w *World) proxyConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect || (req.Host != APIHost+":443" && req.Host != CloudflareHost+":443") {
		w.note("proxy refused " + req.Method + " " + req.Host)
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", w.apiLn.Addr().String())
	if err != nil {
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (w *World) note(s string) {
	w.mu.Lock()
	w.unmodelled = append(w.unmodelled, s)
	w.mu.Unlock()
}

// ---- the cloud API --------------------------------------------------

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

func apiError(rw http.ResponseWriter, status int, code, msg string) {
	writeJSON(rw, status, schema.ErrorResponse{Error: schema.Error{Code: code, Message: msg}})
}

func doneAction(id int64, command string) schema.Action {
	now := time.Now().UTC()
	return schema.Action{ID: id, Status: "success", Command: command, Progress: 100, Started: now, Finished: &now, Resources: []schema.ActionResourceReference{}}
}

func (w *World) id() int64 { w.nextID++; return w.nextID }

func readBody(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func (w *World) apiHandler() http.Handler {
	mux := http.NewServeMux()
	api := func(pattern string, h func(rw http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(pattern, func(rw http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+w.Token {
				apiError(rw, 401, "unauthorized", "unable to authenticate")
				return
			}
			w.mu.Lock()
			defer w.mu.Unlock()
			w.requests = append(w.requests, r.Method+" "+r.URL.Path)
			h(rw, r)
		})
	}
	api("GET /v1/servers", w.serverList)
	api("POST /v1/servers", w.serverCreate)
	api("GET /v1/servers/{id}", w.serverGet)
	api("DELETE /v1/servers/{id}", w.serverDelete)
	api("POST /v1/servers/{id}/actions/rebuild", w.serverRebuild)
	api("GET /v1/server_types", w.serverTypes)
	api("POST /v1/ssh_keys", w.sshKeyCreate)
	api("GET /v1/ssh_keys", w.sshKeyList)
	api("DELETE /v1/ssh_keys/{id}", w.sshKeyDelete)
	api("GET /v1/firewalls", w.firewallList)
	api("POST /v1/firewalls", w.firewallCreate)
	api("GET /v1/firewalls/{id}", w.firewallGet)
	api("DELETE /v1/firewalls/{id}", w.firewallDelete)
	api("POST /v1/firewalls/{id}/actions/set_rules", w.firewallSetRules)
	api("POST /v1/firewalls/{id}/actions/apply_to_resources", w.firewallApply)
	api("POST /v1/firewalls/{id}/actions/remove_from_resources", w.firewallRemove)
	api("GET /v1/floating_ips", w.fipList)
	api("GET /v1/floating_ips/{id}", w.fipGet)
	api("DELETE /v1/floating_ips/{id}", w.fipDelete)
	api("POST /v1/floating_ips/{id}/actions/unassign", w.fipUnassign)
	api("GET /v1/actions/{id}", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, 200, schema.ActionGetResponse{Action: doneAction(pathID(r), "noop")})
	})
	api("GET /v1/actions", func(rw http.ResponseWriter, r *http.Request) {
		out := []schema.Action{}
		for _, s := range r.URL.Query()["id"] {
			id, _ := strconv.ParseInt(s, 10, 64)
			out = append(out, doneAction(id, "noop"))
		}
		writeJSON(rw, 200, schema.ActionListResponse{Actions: out})
	})
	for path, list := range map[string][]string{"/ips-v4": CloudflareRangesV4, "/ips-v6": CloudflareRangesV6} {
		list := list
		mux.HandleFunc("GET "+CloudflareHost+path, func(rw http.ResponseWriter, r *http.Request) {
			w.mu.Lock()
			w.cfFetches++
			w.requests = append(w.requests, r.Method+" "+CloudflareHost+r.URL.Path)
			w.mu.Unlock()
			rw.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(rw, strings.Join(list, "\n")+"\n")
		})
	}
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		w.note("not modelled: " + r.Method + " " + r.Host + r.URL.Path)
		apiError(rw, 501, "not_modelled", "fakeworld does not model "+r.Method+" "+r.URL.Path)
	})
	return mux
}

func (w *World) view(s *server) schema.Server {
	v := s.Server
	v.PublicNet.Firewalls = []schema.ServerFirewall{}
	for _, fw := range w.fws {
		for _, res := range fw.AppliedTo {
			if res.Server != nil && res.Server.ID == s.ID {
				v.PublicNet.Firewalls = append(v.PublicNet.Firewalls, schema.ServerFirewall{ID: fw.ID, Status: "applied"})
			}
		}
	}
	v.PublicNet.FloatingIPs = []int64{}
	for _, f := range w.fips {
		if f.Server != nil && *f.Server == s.ID {
			v.PublicNet.FloatingIPs = append(v.PublicNet.FloatingIPs, f.ID)
		}
	}
	return v
}

func (w *World) sortedServers() []*server {
	out := make([]*server, 0, len(w.servers))
	for _, s := range w.servers {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (w *World) serverList(rw http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	out := []schema.Server{}
	for _, s := range w.sortedServers() {
		if name == "" || s.Name == name {
			out = append(out, w.view(s))
		}
	}
	writeJSON(rw, 200, schema.ServerListResponse{Servers: out})
}

func (w *World) serverGet(rw http.ResponseWriter, r *http.Request) {
	s, ok := w.servers[pathID(r)]
	if !ok {
		apiError(rw, 404, "not_found", "server not found")
		return
	}
	writeJSON(rw, 200, schema.ServerGetResponse{Server: w.view(s)})
}

func (w *World) serverTypes(rw http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "cx22"
	}
	st := schema.ServerType{ID: 1, Name: name, Cores: 2, Memory: 4, Disk: 40, StorageType: "local", CPUType: "shared",
		Prices: []schema.PricingServerTypePrice{}}
	for _, loc := range []string{"fsn1", "nbg1", "hel1"} {
		st.Prices = append(st.Prices, schema.PricingServerTypePrice{Location: loc,
			PriceHourly:  schema.Price{Net: "0.0050", Gross: "0.0060"},
			PriceMonthly: schema.Price{Net: "3.29", Gross: "3.92"}})
	}
	writeJSON(rw, 200, schema.ServerTypeListResponse{ServerTypes: []schema.ServerType{st}})
}

func (w *World) freeIP() string {
	for {
		ip := fmt.Sprintf("127.%d.%d.%d", 1+mrand.IntN(250), mrand.IntN(256), 2+mrand.IntN(250))
		if w.ipsInUse[ip] {
			continue
		}
		// The provisioning health port is fixed: make sure nothing on
		// this machine already holds it on this address.
		if ln, err := net.Listen("tcp", net.JoinHostPort(ip, "9876")); err == nil {
			_ = ln.Close()
			w.ipsInUse[ip] = true
			return ip
		}
	}
}

func (w *World) serverCreate(rw http.ResponseWriter, r *http.Request) {
	var req schema.ServerCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	for _, s := range w.servers {
		if s.Name == req.Name {
			apiError(rw, 409, "uniqueness_error", "server name is already used")
			return
		}
	}
	ip := w.freeIP()
	b, err := w.boot(ip, req.UserData)
	if err != nil {
		apiError(rw, 422, "invalid_input", "fakeworld: "+err.Error())
		return
	}
	id := w.id()
	loc := schema.Location{ID: 1, Name: req.Location, Country: "DE", City: "lab", NetworkZone: "eu-central"}
	s := &server{box: b}
	s.Server = schema.Server{
		ID: id, Name: req.Name, Status: "running", Created: time.Now().UTC(),
		PublicNet:  schema.ServerPublicNet{IPv4: schema.ServerPublicNetIPv4{ID: id, IP: ip}, FloatingIPs: []int64{}},
		ServerType: schema.ServerType{ID: 1, Name: req.ServerType.Name}, Location: loc,
		Datacenter: &schema.Datacenter{ID: 1, Name: req.Location + "-dc1", Location: loc},
		Labels:     map[string]string{},
	}
	if req.Labels != nil {
		for k, v := range *req.Labels {
			s.Labels[k] = v
		}
	}
	w.servers[id] = s
	w.created++
	writeJSON(rw, 201, schema.ServerCreateResponse{Server: w.view(s), Action: doneAction(w.id(), "create_server"), NextActions: []schema.Action{}})
}

func (w *World) serverRebuild(rw http.ResponseWriter, r *http.Request) {
	s, ok := w.servers[pathID(r)]
	if !ok {
		apiError(rw, 404, "not_found", "server not found")
		return
	}
	var req schema.ServerActionRebuildRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	ud := ""
	if req.UserData != nil {
		ud = *req.UserData
	}
	s.box.stop()
	b, err := w.boot(s.PublicNet.IPv4.IP, ud)
	if err != nil {
		apiError(rw, 422, "invalid_input", "fakeworld: "+err.Error())
		return
	}
	s.box = b
	s.rebuilds++
	s.Status = "running"
	w.rebuilds++
	writeJSON(rw, 201, schema.ServerActionRebuildResponse{Action: doneAction(w.id(), "rebuild_server")})
}

func (w *World) serverDelete(rw http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	s, ok := w.servers[id]
	if !ok {
		apiError(rw, 404, "not_found", "server not found")
		return
	}
	s.box.stop()
	delete(w.servers, id)
	for _, fw := range w.fws {
		kept := fw.AppliedTo[:0]
		for _, res := range fw.AppliedTo {
			if res.Server == nil || res.Server.ID != id {
				kept = append(kept, res)
			}
		}
		fw.AppliedTo = kept
	}
	for _, f := range w.fips {
		if f.Server != nil && *f.Server == id {
			f.Server = nil
		}
	}
	writeJSON(rw, 200, schema.ServerDeleteResponse{Action: doneAction(w.id(), "delete_server")})
}

func (w *World) sshKeyCreate(rw http.ResponseWriter, r *http.Request) {
	var req schema.SSHKeyCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	for _, k := range w.sshKeys {
		if k.Name == req.Name || k.PublicKey == req.PublicKey {
			apiError(rw, 409, "uniqueness_error", "SSH key not unique")
			return
		}
	}
	k := &schema.SSHKey{ID: w.id(), Name: req.Name, PublicKey: req.PublicKey, Fingerprint: "00:00", Created: time.Now().UTC(), Labels: map[string]string{}}
	if req.Labels != nil {
		k.Labels = *req.Labels
	}
	w.sshKeys[k.ID] = k
	writeJSON(rw, 201, schema.SSHKeyCreateResponse{SSHKey: *k})
}

func (w *World) sshKeyList(rw http.ResponseWriter, r *http.Request) {
	out := []schema.SSHKey{}
	for _, k := range w.sshKeys {
		out = append(out, *k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(rw, 200, schema.SSHKeyListResponse{SSHKeys: out})
}

func (w *World) sshKeyDelete(rw http.ResponseWriter, r *http.Request) {
	if _, ok := w.sshKeys[pathID(r)]; !ok {
		apiError(rw, 404, "not_found", "ssh key not found")
		return
	}
	delete(w.sshKeys, pathID(r))
	rw.WriteHeader(204)
}

func rulesFromRequest(in []schema.FirewallRuleRequest) []schema.FirewallRule {
	out := make([]schema.FirewallRule, 0, len(in))
	for _, r := range in {
		out = append(out, schema.FirewallRule{Direction: r.Direction, SourceIPs: r.SourceIPs, DestinationIPs: r.DestinationIPs,
			Protocol: r.Protocol, Port: r.Port, Description: r.Description})
	}
	return out
}

func (w *World) firewallList(rw http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	out := []schema.Firewall{}
	for _, f := range w.fws {
		if name == "" || f.Name == name {
			out = append(out, *f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(rw, 200, schema.FirewallListResponse{Firewalls: out})
}

func (w *World) firewallOr404(rw http.ResponseWriter, r *http.Request) *schema.Firewall {
	f, ok := w.fws[pathID(r)]
	if !ok {
		apiError(rw, 404, "not_found", "firewall not found")
		return nil
	}
	return f
}

func (w *World) firewallGet(rw http.ResponseWriter, r *http.Request) {
	if f := w.firewallOr404(rw, r); f != nil {
		writeJSON(rw, 200, schema.FirewallGetResponse{Firewall: *f})
	}
}

func (w *World) firewallCreate(rw http.ResponseWriter, r *http.Request) {
	var req schema.FirewallCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	for _, f := range w.fws {
		if f.Name == req.Name {
			apiError(rw, 409, "uniqueness_error", "firewall name is already used")
			return
		}
	}
	f := &schema.Firewall{ID: w.id(), Name: req.Name, Created: time.Now().UTC(), Labels: map[string]string{},
		Rules: rulesFromRequest(req.Rules), AppliedTo: []schema.FirewallResource{}}
	if req.Labels != nil {
		f.Labels = *req.Labels
	}
	for _, res := range req.ApplyTo {
		if res.Server != nil {
			f.AppliedTo = append(f.AppliedTo, schema.FirewallResource{Type: "server", Server: &schema.FirewallResourceServer{ID: res.Server.ID}})
		}
	}
	w.fws[f.ID] = f
	writeJSON(rw, 201, schema.FirewallCreateResponse{Firewall: *f, Actions: []schema.Action{doneAction(w.id(), "set_firewall_rules")}})
}

func (w *World) firewallDelete(rw http.ResponseWriter, r *http.Request) {
	f := w.firewallOr404(rw, r)
	if f == nil {
		return
	}
	if len(f.AppliedTo) > 0 {
		apiError(rw, 422, "resource_in_use", "firewall is still applied to a resource")
		return
	}
	delete(w.fws, f.ID)
	rw.WriteHeader(204)
}

func (w *World) firewallSetRules(rw http.ResponseWriter, r *http.Request) {
	f := w.firewallOr404(rw, r)
	if f == nil {
		return
	}
	var req schema.FirewallActionSetRulesRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	f.Rules = rulesFromRequest(req.Rules)
	w.setRules++
	writeJSON(rw, 201, schema.FirewallActionSetRulesResponse{Actions: []schema.Action{doneAction(w.id(), "set_firewall_rules")}})
}

func (w *World) firewallApply(rw http.ResponseWriter, r *http.Request) {
	f := w.firewallOr404(rw, r)
	if f == nil {
		return
	}
	var req schema.FirewallActionApplyToResourcesRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	for _, res := range req.ApplyTo {
		if res.Server == nil {
			continue
		}
		dup := false
		for _, have := range f.AppliedTo {
			dup = dup || (have.Server != nil && have.Server.ID == res.Server.ID)
		}
		if !dup {
			f.AppliedTo = append(f.AppliedTo, schema.FirewallResource{Type: "server", Server: &schema.FirewallResourceServer{ID: res.Server.ID}})
		}
	}
	writeJSON(rw, 201, schema.FirewallActionApplyToResourcesResponse{Actions: []schema.Action{doneAction(w.id(), "apply_firewall")}})
}

func (w *World) firewallRemove(rw http.ResponseWriter, r *http.Request) {
	f := w.firewallOr404(rw, r)
	if f == nil {
		return
	}
	var req schema.FirewallActionRemoveFromResourcesRequest
	if err := readBody(r, &req); err != nil {
		apiError(rw, 400, "json_error", err.Error())
		return
	}
	kept := f.AppliedTo[:0]
	for _, have := range f.AppliedTo {
		drop := false
		for _, res := range req.RemoveFrom {
			drop = drop || (res.Server != nil && have.Server != nil && res.Server.ID == have.Server.ID)
		}
		if !drop {
			kept = append(kept, have)
		}
	}
	f.AppliedTo = kept
	writeJSON(rw, 201, schema.FirewallActionRemoveFromResourcesResponse{Actions: []schema.Action{doneAction(w.id(), "remove_firewall")}})
}

func (w *World) fipList(rw http.ResponseWriter, r *http.Request) {
	out := []schema.FloatingIP{}
	for _, f := range w.fips {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(rw, 200, schema.FloatingIPListResponse{FloatingIPs: out})
}

func (w *World) fipGet(rw http.ResponseWriter, r *http.Request) {
	f, ok := w.fips[pathID(r)]
	if !ok {
		apiError(rw, 404, "not_found", "floating IP not found")
		return
	}
	writeJSON(rw, 200, schema.FloatingIPGetResponse{FloatingIP: *f})
}

func (w *World) fipDelete(rw http.ResponseWriter, r *http.Request) {
	f, ok := w.fips[pathID(r)]
	if !ok {
		apiError(rw, 404, "not_found", "floating IP not found")
		return
	}
	if w.failFIPDeletes > 0 {
		w.failFIPDeletes--
		// A refusal hcloud-go does not retry on its own.
		apiError(rw, 423, "protected", "fakeworld: this address cannot be released right now")
		return
	}
	delete(w.fips, f.ID)
	rw.WriteHeader(204)
}

func (w *World) fipUnassign(rw http.ResponseWriter, r *http.Request) {
	f, ok := w.fips[pathID(r)]
	if !ok {
		apiError(rw, 404, "not_found", "floating IP not found")
		return
	}
	f.Server = nil
	writeJSON(rw, 201, schema.FloatingIPActionUnassignResponse{Action: doneAction(w.id(), "unassign_floating_ip")})
}

// ---- boxes ----------------------------------------------------------

var (
	reHealthToken = regexp.MustCompile(`"one_time_token":\s*"([^"]+)"`)
	reMgmtPub     = regexp.MustCompile(`(?s)path: /etc/daal/mgmt/pubkey.*?content: \|\s*\n\s*([0-9a-fA-F]{64})`)
	reMgmtPort    = regexp.MustCompile(`(?s)path: /etc/daal/mgmt/port.*?content: \|\s*\n\s*([0-9]+)`)
)

// boot builds a box from the user-data the product sent, the way
// cloud-init would: the three values it needs are read out of it, so
// a box built from a different user-data is a different box.
func (w *World) boot(ip, userData string) (*box, error) {
	m := reHealthToken.FindStringSubmatch(userData)
	if m == nil {
		return nil, errors.New("user-data carries no health token")
	}
	pm := reMgmtPub.FindStringSubmatch(userData)
	if pm == nil {
		return nil, errors.New("user-data carries no management public key")
	}
	pub, _ := hex.DecodeString(pm[1])
	portM := reMgmtPort.FindStringSubmatch(userData)
	if portM == nil {
		return nil, errors.New("user-data carries no management port")
	}
	port, _ := strconv.Atoi(portM[1])
	b := &box{ip: ip, healthToken: m[1], mgmtPub: ed25519.PublicKey(pub), mgmtPort: port, users: map[string]int{}, families: w.Families}

	mgmtCert, mgmtDER, err := selfSigned("daal-relay-mgmt")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(mgmtDER)
	b.mgmtFP = hex.EncodeToString(sum[:])
	dataCert, dataDER, err := selfSigned("relay data plane")
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(dataDER)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	b.dataPin = base64.StdEncoding.EncodeToString(spki[:])
	b.dataCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dataDER}))
	b.ssKey = randB64(16)

	hh, err := health.NewHandler(health.HandlerConfig{Token: b.healthToken, Probe: probe{w: w, b: b}})
	if err != nil {
		return nil, err
	}
	if err := b.listen("9876", func(ln net.Listener) { _ = (&http.Server{Handler: hh}).Serve(ln) }); err != nil {
		return nil, err
	}
	ml, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		b.stop()
		return nil, err
	}
	b.mgmtLn = ml
	b.mgmtSrv = &http.Server{Handler: b.mgmtHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{mgmtCert}, MinVersion: tls.VersionTLS13}}
	go func() { _ = b.mgmtSrv.ServeTLS(ml, "", "") }()
	for _, fam := range b.families {
		ep := relayports.For(fam)
		if ep.UDP || ep.Port < 1024 {
			continue
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{dataCert}}
		if fam == "shadowsocks" {
			cfg = nil
		}
		if err := b.listen(strconv.Itoa(ep.Port), func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if cfg != nil {
						tc := tls.Server(c, cfg)
						_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
						_ = tc.Handshake()
						return
					}
					_, _ = io.Copy(io.Discard, io.LimitReader(c, 1<<16))
				}()
			}
		}); err != nil {
			b.stop()
			return nil, err
		}
	}
	return b, nil
}

func (b *box) listen(port string, serve func(net.Listener)) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(b.ip, port))
	if err != nil {
		return err
	}
	b.lns = append(b.lns, ln)
	go serve(ln)
	return nil
}

func (b *box) stop() {
	for _, ln := range b.lns {
		_ = ln.Close()
	}
	b.lns = nil
	b.stopMgmt()
}

func (b *box) stopMgmt() {
	if b.mgmtSrv != nil {
		_ = b.mgmtSrv.Close()
		b.mgmtSrv = nil
	}
}

type probe struct {
	w *World
	b *box
}

func (p probe) Snapshot(context.Context) (health.Status, error) {
	p.w.mu.Lock()
	hold := p.w.holdHealth
	p.w.mu.Unlock()
	if hold {
		return health.Status{Healthy: false, DebugLog: "cloud-init still running"}, nil
	}
	return health.Status{Healthy: true, SingBoxRunning: true, DaalVersion: "fakeworld", MgmtTLSFingerprint: p.b.mgmtFP}, nil
}

func (b *box) mgmtHandler() http.Handler {
	m := http.NewServeMux()
	auth := func(h func(rw http.ResponseWriter, r *http.Request, body []byte)) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Daal-Mgmt-Token ")
			op, err := mgmt.VerifyToken(b.mgmtPub, b.mgmtFP, tok, r.Method, r.URL.Path, body)
			b.mu.Lock()
			b.mgmtCalls = append(b.mgmtCalls, r.Method+" "+r.URL.Path)
			b.mu.Unlock()
			if err != nil {
				http.Error(rw, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = op
			b.mu.Lock()
			defer b.mu.Unlock()
			h(rw, r, body)
		}
	}
	m.HandleFunc("GET /health", func(rw http.ResponseWriter, r *http.Request) { writeJSON(rw, 200, map[string]any{"ok": true}) })
	m.HandleFunc("GET /whoami", auth(func(rw http.ResponseWriter, r *http.Request, _ []byte) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		writeJSON(rw, 200, map[string]string{"ip": host})
	}))
	m.HandleFunc("GET /identity", auth(func(rw http.ResponseWriter, r *http.Request, _ []byte) {
		fams := []mgmt.RelayIdentityFamily{}
		for _, f := range b.families {
			fams = append(fams, mgmt.RelayIdentityFamily{Family: f, Port: relayports.For(f).Port, Listening: true})
		}
		writeJSON(rw, 200, mgmt.RelayIdentity{IdentityVersion: mgmt.IdentityVersion, TLSCertSHA256: b.dataPin,
			SSMethod: ssMethod, SSServerKeySHA256: bundle.SSServerKeyDigest(b.ssKey),
			Families: fams, PendingFamilies: []string{}, GeneratedAtUnix: time.Now().Unix()})
	}))
	m.HandleFunc("GET /users/list", auth(func(rw http.ResponseWriter, r *http.Request, _ []byte) {
		out := []mgmt.UserMeta{}
		for _, n := range b.userNames() {
			out = append(out, mgmt.UserMeta{Name: n, ProvisionedAtUnix: int64(b.users[n])})
		}
		writeJSON(rw, 200, map[string]any{"users": out})
	}))
	m.HandleFunc("POST /users/provision", auth(func(rw http.ResponseWriter, r *http.Request, body []byte) {
		var req struct{ Name string }
		_ = json.Unmarshal(body, &req)
		if _, ok := b.users[req.Name]; ok {
			http.Error(rw, fmt.Sprintf("user %q already exists", req.Name), http.StatusConflict)
			return
		}
		b.gen++
		b.users[req.Name] = b.gen
		b.writes = append(b.writes, "provision "+req.Name)
		writeJSON(rw, 200, b.creds(req.Name))
	}))
	m.HandleFunc("POST /users/revoke", auth(func(rw http.ResponseWriter, r *http.Request, body []byte) {
		var req struct{ Name string }
		_ = json.Unmarshal(body, &req)
		if _, ok := b.users[req.Name]; !ok {
			http.Error(rw, fmt.Sprintf("user %q not found", req.Name), http.StatusNotFound)
			return
		}
		delete(b.users, req.Name)
		b.writes = append(b.writes, "revoke "+req.Name)
		writeJSON(rw, 200, mgmt.RevokeResp{RevokedAtUnix: time.Now().Unix()})
	}))
	return m
}

func (b *box) userNames() []string {
	out := make([]string, 0, len(b.users))
	for n := range b.users {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func randHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

const ssMethod = "2022-blake3-aes-128-gcm"

func randB64(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func (b *box) creds(name string) mgmt.UserCreds {
	u := randHex(16)
	return mgmt.UserCreds{
		Name:              name,
		VLESSUUID:         u[0:8] + "-" + u[8:12] + "-4" + u[13:16] + "-8" + u[17:20] + "-" + u[20:32],
		RealityShortID:    randHex(4),
		Hy2Password:       randHex(12),
		NaivePassword:     randHex(12),
		WSPath:            "/" + randHex(6),
		ProvisionedAtUnix: time.Now().Unix(),
		TLSCertSHA256:     b.dataPin,
		TLSCertPEM:        b.dataCertPEM,
		AnyTLSPassword:    randHex(12),
		SSPassword:        b.ssKey + ":" + randB64(16),
		SSMethod:          ssMethod,
	}
}

// ---- the control side (what the test sees and changes) --------------

// ServerState is one server as the test sees it.
type ServerState struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	IP         string            `json:"ip"`
	Labels     map[string]string `json:"labels"`
	Rebuilds   int               `json:"rebuilds"`
	MgmtPort   int               `json:"mgmt_port"`
	MgmtFP     string            `json:"mgmt_fp"`
	Users      []string          `json:"users"`
	MgmtWrites []string          `json:"mgmt_writes"`
}

// Resource is an SSH key, firewall or floating IP.
type Resource struct {
	ID     int64             `json:"id"`
	Name   string            `json:"name"`
	IP     string            `json:"ip,omitempty"`
	Labels map[string]string `json:"labels"`
	Server int64             `json:"server,omitempty"`
}

// State is everything in the account.
type State struct {
	Servers        []ServerState `json:"servers"`
	SSHKeys        []Resource    `json:"ssh_keys"`
	Firewalls      []Resource    `json:"firewalls"`
	FloatingIPs    []Resource    `json:"floating_ips"`
	ServersCreated int           `json:"servers_created"`
	Rebuilds       int           `json:"rebuilds"`
	FirewallWrites int           `json:"firewall_writes"`
	// CloudflareFetches counts GETs of Cloudflare's published ranges.
	CloudflareFetches int      `json:"cloudflare_fetches"`
	Unmodelled        []string `json:"unmodelled"`
	Requests          []string `json:"requests"`
}

func (w *World) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := State{Servers: []ServerState{}, SSHKeys: []Resource{}, Firewalls: []Resource{}, FloatingIPs: []Resource{},
		ServersCreated: w.created, Rebuilds: w.rebuilds, FirewallWrites: w.setRules, CloudflareFetches: w.cfFetches,
		Unmodelled: append([]string{}, w.unmodelled...), Requests: append([]string{}, w.requests...)}
	for _, s := range w.sortedServers() {
		s.box.mu.Lock()
		st.Servers = append(st.Servers, ServerState{ID: s.ID, Name: s.Name, Status: s.Status, IP: s.PublicNet.IPv4.IP,
			Labels: s.Labels, Rebuilds: s.rebuilds, MgmtPort: s.box.mgmtPort, MgmtFP: s.box.mgmtFP, Users: s.box.userNames(),
			MgmtWrites: append([]string{}, s.box.writes...)})
		s.box.mu.Unlock()
	}
	for _, k := range w.sshKeys {
		st.SSHKeys = append(st.SSHKeys, Resource{ID: k.ID, Name: k.Name, Labels: k.Labels})
	}
	for _, f := range w.fws {
		r := Resource{ID: f.ID, Name: f.Name, Labels: f.Labels}
		for _, a := range f.AppliedTo {
			if a.Server != nil {
				r.Server = a.Server.ID
			}
		}
		st.Firewalls = append(st.Firewalls, r)
	}
	for _, f := range w.fips {
		r := Resource{ID: f.ID, Name: f.Name, IP: f.IP, Labels: f.Labels}
		if f.Server != nil {
			r.Server = *f.Server
		}
		st.FloatingIPs = append(st.FloatingIPs, r)
	}
	for _, l := range [][]Resource{st.SSHKeys, st.Firewalls, st.FloatingIPs} {
		sort.Slice(l, func(i, j int) bool { return l[i].ID < l[j].ID })
	}
	return st
}

// HoldHealth keeps every box short of healthy (cloud-init "still
// running"), as a slow boot does.
func (w *World) HoldHealth(on bool) { w.mu.Lock(); w.holdHealth = on; w.mu.Unlock() }

// FailFloatingIPDeletes makes the next n releases fail.
func (w *World) FailFloatingIPDeletes(n int) { w.mu.Lock(); w.failFIPDeletes = n; w.mu.Unlock() }

// SetServerStatus switches a server off ("off") or on ("running").
func (w *World) SetServerStatus(id int64, status string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.servers[id]
	if !ok {
		return errors.New("no such server")
	}
	s.Status = status
	return nil
}

// StopManagement makes a box's management port stop answering.
func (w *World) StopManagement(id int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.servers[id]
	if !ok {
		return errors.New("no such server")
	}
	s.box.stopMgmt()
	return nil
}

// ReplaceInConsole is what a person does at the hosting company's
// website: the server is deleted there and a new one is made by hand
// with the same name and labels, so it has a new id that no Daal record
// holds. The box moves to the new id (it is the same machine for the
// relay's purposes); firewalls and addresses that named the old id let
// go of it, as a real delete does. Returns the new id.
func (w *World) ReplaceInConsole(id int64) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.servers[id]
	if !ok {
		return 0, errors.New("no such server")
	}
	delete(w.servers, id)
	for _, fw := range w.fws {
		kept := fw.AppliedTo[:0]
		for _, res := range fw.AppliedTo {
			if res.Server == nil || res.Server.ID != id {
				kept = append(kept, res)
			}
		}
		fw.AppliedTo = kept
	}
	for _, f := range w.fips {
		if f.Server != nil && *f.Server == id {
			f.Server = nil
		}
	}
	nid := w.id()
	s.ID = nid
	s.PublicNet.IPv4.ID = nid
	w.servers[nid] = s
	w.created++
	return nid, nil
}

// ReserveAddress puts a floating IP in the account with these labels,
// as an earlier address change would have, assigned to server (0 =
// none).
func (w *World) ReserveAddress(labels map[string]string, server int64) Resource {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := w.id()
	ip := fmt.Sprintf("198.51.100.%d", 10+len(w.fips))
	loc := schema.Location{ID: 1, Name: "fsn1", Country: "DE", City: "lab", NetworkZone: "eu-central"}
	f := &schema.FloatingIP{ID: id, Name: fmt.Sprintf("fip-%d", id), IP: ip, Type: "ipv4", Created: time.Now().UTC(),
		HomeLocation: loc, Labels: labels, DNSPtr: []schema.FloatingIPDNSPtr{}}
	if server != 0 {
		f.Server = &server
	}
	w.fips[id] = f
	return Resource{ID: id, Name: f.Name, IP: ip, Labels: labels, Server: server}
}

func (w *World) controlHandler() http.Handler {
	m := http.NewServeMux()
	ok := func(rw http.ResponseWriter, err error) {
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		writeJSON(rw, 200, map[string]bool{"ok": true})
	}
	m.HandleFunc("GET /state", func(rw http.ResponseWriter, r *http.Request) { writeJSON(rw, 200, w.State()) })
	m.HandleFunc("POST /hold-health", func(rw http.ResponseWriter, r *http.Request) {
		w.HoldHealth(r.URL.Query().Get("on") == "1")
		ok(rw, nil)
	})
	m.HandleFunc("POST /fail-fip-deletes", func(rw http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		w.FailFloatingIPDeletes(n)
		ok(rw, nil)
	})
	m.HandleFunc("POST /servers/{id}/status", func(rw http.ResponseWriter, r *http.Request) {
		ok(rw, w.SetServerStatus(pathID(r), r.URL.Query().Get("s")))
	})
	m.HandleFunc("POST /servers/{id}/stop-management", func(rw http.ResponseWriter, r *http.Request) {
		ok(rw, w.StopManagement(pathID(r)))
	})
	m.HandleFunc("POST /servers/{id}/replace-in-console", func(rw http.ResponseWriter, r *http.Request) {
		nid, err := w.ReplaceInConsole(pathID(r))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		writeJSON(rw, 200, map[string]int64{"id": nid})
	})
	m.HandleFunc("POST /reserve-address", func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Labels map[string]string `json:"labels"`
			Server int64             `json:"server"`
		}
		if err := readBody(r, &req); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		writeJSON(rw, 200, w.ReserveAddress(req.Labels, req.Server))
	})
	return m
}

// ---- certificates ---------------------------------------------------

func issueAPICert() (caPEM []byte, leaf tls.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, leaf, err
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fakeworld test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, leaf, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, leaf, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: APIHost}, DNSNames: []string{APIHost, CloudflareHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, leaf, err
	}
	leaf = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf, nil
}

func selfSigned(cn string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, der, nil
}
