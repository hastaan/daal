package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud/schema"
)

// fakecloud is "the outside world's infrastructure" for one run:
//
//   - api.hetzner.cloud — enough of the Hetzner Cloud REST API for the
//     REAL hcloud-go client inside the REAL daal-deploy to provision,
//     firewall, and decommission a server. Creating a server BOOTS one:
//     the user-data is handed, byte for byte, to box/init.py inside the
//     slot's network namespace.
//   - github.com — the release mirror the box's verifier shim downloads
//     its pinned artefacts from.
//   - the cloud firewall — rules set through the API are ENFORCED, as an
//     nft table in front of the box (table inet wb_cloudfw).
//
// It deliberately knows nothing about Daal's logic. An endpoint the
// product calls that is not modelled returns 501 and is logged in
// cloud-requests.jsonl, so the gap is loud.

type slot struct {
	NS   string // network namespace that plays this server's NIC
	IPv4 string // the public address the cloud reports for it
	used int64  // server id occupying it, 0 = free
}

type server struct {
	schema.Server
	slot     *slot
	init     *exec.Cmd
	boxDir   string
	userData string
}

type cloud struct {
	mu        sync.Mutex
	p         Paths
	token     string
	artifacts string
	timescale string
	overrides []string
	nextID    int64
	servers   map[int64]*server
	sshKeys   map[int64]*schema.SSHKey
	firewalls map[int64]*schema.Firewall
	fips      map[int64]*floatingIP // fakecloud_fip.go
	slots     []*slot
	reqLog    *os.File
}

func cmdFakeCloud(args []string) int {
	fs := flag.NewFlagSet("fakecloud", flag.ExitOnError)
	repo := fs.String("repo", "", "")
	rig := fs.String("rig", "", "")
	run := fs.String("run-dir", "", "")
	bin := fs.String("bin", "", "")
	tokenFile := fs.String("token-file", "", "API token the cloud accepts")
	artifacts := fs.String("artifacts", "", "directory holding the release artefacts the mirror serves")
	timescale := fs.String("timescale", "20", "divide cloud-init's provisioning-window sleep by this")
	override := fs.String("override", "", "comma list name=path: replace an installed artefact with a tree build (UNPINNED)")
	_ = fs.Parse(args)

	tok, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatalf("fakecloud: %v", err)
	}
	c := &cloud{
		p:         Paths{Repo: *repo, Rig: *rig, Bin: *bin, Run: *run},
		token:     strings.TrimSpace(string(tok)),
		artifacts: *artifacts,
		timescale: *timescale,
		nextID:    1000,
		servers:   map[int64]*server{},
		sshKeys:   map[int64]*schema.SSHKey{},
		firewalls: map[int64]*schema.Firewall{},
		fips:      map[int64]*floatingIP{},
		slots:     []*slot{{NS: NSRelay1, IPv4: Relay1IP}},
	}
	if *override != "" {
		c.overrides = strings.Split(*override, ",")
	}
	c.reqLog, err = os.OpenFile(filepath.Join(*run, "cloud-requests.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("fakecloud: %v", err)
	}

	mux := http.NewServeMux()
	api := func(pattern string, h func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "api.hetzner.cloud" {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("Authorization") != "Bearer "+c.token {
				apiError(w, 401, "unauthorized", "unable to authenticate")
				return
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			h(w, r)
		})
	}
	api("GET /v1/servers", c.serverList)
	api("POST /v1/servers", c.serverCreate)
	api("GET /v1/servers/{id}", c.serverGet)
	api("DELETE /v1/servers/{id}", c.serverDelete)
	api("POST /v1/ssh_keys", c.sshKeyCreate)
	api("GET /v1/ssh_keys", c.sshKeyList)
	api("DELETE /v1/ssh_keys/{id}", c.sshKeyDelete)
	api("GET /v1/firewalls", c.firewallList)
	api("POST /v1/firewalls", c.firewallCreate)
	api("GET /v1/firewalls/{id}", c.firewallGet)
	api("DELETE /v1/firewalls/{id}", c.firewallDelete)
	api("POST /v1/firewalls/{id}/actions/set_rules", c.firewallSetRules)
	api("POST /v1/firewalls/{id}/actions/apply_to_resources", c.firewallApply)
	api("POST /v1/firewalls/{id}/actions/remove_from_resources", c.firewallRemove)
	c.registerFloatingIPs(api)
	api("GET /v1/actions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		writeJSON(w, 200, schema.ActionGetResponse{Action: doneAction(id, "noop")})
	})
	// The release mirror: /<owner>/<repo>/releases/download/<tag>/<file>.
	mux.HandleFunc("GET /{owner}/{repo}/releases/download/{tag}/{file}", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "github.com" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(c.artifacts, filepath.Base(r.PathValue("file"))))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, 501, "not_modelled", "worldbox fakecloud does not model "+r.Method+" "+r.URL.Path)
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		t0 := time.Now()
		mux.ServeHTTP(rec, r)
		line, _ := json.Marshal(map[string]any{
			"ts": t0.UTC().Format(time.RFC3339Nano), "host": r.Host, "method": r.Method,
			"path": r.URL.RequestURI(), "status": rec.status, "ms": time.Since(t0).Milliseconds(),
			"from": r.RemoteAddr,
		})
		c.reqLog.Write(append(line, '\n'))
	})

	// The provider routes no pool address anywhere until one is assigned.
	if err := c.routeFloatingIPs(); err != nil {
		log.Fatalf("fakecloud: %v", err)
	}

	errc := make(chan error, 2)
	for _, ip := range []string{CloudIP, MirrorIP} {
		srv := &http.Server{Addr: net.JoinHostPort(ip, "443"), Handler: handler}
		go func() {
			errc <- srv.ListenAndServeTLS(filepath.Join(*run, "lab-server.pem"), filepath.Join(*run, "lab-server.key"))
		}()
	}
	fmt.Println("fakecloud: listening")
	log.Printf("fakecloud: %v", <-errc)
	return 1
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, schema.ErrorResponse{Error: schema.Error{Code: code, Message: msg}})
}

func doneAction(id int64, command string) schema.Action {
	now := time.Now().UTC()
	return schema.Action{ID: id, Status: "success", Command: command, Progress: 100, Started: now, Finished: &now}
}

func (c *cloud) id() int64 { c.nextID++; return c.nextID }

func onePage(n int) schema.Meta {
	return schema.Meta{Pagination: &schema.MetaPagination{Page: 1, PerPage: 50, LastPage: 1, TotalEntries: n}}
}

func readBody(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// ---- servers ---------------------------------------------------------

func (c *cloud) serverList(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	out := []schema.Server{}
	for _, s := range c.servers {
		if name == "" || s.Name == name {
			out = append(out, c.view(s))
		}
	}
	writeJSON(w, 200, schema.ServerListResponse{Servers: out})
}

// view returns the server with its firewall attachments filled in.
func (c *cloud) view(s *server) schema.Server {
	v := s.Server
	v.PublicNet.Firewalls = []schema.ServerFirewall{}
	for _, fw := range c.firewalls {
		for _, res := range fw.AppliedTo {
			if res.Server != nil && res.Server.ID == s.ID {
				v.PublicNet.Firewalls = append(v.PublicNet.Firewalls, schema.ServerFirewall{ID: fw.ID, Status: "applied"})
			}
		}
	}
	return v
}

func (c *cloud) serverGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s, ok := c.servers[id]
	if !ok {
		apiError(w, 404, "not_found", "server not found")
		return
	}
	writeJSON(w, 200, schema.ServerGetResponse{Server: c.view(s)})
}

func (c *cloud) serverCreate(w http.ResponseWriter, r *http.Request) {
	var req schema.ServerCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
		return
	}
	for _, s := range c.servers {
		if s.Name == req.Name {
			apiError(w, 409, "uniqueness_error", "server name is already used")
			return
		}
	}
	var sl *slot
	for _, cand := range c.slots {
		if cand.used == 0 {
			sl = cand
			break
		}
	}
	if sl == nil {
		apiError(w, 412, "resource_unavailable", "worldbox: no free server slot (this world has "+strconv.Itoa(len(c.slots))+")")
		return
	}
	id := c.id()
	loc := schema.Location{ID: 1, Name: req.Location, Country: "DE", City: "lab", NetworkZone: "eu-central"}
	s := &server{slot: sl, userData: req.UserData, boxDir: c.p.Box(strconv.FormatInt(id, 10))}
	s.Server = schema.Server{
		ID: id, Name: req.Name, Status: "running", Created: time.Now().UTC(),
		PublicNet: schema.ServerPublicNet{
			IPv4:        schema.ServerPublicNetIPv4{ID: id, IP: sl.IPv4},
			FloatingIPs: []int64{},
		},
		ServerType: schema.ServerType{ID: 1, Name: req.ServerType.Name},
		Location:   loc,
		Datacenter: &schema.Datacenter{ID: 1, Name: req.Location + "-dc1", Location: loc},
		Labels:     map[string]string{},
	}
	if req.Labels != nil {
		s.Labels = *req.Labels
	}
	if err := c.boot(s); err != nil {
		// A real cloud returns the server and lets cloud-init fail in
		// private; the operator learns of it through the SSH log
		// observer, which the lab has no sshd for. Failing the create
		// call with the box's own log is the honest fast equivalent.
		c.destroy(s)
		apiError(w, 500, "server_error", "worldbox: box failed first boot: "+err.Error())
		return
	}
	sl.used = id
	c.servers[id] = s
	writeJSON(w, 201, schema.ServerCreateResponse{Server: c.view(s), Action: doneAction(c.id(), "create_server"), NextActions: []schema.Action{}})
}

func (c *cloud) serverDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s, ok := c.servers[id]
	if !ok {
		apiError(w, 404, "not_found", "server not found")
		return
	}
	c.destroy(s)
	s.slot.used = 0
	delete(c.servers, id)
	// Hetzner drops a deleted server out of every firewall's applied_to.
	for _, fw := range c.firewalls {
		kept := fw.AppliedTo[:0]
		for _, res := range fw.AppliedTo {
			if res.Server == nil || res.Server.ID != id {
				kept = append(kept, res)
			}
		}
		fw.AppliedTo = kept
	}
	writeJSON(w, 200, schema.ServerDeleteResponse{Action: doneAction(c.id(), "delete_server")})
}

// boot runs first boot for a server and returns once the box has reached
// its provisioning window (services enabled), or failed.
func (c *cloud) boot(s *server) error {
	state := filepath.Join(s.boxDir, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		return err
	}
	ud := filepath.Join(s.boxDir, "user-data.yaml")
	if err := os.WriteFile(ud, []byte(s.userData), 0o600); err != nil {
		return err
	}
	for _, o := range c.overrides {
		name, path, ok := strings.Cut(o, "=")
		if !ok {
			return fmt.Errorf("bad --override %q", o)
		}
		if err := os.MkdirAll(filepath.Join(state, "overrides"), 0o755); err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(state, "overrides", name), body, 0o755); err != nil {
			return err
		}
	}
	argv := inNS(s.slot.NS, "unshare", "--mount", "--pid", "--fork", "--kill-child", "--mount-proc", "--propagation", "private",
		"python3", c.p.BoxInit(), "--box-dir", s.boxDir, "--user-data", ud, "--shims", c.p.Shims(),
		"--ca", c.p.CA(), "--timescale", c.timescale, "--resolver", DNSIP)
	for _, h := range LabHosts() {
		argv = append(argv, "--hosts", h)
	}
	logf, err := os.OpenFile(filepath.Join(c.p.Logs(), "box-"+strconv.FormatInt(s.ID, 10)+"-init.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logf.Close()
	s.init = exec.Command(argv[0], argv[1:]...)
	s.init.Stdout, s.init.Stderr = logf, logf
	if err := s.init.Start(); err != nil {
		return err
	}
	dead := make(chan struct{})
	go func() { _ = s.init.Wait(); close(dead) }()
	gone := func() bool {
		select {
		case <-dead:
			return true
		default:
			return false
		}
	}

	exists := func(name string) bool { _, err := os.Stat(filepath.Join(state, name)); return err == nil }
	ok := waitFor(context.Background(), 90*time.Second, func() bool {
		return exists("provision-window-open") || exists("cloud-init.rc") || gone()
	})
	if exists("provision-window-open") {
		return nil
	}
	tail, _ := os.ReadFile(filepath.Join(s.boxDir, "rootfs", "var", "log", "cloud-init-output.log"))
	if len(tail) > 2000 {
		tail = tail[len(tail)-2000:]
	}
	if gone() {
		initLog, _ := os.ReadFile(logf.Name())
		return fmt.Errorf("box init died during first boot:\n%s\n%s", initLog, tail)
	}
	if !ok {
		return fmt.Errorf("first boot did not reach the provisioning window in 90s; cloud-init-output.log tail:\n%s", tail)
	}
	return fmt.Errorf("cloud-init exited before the provisioning window; cloud-init-output.log tail:\n%s", tail)
}

// destroy powers a box off: its init dies, the pid namespace takes every
// unit with it, and the NIC goes back to a blank state.
func (c *cloud) destroy(s *server) {
	if s.init != nil && s.init.Process != nil {
		_ = s.init.Process.Kill()
	}
	_, _ = sh(context.Background(), inNS(s.slot.NS, "nft", "flush", "ruleset")...)
	_ = c.routeFloatingIPs() // the provider's routing outlives any one server
}

// ---- ssh keys --------------------------------------------------------

func (c *cloud) sshKeyCreate(w http.ResponseWriter, r *http.Request) {
	var req schema.SSHKeyCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
		return
	}
	for _, k := range c.sshKeys {
		if k.Name == req.Name || k.PublicKey == req.PublicKey {
			apiError(w, 409, "uniqueness_error", "SSH key not unique")
			return
		}
	}
	k := &schema.SSHKey{ID: c.id(), Name: req.Name, PublicKey: req.PublicKey, Created: time.Now().UTC(), Labels: map[string]string{}}
	if req.Labels != nil {
		k.Labels = *req.Labels
	}
	c.sshKeys[k.ID] = k
	writeJSON(w, 201, schema.SSHKeyCreateResponse{SSHKey: *k})
}

func (c *cloud) sshKeyList(w http.ResponseWriter, r *http.Request) {
	out := []schema.SSHKey{}
	for _, k := range c.sshKeys {
		out = append(out, *k)
	}
	writeJSON(w, 200, schema.SSHKeyListResponse{SSHKeys: out})
}

func (c *cloud) sshKeyDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, ok := c.sshKeys[id]; !ok {
		apiError(w, 404, "not_found", "ssh key not found")
		return
	}
	delete(c.sshKeys, id)
	w.WriteHeader(204)
}

// ---- firewalls -------------------------------------------------------

func rulesFromRequest(in []schema.FirewallRuleRequest) []schema.FirewallRule {
	out := make([]schema.FirewallRule, 0, len(in))
	for _, r := range in {
		out = append(out, schema.FirewallRule{
			Direction: r.Direction, SourceIPs: r.SourceIPs, DestinationIPs: r.DestinationIPs,
			Protocol: r.Protocol, Port: r.Port, Description: r.Description,
		})
	}
	return out
}

func (c *cloud) firewallList(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	out := []schema.Firewall{}
	for _, f := range c.firewalls {
		if name == "" || f.Name == name {
			out = append(out, *f)
		}
	}
	writeJSON(w, 200, schema.FirewallListResponse{Firewalls: out})
}

func (c *cloud) firewallOr404(w http.ResponseWriter, r *http.Request) *schema.Firewall {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f, ok := c.firewalls[id]
	if !ok {
		apiError(w, 404, "not_found", "firewall not found")
		return nil
	}
	return f
}

func (c *cloud) firewallGet(w http.ResponseWriter, r *http.Request) {
	if f := c.firewallOr404(w, r); f != nil {
		writeJSON(w, 200, schema.FirewallGetResponse{Firewall: *f})
	}
}

func (c *cloud) firewallCreate(w http.ResponseWriter, r *http.Request) {
	var req schema.FirewallCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
		return
	}
	for _, f := range c.firewalls {
		if f.Name == req.Name {
			apiError(w, 409, "uniqueness_error", "firewall name is already used")
			return
		}
	}
	f := &schema.Firewall{ID: c.id(), Name: req.Name, Created: time.Now().UTC(), Labels: map[string]string{},
		Rules: rulesFromRequest(req.Rules), AppliedTo: []schema.FirewallResource{}}
	for _, res := range req.ApplyTo {
		if res.Server != nil {
			f.AppliedTo = append(f.AppliedTo, schema.FirewallResource{Type: "server", Server: &schema.FirewallResourceServer{ID: res.Server.ID}})
		}
	}
	c.firewalls[f.ID] = f
	if err := c.enforce(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 201, schema.FirewallCreateResponse{Firewall: *f, Actions: []schema.Action{doneAction(c.id(), "set_firewall_rules")}})
}

func (c *cloud) firewallDelete(w http.ResponseWriter, r *http.Request) {
	f := c.firewallOr404(w, r)
	if f == nil {
		return
	}
	if len(f.AppliedTo) > 0 {
		apiError(w, 422, "resource_in_use", "firewall is still applied to a resource")
		return
	}
	delete(c.firewalls, f.ID)
	w.WriteHeader(204)
}

func (c *cloud) firewallSetRules(w http.ResponseWriter, r *http.Request) {
	f := c.firewallOr404(w, r)
	if f == nil {
		return
	}
	var req schema.FirewallActionSetRulesRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
		return
	}
	f.Rules = rulesFromRequest(req.Rules)
	if err := c.enforce(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 201, schema.FirewallActionSetRulesResponse{Actions: []schema.Action{doneAction(c.id(), "set_firewall_rules")}})
}

func (c *cloud) firewallApply(w http.ResponseWriter, r *http.Request) {
	f := c.firewallOr404(w, r)
	if f == nil {
		return
	}
	var req schema.FirewallActionApplyToResourcesRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
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
	if err := c.enforce(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 201, schema.FirewallActionApplyToResourcesResponse{Actions: []schema.Action{doneAction(c.id(), "apply_firewall")}})
}

func (c *cloud) firewallRemove(w http.ResponseWriter, r *http.Request) {
	f := c.firewallOr404(w, r)
	if f == nil {
		return
	}
	var req schema.FirewallActionRemoveFromResourcesRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
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
	if err := c.enforce(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 201, schema.FirewallActionRemoveFromResourcesResponse{Actions: []schema.Action{doneAction(c.id(), "remove_firewall")}})
}

// enforce renders every server's attached firewalls into its namespace.
//
// Hetzner semantics: with at least one firewall applied, inbound traffic
// that matches no `in` rule is dropped; replies to the server's own
// outbound connections pass; outbound is unrestricted unless there are
// `out` rules (the product sets none, and none are modelled).
func (c *cloud) enforce() error {
	for _, s := range c.servers {
		if err := c.enforceServer(s); err != nil {
			return err
		}
	}
	return nil
}

func (c *cloud) enforceServer(s *server) error {
	var b strings.Builder
	b.WriteString("add table inet wb_cloudfw\ndelete table inet wb_cloudfw\n")
	var rules []schema.FirewallRule
	attached := false
	for _, f := range c.firewalls {
		for _, res := range f.AppliedTo {
			if res.Server != nil && res.Server.ID == s.ID {
				attached = true
				rules = append(rules, f.Rules...)
			}
		}
	}
	if attached {
		b.WriteString("table inet wb_cloudfw {\n  chain input { type filter hook input priority -10; policy drop;\n")
		b.WriteString("    ct state established,related accept\n    iif lo accept\n")
		for _, r := range rules {
			if r.Direction != "in" {
				return fmt.Errorf("worldbox: firewall rule direction %q is not modelled", r.Direction)
			}
			var v4, v6 []string
			for _, cidr := range r.SourceIPs {
				if strings.Contains(cidr, ":") {
					v6 = append(v6, cidr)
				} else {
					v4 = append(v4, cidr)
				}
			}
			match := ""
			switch r.Protocol {
			case "tcp", "udp":
				if r.Port == nil {
					return fmt.Errorf("worldbox: %s firewall rule without a port", r.Protocol)
				}
				match = r.Protocol + " dport " + *r.Port
			case "icmp":
				match = "meta l4proto { icmp, ipv6-icmp }"
			default:
				return fmt.Errorf("worldbox: firewall protocol %q is not modelled", r.Protocol)
			}
			if len(v4) > 0 {
				fmt.Fprintf(&b, "    ip saddr { %s } %s accept\n", strings.Join(v4, ", "), match)
			}
			if len(v6) > 0 {
				fmt.Fprintf(&b, "    ip6 saddr { %s } %s accept\n", strings.Join(v6, ", "), match)
			}
		}
		b.WriteString("  }\n}\n")
	}
	cmd := exec.Command("ip", "netns", "exec", s.slot.NS, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cloud firewall → nft: %v: %s\n%s", err, out, b.String())
	}
	_ = os.WriteFile(filepath.Join(s.boxDir, "state", "cloudfw.nft"), []byte(b.String()), 0o644)
	return nil
}

// CloudRequest is one line of cloud-requests.jsonl: every call the
// product made to the cloud API or the release mirror, in order. Checks
// read it to assert on what the product DID to the account.
type CloudRequest struct {
	TS     string `json:"ts"`
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	From   string `json:"from"`
}

func CloudRequests(p Paths) []CloudRequest {
	body, _ := os.ReadFile(filepath.Join(p.Run, "cloud-requests.jsonl"))
	var out []CloudRequest
	for _, line := range strings.Split(string(body), "\n") {
		var q CloudRequest
		if json.Unmarshal([]byte(line), &q) == nil && q.Method != "" {
			out = append(out, q)
		}
	}
	return out
}
