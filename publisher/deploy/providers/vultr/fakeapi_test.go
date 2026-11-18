package vultr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixtures every test in this package shares.
const (
	testPlan   = "vc2-1c-1gb"
	testRegion = "fra"
)

// testNow is the deterministic clock. Ephemeral-rule expiry is
// asserted to the second; a real clock makes that flaky.
var testNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// fakeVultr is a Vultr API v2 server good enough to drive the real REST
// client through every path this adapter uses.
//
// THE TESTS GO THROUGH THE REAL CLIENT ON PURPOSE. The version of this
// package that shipped before Wave 6 tested a hand-written in-memory
// fake that implemented the client interface, so the only untested code
// was the code that actually talks to Vultr — and that code returned
// ErrLiveNotImplemented from every method while the tests passed. A
// fake HTTP server tests the request shapes, the response parsing, the
// pagination, the 404 mapping and the adapter logic in one pass.
type fakeVultr struct {
	mu  sync.Mutex
	srv *httptest.Server

	token string

	instances map[string]*wireInstance
	sshKeys   map[string]string // id -> name
	groups    map[string]*fakeGroup
	rips      map[string]*wireReservedIP
	seq       int

	// calls is an ordered log of "METHOD /path" — the only way to
	// assert that the firewall is created BEFORE the instance.
	calls []string

	// failOn returns a status code to answer with instead of the real
	// handler. The engine of every rollback test.
	failOn func(method, path string) (int, bool)

	// addressAfter delays main_ip allocation by N instance GETs, the
	// way Vultr really does.
	addressAfter int
	getCount     int

	// attachIsNoop makes the attach call answer 204 without moving
	// anything — the cloud saying yes before it is true, which is the
	// whole reason AssignFloatingIP reads the object back.
	attachIsNoop bool

	// last* capture what the adapter actually sent on the create
	// call, so the tests can assert the cloud-init, the resolved
	// os_id and the one-shot key rather than trusting the shape.
	lastUserData string
	lastOSID     int
	lastSSHKeys  []string
}

type fakeGroup struct {
	ID          string
	Description string
	Instances   int
	Rules       map[string]FirewallRuleInfo
	ruleSeq     int
}

func newFakeVultr(t *testing.T) *fakeVultr {
	t.Helper()
	f := &fakeVultr{
		token:     "test-token",
		instances: map[string]*wireInstance{},
		sshKeys:   map[string]string{},
		groups:    map[string]*fakeGroup{},
		rips:      map[string]*wireReservedIP{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVultr) client() vultrClient { return newLiveClientAt(f.srv.URL, f.token) }

func (f *fakeVultr) provider(t *testing.T) *Provider {
	t.Helper()
	p := New(f.client())
	// Deterministic clock: ephemeral-rule expiry assertions depend on
	// it, and a real clock makes the sweep test flaky by seconds.
	p.SetClock(func() time.Time { return testNow })
	return p
}

func (f *fakeVultr) nextID(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

func (f *fakeVultr) log(method, path string) {
	f.calls = append(f.calls, method+" "+path)
}

// sawBefore reports whether a call matching `first` was logged before
// any call matching `second`.
func (f *fakeVultr) sawBefore(first, second string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	fi, si := -1, -1
	for i, c := range f.calls {
		if fi < 0 && strings.HasPrefix(c, first) {
			fi = i
		}
		if si < 0 && strings.HasPrefix(c, second) {
			si = i
		}
	}
	return fi >= 0 && si >= 0 && fi < si
}

func (f *fakeVultr) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v2")
	if path == r.URL.Path {
		path = r.URL.Path // tests point the client straight at the root
	}
	f.log(r.Method, path)

	if f.failOn != nil {
		if code, ok := f.failOn(r.Method, path); ok {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "injected failure"})
			return
		}
	}

	seg := strings.Split(strings.Trim(path, "/"), "/")
	switch seg[0] {
	case "instances":
		f.handleInstances(w, r, seg)
	case "os":
		f.writeJSON(w, map[string]any{
			"os": []map[string]any{
				{"id": 1743, "name": "Ubuntu 22.04 LTS x64", "arch": "x64"},
				{"id": 2284, "name": imageName, "arch": "x64"},
			},
			"meta": emptyMeta(),
		})
	case "plans":
		f.writeJSON(w, map[string]any{
			"plans": []map[string]any{
				{"id": testPlan, "vcpu_count": 1, "ram": 1024, "disk": 25,
					"monthly_cost": 5.0, "hourly_cost": 0.007, "type": "vc2",
					"locations": []string{"fra", "ams"}},
				{"id": "vc2-2c-4gb", "vcpu_count": 2, "ram": 4096, "disk": 80,
					"monthly_cost": 20.0, "type": "vc2", "locations": []string{"ewr"}},
			},
			"meta": emptyMeta(),
		})
	case "ssh-keys":
		f.handleSSHKeys(w, r, seg)
	case "firewalls":
		f.handleFirewalls(w, r, seg)
	case "reserved-ips":
		f.handleReservedIPs(w, r, seg)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func emptyMeta() map[string]any {
	return map[string]any{"total": 1, "links": map[string]string{"next": "", "prev": ""}}
}

func (f *fakeVultr) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeVultr) handleInstances(w http.ResponseWriter, r *http.Request, seg []string) {
	switch {
	case r.Method == http.MethodPost && len(seg) == 1:
		var body struct {
			Region          string   `json:"region"`
			Plan            string   `json:"plan"`
			OSID            int      `json:"os_id"`
			Label           string   `json:"label"`
			Hostname        string   `json:"hostname"`
			UserData        string   `json:"user_data"`
			SSHKeyID        []string `json:"sshkey_id"`
			Tags            []string `json:"tags"`
			FirewallGroupID string   `json:"firewall_group_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := f.nextID("inst")
		inst := &wireInstance{
			ID: id, Label: body.Label, Hostname: body.Hostname,
			Status: "active", ServerStatus: "ok", Plan: body.Plan, Region: body.Region,
			MainIP: "78.141.10.5", V6MainIP: "2001:db8::5",
			Tags: body.Tags, FirewallGroupID: body.FirewallGroupID,
		}
		if f.addressAfter > 0 {
			inst.MainIP = "0.0.0.0"
		}
		f.instances[id] = inst
		f.lastUserData = body.UserData
		f.lastOSID = body.OSID
		f.lastSSHKeys = body.SSHKeyID
		if g := f.groups[body.FirewallGroupID]; g != nil {
			g.Instances++
		}
		f.writeJSON(w, map[string]any{"instance": inst})
	case r.Method == http.MethodGet && len(seg) == 1:
		label := r.URL.Query().Get("label")
		out := []*wireInstance{}
		for _, inst := range f.instances {
			if label != "" && inst.Label != label {
				continue
			}
			out = append(out, inst)
		}
		f.writeJSON(w, map[string]any{"instances": out, "meta": emptyMeta()})
	case r.Method == http.MethodGet && len(seg) == 2:
		inst, ok := f.instances[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if inst.MainIP == "0.0.0.0" {
			f.getCount++
			if f.getCount >= f.addressAfter {
				inst.MainIP = "78.141.10.5"
			}
		}
		f.writeJSON(w, map[string]any{"instance": inst})
	case r.Method == http.MethodDelete && len(seg) == 2:
		inst, ok := f.instances[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if g := f.groups[inst.FirewallGroupID]; g != nil && g.Instances > 0 {
			g.Instances--
		}
		delete(f.instances, seg[1])
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeVultr) handleSSHKeys(w http.ResponseWriter, r *http.Request, seg []string) {
	switch {
	case r.Method == http.MethodPost && len(seg) == 1:
		var body struct {
			Name   string `json:"name"`
			SSHKey string `json:"ssh_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := f.nextID("key")
		f.sshKeys[id] = body.Name
		f.writeJSON(w, map[string]any{"ssh_key": map[string]string{"id": id, "name": body.Name}})
	case r.Method == http.MethodGet && len(seg) == 1:
		out := []map[string]string{}
		for id, name := range f.sshKeys {
			out = append(out, map[string]string{"id": id, "name": name})
		}
		f.writeJSON(w, map[string]any{"ssh_keys": out, "meta": emptyMeta()})
	case r.Method == http.MethodDelete && len(seg) == 2:
		if _, ok := f.sshKeys[seg[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.sshKeys, seg[1])
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeVultr) handleFirewalls(w http.ResponseWriter, r *http.Request, seg []string) {
	switch {
	case r.Method == http.MethodPost && len(seg) == 1:
		var body struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := f.nextID("fw")
		f.groups[id] = &fakeGroup{ID: id, Description: body.Description, Rules: map[string]FirewallRuleInfo{}}
		f.writeJSON(w, map[string]any{"firewall_group": map[string]string{"id": id, "description": body.Description}})
	case r.Method == http.MethodGet && len(seg) == 1:
		out := []map[string]any{}
		for _, g := range f.groups {
			out = append(out, map[string]any{
				"id": g.ID, "description": g.Description,
				"instance_count": g.Instances, "rule_count": len(g.Rules),
			})
		}
		f.writeJSON(w, map[string]any{"firewall_groups": out, "meta": emptyMeta()})
	case r.Method == http.MethodDelete && len(seg) == 2:
		if _, ok := f.groups[seg[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.groups, seg[1])
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && len(seg) == 3 && seg[2] == "rules":
		g, ok := f.groups[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			IPType     string `json:"ip_type"`
			Protocol   string `json:"protocol"`
			Subnet     string `json:"subnet"`
			SubnetSize int    `json:"subnet_size"`
			Port       string `json:"port"`
			Notes      string `json:"notes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.ruleSeq++
		id := strconv.Itoa(g.ruleSeq)
		g.Rules[id] = FirewallRuleInfo{
			ID: id, IPType: body.IPType, Protocol: body.Protocol,
			Subnet: body.Subnet, SubnetSize: body.SubnetSize, Port: body.Port, Notes: body.Notes,
		}
		f.writeJSON(w, map[string]any{"firewall_rule": map[string]any{"id": g.ruleSeq}})
	case r.Method == http.MethodGet && len(seg) == 3 && seg[2] == "rules":
		g, ok := f.groups[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		out := []map[string]any{}
		for _, rl := range g.Rules {
			out = append(out, map[string]any{
				"id": rl.ID, "ip_type": rl.IPType, "protocol": rl.Protocol,
				"subnet": rl.Subnet, "subnet_size": rl.SubnetSize, "port": rl.Port, "notes": rl.Notes,
			})
		}
		f.writeJSON(w, map[string]any{"firewall_rules": out, "meta": emptyMeta()})
	case r.Method == http.MethodDelete && len(seg) == 4 && seg[2] == "rules":
		g, ok := f.groups[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := g.Rules[seg[3]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(g.Rules, seg[3])
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeVultr) handleReservedIPs(w http.ResponseWriter, r *http.Request, seg []string) {
	switch {
	case r.Method == http.MethodPost && len(seg) == 1:
		var body struct {
			Region string `json:"region"`
			IPType string `json:"ip_type"`
			Label  string `json:"label"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := f.nextID("rip")
		rip := &wireReservedIP{
			ID: id, Region: body.Region, IPType: body.IPType,
			Subnet: "95.179.20.7", SubnetSize: 32, Label: body.Label,
		}
		f.rips[id] = rip
		f.writeJSON(w, map[string]any{"reserved_ip": rip})
	case r.Method == http.MethodGet && len(seg) == 1:
		out := []*wireReservedIP{}
		for _, rip := range f.rips {
			out = append(out, rip)
		}
		f.writeJSON(w, map[string]any{"reserved_ips": out, "meta": emptyMeta()})
	case r.Method == http.MethodGet && len(seg) == 2:
		rip, ok := f.rips[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.writeJSON(w, map[string]any{"reserved_ip": rip})
	case r.Method == http.MethodPost && len(seg) == 3 && seg[2] == "attach":
		rip, ok := f.rips[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			InstanceID string `json:"instance_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !f.attachIsNoop {
			rip.InstanceID = body.InstanceID
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && len(seg) == 3 && seg[2] == "detach":
		rip, ok := f.rips[seg[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rip.InstanceID = ""
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && len(seg) == 2:
		if _, ok := f.rips[seg[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.rips, seg[1])
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
