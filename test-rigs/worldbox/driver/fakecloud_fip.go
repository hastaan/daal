package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud/schema"
)

// Floating IPs — the cloud half of an L3 address move.
//
// What a real provider does and this models:
//
//   - reserve: an address from the provider's pool becomes the
//     account's (and bills). Here the pool is FloatingIPPool, a handful
//     of addresses on the relay's "public" segment.
//   - assign: the provider ROUTES the address to a server. Nothing on
//     the server changes — the guest OS does not answer on the address
//     until something configures it on an interface. That gap is the
//     whole reason daal-relay-mgmt has /bind-address, and it is modelled
//     faithfully: the lab never touches the box's interfaces.
//   - unassign / delete: the provider stops routing it there.
//
// "Routed to the server" is enforced, not assumed: every pool address
// that is NOT assigned to a server is dropped at that server's NIC
// (table inet wb_cloudfip, prerouting), so a box that keeps an address
// configured after the provider took it back stops receiving traffic for
// it, exactly as it would, and a box that configures an address the
// provider never routed to it gets nothing either.
//
// Not modelled: floating-IP protection, DNS PTR, IPv6, action locking
// (the real API locks an address while an action runs — the product
// waits for the unassign action for that reason; here every action is
// already "success").

// FloatingIPPool is the provider's free address pool, in issue order.
var FloatingIPPool = []string{"203.0.113.20", "203.0.113.21", "203.0.113.22"}

// RelayPublicAddrSet is an nft set expression naming every address a
// client may legitimately dial the relay on: the primary address and the
// whole floating-IP pool.
func RelayPublicAddrSet() string {
	return "{ " + strings.Join(append([]string{Relay1IP}, FloatingIPPool...), ", ") + " }"
}

type floatingIP struct {
	schema.FloatingIP
}

func (c *cloud) registerFloatingIPs(api func(pattern string, h func(w http.ResponseWriter, r *http.Request))) {
	api("GET /v1/floating_ips", c.fipList)
	api("POST /v1/floating_ips", c.fipCreate)
	api("GET /v1/floating_ips/{id}", c.fipGet)
	api("DELETE /v1/floating_ips/{id}", c.fipDelete)
	api("POST /v1/floating_ips/{id}/actions/assign", c.fipAssign)
	api("POST /v1/floating_ips/{id}/actions/unassign", c.fipUnassign)
}

func (c *cloud) fipOr404(w http.ResponseWriter, r *http.Request) *floatingIP {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f, ok := c.fips[id]
	if !ok {
		apiError(w, 404, "not_found", "floating IP not found")
		return nil
	}
	return f
}

func (c *cloud) fipList(w http.ResponseWriter, r *http.Request) {
	out := []schema.FloatingIP{}
	for _, f := range c.fips {
		out = append(out, f.FloatingIP)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, 200, schema.FloatingIPListResponse{FloatingIPs: out})
}

func (c *cloud) fipGet(w http.ResponseWriter, r *http.Request) {
	if f := c.fipOr404(w, r); f != nil {
		writeJSON(w, 200, schema.FloatingIPGetResponse{FloatingIP: f.FloatingIP})
	}
}

func (c *cloud) fipCreate(w http.ResponseWriter, r *http.Request) {
	var req schema.FloatingIPCreateRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
		return
	}
	if req.Type != "ipv4" {
		apiError(w, 422, "invalid_input", "worldbox: only ipv4 floating IPs are modelled")
		return
	}
	if req.HomeLocation == nil || *req.HomeLocation == "" {
		apiError(w, 422, "invalid_input", "home_location or server is required")
		return
	}
	name := ""
	if req.Name != nil {
		name = *req.Name
	}
	inUse := map[string]bool{}
	for _, f := range c.fips {
		inUse[f.IP] = true
		if name != "" && f.Name == name {
			apiError(w, 409, "uniqueness_error", "floating IP name is already used")
			return
		}
	}
	addr := ""
	for _, cand := range FloatingIPPool {
		if !inUse[cand] {
			addr = cand
			break
		}
	}
	if addr == "" {
		apiError(w, 412, "resource_limit_exceeded", "worldbox: the floating IP pool is exhausted ("+strconv.Itoa(len(FloatingIPPool))+" addresses)")
		return
	}
	loc := schema.Location{ID: 1, Name: *req.HomeLocation, Country: "DE", City: "lab", NetworkZone: "eu-central"}
	f := &floatingIP{schema.FloatingIP{
		ID: c.id(), Description: req.Description, Created: time.Now().UTC(), IP: addr, Type: "ipv4",
		DNSPtr: []schema.FloatingIPDNSPtr{}, HomeLocation: loc, Labels: map[string]string{}, Name: name,
	}}
	if req.Labels != nil {
		f.Labels = *req.Labels
	}
	c.fips[f.ID] = f
	if err := c.routeFloatingIPs(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	act := doneAction(c.id(), "create_floating_ip")
	writeJSON(w, 201, schema.FloatingIPCreateResponse{FloatingIP: f.FloatingIP, Action: &act})
}

func (c *cloud) fipDelete(w http.ResponseWriter, r *http.Request) {
	f := c.fipOr404(w, r)
	if f == nil {
		return
	}
	delete(c.fips, f.ID)
	if err := c.routeFloatingIPs(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	w.WriteHeader(204)
}

func (c *cloud) fipAssign(w http.ResponseWriter, r *http.Request) {
	f := c.fipOr404(w, r)
	if f == nil {
		return
	}
	var req schema.FloatingIPActionAssignRequest
	if err := readBody(r, &req); err != nil {
		apiError(w, 400, "json_error", err.Error())
		return
	}
	if _, ok := c.servers[req.Server]; !ok {
		apiError(w, 404, "not_found", "server not found")
		return
	}
	srv := req.Server
	f.Server = &srv
	if err := c.routeFloatingIPs(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 201, schema.FloatingIPActionAssignResponse{Action: doneAction(c.id(), "assign_floating_ip")})
}

func (c *cloud) fipUnassign(w http.ResponseWriter, r *http.Request) {
	f := c.fipOr404(w, r)
	if f == nil {
		return
	}
	f.Server = nil
	if err := c.routeFloatingIPs(); err != nil {
		apiError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 201, schema.FloatingIPActionUnassignResponse{Action: doneAction(c.id(), "unassign_floating_ip")})
}

// routeFloatingIPs renders "which pool addresses does the provider route
// to this server" into every slot's namespace. Runs at start-up too, so
// the pool is unrouted from the first packet.
func (c *cloud) routeFloatingIPs() error {
	for _, sl := range c.slots {
		var unrouted []string
		for _, addr := range FloatingIPPool {
			routedHere := false
			for _, f := range c.fips {
				if f.IP == addr && f.Server != nil && sl.used != 0 && *f.Server == sl.used {
					routedHere = true
				}
			}
			if !routedHere {
				unrouted = append(unrouted, addr)
			}
		}
		var b strings.Builder
		b.WriteString("add table inet wb_cloudfip\ndelete table inet wb_cloudfip\n")
		if len(unrouted) > 0 {
			fmt.Fprintf(&b, "table inet wb_cloudfip {\n  chain pre { type filter hook prerouting priority -300; policy accept;\n"+
				"    ip daddr { %s } drop\n  }\n}\n", strings.Join(unrouted, ", "))
		}
		cmd := exec.Command("ip", "netns", "exec", sl.NS, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(b.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("floating-IP routing → nft: %v: %s\n%s", err, out, b.String())
		}
		_ = os.WriteFile(filepath.Join(c.p.Run, "cloudfip-"+sl.NS+".nft"), []byte(b.String()), 0o644)
	}
	return nil
}
