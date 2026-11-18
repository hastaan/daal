package vultr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// liveClient is the Vultr API v2 REST client.
//
// It is hand-written rather than govultr/v3-backed; doc.go argues that
// choice at length. The consequences are contained here: this is the
// only file in the package that speaks HTTP, it is the only file
// allowlisted in deploy/opsec_test.go, and every response field it
// reads is asserted against a fake server in live_client_test.go.
//
// THE TOKEN NEVER ENTERS AN ERROR. Vultr's API takes a bearer token
// with full account authority; a token in a log line is a compromised
// account. Errors here carry method, path and status, never headers,
// and never the request URL's raw form beyond the path this package
// itself constructed.
type liveClient struct {
	endpoint string
	http     *http.Client
}

// DefaultEndpoint is the production Vultr API base.
const DefaultEndpoint = "https://api.vultr.com/v2"

// tokenHolder keeps the bearer token out of struct state for as long as
// Go permits. It is a func so the wizard's keystore can re-fetch (and
// zeroise) rather than handing over a long-lived copy; NewLiveClient
// wraps a plain string for callers that have one.
type tokenHolder func() string

type liveClientWithToken struct {
	liveClient
	token tokenHolder
}

// NewLiveClient returns a vultrClient bound to a live Vultr account.
// The token is a Vultr API personal access token with write access;
// the wizard's keystore supplies it and this package never persists it.
func NewLiveClient(token string) vultrClient {
	return NewLiveClientFunc(func() string { return token })
}

// NewLiveClientFunc is NewLiveClient with a keystore-backed token
// source: the function is called once per request, so a revoked or
// rotated token takes effect without rebuilding the adapter.
func NewLiveClientFunc(src tokenHolder) vultrClient {
	return &liveClientWithToken{
		liveClient: liveClient{
			endpoint: DefaultEndpoint,
			// A bounded client, not http.DefaultClient: a provision
			// that hangs forever is a provision whose rollback never
			// runs.
			http: &http.Client{Timeout: 60 * time.Second},
		},
		token: src,
	}
}

// newLiveClientAt is the test seam: same client, different base URL.
func newLiveClientAt(endpoint, token string) *liveClientWithToken {
	return &liveClientWithToken{
		liveClient: liveClient{endpoint: strings.TrimRight(endpoint, "/"), http: &http.Client{Timeout: 10 * time.Second}},
		token:      func() string { return token },
	}
}

// do issues one request. body is marshalled when non-nil; into is
// decoded when non-nil. 404 becomes errNotFoundHTTP so callers can map
// it onto their own sentinel; 401 becomes errUnauthorized, which the
// wizard renders as "your token was revoked" rather than as a generic
// failure.
func (l *liveClientWithToken) do(ctx context.Context, method, path string, body, into any) error {
	token := ""
	if l.token != nil {
		token = l.token()
	}
	if token == "" {
		return errors.New("vultr: API token required")
	}
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vultr: marshal %s body: %w", path, err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, l.endpoint+path, rdr)
	if err != nil {
		return fmt.Errorf("vultr: build %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := l.http.Do(req)
	if err != nil {
		// url.Error stringifies the full URL, which is ours and
		// contains no secret — but unwrap to the cause anyway so the
		// message stays short and stable.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("vultr: %s %s: %w", method, path, ue.Err)
		}
		return fmt.Errorf("vultr: %s %s: %w", method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return errUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		return errNotFoundHTTP
	case resp.StatusCode >= 400:
		var msg struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(raw, &msg)
		detail := msg.Error
		if detail == "" {
			detail = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("vultr: %s %s -> %d: %s", method, path, resp.StatusCode, detail)
	}
	if into == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("vultr: decode %s %s: %w", method, path, err)
	}
	return nil
}

// errNotFoundHTTP is the transport-level 404. Every caller maps it onto
// the sentinel its own domain uses, because "absent" means something
// different for an instance than for a reserved IP.
var errNotFoundHTTP = errors.New("vultr: 404 not found")

// listPages walks Vultr's cursor pagination, calling fn with each page
// body. Vultr caps per_page at 500; an account with more relays than
// that still gets swept correctly, which matters because teardown
// finds orphans by listing.
func (l *liveClientWithToken) listPages(ctx context.Context, path string, fn func(raw json.RawMessage) error) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	cursor := ""
	for page := 0; page < 100; page++ {
		p := path + sep + "per_page=500"
		if cursor != "" {
			p += "&cursor=" + url.QueryEscape(cursor)
		}
		var envelope struct {
			Meta struct {
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
			} `json:"meta"`
		}
		var raw json.RawMessage
		var combined json.RawMessage
		if err := l.do(ctx, http.MethodGet, p, nil, &combined); err != nil {
			return err
		}
		raw = combined
		if err := json.Unmarshal(combined, &envelope); err != nil {
			return fmt.Errorf("vultr: decode pagination meta for %s: %w", path, err)
		}
		if err := fn(raw); err != nil {
			return err
		}
		if envelope.Meta.Links.Next == "" {
			return nil
		}
		cursor = envelope.Meta.Links.Next
	}
	return fmt.Errorf("vultr: %s paginated past 100 pages", path)
}

// --- wire shapes ---

type wireInstance struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	Hostname        string   `json:"hostname"`
	Status          string   `json:"status"`
	ServerStatus    string   `json:"server_status"`
	Plan            string   `json:"plan"`
	Region          string   `json:"region"`
	MainIP          string   `json:"main_ip"`
	V6MainIP        string   `json:"v6_main_ip"`
	Tags            []string `json:"tags"`
	FirewallGroupID string   `json:"firewall_group_id"`
}

func (w *wireInstance) toInfo() *InstanceInfo {
	if w == nil {
		return nil
	}
	out := &InstanceInfo{
		ID: w.ID, Label: w.Label, Hostname: w.Hostname,
		Status: w.Status, ServerStatus: w.ServerStatus,
		Plan: w.Plan, Region: w.Region, Tags: w.Tags,
		FirewallGroupID: w.FirewallGroupID,
	}
	// Vultr returns "0.0.0.0" for an instance whose address has not
	// been allocated yet. That is not an address; treating it as one
	// puts 0.0.0.0 into a signed pack's public_ip: tag.
	if ip := net.ParseIP(w.MainIP); ip != nil && !ip.IsUnspecified() {
		out.MainIP = ip
	}
	if ip := net.ParseIP(w.V6MainIP); ip != nil && !ip.IsUnspecified() {
		out.V6Main = ip
	}
	return out
}

// --- instances ---

func (l *liveClientWithToken) InstanceCreate(ctx context.Context, opts InstanceCreateOpts) (*InstanceInfo, error) {
	body := map[string]any{
		"region":                 opts.Region,
		"plan":                   opts.Plan,
		"os_id":                  opts.OSID,
		"label":                  opts.Label,
		"hostname":               opts.Hostname,
		"user_data":              opts.UserData,
		"enable_ipv6":            opts.EnableIPv6,
		"backups":                "disabled",
		"ddos_protection":        false,
		"activation_email":       false,
		"disable_public_ipv4":    false,
		"enable_vpc":             false,
		"enable_private_network": false,
	}
	if len(opts.SSHKeys) > 0 {
		body["sshkey_id"] = opts.SSHKeys
	}
	if len(opts.Tags) > 0 {
		body["tags"] = opts.Tags
	}
	if opts.FirewallGroupID != "" {
		body["firewall_group_id"] = opts.FirewallGroupID
	}
	var resp struct {
		Instance wireInstance `json:"instance"`
	}
	if err := l.do(ctx, http.MethodPost, "/instances", body, &resp); err != nil {
		return nil, err
	}
	if resp.Instance.ID == "" {
		return nil, errors.New("vultr: create instance returned no id")
	}
	return resp.Instance.toInfo(), nil
}

func (l *liveClientWithToken) InstanceByID(ctx context.Context, id string) (*InstanceInfo, error) {
	if id == "" {
		return nil, errInstanceNotFound
	}
	var resp struct {
		Instance wireInstance `json:"instance"`
	}
	err := l.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(id), nil, &resp)
	if errors.Is(err, errNotFoundHTTP) {
		return nil, errInstanceNotFound
	}
	if err != nil {
		return nil, err
	}
	return resp.Instance.toInfo(), nil
}

// InstanceByLabel finds this relay's instance by its derived label.
//
// It refuses an ambiguous answer. Vultr does not enforce label
// uniqueness, so two instances can carry one label — and then "pick the
// first" means an idempotent retry adopts, or a teardown destroys,
// whichever the API happened to list first. There is no safe guess, so
// there is no guess.
func (l *liveClientWithToken) InstanceByLabel(ctx context.Context, label string) (*InstanceInfo, error) {
	if label == "" {
		return nil, errInstanceNotFound
	}
	var found []*InstanceInfo
	err := l.listPages(ctx, "/instances?label="+url.QueryEscape(label), func(raw json.RawMessage) error {
		var page struct {
			Instances []wireInstance `json:"instances"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode instance list: %w", err)
		}
		for i := range page.Instances {
			// The server-side filter is trusted but re-checked: a
			// filter that silently stops filtering would otherwise
			// hand teardown the whole account.
			if page.Instances[i].Label != label {
				continue
			}
			found = append(found, page.Instances[i].toInfo())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, errInstanceNotFound
	case 1:
		return found[0], nil
	default:
		ids := make([]string, 0, len(found))
		for _, f := range found {
			ids = append(ids, f.ID)
		}
		return nil, fmt.Errorf("%w: %s (%s) — remove the duplicate in your Vultr console before retrying",
			errAmbiguousLabel, label, strings.Join(ids, ", "))
	}
}

// InstanceList enumerates the account. Unfiltered on purpose: the
// audit's whole job is to find boxes no record names, so it cannot
// start from a label.
func (l *liveClientWithToken) InstanceList(ctx context.Context) ([]*InstanceInfo, error) {
	var out []*InstanceInfo
	err := l.listPages(ctx, "/instances", func(raw json.RawMessage) error {
		var page struct {
			Instances []wireInstance `json:"instances"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode instance list: %w", err)
		}
		for i := range page.Instances {
			out = append(out, page.Instances[i].toInfo())
		}
		return nil
	})
	return out, err
}

func (l *liveClientWithToken) InstanceDelete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := l.do(ctx, http.MethodDelete, "/instances/"+url.PathEscape(id), nil, nil)
	if errors.Is(err, errNotFoundHTTP) {
		return nil // idempotent: already gone is success
	}
	return err
}

// OSIDForImage resolves an image name to Vultr's numeric os_id.
//
// Vultr's create call takes a number, and the numbers are catalogue
// ids, not stable identities. Hard-coding one is how a provisioner
// silently installs a different distribution the day the catalogue
// changes — and the whole relay (cloud-init, sing-box, ufw) is written
// against Ubuntu 24.04.
func (l *liveClientWithToken) OSIDForImage(ctx context.Context, name string) (int, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	id := 0
	err := l.listPages(ctx, "/os", func(raw json.RawMessage) error {
		var page struct {
			OS []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
				Arch string `json:"arch"`
			} `json:"os"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode os list: %w", err)
		}
		for _, o := range page.OS {
			if strings.ToLower(strings.TrimSpace(o.Name)) == want {
				id = o.ID
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, fmt.Errorf("vultr: no OS named %q in the account's catalogue", name)
	}
	return id, nil
}

// PlanPrice returns the plan's price. VULTR PRICES IN USD; the values
// come back as USD and Provider.Pricing stamps Currency:"USD" so no
// screen can render a dollar figure behind a euro sign.
func (l *liveClientWithToken) PlanPrice(ctx context.Context, region, plan string) (float64, float64, error) {
	wantRegion := vultrRegionOf(region)
	var monthly, hourly float64
	var found, inRegion bool
	err := l.listPages(ctx, "/plans", func(raw json.RawMessage) error {
		var page struct {
			Plans []struct {
				ID          string   `json:"id"`
				MonthlyCost float64  `json:"monthly_cost"`
				HourlyCost  float64  `json:"hourly_cost"`
				Locations   []string `json:"locations"`
			} `json:"plans"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode plan list: %w", err)
		}
		for _, p := range page.Plans {
			if p.ID != plan {
				continue
			}
			found = true
			monthly, hourly = p.MonthlyCost, p.HourlyCost
			for _, loc := range p.Locations {
				if vultrRegionOf(loc) == wantRegion {
					inRegion = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if !found {
		return 0, 0, fmt.Errorf("vultr: plan %q not found", plan)
	}
	if !inRegion {
		// Not a pricing quirk — a plan that is not offered in the
		// region cannot be provisioned there, and quoting a price for
		// it invites the operator to pick a box that will fail to
		// create.
		return 0, 0, fmt.Errorf("vultr: plan %q is not available in region %q", plan, region)
	}
	if hourly == 0 {
		hourly = monthlyToHourly(monthly)
	}
	return hourly, monthly, nil
}

// --- ssh keys ---

func (l *liveClientWithToken) SSHKeyCreate(ctx context.Context, name string, publicKey []byte) (string, error) {
	var resp struct {
		SSHKey struct {
			ID string `json:"id"`
		} `json:"ssh_key"`
	}
	body := map[string]string{"name": name, "ssh_key": strings.TrimSpace(string(publicKey))}
	if err := l.do(ctx, http.MethodPost, "/ssh-keys", body, &resp); err != nil {
		return "", err
	}
	if resp.SSHKey.ID == "" {
		return "", errors.New("vultr: create ssh key returned no id")
	}
	return resp.SSHKey.ID, nil
}

func (l *liveClientWithToken) SSHKeyList(ctx context.Context) ([]SSHKeyInfo, error) {
	var out []SSHKeyInfo
	err := l.listPages(ctx, "/ssh-keys", func(raw json.RawMessage) error {
		var page struct {
			SSHKeys []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"ssh_keys"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode ssh key list: %w", err)
		}
		for _, k := range page.SSHKeys {
			out = append(out, SSHKeyInfo{ID: k.ID, Name: k.Name})
		}
		return nil
	})
	return out, err
}

func (l *liveClientWithToken) SSHKeyDelete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := l.do(ctx, http.MethodDelete, "/ssh-keys/"+url.PathEscape(id), nil, nil)
	if errors.Is(err, errNotFoundHTTP) {
		return nil
	}
	return err
}

// --- firewall groups ---

func (l *liveClientWithToken) FirewallGroupCreate(ctx context.Context, description string) (string, error) {
	var resp struct {
		Group struct {
			ID string `json:"id"`
		} `json:"firewall_group"`
	}
	if err := l.do(ctx, http.MethodPost, "/firewalls", map[string]string{"description": description}, &resp); err != nil {
		return "", err
	}
	if resp.Group.ID == "" {
		return "", errors.New("vultr: create firewall group returned no id")
	}
	return resp.Group.ID, nil
}

func (l *liveClientWithToken) FirewallGroupByDescription(ctx context.Context, description string) (*FirewallGroupInfo, error) {
	var out *FirewallGroupInfo
	err := l.listPages(ctx, "/firewalls", func(raw json.RawMessage) error {
		var page struct {
			Groups []struct {
				ID            string `json:"id"`
				Description   string `json:"description"`
				InstanceCount int    `json:"instance_count"`
				RuleCount     int    `json:"rule_count"`
			} `json:"firewall_groups"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode firewall group list: %w", err)
		}
		for _, g := range page.Groups {
			if g.Description != description {
				continue
			}
			out = &FirewallGroupInfo{ID: g.ID, Description: g.Description, InstanceCount: g.InstanceCount, RuleCount: g.RuleCount}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (l *liveClientWithToken) FirewallGroupList(ctx context.Context) ([]FirewallGroupInfo, error) {
	var out []FirewallGroupInfo
	err := l.listPages(ctx, "/firewalls", func(raw json.RawMessage) error {
		var page struct {
			Groups []struct {
				ID            string `json:"id"`
				Description   string `json:"description"`
				InstanceCount int    `json:"instance_count"`
				RuleCount     int    `json:"rule_count"`
			} `json:"firewall_groups"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode firewall group list: %w", err)
		}
		for _, g := range page.Groups {
			out = append(out, FirewallGroupInfo{ID: g.ID, Description: g.Description, InstanceCount: g.InstanceCount, RuleCount: g.RuleCount})
		}
		return nil
	})
	return out, err
}

func (l *liveClientWithToken) FirewallGroupDelete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := l.do(ctx, http.MethodDelete, "/firewalls/"+url.PathEscape(id), nil, nil)
	if errors.Is(err, errNotFoundHTTP) {
		return nil
	}
	return err
}

func (l *liveClientWithToken) FirewallRuleAdd(ctx context.Context, groupID string, rule FirewallRule) (string, error) {
	if groupID == "" {
		return "", errors.New("vultr: firewall rule needs a group id")
	}
	body := map[string]any{
		"ip_type":     rule.IPType,
		"protocol":    rule.Protocol,
		"subnet":      rule.Subnet,
		"subnet_size": rule.SubnetSize,
		"port":        rule.Port,
		"notes":       rule.Notes,
	}
	var resp struct {
		Rule struct {
			ID json.Number `json:"id"`
		} `json:"firewall_rule"`
	}
	if err := l.do(ctx, http.MethodPost, "/firewalls/"+url.PathEscape(groupID)+"/rules", body, &resp); err != nil {
		return "", err
	}
	id := resp.Rule.ID.String()
	if id == "" {
		return "", errors.New("vultr: create firewall rule returned no id")
	}
	return id, nil
}

func (l *liveClientWithToken) FirewallRuleList(ctx context.Context, groupID string) ([]FirewallRuleInfo, error) {
	if groupID == "" {
		return nil, nil
	}
	var out []FirewallRuleInfo
	err := l.listPages(ctx, "/firewalls/"+url.PathEscape(groupID)+"/rules", func(raw json.RawMessage) error {
		var page struct {
			Rules []struct {
				ID         json.Number `json:"id"`
				IPType     string      `json:"ip_type"`
				Protocol   string      `json:"protocol"`
				Subnet     string      `json:"subnet"`
				SubnetSize int         `json:"subnet_size"`
				Port       string      `json:"port"`
				Notes      string      `json:"notes"`
			} `json:"firewall_rules"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode firewall rule list: %w", err)
		}
		for _, r := range page.Rules {
			out = append(out, FirewallRuleInfo{
				ID: r.ID.String(), IPType: r.IPType, Protocol: r.Protocol,
				Subnet: r.Subnet, SubnetSize: r.SubnetSize, Port: r.Port, Notes: r.Notes,
			})
		}
		return nil
	})
	if errors.Is(err, errNotFoundHTTP) {
		return nil, nil
	}
	return out, err
}

func (l *liveClientWithToken) FirewallRuleDelete(ctx context.Context, groupID, ruleID string) error {
	if groupID == "" || ruleID == "" {
		return nil
	}
	err := l.do(ctx, http.MethodDelete, "/firewalls/"+url.PathEscape(groupID)+"/rules/"+url.PathEscape(ruleID), nil, nil)
	if errors.Is(err, errNotFoundHTTP) {
		return nil
	}
	return err
}

// --- reserved ips ---

type wireReservedIP struct {
	ID         string `json:"id"`
	Region     string `json:"region"`
	IPType     string `json:"ip_type"`
	Subnet     string `json:"subnet"`
	SubnetSize int    `json:"subnet_size"`
	Label      string `json:"label"`
	InstanceID string `json:"instance_id"`
}

func (w *wireReservedIP) toInfo() *ReservedIPInfo {
	if w == nil {
		return nil
	}
	out := &ReservedIPInfo{
		ID: w.ID, Region: w.Region, IPType: w.IPType,
		SubnetSize: w.SubnetSize, Label: w.Label, InstanceID: w.InstanceID,
	}
	if ip := net.ParseIP(w.Subnet); ip != nil && !ip.IsUnspecified() {
		out.IP = ip
	}
	return out
}

// ReservedIPCreate reserves an address in a region.
//
// IPv4 ONLY, deliberately, exactly as the Hetzner adapter reserves only
// v4: the relay's dialed address flows into OperatorRecord.PublicIP and
// from there into every candidate's public_ip:* tag and every client
// outbound, all of which are written against an IPv4 literal. A v6
// address here mints a pack that validates and cannot be dialed from a
// v4-only Iranian mobile network, which is most of them.
func (l *liveClientWithToken) ReservedIPCreate(ctx context.Context, opts ReservedIPCreateOpts) (*ReservedIPInfo, error) {
	if opts.Region == "" {
		return nil, errors.New("vultr: reserved ip needs a region")
	}
	ipType := opts.IPType
	if ipType == "" {
		ipType = "v4"
	}
	if ipType != "v4" {
		return nil, fmt.Errorf("vultr: reserved ip type %q refused; the relay record and every client outbound are IPv4", ipType)
	}
	body := map[string]any{"region": opts.Region, "ip_type": ipType}
	if opts.Label != "" {
		body["label"] = opts.Label
	}
	var resp struct {
		ReservedIP wireReservedIP `json:"reserved_ip"`
	}
	if err := l.do(ctx, http.MethodPost, "/reserved-ips", body, &resp); err != nil {
		return nil, err
	}
	info := resp.ReservedIP.toInfo()
	if info == nil || info.ID == "" {
		return nil, errors.New("vultr: create reserved ip returned no id")
	}
	return info, nil
}

func (l *liveClientWithToken) ReservedIPByID(ctx context.Context, id string) (*ReservedIPInfo, error) {
	if id == "" {
		return nil, errReservedIPNotFound
	}
	var resp struct {
		ReservedIP wireReservedIP `json:"reserved_ip"`
	}
	err := l.do(ctx, http.MethodGet, "/reserved-ips/"+url.PathEscape(id), nil, &resp)
	if errors.Is(err, errNotFoundHTTP) {
		return nil, errReservedIPNotFound
	}
	if err != nil {
		return nil, err
	}
	return resp.ReservedIP.toInfo(), nil
}

func (l *liveClientWithToken) ReservedIPList(ctx context.Context) ([]*ReservedIPInfo, error) {
	var out []*ReservedIPInfo
	err := l.listPages(ctx, "/reserved-ips", func(raw json.RawMessage) error {
		var page struct {
			ReservedIPs []wireReservedIP `json:"reserved_ips"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode reserved ip list: %w", err)
		}
		for i := range page.ReservedIPs {
			out = append(out, page.ReservedIPs[i].toInfo())
		}
		return nil
	})
	return out, err
}

func (l *liveClientWithToken) ReservedIPAttach(ctx context.Context, ipID, instanceID string) error {
	if ipID == "" || instanceID == "" {
		return errors.New("vultr: attach reserved ip needs both ids")
	}
	return l.do(ctx, http.MethodPost, "/reserved-ips/"+url.PathEscape(ipID)+"/attach",
		map[string]string{"instance_id": instanceID}, nil)
}

func (l *liveClientWithToken) ReservedIPDetach(ctx context.Context, ipID, instanceID string) error {
	if ipID == "" {
		return nil
	}
	err := l.do(ctx, http.MethodPost, "/reserved-ips/"+url.PathEscape(ipID)+"/detach",
		map[string]string{"instance_id": instanceID}, nil)
	if errors.Is(err, errNotFoundHTTP) {
		return nil
	}
	return err
}

func (l *liveClientWithToken) ReservedIPDelete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := l.do(ctx, http.MethodDelete, "/reserved-ips/"+url.PathEscape(id), nil, nil)
	if errors.Is(err, errNotFoundHTTP) {
		return nil
	}
	return err
}

// --- listing surface for the wizard ---

// ListingClient exposes the read-only calls the wizard's "pick a box"
// screen needs. It is not a vultrClient: it can only read.
type ListingClient struct {
	c *liveClientWithToken
}

// NewLiveClientForListing returns a read-only Vultr client. Mirrors
// hetzner.NewLiveClientForListing so cli.go's switch stays symmetrical.
func NewLiveClientForListing(token string) *ListingClient {
	return &ListingClient{c: NewLiveClientFunc(func() string { return token }).(*liveClientWithToken)}
}

// ServerTypeEntry is one plan with pricing for a region. Field names
// match hetzner.ServerTypeEntry so the wizard renders both providers
// through one shape.
//
// MonthlyEUR/HourlyEUR carry the provider's own currency and Currency
// says which: Vultr bills in USD. The field names are the established
// wire contract with the Rust shim and are not renamed here; the
// Currency field is what stops a dollar figure being drawn behind a
// euro sign.
type ServerTypeEntry struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CPUs        int     `json:"cpus"`
	MemoryGB    float64 `json:"memory_gb"`
	DiskGB      int     `json:"disk_gb"`
	MonthlyEUR  float64 `json:"monthly_eur"`
	HourlyEUR   float64 `json:"hourly_eur"`
	Location    string  `json:"location"`
	Arch        string  `json:"arch"`
	Currency    string  `json:"currency,omitempty"`
}

// ListServerTypes returns the plans that can actually be created in
// region, with pricing.
//
// "Actually" is load-bearing and is the same trap the Hetzner listing
// walked into: Vultr publishes every plan globally and marks
// availability per region in `locations`. Listing a plan the region
// does not carry offers the operator a box whose create call fails.
func (lc *ListingClient) ListServerTypes(ctx context.Context, region string) ([]ServerTypeEntry, error) {
	want := vultrRegionOf(region)
	var out []ServerTypeEntry
	err := lc.c.listPages(ctx, "/plans", func(raw json.RawMessage) error {
		var page struct {
			Plans []struct {
				ID          string   `json:"id"`
				VCPUCount   int      `json:"vcpu_count"`
				RAM         int      `json:"ram"` // MB
				Disk        int      `json:"disk"`
				MonthlyCost float64  `json:"monthly_cost"`
				HourlyCost  float64  `json:"hourly_cost"`
				Type        string   `json:"type"`
				Locations   []string `json:"locations"`
			} `json:"plans"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode plan list: %w", err)
		}
		for _, p := range page.Plans {
			available := false
			for _, loc := range p.Locations {
				if vultrRegionOf(loc) == want {
					available = true
				}
			}
			if !available {
				continue
			}
			hourly := p.HourlyCost
			if hourly == 0 {
				hourly = monthlyToHourly(p.MonthlyCost)
			}
			arch := "x86"
			if strings.Contains(p.Type, "arm") {
				arch = "arm"
			}
			out = append(out, ServerTypeEntry{
				ID:          p.ID,
				Description: fmt.Sprintf("%s (%d vCPU, %s GB RAM)", p.ID, p.VCPUCount, strconv.FormatFloat(float64(p.RAM)/1024.0, 'g', 3, 64)),
				CPUs:        p.VCPUCount,
				MemoryGB:    float64(p.RAM) / 1024.0,
				DiskGB:      p.Disk,
				MonthlyEUR:  p.MonthlyCost,
				HourlyEUR:   hourly,
				Location:    region,
				Arch:        arch,
				Currency:    "USD",
			})
		}
		return nil
	})
	return out, err
}

// ExistingServerEntry mirrors hetzner.ExistingServerEntry.
type ExistingServerEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	ServerType string `json:"server_type"`
	Region     string `json:"region"`
	PublicIP   string `json:"public_ip"`
	PublicIPv6 string `json:"public_ipv6"`
}

// ListServers returns every instance on the account.
func (lc *ListingClient) ListServers(ctx context.Context) ([]ExistingServerEntry, error) {
	var out []ExistingServerEntry
	err := lc.c.listPages(ctx, "/instances", func(raw json.RawMessage) error {
		var page struct {
			Instances []wireInstance `json:"instances"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("vultr: decode instance list: %w", err)
		}
		for i := range page.Instances {
			inf := page.Instances[i].toInfo()
			e := ExistingServerEntry{
				ID: inf.ID, Name: inf.Label, Status: inf.Status,
				ServerType: inf.Plan, Region: inf.Region,
			}
			if inf.MainIP != nil {
				e.PublicIP = inf.MainIP.String()
			}
			if inf.V6Main != nil {
				e.PublicIPv6 = inf.V6Main.String()
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}
