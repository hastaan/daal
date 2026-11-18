package vultr

import (
	"context"
	"errors"
	"net"
	"strings"
)

// vultrClient is the narrow surface the adapter uses against the Vultr
// API. It is defined locally, and every method is a single API call
// with no composition in it, for one reason: composition that lives in
// the client cannot be rolled back by the provider. The provider is
// what knows the ORDER resources were created in, so the provider is
// what has to be able to undo them (see provisionScope).
//
// The production implementation is liveClient (live_client.go), REST
// against api.vultr.com/v2. Tests drive that same implementation
// against an httptest server, so there is no second, kinder client
// with different behaviour.
type vultrClient interface {
	// --- instances ---
	InstanceCreate(ctx context.Context, opts InstanceCreateOpts) (*InstanceInfo, error)
	InstanceByID(ctx context.Context, id string) (*InstanceInfo, error)
	// InstanceByLabel returns errInstanceNotFound when no instance
	// carries the label. Vultr does not enforce label uniqueness, so
	// an account with two same-labelled instances is ambiguous and
	// must be an error rather than a coin flip — see errAmbiguousLabel.
	InstanceByLabel(ctx context.Context, label string) (*InstanceInfo, error)
	InstanceDelete(ctx context.Context, id string) error
	// InstanceList enumerates every instance on the account. Used by
	// the account audit, which exists for the case where the operator
	// has NO record to look a box up by — the two-paid-servers state a
	// failed L5 leaves behind.
	InstanceList(ctx context.Context) ([]*InstanceInfo, error)
	// OSIDForImage resolves an image name ("Ubuntu 24.04 LTS x64") to
	// Vultr's numeric os_id. Vultr's create call takes the number, and
	// hard-coding it is how a provisioner silently installs the wrong
	// distribution the day the catalogue is renumbered.
	OSIDForImage(ctx context.Context, name string) (int, error)
	PlanPrice(ctx context.Context, region, plan string) (hourlyEUR, monthlyEUR float64, err error)

	// --- ssh keys ---
	SSHKeyCreate(ctx context.Context, name string, publicKey []byte) (id string, err error)
	SSHKeyList(ctx context.Context) ([]SSHKeyInfo, error)
	SSHKeyDelete(ctx context.Context, id string) error

	// --- firewall groups ---
	FirewallGroupCreate(ctx context.Context, description string) (string, error)
	FirewallGroupByDescription(ctx context.Context, description string) (*FirewallGroupInfo, error)
	FirewallGroupList(ctx context.Context) ([]FirewallGroupInfo, error)
	FirewallGroupDelete(ctx context.Context, id string) error
	FirewallRuleAdd(ctx context.Context, groupID string, rule FirewallRule) (ruleID string, err error)
	FirewallRuleList(ctx context.Context, groupID string) ([]FirewallRuleInfo, error)
	FirewallRuleDelete(ctx context.Context, groupID, ruleID string) error

	// --- reserved ips (the L3 address) ---
	ReservedIPCreate(ctx context.Context, opts ReservedIPCreateOpts) (*ReservedIPInfo, error)
	// ReservedIPByID returns errReservedIPNotFound for an absent id.
	// The caller MUST distinguish that from a transport error: "this
	// address is gone" and "we could not ask" lead to opposite
	// decisions during a rollback.
	ReservedIPByID(ctx context.Context, id string) (*ReservedIPInfo, error)
	ReservedIPList(ctx context.Context) ([]*ReservedIPInfo, error)
	ReservedIPAttach(ctx context.Context, ipID, instanceID string) error
	ReservedIPDetach(ctx context.Context, ipID, instanceID string) error
	ReservedIPDelete(ctx context.Context, id string) error
}

// InstanceCreateOpts is the POST /v2/instances body this adapter uses.
type InstanceCreateOpts struct {
	Label    string
	Hostname string
	Plan     string
	Region   string
	OSID     int
	// UserData is base64-encoded cloud-init YAML. Vultr requires the
	// base64; the adapter encodes it.
	UserData string
	SSHKeys  []string
	Tags     []string
	// FirewallGroupID attaches the relay's firewall AT CREATE TIME.
	// Hetzner has to attach afterwards and therefore has a window
	// where a booting box is naked; Vultr does not, so this adapter
	// creates the group first and never opens that window.
	FirewallGroupID string
	EnableIPv6      bool
}

// InstanceInfo is the subset of an instance object this adapter acts on.
type InstanceInfo struct {
	ID              string
	Label           string
	Hostname        string
	Status          string
	ServerStatus    string
	Plan            string
	Region          string
	MainIP          net.IP
	V6Main          net.IP
	Tags            []string
	FirewallGroupID string
}

// SSHKeyInfo is one account SSH key. Vultr keys carry a name and
// nothing else — no labels — which is why ownership of a key is
// established by the derived relay prefix (ownsEphemeralKey).
type SSHKeyInfo struct {
	ID   string
	Name string
}

// FirewallGroupInfo is one firewall group. Description is the only
// free-text field Vultr gives a group, so it carries the ownership
// mark (see labels.go).
type FirewallGroupInfo struct {
	ID            string
	Description   string
	InstanceCount int
	RuleCount     int
}

// FirewallRule is one inbound rule to create.
//
// Vultr splits v4 and v6 into separate rules with an IPType, unlike
// Hetzner's single rule with a SourceIPs list. "Open to the world"
// is therefore always two calls, and forgetting the second silently
// makes the relay v4-only.
type FirewallRule struct {
	IPType     string // "v4" or "v6"
	Protocol   string // "tcp" or "udp"
	Subnet     string // "0.0.0.0", "::", or a specific address
	SubnetSize int    // 0 for any, 32 / 128 for a single host
	Port       string // "443"
	Notes      string
}

// FirewallRuleInfo is a rule read back from the API.
type FirewallRuleInfo struct {
	ID         string
	IPType     string
	Protocol   string
	Subnet     string
	SubnetSize int
	Port       string
	Notes      string
}

// ReservedIPCreateOpts reserves an address. Region is required and is
// always the relay's own — see CreateFloatingIP for why homing it
// elsewhere is a cover-story problem, not just a routing detour.
type ReservedIPCreateOpts struct {
	Region string
	IPType string // "v4"
	Label  string
}

// ReservedIPInfo is a reserved address. InstanceID is empty when the
// address is detached.
type ReservedIPInfo struct {
	ID         string
	Region     string
	IPType     string
	IP         net.IP
	SubnetSize int
	Label      string
	InstanceID string
}

// Sentinels. Each names a state the caller must be able to tell apart
// from "the API call failed", because they lead to opposite decisions.
var (
	errInstanceNotFound   = errors.New("vultr: instance not found")
	errReservedIPNotFound = errors.New("vultr: reserved ip not found")
	errUnauthorized       = errors.New("vultr: 401 unauthorized (token revoked, invalid, or lacking write scope)")

	// errAmbiguousLabel fires when the derived relay label matches
	// more than one instance. Vultr does not enforce label
	// uniqueness, so this is reachable — and picking the first match
	// would mean an idempotent retry adopting, or a teardown
	// destroying, whichever box the API happened to list first.
	errAmbiguousLabel = errors.New("vultr: more than one instance carries this relay's label")
)

// ErrLiveNotImplemented is retained for one release so callers that
// tested for it still compile. Nothing returns it any more: every
// method on liveClient is wired.
//
// Deprecated: the Vultr live client is implemented; see live_client.go.
var ErrLiveNotImplemented = errors.New("vultr: live client is implemented; this error is no longer returned")

// vultrRegionOf normalises a region code for comparison.
func vultrRegionOf(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
