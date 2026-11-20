package fieldprobe

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// THE TARGET LIST — what the test may speak to, and nothing else.
//
// Every name the test resolves or puts in a hello comes from this list;
// nothing the person types and nothing a page sends goes into it. The
// default is compiled into the engine (targets-v2.json, embedded below),
// so it is covered by the app's own signature; its version and SHA-256
// go into every report (app.targets_list_*), so the publisher knows
// exactly which list produced a result. A publisher-signed list carried
// in the Test pack is the next step (specs/field-probe-v2.md, "Target
// list"); LoadTargets is already the function it will go through.
//
// The loader REFUSES, rather than skips:
//   - any name under .ir, or marked "domestic" — the test never touches
//     a domestic name or address;
//   - an address literal where a name belongs;
//   - a name under the infrastructure the test must never touch (Tor,
//     Psiphon, Snowflake, Conjure; VPN services);
//   - a public resolver other than Cloudflare's two anycast addresses;
//   - a path that is not an absolute path.

//go:embed targets-v2.json
var defaultTargetsJSON []byte

// KnownRecord is one record of the known-answer zone (A4).
type KnownRecord struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Expect string `json:"expect"`
	// Domestic marks an entry the loader must refuse. Never set in a
	// list that loads.
	Domestic bool `json:"domestic,omitempty"`
}

// Targets is a loaded, checked list.
type Targets struct {
	Version         string        `json:"version"`
	Google          string        `json:"google"`
	GoogleFrontHost string        `json:"google_front_host"`
	GoogleFrontPath string        `json:"google_front_path"`
	RedirectSuffix  string        `json:"redirect_suffix"`
	GitHub          string        `json:"github"`
	GitHubFeedPath  string        `json:"github_feed_path"`
	WhiteName       string        `json:"white_name"`
	WhitePath       string        `json:"white_path"`
	WhiteHints      []string      `json:"white_hints"`
	CFECHOuter      string        `json:"cf_ech_outer"`
	CFECHInner      string        `json:"cf_ech_inner"`
	CFTracePath     string        `json:"cf_trace_path"`
	CFECHConfigB64  string        `json:"cf_ech_config_b64"`
	CFNeutral       string        `json:"cf_neutral"`
	CFNeutralPath   string        `json:"cf_neutral_path"`
	CFDNSName       string        `json:"cf_dns_name"`
	NeutralSNI      string        `json:"neutral_sni"`
	PublicResolver  string        `json:"public_resolver"`
	CalibrationNet  string        `json:"calibration_bogon"`
	KnownZone       []KnownRecord `json:"known_zone"`
	// AllowNets: per target role, the address blocks the role's operator
	// announces (Google, GitHub, Cloudflare). A resolver's answer is
	// connected to ONLY when it falls inside its role's blocks; a public
	// answer outside them is recorded as dns_wrong_public and not used —
	// an Iranian resolver can answer a foreign name with a public
	// domestic address, and the test must never open a connection to a
	// domestic host. Re-checked against the operators' published lists
	// whenever the list is re-signed (specs/field-probe-v2.md).
	AllowNets map[string][]string `json:"allow_nets"`
	Domestic  []string            `json:"domestic,omitempty"`

	// Filled by LoadTargets.
	SHA256      string         `json:"-"`
	hints       []netip.Addr   `json:"-"`
	resolver    netip.AddrPort `json:"-"`
	calibration netip.Prefix   `json:"-"`
	echConfig   []byte         `json:"-"`
	allow       map[string][]netip.Prefix
}

// allowRoles are the roles whose answers Stage B connects to: each must
// have its blocks.
var allowRoles = []string{"google", "github", "cf_edge", "white_name"}

// ErrTargets wraps every refusal of a list.
var ErrTargets = errors.New("fieldprobe: target list refused")

// allowedResolvers: the only public resolvers A6 may ask.
var allowedResolvers = map[string]bool{"1.1.1.1:53": true, "1.0.0.1:53": true}

// neverTouch are name fragments the list may not contain anywhere.
var neverTouch = []string{"torproject", "tor2web", "psiphon", "snowflake", "conjure", "refraction",
	"lantern", "getlantern", "nordvpn", "expressvpn", "protonvpn", "mullvad", "windscribe", "openvpn", "wireguard"}

// DefaultTargets is the compiled-in list.
func DefaultTargets() (*Targets, error) { return LoadTargets(defaultTargetsJSON) }

// LoadTargets parses and checks a list.
func LoadTargets(raw []byte) (*Targets, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var t Targets
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTargets, err)
	}
	if len(t.Domestic) > 0 {
		return nil, fmt.Errorf("%w: the list marks entries domestic", ErrTargets)
	}
	if t.Version == "" || len(t.Version) > 32 {
		return nil, fmt.Errorf("%w: version", ErrTargets)
	}
	names := map[string]string{
		"google": t.Google, "google_front_host": t.GoogleFrontHost, "redirect_suffix": t.RedirectSuffix,
		"github": t.GitHub, "white_name": t.WhiteName, "cf_ech_outer": t.CFECHOuter,
		"cf_ech_inner": t.CFECHInner, "cf_neutral": t.CFNeutral, "cf_dns_name": t.CFDNSName,
		"neutral_sni": t.NeutralSNI,
	}
	for field, n := range names {
		if err := checkName(n); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrTargets, field, err)
		}
	}
	for field, p := range map[string]string{"google_front_path": t.GoogleFrontPath, "github_feed_path": t.GitHubFeedPath,
		"white_path": t.WhitePath, "cf_trace_path": t.CFTracePath, "cf_neutral_path": t.CFNeutralPath} {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " \r\n\t") || len(p) > 200 {
			return nil, fmt.Errorf("%w: %s", ErrTargets, field)
		}
	}
	if len(t.KnownZone) == 0 || len(t.KnownZone) > 6 {
		return nil, fmt.Errorf("%w: known_zone", ErrTargets)
	}
	for _, k := range t.KnownZone {
		if k.Domestic {
			return nil, fmt.Errorf("%w: known_zone entry marked domestic", ErrTargets)
		}
		if _, ok := qtypeOf[k.Type]; !ok {
			return nil, fmt.Errorf("%w: known_zone type", ErrTargets)
		}
		if err := checkName(k.Name); err != nil {
			return nil, fmt.Errorf("%w: known_zone: %v", ErrTargets, err)
		}
	}
	if !allowedResolvers[t.PublicResolver] {
		return nil, fmt.Errorf("%w: public_resolver is not one the test may ask", ErrTargets)
	}
	t.resolver = netip.MustParseAddrPort(t.PublicResolver)
	pfx, err := netip.ParsePrefix(t.CalibrationNet)
	if err != nil {
		return nil, fmt.Errorf("%w: calibration_bogon", ErrTargets)
	}
	t.calibration = pfx
	t.allow = map[string][]netip.Prefix{}
	for role, nets := range t.AllowNets {
		known := false
		for _, r := range allowRoles {
			known = known || r == role
		}
		if !known || len(nets) == 0 || len(nets) > 64 {
			return nil, fmt.Errorf("%w: allow_nets %s", ErrTargets, role)
		}
		for _, n := range nets {
			p, err := netip.ParsePrefix(n)
			// No catch-all block, and nothing that is not public.
			if err != nil || p != p.Masked() || (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 19) ||
				isBogon(p.Addr(), netip.Prefix{}) || isBogon(lastAddr(p), netip.Prefix{}) {
				return nil, fmt.Errorf("%w: allow_nets %s", ErrTargets, role)
			}
			t.allow[role] = append(t.allow[role], p)
		}
	}
	for _, r := range allowRoles {
		if len(t.allow[r]) == 0 {
			return nil, fmt.Errorf("%w: allow_nets has no %s", ErrTargets, r)
		}
	}
	for _, h := range t.WhiteHints {
		a, err := netip.ParseAddr(h)
		if err != nil || isBogon(a, netip.Prefix{}) || !t.Allowed("white_name", a) {
			return nil, fmt.Errorf("%w: white_hints", ErrTargets)
		}
		t.hints = append(t.hints, a)
	}
	if t.CFECHConfigB64 != "" {
		b, err := base64.StdEncoding.DecodeString(t.CFECHConfigB64)
		if err != nil || len(b) < 8 {
			return nil, fmt.Errorf("%w: cf_ech_config_b64", ErrTargets)
		}
		t.echConfig = b
	}
	sum := sha256.Sum256(raw)
	t.SHA256 = hex.EncodeToString(sum[:])
	return &t, nil
}

// checkName: a DNS name, not an address, not domestic, not forbidden.
func checkName(n string) error {
	n = strings.ToLower(strings.TrimSuffix(n, "."))
	switch {
	case n == "" || len(n) > 253:
		return errors.New("empty or too long")
	case strings.HasSuffix(n, ".ir") || n == "ir":
		return errors.New("a domestic name")
	case strings.Contains(n, ":"):
		return errors.New("not a name")
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return errors.New("an address where a name belongs")
	}
	for _, f := range neverTouch {
		if strings.Contains(n, f) {
			return errors.New("a name the test must never touch")
		}
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("bad label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("bad character")
			}
		}
	}
	if !strings.Contains(n, ".") {
		return errors.New("not a full name")
	}
	return nil
}

// Allowed: a is inside the blocks of role (always false for a role
// without blocks).
func (t *Targets) Allowed(role string, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range t.allow[role] {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// lastAddr is the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		lo := i * 8
		switch {
		case bits <= lo:
			b[i] = 0xff
		case bits < lo+8:
			b[i] |= byte(0xff >> uint(bits-lo))
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// CheckName is the list's rule for a name, for names that come from
// elsewhere (the Test relay's cover name, from its pack): a DNS name,
// not an address, not domestic, not one the test must never touch.
func CheckName(n string) error { return checkName(n) }

// Hints are the bundled addresses of the white name (B5 when DNS lies).
func (t *Targets) Hints() []netip.Addr { return t.hints }

// Names lists every name the list holds, for the privacy test and the
// "what is tested" screen.
func (t *Targets) Names() []string {
	out := []string{t.Google, t.GoogleFrontHost, t.GitHub, t.WhiteName, t.CFECHOuter, t.CFECHInner,
		t.CFNeutral, t.CFDNSName, t.NeutralSNI}
	for _, k := range t.KnownZone {
		out = append(out, k.Name)
	}
	return out
}
