// The box's own family set.
//
// A Daal relay serves a set of transport families that the publisher
// resolves ONCE, at provision time, and derives three things from: the
// inbounds cloud-init bakes into the sing-box config, the ports both
// firewalls open, and the candidates the minted packs carry. Until this
// file existed the box itself was not told. That was survivable for the
// inbounds cloud-init writes — they are there or they are not — but this
// service CREATES four inbounds on the first recipient (naive-in, ws-in,
// ss-in, anytls-in: none of them may exist with an empty users[]), and
// with nothing to consult it created all four on every relay and minted
// credentials for all of them. A relay provisioned for
// `shadowsocks,anytls` ended up listening on 8444 and 8445 too; a default
// relay bound 8446 and 8447 for two families it does not serve (finding
// FAM-4, observation O-3, backlog W5-1).
//
// cloud-init now writes the set to /etc/daal/families, one name per
// line, and every write to the user table obeys it: a family the relay
// was not provisioned with gets no inbound, no user row and no
// credential in the response.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// defaultFamiliesPath is where cloud-init writes the relay's family set.
const defaultFamiliesPath = "/etc/daal/families"

// Family names, as the publisher's toolbox profiles and
// publisher/deploy/relayports spell them. Local copies for the same
// reason the listen ports are: this is a separate module and importing
// the publisher would pull its whole dependency tree into the on-box
// binary. box_client_agreement_test.go holds the two spellings together.
const (
	famVLESSReality = "vless-reality"
	famHysteria2    = "hysteria2"
	famNaive        = "naive"
	famWebSocketTLS = "websocket-tls"
	famTUIC         = "tuic"
	famShadowsocks  = "shadowsocks"
	famAnyTLS       = "anytls"
)

// familySet is the set of families this relay was provisioned to serve.
//
// The nil set means UNDECLARED: the box was built by a cloud-init that
// predates /etc/daal/families, so there is nothing to obey and the
// service behaves exactly as it did before — every family this binary
// knows is created on first use. That is the only honest reading of "the
// publisher never said"; guessing a narrower set would silently take
// tiers away from a relay whose packs already carry them.
type familySet map[string]bool

// serves reports whether the relay was provisioned to serve family.
func (f familySet) serves(family string) bool {
	return f == nil || f[family]
}

// readFamilySet loads the declared family set.
//
//   - path empty or file absent → nil (undeclared), no error.
//   - file present and names at least one family → that set. Names this
//     binary does not recognise are kept and simply never match: a newer
//     publisher may name a family an older daemon cannot serve, and the
//     publisher already fails closed on a credential the box does not
//     send back.
//   - file present but unreadable, or naming nothing → an ERROR. A box
//     that was told its family set and cannot read it must not fall back
//     to "everything": that is the exact over-exposure the file exists to
//     prevent, arrived at through a truncated write.
func readFamilySet(path string) (familySet, error) {
	if path == "" {
		return nil, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("family set %s: %w", path, err)
	}
	set := familySet{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("family set %s names no family; refusing to treat a declared-but-empty set as \"serve everything\"", path)
	}
	return set, nil
}

// recipientInbounds lists every inbound tag this service manages,
// together with the key its user rows are named by. naive spells it
// `username`; everything else spells it `name`.
var recipientInbounds = []struct{ tag, nameKey string }{
	{tagVLESS, "name"},
	{tagHy2, "name"},
	{tagNaive, "username"},
	{tagWS, "name"},
	{tagTUIC, "name"},
	{tagSS, "name"},
	{tagAnyTLS, "name"},
}

// recipientNames returns the name of every recipient that owns a row in
// ANY managed inbound, each once, in order of first appearance.
//
// This is the box's user registry. It used to be vless-in's users[]
// alone ("every user appears there"), which was true only while every
// relay served vless-reality. On a relay provisioned without it there is
// no vless-in, so the registry was permanently empty: the duplicate
// check passed for a name already present, the recipient cap never
// counted anyone, and /users/list said the relay had no users.
func recipientNames(doc map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, ib := range recipientInbounds {
		in := findInboundByTag(doc, ib.tag)
		if in == nil {
			continue
		}
		for _, raw := range asSlice(in["users"]) {
			u, _ := raw.(map[string]any)
			name, _ := u[ib.nameKey].(string)
			if name == "" || seen[name] || !nameRegex.MatchString(name) {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// userRow returns the recipient's row in the tagged inbound, or nil.
func userRow(doc map[string]any, tag, name string) map[string]any {
	in := findInboundByTag(doc, tag)
	if in == nil {
		return nil
	}
	key := "name"
	if tag == tagNaive {
		key = "username"
	}
	for _, raw := range asSlice(in["users"]) {
		u, _ := raw.(map[string]any)
		if n, _ := u[key].(string); n == name {
			return u
		}
	}
	return nil
}

// blankUnservedCreds clears every per-recipient credential whose row is
// not in the live config, so the response states what the box SERVES for
// this recipient rather than what mintCreds generated.
//
// It is the rule tuic, shadowsocks and anytls already follow — "a value
// the box does not send is the reliable signal, never an inference from
// one it does" — applied to the four older families, which predate it
// and were echoed unconditionally. On a relay provisioned without
// hysteria2 the response used to carry a hy2 password that no inbound
// would ever check.
func blankUnservedCreds(doc map[string]any, c *userCreds) {
	vless := userRow(doc, tagVLESS, c.Name)
	ws := userRow(doc, tagWS, c.Name)
	if vless == nil {
		c.RealityShortID = ""
	}
	if vless == nil && ws == nil {
		c.VLESSUUID = ""
	}
	if ws == nil {
		c.WSPath = ""
	}
	if userRow(doc, tagHy2, c.Name) == nil {
		c.Hy2Password = ""
	}
	if userRow(doc, tagNaive, c.Name) == nil {
		c.NaivePassword = ""
	}
}
