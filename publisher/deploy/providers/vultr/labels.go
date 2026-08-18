package vultr

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// OWNERSHIP: TWO FACTS, ALWAYS BOTH.
//
// The Hetzner adapter proves a resource is ours with a PAIR of labels:
// managed-by=daal-deploy says "some daal relay owns this", and
// daal-relay=<name> says WHICH ONE. The pair is not decoration. In an
// account running two relays, every sibling resource carries the
// managed-by label, so matching on it alone is precisely the case where
// deleting is wrong — and the absence of the second label was once the
// difference between a refused delete and a destroyed live relay.
//
// Vultr has no key/value labels. An instance has a `label` plus a
// `tags` array; an SSH key has only a name; a reserved IP has only a
// label; a firewall group has only a description. So the same two facts
// are carried in whatever field exists:
//
//	instance        tags: ["managed-by:daal-deploy", "daal-relay:<name>"]
//	reserved ip     label:       "managed-by=daal-deploy daal-relay=<name> ..."
//	firewall group  description: "managed-by=daal-deploy daal-relay=<name> ..."
//	ssh key         name:        "<name>-ephemeral-<rand>"
//
// The rule does not soften because the field is a string: ownership
// checks below require BOTH fields to parse out, exactly, with no
// prefix matching. "daal-relay=daal-fra-aabbccdd" must not satisfy a
// check for "daal-relay=daal-fra-aabbccdde" — hence the k=v parse
// rather than strings.Contains.
//
// The SSH key is the one exception and it is a Vultr limitation, not a
// choice: a key object has a name and an id and nothing else. The name
// is a pure function of (publisher pubkey, region) plus 4 random bytes,
// so a match is still proof this operator's own tooling minted it, and
// the sweep additionally refuses to touch a key whose relay is still
// alive.

const (
	markManagedByKey   = "managed-by"
	markManagedByValue = "daal-deploy"
	markRelayKey       = "daal-relay"

	tagManagedBy   = markManagedByKey + ":" + markManagedByValue
	tagRelayPrefix = markRelayKey + ":"
	tagToolboxPfx  = "toolbox:"
)

// ownershipTags is the tag set every instance this adapter creates
// carries. toolbox is diagnostic only; nothing keys ownership off it.
func ownershipTags(relay, toolboxProfile string) []string {
	return []string{tagManagedBy, tagRelayPrefix + relay, tagToolboxPfx + toolboxProfile}
}

// ownsInstance reports whether daal-deploy created this instance FOR
// THIS RELAY. Both tags, exact match, never a prefix.
//
// A pre-Wave-6 Vultr instance cannot exist to be stranded by this rule:
// every method of the old live client returned ErrLiveNotImplemented,
// so this adapter has never created a Vultr instance in the world.
func ownsInstance(inst *InstanceInfo, relay string) bool {
	if inst == nil || relay == "" {
		return false
	}
	managed, mine := false, false
	for _, t := range inst.Tags {
		switch strings.TrimSpace(t) {
		case tagManagedBy:
			managed = true
		case tagRelayPrefix + relay:
			mine = true
		}
	}
	return managed && mine
}

// ownershipMark renders the two facts into the ONE string field Vultr
// offers on reserved IPs and firewall groups. note is free text for a
// human reading the Vultr console; it is never parsed.
func ownershipMark(relay, note string) string {
	m := fmt.Sprintf("%s=%s %s=%s", markManagedByKey, markManagedByValue, markRelayKey, relay)
	if note != "" {
		m += " " + note
	}
	return m
}

// markedFor reports whether a single-string field carries BOTH facts
// for this relay. Whitespace-delimited k=v parse: a check for relay
// "daal-fra-aabbccdd" must not be satisfied by "daal-fra-aabbccdde".
func markedFor(field, relay string) bool {
	if field == "" || relay == "" {
		return false
	}
	managed, mine := false, false
	for _, tok := range strings.Fields(field) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		switch k {
		case markManagedByKey:
			managed = managed || v == markManagedByValue
		case markRelayKey:
			mine = mine || v == relay
		}
	}
	return managed && mine
}

// derivedInstanceLabel is the relay's durable name: a pure function of
// (publisher pubkey, region). A match is proof this operator's own
// tooling minted it — the same construction the Hetzner adapter uses
// for its server name — which is what lets Decommission find a box
// whose id was never persisted.
func derivedInstanceLabel(pubKey []byte, region string) string {
	if len(pubKey) < 8 {
		return fmt.Sprintf("daal-%s-%x", region, pubKey)
	}
	return fmt.Sprintf("daal-%s-%s", region, hex.EncodeToString(pubKey[:8]))
}

// firewallGroupDescription names this relay's firewall group. Vultr
// caps a description at 255 characters; the mark is ~50.
func firewallGroupDescription(relay string) string {
	return ownershipMark(relay, "relay firewall")
}

// ephemeralKeyPrefix is the stem every one-shot SSH key for this relay
// shares. The sweep matches on it; nothing matches on a bare "daal-".
func ephemeralKeyPrefix(relay string) string { return relay + "-ephemeral-" }

// ownsEphemeralKey reports whether this key is one of THIS relay's
// one-shot provisioning keys. Vultr keys have no labels, so the derived
// name is the only handle — but the derived name is still a function of
// the operator's own publisher key, so it cannot collide with another
// operator's key on a shared account.
func ownsEphemeralKey(k SSHKeyInfo, relay string) bool {
	return relay != "" && strings.HasPrefix(k.Name, ephemeralKeyPrefix(relay))
}
