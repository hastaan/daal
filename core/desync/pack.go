package desync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// PackKey is the member of a route's signed family_specific_config that
// carries the publisher's desync offer, beside `_endpoint` and
// `_relaypack`. The manifest signature covers family_specific_config;
// the profile bytes (the sing-box outbound) it is NOT — so a strategy
// in the outbound JSON would be unauthenticated, and one here is signed.
// An engine that predates this key ignores it (the parsers of the other
// members read only their own key), so a publisher can ship it without
// stranding older phones.
const PackKey = "_desync"

// Apply says what the engine does with a pack's strategy on its own.
const (
	// ApplyOffer (the default): the strategy is available to the
	// selection ladder for this route and is NOT used until the ladder
	// turns it on for a network (core/engine SetRouteDesync). The plan's
	// rule: the fragmentation pattern is itself classifiable, so it is
	// remembered per network, never an unconditional default.
	ApplyOffer = "offer"
	// ApplyAlways: every connection of this route would use it, unless
	// the ladder forces it off for the current network. This engine
	// HOLDS it as an offer (core/engine packAlwaysAllowed) until the
	// tls_fragment modifier has a PASS record: a pack cannot make a cut
	// pattern a fleet-wide default on its own. Parsed, so a pack that
	// says it is not refused.
	ApplyAlways = "always"
)

// Offer is the `_desync` member:
//
//	"_desync": {"v": 1, "apply": "offer", "strategy": {"preset": "sni-cut"}}
type Offer struct {
	V        int             `json:"v"`
	Apply    string          `json:"apply,omitempty"`
	Strategy json.RawMessage `json:"strategy"`

	// parsed is Strategy decoded and Normalized.
	parsed Strategy
}

// ErrNoOffer: the route's config carries no `_desync` member.
var ErrNoOffer = errors.New("desync: no offer in family_specific_config")

// OfferFromFamilyConfig reads the `_desync` member of a route's
// family_specific_config. ErrNoOffer when absent; any other error means
// the member is there and unusable — the caller treats the route as
// having no strategy (OFF), never as having a default one.
func OfferFromFamilyConfig(familySpecificConfig []byte) (Offer, error) {
	if len(bytes.TrimSpace(familySpecificConfig)) == 0 {
		return Offer{}, ErrNoOffer
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &probe); err != nil {
		return Offer{}, fmt.Errorf("desync: family_specific_config: %w", err)
	}
	raw, ok := probe[PackKey]
	if !ok {
		return Offer{}, ErrNoOffer
	}
	var o Offer
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return Offer{}, fmt.Errorf("desync: %s: %w", PackKey, err)
	}
	if o.V != 1 {
		return Offer{}, fmt.Errorf("desync: %s: version %d, this engine reads 1", PackKey, o.V)
	}
	switch o.Apply {
	case "":
		o.Apply = ApplyOffer
	case ApplyOffer, ApplyAlways:
	default:
		return Offer{}, fmt.Errorf("desync: %s: apply %q, want offer|always", PackKey, o.Apply)
	}
	s, err := ParseStrategy(o.Strategy)
	if err != nil {
		return Offer{}, err
	}
	if !s.Enabled() {
		return Offer{}, fmt.Errorf("desync: %s: the strategy cuts nothing", PackKey)
	}
	o.parsed = s
	return o, nil
}

// StrategyValue is the offer's strategy, Normalized.
func (o Offer) StrategyValue() Strategy { return o.parsed }
