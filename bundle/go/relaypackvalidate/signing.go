package relaypackvalidate

// signing.go — checks the PUBLISHER runs before it signs a RelayPack,
// for the members the optional add-ons put into family_specific_config
// (`_cdn_endpoint`, `_standby`; specs/relaypack-v1.md).
//
// They are deliberately NOT part of Validate. Validate also runs on every
// recipient, and any error there refuses the whole pack. These members
// were added so that a build that cannot use one degrades by a route,
// never by the pack (bundle/cdn_endpoint.go, bundle/standby.go); a
// recipient-side rule that refused a shape it does not know would undo
// exactly that for the next version. On the signing side the opposite
// holds: a publisher must never sign a member its own build cannot
// enforce.

import (
	"encoding/json"
	"errors"
	"fmt"

	"daal/bundle-go/bundle"
)

// ValidateForSigning enforces RP026 and RP027 on a pack about to be
// signed. nil when every route's add-on members are well formed (or
// absent). It does not repeat Validate; the signer runs both.
func ValidateForSigning(b *bundle.Bundle) error {
	if b == nil {
		return &ValidationError{Code: "RP000", Message: "nil bundle"}
	}
	standbyByServer := map[string]string{}
	routesByServer := map[string][]string{}
	for _, r := range b.Manifest.Routes {
		entry, err := bundle.ParseRelayPackEntry(r.FamilySpecificConfig)
		cdnFronted := err == nil && entry != nil && entry.ExposureMode == "cdn_fronted"
		hasCDN := bundle.HasCDNEndpoint(r.FamilySpecificConfig)
		ep, epErr := bundle.ParseEndpoint(r.FamilySpecificConfig)
		hasEP := !errors.Is(epErr, bundle.ErrNoEndpoint)

		fail26 := func(format string, args ...any) error {
			return &ValidationError{Code: CodeRP026, Pointer: r.ID, Message: fmt.Sprintf(format, args...)}
		}
		switch {
		case cdnFronted:
			if hasEP {
				return fail26("a cdn_fronted candidate carries _endpoint; its commitment belongs in _cdn_endpoint alone")
			}
			cep, err := bundle.ParseCDNEndpoint(r.TransportFamily, r.FamilySpecificConfig)
			if err != nil {
				return fail26("cdn_fronted candidate: %v", err)
			}
			if cep.ECHConfig == "" && !cep.PlainFallback {
				return fail26("cdn_fronted candidate can never be dialled: no ech_config and plain_fallback is off")
			}
		case hasCDN:
			return fail26("_cdn_endpoint on a candidate that is not cdn_fronted")
		}

		if _, err := bundle.ParseStandby(r.FamilySpecificConfig); errors.Is(err, bundle.ErrNoStandby) {
			if hasEP && epErr == nil && r.TransportFamily != string(bundle.TransportShadowsocks) {
				routesByServer[ep.Server] = append(routesByServer[ep.Server], "")
			}
			continue
		}
		fail27 := func(format string, args ...any) error {
			return &ValidationError{Code: CodeRP027, Pointer: r.ID, Message: fmt.Sprintf(format, args...)}
		}
		if epErr != nil {
			return fail27("_standby on a candidate with no usable direct _endpoint")
		}
		if _, err := bundle.StandbyForRoute(r.TransportFamily, r.FamilySpecificConfig, ep); err != nil {
			return fail27("%v", err)
		}
		raw, _ := rawMember(r.FamilySpecificConfig, bundle.StandbyKey)
		canon, err := canonicalJSON(raw)
		if err != nil {
			return fail27("_standby: %v", err)
		}
		if prev, ok := standbyByServer[ep.Server]; ok && prev != canon {
			return fail27("routes of the same relay address carry different _standby members")
		}
		standbyByServer[ep.Server] = canon
		routesByServer[ep.Server] = append(routesByServer[ep.Server], canon)
	}
	// One relay, one standby: every committable route of an address that
	// has one carries it (shadowsocks excepted).
	for server, list := range routesByServer {
		want, ok := standbyByServer[server]
		if !ok {
			continue
		}
		for _, got := range list {
			if got != want {
				return &ValidationError{Code: CodeRP027, Pointer: "manifest",
					Message: "a route of a relay address with a standby does not carry its _standby"}
			}
		}
	}
	return nil
}

func rawMember(object json.RawMessage, key string) ([]byte, bool) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(object, &probe) != nil {
		return nil, false
	}
	raw, ok := probe[key]
	return raw, ok
}

func canonicalJSON(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}
