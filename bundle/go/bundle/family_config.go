package bundle

import (
	"bytes"
	"encoding/json"
)

// EngineFamilyConfigKeys are the members of a route's signed
// family_specific_config that the importer keeps on the route's row
// (routestore RouteRow.FamilySpecificConfigJSON) for the engine to read
// at connect time: the pack's desync offer (core/desync pack.go) and the
// cover-name list (cover_names.go).
//
// An allowlist, deliberately. The row is NOT the encrypted half of the
// store (the outbound itself lives age-encrypted in secrets_kv), and
// family_specific_config also carries `_endpoint` — the relay's address
// and keys — which must never be copied there. A member is added here
// only when the engine reads it and it holds no address, key or secret.
var EngineFamilyConfigKeys = []string{"_desync", CoverNamesKey}

// EngineFamilyConfig returns the part of a route's signed
// family_specific_config the engine reads (EngineFamilyConfigKeys), as a
// JSON object; "" when the config carries none of them or is not an
// object. Members are copied as signed (whitespace aside); their parsers
// (desync.OfferFromFamilyConfig, CoverNamesFromFamilyConfig) are the
// ones that decide whether they are usable.
func EngineFamilyConfig(familySpecificConfig json.RawMessage) string {
	if len(bytes.TrimSpace(familySpecificConfig)) == 0 {
		return ""
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(familySpecificConfig, &all); err != nil {
		return ""
	}
	kept := map[string]json.RawMessage{}
	for _, k := range EngineFamilyConfigKeys {
		if v, ok := all[k]; ok {
			kept[k] = v
		}
	}
	if len(kept) == 0 {
		return ""
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return ""
	}
	return string(out)
}
