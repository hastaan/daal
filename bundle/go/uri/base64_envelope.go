package uri

import (
	"strings"
)

// parseSubscriptionEnvelope handles the de-facto Iranian provider envelope:
// an HTTPS URL serves a base64 body that decodes to one URI per line, mixed
// schemes. We also accept already-decoded plain multi-line input.
func parseSubscriptionEnvelope(body []byte) ([]Profile, Provenance, error) {
	text := strings.TrimSpace(string(body))
	// First, try to base64-decode the entire body (provider envelope).
	if dec, err := base64Decode(text); err == nil {
		text = strings.TrimSpace(string(dec))
	}
	// Now expect one URI per line.
	lines := strings.Split(text, "\n")
	var profiles []Profile
	prov := Provenance{Scheme: "subscription"}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, sub, err := ParseURI(line)
		if err != nil {
			prov.WarningCount++
			continue
		}
		prov.BareSchemes = append(prov.BareSchemes, sub.Scheme)
		profiles = append(profiles, p)
	}
	if len(profiles) == 0 {
		return nil, prov, ErrNoMatch
	}
	return profiles, prov, nil
}
