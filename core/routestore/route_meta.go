package routestore

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// RouteMeta is what the engine itself knows about a route it is about
// to import and that the file carrying the route does not say: today a
// pasted link (core/abi URIImport), which is wrapped in a bundle signed
// by this phone's own sharing identity. Kept in the encrypted secrets
// table under RouteMetaKey(route id), never on the route row: the name
// a link gives itself can name its provider.
//
//   - ManualOnly: the route is dialled only when the person picks it.
//     UpsertRoute reads it when the row is written, so the row is
//     never, even for an instant, an ordinary route an automatic
//     connect could race (RouteRow.ManualOnly).
//   - Name: the link's own name (its #fragment, or VMess `ps`), for
//     DISPLAY ONLY (core/abi d2_summaries.go route_nickname). Cleaned
//     by CleanRouteName on the way in and on the way out. Nothing may
//     match, route, log or decide on it.
//   - At: when it was written (RFC 3339, hour bucket): PruneRouteMeta
//     drops a name left behind by a paste whose import never finished.
type RouteMeta struct {
	ManualOnly bool   `json:"manual_only,omitempty"`
	Name       string `json:"name,omitempty"`
	At         string `json:"at,omitempty"`
}

// RouteMetaKey is the secrets_kv key of a route's meta. Removed with the
// route (perRouteSecretKeys).
func RouteMetaKey(routeID string) string { return "route-meta:" + routeID }

// MaxRouteNameRunes bounds a route's display name. A link name is a
// label ("Germany 2", "🇩🇪 fast"), not a paragraph; 48 runes fit one line
// of the route card on a phone and leave no room for a hidden message.
const MaxRouteNameRunes = 48

// CleanRouteName makes a link's name safe to show: control characters
// (C0, C1, DEL), bidi controls (the embeddings, overrides and isolates,
// LRM/RLM/ALM: they can reverse what the next text on the line reads as)
// and other format characters (zero-width joiners excepted, which emoji
// flags and sequences need) are removed; runs of white space become one
// space; the result is trimmed and cut to MaxRouteNameRunes. Invalid
// UTF-8 is dropped. "" when nothing is left.
func CleanRouteName(s string) string {
	var b strings.Builder
	n := 0
	space := false
	for i := 0; i < len(s) && n < MaxRouteNameRunes; {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			continue
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), isBidiControl(r):
			continue
		case unicode.Is(unicode.Cf, r) && r != 0x200D: // ZWJ stays (emoji)
			continue
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
			if n >= MaxRouteNameRunes {
				break
			}
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func isBidiControl(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F: // ALM, LRM, RLM
		return true
	case r >= 0x202A && r <= 0x202E: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	}
	return false
}

// PutRouteMeta writes a route's meta (the name cleaned, At set to now's
// hour). An empty meta (no flag, no name) removes what is held.
func (s *Store) PutRouteMeta(routeID string, m RouteMeta, now time.Time) error {
	m.Name = CleanRouteName(m.Name)
	if !m.ManualOnly && m.Name == "" {
		return s.DeleteSecret(RouteMetaKey(routeID))
	}
	m.At = HourBucket(now)
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.PutSecret(RouteMetaKey(routeID), body)
}

// GetRouteMeta reads a route's meta; ok=false when none is held or it
// cannot be read. The name comes back cleaned.
func (s *Store) GetRouteMeta(routeID string) (RouteMeta, bool) {
	body, err := s.GetSecret(RouteMetaKey(routeID))
	if err != nil || len(body) == 0 {
		return RouteMeta{}, false
	}
	var m RouteMeta
	if json.Unmarshal(body, &m) != nil {
		return RouteMeta{}, false
	}
	m.Name = CleanRouteName(m.Name)
	return m, true
}

// routeMetaOrphanAge: a meta whose route was never stored (the trust
// prompt for a paste was cancelled, or never answered) is dropped once
// it is this old.
const routeMetaOrphanAge = 31 * 24 * time.Hour

// PruneRouteMeta removes the metas of routes that are not stored and
// were written more than routeMetaOrphanAge ago. A meta that marks a
// route manual-only is kept whatever its age: a trust prompt can be
// answered late (pending prompts are persisted), and the import that
// follows must still find the flag. Best effort; returns how many it
// removed.
func (s *Store) PruneRouteMeta(now time.Time) (int, error) {
	keys, err := s.ListSecretKeys("route-meta:")
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, k := range keys {
		id := strings.TrimPrefix(k, "route-meta:")
		if _, err := s.GetRoute(id); err == nil {
			continue
		}
		m, ok := s.GetRouteMeta(id)
		if ok && m.ManualOnly {
			continue
		}
		if ok {
			at, err := time.Parse(time.RFC3339, m.At)
			if err == nil && now.Sub(at) < routeMetaOrphanAge {
				continue
			}
		}
		if s.DeleteSecret(k) == nil {
			removed++
		}
	}
	return removed, nil
}
