package publisher

import (
	"fmt"
	"strings"
	"time"
)

// ParseDuration accepts Go duration syntax extended with "d" (days) and
// "w" (weeks). It supports a single trailing unit, e.g. "14d", "2w", "336h",
// "30m".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") {
		body := strings.TrimSuffix(s, "d")
		d, err := time.ParseDuration(body + "h")
		if err != nil {
			return 0, fmt.Errorf("invalid days duration %q: %w", s, err)
		}
		return d * 24, nil
	}
	if strings.HasSuffix(s, "w") {
		body := strings.TrimSuffix(s, "w")
		d, err := time.ParseDuration(body + "h")
		if err != nil {
			return 0, fmt.Errorf("invalid weeks duration %q: %w", s, err)
		}
		return d * 24 * 7, nil
	}
	return time.ParseDuration(s)
}
