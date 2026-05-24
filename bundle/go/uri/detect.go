package uri

import (
	"net/textproto"
	"strconv"
	"strings"
)

// SubscriptionMeta is the small subset of the Iranian-provider metadata
// header we want to pass through to the importer.
type SubscriptionMeta struct {
	UserInfo              map[string]string
	ProfileTitle          string
	ProfileUpdateInterval int // hours
	SupportURL            string
	MovedPermanentlyTo    string // Hiddify extension
}

// ParseSubscriptionHeaders extracts known subscription header fields from
// an HTTP-shaped header block. Headers we do not know are ignored.
func ParseSubscriptionHeaders(headers textproto.MIMEHeader) SubscriptionMeta {
	m := SubscriptionMeta{}
	if v := headers.Get("Subscription-Userinfo"); v != "" {
		m.UserInfo = parseUserInfo(v)
	}
	m.ProfileTitle = headers.Get("Profile-Title")
	if v := headers.Get("Profile-Update-Interval"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			m.ProfileUpdateInterval = n
		}
	}
	m.SupportURL = headers.Get("Support-URL")
	m.MovedPermanentlyTo = headers.Get("Moved-Permanently-To")
	return m
}

func parseUserInfo(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		idx := strings.Index(kv, "=")
		if idx < 0 {
			continue
		}
		out[strings.TrimSpace(kv[:idx])] = strings.TrimSpace(kv[idx+1:])
	}
	return out
}
