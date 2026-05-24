package share

import "strings"

// DetectURIs scans free text for known route URI schemes. Returns one
// hit per recognized line, in order. The function never imports anything;
// callers display a confirmation UI before importing.
type ClipboardHit struct {
	Scheme  string // "vless", "vmess", ... or "subscription" / "sip008" / "wireguard"
	URI     string // the unmodified line
	Preview string // a short, redacted preview (host:port#tag if available)
}

var knownSchemes = []string{
	"vless://", "vmess://", "trojan://", "ss://",
	"hysteria2://", "hy2://", "tuic://",
}

// DetectURIs returns hits. To honor V0.3 redaction rules, Preview never
// contains the userinfo portion (passwords, UUIDs).
func DetectURIs(text string) []ClipboardHit {
	if text == "" {
		return nil
	}
	out := []ClipboardHit{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, sch := range knownSchemes {
			if strings.HasPrefix(line, sch) {
				out = append(out, ClipboardHit{
					Scheme:  strings.TrimSuffix(sch, "://"),
					URI:     line,
					Preview: redactPreview(line),
				})
				break
			}
		}
	}
	return out
}

func redactPreview(uri string) string {
	// Strip everything between scheme://...@ to remove userinfo.
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return ""
	}
	rest := uri[idx+3:]
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	// Cut anything after first '?'.
	if q := strings.Index(rest, "?"); q >= 0 {
		rest = rest[:q]
	}
	return uri[:idx+3] + "•••@" + rest
}
