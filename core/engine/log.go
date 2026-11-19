package engine

import (
	"regexp"
	"strings"
	"sync/atomic"
)

// Engine logging.
//
// On Android the lines go to logcat under the tag "daalengine"
// (androidlog_android.go); elsewhere they are dropped unless
// DAAL_ENGINE_LOG is set, in which case they go to stderr
// (androidlog_other.go). The first real-phone pass produced NOTHING in
// logcat for a connect, a switch and three failing screens; these
// lines are what a helper reads next time.
//
// Every line passes through Scrub. Callers still must not build a line
// out of secrets: Scrub is the net, not the plan. Never pass it a
// config, a profile, a pack or a key and rely on the patterns.

const (
	logLevelInfo  = 4 // ANDROID_LOG_INFO
	logLevelError = 6 // ANDROID_LOG_ERROR
)

// logTap, when set, receives every line after scrubbing. Tests only.
var logTap atomic.Pointer[func(level int, line string)]

// SetLogTapForTest installs f (nil removes it) and returns a restore
// function.
func SetLogTapForTest(f func(level int, line string)) (restore func()) {
	prev := logTap.Load()
	if f == nil {
		logTap.Store(nil)
	} else {
		logTap.Store(&f)
	}
	return func() { logTap.Store(prev) }
}

// LogInfo writes one scrubbed line at Info.
func LogInfo(msg string) { emitLog(logLevelInfo, msg) }

// LogError writes one scrubbed line at Error.
func LogError(msg string) { emitLog(logLevelError, msg) }

func emitLog(level int, msg string) {
	line := Scrub(msg)
	if tap := logTap.Load(); tap != nil {
		(*tap)(level, line)
	}
	platformLog(level, line)
}

// IsErrorLevel reports whether a level handed to a log tap is Error.
func IsErrorLevel(level int) bool { return level == logLevelError }

// scrubMax bounds one line. An error that needs more than this to say
// what class of thing went wrong is carrying data, not a diagnosis.
const scrubMax = 240

var (
	scrubURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>]+`)
	// A JSON-ish secret assignment: "password":"…", uuid=…, token: ….
	scrubKV   = regexp.MustCompile(`(?i)("?(?:password|passwd|secret|token|uuid|private[_-]?key|public[_-]?key|pre[_-]?shared[_-]?key|psk|short[_-]?id|auth|authorization|credential|username|user)"?\s*[:=]\s*)("[^"]*"|[^\s,;}]+)`)
	scrubUUID = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	scrubV6Br = regexp.MustCompile(`\[[0-9A-Fa-f:.%a-z]*:[0-9A-Fa-f:.%a-z]*\](?::\d{1,5})?`)
	scrubV4   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)
	// Hex groups with at least two colons between them, "::" included.
	// It also takes a clock time like 12:34:56, which is no loss.
	scrubV6 = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4})?(?::[0-9a-f]{0,4}){2,}`)
	// name.name[.name…][:port] — a host name. File names the engine
	// itself produces are let through (scrubKeepSuffix).
	scrubHost = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,23}(?::\d{1,5})?\b`)
	// A long unbroken run of key-alphabet characters: base64, hex, an
	// age identity, a bearer token. See looksLikeToken for which runs
	// are removed.
	scrubBlob = regexp.MustCompile(`[A-Za-z0-9+/_\-]{24,}`)
)

// scrubKeepSuffix are the dotted names that are the engine's own files
// and Go identifiers, not hosts.
var scrubKeepSuffix = []string{".json", ".db", ".key", ".sbp", ".sbpx", ".go", ".so", ".share", ".wasm"}

// Scrub removes what must never reach a log or a shared diagnostics
// blob from free text: URLs, IP addresses and host names (with or
// without a port), UUIDs, credential-looking assignments and any long
// token. It errs toward removing too much. The result is one line of
// at most scrubMax bytes.
func Scrub(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = scrubURL.ReplaceAllString(s, "<url>")
	s = scrubKV.ReplaceAllString(s, "${1}<redacted>")
	s = scrubUUID.ReplaceAllString(s, "<redacted>")
	s = scrubV6Br.ReplaceAllString(s, "<addr>")
	s = scrubV4.ReplaceAllString(s, "<addr>")
	s = scrubV6.ReplaceAllString(s, "<addr>")
	s = scrubHost.ReplaceAllStringFunc(s, func(m string) string {
		lower := strings.ToLower(m)
		for _, sfx := range scrubKeepSuffix {
			if strings.HasSuffix(lower, sfx) {
				return m
			}
		}
		return "<host>"
	})
	s = scrubBlob.ReplaceAllStringFunc(s, func(m string) string {
		if looksLikeToken(m) {
			return "<redacted>"
		}
		return m
	})
	if len(s) > scrubMax {
		cut := scrubMax
		for cut > 0 && s[cut]&0xC0 == 0x80 { // do not split a rune
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// looksLikeToken separates key material from the engine's own long
// names ("engine_subscription_list", "tcp_connect_timeout"): a run is a
// token when it holds a digit, or mixes upper and lower case. The
// engine's names are lower-case words; encoded bytes almost never are.
func looksLikeToken(m string) bool {
	var digit, upper, lower bool
	for i := 0; i < len(m); i++ {
		switch c := m[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		}
	}
	return digit || (upper && lower) || (upper && !lower && len(m) >= 32)
}

// LogID renders an identifier a caller supplied (a route id) for a log
// line: bounded, and reduced to the characters an id is made of, so a
// host that passes something else in the id argument cannot put it in
// the log.
func LogID(id string) string {
	const max = 64
	var b strings.Builder
	for _, r := range id {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
