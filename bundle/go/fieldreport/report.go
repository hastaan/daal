// Package fieldreport is the network-test report, schema v2
// (specs/field-probe-v2.md, test-rigs/field-probe/schema/probe-report-v2.json):
// its types, its strict validation, the 16 KiB padding and the sealing
// to the publisher's report key (envelope.EncryptReport).
//
// It lives in bundle-go because both sides need it: core/fieldprobe
// builds and seals reports on the device, and the publisher's opener
// (`daal-deploy report-open`) decrypts and validates them. Neither side
// trusts the other's bytes: Open refuses anything the schema does not
// allow, field by field, closed enum by closed enum.
//
// PRIVACY BY CONSTRUCTION. Every string in a report is either a closed
// enum, a fixed-shape token (hex, bucket, probe id), or the person's own
// note. There is no field a host name, an address, an SSID or a carrier
// id could go in: `variant` is restricted to [a-z0-9_+-] (no dot, no
// colon), so even a bug cannot put "1.2.3.4" or "example.com" there.
package fieldreport

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"daal/bundle-go/envelope"
)

// SchemaVersion is the report schema this package writes and reads.
const SchemaVersion = 2

// PadBucket is the size every sealed plaintext is padded up to a
// multiple of, so the file's size says nothing about what was found.
const PadBucket = 16 * 1024

// MaxNotes is the longest note the person may add.
const MaxNotes = 500

// Report is one network test, as it leaves the device.
type Report struct {
	SchemaVersion       int    `json:"schema_version"`
	ReportID            string `json:"report_id"`
	GeneratedHourBucket string `json:"generated_hour_bucket"`
	Platform            string `json:"platform"`
	CountryHint         string `json:"country_hint"`
	CarrierClass        string `json:"carrier_class"`
	NetworkLabel        string `json:"network_label"`
	Net                 Net    `json:"net"`
	App                 App    `json:"app"`
	// RelayRef: the first 8 hex of SHA-256(relay_pack_id), or "none".
	RelayRef string    `json:"relay_ref"`
	Run      Run       `json:"run"`
	Probes   []Probe   `json:"probes"`
	Findings []Finding `json:"findings"`
	Failures []Failure `json:"failures"`
	Notes    string    `json:"notes,omitempty"`
}

// Net is what the device knew about the network, coarsely.
type Net struct {
	Kind          string `json:"kind"`
	Validated     string `json:"validated"`
	Metered       string `json:"metered"`
	IPv6Global    bool   `json:"ipv6_global"`
	PrivateDNS    string `json:"private_dns"`
	ResolverClass string `json:"resolver_class"`
}

// App is which build ran which list.
type App struct {
	Build              string `json:"build"`
	TargetsListVersion string `json:"targets_list_version"`
	TargetsListSHA256  string `json:"targets_list_sha256"`
	DesyncAvailable    bool   `json:"desync_available"`
	HelloFP            string `json:"hello_fp"`
}

// Run is how the test went as a whole.
type Run struct {
	Complete        bool   `json:"complete"`
	AbortReason     string `json:"abort_reason"`
	DurationBucketS int    `json:"duration_bucket_s"`
	StepsRun        int    `json:"steps_run"`
	ShortCircuit    bool   `json:"short_circuit"`
}

// Probe is one step's result.
type Probe struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	TargetRole string  `json:"target_role"`
	Variant    string  `json:"variant,omitempty"`
	Result     string  `json:"result"`
	Phase      string  `json:"phase"`
	Signals    Signals `json:"signals"`
}

// Signals are the measurements behind a result, bucketed.
type Signals struct {
	ConnectRTTBucketMs    string `json:"connect_rtt_bucket_ms,omitempty"`
	FirstEventRatioTenths *int   `json:"first_event_ratio_tenths,omitempty"`
	HelloAcked            *bool  `json:"hello_acked,omitempty"`
	RxBytesBucket         string `json:"rx_bytes_bucket,omitempty"`
	HTTPStatusClass       string `json:"http_status_class,omitempty"`
	DNSRcode              string `json:"dns_rcode,omitempty"`
	// CertValid: the server's chain verified against the device's roots
	// for the name in the hello (Stage B only; C4–C6 talk to the relay's
	// cover forward, whose certificate is not the question).
	CertValid *bool `json:"cert_valid,omitempty"`
	// HandshakeEnd: how a TLS handshake ended, apart from the first
	// event after the hello (a server flight, then a stall, is the
	// grey-cap shape; a real alert record is something else).
	HandshakeEnd string `json:"handshake_end,omitempty"`
	// HelloFP: which ClientHello this probe sent.
	HelloFP string `json:"hello_fp,omitempty"`
}

// Finding is one question the publisher wants answered.
type Finding struct {
	Question string   `json:"question"`
	Variant  string   `json:"variant,omitempty"`
	Answer   string   `json:"answer"`
	Basis    []string `json:"basis"`
}

// Failure is the v1 failure tally.
type Failure struct {
	Category    string `json:"category"`
	CountBucket int    `json:"count_bucket"`
}

// ---- closed sets ------------------------------------------------------

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

var (
	Platforms     = set("linux", "windows", "android", "macos", "ios", "unknown")
	CarrierClass  = set("mobile", "fixed", "wifi", "unknown")
	NetworkLabels = set("home_internet", "mci", "irancell", "rightel", "other_mobile", "work_or_public", "not_said")
	NetKinds      = set("wifi", "cellular", "ethernet", "other", "unknown")
	TriStates     = set("yes", "no", "unknown")
	PrivateDNS    = set("off", "auto", "strict", "unknown")
	ResolverClass = set("private", "isp_public", "well_known_public", "unknown")
	HelloFPs      = set("chrome_auto", "chrome_auto_h1", "go_std", "mixed", "none")
	AbortReasons  = set("", "cancelled", "backgrounded", "time_limit", "budget", "network_changed", "shutdown", "error",
		"local_blocked", "vpn_active", "connected")
	Durations     = map[int]bool{60: true, 120: true, 180: true, 240: true}

	ProbeNames = map[string]string{
		"A1": "dns_link_allowed", "A2": "dns_https_record", "A3": "dns_white_name",
		"A4": "dns_known_zone", "A5": "dns_calibration", "A6": "dns_public_resolver",
		"B1": "tls_baseline", "B2": "google_front", "B3": "google_front_redirect",
		"B4": "github_feed", "B5": "white_name_cdn", "B6": "cdn_neutral_carry",
		"B7": "ech", "B8": "ech_control", "B9": "quic_443",
		"C1": "relay_http_80", "C2": "relay_reality", "C3": "relay_reality_split",
		"C4": "relay_plain_white_sni", "C5": "relay_plain_cover_sni", "C6": "relay_plain_neutral_sni",
		"C7": "relay_alt_port", "C8": "relay_quic", "C9": "relay_reality_again",
	}
	TargetRoles = set("google", "github", "cf_edge", "white_name", "neutral_name", "relay", "known_zone", "public_resolver")
	Results     = set(
		"ok", "ok_carried", "reset_injected_likely", "reset", "silent_drop_forward", "silent_no_reply",
		"flow_capped_suspected", "refused", "closed", "tls_alert", "timeout", "auth_failed", "skipped",
		"bogon", "nxdomain", "servfail", "dns_timeout", "type_dropped", "answer_altered",
		"local_error", "unreachable", "dns_wrong_public", "cert_invalid",
	)
	Phases      = set("reach", "handshake", "carry", "none")
	RTTBuckets  = set("<20", "<40", "<80", "<160", "<320", "<640", ">=640")
	RxBuckets   = set("0", "<1.5k", "<4k", "<8k", "<16k", "<32k", ">=32k")
	HTTPClasses = set("1xx", "2xx", "3xx", "4xx", "5xx", "none")
	DNSRcodes   = set("noerror", "nxdomain", "servfail", "refused", "other")
	HSEnds      = set("ok", "alert", "rst", "fin", "timeout", "other")
	ProbeFPs    = set("chrome_auto", "chrome_auto_h1", "go_std")
	Questions   = set(
		"reality_443_works", "split_hello_helps", "white_name_helps_on_relay_ip",
		"white_name_uncapped_on_cdn_ip", "grey_cap_seen_on_cdn_ip", "reset_looks_injected",
		"cloudflare_edge_reachable", "ech_passes", "google_front_passes", "github_feed_fetchable",
		"resolver_recurses_foreign_zone", "dns_injection_on_path", "quic_443_alive",
		"relay_alt_ports_open", "test_changed_outcome",
	)
	Answers           = set("yes", "no", "unclear")
	FailureCategories = set(
		"dns_poisoned", "dns_timeout", "tcp_connect_timeout", "tcp_reset", "tls_handshake_failed",
		"tls_sni_or_cert_block_suspected", "udp_unavailable", "quic_unavailable", "auth_failed",
		"route_expired", "publisher_revoked", "publisher_key_changed", "subscription_unreachable",
		"engine_crash", "bundle_signature_invalid", "bundle_corrupted", "network_offline", "unknown",
		"flow_capped_suspected",
	)
)

var (
	reReportID = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	reHour     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00Z$`)
	reCountry  = regexp.MustCompile(`^[A-Z]{2}$|^unknown$`)
	reBuild    = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,48}$`)
	reListVer  = regexp.MustCompile(`^[0-9A-Za-z._-]{1,32}$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reRelayRef = regexp.MustCompile(`^[0-9a-f]{8}$|^none$`)
	reVariant  = regexp.MustCompile(`^[a-z0-9_+-]{0,40}$`)
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("fieldreport: report does not match schema v2")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Validate checks r against schema v2. It is the Go twin of
// probe-report-v2.json; the two are held together by a test.
func (r *Report) Validate() error {
	switch {
	case r.SchemaVersion != SchemaVersion:
		return bad("schema_version %d", r.SchemaVersion)
	case !reReportID.MatchString(r.ReportID):
		return bad("report_id")
	case !reHour.MatchString(r.GeneratedHourBucket):
		return bad("generated_hour_bucket")
	case !Platforms[r.Platform]:
		return bad("platform")
	case !reCountry.MatchString(r.CountryHint):
		return bad("country_hint")
	case !CarrierClass[r.CarrierClass]:
		return bad("carrier_class")
	case !NetworkLabels[r.NetworkLabel]:
		return bad("network_label")
	case !NetKinds[r.Net.Kind], !TriStates[r.Net.Validated], !TriStates[r.Net.Metered],
		!PrivateDNS[r.Net.PrivateDNS], !ResolverClass[r.Net.ResolverClass]:
		return bad("net")
	case !reBuild.MatchString(r.App.Build), !reListVer.MatchString(r.App.TargetsListVersion),
		!reSHA256.MatchString(r.App.TargetsListSHA256), !HelloFPs[r.App.HelloFP]:
		return bad("app")
	case !reRelayRef.MatchString(r.RelayRef):
		return bad("relay_ref")
	case !AbortReasons[r.Run.AbortReason], !Durations[r.Run.DurationBucketS],
		r.Run.StepsRun < 0, r.Run.StepsRun > 64:
		return bad("run")
	case r.Probes == nil, r.Findings == nil, r.Failures == nil:
		return bad("probes, findings and failures must be present")
	case len(r.Probes) > 96, len(r.Findings) > 32, len(r.Failures) > 32:
		return bad("too many entries")
	case len([]rune(r.Notes)) > MaxNotes:
		return bad("notes longer than %d", MaxNotes)
	}
	for i, p := range r.Probes {
		if err := p.validate(); err != nil {
			return bad("probes[%d]: %v", i, err)
		}
	}
	for i, f := range r.Findings {
		if !Questions[f.Question] || !Answers[f.Answer] || !reVariant.MatchString(f.Variant) || len(f.Basis) > 24 {
			return bad("findings[%d]", i)
		}
		for _, id := range f.Basis {
			if _, ok := ProbeNames[id]; !ok {
				return bad("findings[%d].basis", i)
			}
		}
	}
	for i, f := range r.Failures {
		if !FailureCategories[f.Category] || f.CountBucket < 0 || f.CountBucket > 10000 {
			return bad("failures[%d]", i)
		}
	}
	return nil
}

func (p Probe) validate() error {
	name, ok := ProbeNames[p.ID]
	switch {
	case !ok:
		return errors.New("id")
	case p.Name != name:
		return errors.New("name does not match id")
	case !TargetRoles[p.TargetRole]:
		return errors.New("target_role")
	case !reVariant.MatchString(p.Variant):
		return errors.New("variant")
	case !Results[p.Result]:
		return errors.New("result")
	case !Phases[p.Phase]:
		return errors.New("phase")
	}
	s := p.Signals
	switch {
	case s.ConnectRTTBucketMs != "" && !RTTBuckets[s.ConnectRTTBucketMs]:
		return errors.New("signals.connect_rtt_bucket_ms")
	case s.FirstEventRatioTenths != nil && (*s.FirstEventRatioTenths < 0 || *s.FirstEventRatioTenths > 100):
		return errors.New("signals.first_event_ratio_tenths")
	case s.RxBytesBucket != "" && !RxBuckets[s.RxBytesBucket]:
		return errors.New("signals.rx_bytes_bucket")
	case s.HTTPStatusClass != "" && !HTTPClasses[s.HTTPStatusClass]:
		return errors.New("signals.http_status_class")
	case s.DNSRcode != "" && !DNSRcodes[s.DNSRcode]:
		return errors.New("signals.dns_rcode")
	case s.HandshakeEnd != "" && !HSEnds[s.HandshakeEnd]:
		return errors.New("signals.handshake_end")
	case s.HelloFP != "" && !ProbeFPs[s.HelloFP]:
		return errors.New("signals.hello_fp")
	}
	return nil
}

// ---- buckets ------------------------------------------------------------

// RTTBucket buckets a round-trip time in milliseconds.
func RTTBucket(ms int64) string {
	for _, b := range []struct {
		lim int64
		s   string
	}{{20, "<20"}, {40, "<40"}, {80, "<80"}, {160, "<160"}, {320, "<320"}, {640, "<640"}} {
		if ms < b.lim {
			return b.s
		}
	}
	return ">=640"
}

// RxBucket buckets a received byte count.
func RxBucket(n int64) string {
	switch {
	case n <= 0:
		return "0"
	case n < 1536:
		return "<1.5k"
	case n < 4096:
		return "<4k"
	case n < 8192:
		return "<8k"
	case n < 16384:
		return "<16k"
	case n < 32768:
		return "<32k"
	}
	return ">=32k"
}

// HTTPClass is the class of an HTTP status code ("none" for 0).
func HTTPClass(code int) string {
	if code >= 100 && code < 600 {
		return fmt.Sprintf("%dxx", code/100)
	}
	return "none"
}

// DurationBucket rounds a run's length in seconds UP to 60/120/180/240.
func DurationBucket(sec int) int {
	for _, b := range []int{60, 120, 180} {
		if sec <= b {
			return b
		}
	}
	return 240
}

// CountBucket buckets a failure count (0, 1, 2, 3, 5, 10, 10000).
func CountBucket(n int) int {
	for _, b := range []int{0, 1, 2, 3, 5, 10} {
		if n <= b {
			return b
		}
	}
	return 10000
}

// NewReportID is 26 random Crockford base32 characters. NOT a ULID: a
// ULID's first ten characters are the creation time to the millisecond,
// which the report must not carry (hour bucket only). The shape is the
// v1 pattern, so v1 tooling still recognises it.
func NewReportID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var raw [26]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	for i := range raw {
		raw[i] = alphabet[raw[i]&31]
	}
	return string(raw[:]), nil
}

// ---- encoding, padding, sealing -----------------------------------------

// Marshal validates r and returns its JSON.
func (r *Report) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// Pad appends spaces up to the next multiple of PadBucket. JSON allows
// trailing whitespace, so a padded report still parses as itself.
func Pad(body []byte) []byte {
	n := (len(body)/PadBucket + 1) * PadBucket
	out := make([]byte, n)
	copy(out, body)
	for i := len(body); i < n; i++ {
		out[i] = ' '
	}
	return out
}

// Parse decodes a report strictly (no unknown field anywhere, nothing
// after the object but whitespace) and validates it.
func Parse(body []byte) (*Report, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimRight(body, " \t\r\n")))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, bad("trailing data")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Seal validates, pads and encrypts r to the report address
// (`daal1…`). The result is the bytes of the file the person shares.
func Seal(r *Report, reportTo string) ([]byte, error) {
	pub, err := DecodeAddress(reportTo)
	if err != nil {
		return nil, err
	}
	body, err := r.Marshal()
	if err != nil {
		return nil, err
	}
	return envelope.EncryptReport(Pad(body), pub)
}

// Open decrypts a sealed report with the report key and returns it,
// strictly parsed. The caller still treats it as untrusted: age does
// not say who made it.
func Open(sealed []byte, priv [32]byte) (*Report, error) {
	plain, err := envelope.DecryptReport(sealed, priv)
	if err != nil {
		return nil, err
	}
	return Parse(plain)
}

// SealedFileName is the neutral name of the shared file: no app name,
// no date — `net-` and 8 random lowercase letters and digits, `.dat`.
func SealedFileName() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	var b strings.Builder
	b.WriteString("net-")
	for _, c := range raw {
		b.WriteByte(alphabet[c&31])
	}
	b.WriteString(".dat")
	return b.String()
}
