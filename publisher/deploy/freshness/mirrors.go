package freshness

// mirrors.go carries the FRP-8 mirror set: the N freshness
// endpoints, across N DISTINCT providers, that one signed pack
// points at.
//
// WHY A SET AND NOT A URL. A freshness endpoint is a fixed URL
// baked into a signed pack. It is therefore itself a censorship
// target with the same shelf life as any other fixed endpoint —
// arguably a shorter one, because it is small, unique, pollable
// and cheap to enumerate: a censor who has one recipient's pack
// has the URL every other recipient of that publisher will poll.
// A single-URL freshness path is one DNS entry away from turning
// the whole recovery mechanism off. So the pack carries a set,
// the recipient tries the members in RANDOMISED order, and the
// bootstrap-pointer envelope is the layer below when every
// member is blocked.
//
// The type is built so a single-URL pack cannot be expressed:
// there is no exported one-URL constructor, NewMirrorSet refuses
// fewer than MinMirrors entries, and it refuses two entries that
// share a provider or a host. A future caller who wants one host
// has to delete code to get it, which is the point — a comment
// asking them not to would not survive.
//
// HOW A PUBLISHER CONFIGURES THIS. The provider label is the
// publisher's declaration of which storage accounts they hold:
// `daal-deploy bind-and-sign --freshness-mirror r2=https://…
// --freshness-mirror ghpages=https://…`. The label is not
// cosmetic — distinctness of labels is what the type enforces,
// so two buckets in the same Cloudflare account cannot masquerade
// as diversity.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"daal/bundle-go/bundle"
)

// MirrorsArchivePath is the .sbp archive entry that carries the
// signed mirror set.
//
// It is a separate archive entry rather than a new field on
// bundle.RelayPack for one hard reason: bundle.VerifyManifest
// verifies the signature over CanonicalManifestJSON(manifest),
// which is re-marshalled FROM THE PARSED STRUCT. A field an
// already-distributed client does not know is dropped on its side
// before canonicalisation, so its computed body no longer matches
// the signature and it rejects the ENTIRE pack — not just the new
// field. Adding a manifest field is a wire break for every
// recipient in the field, which under blackout conditions is the
// one thing this wave exists to avoid. The FRP-11 cell documents
// (trust/cell-membership.json, trust/cell-delegation.json) took
// exactly this route for exactly this reason and sbp.go records
// it: "VerifyBundle is intentionally NOT extended; older clients
// continue to verify the bundle."
//
// The entry therefore carries its own signature, chained to the
// same publisher root (or FRP-7.5 sub-key) as the manifest.
//
// The literal lives in bundle.FreshnessMirrorsPath — the module the
// publisher and the recipient both already depend on — so a rename on
// one side cannot leave the publisher writing an entry no recipient
// looks for. That failure is silent in both directions: the pack still
// verifies and the mirrors simply vanish.
const MirrorsArchivePath = bundle.FreshnessMirrorsPath

// MirrorsKind is the mirror document's kind discriminator.
const MirrorsKind = "daal/freshness-mirrors-v1"

// MinMirrors is the floor on distinct providers per pack. Two is
// not "enough"; it is the smallest number for which the word
// "fallback" means anything. Publishers with three accounts
// should use three.
const MinMirrors = 2

// MaxMirrors bounds the set. The document is attacker-supplied
// bytes on the recipient side and every member is a URL the
// device will poll, so the count is capped.
//
// IT MUST EQUAL core/refresh.maxFreshnessEndpoints, and did not.
// The publisher accepted 8 while every recipient truncated at 6 —
// and both sides order mirrors by the same deterministic
// (provider, url) sort, so it was always the SAME two providers
// that fell off, on every device in the fleet, identically. A
// publisher with eight storage accounts saw an eight-way-redundant
// panel while a censor only had to block six. A cap the publisher
// cannot see is worse than a smaller cap the publisher is told
// about, so the publisher's ceiling is now the device's budget.
const MaxMirrors = 6

// Provider is the storage-provider label of one mirror. The label
// is the unit of independence: two mirrors with the same label
// are assumed to fail together.
type Provider string

// The providers this build ships uploaders for. Any other
// lowercase token is accepted (a publisher's own static host, a
// third-party pinning service) — the set is open because the
// point is provider DIVERSITY, and an enum would cap it at
// whatever we thought of today.
const (
	ProviderR2      Provider = "r2"
	ProviderGHPages Provider = "ghpages"
	ProviderIPFS    Provider = "ipfs" // reserved; backends/ipfs is disabled
)

var providerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,15}$`)

// Mirror is one freshness endpoint.
type Mirror struct {
	Provider Provider `json:"provider"`
	URL      string   `json:"url"`
}

// MirrorSet is a validated, deterministically-ordered set of
// mirrors. The slice is unexported so the invariants cannot be
// bypassed by constructing the struct literal.
type MirrorSet struct {
	mirrors []Mirror
}

// errors -------------------------------------------------------

var (
	// ErrTooFewMirrors is returned when a caller tries to express
	// a freshness endpoint with fewer than MinMirrors distinct
	// providers. This is the error that makes single-URL
	// freshness unrepresentable.
	ErrTooFewMirrors = fmt.Errorf("freshness: at least %d mirrors on distinct providers are required", MinMirrors)

	// ErrDuplicateProvider is returned when two mirrors share a
	// provider label — the same failure domain wearing two URLs.
	ErrDuplicateProvider = errors.New("freshness: two mirrors share a provider label")

	// ErrDuplicateHost is returned when two mirrors share a host.
	ErrDuplicateHost = errors.New("freshness: two mirrors share a host")

	// ErrMirrorsMismatch is returned by VerifyMirrors when the
	// document does not belong to the pack it was found in.
	ErrMirrorsMismatch = errors.New("freshness: mirror document does not match this pack")
)

// NewMirrorSet validates and orders the supplied mirrors.
//
// Ordering is by (provider, url) so the set — and therefore the
// signed bytes and the pack that embeds them — is a pure function
// of its members, independent of the order the operator typed the
// flags in. BindAndSign's determinism contract depends on this.
func NewMirrorSet(mirrors []Mirror) (*MirrorSet, error) {
	if len(mirrors) < MinMirrors {
		return nil, ErrTooFewMirrors
	}
	if len(mirrors) > MaxMirrors {
		return nil, fmt.Errorf("freshness: at most %d mirrors (got %d)", MaxMirrors, len(mirrors))
	}
	out := make([]Mirror, 0, len(mirrors))
	seenProvider := map[Provider]bool{}
	seenHost := map[string]bool{}
	for _, m := range mirrors {
		if !providerRe.MatchString(string(m.Provider)) {
			return nil, fmt.Errorf("freshness: bad provider label %q (want ^[a-z0-9][a-z0-9-]{1,15}$)", m.Provider)
		}
		if err := ValidateMirrorURL(m.URL); err != nil {
			return nil, fmt.Errorf("freshness: mirror %s: %w", m.Provider, err)
		}
		if seenProvider[m.Provider] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateProvider, m.Provider)
		}
		seenProvider[m.Provider] = true
		host := strings.ToLower(mustHost(m.URL))
		if seenHost[host] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateHost, host)
		}
		seenHost[host] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].URL < out[j].URL
	})
	return &MirrorSet{mirrors: out}, nil
}

// SharedDomains reports mirrors whose hostnames share a registrable
// domain, grouped. An empty result means no two mirrors are obviously
// the same failure domain.
//
// WHY THIS IS A WARNING AND NOT A REFUSAL. "Distinct providers" is
// enforced here as distinct LABELS plus distinct HOSTS, and neither is
// evidence of a distinct failure domain. Two subdomains of one zone
// (`a.pub.example` and `b.pub.example`) is the common way an operator
// accidentally buys nothing: one registration, one account, one
// takedown. That is worth naming out loud — but it is also a legitimate
// configuration when the two subdomains genuinely point into different
// providers' storage, so refusing it would block a working setup.
//
// WHAT IT CANNOT SEE, and this must never be presented as if it could:
// two different registrable domains that both CNAME into one Cloudflare
// account are indistinguishable from real diversity here, and they die
// together the day Cloudflare is nationally blocked. The provider label
// is the publisher's DECLARATION of independence; nothing in this
// package can verify it, and the recipient-side count is documented the
// same way.
func (s *MirrorSet) SharedDomains() [][]Mirror {
	if s == nil {
		return nil
	}
	order := []string{}
	byDomain := map[string][]Mirror{}
	for _, m := range s.mirrors {
		d := registrableDomain(mustHost(m.URL))
		if _, ok := byDomain[d]; !ok {
			order = append(order, d)
		}
		byDomain[d] = append(byDomain[d], m)
	}
	var out [][]Mirror
	for _, d := range order {
		if len(byDomain[d]) > 1 {
			out = append(out, byDomain[d])
		}
	}
	return out
}

// registrableDomain reduces a hostname to its last two labels. A
// deliberate approximation; see the recipient-side twin in
// core/refresh/endpoints.go for why a public-suffix list is not worth
// the dependency here either.
func registrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Mirrors returns a copy of the ordered members.
func (s *MirrorSet) Mirrors() []Mirror {
	if s == nil {
		return nil
	}
	return append([]Mirror(nil), s.mirrors...)
}

// Len reports the number of mirrors.
func (s *MirrorSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.mirrors)
}

// LegacyScalarURL is the single URL written into the V1.6
// manifest's `relay_pack.freshness_url` slot.
//
// That slot is a string and cannot hold a set without a
// wire-breaking manifest change (see MirrorsArchivePath), so it
// carries the set's first member and nothing else. It exists for
// two readers: a recipient build that predates the mirror
// document, and the RP021 shape gate, which is the only
// validator rule that looks at freshness at all.
//
// A recipient that can read MirrorsArchivePath MUST prefer the
// set and MUST NOT treat this value as primary — it is the
// lowest-sorting provider label, not a ranked choice, and
// ranking is the recipient's job (randomised order, per member,
// per attempt). The scalar can never be the ONLY endpoint in a
// pack: BindAndSign refuses to write it without a valid set
// beside it.
func (s *MirrorSet) LegacyScalarURL() string {
	if s == nil || len(s.mirrors) == 0 {
		return ""
	}
	return s.mirrors[0].URL
}

// ValidateMirrorURL enforces the same syntactic rules the shared
// validator's RP021 V1.6 half enforces on
// `manifest.relay_pack.freshness_url`
// (bundle/go/relaypackvalidate/validator.go:validateFreshnessURL).
//
// It is duplicated rather than imported because the rule there is
// unexported and phrased as a ValidationError with a manifest
// JSON pointer. The duplication is load-bearing and is pinned by
// a test in publisher/deploy/relaypack that binds every mirror
// through the real validator: a mirror that this function accepts
// but RP021 rejects would produce a pack whose scalar slot fails
// import, which is exactly the silent-divergence bug the
// duplication invites.
func ValidateMirrorURL(raw string) error {
	const maxLen = 2048 // == relaypackvalidate.maxFreshnessURLLen
	if raw == "" {
		return errors.New("url is empty")
	}
	if len(raw) > maxLen {
		return fmt.Errorf("url exceeds %d bytes", maxLen)
	}
	if strings.TrimSpace(raw) != raw {
		return errors.New("url must not carry leading/trailing whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("url is not parseable")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("url scheme must be https (got %q)", u.Scheme)
	}
	if u.User != nil {
		return errors.New("url must not carry embedded credentials")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("url must carry a host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return errors.New("url host must be a domain name, not an IP literal")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return errors.New("url host must not be loopback")
	}
	if !strings.Contains(host, ".") {
		return errors.New("url host must be a fully-qualified domain name")
	}
	return nil
}

func mustHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}

// MirrorDoc is the on-wire shape of MirrorsArchivePath.
//
// It is bound to one pack by RelayPackID and to one publisher by
// PublisherPubHex + the signature, so a mirror document lifted
// out of publisher A's pack cannot be dropped into publisher B's,
// and one lifted out of an older pack of the SAME publisher is
// rejected by the RelayPackID check.
type MirrorDoc struct {
	Kind            string   `json:"kind"`
	RelayPackID     string   `json:"relay_pack_id"`
	PublisherPubHex string   `json:"publisher_pub_hex"`
	IssuedAt        string   `json:"issued_at"`
	Mirrors         []Mirror `json:"mirrors"`

	// NotAfter is the signed instant after which this mirror set
	// stops being usable. The binder sets it to the ENCLOSING
	// BUNDLE's expires_at, which is the honest bound: the set is a
	// statement about where to look for the pack, so it cannot
	// outlive the pack.
	//
	// WHY IT IS REQUIRED AND NOT "NICE TO HAVE". This entry is NOT
	// covered by manifest.sig — it is a separate archive entry
	// precisely so adding it did not break every distributed client
	// (see MirrorsArchivePath) — which means whoever hands over a
	// .sbp can swap it for a different signed one without breaking
	// the pack. The relay_pack_id check was documented as stopping
	// that. It does not: an in-place rotation (L1/L2/L7) leaves the
	// pack id untouched, so a mirror document lifted from an OLDER
	// copy of the same pack verifies indefinitely. That hands a
	// courier the choice of which hosts every recipient polls, on
	// the recovery cadence, from their real address — and if the
	// publisher has since let one of those hostnames lapse, it
	// hands it to whoever registers it. An expiry does not make the
	// entry tamper-proof, but it bounds the window to the life of
	// the pack it shipped in instead of forever.
	NotAfter string `json:"not_after"`

	SubkeyCert   json.RawMessage `json:"subkey_cert,omitempty"`
	SignatureHex string          `json:"signature_hex"`
}

// mirrorClockSkew is the tolerance applied to MirrorDoc.NotAfter.
// A recipient with a slow clock must not lose its spare endpoints;
// a fast one must not extend the window meaningfully.
const mirrorClockSkew = 10 * time.Minute

// SignMirrors emits the signed MirrorsArchivePath bytes.
//
// signingPriv is the key that signs the enclosing bundle: the
// publisher root when subkeyCertJSON is empty, the certified
// FRP-7.5 sub-key when it is not. Keeping the two in lockstep
// means a recipient that could verify the pack can always verify
// its mirror document — there is no second trust root to
// distribute.
//
// Deterministic: Ed25519 signatures are deterministic and the
// body is canonical JSON, so identical inputs (including
// issuedAt) produce identical bytes. BindAndSign's byte-stability
// contract depends on it.
// notAfter must be after issuedAt; the binder passes the enclosing
// bundle's expires_at so the set cannot outlive the pack that
// carries it. See MirrorDoc.NotAfter.
func SignMirrors(set *MirrorSet, relayPackID string, rootPub ed25519.PublicKey,
	signingPriv ed25519.PrivateKey, subkeyCertJSON []byte, issuedAt, notAfter time.Time) ([]byte, error) {

	if set == nil || set.Len() < MinMirrors {
		return nil, ErrTooFewMirrors
	}
	if relayPackID == "" {
		return nil, errors.New("freshness: relayPackID required")
	}
	if len(rootPub) != ed25519.PublicKeySize {
		return nil, errors.New("freshness: publisher root public key required")
	}
	if len(signingPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("freshness: invalid signing private key")
	}
	if notAfter.IsZero() || !notAfter.After(issuedAt) {
		return nil, errors.New("freshness: mirror document notAfter must be after issuedAt")
	}
	doc := MirrorDoc{
		Kind:            MirrorsKind,
		RelayPackID:     relayPackID,
		PublisherPubHex: hex.EncodeToString(rootPub),
		IssuedAt:        issuedAt.UTC().Format(time.RFC3339),
		NotAfter:        notAfter.UTC().Format(time.RFC3339),
		Mirrors:         set.Mirrors(),
	}
	if len(subkeyCertJSON) > 0 {
		canonCert, err := canonicalRawJSON(subkeyCertJSON)
		if err != nil {
			return nil, fmt.Errorf("freshness: canonical subkey cert: %w", err)
		}
		doc.SubkeyCert = canonCert
	}
	body, err := canonicalExcluding(doc, "signature_hex")
	if err != nil {
		return nil, err
	}
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(signingPriv, body))
	return canonicalAll(doc)
}

// VerifyMirrors parses and verifies a MirrorsArchivePath blob
// against the pack that carried it. expectRelayPackID is the
// enclosing bundle's RelayPack.RelayPackID; passing "" skips only
// that check and is intended for publisher-side tooling, never
// for a recipient.
//
// This is the function a recipient mirrors. It returns a
// validated MirrorSet, so a recipient that calls it can never end
// up polling one host: a document that degraded to a single
// mirror fails NewMirrorSet and the recipient falls back to the
// scalar slot plus the bootstrap pointer.
func VerifyMirrors(raw []byte, publisherRootPub ed25519.PublicKey, expectRelayPackID string, now time.Time) (*MirrorSet, error) {
	if len(publisherRootPub) != ed25519.PublicKeySize {
		return nil, errors.New("freshness: PublisherRootPub required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var doc MirrorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("freshness: malformed mirror document: %w", err)
	}
	if doc.Kind != MirrorsKind {
		return nil, errors.New("freshness: unsupported mirror document kind")
	}
	if !equalHex(hex.EncodeToString(publisherRootPub), doc.PublisherPubHex) {
		return nil, ErrMirrorsMismatch
	}
	if expectRelayPackID != "" && doc.RelayPackID != expectRelayPackID {
		return nil, ErrMirrorsMismatch
	}
	if _, err := time.Parse(time.RFC3339, doc.IssuedAt); err != nil {
		return nil, fmt.Errorf("freshness: malformed issued_at: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, doc.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("freshness: malformed not_after: %w", err)
	}
	signingPub := ed25519.PublicKey(publisherRootPub)
	if len(doc.SubkeyCert) > 0 {
		sub, err := walkSubkeyCert(doc.SubkeyCert, publisherRootPub, now)
		if err != nil {
			return nil, fmt.Errorf("freshness: mirror subkey cert: %w", err)
		}
		signingPub = sub
	}
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("freshness: malformed mirror signature_hex")
	}
	// Verify over the RECEIVED bytes with signature_hex removed,
	// not over a re-marshal of the parsed struct: a field a future
	// version adds must not silently vanish from the body this
	// side hashes. That failure mode is invisible in tests written
	// against one version and total in the field.
	body, err := canonicalRawExcluding(raw, "signature_hex")
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signingPub, body, sig) {
		return nil, errors.New("freshness: mirror signature invalid")
	}
	// Expiry is enforced HERE, after the signature — the same
	// ordering rule the freshness document's verifier follows. Every
	// branch below the signature is steered by bytes the publisher
	// signed; every branch above it is steered by an attacker's.
	if now.After(notAfter.Add(mirrorClockSkew)) {
		return nil, fmt.Errorf("freshness: mirror document expired at %s", doc.NotAfter)
	}
	return NewMirrorSet(doc.Mirrors)
}

// canonicalAll / canonicalExcluding / canonicalRawExcluding are
// the shared canonicalisation helpers used by both documents.
func canonicalAll(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicalRawExcluding(raw, "")
}

func canonicalExcluding(v any, key string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicalRawExcluding(raw, key)
}

func canonicalRawExcluding(raw []byte, key string) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if key != "" {
		if obj, ok := value.(map[string]any); ok {
			delete(obj, key)
		}
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
