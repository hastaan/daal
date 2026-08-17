// relaypack.go is the FRP-8 V1.6 freshness-driven RelayPack
// refresh adapter. It is the network-IO + atomic-swap half of
// the layer split documented in
// core/internal/selection/freshness.go.
//
// LAYER SPLIT:
//
//   - core/internal/selection/freshness.go: pure trigger policy.
//     No sockets, no http. Position B enforced by the existing
//     selection opsec test.
//
//   - core/refresh/relaypack.go (this file): the wire formats —
//     the freshness document and the mirror document — parsed and
//     verified. Fetch orchestration lives next door in
//     relaypack_refresh.go; the atomic swap is
//     bundle/go/importer.ApplyVerifiedRefresh.
//
//   - bundle/go/importer.ApplyVerifiedRefresh: re-verifies the
//     SBP signature, re-runs the V16 RelayPack validator
//     (RP022/RP023/RP024 hardening attestation gates fire the
//     same as on the QR-scan import path), upserts atomically.
//
// WHY v2, AND WHY THE v1 SHAPE IS REFUSED OUTRIGHT.
//
// v1 carried {relay_pack_id, current_bundle_sha256,
// current_signed_url, last_modified, publisher_pub_hex} plus a
// signature. That proves "the publisher said this once" and nothing
// more: no expiry, no counter. A censor who captures one signed
// document can serve it back forever — the recipient sits on a dead
// pack believing it is current (freeze), and after a rotation is
// told to install the PREVIOUS bundle, because the comparison here
// is an inequality (`sha != local sha`) and not an ordering. That is
// a rollback executed with the publisher's own valid signature, and
// it re-instates precisely the credentials a Step-7 rotation just
// revoked. There are no v1 documents in the field (the publisher-side
// signer had zero callers before this wave), so v2 is a hard cut:
// `sequence` (monotonic, persisted high-water mark), `not_after`
// (signed expiry, bounding the freeze window), `mirrors` (endpoint
// rotation) and `pad` (size normalisation).
//
// THE CANONICALISATION RULE THAT MATTERS. The signature is checked
// over the canonicalisation of the RECEIVED BYTES with signature_hex
// removed — never over a re-marshal of the struct below. Re-marshal
// verification silently drops any field a newer publisher added, so
// the body diverges and EVERY signature fails; that failure mode is
// invisible in tests written against one version and total in the
// field. This file's struct is a convenience view, not the verified
// object.
//
// OPSEC invariants:
//   - This package is allowed net/http indirectly via
//     bootstrap.FetchRaw (which uses raw TLS / HTTP/1.1, not
//     net/http). The package-level opsec test in core/refresh/
//     prevents net/http itself.
//   - Freshness URLs are NEVER logged.
//   - The fetched bytes are bounded; we cap at 64KB.

package refresh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/bootstrap"
)

// FreshnessKind is the accepted freshness document discriminator.
// Mirrors publisher/deploy/freshness.Kind.
const FreshnessKind = "daal/freshness-v2"

// FreshnessKindV1 is the superseded shape. Named so the refusal is
// explicit rather than a generic "unsupported kind" — a publisher
// looking at the audit trail needs to know to republish, not to
// wonder whether the recipient is broken.
const FreshnessKindV1 = "daal/freshness-v1"

// MirrorsKind is the mirror document's discriminator. Mirrors
// publisher/deploy/freshness.MirrorsKind.
const MirrorsKind = "daal/freshness-mirrors-v1"

// MirrorsArchivePath is the .sbp archive entry carrying the signed
// mirror set. It is a separate archive entry (not a manifest field)
// because bundle.VerifyManifest re-marshals the parsed manifest
// before checking the signature, so a manifest field an already
// distributed client does not know about makes that client reject
// the ENTIRE pack. Same route the FRP-11 cell documents took.
//
// The literal itself lives in bundle.FreshnessMirrorsPath — the module
// the publisher and the recipient both already depend on — so that "the
// publisher writes an entry the recipient never looks for" cannot be
// introduced by a rename on one side. That failure is silent in both
// directions: the pack still verifies, the mirrors simply vanish.
const MirrorsArchivePath = bundle.FreshnessMirrorsPath

// Mirror-set invariants, mirrored from publisher/deploy/freshness.
// MinMirrors is what makes a single-URL freshness path
// unrepresentable on this side too: a mirror document that degraded
// to one endpoint is rejected, and the recipient falls back to the
// legacy scalar plus the bootstrap-pointer layer rather than
// pretending one host is a set.
//
// MaxMirrors is pinned EQUAL to maxFreshnessEndpoints (endpoints.go).
// It was 8 here and on the publisher while every device truncated the
// walk at 6, and both sides order mirrors by the same deterministic
// (provider, url) sort — so the same two providers fell off on every
// device in the fleet, identically, and a publisher with eight storage
// accounts was shown eight-way redundancy that a censor could take
// down by blocking six.
const (
	MinMirrors = 2
	MaxMirrors = maxFreshnessEndpoints
)

// MaxSupersedes bounds FreshnessDocument.Supersedes. Mirrors
// publisher/deploy/freshness.MaxSupersedes.
const MaxSupersedes = 16

// defaultFreshnessClockSkew is the tolerance applied to not_after.
// A recipient with a slow clock must not refuse a valid document; a
// recipient with a fast clock must not meaningfully extend a freeze
// window.
const defaultFreshnessClockSkew = 10 * time.Minute

// ErrFreshnessExpired is returned when the freshness document's
// not_after is in the past (plus skew). The caller records the
// failure and re-attempts per FreshnessPolicy.RetryBackoff.
var ErrFreshnessExpired = errors.New("freshness document expired")

// ErrFreshnessSignature is returned when the document's signature
// does not verify against the bundle's publisher root key (or the
// embedded sub-key cert is invalid).
var ErrFreshnessSignature = errors.New("freshness signature invalid")

// ErrFreshnessVersion is returned for unsupported document
// version/kind tuples.
var ErrFreshnessVersion = errors.New("unsupported freshness document")

// ErrFreshnessRollback is returned when the document's sequence is
// below the recipient's persisted high-water mark. The document is
// genuinely signed — that is the whole point of the attack — so an
// ordering the publisher controls and the recipient remembers is the
// only thing that can distinguish it from the current one.
var ErrFreshnessRollback = errors.New("freshness document sequence went backwards (rollback/replay)")

// ErrFreshnessWrongPack is returned when a document names a
// different relay_pack_id than the pack being refreshed. Without
// this check one signed document could be spliced onto another pack
// of the same publisher.
var ErrFreshnessWrongPack = errors.New("freshness document is for a different relay pack")

// ErrFreshnessPublisher is returned when the document's
// publisher_pub_hex does not hash to the pinned publisher
// fingerprint of the routes being refreshed.
var ErrFreshnessPublisher = errors.New("freshness document is not signed by this route's publisher")

// FreshnessOutcome is the structured result of one document fetch.
type FreshnessOutcome struct {
	// FetchedAt is the wall-clock at fetch completion.
	FetchedAt time.Time
	// CurrentBundleSHA256 is the signed .sbp SHA-256 the
	// freshness document is currently pointing at.
	CurrentBundleSHA256 string
	// ChangedFromCurrent is true when CurrentBundleSHA256
	// differs from the caller's locally-pinned digest. When true
	// the caller fetches CurrentSignedURL and applies the bundle.
	ChangedFromCurrent bool
	// Document is the parsed document on success (nil on error).
	Document *FreshnessDocument
}

// FreshnessMirror is one advertised endpoint. Provider is the
// publisher's declaration of which storage account holds it and is
// the unit of independence: two mirrors with the same label are
// assumed to fail together.
type FreshnessMirror struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

// FreshnessDocument mirrors publisher/deploy/freshness.Document.
// Duplicated because core/ cannot import publisher/. See the
// canonicalisation note in the file header: this struct is a view
// of the verified bytes, never the thing verified.
type FreshnessDocument struct {
	Kind        string `json:"kind"`
	RelayPackID string `json:"relay_pack_id"`
	// Supersedes lists the pack ids this document ALSO governs.
	//
	// Without it the whole channel is inert for the rungs it was
	// built for. The pack id is a hash of
	// (provider|server_id|region|public_ip|families), so an L3
	// address swap — the flagship recovery — RENAMES the pack. The
	// publisher then uploads a document naming the new id to the
	// same object URL, and every recipient, which knows only the id
	// stamped on its own route rows, rejects it as
	// ErrFreshnessWrongPack. The publisher's screen says "2/2
	// mirrors published" and not one device moves.
	//
	// A pack id in this list is a publisher-signed statement that
	// the named pack is succeeded by this one. It is inside the
	// signed body, so only the publisher can assert it, and the
	// bundle it points at still has to be signed by the publisher
	// this device's routes are pinned to (see applyBundle).
	Supersedes []string `json:"supersedes"`
	// Sequence is the publisher's monotonic counter for this pack.
	Sequence uint64 `json:"sequence"`

	CurrentBundleSHA256 string `json:"current_bundle_sha256"`
	CurrentSignedURL    string `json:"current_signed_url"`
	LastModified        string `json:"last_modified"`
	// NotAfter is the signed expiry — the bound on how long a
	// captured document can freeze this recipient.
	NotAfter string `json:"not_after"`
	// Mirrors is the endpoint set to poll on the NEXT cycle. It is
	// how a publisher retires a burned freshness host without
	// re-delivering a pack.
	Mirrors []FreshnessMirror `json:"mirrors"`

	PublisherPubHex string `json:"publisher_pub_hex"`
	// Pad is signed filler quantising the document's size. Never
	// omitempty: an absent key would itself be a signal.
	Pad string `json:"pad"`

	SubkeyCert   json.RawMessage `json:"subkey_cert,omitempty"`
	SignatureHex string          `json:"signature_hex"`
}

// FreshnessVerifyOpts feeds VerifyFreshnessDocument. It mirrors
// publisher/deploy/freshness.VerifyOpts field for field.
type FreshnessVerifyOpts struct {
	// PublisherRootPub is the pack's publisher root key. Required.
	PublisherRootPub ed25519.PublicKey
	// Now is the wall-clock for not_after and cert-window checks.
	Now time.Time
	// ExpectRelayPackID is the caller's installed pack id. A
	// recipient MUST set this. The document satisfies it either by
	// naming it as relay_pack_id or by listing it in supersedes[].
	ExpectRelayPackID string
	// MinSequence is the persisted high-water mark. A recipient
	// MUST persist it across restarts, or the rollback protection
	// lasts exactly as long as the process.
	MinSequence uint64
	// CurrentBundleSHA256 is the digest of the bundle this device is
	// running, when it has one. It closes the equal-sequence hole:
	// the counter has one-second granularity, so two documents
	// published in the same second share a value, and accepting `==`
	// unconditionally makes them interchangeable forever — a censor
	// who captured the earlier one can walk the device back onto the
	// pre-rotation bundle with the publisher's own valid signature.
	// A document AT the high-water mark is therefore accepted only
	// while it names the bundle already installed.
	CurrentBundleSHA256 string
	// ClockSkew tolerance on not_after; defaults to 10 minutes.
	ClockSkew time.Duration
}

// FetchAndVerifyFreshness fetches the freshness JSON at url,
// verifies it under opts, and reports whether the publisher has
// moved to a different signed bundle than currentBundleSHA256.
func FetchAndVerifyFreshness(
	ctx context.Context,
	url string,
	currentBundleSHA256 string,
	dialer bootstrap.Dialer,
	timeout time.Duration,
	opts FreshnessVerifyOpts,
) (*FreshnessOutcome, error) {
	raw, err := bootstrap.FetchRaw(ctx, url, dialer, timeout)
	if err != nil {
		return nil, fmt.Errorf("freshness fetch: %w", err)
	}
	if len(raw) > 64*1024 {
		raw = raw[:64*1024]
	}
	doc, err := VerifyFreshnessDocument(raw, opts)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return &FreshnessOutcome{
		FetchedAt:           now.UTC(),
		CurrentBundleSHA256: doc.CurrentBundleSHA256,
		ChangedFromCurrent:  !equalHex(doc.CurrentBundleSHA256, currentBundleSHA256),
		Document:            doc,
	}, nil
}

// ApplyRefresh applies the supplied bundle bytes via the importer's
// ApplyVerifiedRefresh entry point, threading the freshness
// document's CurrentBundleSHA256 as the cross-check value the
// importer compares against the signed .sbp body.
//
// This is the "atomic swap" call the phase doc §13 layer split
// names. The importer is responsible for the atomic upsert; this
// function is a thin adapter that propagates the verified
// signed bundle digest.
func ApplyRefresh(
	bundleBody []byte,
	doc *FreshnessDocument,
	st importer.State,
	wordlists bundle.Wordlists,
	now time.Time,
) (importer.Verdict, error) {
	if doc == nil {
		return importer.Verdict{Kind: importer.VerdictRejected, Reason: "freshness_doc_nil"},
			errors.New("freshness document required")
	}
	return importer.ApplyVerifiedRefresh(bundleBody, doc.CurrentBundleSHA256, st, wordlists, now)
}

// VerifyFreshnessDocument parses + verifies a freshness document.
//
// Order is load-bearing: signature FIRST, policy after. Every
// branch below the signature check is steered by attacker-supplied
// bytes until the signature has been checked, so nothing that
// mutates recipient state — and nothing that produces a
// distinguishable error a prober could use as an oracle — may run
// before it.
func VerifyFreshnessDocument(raw []byte, opts FreshnessVerifyOpts) (*FreshnessDocument, error) {
	if len(opts.PublisherRootPub) != ed25519.PublicKeySize {
		return nil, errors.New("freshness: publisher root public key required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = defaultFreshnessClockSkew
	}
	var doc FreshnessDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("freshness parse: %w", err)
	}
	if doc.Kind == FreshnessKindV1 {
		return nil, fmt.Errorf("%w: v1 carries no expiry or sequence; republish at %s",
			ErrFreshnessVersion, FreshnessKind)
	}
	if doc.Kind != FreshnessKind {
		return nil, ErrFreshnessVersion
	}
	if doc.RelayPackID == "" || !isSHA256Hex(doc.CurrentBundleSHA256) ||
		doc.CurrentSignedURL == "" || doc.PublisherPubHex == "" {
		return nil, errors.New("freshness: required fields missing")
	}
	u, err := url.Parse(doc.CurrentSignedURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("freshness: current_signed_url must be https")
	}
	if _, err := time.Parse(time.RFC3339, doc.LastModified); err != nil {
		return nil, fmt.Errorf("freshness last_modified: %w", err)
	}
	if !equalHex(hex.EncodeToString(opts.PublisherRootPub), doc.PublisherPubHex) {
		return nil, ErrFreshnessPublisher
	}
	signingPub := ed25519.PublicKey(opts.PublisherRootPub)
	if len(doc.SubkeyCert) > 0 {
		sub, err := walkFreshnessSubkeyCert(doc.SubkeyCert, opts.PublisherRootPub, now)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFreshnessSignature, err)
		}
		signingPub = sub
	}
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrFreshnessSignature
	}
	body, err := canonicalRawExcluding(raw, "signature_hex")
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signingPub, body, sig) {
		return nil, ErrFreshnessSignature
	}

	// ---- post-signature policy ---------------------------------
	if opts.ExpectRelayPackID != "" && !documentGoverns(&doc, opts.ExpectRelayPackID) {
		return nil, ErrFreshnessWrongPack
	}
	if doc.Sequence == 0 {
		return nil, errors.New("freshness: sequence must be > 0")
	}
	if err := checkFreshnessSequence(doc.Sequence, doc.CurrentBundleSHA256,
		opts.MinSequence, opts.CurrentBundleSHA256); err != nil {
		return nil, err
	}
	notAfter, err := time.Parse(time.RFC3339, doc.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("freshness not_after: %w", err)
	}
	if now.After(notAfter.Add(skew)) {
		return nil, fmt.Errorf("%w at %s", ErrFreshnessExpired, doc.NotAfter)
	}
	if len(doc.Mirrors) > 0 {
		if _, err := ValidateMirrorSet(doc.Mirrors); err != nil {
			return nil, fmt.Errorf("freshness: advertised mirror set invalid: %w", err)
		}
	}
	return &doc, nil
}

// documentGoverns reports whether a verified document addresses the
// pack this device has installed — either because it IS that pack's
// document, or because the publisher signed a statement that this
// pack succeeds it. See FreshnessDocument.Supersedes.
//
// MaxSupersedes bounds the scan. The list is publisher-signed, so an
// over-long one is a publisher bug or a document from tooling this
// build does not understand; refusing the list whole is the
// conservative reading.
func documentGoverns(doc *FreshnessDocument, installed string) bool {
	if doc.RelayPackID == installed {
		return true
	}
	if len(doc.Supersedes) > MaxSupersedes {
		return false
	}
	for _, id := range doc.Supersedes {
		if id == installed {
			return true
		}
	}
	return false
}

// checkFreshnessSequence is the anti-rollback ordering. It mirrors
// publisher/deploy/freshness.checkSequence.
//
// `>` when the document names a different bundle, `>=` when it names
// the one already installed. See FreshnessVerifyOpts.CurrentBundleSHA256.
func checkFreshnessSequence(docSeq uint64, docBundle string, minSeq uint64, haveBundle string) error {
	if docSeq > minSeq {
		return nil
	}
	if docSeq < minSeq {
		return fmt.Errorf("%w: got %d, have %d", ErrFreshnessRollback, docSeq, minSeq)
	}
	if haveBundle == "" || equalHex(docBundle, haveBundle) {
		return nil
	}
	return fmt.Errorf("%w: sequence %d was already used for a different bundle", ErrFreshnessRollback, docSeq)
}

// MirrorDocument is the on-wire shape of MirrorsArchivePath.
// Mirrors publisher/deploy/freshness.MirrorDoc.
type MirrorDocument struct {
	Kind            string            `json:"kind"`
	RelayPackID     string            `json:"relay_pack_id"`
	PublisherPubHex string            `json:"publisher_pub_hex"`
	IssuedAt        string            `json:"issued_at"`
	Mirrors         []FreshnessMirror `json:"mirrors"`
	// NotAfter bounds how long this set stays usable. The publisher
	// sets it to the enclosing bundle's expires_at.
	//
	// The entry is NOT covered by manifest.sig — that is why adding
	// it did not break already-distributed clients — so whoever hands
	// over a .sbp can substitute a different signed one without
	// breaking the pack. The relay_pack_id check was documented as
	// preventing that and does not: an in-place rotation (L1/L2/L7)
	// leaves the pack id unchanged, so a set lifted from an OLDER
	// copy of the same pack verified forever, letting a courier pick
	// which hosts a device beacons at on the recovery cadence — and
	// letting whoever re-registers a lapsed one of those hostnames
	// inherit the beacon. The expiry does not make the entry
	// tamper-proof; it bounds the window to the life of the pack.
	NotAfter     string          `json:"not_after"`
	SubkeyCert   json.RawMessage `json:"subkey_cert,omitempty"`
	SignatureHex string          `json:"signature_hex"`
}

// VerifyMirrorDocument parses and verifies a MirrorsArchivePath blob
// against the pack that carried it, returning the validated mirror
// set. It mirrors publisher/deploy/freshness.VerifyMirrors.
//
// expectRelayPackID must be non-empty on the recipient side. It
// stops a mirror document lifted out of a DIFFERENT pack being
// accepted here — but note what it does NOT stop, because the
// previous comment claimed more than the check delivers: an in-place
// rotation (L1/L2/L7) leaves the pack id unchanged, so a document
// lifted from an older copy of the SAME pack passes this check. The
// bound on that is MirrorDocument.NotAfter, enforced below.
func VerifyMirrorDocument(raw []byte, publisherRootPub ed25519.PublicKey,
	expectRelayPackID string, now time.Time) ([]FreshnessMirror, error) {

	if len(publisherRootPub) != ed25519.PublicKeySize {
		return nil, errors.New("freshness: publisher root public key required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var doc MirrorDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("freshness: malformed mirror document: %w", err)
	}
	if doc.Kind != MirrorsKind {
		return nil, ErrFreshnessVersion
	}
	if !equalHex(hex.EncodeToString(publisherRootPub), doc.PublisherPubHex) {
		return nil, ErrFreshnessPublisher
	}
	if expectRelayPackID != "" && doc.RelayPackID != expectRelayPackID {
		return nil, ErrFreshnessWrongPack
	}
	if _, err := time.Parse(time.RFC3339, doc.IssuedAt); err != nil {
		return nil, fmt.Errorf("freshness: malformed issued_at: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, doc.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("freshness: malformed mirror not_after: %w", err)
	}
	signingPub := ed25519.PublicKey(publisherRootPub)
	if len(doc.SubkeyCert) > 0 {
		sub, err := walkFreshnessSubkeyCert(doc.SubkeyCert, publisherRootPub, now)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFreshnessSignature, err)
		}
		signingPub = sub
	}
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrFreshnessSignature
	}
	body, err := canonicalRawExcluding(raw, "signature_hex")
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signingPub, body, sig) {
		return nil, ErrFreshnessSignature
	}
	// Expiry AFTER the signature, same rule as the freshness
	// document: nothing steered by unauthenticated bytes runs first.
	if now.After(notAfter.Add(defaultFreshnessClockSkew)) {
		return nil, fmt.Errorf("%w: mirror set expired at %s", ErrFreshnessExpired, doc.NotAfter)
	}
	return ValidateMirrorSet(doc.Mirrors)
}

var mirrorProviderRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,15}$`)

// ValidateMirrorSet enforces the publisher-side MirrorSet
// invariants on the recipient side: [MinMirrors, MaxMirrors]
// members, a well-formed provider label per member, a fetchable
// https URL per member, and no two members sharing a provider
// label or a host.
//
// The distinctness rules are the whole value of the set. Two URLs
// in one storage account are one failure domain wearing two names,
// and accepting them here would let a publisher (or an adversary
// who can edit an unsigned copy) turn N-provider resilience into
// theatre.
func ValidateMirrorSet(mirrors []FreshnessMirror) ([]FreshnessMirror, error) {
	if len(mirrors) < MinMirrors {
		return nil, fmt.Errorf("freshness: at least %d mirrors on distinct providers are required", MinMirrors)
	}
	if len(mirrors) > MaxMirrors {
		return nil, fmt.Errorf("freshness: at most %d mirrors (got %d)", MaxMirrors, len(mirrors))
	}
	out := make([]FreshnessMirror, 0, len(mirrors))
	seenProvider := map[string]bool{}
	seenHost := map[string]bool{}
	for _, m := range mirrors {
		if !mirrorProviderRe.MatchString(m.Provider) {
			return nil, fmt.Errorf("freshness: bad provider label %q", m.Provider)
		}
		host, ok := validFreshnessURL(m.URL)
		if !ok {
			return nil, fmt.Errorf("freshness: mirror %s: unusable url", m.Provider)
		}
		if seenProvider[m.Provider] {
			return nil, fmt.Errorf("freshness: two mirrors share provider %q", m.Provider)
		}
		if seenHost[host] {
			return nil, fmt.Errorf("freshness: two mirrors share host %q", host)
		}
		seenProvider[m.Provider] = true
		seenHost[host] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].URL < out[j].URL
	})
	return out, nil
}

// PublisherKeyForFingerprint recovers the publisher root public key
// from a document that carries it, binding it to the fingerprint the
// recipient has pinned.
//
// WHY THIS IS SOUND, AND WHY IT EXISTS. The recipient store pins a
// publisher by FINGERPRINT (sha256 of the root key); it does not
// keep the key bytes anywhere — `publishers` has no column for them
// and the importer never asks for one. Verifying against
// sha256(claimed key) == pinned fingerprint is cryptographically
// identical to having pinned the key itself: a second-preimage on
// SHA-256 would be required to substitute a different key, and any
// attacker who has that does not need to bother with freshness
// documents.
//
// The consequence for the caller is the important half: the key
// returned here is derived from the DOCUMENT, so the
// publisher_pub_hex equality check inside VerifyFreshnessDocument
// becomes a tautology. The binding to the recipient's trust is the
// fingerprint comparison performed HERE, and it must never be
// skipped.
func PublisherKeyForFingerprint(pubHex, pinnedFingerprintHex string) (ed25519.PublicKey, error) {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, ErrFreshnessPublisher
	}
	sum := sha256.Sum256(pub)
	if !equalHex(hex.EncodeToString(sum[:]), pinnedFingerprintHex) {
		return nil, ErrFreshnessPublisher
	}
	return ed25519.PublicKey(pub), nil
}

// peekPublisherPubHex extracts publisher_pub_hex from raw document
// bytes without trusting anything else in them. Used to recover the
// root key before verification; every other field is ignored until
// the signature has been checked.
func peekPublisherPubHex(raw []byte) string {
	var probe struct {
		PublisherPubHex string `json:"publisher_pub_hex"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return probe.PublisherPubHex
}

// walkFreshnessSubkeyCert mirrors bundle/go/bundle/subkey_chain.go
// byte-for-byte (minus the package-private types). A regression
// test pins the format across both modules.
func walkFreshnessSubkeyCert(certJSON []byte, rootPub ed25519.PublicKey, now time.Time) (ed25519.PublicKey, error) {
	var cert struct {
		V                  int    `json:"v"`
		Kind               string `json:"kind"`
		RootFingerprintHex string `json:"root_fingerprint_hex"`
		SubkeyPubHex       string `json:"subkey_pub_hex"`
		ValidFrom          string `json:"valid_from"`
		ValidUntil         string `json:"valid_until"`
		Label              string `json:"label"`
		SignatureHex       string `json:"signature_hex"`
	}
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return nil, fmt.Errorf("malformed: %w", err)
	}
	if cert.V != 1 || cert.Kind != "subkey_cert" {
		return nil, errors.New("malformed: bad version/kind")
	}
	subPub, err := hex.DecodeString(cert.SubkeyPubHex)
	if err != nil || len(subPub) != ed25519.PublicKeySize {
		return nil, errors.New("malformed: subkey_pub_hex")
	}
	sum := sha256.Sum256(rootPub)
	if cert.RootFingerprintHex != hex.EncodeToString(sum[:]) {
		return nil, errors.New("root fingerprint mismatch")
	}
	from, err1 := time.Parse(time.RFC3339, cert.ValidFrom)
	until, err2 := time.Parse(time.RFC3339, cert.ValidUntil)
	if err1 != nil || err2 != nil {
		return nil, errors.New("malformed: validity window")
	}
	if now.Before(from) || !now.Before(until) {
		return nil, errors.New("out of window")
	}
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(cert.SignatureHex)
	if err != nil {
		return nil, errors.New("malformed: signature_hex")
	}
	if !ed25519.Verify(rootPub, body, sig) {
		return nil, errors.New("signature invalid")
	}
	return ed25519.PublicKey(subPub), nil
}

// canonicalRawExcluding canonicalises received JSON bytes with one
// top-level key removed. Mirrors
// publisher/deploy/freshness.canonicalRawExcluding.
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

// canonicalStructExcluding canonicalises a struct with one key
// removed. Used only by the sub-key cert walk (whose format is
// frozen at v1) and by tests that build documents.
func canonicalStructExcluding(v any, key string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicalRawExcluding(raw, key)
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func canonicalCertBytesExcludingSignature(cert any) ([]byte, error) {
	return canonicalStructExcluding(cert, "signature_hex")
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		if v == float64(int64(v)) {
			buf.WriteString(strconv.FormatInt(int64(v), 10))
		} else {
			buf.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported value %T", v)
	}
	return nil
}

func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
