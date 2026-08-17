package freshness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Kind is the freshness document's kind discriminator.
//
// v2 supersedes the never-published v1. v1 carried
// {relay_pack_id, current_bundle_sha256, current_signed_url,
// last_modified, publisher_pub_hex} and a signature — which is
// enough to prove "the publisher said this at some point" and
// nothing else. It had no expiry and no counter, so a censor who
// captured one signed document could serve it back forever: the
// recipient would sit on a dead pack believing it was current
// (freeze), and after a rotation would be told to install the
// PREVIOUS bundle, because the recipient-side comparison is an
// inequality (`ChangedFromCurrent = doc.sha != local.sha`), not
// an ordering. That is a rollback attack executed with the
// publisher's own valid signature, and it re-enables exactly the
// credentials a Step-7 rotation just revoked.
//
// v2 adds `sequence` (monotonic), `not_after` (signed expiry),
// `mirrors` (endpoint rotation) and `pad` (size normalisation).
// There are no v1 documents anywhere — the publisher-side signer
// had zero callers before this wave — so v2 is a hard cut rather
// than a migration, and Verify refuses v1 outright instead of
// accepting a shape with no rollback protection.
const Kind = "daal/freshness-v2"

// KindV1 is the superseded kind. Named so the refusal can be
// explicit rather than a generic "unsupported kind".
const KindV1 = "daal/freshness-v1"

// DefaultTTL is the document's validity window when BuildOpts.TTL
// is zero.
//
// It is the knob that bounds a freeze attack: a censor who blocks
// the publisher's uploads (or just serves a cached copy) can hold
// a recipient still for at most TTL, after which the document is
// refused and the recipient KNOWS its freshness path is being
// interfered with rather than quietly believing it is current.
// Too short and an offline publisher bricks their own recipients'
// refresh; too long and the freeze window grows. 72h is three
// missed daily publishes.
const DefaultTTL = 72 * time.Hour

// maxSequence is the largest sequence value that survives
// canonicalisation. The canonical writer round-trips numbers
// through float64 (encoding/json's default for `any`), so an
// integer above 2^53-1 would canonicalise to a different string
// than it was signed as and every signature would fail. Bound it
// at build time where the error is legible.
const maxSequence = uint64(1)<<53 - 1

// padBucket is the size quantum the signed document is padded to.
// See padTo for the leak this addresses.
const padBucket = 2048

// MaxSupersedes bounds the superseded-id list.
//
// It is a bound and not a policy: the list only has to be long
// enough that a recipient which has missed a run of rotations can
// still be reached, and short enough that the document stays inside
// one padBucket (each id is 35 bytes, so 16 of them is ~600 bytes —
// comfortably under 2 KiB together with everything else). A
// publisher who has rotated more than MaxSupersedes times since a
// recipient last refreshed has a recipient that is months stale and
// is past what a freshness document can fix; that recipient falls
// through to the bootstrap-pointer layer.
const MaxSupersedes = 16

// defaultClockSkew is the tolerance applied to not_after. A
// recipient with a slow clock must not refuse a valid document;
// a recipient with a fast clock must not extend a freeze window
// meaningfully.
const defaultClockSkew = 10 * time.Minute

// Document is the in-memory representation of one freshness
// statement. The on-wire format is the canonical JSON of this
// struct.
//
// RECIPIENT-SIDE MIRROR: core/refresh/relaypack.go declares a
// byte-for-byte copy of this struct (FreshnessDocument) because
// core/ cannot import publisher/. That copy verifies the
// signature by re-marshalling ITS OWN struct — so any field
// present here and absent there is dropped before the recipient
// canonicalises, and EVERY signature fails. The mirror must
// therefore gain sequence/not_after/mirrors/pad in the same
// change, and should switch to canonicalising the received bytes
// (as VerifyDocument below does) so the next field addition is
// not another flag day.
type Document struct {
	Kind        string `json:"kind"`
	RelayPackID string `json:"relay_pack_id"`

	// Supersedes lists the relay_pack_ids this document ALSO
	// governs — the ids the same relay published under before the
	// rotation that produced RelayPackID.
	//
	// WHY THIS FIELD IS NOT OPTIONAL POLISH. relaypack.DeriveRelayPackID
	// hashes (provider | server_id | region | public_ip | families).
	// Every one of those is something the rotation ladder deliberately
	// changes: L3 moves public_ip, L4 the region, L5 the provider,
	// L6 the family set, L1/L2 rebuild onto a new server_id. So the
	// pack id is NOT a stable name for "this relay" — it is a
	// fingerprint of the relay's current shape, and a rotation
	// renames the thing at exactly the moment recipients need to
	// find it.
	//
	// Without this list the channel is inert for the rungs it was
	// built for: the publisher uploads a document naming the NEW id
	// to the SAME object URL every recipient polls, and every
	// recipient — which knows only the OLD id, read off its own
	// installed routes — rejects it as ErrWrongPack. The publisher's
	// screen reports a successful two-mirror publish while nothing
	// heals. A courier is still required, which is the whole failure
	// Step 8 exists to end.
	//
	// The alternative fix — deriving the id from a stable per-relay
	// secret — was rejected for this wave: the id is already inside
	// every distributed manifest and is what the shared-risk graph
	// and the recipient's route rows are keyed on, so changing its
	// derivation renames every pack in the field at once, which is
	// the same outage in a different costume. A signed, explicit
	// "this pack succeeds that one" is narrower and auditable.
	//
	// SECURITY. The list is inside the signed body, so only the
	// publisher can assert it, and the recipient still requires the
	// fetched .sbp to be signed by the publisher its routes are
	// pinned to (applyBundle) and refuses to re-home another
	// publisher's route ids. The new capability this grants an
	// attacker is therefore nil; the new capability it grants a
	// publisher is "move the holders of pack A onto pack B", which
	// is precisely what a rotation is.
	//
	// Not omitempty: an always-present key means its absence cannot
	// itself be a signal, matching Pad and Mirrors.
	Supersedes []string `json:"supersedes"`

	// Sequence is the publisher's monotonic counter for this
	// relay_pack_id. STRICTLY increasing across publishes; the
	// recipient persists the highest value it has accepted and
	// refuses anything below it. This is the anti-rollback
	// primitive: a replayed document is not forged, it is
	// genuinely signed, so the only thing that can distinguish
	// it from the current one is an ordering the publisher
	// controls and the recipient remembers.
	Sequence uint64 `json:"sequence"`

	CurrentBundleSHA256 string `json:"current_bundle_sha256"`
	CurrentSignedURL    string `json:"current_signed_url"`
	LastModified        string `json:"last_modified"`

	// NotAfter is the signed expiry. Bounds the freeze window a
	// censor gets from replaying a captured document.
	NotAfter string `json:"not_after"`

	// Mirrors is the endpoint set the recipient should poll on
	// its NEXT cycle. It lets a publisher retire a burned
	// freshness host without re-delivering a pack, which is the
	// whole reason this is a set and not a URL. Advisory: a
	// recipient adopts it only from a document that verifies and
	// whose sequence advances, and only if it still satisfies
	// the ≥MinMirrors distinct-provider rule.
	Mirrors []Mirror `json:"mirrors"`

	PublisherPubHex string `json:"publisher_pub_hex"`

	// Pad is signed filler that quantises the document's size.
	// Not omitempty: the key is always present so its absence
	// cannot itself be a signal.
	Pad string `json:"pad"`

	SubkeyCert   json.RawMessage `json:"subkey_cert,omitempty"`
	SignatureHex string          `json:"signature_hex"`
}

// BuildOpts feeds Build.
type BuildOpts struct {
	// RelayPackID is the bundle's Manifest.RelayPack.RelayPackID.
	RelayPackID string

	// Supersedes are the relay_pack_ids the same relay published
	// under previously. See Document.Supersedes. Deduped, sorted and
	// bounded by Build; the caller passes the raw history and does
	// not have to normalise it.
	Supersedes []string

	// Sequence is the monotonic counter. Required and non-zero:
	// there is no safe default for it inside the library, and a
	// zero-valued counter would silently disable rollback
	// protection for every recipient. The CLI derives it from
	// the publish timestamp.
	Sequence uint64

	// BundleBytes is the signed .sbp body currently published at
	// CurrentSignedURL. If set, Build hashes these bytes into
	// CurrentBundleSHA256.
	BundleBytes []byte

	// CurrentBundleSHA256 is the SHA-256 hex digest of the signed
	// .sbp body. Required when BundleBytes is empty.
	CurrentBundleSHA256 string

	// CurrentSignedURL is the recipient-fetchable signed .sbp URL.
	CurrentSignedURL string

	// PublisherPubHex is the publisher root public key in hex.
	PublisherPubHex string

	// Mirrors is the advertised endpoint set. Optional; when
	// supplied it must be a valid MirrorSet (so it can never
	// advertise a single host).
	Mirrors *MirrorSet

	// LastModified is the document's freshness timestamp; defaults
	// to now.
	LastModified time.Time

	// TTL is the validity window; defaults to DefaultTTL.
	TTL time.Duration
}

// ErrRollback is returned by VerifyDocument when the document's
// sequence is below the recipient's high-water mark.
var ErrRollback = errors.New("freshness: document sequence went backwards (rollback/replay)")

// ErrExpired is returned when now is past not_after.
var ErrExpired = errors.New("freshness: document expired")

// ErrWrongPack is returned when the document is for a different
// relay_pack_id than the caller's pack.
var ErrWrongPack = errors.New("freshness: document is for a different relay pack")

// Build emits an unsigned Document. The caller signs with Sign or
// SignWithSubkey.
func Build(opts BuildOpts) (*Document, error) {
	if opts.RelayPackID == "" {
		return nil, errors.New("freshness: RelayPackID required")
	}
	if opts.Sequence == 0 {
		return nil, errors.New("freshness: Sequence required and must be > 0")
	}
	if opts.Sequence > maxSequence {
		return nil, fmt.Errorf("freshness: Sequence exceeds %d (canonical JSON number precision)", maxSequence)
	}
	if opts.CurrentSignedURL == "" {
		return nil, errors.New("freshness: CurrentSignedURL required")
	}
	u, err := url.Parse(opts.CurrentSignedURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("freshness: CurrentSignedURL must be https")
	}
	if opts.PublisherPubHex == "" {
		return nil, errors.New("freshness: PublisherPubHex required")
	}
	shaHex := opts.CurrentBundleSHA256
	if len(opts.BundleBytes) > 0 {
		sum := sha256.Sum256(opts.BundleBytes)
		shaHex = hex.EncodeToString(sum[:])
	}
	if !isSHA256Hex(shaHex) {
		return nil, errors.New("freshness: CurrentBundleSHA256 required")
	}
	if _, err := hex.DecodeString(opts.PublisherPubHex); err != nil {
		return nil, errors.New("freshness: PublisherPubHex must be hex")
	}
	modified := opts.LastModified
	if modified.IsZero() {
		modified = time.Now().UTC()
	}
	modified = modified.UTC()
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	// A MirrorSet can only exist in a valid state, so the only
	// check left is "if the caller passed one, it survived
	// NewMirrorSet". Nil is allowed: the pack's own signed mirror
	// document is the authority, and the in-document set is the
	// rotation channel on top of it.
	mirrors := opts.Mirrors.Mirrors()
	if mirrors == nil {
		mirrors = []Mirror{}
	}
	supersedes, err := normaliseSupersedes(opts.RelayPackID, opts.Supersedes)
	if err != nil {
		return nil, err
	}
	return &Document{
		Kind:                Kind,
		RelayPackID:         opts.RelayPackID,
		Supersedes:          supersedes,
		Sequence:            opts.Sequence,
		CurrentBundleSHA256: shaHex,
		CurrentSignedURL:    opts.CurrentSignedURL,
		LastModified:        modified.Format(time.RFC3339),
		NotAfter:            modified.Add(ttl).Format(time.RFC3339),
		Mirrors:             mirrors,
		PublisherPubHex:     opts.PublisherPubHex,
	}, nil
}

// normaliseSupersedes dedupes, sorts and bounds the superseded-id
// list, and refuses a list that names the current pack.
//
// Sorted because the document must be a pure function of its inputs
// (the publish path is re-run on retries and the bytes are compared);
// deduped because a rotation history naturally repeats an id when a
// rung changed nothing the id is derived from; and self-excluding
// because "this pack supersedes itself" would make the recipient's
// two acceptance branches overlap, hiding a publisher bug behind a
// tautology.
func normaliseSupersedes(current string, ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{current: true}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		if !relayPackIDRe.MatchString(id) {
			return nil, fmt.Errorf("freshness: superseded id %q is not a relay pack id", id)
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) > MaxSupersedes {
		// Keep the MOST RECENT ids: the caller passes history
		// newest-first, and a recipient that is only one or two
		// rotations behind is the one worth reaching.
		out = out[:MaxSupersedes]
	}
	sort.Strings(out)
	return out, nil
}

// relayPackIDRe is the shape relaypack.DeriveRelayPackID emits:
// "rp-" plus 32 lowercase hex characters. Fixture ids in the FRP-1
// corpus are looser ("rp-frp1-direct-mode-base"), so the pattern
// admits lowercase words and dashes too — it is a sanity bound on
// what goes into a signed list, not an identity check.
var relayPackIDRe = regexp.MustCompile(`^rp-[a-z0-9][a-z0-9-]{1,62}$`)

// Sign signs the supplied unsigned Document with the publisher
// root key. Use this when the FRP has no active sub-key.
func Sign(doc *Document, rootPriv ed25519.PrivateKey) ([]byte, error) {
	if doc == nil {
		return nil, errors.New("freshness: nil document")
	}
	if len(rootPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("freshness: invalid root private key")
	}
	doc.SubkeyCert = nil
	pub := rootPriv.Public().(ed25519.PublicKey)
	if doc.PublisherPubHex == "" {
		doc.PublisherPubHex = hex.EncodeToString(pub)
	}
	return signDoc(doc, rootPriv)
}

// SignWithSubkey signs with an active sub-key. The supplied
// subkeyCertJSON is the publisher-side SubkeyCert JSON the
// recipient walks to validate the chain. The cert is embedded as
// the structured `subkey_cert` object in the document.
func SignWithSubkey(doc *Document, subkeyPriv ed25519.PrivateKey, subkeyCertJSON []byte) ([]byte, error) {
	if doc == nil {
		return nil, errors.New("freshness: nil document")
	}
	if len(subkeyPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("freshness: invalid sub-key private key")
	}
	if len(subkeyCertJSON) == 0 {
		return nil, errors.New("freshness: SubkeyCertJSON required when signing with sub-key")
	}
	canonCert, err := canonicalRawJSON(subkeyCertJSON)
	if err != nil {
		return nil, fmt.Errorf("freshness: canonical subkey cert: %w", err)
	}
	doc.SubkeyCert = canonCert
	return signDoc(doc, subkeyPriv)
}

// signDoc pads, signs and emits the canonical published bytes.
func signDoc(doc *Document, priv ed25519.PrivateKey) ([]byte, error) {
	if doc.Kind != Kind {
		return nil, fmt.Errorf("freshness: refusing to sign kind %q (want %q)", doc.Kind, Kind)
	}
	if doc.Sequence == 0 || doc.Sequence > maxSequence {
		return nil, errors.New("freshness: document sequence out of range")
	}
	if err := padTo(doc); err != nil {
		return nil, err
	}
	body, err := canonicalExcluding(doc, "signature_hex")
	if err != nil {
		return nil, err
	}
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(priv, body))
	return canonicalAll(doc)
}

// padTo sets doc.Pad so the published canonical bytes land on a
// padBucket boundary.
//
// WHAT THIS BUYS. Every recipient of one publisher fetches the
// same URL on a cadence, and the response is small, so its exact
// length is a stable, observable per-publisher signal. Without
// padding the length also MOVES: a rotation changes the URL and
// the digest, an added mirror grows the array, a sub-key cert
// appears and disappears. An on-path observer who cannot read the
// TLS body can still read "the object at this URL changed size
// today" — i.e. can detect a rotation in progress, across every
// recipient at once, and time an IP block to it. Quantising to a
// bucket makes the length constant across all of those states.
//
// It does NOT hide that a fetch happened, the cadence, or the
// fact that two devices fetched the same host; see the leak
// analysis in doc.go for what remains and who owns it.
//
// The math is exact and single-pass because the signature is a
// fixed 128 hex chars and pad is fixed-width ASCII: we canonicalise
// with a placeholder signature, then add the shortfall byte for
// byte.
//
// Quantising, not equalising: a publisher whose URLs push the
// document past one bucket lands in the next one. What is
// guaranteed is that ROTATIONS — the state changes an observer
// would want to detect — do not move the length, because they are
// tens of bytes inside a 2 KiB quantum. Two different publishers
// are not made indistinguishable by this and are not trying to
// be; they are already distinguishable by hostname.
func padTo(doc *Document) error {
	doc.Pad = ""
	doc.SignatureHex = strings.Repeat("0", ed25519.SignatureSize*2)
	probe, err := canonicalAll(doc)
	if err != nil {
		return err
	}
	n := len(probe)
	target := ((n + padBucket - 1) / padBucket) * padBucket
	if target == n {
		return nil
	}
	doc.Pad = strings.Repeat("0", target-n)
	return nil
}

// VerifyOpts feeds VerifyDocument.
type VerifyOpts struct {
	// PublisherRootPub is the bundle's publisher root key.
	// Required.
	PublisherRootPub ed25519.PublicKey

	// Now is the wall-clock used for the not_after check and for
	// cert-chain window checks. Defaults to time.Now().
	Now time.Time

	// ExpectRelayPackID is the caller's installed pack id. When
	// non-empty the document must name it, EITHER as relay_pack_id
	// or in supersedes[]. A recipient MUST set this: it is what
	// stops one signed document being spliced onto a different pack
	// of the same publisher.
	ExpectRelayPackID string

	// MinSequence is the caller's high-water mark — the highest
	// sequence it has ever accepted for this relay_pack_id. A
	// document ABOVE it is accepted; below it is ErrRollback. A
	// document exactly AT it is accepted only when it names the
	// bundle the caller already has — see CurrentBundleSHA256. A
	// recipient MUST persist this across restarts, or the
	// protection lasts exactly as long as the process.
	MinSequence uint64

	// CurrentBundleSHA256 is the digest of the bundle the caller is
	// currently running, if any.
	//
	// It closes the equal-sequence hole. The sequence is a
	// one-second-granularity counter, so two documents published
	// inside the same second — a retried publish, a scripted
	// rotation — share a value. Accepting `==` then makes those two
	// documents interchangeable forever: a censor who captured the
	// FIRST can replay it over the second and walk the device back
	// onto the pre-rotation bundle, with the publisher's own valid
	// signature and revoked credentials. Requiring a STRICT advance
	// whenever the document names a different bundle removes the
	// interchangeability while still letting an unchanged document
	// be re-served all day.
	//
	// Empty means "no installed bundle to compare", and the check
	// degrades to the plain `<` rule.
	CurrentBundleSHA256 string

	// ClockSkew tolerance on not_after; defaults to
	// defaultClockSkew.
	ClockSkew time.Duration
}

// VerifyDocument parses the document, walks the cert chain when
// present, verifies the signature, and enforces the freshness and
// anti-rollback rules. Returns the parsed document on success.
//
// Used by publisher-side tooling AND as the reference for the
// recipient-side core/refresh/ implementation; the two are pinned
// together by a shared canonical-bytes fixture.
func VerifyDocument(docBytes []byte, opts VerifyOpts) (*Document, error) {
	if len(opts.PublisherRootPub) != ed25519.PublicKeySize {
		return nil, errors.New("freshness: PublisherRootPub required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = defaultClockSkew
	}
	var doc Document
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("freshness: malformed document: %w", err)
	}
	if doc.Kind == KindV1 {
		return nil, errors.New("freshness: v1 documents carry no expiry or sequence and are refused; republish at " + Kind)
	}
	if doc.Kind != Kind {
		return nil, errors.New("freshness: unsupported document kind/version")
	}
	if doc.RelayPackID == "" || !isSHA256Hex(doc.CurrentBundleSHA256) || doc.CurrentSignedURL == "" || doc.PublisherPubHex == "" {
		return nil, errors.New("freshness: required fields missing")
	}
	u, err := url.Parse(doc.CurrentSignedURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("freshness: current_signed_url must be https")
	}
	if _, err := time.Parse(time.RFC3339, doc.LastModified); err != nil {
		return nil, fmt.Errorf("freshness: malformed last_modified: %w", err)
	}
	pubHex := hex.EncodeToString(opts.PublisherRootPub)
	if !equalHex(pubHex, doc.PublisherPubHex) {
		return nil, errors.New("freshness: publisher_pub_hex mismatch")
	}
	signingPub := ed25519.PublicKey(opts.PublisherRootPub)
	if len(doc.SubkeyCert) > 0 {
		// Walk the FRP-7.5 chain: cert is signed by root; sub-key
		// is the cert's subject. Cert's validity window enforced
		// by walkSubkeyCert.
		sub, err := walkSubkeyCert(doc.SubkeyCert, opts.PublisherRootPub, now)
		if err != nil {
			return nil, fmt.Errorf("freshness: subkey cert: %w", err)
		}
		signingPub = sub
	}
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("freshness: malformed signature_hex")
	}
	// Canonicalise the RECEIVED bytes, not a re-marshal of the
	// parsed struct: a field added by a newer publisher must not
	// disappear from the body this side verifies. Doing it the
	// other way is why the recipient's byte-for-byte struct copy
	// is a flag day rather than a no-op.
	body, err := canonicalRawExcluding(docBytes, "signature_hex")
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signingPub, body, sig) {
		return nil, errors.New("freshness: signature invalid")
	}

	// ---- post-signature policy -------------------------------
	// Everything below is checked AFTER the signature so an
	// unauthenticated blob can never steer these branches.
	if opts.ExpectRelayPackID != "" && !documentGoverns(&doc, opts.ExpectRelayPackID) {
		return nil, ErrWrongPack
	}
	if doc.Sequence == 0 {
		return nil, errors.New("freshness: sequence must be > 0")
	}
	if err := checkSequence(doc.Sequence, doc.CurrentBundleSHA256, opts.MinSequence, opts.CurrentBundleSHA256); err != nil {
		return nil, err
	}
	notAfter, err := time.Parse(time.RFC3339, doc.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("freshness: malformed not_after: %w", err)
	}
	if now.After(notAfter.Add(skew)) {
		return nil, fmt.Errorf("%w at %s", ErrExpired, doc.NotAfter)
	}
	// A malformed advertised mirror set is not fatal to THIS
	// document — the pack's own signed set still governs — but it
	// must not be adopted, so surface it as an empty set rather
	// than a half-valid one.
	if len(doc.Mirrors) > 0 {
		if _, err := NewMirrorSet(doc.Mirrors); err != nil {
			return nil, fmt.Errorf("freshness: advertised mirror set invalid: %w", err)
		}
	}
	return &doc, nil
}

// documentGoverns reports whether a document addresses the caller's
// installed pack — either because it IS that pack's document, or
// because the publisher signed a statement that this pack succeeds
// it. See Document.Supersedes for why the second branch exists.
func documentGoverns(doc *Document, installed string) bool {
	if doc.RelayPackID == installed {
		return true
	}
	if len(doc.Supersedes) > MaxSupersedes {
		// A publisher-signed list longer than the bound is a
		// publisher bug or a document minted by tooling this build
		// does not understand. Refuse the whole list rather than
		// scanning an unbounded one.
		return false
	}
	for _, id := range doc.Supersedes {
		if id == installed {
			return true
		}
	}
	return false
}

// checkSequence is the anti-rollback ordering, shared by the
// publisher-side verifier and mirrored on the recipient.
//
// `>` when the bundle moves, `>=` when it does not. See
// VerifyOpts.CurrentBundleSHA256 for why equality alone is not safe:
// the sequence has one-second granularity, so two documents can share
// one, and if they name different bundles then accepting `==` makes
// them interchangeable in both directions forever.
func checkSequence(docSeq uint64, docBundle string, minSeq uint64, haveBundle string) error {
	if docSeq > minSeq {
		return nil
	}
	if docSeq < minSeq {
		return fmt.Errorf("%w: got %d, have %d", ErrRollback, docSeq, minSeq)
	}
	if haveBundle == "" || equalHex(docBundle, haveBundle) {
		return nil
	}
	return fmt.Errorf("%w: sequence %d was already used for a different bundle", ErrRollback, docSeq)
}

// AdvertisedMirrors returns the document's advertised endpoint set
// once it has been through VerifyDocument, or nil when the
// document advertises none.
func (d *Document) AdvertisedMirrors() *MirrorSet {
	if d == nil || len(d.Mirrors) == 0 {
		return nil
	}
	set, err := NewMirrorSet(d.Mirrors)
	if err != nil {
		return nil
	}
	return set
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
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

func canonicalRawJSON(raw []byte) (json.RawMessage, error) {
	b, err := canonicalRawExcluding(raw, "")
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
