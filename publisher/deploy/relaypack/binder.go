package relaypack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fieldreport"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/cloudflare"
	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/modifiers"
	"daal/publisher/deploy/provider"
)

// defaultExpiry is the bundle validity window when BindOpts.Expiry
// is zero. 30 days is the V1.5 ship default agreed at FRP-4b spec
// review (rotation lands at FRP-7; recipients re-import on next
// QR scan).
const defaultExpiry = 30 * 24 * time.Hour

// defaultPublisherDisplayName is used when BindOpts.PublisherDisplayName
// is empty. Kept neutral; the Helper UI lets the operator override.
const defaultPublisherDisplayName = "Family Relay Publisher"

// BindOpts configures BindAndSign. Now is the only non-deterministic
// input; same (rec, priv, opts) ⇒ byte-identical .sbp output.
type BindOpts struct {
	// Now is stamped into Bundle.CreatedAt and used as the base for
	// expiry windows. The CLI exposes --now-unix to make determinism
	// testable at the binary boundary.
	Now time.Time

	// Expiry is the bundle validity window. Default 30 days.
	Expiry time.Duration

	// Phase selects the validator gate. V1.5 at FRP-4b ship; FRP-8
	// flips to V1.6 to lift cdn_fronted; FRP-12 to PostV2 to lift
	// modifiers.
	Phase relaypackvalidate.Phase

	// Freshness is the pack's freshness endpoint SET. Nil means the
	// pack ships without remote replacement (V1.5 behaviour: RP021
	// rejects a populated slot there anyway).
	//
	// It is a *freshness.MirrorSet and not a string on purpose. The
	// slot in the manifest is a single string, and a single fixed
	// URL is a censorship target with a shorter shelf life than the
	// relay it describes — so the type a caller has to construct
	// cannot hold fewer than freshness.MinMirrors entries on
	// distinct providers. There is no way to reach BindAndSign with
	// one host; the previous `FreshnessURL string` field was
	// removed rather than deprecated for that reason.
	//
	// When set, BindAndSign writes BOTH:
	//   - manifest.relay_pack.freshness_url  = set.LegacyScalarURL()
	//   - trust/freshness-mirrors.json       = the signed set
	// See freshness.MirrorsArchivePath for why the set travels as
	// an archive entry instead of a manifest field.
	Freshness *freshness.MirrorSet

	// RevocationURL is the publisher's signed revocation list
	// endpoint, written to manifest.publisher.revocation_url.
	//
	// Leaving it empty is what has kept the ENTIRE revocation
	// subsystem inert: core/routestore.ListPublishersWithRevocationURL
	// selects `WHERE revocation_url <> ''`, so with no publisher
	// ever setting it, the per-publisher revocation refresher
	// iterates zero rows on every device, forever, while the code
	// that would act on a revocation sits fully written and tested.
	RevocationURL string

	// RevocationPubHex is the revocation list's SIGNING PUBLIC KEY
	// in hex (32 bytes), written to
	// manifest.publisher.revocation_fingerprint_hex.
	//
	// The field name says "fingerprint" and the value is not one.
	// core/refresh/revocation.go:refreshOne hex-decodes this field
	// and uses it directly as the ed25519.PublicKey that verifies
	// the fetched list ("the hex field is the SHA-256 of the key,
	// not the key itself... for Phase 1.5A we treat it as a key
	// pin"). Writing an actual fingerprint here produces the
	// `bad_fingerprint` outcome on every refresh — a failure that
	// only shows up in an audit row on a recipient's device. So
	// BindAndSign requires a 32-byte hex value and rejects
	// anything else at sign time, where the publisher can see it.
	RevocationPubHex string

	// PublisherDisplayName is the human-readable name shown to the
	// recipient on TOFU. Optional; defaults to "Family Relay
	// Publisher".
	PublisherDisplayName string

	// Endpoint, when non-nil, is the relay's own live connection
	// material (the relay-wide fields of a `users-provision` reply). It
	// fills whatever the OperatorRecord does not carry — the record has
	// no shadowsocks key at all, and on a relay provisioned without the
	// SSH read it has no REALITY key or TLS pin either. See
	// EndpointMaterial.Overlay for the precedence.
	Endpoint *EndpointMaterial

	// RelayIdentity, when non-nil, is what the relay itself said it is
	// just before this signature (mgmt GET /identity). Where it speaks
	// it outranks the record — see EndpointMaterial.PreferRelay — and
	// Endpoint then fills whatever is still empty.
	RelayIdentity *EndpointMaterial

	// SubkeyCertJSON is optional FRP-7.5 cert-chain material. When
	// non-empty, priv is allowed to be the certified sub-key while
	// rec.PublisherPubKey remains the root publisher key shipped as
	// publisher.pub. The bundle is emitted at spec_version=4 with
	// trust/subkey-cert.json.
	SubkeyCertJSON []byte

	// ReportTo, when set, is the publisher's network-test report
	// address (`daal1…`, from `report-keygen`). It is written into
	// every route's signed family_specific_config as `_report_to`
	// (specs/field-probe-v2.md, specs/relaypack-v1.md): that marks this
	// pack's relay as the Test relay, and the app seals each network
	// test result to it. Every route gets it, because the app refuses
	// a Test relay whose address also serves a route without it
	// (`test_relay_shared`). Empty = an ordinary pack, byte for byte as
	// before.
	ReportTo string

	// CDN, when non-nil, adds the way in through Cloudflare (add-on 2)
	// as one more route: websocket-tls, exposure cdn_fronted, committed
	// by `_cdn_endpoint` and never by `_endpoint` (specs/relaypack-v1.md,
	// "The CDN-fronted endpoint"). Nil signs exactly as before. Needs
	// Phase V1.6 or later (RP004).
	CDN *CDNFront
}

// CDNFront is what the binder signs for the way in through Cloudflare.
// Everything in it is public metadata: the hostname, the edge prefixes
// and the ECH configuration are the same for every recipient, and the
// WebSocket path (a credential) is not here at all — the minter puts it
// in each recipient's profile.
type CDNFront struct {
	// Front is the record cdn-provision wrote. The binder reads its
	// hostname, its attestation fields and Front.ECH.ConfigListB64, and
	// no file it names.
	Front *cloudflare.FrontRecord
	// EdgeSeeds are 1–8 prefixes from Cloudflare's published ranges,
	// read by the publisher abroad at sign time. Canonicalised here.
	EdgeSeeds []string
	// TLSRootsSHA256 are the standard-base64 SHA-256 digests of the
	// SubjectPublicKeyInfo of the roots the app ships for the edge
	// (CDNRootDigests computes them from PEM).
	TLSRootsSHA256 []string
	// PlainFallback is the signed flag of owner decision D-2: a hello
	// without ECH (which shows the zone name) only when set.
	PlainFallback bool
}

// CDNEdgePort is the port recipients dial at the Cloudflare edge. The
// relay door's own port (relayports.CDNOrigin) is Cloudflare's to dial
// and appears nowhere in the pack.
const CDNEdgePort = 443

// ErrCDNCandidateInRecord refuses a record that already carries a
// cdn_fronted candidate: the front reaches the binder through
// BindOpts.CDN only, so there is one way such a route is signed.
var ErrCDNCandidateInRecord = errors.New("relaypack: the record carries a cdn_fronted candidate; pass the way in through Cloudflare as BindOpts.CDN")

// ReportToKey is the reserved family_specific_config key naming the
// network-test report address.
const ReportToKey = "_report_to"

// ErrBadReportTo is returned when BindOpts.ReportTo is not a valid
// `daal1…` address.
var ErrBadReportTo = errors.New("relaypack: ReportTo must be a daal1… report address")

// BindResult is returned by BindAndSign. Carries the signed .sbp
// bytes plus the metadata the wizard renders on screen 6.
type BindResult struct {
	// SBPBytes is the deterministic signed bundle.
	SBPBytes []byte

	// BundleSHA256 is hex(sha256(SBPBytes)).
	BundleSHA256 string

	// FingerprintHex / EN / FA describe the publisher key
	// (sha256(pub) + per-implementation wordlist mappings).
	FingerprintHex string
	FingerprintEN  string
	FingerprintFA  string

	// LintReport carries non-blocking warnings (RP019 / RP020). The
	// wizard surfaces these in a yellow banner; they never halt the
	// bind.
	LintReport relaypackvalidate.LintReport

	// RelayPackID is the deterministic id derived by DeriveRelayPackID.
	RelayPackID string

	// SharedRiskGraph is the bundle-wide §12.3 graph (signed inside
	// the bundle; surfaced here for the wizard's diagnostics view).
	SharedRiskGraph []bundle.SharedRiskEdge

	// Uncommitted lists every route that was signed WITHOUT an endpoint
	// commitment because the material its family needs was missing.
	// Those routes can never be made connectable from this pack: the
	// recipient's client refuses an outbound it cannot check against a
	// signed endpoint. Callers MUST surface this — it is the same
	// "the pack is one tier smaller than you think" notice as
	// RewriteProfilesForRecipient's skipped list, one step earlier.
	Uncommitted []SkippedRoute

	// Committed is the relay identity this pack's signed endpoints
	// actually carry, read back out of the routes that were signed. A
	// caller keeps it to tell, later, whether the relay has moved away
	// from what its recipients' packs commit to.
	Committed CommittedIdentity
}

// errors -------------------------------------------------------------

var (
	// ErrNilRecord is returned when BindAndSign is called with rec=nil.
	ErrNilRecord = errors.New("relaypack: nil OperatorRecord")
	// ErrEmptyPrivKey is returned when priv is zero-length or wrong size.
	ErrEmptyPrivKey = errors.New("relaypack: empty or wrong-size ed25519 private key")
	// ErrMissingPubKey is returned when rec.PublisherPubKey is empty.
	ErrMissingPubKey = errors.New("relaypack: OperatorRecord.PublisherPubKey is empty")
	// ErrPubKeyMismatch is returned when the privkey's public half
	// disagrees with rec.PublisherPubKey.
	ErrPubKeyMismatch = errors.New("relaypack: priv.Public() does not match OperatorRecord.PublisherPubKey")
	// ErrSubkeyCertWithRootKey is returned when callers supply a
	// sub-key cert but still pass the root private key. The cert-chain
	// path must actually sign with the certified sub-key.
	ErrSubkeyCertWithRootKey = errors.New("relaypack: sub-key cert supplied with root signing key")
	// ErrNoPhase is returned when opts.Phase is empty.
	ErrNoPhase = errors.New("relaypack: BindOpts.Phase is required")
	// ErrBadRevocationPub is returned when RevocationURL is set
	// without a 32-byte hex signing key beside it (or vice versa).
	// A revocation URL with no verifying key is a URL the recipient
	// polls and can never act on.
	ErrBadRevocationPub = errors.New("relaypack: RevocationURL requires a 32-byte hex RevocationPubHex (the list's SIGNING KEY, not a fingerprint)")
	// ErrBadRevocationURL is returned when RevocationURL is not an
	// absolute https URL.
	ErrBadRevocationURL = errors.New("relaypack: RevocationURL must be an absolute https:// URL")
)

// BindAndSign is the FRP-4b binder.
//
// Pure function: same (rec, priv, opts) ⇒ byte-identical .sbp output.
// Reads no environment, opens no network connections, touches no files.
//
// Steps:
//
//  1. Validate inputs (nil record, key shape, key/record agreement).
//  2. Render the OperatorRecord candidates into bundle routes +
//     RelayPackEntry objects via candidate_render.
//  3. Compute the deterministic RelayPackID and the bundle-wide
//     shared_risk_graph.
//  4. Build the bundle.Manifest with SpecVersion=3, Publisher info,
//     Bundle id/type/created/expires, Routes, and the RelayPack slot.
//  5. Run relaypackvalidate.Validate(b, ValidateOpts{Phase: opts.Phase})
//     BEFORE signing. Hard-stop on any error (RP001..RP018/RP021);
//     LintReport carries non-blocking RP019/RP020 warnings.
//  6. Sign deterministically via bundle.BuildSignedBundleDeterministic.
//  7. Compute bundle-byte sha256 + the publisher fingerprint render.
//
// Signature locked at FRP-4b spec §5; BindResult shape locked there too.
func BindAndSign(rec *provider.OperatorRecord, priv ed25519.PrivateKey, opts BindOpts) (*BindResult, error) {
	// ---- 1. Input validation -------------------------------------
	if rec == nil {
		return nil, ErrNilRecord
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrEmptyPrivKey
	}
	if isAllZero(priv) {
		return nil, ErrEmptyPrivKey
	}
	if len(rec.PublisherPubKey) == 0 {
		return nil, ErrMissingPubKey
	}
	rootPub := ed25519.PublicKey(rec.PublisherPubKey)
	signingPub := ed25519.PublicKey(priv.Public().(ed25519.PublicKey))
	usingSubkey := len(opts.SubkeyCertJSON) > 0
	if !usingSubkey && !bytes.Equal(signingPub, rootPub) {
		return nil, ErrPubKeyMismatch
	}
	if usingSubkey && bytes.Equal(signingPub, rootPub) {
		return nil, ErrSubkeyCertWithRootKey
	}
	if opts.Phase == "" {
		return nil, ErrNoPhase
	}
	// Freshness sanity before any work: a MirrorSet can only exist
	// in a valid state, but a caller can still hand us a non-nil
	// zero value.
	// MeetsFloor is the two-mirror rule with its one exception (D-3:
	// a set whose only provider is appsscript).
	if opts.Freshness != nil && !opts.Freshness.MeetsFloor() {
		return nil, freshness.ErrTooFewMirrors
	}
	revocationURL, revocationPub, err := normaliseRevocation(opts.RevocationURL, opts.RevocationPubHex)
	if err != nil {
		return nil, err
	}
	reportTo := strings.TrimSpace(opts.ReportTo)
	if reportTo != "" {
		if _, err := fieldreport.DecodeAddress(reportTo); err != nil {
			return nil, ErrBadReportTo
		}
	}

	now := opts.Now.UTC()
	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultExpiry
	}
	displayName := opts.PublisherDisplayName
	if displayName == "" {
		displayName = defaultPublisherDisplayName
	}

	createdAt := now.Format(time.RFC3339)
	expiresAt := now.Add(expiry).Format(time.RFC3339)

	// ---- 2. Render candidates ------------------------------------
	material := EndpointMaterialFromRecord(rec)
	if opts.RelayIdentity != nil {
		material = material.PreferRelay(*opts.RelayIdentity)
	}
	if opts.Endpoint != nil {
		material = material.Overlay(*opts.Endpoint)
	}
	renderRec := rec
	cdnRouteID := ""
	if opts.CDN != nil {
		for _, c := range rec.Candidates {
			if c.ExposureMode == "cdn_fronted" {
				return nil, ErrCDNCandidateInRecord
			}
		}
		meta, err := cdnCandidate(rec, opts.CDN)
		if err != nil {
			return nil, err
		}
		cp := *rec
		cp.Candidates = append(append([]provider.CandidateMeta(nil), rec.Candidates...), meta)
		renderRec = &cp
		cdnRouteID = fmt.Sprintf("r%d", len(cp.Candidates))
	}
	rendered, err := renderCandidates(renderRec, material, createdAt, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("relaypack: render candidates: %w", err)
	}
	// Before _standby: the CDN route must carry no _endpoint by the
	// time eligibility for a standby is read.
	if cdnRouteID != "" {
		if err := rendered.setCDNEndpoint(cdnRouteID, opts.CDN); err != nil {
			return nil, err
		}
	}
	if reportTo != "" {
		if err := rendered.setReportTo(reportTo); err != nil {
			return nil, fmt.Errorf("relaypack: %w", err)
		}
	}
	// The standby address add-on: `_standby` beside each `_endpoint`
	// (endpoint.go). A record without one renders exactly as before.
	if err := rendered.setStandby(rec.Standby); err != nil {
		return nil, err
	}
	// A pack in which not one servable route has a signed endpoint is a
	// pack every recipient's client will refuse. Do not sign it.
	if committable, committed := countCommitments(rendered); committable > 0 && committed == 0 {
		return nil, ErrNoEndpointMaterial
	}

	// ---- 3. RelayPackID + shared_risk_graph ---------------------
	relayPackID := DeriveRelayPackID(rec)
	srg := BuildSharedRiskGraph(rendered.ids, rendered.entries)

	// ---- 4. Build the manifest -----------------------------------
	specVersion := 3
	extras := map[string][]byte{}
	if usingSubkey {
		specVersion = 4
		extras["trust/subkey-cert.json"] = append([]byte(nil), opts.SubkeyCertJSON...)
	}
	// WAVE 5. A pack that names anytls MUST declare spec_version 5, and
	// a pack that does not MUST NOT — the condition is exactly "does
	// this pack contain such a route", never "is this a new build".
	//
	// Both directions matter and they matter for opposite reasons.
	//
	// Bumping when anytls IS present: every client shipped before Wave 5
	// rejects an unknown transport_family by failing the WHOLE bundle
	// (bundle/go/bundle/sbp.go's route loop, mirrored in
	// bundle-rs/src/sbp.rs), and its importer classifies that as
	// "bundle_corrupted". Declaring 5 makes the same old client stop at
	// the spec gate instead, which sits BEFORE the route loop, and
	// report an unsupported spec version — true, actionable, and not an
	// accusation that the file arrived damaged. bundle.validateRoute
	// enforces the same rule from the verifying side, so a pack that
	// skipped this line would fail to verify on the publisher's own
	// machine rather than in a recipient's hands.
	//
	// NOT bumping when anytls is absent is the more important half. It
	// is what makes adding this family cost nothing for anyone who is
	// not offered it: an operator whose profile leaves anytls disabled
	// keeps minting spec-3/4 packs that every already-distributed client
	// imports exactly as before. The blast radius of this whole wave is
	// therefore confined to packs that actually carry the new route.
	if anyFamily(rendered.routes, string(bundle.TransportAnyTLS)) &&
		specVersion < bundle.SpecVersionAnyTLS {
		specVersion = bundle.SpecVersionAnyTLS
	}
	// The mirror set travels as a signed archive entry, NOT as a
	// manifest field, and therefore does NOT bump spec_version.
	// bundle.VerifyManifest verifies over
	// CanonicalManifestJSON(parsed struct), so a manifest field an
	// already-distributed client does not know is dropped on its
	// side before canonicalisation and the whole pack fails to
	// verify. An unknown archive entry is simply ignored (ParseSBP
	// keeps only the names it knows), which is the same route the
	// FRP-11 cell documents took. Old client: sees freshness_url,
	// polls one host. New client: reads the set. Neither breaks.
	if opts.Freshness != nil {
		// notAfter is the ENCLOSING BUNDLE's expires_at, not a TTL of
		// its own. The mirror set says where to look for this pack, so
		// letting it outlive the pack would leave a signed, in-transit-
		// mutable list of hosts valid forever — see MirrorDoc.NotAfter.
		mirrorsJSON, err := freshness.SignMirrors(
			opts.Freshness, relayPackID, rootPub, priv, opts.SubkeyCertJSON, now, now.Add(expiry))
		if err != nil {
			return nil, fmt.Errorf("relaypack: sign freshness mirrors: %w", err)
		}
		extras[freshness.MirrorsArchivePath] = mirrorsJSON
	}
	if len(extras) == 0 {
		extras = nil
	}
	fingerprint := bundle.PublisherFingerprint(rootPub)
	manifest := bundle.Manifest{
		SpecVersion: specVersion,
		Publisher: bundle.PublisherInfo{
			Name:              displayName,
			KeyFingerprintHex: fingerprint.Hex,
			KeyCreatedAt:      createdAt,
			TrustClass:        "unknown",
			// Both halves or neither — normaliseRevocation has
			// already refused a URL without a key.
			RevocationURL:            revocationURL,
			RevocationFingerprintHex: revocationPub,
		},
		Bundle: bundle.BundleInfo{
			ID:             relayPackID,
			Type:           "provider",
			CreatedAt:      createdAt,
			ExpiresAt:      expiresAt,
			SupersedesKeys: []string{},
		},
		Routes: rendered.routes,
		RelayPack: &bundle.RelayPack{
			RelayPackID:     relayPackID,
			SharedRiskGraph: srg,
			// Empty when Freshness is nil. Never a lone host: the
			// scalar is only ever written together with the signed
			// mirror set above.
			FreshnessURL: opts.Freshness.LegacyScalarURL(),
		},
	}

	// ---- 5. Validate BEFORE signing ------------------------------
	// We need a Bundle, not a Manifest, because relaypackvalidate
	// reads both Manifest.RelayPack and per-route FamilySpecificConfig
	// off a Bundle struct.
	preBundle := &bundle.Bundle{Manifest: manifest, PublisherPub: rootPub}
	// FRP-12: populate AllowedModifierKinds from the modifier
	// registry. At FRP-12 ship the registry has zero PASS records
	// (locked invariant 37) so this map is empty and RP013 keeps
	// rejecting every non-empty modifiers[] array. The wiring
	// itself is what FRP-12 ships; the first concrete PASS record
	// is a separate post-track phase that re-runs genregistry with
	// --allow-pass.
	lintReport, err := relaypackvalidate.Validate(preBundle, relaypackvalidate.ValidateOpts{
		Phase:                opts.Phase,
		AllowedModifierKinds: allowedModifierKindsForPhase(opts.Phase),
	})
	if err != nil {
		return nil, fmt.Errorf("relaypack validate (%s): %w", opts.Phase, err)
	}
	// The add-on members (RP026 `_cdn_endpoint`, RP027 `_standby`):
	// checks a recipient's importer would refuse a route for, run here
	// so the publisher sees them instead.
	if err := relaypackvalidate.ValidateForSigning(preBundle); err != nil {
		return nil, fmt.Errorf("relaypack validate for signing: %w", err)
	}

	// ---- 6. Sign deterministically -------------------------------
	sbpBytes, err := bundle.BuildSignedBundleDeterministic(manifest, rendered.profiles, extras, rootPub, priv)
	if err != nil {
		return nil, fmt.Errorf("relaypack: sign: %w", err)
	}

	// ---- 7. Render fingerprint + final result --------------------
	sum := sha256.Sum256(sbpBytes)
	bundleSHA := hex.EncodeToString(sum[:])
	rendered2, _ := bundle.RenderFingerprint(fingerprint, defaultWordlists())

	return &BindResult{
		SBPBytes:        sbpBytes,
		BundleSHA256:    bundleSHA,
		FingerprintHex:  fingerprint.Hex,
		FingerprintEN:   rendered2.EN,
		FingerprintFA:   rendered2.FA,
		LintReport:      lintReport,
		RelayPackID:     relayPackID,
		SharedRiskGraph: srg,
		Uncommitted:     rendered.uncommitted,
		Committed:       committedIdentity(rendered.routes),
	}, nil
}

// countCommitments reports how many rendered routes are of a family
// Daal can commit an endpoint for, and how many of those got one.
func countCommitments(r *renderedCandidates) (committable, committed int) {
	missing := map[string]bool{}
	for _, u := range r.uncommitted {
		missing[u.RouteID] = true
	}
	for _, route := range r.routes {
		if !bundle.EndpointFamilySupported(route.TransportFamily) {
			continue
		}
		committable++
		if !missing[route.ID] {
			committed++
		}
	}
	return committable, committed
}

// normaliseRevocation validates the revocation pair and returns
// the values to stamp on PublisherInfo.
//
// Empty+empty is legal (a publisher with no revocation endpoint).
// Anything else must be a complete, usable pair, because both
// half-configured states fail silently on the recipient:
//   - URL without key → refreshOne records `missing_fingerprint`
//     in an audit row and returns;
//   - key without URL → the publisher row is never selected at
//     all, because the query filters on a non-empty
//     revocation_url.
//
// Both are invisible from the publisher's side, so they are
// refused here where the operator is watching.
func normaliseRevocation(rawURL, pubHex string) (string, string, error) {
	if rawURL == "" && pubHex == "" {
		return "", "", nil
	}
	if rawURL == "" || pubHex == "" {
		return "", "", ErrBadRevocationPub
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", "", ErrBadRevocationURL
	}
	// 32 raw bytes == 64 hex chars. This is a signing key.
	if len(pubHex) != ed25519.PublicKeySize*2 {
		return "", "", ErrBadRevocationPub
	}
	if _, err := hex.DecodeString(pubHex); err != nil {
		return "", "", ErrBadRevocationPub
	}
	return rawURL, strings.ToLower(pubHex), nil
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// allowedModifierKindsForPhase translates the validator's Phase
// enum into the modifier-registry equivalent and returns the
// AllowedModifierKinds map for relaypackvalidate.ValidateOpts.
//
// At FRP-12 ship every registered kind is PENDING, so the returned
// map is empty for every phase (locked invariant 37). The first
// concrete modifier PASS record is a separate post-track phase.
func allowedModifierKindsForPhase(p relaypackvalidate.Phase) map[string]bool {
	var rp modifiers.Phase
	switch p {
	case relaypackvalidate.PhaseV15:
		rp = modifiers.PhaseV15
	case relaypackvalidate.PhaseV16:
		rp = modifiers.PhaseV16
	case relaypackvalidate.PhasePostV2:
		rp = modifiers.PhasePostV2
	default:
		return map[string]bool{}
	}
	return modifiers.AllowedKindsAt(rp)
}

// defaultWordlists returns the 16-word EN+FA placeholders that the
// FRP-5 wizard ports verbatim. FRP-7.5 lifts both sides to BIP-39 +
// curated Persian; the same commit will replace this list AND the
// Rust-side EN_WORDLIST/FA_WORDLIST in publisher_key.rs.
//
// Kept small and identical to bundle/go/publisher/keystore.go's
// defaultWordlists so cross-implementation parity holds at FRP-4b.
func defaultWordlists() bundle.Wordlists {
	return bundle.Wordlists{
		English: []string{
			"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
			"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
		},
		Persian: []string{
			"یک", "دو", "سه", "چهار", "پنج", "شش", "هفت", "هشت",
			"نه", "ده", "یازده", "دوازده", "سیزده", "چهارده", "پانزده", "شانزده",
		},
	}
}

// ---- the way in through Cloudflare (add-on 2) ----------------------

// cdnCandidate is the one candidate the binder adds for the front. It
// borrows the family class and Params of the relay's direct
// websocket-tls candidate when there is one (multiplex and the like
// are the same on both doors), and takes its tags from the front:
// `cdn:cloudflare` and the hostname in public_risk_tags (RP005), the
// relay's address in origin_risk_tags (RP006), and the attestation
// RP022/RP023 read.
func cdnCandidate(rec *provider.OperatorRecord, cdn *CDNFront) (provider.CandidateMeta, error) {
	f := cdn.Front
	if f == nil {
		return provider.CandidateMeta{}, errors.New("relaypack: CDN: no front record")
	}
	host, err := cloudflare.NormalizeHostname(f.Hostname)
	if err != nil {
		return provider.CandidateMeta{}, fmt.Errorf("relaypack: CDN: %w", err)
	}
	if rec.PublicIP == nil {
		return provider.CandidateMeta{}, errors.New("relaypack: CDN: the record has no relay address for origin_risk_tags")
	}
	meta := provider.CandidateMeta{
		Family:           string(bundle.TransportWebSocketTLS),
		ExposureMode:     "cdn_fronted",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		Port:             CDNEdgePort,
		PublicRiskTags:   []string{"cdn:" + bundle.CDNCloudflare, "public_domain:" + host},
		OriginRiskTags:   []string{"origin_ip:" + rec.PublicIP.String()},
		CDNAttestation: &provider.CDNAttestation{
			OriginCAFingerprint: f.OriginCAFingerprint,
			AOPEnabled:          f.AOPEnabled,
			FirewallID:          f.FirewallID,
			// cdn-provision creates proxied records only.
			DNSOnlyPresent: false,
		},
	}
	for _, c := range rec.Candidates {
		if normaliseFamily(c.Family) == string(bundle.TransportWebSocketTLS) && c.ExposureMode != "cdn_fronted" {
			if c.FamilyClass != "" {
				meta.FamilyClass = c.FamilyClass
			}
			if c.ProbingRiskClass != "" {
				meta.ProbingRiskClass = c.ProbingRiskClass
			}
			meta.Params = append([]byte(nil), c.Params...)
			break
		}
	}
	return meta, nil
}

// setCDNEndpoint turns the rendered CDN route into a CDN-fronted one:
// whatever `_endpoint` the direct renderer gave it goes (a CDN route
// never carries one — RP026, and every earlier build would refuse the
// pack for the unknown members if it went there), `_cdn_endpoint` is
// written from the front, and the route leaves the uncommitted list.
func (r *renderedCandidates) setCDNEndpoint(routeID string, cdn *CDNFront) error {
	ep, err := cdnEndpointFor(cdn)
	if err != nil {
		return err
	}
	for i := range r.routes {
		if r.routes[i].ID != routeID {
			continue
		}
		fc := map[string]any{}
		if err := json.Unmarshal(r.routes[i].FamilySpecificConfig, &fc); err != nil {
			return fmt.Errorf("route %s: family_specific_config: %w", routeID, err)
		}
		delete(fc, bundle.EndpointKey)
		fc[bundle.CDNEndpointKey] = ep
		b, err := json.Marshal(fc)
		if err != nil {
			return fmt.Errorf("route %s: marshal family_specific_config: %w", routeID, err)
		}
		r.routes[i].FamilySpecificConfig = b
		r.profiles[r.routes[i].ConfigPath] = b
		kept := r.uncommitted[:0]
		for _, u := range r.uncommitted {
			if u.RouteID != routeID {
				kept = append(kept, u)
			}
		}
		r.uncommitted = kept
		return nil
	}
	return fmt.Errorf("relaypack: CDN route %s was not rendered", routeID)
}

// cdnEndpointFor builds and validates the signed commitment. The ECH
// configuration is the one cdn-provision (or the last freshness
// publish) read over DoH from abroad; empty means the zone serves none,
// and then only a signed plain_fallback makes the route dialable —
// ValidateForSigning refuses the other case (RP026).
func cdnEndpointFor(cdn *CDNFront) (*bundle.CDNEndpoint, error) {
	host, err := cloudflare.NormalizeHostname(cdn.Front.Hostname)
	if err != nil {
		return nil, fmt.Errorf("relaypack: CDN: %w", err)
	}
	seeds := make([]string, 0, len(cdn.EdgeSeeds))
	seen := map[string]bool{}
	for _, s := range cdn.EdgeSeeds {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("relaypack: CDN: edge seed %q: %w", s, err)
		}
		c := p.Masked().String()
		if !seen[c] {
			seen[c] = true
			seeds = append(seeds, c)
		}
	}
	ep := &bundle.CDNEndpoint{
		V:              bundle.CDNEndpointVersion,
		Server:         host,
		Port:           CDNEdgePort,
		ServerName:     host,
		CDN:            bundle.CDNCloudflare,
		EdgeSeeds:      seeds,
		ECHConfig:      strings.TrimSpace(cdn.Front.ECH.ConfigListB64),
		TLSRootsSHA256: append([]string(nil), cdn.TLSRootsSHA256...),
		PlainFallback:  cdn.PlainFallback,
	}
	if err := ep.Validate(string(bundle.TransportWebSocketTLS)); err != nil {
		return nil, fmt.Errorf("relaypack: CDN: %w", err)
	}
	return ep, nil
}

// CDNRootDigests returns the `tls_roots_sha256` entries for a PEM
// bundle of root certificates: standard base64 of the SHA-256 of each
// certificate's SubjectPublicKeyInfo, in file order, without repeats.
// Anything in the bundle that is not a CA certificate is refused.
func CDNRootDigests(pemBundle []byte) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	rest := pemBundle
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("relaypack: CDN roots: a %q block is not a certificate", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("relaypack: CDN roots: %w", err)
		}
		if !c.IsCA {
			return nil, errors.New("relaypack: CDN roots: a certificate in the bundle is not a CA")
		}
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		d := base64.StdEncoding.EncodeToString(sum[:])
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("relaypack: CDN roots: no certificate in the bundle")
	}
	return out, nil
}
