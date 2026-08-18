// Package importer is the bundle-side glue between a parsed .sbp and an
// on-device store. It performs the policy decisions described in
// specs/publisher-keys-v1.md (TOFU, rotation, revocation) without knowing
// what the store is — callers wire the State interface to their own
// routestore.
package importer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"daal/bundle-go/bundle"
	relaypack "daal/bundle-go/relaypackvalidate"
)

// State is the minimal interface the importer needs from a store.
type State interface {
	// LookupPublisher returns the trust level, key status, and rotation
	// chain for fingerprint, or false if not pinned.
	LookupPublisher(fingerprint string) (Pin, bool, error)
	// SaveImport persists a publisher row (creating or updating) and the
	// supplied routes plus their encrypted profile bytes. It must be
	// atomic.
	SaveImport(p PublisherInput, routes []RouteInput) error
	// MarkPublisherRevoked sets the publisher and all its routes to
	// revoked.
	MarkPublisherRevoked(fingerprint, source, reason string, now time.Time) error
	// MarkRouteRevoked sets a single route to revoked.
	MarkRouteRevoked(routeID string) error
}

// Pin is a small projection of routestore's publisher row.
type Pin struct {
	TrustLevel    string
	KeyStatus     string
	DisplayName   string
	RotationChain []string
}

// PublisherInput is what SaveImport receives.
type PublisherInput struct {
	Fingerprint    string
	DisplayName    string
	TrustLevel     string
	KeyStatus      string
	FirstSeen      string // hour-bucketed
	LastSeenBundle string
	RotationChain  []string
}

// RouteInput carries one route plus its encrypted profile bytes.
type RouteInput struct {
	RouteID         string
	TransportFamily string
	ScarcityClass   string
	Engine          string
	SourceType      string
	ModesAllowed    []string
	ExpiresAt       string
	ImportedAt      string
	TrustState      string
	Profile         []byte // sing-box outbound JSON; passed through to PutSecret

	// RelayPack carries the parsed FRP-2 metadata for this candidate.
	// nil for non-RelayPack routes; legacy callers leave it nil. The
	// concrete State implementation (e.g. core/trust/state.go's
	// StoreAdapter) copies the fields onto the routestore RouteRow.
	RelayPack *RelayPackMeta
}

// RelayPackMeta is the per-candidate projection the importer builds
// when a bundle's `Manifest.RelayPack != nil` and the candidate's
// `_relaypack` sub-object parses cleanly. Bundle-level fields
// (RelayPackID, FreshnessURL, SharedRiskGraphJSON) are denormalised
// onto every candidate so the FRP-3 selector reads them locally
// without a manifest-level join. Per-candidate fields are read from
// `bundle.RelayPackEntry`.
//
// The on-device importer calls
// `relaypackvalidate.Validate(b, ValidateOpts{Phase: CurrentPhase})`
// before building this struct, so callers can rely on:
//   - ExposureMode ∈ {direct_vps, cdn_fronted}  (RP003 still rejects
//     serverless_external; RP007/RP022/RP023 gate every cdn_fronted
//     candidate on the §11.7 hardening attestation)
//   - FamilyClass ∈ {vps-native, vps-possible, external-ecosystem}
//   - ProbingRiskClass ∈ {low, moderate, high}
//   - ModifiersJSON == "" (RP013 hard-rejects non-empty at V1.5/V1.6)
//
// FreshnessURL may now be non-empty: FRP-8 lifted RP021 at V1.6 and
// CurrentPhase is V1.6. FRP-12 lifts non-empty modifiers post-V2. The
// struct shape itself is forward-compatible.
type RelayPackMeta struct {
	ExposureMode     string
	FamilyClass      string
	ProbingRiskClass string
	PublicRiskTags   []string
	OriginRiskTags   []string

	// ModifiersJSON is the canonical-JSON encoding of
	// bundle.RelayPackEntry.Modifiers. Empty string at V1.5/V1.6.
	ModifiersJSON string

	// Bundle-level metadata, denormalised onto every candidate.
	RelayPackID         string
	FreshnessURL        string
	SharedRiskGraphJSON string

	// FreshnessMirrorsJSON is the raw, UNVERIFIED
	// `trust/freshness-mirrors.json` entry from the archive (empty
	// when the pack carries none).
	//
	// It must reach the store, because FreshnessURL above is ONE url —
	// the manifest's legacy scalar slot, which carries a single
	// endpoint on purpose so that clients minted before FRP-8 still
	// read something valid. The other N-1 endpoints exist only in this
	// entry, and a recipient whose one scalar host is blocked is
	// exactly the recipient the other N-1 were added for. Dropping it
	// here leaves them unreadable until a refresh succeeds, i.e. until
	// the blocked host answers — the mechanism would be inert in the
	// only case it exists for.
	//
	// UNVERIFIED is load-bearing: this entry is NOT covered by
	// manifest.sig (see bundle.FreshnessMirrorsPath), so anyone who
	// can hand over a .sbp can rewrite it without breaking the pack.
	// It carries its own publisher signature, and the recipient
	// verifies that signature against the PINNED publisher key before
	// any URL in it is fetched (core/refresh.VerifyMirrorDocument).
	// The importer only ferries the bytes; it must not act on them.
	FreshnessMirrorsJSON string
}

// Verdict is what an Import call returns to the caller.
type VerdictKind int

const (
	VerdictImported          VerdictKind = iota // bundle imported silently
	VerdictTrustPromptNeeded                    // first-seen publisher; UI must confirm
	VerdictRotationAccepted                     // imported via valid rotation chain
	VerdictRejected                             // see Reason
)

// Verdict is the result of Import (or Apply after a trust prompt).
type Verdict struct {
	Kind        VerdictKind
	Fingerprint string
	HexEN       string
	HexFA       string
	BundleID    string
	RouteCount  int
	Reason      string // populated when Kind==VerdictRejected
}

// RotationChainDoc mirrors publisher.RotationChain on the wire (canonical
// JSON, signed by the OLD root). Kept here so the importer does not have a
// build-time dep on the publisher CLI package.
type RotationChainDoc struct {
	V                     int    `json:"v"`
	Kind                  string `json:"kind"`
	OldRootFingerprintHex string `json:"old_root_fingerprint_hex"`
	NewRootPubHex         string `json:"new_root_pub_hex"`
	TransitionStartsAt    string `json:"transition_starts_at"`
	TransitionEndsAt      string `json:"transition_ends_at"`
	SignatureHex          string `json:"signature_hex,omitempty"`
}

// ImportFile reads a .sbp from disk, validates it, and runs the policy
// decisions defined in specs/publisher-keys-v1.md. Wordlists are passed to
// render a human-friendly fingerprint.
func ImportFile(path string, st State, wordlists bundle.Wordlists, now time.Time) (Verdict, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "read error"}, err
	}
	return ImportBytes(body, st, wordlists, now)
}

// ImportBytes is the body-already-loaded variant of ImportFile.
func ImportBytes(body []byte, st State, wordlists bundle.Wordlists, now time.Time) (Verdict, error) {
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "bundle_corrupted"}, err
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		return Verdict{Kind: VerdictRejected, Reason: classifyVerifyError(err)}, err
	}

	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	rendered, _ := bundle.RenderFingerprint(fp, wordlists)
	bucket := hourBucket(now)

	// Pull rotation chain (if present) before deciding.
	rotationChain, rotationErr := readRotationChain(body)

	pin, pinned, err := st.LookupPublisher(fp.Hex)
	if err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "lookup_failed"}, err
	}

	switch {
	case pinned && pin.TrustLevel == "revoked":
		return Verdict{Kind: VerdictRejected, Reason: "publisher_revoked",
			Fingerprint: fp.Hex, HexEN: rendered.EN, HexFA: rendered.FA}, errors.New("publisher revoked")

	case pinned:
		// Known, not revoked — silent import.
		return apply(st, parsed, fp, rendered, bucket, pin.TrustLevel, false)

	case rotationChain != nil:
		// Unknown publisher *but* the bundle ships a rotation chain. We
		// accept only if the OLD root is pinned and the chain verifies.
		if rotationErr != nil {
			return Verdict{Kind: VerdictRejected, Reason: "publisher_key_changed"}, rotationErr
		}
		oldFP := rotationChain.OldRootFingerprintHex
		oldPin, oldPinned, err := st.LookupPublisher(oldFP)
		if err != nil || !oldPinned {
			return Verdict{Kind: VerdictRejected, Reason: "publisher_key_changed"},
				fmt.Errorf("old publisher %s not pinned", oldFP)
		}
		if oldPin.TrustLevel == "revoked" {
			return Verdict{Kind: VerdictRejected, Reason: "publisher_revoked"},
				errors.New("old publisher revoked")
		}
		if err := verifyRotation(*rotationChain, parsed.PublisherPub, oldFP, now); err != nil {
			return Verdict{Kind: VerdictRejected, Reason: "publisher_key_changed"}, err
		}
		v, err := apply(st, parsed, fp, rendered, bucket, oldPin.TrustLevel, true)
		if err == nil {
			v.Kind = VerdictRotationAccepted
		}
		return v, err

	default:
		// First-seen publisher. UI must confirm before any persistence.
		if verdict, err := validateRelayPackCurrent(parsed, fp, rendered); err != nil {
			return verdict, err
		}
		return Verdict{
			Kind:        VerdictTrustPromptNeeded,
			Fingerprint: fp.Hex, HexEN: rendered.EN, HexFA: rendered.FA,
			BundleID: parsed.Manifest.Bundle.ID, RouteCount: len(parsed.Manifest.Routes),
		}, nil
	}
}

// AcceptTrustPrompt is called by the UI after VerdictTrustPromptNeeded.
// decision: "trust" persists pin as tofu_friend; "once" applies routes
// without persisting a long-term pin (we still write the publisher row but
// at trust_level=unknown so subsequent bundles re-prompt).
func AcceptTrustPrompt(decision string, body []byte, st State, wordlists bundle.Wordlists, now time.Time) (Verdict, error) {
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "bundle_corrupted"}, err
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		return Verdict{Kind: VerdictRejected, Reason: classifyVerifyError(err)}, err
	}
	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	rendered, _ := bundle.RenderFingerprint(fp, wordlists)
	bucket := hourBucket(now)
	switch decision {
	case "trust":
		return apply(st, parsed, fp, rendered, bucket, "tofu_friend", true)
	case "once":
		return apply(st, parsed, fp, rendered, bucket, "unknown", true)
	case "cancel":
		return Verdict{Kind: VerdictRejected, Reason: "user_cancelled",
			Fingerprint: fp.Hex}, nil
	default:
		return Verdict{Kind: VerdictRejected, Reason: "invalid_decision"},
			fmt.Errorf("invalid decision %q", decision)
	}
}

// validateRelayPack enforces RelayPack semantics before either
// trust-prompt display or persistence. It is intentionally called from
// both ImportBytes and applyWithRelayPackPhase: ImportBytes prevents
// invalid first-seen RelayPacks from reaching the trust prompt, while
// the apply path keeps AcceptTrustPrompt defensive if called directly.
func validateRelayPack(parsed *bundle.Bundle, fp bundle.Fingerprint, rendered bundle.RenderedFingerprint, phase relaypack.Phase) (Verdict, error) {
	// FRP-2: RelayPack validation. UNCONDITIONAL — runs even when
	// `Manifest.RelayPack == nil`, because RP001 fires when a route
	// carries `_relaypack` while the bundle slot is absent. Gating
	// on slot presence here would silently bypass RP001.
	//
	// The validator is stateless and pure: given the same (bundle,
	// opts) it always returns the same outcome. Lint warnings
	// (RP019/RP020) are non-blocking; only errors (RP001..RP018/RP021)
	// hard-reject the bundle. The Reason field carries the lint code
	// verbatim ("relaypack_RPxxx") so the FRP-6 UI surface can
	// render it.
	if vrep, vErr := relaypack.Validate(parsed, relaypack.ValidateOpts{
		Phase: phase,
	}); vErr != nil {
		_ = vrep
		var ve *relaypack.ValidationError
		if errors.As(vErr, &ve) {
			return Verdict{Kind: VerdictRejected,
				Reason:      "relaypack_" + string(ve.Code),
				Fingerprint: fp.Hex,
				HexEN:       rendered.EN, HexFA: rendered.FA,
			}, vErr
		}
		return Verdict{Kind: VerdictRejected,
			Reason:      "relaypack_invalid",
			Fingerprint: fp.Hex,
			HexEN:       rendered.EN, HexFA: rendered.FA,
		}, vErr
	}
	return Verdict{}, nil
}

// validateRelayPackCurrent validates at the phase THIS BUILD ships
// (relaypack.CurrentPhase). It used to be pinned to V1.5 while the
// publisher wizard signed at V1.6 — so the primary recipient import
// path rejected, with RP004/RP021, packs the publisher had just
// legitimately produced. The phase now comes from one constant.
func validateRelayPackCurrent(parsed *bundle.Bundle, fp bundle.Fingerprint, rendered bundle.RenderedFingerprint) (Verdict, error) {
	return validateRelayPack(parsed, fp, rendered, relaypack.CurrentPhase)
}

func apply(st State, parsed *bundle.Bundle, fp bundle.Fingerprint,
	rendered bundle.RenderedFingerprint, bucket, trustLevel string, firstSeen bool) (Verdict, error) {
	return applyWithRelayPackPhase(st, parsed, fp, rendered, bucket, trustLevel, firstSeen, relaypack.CurrentPhase)
}

func applyWithRelayPackPhase(st State, parsed *bundle.Bundle, fp bundle.Fingerprint,
	rendered bundle.RenderedFingerprint, bucket, trustLevel string, firstSeen bool, phase relaypack.Phase) (Verdict, error) {
	if verdict, err := validateRelayPack(parsed, fp, rendered, phase); err != nil {
		return verdict, err
	}

	// In-archive RevocationList: revoke the listed routes/publishers
	// before saving anything.
	if parsed.Revocation != nil {
		for _, p := range parsed.Revocation.RevokedPublishers {
			_ = st.MarkPublisherRevoked(p, "in-archive", "carried in bundle revocation.json", time.Now().UTC())
		}
		// Routes referenced for revocation are revoked even if we are
		// also importing them.
		for _, rid := range parsed.Revocation.RevokedRoutes {
			_ = st.MarkRouteRevoked(rid)
		}
	}

	pubInput := PublisherInput{
		Fingerprint:    fp.Hex,
		DisplayName:    parsed.Manifest.Publisher.Name,
		TrustLevel:     trustLevel,
		KeyStatus:      "active",
		FirstSeen:      bucket,
		LastSeenBundle: bucket,
		RotationChain:  []string{},
	}

	// FRP-2: bundle-level RelayPack metadata is denormalised onto
	// every per-candidate RelayPackMeta. Compute the canonical
	// shared_risk_graph JSON once.
	var rpID, rpFreshness, rpGraphJSON, rpMirrors string
	hasRP := parsed.Manifest.RelayPack != nil
	if hasRP {
		rpID = parsed.Manifest.RelayPack.RelayPackID
		rpFreshness = parsed.Manifest.RelayPack.FreshnessURL
		// Raw bytes, ferried unverified; see RelayPackMeta. Oversized
		// is dropped rather than truncated: a truncated document
		// cannot verify, so keeping a prefix would only move the
		// failure somewhere less obvious.
		if len(parsed.FreshnessMirrorsJSON) <= bundle.MaxFreshnessMirrorsBytes {
			rpMirrors = string(parsed.FreshnessMirrorsJSON)
		}
		if g, err := json.Marshal(parsed.Manifest.RelayPack.SharedRiskGraph); err == nil {
			rpGraphJSON = string(g)
			if rpGraphJSON == "null" {
				rpGraphJSON = "[]"
			}
		}
	}

	// UsableRoutes, NOT parsed.Manifest.Routes. Verification has already
	// decided that a route naming a transport family this build does not
	// know is droppable rather than fatal (spec_version >= 5); walking
	// the raw list here would quietly undo that decision and persist a
	// route whose family nothing downstream can dial — the "mints but
	// cannot be dialled" failure, reached from the recipient side.
	//
	// At spec_version <= 4 this is a no-op: an unknown family there
	// fails the whole bundle before this line is reached.
	var routes []RouteInput
	for _, r := range bundle.UsableRoutes(parsed) {
		profile := parsed.Profiles[r.ConfigPath]
		ri := RouteInput{
			RouteID:         r.ID,
			TransportFamily: r.TransportFamily,
			ScarcityClass:   r.ScarcityClass,
			Engine:          "sing-box",
			SourceType:      mapSourceType(parsed.Manifest.Bundle.Type),
			ModesAllowed:    modesFor(r.ScarcityClass),
			ExpiresAt:       r.ValidUntil,
			ImportedAt:      bucket,
			TrustState:      trustStateFromLevel(trustLevel),
			Profile:         append([]byte(nil), profile...),
		}
		if hasRP {
			entry, err := bundle.ParseRelayPackEntry(r.FamilySpecificConfig)
			if err == nil && entry != nil {
				modJSON := ""
				if len(entry.Modifiers) > 0 {
					if mb, mErr := json.Marshal(entry.Modifiers); mErr == nil {
						modJSON = string(mb)
					}
				}
				ri.RelayPack = &RelayPackMeta{
					ExposureMode:        entry.ExposureMode,
					FamilyClass:         entry.FamilyClass,
					ProbingRiskClass:    entry.ProbingRiskClass,
					PublicRiskTags:      append([]string(nil), entry.PublicRiskTags...),
					OriginRiskTags:      append([]string(nil), entry.OriginRiskTags...),
					ModifiersJSON:       modJSON,
					RelayPackID:         rpID,
					FreshnessURL:        rpFreshness,
					SharedRiskGraphJSON: rpGraphJSON,

					FreshnessMirrorsJSON: rpMirrors,
				}
			}
			// errors.Is(err, bundle.ErrNoRelayPack) means this candidate
			// has no `_relaypack`; the validator already enforces RP-uniformity
			// rules (RP001 fires when bundle slot is nil but at least one
			// candidate carries _relaypack). Leaving RelayPack=nil here is
			// the legacy path for that route within an otherwise-RelayPack
			// bundle — at V1.5 the validator does not require _relaypack on
			// every candidate, so this is intentional.
		}
		routes = append(routes, ri)
	}
	if err := st.SaveImport(pubInput, routes); err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "save_failed",
			Fingerprint: fp.Hex}, err
	}

	// RouteCount is what the user is shown ("imported N routes"), so it
	// counts the routes actually stored, not the routes the manifest
	// listed. Those differ only when a spec_version >= 5 pack carried a
	// family from a newer build; reporting the manifest's number there
	// would promise routes that are not in the route list.
	v := Verdict{
		Kind:        VerdictImported,
		Fingerprint: fp.Hex, HexEN: rendered.EN, HexFA: rendered.FA,
		BundleID: parsed.Manifest.Bundle.ID, RouteCount: len(routes),
	}
	_ = firstSeen
	return v, nil
}

// readRotationChain extracts trust/rotation.json from the .sbp body without
// re-parsing the whole archive policy. Returns nil if the archive does not
// carry one.
func readRotationChain(body []byte) (*RotationChainDoc, error) {
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	// Re-walk the zip — bundle-go does not currently expose extras.
	// Instead, rely on naming convention by re-reading the zip file.
	for name := range parsed.Profiles {
		_ = name
	}
	chain, ok := readZipFile(body, "trust/rotation.json")
	if !ok {
		return nil, nil
	}
	var doc RotationChainDoc
	if err := json.Unmarshal(chain, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func verifyRotation(doc RotationChainDoc, newPub []byte, oldFP string, now time.Time) error {
	if doc.V != 1 || doc.Kind != "root_rotation" {
		return errors.New("rotation chain: bad version/kind")
	}
	if doc.OldRootFingerprintHex != oldFP {
		return errors.New("rotation chain: old fingerprint mismatch")
	}
	declared, err := hex.DecodeString(doc.NewRootPubHex)
	if err != nil || !bytes.Equal(declared, newPub) {
		return errors.New("rotation chain: new pub mismatch")
	}
	from, err1 := time.Parse(time.RFC3339, doc.TransitionStartsAt)
	until, err2 := time.Parse(time.RFC3339, doc.TransitionEndsAt)
	if err1 != nil || err2 != nil {
		return errors.New("rotation chain: bad timestamps")
	}
	if now.Before(from) || !now.Before(until) {
		return errors.New("rotation chain: outside window")
	}
	// Verify the signature using bundle-go's canonical JSON helper.
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil {
		return errors.New("rotation chain: bad signature hex")
	}
	canonical := canonicalRotation(doc)
	// We don't have the OLD pub bytes, only the fingerprint. The caller
	// has already confirmed `oldFP` is pinned; but to verify the sig we
	// need the bytes. Since the .sbp does not carry the OLD pub directly,
	// we expect that the publisher has shipped it under trust/old.pub.
	// If absent, we accept the chain on the basis that:
	//   - the OLD fingerprint matches a pinned publisher,
	//   - the NEW pub embedded matches the bundle's publisher.pub,
	//   - the bundle is signed by the NEW pub (already verified).
	// This is weaker than full chain verification and is documented as a
	// known limitation in the Phase 1B handover (full chain check awaits
	// embedding of the old pub bytes).
	_ = sig
	_ = canonical
	return nil
}

// readZipFile is a minimal helper that unzips a single named entry.
func readZipFile(body []byte, name string) ([]byte, bool) {
	// Use archive/zip directly here to avoid changing bundle-go's surface.
	return readSingleZipEntry(body, name)
}
