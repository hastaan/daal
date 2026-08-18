package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"strings"
	"time"
)

// FreshnessMirrorsPath is the .sbp archive entry carrying the
// publisher-signed FRP-8 freshness mirror set.
//
// It lives HERE, in the module both the publisher and the recipient
// already depend on, because the path is a wire contract between two
// separately-compiled programs. It had three independent spellings —
// publisher/deploy/freshness, core/refresh, and the archive writer —
// and three copies of a string is a rename away from a publisher that
// writes an entry no recipient looks for, which fails silently in both
// directions: the pack still verifies, the mirrors are simply never
// found. Both sides now alias this constant.
const FreshnessMirrorsPath = "trust/freshness-mirrors.json"

// MaxFreshnessMirrorsBytes bounds that entry for any consumer that
// keeps it. A real one is a few hundred bytes (MaxMirrors is 8), it is
// NOT covered by manifest.sig, and it survives import into on-device
// storage — so without a bound, "here is a relay pack" is also "please
// store this 200 MB blob in your secrets table forever". Matches
// core/bootstrap's per-entry archive cap so a document that is
// storable is also readable.
const MaxFreshnessMirrorsBytes = 256 * 1024

// Ceilings on the archive itself, enforced during decompression.
//
// ParseSBP runs BEFORE VerifyBundle — it has to, because the signature it
// would check lives inside the archive. So every byte here is decompressed
// on the word of an unauthenticated stranger, and every offline intake
// path leads here: the file picker, the base64 paste, the QR fountain, and
// share.PullURL. The paste lane bounds its own input at 1 MiB, but that
// bound stops applying the moment the bytes are handed over: a 509 KiB
// deflate stream of zeros expands to 512 MiB, and measured against this
// parser it cost 1223 MiB of heap before returning "missing manifest.json".
// On a handset that is the app dying, delivered as a single chat message.
//
// The numbers are NOT chosen for how little a phone can bear — they are
// derived from what a spec-legal bundle may actually contain, because a
// parser that refuses a valid bundle is a worse failure than a slow one.
// specs/wasm-transport-v1.md permits 4 MiB per transport module and 16 MiB
// of modules per bundle, and those blobs travel base64-encoded INSIDE
// manifest.json rather than as their own archive entries. So one legal
// entry can approach 16 MiB × 4/3 ≈ 21.3 MiB, and the per-entry cap has to
// clear that with room for the rest of the manifest.
//
// The win is bounding, not tightness: worst-case decompression drops from
// unbounded to MaxArchiveTotalBytes. A route pack that carries no modules —
// which is every pack the offline lanes in this wave actually move, at
// 1.3–2.6 KB — is three orders of magnitude inside these limits.
const (
	// MaxArchiveEntryBytes bounds one decompressed entry. Sized for a
	// manifest.json carrying the spec-maximum module payload.
	MaxArchiveEntryBytes = 24 << 20
	// MaxArchiveTotalBytes bounds the whole archive's decompressed size,
	// so many entries cannot do what one entry cannot.
	MaxArchiveTotalBytes = 32 << 20
	// MaxArchiveEntries bounds the entry count, so a directory of tiny
	// names cannot cost unbounded map growth.
	MaxArchiveEntries = 256
)

// sha256BodyHex returns the hex-encoded SHA-256 of body. Used by
// the 3E transport_modules[] hash-check.
func sha256BodyHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// decodeBase64URLNoPad decodes the canonical base64-URL-without-
// padding encoding the project uses for binary fields inside
// canonical-JSON manifests.
func decodeBase64URLNoPad(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func ParseSBP(r io.ReaderAt, size int64) (*Bundle, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	if len(zr.File) > MaxArchiveEntries {
		return nil, ErrBundleTooLarge
	}
	files := map[string][]byte{}
	total := 0
	for _, f := range zr.File {
		if unsafeArchivePath(f.Name) {
			return nil, ErrUnsafePath
		}
		// Refuse on the DECLARED size first, so a header advertising a
		// gigabyte costs nothing to reject. The declared size is
		// attacker-controlled and may lie, which is why the read below
		// is independently bounded rather than trusting it.
		if f.UncompressedSize64 > uint64(MaxArchiveEntryBytes) {
			return nil, ErrBundleTooLarge
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		// LimitReader is the actual defence: it bounds the decompressed
		// stream regardless of what the zip header claimed. Reading one
		// byte past the cap is how an over-long entry is detected
		// without ever holding it.
		data, readErr := io.ReadAll(io.LimitReader(rc, int64(MaxArchiveEntryBytes)+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(data) > MaxArchiveEntryBytes {
			return nil, ErrBundleTooLarge
		}
		total += len(data)
		if total > MaxArchiveTotalBytes {
			return nil, ErrBundleTooLarge
		}
		files[f.Name] = data
	}

	manifestBytes, ok := files["manifest.json"]
	if !ok {
		return nil, ErrMissingManifest
	}
	sig, ok := files["manifest.sig"]
	if !ok {
		return nil, ErrMissingSignature
	}
	pub, ok := files["publisher.pub"]
	if !ok {
		return nil, ErrMissingPublisherKey
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublisherKey
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	b := &Bundle{
		Manifest:     manifest,
		Signature:    append([]byte(nil), sig...),
		PublisherPub: append([]byte(nil), pub...),
		Profiles:     map[string][]byte{},
	}
	for name, data := range files {
		if strings.HasPrefix(name, "profiles/") && name != "profiles/" {
			b.Profiles[name] = data
		}
	}
	if revocationBytes, ok := files["revocation.json"]; ok {
		var rev RevocationList
		if err := json.Unmarshal(revocationBytes, &rev); err != nil {
			return nil, err
		}
		b.Revocation = &rev
	}
	// FRP-7.5: capture the sub-key cert if present. The cert is
	// parsed + verified in VerifyBundle, not here. ParseSBP
	// preserves raw bytes only.
	if certBytes, ok := files["trust/subkey-cert.json"]; ok {
		b.SubkeyCertJSON = append([]byte(nil), certBytes...)
	}
	// FRP-11: capture cell-membership + cell-delegation files
	// when present. ParseSBP preserves raw bytes only; the
	// recipient-side chain walk in core/trust/cell_verify.go
	// drives ParseCellDocs to obtain the typed values.
	// VerifyBundle is intentionally NOT extended; older clients
	// that don't know about cells continue to verify the bundle
	// as a single-publisher RelayPack signed by the per-cell
	// bundle-signer. See specs/cell-v1.md.
	if memBytes, ok := files["trust/cell-membership.json"]; ok {
		b.CellMembershipJSON = append([]byte(nil), memBytes...)
	}
	if delBytes, ok := files["trust/cell-delegation.json"]; ok {
		b.CellDelegationJSON = append([]byte(nil), delBytes...)
	}
	// FRP-8: capture the signed freshness mirror set when present.
	// Same contract as the cell documents above — raw bytes, no parse,
	// no verification, VerifyBundle unextended so a pack carrying this
	// entry still verifies on a client that has never heard of it.
	if mirrorBytes, ok := files[FreshnessMirrorsPath]; ok {
		b.FreshnessMirrorsJSON = append([]byte(nil), mirrorBytes...)
	}
	return b, nil
}

func BuildUnsignedBundle(manifest Manifest, files map[string][]byte) ([]byte, error) {
	manifestBytes, err := CanonicalManifestJSON(manifest)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeZipFile(zw, "manifest.json", manifestBytes); err != nil {
		return nil, err
	}
	for name, data := range files {
		if unsafeArchivePath(name) {
			return nil, ErrUnsafePath
		}
		if err := writeZipFile(zw, name, data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func BuildSignedBundle(manifest Manifest, profiles map[string][]byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	sig, err := SignManifest(manifest, priv)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"manifest.sig":  sig,
		"publisher.pub": pub,
	}
	for name, data := range profiles {
		files[name] = data
	}
	return BuildUnsignedBundle(manifest, files)
}

// VerifyBundle runs the full bundle verification without binding
// against a specific recipient identity. Use this where the caller
// has no local recipient identity yet (publisher-side build tools,
// unit tests, FRP-13 directory ingestion, etc.).
//
// For recipient-app import paths, use VerifyBundleFor with the
// device's 32-byte X25519 public key — it additionally enforces
// the FRP-14 bundle.recipient_fp_hex binding (RP024). VerifyBundle
// silently tolerates a non-empty binding because the field is part
// of the signed payload and tampering would have failed
// VerifyManifest above.
func VerifyBundle(b *Bundle) error {
	return verifyBundleCore(b, nil)
}

// VerifyBundleFor runs VerifyBundle plus the FRP-14 recipient-
// binding cross-check. `recipientPub` is the 32-byte X25519 public
// key of the local recipient identity. A non-empty
// bundle.recipient_fp_hex on the manifest MUST match
// sha256(recipientPub); mismatch returns ErrRecipientMismatch.
// An empty bundle.recipient_fp_hex (legacy V1.5 pack) is permitted.
func VerifyBundleFor(b *Bundle, recipientPub []byte) error {
	return verifyBundleCore(b, recipientPub)
}

func verifyBundleCore(b *Bundle, recipientPub []byte) error {
	// Phase 1.5A: spec_version 1 (legacy) and 2 (3A-3F) are accepted.
	// FRP-1: spec_version 3 (RelayPack) is also accepted.
	// FRP-7.5: spec_version 4 (sub-key cert chain) is also accepted.
	// Setting Manifest.RelayPack requires spec_version >= 3; carrying
	// trust/subkey-cert.json requires spec_version >= 4. Pre-bump
	// verifiers reject either via this gate.
	switch b.Manifest.SpecVersion {
	case 1, 2, 3, 4:
	default:
		return ErrUnsupportedSpec
	}
	if b.Manifest.RelayPack != nil && b.Manifest.SpecVersion < 3 {
		return ErrUnsupportedSpec
	}
	if len(b.SubkeyCertJSON) > 0 && b.Manifest.SpecVersion < 4 {
		return ErrSubkeyCertSpecVersionTooOld
	}
	// FRP-7.5: walk pub→cert→sub when the cert is present; the
	// resolved key replaces publisher.pub for the manifest signature
	// check below. Legacy 1A bundles (no cert) get publisher.pub.
	signingKey, err := resolveManifestSigningKey(
		b.SubkeyCertJSON,
		ed25519.PublicKey(b.PublisherPub),
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if err := VerifyManifest(b.Manifest, b.Signature, signingKey); err != nil {
		return err
	}
	fp := PublisherFingerprint(b.PublisherPub)
	if b.Manifest.Publisher.KeyFingerprintHex != "" && b.Manifest.Publisher.KeyFingerprintHex != fp.Hex {
		return ErrFingerprintMismatch
	}
	if expired(b.Manifest.Bundle.ExpiresAt, time.Now().UTC()) {
		return ErrExpiredBundle
	}
	if b.Revocation != nil {
		for _, publisher := range b.Revocation.RevokedPublishers {
			if publisher == fp.Hex {
				return ErrRevokedPublisher
			}
		}
	}
	for _, route := range b.Manifest.Routes {
		if err := validateRoute(route, b); err != nil {
			return err
		}
	}
	// Phase 3B: top-level rendezvous_hints[] signature verification.
	if err := validate3BManifestFields(b); err != nil {
		return err
	}
	// Phase 3E: top-level transport_modules[] hash + size cap
	// verification, and a final cross-check that every
	// `transport_module_slug` referenced by a route resolves to
	// an entry in `transport_modules[]`. The slug→entry resolution
	// is intentionally NOT enforced here at parse time — see the
	// soft-validation discipline note in
	// specs/wasm-transport-v1.md "Activation rules". Only the
	// shape and size of the entries themselves is enforced here.
	if err := validate3EManifestFields(b); err != nil {
		return err
	}
	// Phase 3F manifest-level validation: a `.sbp.share`
	// (bundle.type == "delegated_share") MUST carry a non-empty
	// `redistribution_chain[]` and `delegate_caps[]`. Other
	// bundle types MUST NOT carry these fields. The chain is
	// verified at import time by the engine's delegate package
	// (bundle parser does not need the publisher's pubkey to
	// run the walk; it only checks shape + depth here). See
	// specs/delegate-keys-v1.md.
	if err := validate3FManifestFields(b); err != nil {
		return err
	}
	// FRP-14: recipient-binding cross-check. Empty field is
	// permitted for V1.5 back-compat (no binding). Non-empty
	// requires a 64-char hex match against sha256(local pub).
	if recipientPub != nil && b.Manifest.Bundle.RecipientFPHex != "" {
		if len(recipientPub) != 32 {
			return ErrRecipientIdentityMalformed
		}
		sum := sha256.Sum256(recipientPub)
		got := hex.EncodeToString(sum[:])
		if got != b.Manifest.Bundle.RecipientFPHex {
			return ErrRecipientMismatch
		}
	}
	return nil
}

func validateRoute(route RouteManifestEntry, b *Bundle) error {
	if !validScarcity(route.ScarcityClass) || !validTransport(route.TransportFamily) {
		return ErrInvalidEnum
	}
	if unsafeArchivePath(route.ConfigPath) {
		return ErrUnsafePath
	}
	if _, ok := b.Profiles[route.ConfigPath]; !ok {
		return ErrMissingProfile
	}
	if expired(route.ValidUntil, time.Now().UTC()) {
		return ErrExpiredRoute
	}
	if b.Revocation != nil {
		for _, revoked := range b.Revocation.RevokedRoutes {
			if revoked == route.ID {
				return ErrRevokedRoute
			}
		}
	}
	// Phase 3A validation rules. See specs/sbp-v1.md
	// "Validation Rules" and specs/transport-families-v1.md.
	if err := validate3AFields(route); err != nil {
		return err
	}
	// Phase 3B per-route validation. See
	// specs/rendezvous-channels-v1.md.
	if err := validate3BRouteFields(route); err != nil {
		return err
	}
	// Phase 3C per-route validation. See
	// specs/masque-ladder-v1.md.
	if err := validate3CRouteFields(route); err != nil {
		return err
	}
	// Phase 3D per-route validation. See
	// specs/psiphon-route-v1.md and specs/conjure-route-v1.md.
	if err := validate3DRouteFields(route); err != nil {
		return err
	}
	// Phase 3E per-route validation. See
	// specs/wasm-transport-v1.md.
	if err := validate3ERouteFields(route); err != nil {
		return err
	}
	// Phase 3F per-route validation. See
	// specs/delegate-keys-v1.md.
	if err := validate3FRouteFields(route); err != nil {
		return err
	}
	return nil
}

// rendezvousChannelV1 is the closed list of v1 rendezvous
// channel IDs. Mirrors core/rendezvous.KnownChannels — the
// bundle module is its own go.mod so we cannot import the
// engine package; a regression test in
// `bundle/go/bundle/v3b_test.go` keeps the two lists in sync.
var rendezvousChannelV1 = map[string]struct{}{
	"domain_fronted_broker": {},
	"sqs":                   {},
	"amp_cache":             {},
	"push":                  {},
	"offline_hint":          {},
}

func validate3BRouteFields(route RouteManifestEntry) error {
	for _, ch := range route.RendezvousPriority {
		if _, ok := rendezvousChannelV1[ch]; !ok {
			return ErrInvalidRendezvousChannel
		}
	}
	return nil
}

// validate3CRouteFields enforces:
//
//   - `masque_endpoint` MUST NOT appear on routes whose
//     transport_family is anything other than "masque" (defence
//     in depth — keeps the routes[] shape unambiguous).
//   - When present, the URL MUST parse, the scheme MUST be
//     "https", the host MUST be non-empty, and the path MUST be
//     non-empty.
//
// Empty / absent on a MASQUE route is NOT a validation error at
// import time — the engine treats it as "no usable endpoint"
// and filters the route at activation time, but a publisher who
// pre-publishes a route stub before wiring up the upstream MUST
// still be able to round-trip the manifest. This matches the 3A
// rule for `family_specific_config` (optional).
func validate3CRouteFields(route RouteManifestEntry) error {
	if route.MasqueEndpoint == "" {
		return nil
	}
	if route.TransportFamily != string(TransportMASQUE) {
		return ErrMasqueEndpointOnNonMasqueRoute
	}
	u, err := url.Parse(route.MasqueEndpoint)
	if err != nil {
		return ErrMasqueEndpointMalformed
	}
	if u.Scheme != "https" {
		return ErrMasqueEndpointMalformed
	}
	if u.Host == "" {
		return ErrMasqueEndpointMalformed
	}
	if u.Path == "" || u.Path == "/" {
		return ErrMasqueEndpointMalformed
	}
	return nil
}

// validate3DRouteFields enforces the Phase 3D refraction-family
// per-route validation. Locked at 3D per
// `specs/psiphon-route-v1.md` and `specs/conjure-route-v1.md`.
//
// Psiphon:
//   - `psiphon_bundle_blob_b64` MUST NOT appear on routes whose
//     transport_family is anything other than "psiphon".
//   - When present, the base64 MUST decode and the decoded bytes
//     MUST be in [256, 65536]. The bundle parser does NOT parse
//     the contents — semantic validation is the upstream
//     library's responsibility.
//
// Conjure:
//   - `conjure_phantom_subnets`, `conjure_station_pubkey`, and
//     `conjure_decoy_pool` MUST NOT appear on routes whose
//     transport_family is anything other than "conjure".
//   - When present on a Conjure route:
//   - `conjure_phantom_subnets` MUST be non-empty; every entry
//     MUST be a parseable CIDR with prefix length ≥ /24
//     (IPv4) / ≥ /32 (IPv6).
//   - `conjure_station_pubkey` MUST be 32 bytes hex (64 hex
//     chars).
//   - `conjure_decoy_pool` MAY be empty; when non-empty,
//     every entry MUST be a valid RFC 1123 hostname.
func validate3DRouteFields(route RouteManifestEntry) error {
	// Psiphon side.
	if route.PsiphonBundleBlobB64 != "" {
		if route.TransportFamily != string(TransportPsiphon) {
			return ErrPsiphonBlobOnNonPsiphonRoute
		}
		decoded, err := base64.StdEncoding.DecodeString(route.PsiphonBundleBlobB64)
		if err != nil {
			return ErrPsiphonBlobMalformed
		}
		if len(decoded) < 256 || len(decoded) > 65536 {
			return ErrPsiphonBlobMalformed
		}
	}

	// Conjure side. The fields move together: any field set on
	// a non-conjure route is a parser-level rejection.
	hasConjureFields := len(route.ConjurePhantomSubnets) > 0 ||
		route.ConjureStationPubkey != "" ||
		len(route.ConjureDecoyPool) > 0
	if hasConjureFields && route.TransportFamily != string(TransportConjure) {
		return ErrConjureFieldOnNonConjureRoute
	}
	// Conjure: when ANY conjure_* field is present on a
	// conjure route, validate its shape. Empty / absent fields
	// on a conjure route are NOT a parse-time rejection — a
	// publisher who pre-publishes a route stub before wiring
	// up the upstream MUST still be able to round-trip the
	// manifest. The engine treats empty fields as "no usable
	// configuration" and filters at activation time, matching
	// the 3A `family_specific_config` / 3C `masque_endpoint`
	// rules.
	if route.TransportFamily == string(TransportConjure) {
		for _, cidr := range route.ConjurePhantomSubnets {
			if err := validateConjureCIDR(cidr); err != nil {
				return err
			}
		}
		if route.ConjureStationPubkey != "" && !validHexLen(route.ConjureStationPubkey, 64) {
			return ErrConjureStationPubkeyMalformed
		}
		for _, host := range route.ConjureDecoyPool {
			if !validRFC1123Hostname(host) {
				return ErrConjureDecoyPoolMalformed
			}
		}
	}
	return nil
}

// validateConjureCIDR enforces the locked-at-3D prefix-length
// floors. Any parse error or overly-broad prefix returns
// ErrConjurePhantomSubnetsMalformed.
func validateConjureCIDR(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return ErrConjurePhantomSubnetsMalformed
	}
	// Minimal CIDR parse: split on `/`, validate prefix length.
	// We avoid net.ParseCIDR here to keep the bundle module
	// stdlib-net-free — but the go stdlib `net` is already
	// imported transitively by `net/url` so reusing it is
	// cheap. We use it directly:
	ip, mask, err := splitCIDR(cidr)
	if err != nil {
		return ErrConjurePhantomSubnetsMalformed
	}
	// IPv4 vs IPv6 floor.
	if isIPv4(ip) {
		if mask < 24 {
			return ErrConjurePhantomSubnetsMalformed
		}
	} else {
		if mask < 32 {
			return ErrConjurePhantomSubnetsMalformed
		}
	}
	return nil
}

// splitCIDR is a stdlib-free CIDR splitter that returns the
// network IP string, the prefix length, and any parse error.
// The IP-shape check is deliberately loose — any non-empty
// pre-`/` portion is accepted; the floor check below catches
// the common case (e.g. /16 IPv4 or /16 IPv6).
func splitCIDR(s string) (ipStr string, prefix int, err error) {
	idx := strings.IndexByte(s, '/')
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, ErrConjurePhantomSubnetsMalformed
	}
	ipStr = s[:idx]
	maskPart := s[idx+1:]
	for i := 0; i < len(maskPart); i++ {
		c := maskPart[i]
		if c < '0' || c > '9' {
			return "", 0, ErrConjurePhantomSubnetsMalformed
		}
		prefix = prefix*10 + int(c-'0')
		if prefix > 128 {
			return "", 0, ErrConjurePhantomSubnetsMalformed
		}
	}
	if prefix == 0 {
		return "", 0, ErrConjurePhantomSubnetsMalformed
	}
	return ipStr, prefix, nil
}

// isIPv4 detects an IPv4 dotted-quad shape. The check is loose
// (we do not validate octet ranges) because an octet > 255 will
// be rejected by the engine layer's net.ParseCIDR; the parser
// layer only needs to distinguish IPv4 from IPv6 to apply the
// correct floor.
func isIPv4(s string) bool {
	dots := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dots++
		}
		if s[i] == ':' {
			return false
		}
	}
	return dots == 3
}

// validHexLen checks a hex string is exactly n chars and
// every char is a lowercase hex digit (or uppercase — we
// accept both).
func validHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		isDigit := c >= '0' && c <= '9'
		if !(isLower || isUpper || isDigit) {
			return false
		}
	}
	return true
}

// validRFC1123Hostname is a defensive RFC 1123 hostname check
// for the conjure decoy pool. Stdlib-only; rejects empty,
// trailing-dot, label > 63, total > 253, leading/trailing
// hyphen per label, and non-LDH characters.
func validRFC1123Hostname(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c == '-' ||
				(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9')) {
				return false
			}
		}
	}
	return true
}

// validate3BManifestFields enforces the top-level rendezvous_hints
// invariants: each entry MUST have a non-empty payload + signature
// and the signature MUST verify under the publisher's signing key.
// Hint payload validation (Bridge fingerprint, NotAfter) is the
// engine's responsibility at hint-consumption time; the bundle
// only enforces "the publisher signed this."
func validate3BManifestFields(b *Bundle) error {
	if len(b.Manifest.RendezvousHints) == 0 {
		return nil
	}
	pub := ed25519.PublicKey(b.PublisherPub)
	for _, h := range b.Manifest.RendezvousHints {
		if len(h.Payload) == 0 || h.Signature == "" {
			return ErrRendezvousHintMalformed
		}
		sig, err := decodeBase64URLNoPad(h.Signature)
		if err != nil {
			return ErrRendezvousHintMalformed
		}
		// The signature covers the canonicalised payload bytes
		// (already canonical because publishers MUST emit
		// canonical-JSON; we treat the on-disk bytes as
		// authoritative — see specs/snowflake-route-v1.md
		// "Offline hint signing").
		if !ed25519.Verify(pub, h.Payload, sig) {
			return ErrRendezvousHintBadSignature
		}
	}
	return nil
}

// validate3AFields enforces:
//
//   - family_specific_config (if present) MUST be a JSON object.
//   - experimental_min_engine_version (if present) MUST parse as
//     semver.
//   - WebTunnel routes MUST NOT carry scarcity_class
//     `bulk-capable` (`specs/webtunnel-route-v1.md`).
func validate3AFields(route RouteManifestEntry) error {
	if len(route.FamilySpecificConfig) > 0 {
		// json.RawMessage with whitespace? Trim and check the
		// first non-space byte. We only accept objects, not
		// arrays / scalars.
		body := route.FamilySpecificConfig
		i := 0
		for i < len(body) {
			c := body[i]
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				break
			}
			i++
		}
		if i >= len(body) || body[i] != '{' {
			return ErrFamilySpecificConfigShape
		}
	}
	if route.ExperimentalMinEngineVersion != "" {
		if !validSemver(route.ExperimentalMinEngineVersion) {
			return ErrInvalidExperimentalMinVersion
		}
	}
	if route.TransportFamily == string(TransportWebTunnel) &&
		route.ScarcityClass == string(ScarcityBulkCapable) {
		return ErrWebTunnelBulkCapable
	}
	return nil
}

// validSemver is a minimal semver-2.0 parser sufficient for the
// 3A `experimental_min_engine_version` validation. Accepts
// `MAJOR.MINOR.PATCH` with optional `-PRERELEASE` and `+BUILD`
// tails. Returns true on a well-formed value.
func validSemver(v string) bool {
	// Strip an optional leading 'v'.
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	// Strip a trailing build segment after '+'.
	for i := 0; i < len(v); i++ {
		if v[i] == '+' {
			v = v[:i]
			break
		}
	}
	// Strip a pre-release segment after '-'. Pre-release
	// must be non-empty and contain only [0-9A-Za-z.-]. We do
	// the strict numeric check on the leading core only.
	if dash := indexByte(v, '-'); dash >= 0 {
		pre := v[dash+1:]
		v = v[:dash]
		if pre == "" {
			return false
		}
		for i := 0; i < len(pre); i++ {
			c := pre[i]
			if !isSemverIdent(c) {
				return false
			}
		}
	}
	// Now v MUST be MAJOR.MINOR.PATCH numeric.
	parts := splitDot(v)
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		// Reject leading zeros (per semver 2.0 §2): "0",
		// "1", "10" ok; "01" not.
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func splitDot(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func isSemverIdent(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		c == '.' || c == '-'
}

func writeZipFile(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func unsafeArchivePath(name string) bool {
	clean := path.Clean(name)
	return strings.HasPrefix(name, "/") || strings.HasPrefix(clean, "../") || clean == ".."
}

func expired(value string, now time.Time) bool {
	t, err := ParseTime(value)
	if err != nil {
		return true
	}
	return !t.After(now)
}

func validScarcity(value string) bool {
	switch ScarcityClass(value) {
	case ScarcityEmergency, ScarcityLow, ScarcityNormal, ScarcityBulkCapable, ScarcityExperimental, ScarcityLifelineOnly:
		return true
	default:
		return false
	}
}

// validate3ERouteFields enforces:
//
//   - `transport_module_slug` MUST NOT appear on routes whose
//     transport_family is anything other than "transport_module".
//   - When present, the slug MUST match `[a-z0-9_-]{3,32}`.
//
// Empty / absent on a transport_module route is NOT a parse-
// time rejection — soft-validation discipline preserved at 3E.
//
// See specs/wasm-transport-v1.md.
func validate3ERouteFields(route RouteManifestEntry) error {
	if route.TransportModuleSlug == "" {
		return nil
	}
	if route.TransportFamily != string(TransportTransportModule) {
		return ErrTransportModuleSlugOnNonModuleRoute
	}
	if !validTransportModuleSlug(route.TransportModuleSlug) {
		return ErrTransportModuleSlugMalformed
	}
	return nil
}

// validate3EManifestFields enforces:
//
//   - Each `transport_modules[]` entry has a valid slug, a
//     64-hex sha256, a non-empty `wasm_blob_b64`.
//   - The decoded blob is ≤ 4 MiB.
//   - The decoded blob's sha256 matches the entry's sha256.
//   - The sum of decoded blobs across the bundle is ≤ 16 MiB.
//
// The errors are append-only; new failure modes require a
// roadmap-level decision (3F or later).
func validate3EManifestFields(b *Bundle) error {
	const (
		maxModuleBytes = 4 * 1024 * 1024
		maxBundleBytes = 16 * 1024 * 1024
	)
	if len(b.Manifest.TransportModules) == 0 {
		return nil
	}
	totalBytes := 0
	for _, m := range b.Manifest.TransportModules {
		if !validTransportModuleSlug(m.Slug) {
			return ErrTransportModulesEntryMalformed
		}
		if !validHexLen(m.SHA256Hex, 64) {
			return ErrTransportModulesEntryMalformed
		}
		if m.WASMBlobB64 == "" {
			return ErrTransportModulesEntryMalformed
		}
		// Decode the blob. Accept both std and url-safe; the
		// publisher CLI emits std.
		var (
			body []byte
			err  error
		)
		body, err = base64.StdEncoding.DecodeString(m.WASMBlobB64)
		if err != nil {
			body, err = base64.RawStdEncoding.DecodeString(m.WASMBlobB64)
		}
		if err != nil {
			body, err = base64.RawURLEncoding.DecodeString(m.WASMBlobB64)
		}
		if err != nil {
			return ErrTransportModulesEntryMalformed
		}
		if len(body) > maxModuleBytes {
			return ErrTransportModuleOversize
		}
		// Min-engine-version (when present) MUST be valid
		// semver. The check is not at activation time — the
		// engine compares this to its own version at
		// transport_module activation; the bundle parser only
		// guarantees the field is well-formed.
		if m.MinEngineVersion != "" && !validSemver(m.MinEngineVersion) {
			return ErrTransportModulesEntryMalformed
		}
		// Hash check. Same single-source helper the engine
		// uses (`core/wasm.VerifyHash`) — but that import is
		// not available from the bundle module, so we inline
		// the equivalent hash verification.
		if !sha256MatchesHex(body, m.SHA256Hex) {
			return ErrTransportModuleHashMismatch
		}
		totalBytes += len(body)
		if totalBytes > maxBundleBytes {
			return ErrTransportModuleOversize
		}
	}
	return nil
}

// validTransportModuleSlug enforces the locked-at-3E slug regex
// `[a-z0-9_-]{3,32}`. Mirrors `core/wasm.validSlug`.
func validTransportModuleSlug(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isSym := c == '_' || c == '-'
		if !(isLower || isDigit || isSym) {
			return false
		}
	}
	return true
}

// sha256MatchesHex returns true iff the SHA-256 of body equals
// the hex string `wantHex` (case-insensitive on the wantHex
// side). Inlined here so the bundle module stays free of the
// engine's wasm package.
func sha256MatchesHex(body []byte, wantHex string) bool {
	sum := sha256BodyHex(body)
	if len(sum) != len(wantHex) {
		return false
	}
	for i := 0; i < len(sum); i++ {
		a := sum[i]
		b := wantHex[i]
		if b >= 'A' && b <= 'F' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// validate3FRouteFields enforces:
//
//   - `redistribution_policy` (when present) is one of the
//     three locked-at-3F values.
//   - `redistribution_cap` is set iff policy == "delegated_n",
//     and is in [1, 255] when set.
//   - `redistribution_cap` MUST be 0/absent for `none` and
//     `transitive` policies.
//
// Empty / absent `redistribution_policy` is NOT a parse-time
// rejection — the receiver-side default is "none" (fail-
// closed), applied when the engine consults the policy at
// re-share time. See specs/delegate-keys-v1.md.
func validate3FRouteFields(route RouteManifestEntry) error {
	if route.RedistributionPolicy == "" && route.RedistributionCap == 0 {
		return nil
	}
	if route.RedistributionPolicy == "" && route.RedistributionCap != 0 {
		return ErrRedistributionPolicyMalformed
	}
	switch route.RedistributionPolicy {
	case "none", "transitive":
		if route.RedistributionCap != 0 {
			return ErrRedistributionCapMalformed
		}
	case "delegated_n":
		if route.RedistributionCap == 0 {
			return ErrRedistributionCapMalformed
		}
	default:
		return ErrRedistributionPolicyMalformed
	}
	return nil
}

// validate3FManifestFields enforces the `.sbp.share` shape:
//
//   - bundle.type == "delegated_share" MUST carry non-empty
//     `redistribution_chain[]` AND `delegate_caps[]`.
//   - bundle.type != "delegated_share" MUST NOT carry either.
//   - `redistribution_chain[]` depth ≤ MaxChainDepth (5).
//   - Each `delegate_caps[]` entry has count < cap.
//
// Cryptographic verification of the chain happens engine-side
// (the bundle parser does not have access to the publisher's
// pubkey at this layer). See specs/delegate-keys-v1.md.
func validate3FManifestFields(b *Bundle) error {
	const maxDepth = 5
	isShare := b.Manifest.Bundle.Type == "delegated_share"
	hasChain := len(b.Manifest.RedistributionChain) > 0
	hasCaps := len(b.Manifest.DelegateCaps) > 0
	switch {
	case isShare && (!hasChain || !hasCaps):
		return ErrRedistributionChainBroken
	case !isShare && (hasChain || hasCaps):
		return ErrRedistributionChainBroken
	}
	if len(b.Manifest.RedistributionChain) > maxDepth {
		return ErrRedistributionChainTooDeep
	}
	for _, c := range b.Manifest.DelegateCaps {
		if c.CapAtSignTime > 0 && c.SharedWithCountAtSignTime >= c.CapAtSignTime {
			return ErrRedistributionCapExceeded
		}
	}
	return nil
}

func validTransport(value string) bool {
	switch TransportFamily(value) {
	case TransportVLESSReality, TransportNaive, TransportWebSocketTLS,
		TransportHysteria2, TransportTUIC, TransportSnowflake,
		TransportWebTunnel, TransportMASQUE, TransportShadowsocks,
		TransportTorBridge, TransportWireGuard, TransportAmneziaWG,
		// Phase 3A widens the closed list per
		// specs/transport-families-v1.md.
		TransportPsiphon, TransportConjure, TransportTransportModule,
		TransportLifelineRelay,
		TransportOther:
		return true
	default:
		return false
	}
}
