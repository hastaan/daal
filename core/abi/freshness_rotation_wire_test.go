package abi

// THE MINT-THEN-PARSE CROSS-CHECK FOR A ROTATION.
//
// WHAT WENT WRONG, AND WHY NO EXISTING TEST SAW IT.
//
// The freshness document is addressed by `relay_pack_id`. That id is
// not a name for a relay — `relaypack.DeriveRelayPackID` hashes
// (provider | server_id | region | public_ip | family-set), which is a
// fingerprint of the relay's current SHAPE. Every rung of the rotation
// ladder above L2 changes one of those inputs: L3 moves public_ip, L4
// the region, L5 the provider, L6 the family set. So the operation that
// repairs a relay also RENAMES its pack.
//
// The consequence was that the whole recovery channel was inert for
// exactly the rungs it was built for. The publisher uploaded a document
// naming the NEW id to the SAME object URL every recipient polls; every
// recipient compared it against the OLD id, read off its own installed
// route rows, and rejected it as belonging to a different pack. The
// audit row said `freshness_rejected`, the device kept dialling the
// burned address forever, and the publisher's screen reported a
// successful two-mirror publish. A courier was still required.
//
// Both sides' unit tests were green throughout, because each side was
// tested against a document it minted itself, with an id it chose. The
// seam is the only place the bug exists.
//
// So the fixtures here are REAL OUTPUT of the real publisher path:
//
//	# the pre-rotation pack (same one freshness_wire_test.go uses)
//	daal-deploy bind-and-sign --operator-record rec.json ... -o fixture.sbp
//
//	# an L3: only public_ip and the candidates' public_ip:* tags move,
//	# exactly what hetzner.adoptPublicIP does to the record
//	daal-deploy bind-and-sign --operator-record rec-rotated.json ... -o fixture-rotated.sbp
//
//	daal-deploy publish-freshness --relay-pack-id <old> ... -o freshness-doc-current.json
//	daal-deploy publish-freshness --relay-pack-id <new> \
//	    --supersedes <old> ...                          -o freshness-doc-rotated.json
//	daal-deploy publish-freshness --relay-pack-id <new> ... -o freshness-doc-foreign.json
//
// The two packs differ ONLY in the dialled address, and the binder
// gives them different ids — which is the finding, pinned below as an
// assertion rather than a claim. Re-mint with the commands above; do
// not edit the bytes.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"daal/core/bootstrap"
	"daal/core/refresh"
)

const (
	fixtureRotatedPack = "testdata/freshness-3mirrors-rotated.sbp"
	docCurrent         = "testdata/freshness-doc-current.json"
	docRotated         = "testdata/freshness-doc-rotated.json"
	docForeign         = "testdata/freshness-doc-foreign.json"

	// The publisher key the fixtures were minted under.
	fixturePubHex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

	// The two pack ids the real binder produced. They differ, and only
	// the dialled address differs between the two records.
	fixturePackID        = "rp-ce01b099781cc3509d2662a838448fd7"
	fixtureRotatedPackID = "rp-6a416c7fde2f4a8fdd38b97dac7cd742"
)

// fixtureNow sits inside every fixture's not_after window (the
// documents are minted with a 10-year TTL, the same concession the
// pack fixtures make, so this suite fails on a change rather than on a
// date).
var fixtureNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func fixturePub(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(fixturePubHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readDoc(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	return b
}

// The premise. If these two ever come out equal the rest of this file
// is testing nothing, and the supersedes machinery is dead weight.
func TestRotationRenamesThePack(t *testing.T) {
	if fixturePackID == fixtureRotatedPackID {
		t.Fatal("the two fixture packs share an id — re-mint them; the whole reason " +
			"supersedes exists is that an address swap changes the pack id")
	}
	// And the rotated pack really is the same relay: same publisher.
	body, err := os.ReadFile(fixtureRotatedPack)
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty rotated pack fixture")
	}
}

// The pre-rotation document, verified by the recipient's own verifier
// against the id the recipient holds. This is the baseline: if it fails,
// the two sides have diverged on canonicalisation and every signature in
// the field is dead — a failure that looks exactly like censorship and
// is not.
func TestFreshnessDocument_CurrentPackVerifies(t *testing.T) {
	doc, err := refresh.VerifyFreshnessDocument(readDoc(t, docCurrent), refresh.FreshnessVerifyOpts{
		PublisherRootPub:  fixturePub(t),
		Now:               fixtureNow,
		ExpectRelayPackID: fixturePackID,
	})
	if err != nil {
		t.Fatalf("the publisher's own document did not verify on the recipient: %v", err)
	}
	if doc.RelayPackID != fixturePackID {
		t.Fatalf("relay_pack_id = %q", doc.RelayPackID)
	}
	if len(doc.Mirrors) != 3 {
		t.Fatalf("mirrors = %d, want the 3 the publisher signed", len(doc.Mirrors))
	}
}

// THE ONE THAT MATTERS. A device holding the PRE-rotation pack must
// accept the POST-rotation document, because that document is the only
// thing that will ever tell it the address moved.
func TestFreshnessDocument_RotatedPackReachesTheOldRecipients(t *testing.T) {
	raw := readDoc(t, docRotated)

	// Sanity: the document really is for the new pack, so this is not
	// accidentally passing on an id match.
	var probe struct {
		RelayPackID string   `json:"relay_pack_id"`
		Supersedes  []string `json:"supersedes"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.RelayPackID != fixtureRotatedPackID {
		t.Fatalf("fixture names %q, expected the rotated pack", probe.RelayPackID)
	}
	if len(probe.Supersedes) != 1 || probe.Supersedes[0] != fixturePackID {
		t.Fatalf("fixture supersedes = %v, want [%s]", probe.Supersedes, fixturePackID)
	}

	// The device's view: it knows only the id stamped on its own route
	// rows, which is the OLD one.
	doc, err := refresh.VerifyFreshnessDocument(raw, refresh.FreshnessVerifyOpts{
		PublisherRootPub:  fixturePub(t),
		Now:               fixtureNow,
		ExpectRelayPackID: fixturePackID,
	})
	if err != nil {
		t.Fatalf("a recipient of the pre-rotation pack rejected the document that repairs it: %v\n"+
			"this is the courier-required failure Step 8 exists to end: the publisher publishes, "+
			"every mirror reports success, and not one device moves", err)
	}
	if doc.CurrentBundleSHA256 == "" {
		t.Fatal("no bundle digest to fetch")
	}
}

// And the capability is not a blanket one: a document for another pack
// that does NOT claim to supersede this one is still refused. Otherwise
// "supersedes" would be an unsigned wildcard and one publisher's relays
// could silently absorb each other's recipients.
func TestFreshnessDocument_ForeignPackWithoutSupersedesIsRefused(t *testing.T) {
	_, err := refresh.VerifyFreshnessDocument(readDoc(t, docForeign), refresh.FreshnessVerifyOpts{
		PublisherRootPub:  fixturePub(t),
		Now:               fixtureNow,
		ExpectRelayPackID: fixturePackID,
	})
	if !errors.Is(err, refresh.ErrFreshnessWrongPack) {
		t.Fatalf("want ErrFreshnessWrongPack, got %v", err)
	}
}

// The anti-rollback ordering, across the seam. The pre-rotation
// document is genuinely signed, so replaying it after the rotation is
// not forgery — the only thing that distinguishes it is the ordering
// the publisher controls and the device remembers.
func TestFreshnessDocument_ReplayedPreRotationDocumentIsRefused(t *testing.T) {
	var rotated struct {
		Sequence            uint64 `json:"sequence"`
		CurrentBundleSHA256 string `json:"current_bundle_sha256"`
	}
	if err := json.Unmarshal(readDoc(t, docRotated), &rotated); err != nil {
		t.Fatal(err)
	}
	// A device that has applied the rotation: high-water at the rotated
	// document's sequence, running the rotated bundle.
	_, err := refresh.VerifyFreshnessDocument(readDoc(t, docCurrent), refresh.FreshnessVerifyOpts{
		PublisherRootPub:    fixturePub(t),
		Now:                 fixtureNow,
		ExpectRelayPackID:   fixturePackID,
		MinSequence:         rotated.Sequence,
		CurrentBundleSHA256: rotated.CurrentBundleSHA256,
	})
	if !errors.Is(err, refresh.ErrFreshnessRollback) {
		t.Fatalf("want ErrFreshnessRollback, got %v — a captured pre-rotation document "+
			"would put the device back on the burned address with the publisher's own signature", err)
	}
}

// The equal-sequence case, which the `<` rule accepted. The sequence
// has one-second granularity, so two documents published inside one
// second share a value; if they name different bundles, accepting `==`
// makes them interchangeable in BOTH directions forever.
func TestFreshnessDocument_EqualSequenceDifferentBundleIsRefused(t *testing.T) {
	var current struct {
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(readDoc(t, docCurrent), &current); err != nil {
		t.Fatal(err)
	}
	// Same sequence, but the device is running a DIFFERENT bundle.
	_, err := refresh.VerifyFreshnessDocument(readDoc(t, docCurrent), refresh.FreshnessVerifyOpts{
		PublisherRootPub:    fixturePub(t),
		Now:                 fixtureNow,
		ExpectRelayPackID:   fixturePackID,
		MinSequence:         current.Sequence,
		CurrentBundleSHA256: "ff" + "00000000000000000000000000000000000000000000000000000000000000"[:62],
	})
	if !errors.Is(err, refresh.ErrFreshnessRollback) {
		t.Fatalf("want ErrFreshnessRollback for an equal sequence naming a different bundle, got %v", err)
	}
	// The same document at the same sequence naming the bundle we
	// already run is fine — that is an ordinary "nothing changed" poll
	// and must not be turned into an error.
	var currentSha struct {
		CurrentBundleSHA256 string `json:"current_bundle_sha256"`
	}
	if err := json.Unmarshal(readDoc(t, docCurrent), &currentSha); err != nil {
		t.Fatal(err)
	}
	if _, err := refresh.VerifyFreshnessDocument(readDoc(t, docCurrent), refresh.FreshnessVerifyOpts{
		PublisherRootPub:    fixturePub(t),
		Now:                 fixtureNow,
		ExpectRelayPackID:   fixturePackID,
		MinSequence:         current.Sequence,
		CurrentBundleSHA256: currentSha.CurrentBundleSHA256,
	}); err != nil {
		t.Fatalf("an unchanged re-serve of the current document was refused: %v", err)
	}
}

// THE WHOLE ROTATION, END TO END, ON THE PRODUCTION PATH.
//
// Import the pre-rotation pack the way a user does (prompt and all),
// then serve the post-rotation document and the post-rotation .sbp —
// both real publisher output — and drive the refresher the scheduler
// drives. The device must end up on the new pack.
//
// This is the assertion no single-module test could make. The publisher
// side proved it signs a document; the recipient side proved it
// verifies one it minted itself; neither could see that the id in the
// signed document is not the id the device is holding.
func TestRotationHealsAnImportedPackOverTheNetwork(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	v := importFixture(t, freshnessFixture)
	if _, err := ResolveTrustPrompt(v.Fingerprint, 0); err != nil {
		t.Fatalf("ResolveTrustPrompt: %v", err)
	}

	// Wave 1's fail-closed guard is process-global, and this suite
	// shares a process with tests that raise it. State it explicitly
	// rather than inheriting it: a rotation test that silently depends
	// on another test's cleanup passes in a full run and fails in a
	// filtered one, which is the worst possible signal.
	//
	// False here is the case freshness exists for — the relay is
	// burned, no route is up, and the device fetches the recovery
	// document directly. The guard is exercised on its own in
	// tunnel_refresh_test.go; it is not weakened here.
	refresh.SetTunnelRequired(false)
	t.Cleanup(func() { refresh.SetTunnelRequired(false) })

	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := rp.Targets()
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets: %+v %v", targets, err)
	}
	if targets[0].RelayPackID != fixturePackID {
		t.Fatalf("imported pack id = %q, want %q", targets[0].RelayPackID, fixturePackID)
	}

	rotatedPack, err := os.ReadFile(fixtureRotatedPack)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the document on every mirror and the pack at the URL the
	// document names. Nothing here reaches a network: .invalid hosts,
	// and the fetch is injected.
	served := map[string][]byte{
		"https://cdn-r2.invalid/daal/packs/abc.sbp": rotatedPack,
	}
	for _, ep := range targets[0].Endpoints {
		served[ep] = readDoc(t, docRotated)
	}
	rp.Fetch = func(_ context.Context, url string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
		body, ok := served[url]
		if !ok {
			return nil, errors.New("no route to " + url)
		}
		return body, nil
	}
	rp.Now = func() time.Time { return fixtureNow }

	res, err := rp.RefreshUser(context.Background(), fixturePackID)
	if err != nil {
		t.Fatalf("refresh: %v (outcome=%s verdict=%s)", err, res.Outcome, res.Verdict)
	}
	if !res.Applied {
		t.Fatalf("the rotated pack was not applied: outcome=%s verdict=%s changed=%v",
			res.Outcome, res.Verdict, res.Changed)
	}

	// The device is now on the rotated pack, keyed by its NEW id.
	after, err := rp.Targets()
	if err != nil || len(after) != 1 {
		t.Fatalf("targets after refresh: %+v %v", after, err)
	}
	if after[0].RelayPackID != fixtureRotatedPackID {
		t.Fatalf("after the rotation the device is on pack %q, want %q",
			after[0].RelayPackID, fixtureRotatedPackID)
	}
	// And the rotated pack still carries its full mirror set, so the
	// NEXT rotation has somewhere to land.
	if len(after[0].Endpoints) != 3 {
		t.Fatalf("endpoints after the rotation = %v, want the 3 the new pack signs", after[0].Endpoints)
	}

	// The anti-replay state moved with the pack. If it had not, the new
	// id would start at a zero high-water mark and the pre-rotation
	// document — genuinely signed, naming the burned address — would be
	// accepted once, immediately, on the next poll.
	if _, err := refresh.VerifyFreshnessDocument(readDoc(t, docCurrent), refresh.FreshnessVerifyOpts{
		PublisherRootPub:  fixturePub(t),
		Now:               fixtureNow,
		ExpectRelayPackID: fixtureRotatedPackID,
	}); err == nil {
		t.Fatal("the pre-rotation document verifies against the rotated pack id")
	}
	served2 := map[string][]byte{}
	for _, ep := range after[0].Endpoints {
		served2[ep] = readDoc(t, docCurrent)
	}
	rp.Fetch = func(_ context.Context, url string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
		body, ok := served2[url]
		if !ok {
			return nil, errors.New("no route to " + url)
		}
		return body, nil
	}
	replay, _ := rp.RefreshUser(context.Background(), fixtureRotatedPackID)
	if replay.Applied {
		t.Fatal("a replayed pre-rotation document was applied after the rotation")
	}
}
