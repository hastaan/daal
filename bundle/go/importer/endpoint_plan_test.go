package importer_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
)

// deviceState is fakeState plus what a real store has: the routes and
// profiles of earlier imports, readable by route id.
type deviceState struct {
	*fakeState
	routes map[string]importer.DeviceRoute
}

func newDeviceState() *deviceState {
	return &deviceState{fakeState: newFakeState(), routes: map[string]importer.DeviceRoute{}}
}

func (d *deviceState) SaveImport(p importer.PublisherInput, routes []importer.RouteInput) error {
	if err := d.fakeState.SaveImport(p, routes); err != nil {
		return err
	}
	for _, r := range routes {
		dr := importer.DeviceRoute{PublisherFingerprint: p.Fingerprint, TransportFamily: r.TransportFamily,
			Profile:  append([]byte(nil), r.Profile...),
			Endpoint: append([]byte(nil), r.Endpoint...), SignedAt: r.SignedAt}
		if r.RelayPack != nil {
			dr.RelayPackID = r.RelayPack.RelayPackID
		}
		d.routes[r.RouteID] = dr
	}
	return nil
}

func (d *deviceState) DeviceRoute(id string) (importer.DeviceRoute, bool, error) {
	r, ok := d.routes[id]
	return r, ok, nil
}

// repack rewrites archive entries of a signed .sbp WITHOUT any key:
// manifest.json and manifest.sig are copied through untouched, exactly
// as somebody who intercepted the file would have to.
func repack(t *testing.T, body []byte, edit func(profiles map[string][]byte)) []byte {
	t.Helper()
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string][]byte{}
	for k, v := range parsed.Profiles {
		profiles[k] = append([]byte(nil), v...)
	}
	edit(profiles)
	files := map[string][]byte{"manifest.sig": parsed.Signature, "publisher.pub": parsed.PublisherPub}
	for k, v := range profiles {
		files[k] = v
	}
	out, err := bundle.BuildUnsignedBundle(parsed.Manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func setField(t *testing.T, profile []byte, path string, value any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(profile, &doc); err != nil {
		t.Fatal(err)
	}
	cur := doc
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		cur = cur[p].(map[string]any)
	}
	cur[parts[len(parts)-1]] = value
	out, _ := json.Marshal(doc)
	return out
}

// F-004. A pack whose outbound was rewritten after signing is refused —
// at first sight, BEFORE the trust prompt, with a reason of its own —
// for every field that says where the route points or what proves the
// relay is the relay.
func TestImport_TamperedEndpointIsRefusedNotPrompted(t *testing.T) {
	genuine := makeBundle(t, func(m *bundle.Manifest) { addRelayPack(t, m) })
	if v, err := importer.ImportBytes(genuine, newFakeState(), wordlists(), time.Now().UTC()); err != nil || v.Kind != importer.VerdictTrustPromptNeeded {
		t.Fatalf("control: the genuine pack must reach the trust prompt: %+v %v", v, err)
	}
	rewrites := map[string]struct {
		path  string
		value any
	}{
		"server":             {"server", "198.51.100.66"},
		"port":               {"server_port", 8443},
		"reality public key": {"tls.reality.public_key", "attacker-key"},
		"cover host":         {"tls.server_name", "attacker.example"},
		"insecure":           {"tls.insecure", true},
		// The signed value stays in place; a second member is added
		// under a name sing-box reads as the same field (it matches
		// names without regard to case: U+017F folds to s, U+212A to
		// k) and, coming later, prefers. See bundle.CheckOutbound.
		"second spelling of server":         {"\u017ferver", "198.51.100.66"},
		"second spelling of reality key":    {"tls.reality.public_\u212aey", "attacker-key"},
		"second spelling of insecure":       {"tls.Insecure", true},
		"second spelling of an absent knob": {"Detour", "direct"},
	}
	for name, rw := range rewrites {
		tampered := repack(t, genuine, func(p map[string][]byte) {
			p["profiles/rA.json"] = setField(t, p["profiles/rA.json"], rw.path, rw.value)
		})
		// The signature still verifies: nothing signed was touched.
		parsed, _ := bundle.ParseSBP(bytes.NewReader(tampered), int64(len(tampered)))
		if err := bundle.VerifyBundle(parsed); err != nil {
			t.Fatalf("%s: tampered fixture must still verify (it is the PROFILE that changed): %v", name, err)
		}
		st := newFakeState()
		v, err := importer.ImportBytes(tampered, st, wordlists(), time.Now().UTC())
		if err == nil || v.Kind != importer.VerdictRejected || v.Reason != importer.ReasonEndpointMismatch {
			t.Fatalf("%s rewritten: verdict=%+v err=%v, want rejected/%s", name, v, err, importer.ReasonEndpointMismatch)
		}
		if !errors.Is(err, bundle.ErrEndpointMismatch) {
			t.Fatalf("%s: err=%v", name, err)
		}
		// And the trust step cannot be used to get round it.
		v, err = importer.AcceptTrustPrompt("trust", tampered, st, wordlists(), time.Now().UTC())
		if err == nil || v.Reason != importer.ReasonEndpointMismatch || st.saveCalls != 0 {
			t.Fatalf("%s: AcceptTrustPrompt stored a tampered pack: %+v err=%v saves=%d", name, v, err, st.saveCalls)
		}
	}
}

// A RelayPack signed WITHOUT commitments (the format before this
// change, or a commitment stripped by re-signing with another key —
// which the signature check catches first) cannot say where it points.
// It is refused; it is not offered to the user as a trust decision.
func TestImport_RelayPackWithoutCommitmentIsRefused(t *testing.T) {
	legacy := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		for i := range m.Routes {
			var fc map[string]json.RawMessage
			_ = json.Unmarshal(m.Routes[i].FamilySpecificConfig, &fc)
			delete(fc, bundle.EndpointKey)
			m.Routes[i].FamilySpecificConfig, _ = json.Marshal(fc)
		}
	})
	st := newFakeState()
	v, err := importer.ImportBytes(legacy, st, wordlists(), time.Now().UTC())
	if err == nil || v.Kind != importer.VerdictRejected || v.Reason != importer.ReasonEndpointUnauthenticated {
		t.Fatalf("verdict=%+v err=%v", v, err)
	}
	// Stripping the commitment out of a SIGNED manifest is a signature
	// failure, not this case.
	genuine := makeBundle(t, func(m *bundle.Manifest) { addRelayPack(t, m) })
	parsed, _ := bundle.ParseSBP(bytes.NewReader(genuine), int64(len(genuine)))
	for i := range parsed.Manifest.Routes {
		var fc map[string]json.RawMessage
		_ = json.Unmarshal(parsed.Manifest.Routes[i].FamilySpecificConfig, &fc)
		delete(fc, bundle.EndpointKey)
		parsed.Manifest.Routes[i].FamilySpecificConfig, _ = json.Marshal(fc)
	}
	files := map[string][]byte{"manifest.sig": parsed.Signature, "publisher.pub": parsed.PublisherPub}
	for k, p := range parsed.Profiles {
		files[k] = p
	}
	stripped, err := bundle.BuildUnsignedBundle(parsed.Manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	v, err = importer.ImportBytes(stripped, newFakeState(), wordlists(), time.Now().UTC())
	if err == nil || v.Reason != "bundle_signature_invalid" {
		t.Fatalf("stripped commitment: verdict=%+v err=%v, want bundle_signature_invalid", v, err)
	}
}

func skeletonOf(t *testing.T, body []byte, mark map[string]string) []byte {
	return repack(t, body, func(p map[string][]byte) {
		for k := range p {
			p[k] = []byte(`{"port":443,"_relaypack":{}}`)
		}
		for k, v := range mark {
			p[k] = []byte(v)
		}
	})
}

// LC-2, first half: the publisher's signed, credential-less pack on a
// device that holds nothing is not an import. It is refused with a
// reason that says what is missing, and nothing is stored.
func TestImport_SkeletonAloneIsRefused(t *testing.T) {
	genuine := makeBundle(t, func(m *bundle.Manifest) { addRelayPack(t, m) })
	st := newDeviceState()
	v, err := importer.ImportBytes(skeletonOf(t, genuine, nil), st, wordlists(), time.Now().UTC())
	if err == nil || v.Kind != importer.VerdictRejected || v.Reason != importer.ReasonNoCredentials || st.saveCalls != 0 {
		t.Fatalf("verdict=%+v err=%v saves=%d", v, err, st.saveCalls)
	}
}

// movedPack is the same relay after its address moved (L3) and its
// cover host changed (L2): a NEW signed manifest, new pack id.
func movedPack(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, bundle.Endpoint) {
	moved := fixtureEndpoint()
	moved.Server = "198.51.100.200"
	moved.ServerName = "new-cover.example"
	body := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		m.RelayPack.RelayPackID = "rp-importer-test-002"
		for i := range m.Routes {
			var fc map[string]any
			_ = json.Unmarshal(m.Routes[i].FamilySpecificConfig, &fc)
			fc[bundle.EndpointKey] = moved
			m.Routes[i].FamilySpecificConfig, _ = json.Marshal(fc)
		}
	})
	return body, moved
}

func mustImport(t *testing.T, st importer.State, body []byte) {
	t.Helper()
	if v, err := importer.ImportBytes(body, st, wordlists(), time.Now().UTC()); err != nil || v.Kind != importer.VerdictTrustPromptNeeded {
		t.Fatalf("import: %+v %v", v, err)
	}
	if v, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), time.Now().UTC()); err != nil || v.Kind != importer.VerdictImported {
		t.Fatalf("trust: %+v %v", v, err)
	}
}

// LC-2, the fix. A freshness-delivered signed skeleton is MERGED: the
// device keeps its credentials and takes the new signed endpoint. No
// profile that yields no outbound replaces one that does.
func TestApplyVerifiedRefresh_MergesSignedEndpointIntoDeviceCredentials(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	genuine := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) { addRelayPack(t, m) })
	st := newDeviceState()
	mustImport(t, st, genuine)

	moved, movedEP := movedPack(t, pub, priv)
	// rA: skeleton. rB: the minter's "not offered" marker.
	skeleton := skeletonOf(t, moved, map[string]string{
		"profiles/rB.json": `{"port":443,"_daal_unavailable":{"family":"vless-reality","reason":"x"}}`,
	})
	sum := sha256.Sum256(skeleton)
	v, err := importer.ApplyVerifiedRefresh(skeleton, hex.EncodeToString(sum[:]), st, wordlists(), time.Now().UTC())
	if err != nil || v.Kind != importer.VerdictImported {
		t.Fatalf("refresh: %+v %v", v, err)
	}
	if v.Merged != 2 || v.RouteCount != 2 || len(v.Unavailable) != 0 {
		t.Fatalf("both routes hold credentials on the device and must merge: %+v", v)
	}
	last := st.saved[len(st.saved)-1]
	for _, r := range last {
		if err := bundle.CheckOutbound(r.TransportFamily, &movedEP, r.Profile); err != nil {
			t.Fatalf("route %s: stored profile does not match the NEW signed endpoint: %v", r.RouteID, err)
		}
		var ob map[string]any
		_ = json.Unmarshal(r.Profile, &ob)
		if ob["uuid"] != "11111111-2222-3333-4444-555555555555" {
			t.Fatalf("route %s: the device's credential was not kept: %v", r.RouteID, ob["uuid"])
		}
		var ep bundle.Endpoint
		if json.Unmarshal(r.Endpoint, &ep) != nil || ep.Server != "198.51.100.200" {
			t.Fatalf("route %s: the signed endpoint was not handed to the store: %s", r.RouteID, r.Endpoint)
		}
	}
}

// The same skeleton handed over as a FILE, for a different pack id,
// carries no publisher statement that it replaces the device's pack.
// It is not merged, and nothing on the device changes.
func TestImport_SkeletonForAnotherPackIsNotMerged(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	genuine := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) { addRelayPack(t, m) })
	st := newDeviceState()
	mustImport(t, st, genuine)
	before := st.saveCalls
	moved, _ := movedPack(t, pub, priv)
	v, err := importer.ImportBytes(skeletonOf(t, moved, nil), st, wordlists(), time.Now().UTC())
	if err == nil || v.Reason != importer.ReasonNoCredentials || st.saveCalls != before {
		t.Fatalf("verdict=%+v err=%v saves=%d (was %d)", v, err, st.saveCalls, before)
	}
	// Same pack id (a re-sign that changed nothing the id hashes): merged.
	same := skeletonOf(t, genuine, nil)
	v, err = importer.ImportBytes(same, st, wordlists(), time.Now().UTC())
	if err != nil || v.Merged != 2 {
		t.Fatalf("same-pack skeleton: %+v %v", v, err)
	}
}

// A route the device holds credentials for, whose relay key changed
// (a rebuilt box), cannot be merged. It is reported as needing a new
// file and the route the device has is LEFT AS IT WAS.
func TestApplyVerifiedRefresh_NeverReplacesAWorkingRouteWithOneThatCannotConnect(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	genuine := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) { addRelayPack(t, m) })
	st := newDeviceState()
	mustImport(t, st, genuine)
	// Make rB's device profile one that cannot take the new endpoint:
	// another family's outbound sitting under the route id.
	held := st.routes["rB"]
	held.Profile = []byte(`{"type":"hysteria2","server":"5.75.0.1","server_port":443,"password":"p"}`)
	st.routes["rB"] = held
	keep := append([]byte(nil), st.routes["rB"].Profile...)

	moved, _ := movedPack(t, pub, priv)
	skeleton := skeletonOf(t, moved, nil)
	sum := sha256.Sum256(skeleton)
	v, err := importer.ApplyVerifiedRefresh(skeleton, hex.EncodeToString(sum[:]), st, wordlists(), time.Now().UTC())
	if err != nil || v.Merged != 1 || v.RouteCount != 1 {
		t.Fatalf("refresh: %+v %v", v, err)
	}
	if len(v.Unavailable) != 1 || v.Unavailable[0].RouteID != "rB" || v.Unavailable[0].Reason != importer.UnavailableNeedsNewFile {
		t.Fatalf("unavailable: %+v", v.Unavailable)
	}
	for _, r := range st.saved[len(st.saved)-1] {
		if r.RouteID == "rB" {
			t.Fatal("rB was written: a profile that cannot connect replaced the one the device had")
		}
	}
	if !bytes.Equal(st.routes["rB"].Profile, keep) {
		t.Fatal("rB's profile on the device changed")
	}
}

// F-003. A route the minter dropped is not a route on the client: it is
// not stored, so nothing can list, select or activate it. The verdict
// names it, with a reason the UI has copy for.
func TestImport_RoutesTheMinterDroppedAreNotStored(t *testing.T) {
	genuine := makeBundle(t, func(m *bundle.Manifest) { addRelayPack(t, m) })
	pack := repack(t, genuine, func(p map[string][]byte) {
		p["profiles/rB.json"] = []byte(`{"port":443,"_relaypack":{},"_daal_unavailable":{"family":"vless-reality","reason":"this relay did not report a credential"}}`)
	})
	st := newDeviceState()
	v, err := importer.ImportBytes(pack, st, wordlists(), time.Now().UTC())
	if err != nil || v.Kind != importer.VerdictTrustPromptNeeded || v.RouteCount != 1 {
		t.Fatalf("prompt: %+v %v", v, err)
	}
	v, err = importer.AcceptTrustPrompt("trust", pack, st, wordlists(), time.Now().UTC())
	if err != nil || v.RouteCount != 1 {
		t.Fatalf("import: %+v %v", v, err)
	}
	if len(st.saved) != 1 || len(st.saved[0]) != 1 || st.saved[0][0].RouteID != "rA" {
		t.Fatalf("stored routes: %+v", st.saved)
	}
	if len(v.Unavailable) != 1 || v.Unavailable[0].RouteID != "rB" ||
		v.Unavailable[0].Reason != importer.UnavailableNotOffered || v.Unavailable[0].Family != "vless-reality" {
		t.Fatalf("unavailable: %+v", v.Unavailable)
	}
}

// packIssuedAt is the fixture RelayPack, same pack id, signed at a
// chosen time and committing to a chosen REALITY key — an in-place
// rotation, which by design does not change the pack id.
func packIssuedAt(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, at time.Time, realityKey string) ([]byte, bundle.Endpoint) {
	t.Helper()
	ep := fixtureEndpoint()
	ep.RealityPublicKey = realityKey
	body := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		m.Bundle.CreatedAt = at.UTC().Format(time.RFC3339)
		for i := range m.Routes {
			var fc map[string]any
			_ = json.Unmarshal(m.Routes[i].FamilySpecificConfig, &fc)
			fc[bundle.EndpointKey] = ep
			m.Routes[i].FamilySpecificConfig, _ = json.Marshal(fc)
		}
	})
	return body, ep
}

// A signed skeleton is public (it is what the freshness mirrors serve),
// so anybody can keep an old one. Handed over as a FILE after the
// publisher rotated a burned key in place, it must not put the device
// back on that key: a file-path merge only ever moves a route FORWARD.
func TestImport_AnOlderSkeletonDoesNotRollARouteBack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	v1, _ := packIssuedAt(t, pub, priv, now.Add(-2*time.Hour), "fixture-reality-public-key")
	v2, v2EP := packIssuedAt(t, pub, priv, now.Add(-1*time.Hour), "rotated-reality-public-key")

	st := newDeviceState()
	mustImport(t, st, v1)
	// The rotation reaches the device as the newer skeleton, by file.
	v, err := importer.ImportBytes(skeletonOf(t, v2, nil), st, wordlists(), now)
	if err != nil || v.Kind != importer.VerdictImported || v.Merged != 2 {
		t.Fatalf("newer skeleton must merge: %+v %v", v, err)
	}
	before := st.saveCalls
	held := map[string][]byte{}
	for id, r := range st.routes {
		held[id] = append([]byte(nil), r.Profile...)
	}

	// The replay: v1's skeleton, publisher pinned, so no prompt.
	v, err = importer.ImportBytes(skeletonOf(t, v1, nil), st, wordlists(), now)
	if err == nil || v.Kind != importer.VerdictRejected || v.Reason != importer.ReasonPackIsOlder {
		t.Fatalf("an older skeleton was not refused as older: %+v %v", v, err)
	}
	if v.Merged != 0 || st.saveCalls != before {
		t.Fatalf("the replay wrote to the device: merged=%d saves=%d (was %d)", v.Merged, st.saveCalls, before)
	}
	for id, r := range st.routes {
		if !bytes.Equal(r.Profile, held[id]) {
			t.Fatalf("route %s: profile changed", id)
		}
		if err := bundle.CheckOutbound(r.TransportFamily, &v2EP, r.Profile); err != nil {
			t.Fatalf("route %s is no longer on the rotated key: %v", id, err)
		}
	}

	// The skeleton the device is already on is a no-op, not a refusal.
	v, err = importer.ImportBytes(skeletonOf(t, v2, nil), st, wordlists(), now)
	if err != nil || v.Merged != 2 {
		t.Fatalf("re-importing the current skeleton: %+v %v", v, err)
	}
}

// A pack with one route the device can take and one that would be
// rolled back: the first is stored, the second is reported and left.
func TestImport_AnOlderSkeletonRouteIsReportedAndLeftAlone(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	v1, _ := packIssuedAt(t, pub, priv, now.Add(-2*time.Hour), "fixture-reality-public-key")
	v2, _ := packIssuedAt(t, pub, priv, now.Add(-1*time.Hour), "rotated-reality-public-key")
	st := newDeviceState()
	mustImport(t, st, v1)
	if v, err := importer.ImportBytes(skeletonOf(t, v2, nil), st, wordlists(), now); err != nil || v.Merged != 2 {
		t.Fatalf("newer skeleton: %+v %v", v, err)
	}
	keep := append([]byte(nil), st.routes["rB"].Profile...)
	// v1 with rA's credentials still in the file and rB as a skeleton.
	mixed := repack(t, v1, func(p map[string][]byte) {
		p["profiles/rB.json"] = []byte(`{"port":443,"_relaypack":{}}`)
	})
	v, err := importer.ImportBytes(mixed, st, wordlists(), now)
	if err != nil || v.Kind != importer.VerdictImported || v.Merged != 0 || v.RouteCount != 1 {
		t.Fatalf("mixed: %+v %v", v, err)
	}
	if len(v.Unavailable) != 1 || v.Unavailable[0].RouteID != "rB" || v.Unavailable[0].Reason != importer.UnavailableOlderThanDevice {
		t.Fatalf("unavailable: %+v", v.Unavailable)
	}
	if !bytes.Equal(st.routes["rB"].Profile, keep) {
		t.Fatal("rB was rolled back")
	}
}

// A route with no record of when its endpoint was signed cannot be
// shown to be older than an incoming skeleton, so a file does not
// merge into it. The freshness path, which carries the publisher's own
// statement of succession, still does.
func TestImport_SkeletonDoesNotMergeIntoARouteOfUnknownAge(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	genuine := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) { addRelayPack(t, m) })
	st := newDeviceState()
	mustImport(t, st, genuine)
	for id, r := range st.routes {
		r.SignedAt = ""
		st.routes[id] = r
	}
	v, err := importer.ImportBytes(skeletonOf(t, genuine, nil), st, wordlists(), time.Now().UTC())
	if err == nil || v.Merged != 0 || v.Reason != importer.ReasonNoCredentials {
		t.Fatalf("file: %+v %v", v, err)
	}
	skeleton := skeletonOf(t, genuine, nil)
	sum := sha256.Sum256(skeleton)
	v, err = importer.ApplyVerifiedRefresh(skeleton, hex.EncodeToString(sum[:]), st, wordlists(), time.Now().UTC())
	if err != nil || v.Merged != 2 {
		t.Fatalf("freshness: %+v %v", v, err)
	}
}

// committedState is deviceState plus what the real store answers for
// importer.CommittedRoutes: is a route this device holds bound to a
// signed endpoint (or part of a RelayPack)?
type committedState struct{ *deviceState }

func (c committedState) RouteCommitted(id string) (bool, error) {
	r, ok := c.routes[id]
	return ok && (len(r.Endpoint) > 0 || r.RelayPackID != ""), nil
}

// A bundle with no relay_pack slot carries profiles that nothing signs.
// One genuine, unexpired bundle of that kind from the SAME publisher,
// with the same route ids and its profiles rewritten by anybody, must
// not replace routes that are held to a signed endpoint: it would turn
// authenticated routes into unauthenticated ones pointing wherever the
// rewriter chose, silently (the publisher is already trusted).
func TestImport_BundleWithoutCommitmentsDoesNotReplaceCommittedRoutes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := committedState{newDeviceState()}
	pack := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) { addRelayPack(t, m) })
	mustImport(t, st, pack)
	held := map[string]importer.DeviceRoute{}
	for id, r := range st.routes {
		held[id] = r
	}
	savesBefore := st.saveCalls

	// Same key, same route ids, no relay_pack slot — then rewritten
	// with no key at all.
	plain := makeBundleSignedBy(t, pub, priv, nil)
	evil := []byte(`{"type":"vless","server":"198.51.100.66","server_port":443,"tls":{"enabled":true,"insecure":true}}`)
	attack := repack(t, plain, func(p map[string][]byte) {
		for k := range p {
			p[k] = evil
		}
	})

	v, err := importer.ImportBytes(attack, st, wordlists(), time.Now().UTC())
	if err == nil || v.Kind != importer.VerdictRejected || v.Reason != importer.ReasonEndpointDowngrade {
		t.Fatalf("want rejected/%s, got %+v err=%v", importer.ReasonEndpointDowngrade, v, err)
	}
	if st.saveCalls != savesBefore {
		t.Fatalf("a refused import wrote routes: %d saved, was %d", st.saveCalls, savesBefore)
	}
	for id, was := range held {
		now := st.routes[id]
		if !bytes.Equal(now.Profile, was.Profile) || !bytes.Equal(now.Endpoint, was.Endpoint) || now.RelayPackID != was.RelayPackID {
			t.Fatalf("route %s changed: %+v", id, now)
		}
	}
	// The trust-prompt path reaches the same gate.
	if v, err := importer.AcceptTrustPrompt("trust", attack, st, wordlists(), time.Now().UTC()); err == nil || v.Reason != importer.ReasonEndpointDowngrade {
		t.Fatalf("AcceptTrustPrompt: want %s, got %+v err=%v", importer.ReasonEndpointDowngrade, v, err)
	}

	// A bundle without commitments whose routes are NEW to the device
	// is unaffected: the rule is about replacing, not about the format.
	fresh := makeBundleSignedBy(t, pub, priv, func(m *bundle.Manifest) {
		m.Routes[0].ID, m.Routes[1].ID = "rC", "rD"
	})
	if v, err := importer.ImportBytes(fresh, st, wordlists(), time.Now().UTC()); err != nil || v.Kind != importer.VerdictImported {
		t.Fatalf("new route ids: %+v %v", v, err)
	}
}
