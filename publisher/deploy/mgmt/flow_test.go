package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// The ephemeral firewall window is the one thing in this package that
// is a security bug when it goes wrong rather than a broken feature: a
// window left open leaves the mgmt port reachable from the caller's IP
// for the rest of its 300 seconds. Every test below asserts the same
// pair — opened exactly once, closed exactly once — across the success
// path and every distinct failure path there is.

// stubProvider captures (Set|Remove)EphemeralFirewallRule calls.
type stubProvider struct {
	provider.Provider
	setCalls    int
	removeCalls int
	setErr      error
	rule        *EphemeralRuleRecord
	// onSet fires once the window is open, so a test can kill the
	// caller's context at exactly the moment that matters.
	onSet func()
	// removeCtxErr records the state of the context the teardown was
	// handed. A real provider makes an API call there, so a cancelled
	// context means the rule is NOT actually removed.
	removeCtxErr error
}

func (s *stubProvider) SetEphemeralFirewallRule(_ context.Context, serverID, callerIP string, port, dur int) (*provider.EphemeralFirewallRule, error) {
	s.setCalls++
	if s.setErr != nil {
		return nil, s.setErr
	}
	s.rule = &EphemeralRuleRecord{ServerID: serverID, CallerIP: callerIP, Port: port, DurationSec: dur}
	if s.onSet != nil {
		s.onSet()
	}
	return &provider.EphemeralFirewallRule{ID: "stub-rule", ServerID: serverID, CallerIP: callerIP, Port: port}, nil
}

func (s *stubProvider) RemoveEphemeralFirewallRule(ctx context.Context, _ *provider.EphemeralFirewallRule) error {
	s.removeCalls++
	s.removeCtxErr = ctx.Err()
	return s.removeCtxErr
}

// EphemeralRuleRecord records what the window was opened with.
type EphemeralRuleRecord struct {
	ServerID    string
	CallerIP    string
	Port        int
	DurationSec int
}

// assertWindowBalanced is the invariant every path shares.
func assertWindowBalanced(t *testing.T, prov *stubProvider, wantSet int) {
	t.Helper()
	if prov.setCalls != wantSet {
		t.Errorf("SetEphemeralFirewallRule called %d times, want %d", prov.setCalls, wantSet)
	}
	if prov.removeCalls != wantSet {
		t.Errorf("firewall window left open: set=%d remove=%d", prov.setCalls, prov.removeCalls)
	}
}

// capableBox is a fake relay running post-Step-7 software.
func capableBox(t *testing.T, pub ed25519.PublicKey, routes map[string]http.HandlerFunc) (*http.ServeMux, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(BoxCapabilities{
			OK:             true,
			MgmtAPIVersion: MgmtAPIVersionSplitRotation,
			Capabilities:   []string{CapRotateCredentialsScoped, CapRotateTLSScoped},
		})
	})
	for path, h := range routes {
		p, fn := path, h
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Daal-Mgmt-Token ")
			nonce, tsStr, op, sig, err := ParseToken(tok)
			if err != nil || !ed25519.Verify(pub, []byte(nonce+":"+tsStr+":"+op), sig) {
				http.Error(w, "auth", 401)
				return
			}
			fn(w, r)
		})
	}
	return mux, func() {}
}

// legacyBox is a relay running the PRE-Step-7 binary: the routes exist
// (they have since FRP-10), /health says only {"ok":true}, and
// /rotate-credentials would happily rotate the box-wide REALITY keypair
// if anyone let it. Nothing must reach those routes.
func legacyBox(t *testing.T, tripped *bool) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	boom := func(w http.ResponseWriter, r *http.Request) {
		*tripped = true
		_ = json.NewEncoder(w).Encode(map[string]any{"uuid": "conflated"})
	}
	mux.HandleFunc("/rotate-credentials", boom)
	mux.HandleFunc("/rotate-tls", boom)
	return mux
}

func mkLiveRec(t *testing.T, mux http.Handler) (rec *provider.OperatorRecord, closeFn func()) {
	t.Helper()
	ts, fp := startTLSServer(t, mux)
	port, host := splitURL(t, ts.URL)
	r := mkRec(t, fp, port)
	r.PublicIP = net.ParseIP(host)
	r.Region = "fsn1"
	r.CoverSNI = "mirror.init7.net"
	return r, ts.Close
}

// --- rotate-credentials ---

func TestRotateCredentialsWithFW_OpensAndClosesRule(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawName string
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-credentials": func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			sawName = req.Name
			_ = json.NewEncoder(w).Encode(RotatedCreds{
				UserCreds:     UserCreds{Name: req.Name, VLESSUUID: "new-uuid", CoverSNI: "mirror.init7.net", MuxInbound: true},
				RotatedAtUnix: 1777000000,
			})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()

	prov := &stubProvider{}
	creds, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "r2")
	if err != nil {
		t.Fatal(err)
	}
	if sawName != "r2" {
		t.Errorf("box saw name %q, want r2", sawName)
	}
	if creds.VLESSUUID != "new-uuid" {
		t.Errorf("UUID lost: %q", creds.VLESSUUID)
	}
	// The box→publisher carrier fields must survive the hop. They were
	// silently dropped once already on the provision path.
	if creds.CoverSNI != "mirror.init7.net" || !creds.MuxInbound {
		t.Errorf("rotation dropped box-wide carrier fields: %+v", creds.UserCreds)
	}
	if creds.RotatedAtUnix == 0 {
		t.Errorf("rotated_at_unix lost")
	}
	assertWindowBalanced(t, prov, 1)
	if prov.rule.Port != rec.MgmtPort {
		t.Errorf("rule opened wrong port; got %d want %d", prov.rule.Port, rec.MgmtPort)
	}
	if prov.rule.DurationSec != EphemeralWindowSeconds {
		t.Errorf("window duration %d, want %d", prov.rule.DurationSec, EphemeralWindowSeconds)
	}
}

func TestRotateCredentialsWithFW_CleansUpOnBoxError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-credentials": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", 500)
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()

	prov := &stubProvider{}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "r1"); err == nil {
		t.Fatal("expected error from 500 response")
	}
	assertWindowBalanced(t, prov, 1)
}

// A cancelled caller context is the case where cleanup matters most and
// is easiest to get wrong. The obvious teardown reuses ctx — which by
// then is exactly the context that just died — so the removal call
// fails instantly and the window stays open for the rest of its 300
// seconds, on the one path where a rotation went wrong. The window is
// killed here the moment it opens, and the teardown must still be
// handed a live context.
func TestRotateCredentialsWithFW_ClosesWindowWhenContextCancelled(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-credentials": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(RotatedCreds{})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()

	prov := &stubProvider{onSet: cancel}
	if _, err := RotateCredentialsWithFW(ctx, prov, rec, priv, "1.2.3.4", "r1"); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	assertWindowBalanced(t, prov, 1)
	if prov.removeCtxErr != nil {
		t.Fatalf("teardown ran on a dead context (%v) — the rule would have survived the failure", prov.removeCtxErr)
	}
}

// An empty name must be refused BEFORE the window opens. On a
// version-skewed box it is not a no-op — it is a box-wide REALITY key
// rotation that kills every distributed pack.
func TestRotateCredentialsWithFW_EmptyNameOpensNothing(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, strings.Repeat("ab", 32), 42424)
	prov := &stubProvider{}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "  "); !errors.Is(err, ErrRecipientNameRequired) {
		t.Fatalf("err = %v, want ErrRecipientNameRequired", err)
	}
	assertWindowBalanced(t, prov, 0)
}

func TestRotateCredentialsWithFW_FallsBackOnZeroPort(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, "fp", 0) // V1.5 record (no MgmtPort)
	prov := &stubProvider{}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "r1"); err == nil {
		t.Fatal("V1.5 record (zero MgmtPort) must error so caller falls back to redeploy")
	}
	assertWindowBalanced(t, prov, 0)
}

// A provider that cannot open the window must not leave a phantom
// close (or a nil rule) behind it.
func TestRotateCredentialsWithFW_ProviderOpenFailureClosesNothing(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, strings.Repeat("ab", 32), 42424)
	prov := &stubProvider{setErr: errors.New("quota")}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "r1"); err == nil {
		t.Fatal("expected error when the firewall rule cannot be opened")
	}
	if prov.setCalls != 1 {
		t.Errorf("setCalls = %d want 1", prov.setCalls)
	}
	if prov.removeCalls != 0 {
		t.Errorf("removeCalls = %d; nothing was opened, nothing to close", prov.removeCalls)
	}
}

// --- capability interlock ---

// The flagship old-relay path: routes exist, box answers 200, and the
// publisher must still refuse — and must refuse without sending the
// mutating request, because on that box it is destructive.
func TestRotateCredentialsWithFW_RefusesOldRelayWithoutTouchingIt(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tripped := false
	rec, done := mkLiveRec(t, legacyBox(t, &tripped))
	defer done()

	prov := &stubProvider{}
	_, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "r1")
	if !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err = %v, want ErrCapabilityUnsupported", err)
	}
	if tripped {
		t.Fatal("publisher sent a rotation to a box that would have rotated the box-wide REALITY keypair")
	}
	if !strings.Contains(err.Error(), "reprovision") {
		t.Errorf("error must tell the operator what to do; got %v", err)
	}
	assertWindowBalanced(t, prov, 1)
}

func TestRotateTLSWithFW_RefusesOldRelayWithoutTouchingIt(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tripped := false
	rec, done := mkLiveRec(t, legacyBox(t, &tripped))
	defer done()

	before := rec.CoverSNI
	prov := &stubProvider{}
	_, err := RotateTLSWithFW(context.Background(), prov, rec, priv, "1.2.3.4", TLSProfile{})
	if !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err = %v, want ErrCapabilityUnsupported", err)
	}
	if tripped {
		t.Fatal("publisher sent a TLS rotation to a relay too old to scope it")
	}
	if rec.CoverSNI != before {
		t.Errorf("record moved to %q for a rotation that never happened", rec.CoverSNI)
	}
	assertWindowBalanced(t, prov, 1)
}

// "Cannot tell" is not "probably fine". A box we cannot identify is not
// a box we rotate.
func TestRotateCredentialsWithFW_UnreadableHealthFailsClosed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tripped := false
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gateway", 502)
	})
	mux.HandleFunc("/rotate-credentials", func(w http.ResponseWriter, r *http.Request) { tripped = true })
	rec, done := mkLiveRec(t, mux)
	defer done()

	prov := &stubProvider{}
	if _, err := RotateCredentialsWithFW(context.Background(), prov, rec, priv, "1.2.3.4", "r1"); err == nil {
		t.Fatal("a box whose capabilities cannot be read must not be rotated")
	}
	if tripped {
		t.Fatal("rotation fired despite an unreadable capability probe")
	}
	assertWindowBalanced(t, prov, 1)
}

// A capability list that names something else is still "no".
func TestCapabilities_FailsClosedOnUnrelatedVerbs(t *testing.T) {
	caps := &BoxCapabilities{OK: true, Capabilities: []string{"users-provision", "whoami"}}
	if caps.Has(CapRotateCredentialsScoped) || caps.Has(CapRotateTLSScoped) {
		t.Fatal("unrelated verbs read as support")
	}
	// api_version is the second positive signal, for a box that reports
	// a version but no list.
	versioned := &BoxCapabilities{OK: true, MgmtAPIVersion: MgmtAPIVersionSplitRotation}
	if !versioned.Has(CapRotateCredentialsScoped) || !versioned.Has(CapRotateTLSScoped) {
		t.Fatal("mgmt_api_version did not imply the verbs it defines")
	}
	older := &BoxCapabilities{OK: true, MgmtAPIVersion: MgmtAPIVersionSplitRotation - 1}
	if older.Has(CapRotateTLSScoped) {
		t.Fatal("an older api_version read as support")
	}
	var nilCaps *BoxCapabilities
	if nilCaps.Has(CapRotateTLSScoped) {
		t.Fatal("nil capabilities read as support")
	}
}

// The exact body a pre-Step-7 box sends must decode without error and
// mean "no". That absence IS the signal; an error here would turn it
// into a reachability failure.
func TestCapabilities_LegacyHealthBodyIsAValidNo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	rec, done := mkLiveRec(t, mux)
	defer done()
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := cli.Capabilities(context.Background(), rec)
	if err != nil {
		t.Fatalf("legacy /health must not be an error: %v", err)
	}
	if caps.Has(CapRotateCredentialsScoped) || caps.Has(CapRotateTLSScoped) {
		t.Fatal("legacy box read as capable")
	}
	if caps.Advertised() != "(none)" {
		t.Errorf("Advertised() = %q", caps.Advertised())
	}
}

// TestCapabilities_AcceptsRealBoxHealthBody is the peer of
// cmd/daal-relay-mgmt.TestHealthAdvertisesSplitRotation.
//
// The two modules have separate go.mod files and share no symbol, so
// nothing at compile time connects the strings the box emits to the
// strings this package looks for. The interlock fails CLOSED, which
// means a drift does not surface as an error — it surfaces as the
// publisher refusing to rotate CORRECT, freshly-released relays and
// telling the operator to reprovision. That is a very expensive way to
// discover a typo, so the body below is the box's literal output,
// pasted rather than constructed, and this test decodes it exactly as
// the wire would.
func TestCapabilities_AcceptsRealBoxHealthBody(t *testing.T) {
	// Byte-for-byte what cmd/daal-relay-mgmt's handleHealth writes,
	// trailing newline included — it uses json.Encoder, which appends
	// one, and a decoder that choked on it would fail only in the field.
	const boxHealthBody = `{"capabilities":["rotate-credentials-scoped","rotate-tls-scoped"],"mgmt_api_version":2,"ok":true}` + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, boxHealthBody)
	})
	rec, done := mkLiveRec(t, mux)
	defer done()
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := cli.Capabilities(context.Background(), rec)
	if err != nil {
		t.Fatalf("real box /health must decode: %v", err)
	}
	if !caps.Has(CapRotateCredentialsScoped) {
		t.Errorf("real box read as incapable of %q — in-place rotation would be refused against a correct relay", CapRotateCredentialsScoped)
	}
	if !caps.Has(CapRotateTLSScoped) {
		t.Errorf("real box read as incapable of %q", CapRotateTLSScoped)
	}
	if caps.MgmtAPIVersion != MgmtAPIVersionSplitRotation {
		t.Errorf("MgmtAPIVersion = %d want %d", caps.MgmtAPIVersion, MgmtAPIVersionSplitRotation)
	}
	// The version signal alone must also carry a box that reports a
	// version but no verb list.
	versionOnly := &BoxCapabilities{OK: true, MgmtAPIVersion: MgmtAPIVersionSplitRotation}
	if !versionOnly.Has(CapRotateCredentialsScoped) || !versionOnly.Has(CapRotateTLSScoped) {
		t.Error("mgmt_api_version alone must be a sufficient positive signal")
	}
}

// --- rotate-tls ---

func TestRotateTLSWithFW_PicksAFreshHostAndRecordsIt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawProfile TLSProfile
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-tls": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&sawProfile)
			_ = json.NewEncoder(w).Encode(RotateTLSResp{
				AppliedAtUnix:    1777000001,
				AppliedSNI:       sawProfile.NewSNI,
				AppliedHandshake: sawProfile.NewSNI + ":443",
			})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()
	before := rec.CoverSNI

	prov := &stubProvider{}
	resp, err := RotateTLSWithFW(context.Background(), prov, rec, priv, "1.2.3.4", TLSProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if sawProfile.NewSNI == "" {
		t.Fatal("box was asked to rotate TLS with no cover host at all")
	}
	if sawProfile.NewSNI == before {
		t.Errorf("rotation handed the relay back the host it already advertises (%q)", before)
	}
	if len(sawProfile.NewDests) != 1 || !strings.HasSuffix(sawProfile.NewDests[0], ":443") {
		t.Errorf("dest not derived from the new cover host: %v", sawProfile.NewDests)
	}
	// The record must follow the box, or the next pack is minted for the
	// burned host.
	if rec.CoverSNI != resp.AppliedSNI {
		t.Errorf("record CoverSNI = %q, box applied %q", rec.CoverSNI, resp.AppliedSNI)
	}
	assertWindowBalanced(t, prov, 1)
}

func TestRotateTLSWithFW_HonoursAPinnedSNI(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawProfile TLSProfile
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-tls": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&sawProfile)
			_ = json.NewEncoder(w).Encode(RotateTLSResp{
				AppliedAtUnix:    1,
				AppliedSNI:       sawProfile.NewSNI,
				AppliedHandshake: sawProfile.NewSNI + ":443",
			})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()
	prov := &stubProvider{}
	if _, err := RotateTLSWithFW(context.Background(), prov, rec, priv, "1.2.3.4", TLSProfile{NewSNI: "mirrors.dotsrc.org"}); err != nil {
		t.Fatal(err)
	}
	if sawProfile.NewSNI != "mirrors.dotsrc.org" {
		t.Errorf("pinned SNI not honoured; box saw %q", sawProfile.NewSNI)
	}
	if rec.CoverSNI != "mirrors.dotsrc.org" {
		t.Errorf("record CoverSNI = %q", rec.CoverSNI)
	}
}

// Wave 2's whole point was that tls.server_name and
// reality.handshake.server move together. A box that answers 200 with
// them disagreeing has left itself in a state that will fail
// classification, and a bare 200 must not hide it.
func TestRotateTLSWithFW_CatchesSNIHandshakeDisagreement(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-tls": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(RotateTLSResp{
				AppliedAtUnix:    1,
				AppliedSNI:       "mirrors.dotsrc.org",
				AppliedHandshake: "www.cloudflare.com:443",
			})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()
	prov := &stubProvider{}
	resp, err := RotateTLSWithFW(context.Background(), prov, rec, priv, "1.2.3.4", TLSProfile{NewSNI: "mirrors.dotsrc.org"})
	if err == nil {
		t.Fatal("accepted a box whose server_name and handshake.server disagree")
	}
	if resp == nil {
		t.Fatal("response withheld — the rotation DID apply and the caller must be able to persist it")
	}
	if rec.CoverSNI != "mirrors.dotsrc.org" {
		t.Errorf("record must still follow what the box applied; got %q", rec.CoverSNI)
	}
	assertWindowBalanced(t, prov, 1)
}

func TestRotateTLSWithFW_CleansUpOnBoxError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-tls": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "config rejected", 500)
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()
	before := rec.CoverSNI
	prov := &stubProvider{}
	if _, err := RotateTLSWithFW(context.Background(), prov, rec, priv, "1.2.3.4", TLSProfile{}); err == nil {
		t.Fatal("expected error from 500 response")
	}
	if rec.CoverSNI != before {
		t.Errorf("record moved for a rotation the box rejected: %q", rec.CoverSNI)
	}
	assertWindowBalanced(t, prov, 1)
}

func TestRotateTLSWithFW_FallsBackOnZeroPort(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, "fp", 0)
	rec.Region = "fsn1"
	prov := &stubProvider{}
	if _, err := RotateTLSWithFW(context.Background(), prov, rec, priv, "1.2.3.4", TLSProfile{}); err == nil {
		t.Fatal("V1.5 record (zero MgmtPort) must error")
	}
	assertWindowBalanced(t, prov, 0)
}

// --- the third operation stays absent ---

// Rotating the box's REALITY keypair invalidates every distributed pack
// at once. It must not be reachable from this package as a flag, an
// option or a side effect of either verb above. This test is a
// tripwire: if someone adds it here, they have to delete this and read
// why it was written.
func TestNoBoxKeyRotationSurfaceExists(t *testing.T) {
	if TLSProfileHasBoxKeyField() {
		t.Fatal("TLSProfile grew a box-key rotation field; that is a third operation with its own blast radius, not a flag on this one")
	}
}

// TLSProfileHasBoxKeyField reports whether TLSProfile carries anything
// that would rotate box-wide REALITY key material.
func TLSProfileHasBoxKeyField() bool {
	b, _ := json.Marshal(TLSProfile{NewSNI: "x", NewDests: []string{"x:443"}, NewWSPath: "/p"})
	s := string(b)
	for _, forbidden := range []string{"reality", "private_key", "keypair", "box_key"} {
		if strings.Contains(s, forbidden) {
			return true
		}
	}
	return false
}

// --- the box's honesty fields must survive the hop ---

// The box reports which inbounds it rewrote, whether it touched box-wide
// key material, and anything it wants said out loud. mgmt.UserCreds has
// already cost this project one inert feature by dropping fields the box
// sent; these are the rotation-path equivalents, and updated_inbounds is
// the one that distinguishes a complete revocation from a partial one.
func TestRotateCredentialsWithFW_CarriesTheBoxHonestyFields(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-credentials": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
				"name":"r2","vless_uuid":"u","reality_short_id":"ab",
				"updated_inbounds":["vless-reality","vless-ws","hy2","naive"],
				"warnings":["kick wrapper unavailable; sessions drop on next reload"],
				"box_keys_rotated":false,
				"generated_at_unix":1777000009
			}`))
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()

	creds, err := RotateCredentialsWithFW(context.Background(), &stubProvider{}, rec, priv, "1.2.3.4", "r2")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds.UpdatedInbounds) != 4 {
		t.Errorf("updated_inbounds dropped: %+v", creds.UpdatedInbounds)
	}
	if len(creds.Warnings) != 1 {
		t.Errorf("box warnings dropped: %+v", creds.Warnings)
	}
	// The box emits the legacy spelling too; a caller reading only
	// rotated_at_unix must still get a timestamp.
	if creds.RotatedAtUnix != 1777000009 {
		t.Errorf("RotatedAtUnix = %d, want the generated_at_unix fallback", creds.RotatedAtUnix)
	}
}

// box_keys_rotated=true means every pinned public key in the field just
// died. That is a fleet event, and the operator has to be told so in
// those words — but it is an ESCALATION, not a failure. The box has
// already moved, so the credentials must still reach the caller: a
// rotation reported as an error exits the CLI before the JSON is
// printed, leaves the roster pinning credentials the relay no longer
// accepts, and replaces the wizard's translated escalation banner with a
// raw Go sentence. The flag and the leading warning are what carry it.
func TestRotateCredentialsWithFW_FlagsBoxKeyRotation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-credentials": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(RotatedCreds{
				UserCreds:      UserCreds{Name: "r1", VLESSUUID: "u"},
				BoxKeysRotated: true,
			})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()

	creds, err := RotateCredentialsWithFW(context.Background(), &stubProvider{}, rec, priv, "1.2.3.4", "r1")
	if err != nil {
		t.Fatalf("the rotation happened; returning an error here throws the new credentials away: %v", err)
	}
	if creds == nil {
		t.Fatal("creds withheld — the rotation happened and the caller still has to persist it")
	}
	if !creds.BoxKeysRotated {
		t.Error("box_keys_rotated was dropped; it is the flag the wizard renders the fleet-wide escalation from")
	}
	if len(creds.Warnings) == 0 || !strings.Contains(creds.Warnings[0], "EVERY distributed pack") {
		t.Errorf("leading warning does not convey the blast radius: %v", creds.Warnings)
	}
}

// `changed` keeps an empty-bodied rotation honest. A box that answers
// 200 while leaving the cover host alone must not be read as a
// successful L2, or the relay stays burned behind a green tick.
func TestRotateTLSWithFW_DetectsACoverHostThatDidNotMove(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux, _ := capableBox(t, pub, map[string]http.HandlerFunc{
		"/rotate-tls": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(RotateTLSResp{
				AppliedAtUnix:    1,
				AppliedSNI:       "mirror.init7.net", // unchanged
				AppliedHandshake: "mirror.init7.net:443",
				Changed:          []string{"ws_path"},
			})
		},
	})
	rec, done := mkLiveRec(t, mux)
	defer done()

	_, err := RotateTLSWithFW(context.Background(), &stubProvider{}, rec, priv, "1.2.3.4", TLSProfile{})
	if err == nil {
		t.Fatal("accepted a 200 in which the cover host never moved")
	}
	if !strings.Contains(err.Error(), "still advertising") {
		t.Errorf("error does not say the relay is still on the burned host: %v", err)
	}
}
