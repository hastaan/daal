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
	"time"
)

// bindingBox is a relay running software that advertises the
// address-binding verbs.
func bindingBox(t *testing.T, pub ed25519.PublicKey, routes map[string]http.HandlerFunc) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(BoxCapabilities{
			OK:             true,
			MgmtAPIVersion: MgmtAPIVersionAddressBinding,
			Capabilities:   []string{CapRotateCredentialsScoped, CapRotateTLSScoped, CapBindAddress},
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
			// The box binds the token's op to the route (opFromPath in
			// cmd/daal-relay-mgmt). Assert the same here so a publisher
			// that mints the wrong op fails in this package rather than
			// against a live relay.
			if want := strings.TrimPrefix(p, "/"); op != want {
				http.Error(w, "op "+op+" does not match endpoint "+want, 401)
				return
			}
			fn(w, r)
		})
	}
	return mux
}

// --- the address-class guard ---------------------------------------
//
// Binding an address is root-level network configuration driven by a
// remote request. Request signing is the primary control; this is the
// defence behind it, and each rejected class is a distinct way a caller
// with the key (or a bug holding it) could hurt the host.

func TestBindableAddress_RefusesEverythingThatIsNotPublicUnicast(t *testing.T) {
	cases := []struct {
		addr string
		why  string
	}{
		{"0.0.0.0", "the unspecified address is not a host address"},
		{"127.0.0.1", "loopback would shadow the host's own stack"},
		{"169.254.169.254", "the cloud metadata service — owning it locally redirects the box's credential lookups"},
		{"169.254.1.1", "link-local"},
		{"10.0.0.5", "RFC1918"},
		{"172.16.4.4", "RFC1918"},
		{"192.168.1.1", "RFC1918"},
		{"100.64.0.1", "CGNAT/shared space is an internal route"},
		{"224.0.0.1", "multicast is not unicast"},
		{"239.1.2.3", "multicast"},
		{"255.255.255.255", "broadcast"},
		{"240.0.0.1", "reserved"},
		{"0.1.2.3", "\"this network\""},
		{"198.18.0.1", "benchmarking range"},
		{"192.0.0.8", "IETF protocol assignments"},
		{"::", "the unspecified address"},
		{"::1", "loopback"},
		{"fe80::1", "IPv6 link-local"},
		{"fd00::1", "IPv6 ULA is private"},
		{"ff02::1", "IPv6 multicast"},
		{"2002::1", "6to4 tunnelling, not a host address"},
		{"64:ff9b::1.2.3.4", "NAT64 translation prefix"},
		// The long spelling of a private address must not slip past the
		// v4 rules.
		{"::ffff:10.0.0.5", "IPv4-mapped RFC1918"},
		{"::ffff:127.0.0.1", "IPv4-mapped loopback"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.addr)
		if ip == nil {
			t.Fatalf("test bug: %q is not an IP", c.addr)
		}
		if _, err := BindableAddress(ip); err == nil {
			t.Errorf("BindableAddress(%s) allowed it — %s", c.addr, c.why)
		} else if !errors.Is(err, ErrAddressNotBindable) {
			t.Errorf("BindableAddress(%s) = %v, want ErrAddressNotBindable", c.addr, err)
		}
	}
	if _, err := BindableAddress(nil); err == nil {
		t.Error("a nil address must be refused")
	}
}

func TestBindableAddress_AcceptsAndCanonicalisesAPublicAddress(t *testing.T) {
	// A real Hetzner floating IP shape, and the documentation ranges the
	// fixtures use: routable-class unicast, nothing that shadows a host
	// route.
	for _, in := range []string{"203.0.113.5", "5.75.129.4", "2a01:4f8:1c1c:abcd::1"} {
		got, err := BindableAddress(net.ParseIP(in))
		if err != nil {
			t.Fatalf("BindableAddress(%s): %v", in, err)
		}
		if !got.Equal(net.ParseIP(in)) {
			t.Errorf("BindableAddress(%s) = %s", in, got)
		}
	}
	// Canonicalisation: the mapped spelling of a public v4 address comes
	// back as a dotted quad, so the wire always carries one shape.
	got, err := BindableAddress(net.ParseIP("::ffff:203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "203.0.113.5" {
		t.Errorf("mapped address rendered as %q, want 203.0.113.5", got.String())
	}
}

// TestBindableAddress_AgreesWithTheBoxValidator pins the reconciliation
// between this function and cmd/daal-relay-mgmt's validateBindAddress.
//
// The two ran with different tables when they first landed: the box also
// refused the four documentation ranges, so a bind of a documentation
// address passed here and came back 400 from the box — a refusal AFTER
// the reserve, the attach and an open firewall window, and a seam that
// could not be exercised end to end at all. They were made to agree in
// both directions: the box relaxed onto the documentation ranges (they
// shadow nothing and are the only addresses a reachability test can dial
// while being certain nobody answers), and this table tightened onto
// 192.88.99.0/24 (6to4 relay anycast has real routing meaning).
//
// The two modules share no symbol, so nothing but a test on each side
// can hold this. Changing one table without the other reintroduces a
// mid-swap refusal.
func TestBindableAddress_AgreesWithTheBoxValidator(t *testing.T) {
	// Refused by BOTH ends.
	for _, in := range []string{
		"192.88.99.1", // deprecated 6to4 relay anycast
		"192.0.0.1",   // IETF protocol assignments
		"198.18.0.1",  // benchmarking
		"2002::1",     // 6to4
	} {
		if _, err := BindableAddress(net.ParseIP(in)); err == nil {
			t.Errorf("BindableAddress(%s) accepted an address the box refuses", in)
		}
	}
	// Accepted by BOTH ends.
	for _, in := range []string{
		"192.0.2.5", "198.51.100.7", "203.0.113.5", "2001:db8::1",
	} {
		if _, err := BindableAddress(net.ParseIP(in)); err != nil {
			t.Errorf("BindableAddress(%s) refused an address the box accepts: %v", in, err)
		}
	}
}

// --- the wire ------------------------------------------------------

func TestBindAddress_SendsACanonicalLiteralAndNothingElse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var body string
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/bind-address": func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
			_ = json.NewEncoder(w).Encode(BindAddressResp{
				IP: "203.0.113.5", Interface: "eth0", Persisted: true,
				BoundAddresses: []string{"198.51.100.7", "203.0.113.5"},
			})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, err := NewClient(rec)
	if err != nil {
		t.Fatal(err)
	}
	// The caller hands the long spelling; the box must receive the
	// canonical one. Nothing a caller composed reaches the wire: the
	// parameter is parsed bytes and the body is re-rendered from them,
	// which is what makes a shell-out on the far side injection-proof.
	resp, err := cli.BindAddress(context.Background(), rec, priv, net.ParseIP("::ffff:203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(body) != `{"ip":"203.0.113.5"}` {
		t.Errorf("request body = %s, want a single canonical address literal", body)
	}
	if resp.Interface != "eth0" || !resp.Persisted {
		t.Errorf("the box's answer was dropped on the floor: %+v", resp)
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("a persisted bind needs no warning: %v", resp.Warnings)
	}
}

// A box that answers 200 about a DIFFERENT address did not do what was
// asked, and the caller is about to re-sign every pack on the strength
// of this answer.
func TestBindAddress_RefusesAnAnswerAboutAnotherAddress(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/bind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(BindAddressResp{IP: "198.51.100.99", Persisted: true})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	_, err := cli.BindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5"))
	if err == nil || !strings.Contains(err.Error(), "answered for") {
		t.Fatalf("err = %v, want a refusal naming the mismatch", err)
	}
}

// The quantity bound. The box is the enforcement point; this is what
// makes a box that forgets to enforce produce a visible failure instead
// of a slowly filling interface.
func TestBindAddress_RefusesWhenTheRelayHoldsTooManyAddresses(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	many := make([]string, MaxBoundAddresses+1)
	for i := range many {
		many[i] = net.IPv4(203, 0, 113, byte(i+1)).String()
	}
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/bind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(BindAddressResp{IP: "203.0.113.5", Persisted: true, BoundAddresses: many})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	_, err := cli.BindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5"))
	if !errors.Is(err, ErrTooManyBoundAddresses) {
		t.Fatalf("err = %v, want ErrTooManyBoundAddresses", err)
	}
}

// A bind that works now and dies on the next reboot is a latent outage,
// because by then every pack names the address. It is a loud warning
// rather than a refusal: refusing would abort the swap and leave the
// relay on the address the operator is escaping.
func TestBindAddress_WarnsLoudlyWhenTheBindIsNotPersisted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/bind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(BindAddressResp{IP: "203.0.113.5", Persisted: false})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	resp, err := cli.BindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5"))
	if err != nil {
		t.Fatalf("a non-persisted bind must not fail the swap: %v", err)
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "reboot") {
		t.Errorf("warnings = %v, want the reboot warning first", resp.Warnings)
	}
}

// --- the orchestration ---------------------------------------------

// The whole ordering problem in one assertion: the request that brings
// an address up cannot be delivered over the address it is bringing up,
// so the client dials the address the relay still answers on while the
// body names the new one.
func TestBindAddressWithFW_DialsTheWorkingAddressAndBindsTheNewOne(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawIP string
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/bind-address": func(w http.ResponseWriter, r *http.Request) {
			var req bindAddressReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			sawIP = req.IP
			_ = json.NewEncoder(w).Encode(BindAddressResp{IP: req.IP, Persisted: true})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	working := append(net.IP(nil), rec.PublicIP...)
	// The record has already been moved onto the new address by the
	// provider adapter, exactly as it is when the assign flow calls this.
	rec.PublicIP = net.ParseIP("203.0.113.5")

	prov := &stubProvider{}
	resp, err := BindAddressWithFW(context.Background(), prov, rec, priv, "1.2.3.4", working, rec.PublicIP)
	if err != nil {
		t.Fatalf("BindAddressWithFW: %v", err)
	}
	if sawIP != "203.0.113.5" {
		t.Errorf("box was asked to bind %q, want the new address", sawIP)
	}
	if resp.IP != "203.0.113.5" {
		t.Errorf("resp.IP = %q", resp.IP)
	}
	assertWindowBalanced(t, prov, 1)
}

// An older box has no bind endpoint, and the refusal must name the
// remediation the operator can act on rather than a raw Go sentence.
func TestBindAddressWithFW_RefusesARelayThatCannotBind(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tripped := false
	mux := legacyBox(t, &tripped)
	mux.HandleFunc("/bind-address", func(w http.ResponseWriter, r *http.Request) {
		tripped = true
		http.Error(w, "no such thing", 404)
	})
	_ = pub
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	working := append(net.IP(nil), rec.PublicIP...)
	rec.PublicIP = net.ParseIP("203.0.113.5")

	prov := &stubProvider{}
	_, err := BindAddressWithFW(context.Background(), prov, rec, priv, "1.2.3.4", working, rec.PublicIP)
	if !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err = %v, want ErrCapabilityUnsupported", err)
	}
	if tripped {
		t.Error("the publisher sent a bind to a box it had not confirmed could handle one")
	}
	for _, want := range []string{"interface", "Re-release daal-relay-mgmt", "reprovision"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	assertWindowBalanced(t, prov, 1)
}

// A refusal must not leave a firewall rule behind it: validation runs
// before the window is opened.
func TestBindAddressWithFW_RefusesABadAddressBeforeOpeningAnything(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, strings.Repeat("ab", 32), 8443)
	prov := &stubProvider{}
	_, err := BindAddressWithFW(context.Background(), prov, rec, priv, "1.2.3.4",
		net.ParseIP("198.51.100.7"), net.ParseIP("169.254.169.254"))
	if !errors.Is(err, ErrAddressNotBindable) {
		t.Fatalf("err = %v, want ErrAddressNotBindable", err)
	}
	if prov.setCalls != 0 {
		t.Errorf("a refused request opened %d firewall windows, want 0", prov.setCalls)
	}
}

// The unbind must not cut the ground out from under itself: reaching the
// relay ON the address being removed would drop the connection that is
// removing it, and leave nobody able to say whether it worked.
func TestUnbindAddressWithFW_RefusesToTravelOverTheAddressItRemoves(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, strings.Repeat("ab", 32), 8443)
	prov := &stubProvider{}
	addr := net.ParseIP("203.0.113.5")
	_, err := UnbindAddressWithFW(context.Background(), prov, rec, priv, "1.2.3.4", addr, addr)
	if err == nil || !strings.Contains(err.Error(), "detach the address at the provider first") {
		t.Fatalf("err = %v, want the ordering refusal", err)
	}
	if prov.setCalls != 0 {
		t.Errorf("a refused request opened %d firewall windows, want 0", prov.setCalls)
	}
}

func TestUnbindAddressWithFW_RemovesTheAddressAndItsPersistence(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sawIP string
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/unbind-address": func(w http.ResponseWriter, r *http.Request) {
			var req bindAddressReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			sawIP = req.IP
			_ = json.NewEncoder(w).Encode(UnbindAddressResp{
				IP: req.IP, WasBound: true, Removed: true, PersistenceRemoved: true,
			})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	prov := &stubProvider{}
	resp, err := UnbindAddressWithFW(context.Background(), prov, rec, priv, "1.2.3.4",
		rec.PublicIP, net.ParseIP("203.0.113.5"))
	if err != nil {
		t.Fatalf("UnbindAddressWithFW: %v", err)
	}
	if sawIP != "203.0.113.5" {
		t.Errorf("box was asked to drop %q", sawIP)
	}
	if !resp.Removed || len(resp.Warnings) != 0 {
		t.Errorf("clean unbind reported as %+v", resp)
	}
	assertWindowBalanced(t, prov, 1)
}

// An address removed from the live interface but left in the persisted
// config comes back on the next reboot — on an address this relay no
// longer owns.
func TestUnbindAddress_WarnsWhenThePersistenceSurvives(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/unbind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(UnbindAddressResp{
				IP: "203.0.113.5", WasBound: true, Removed: true, PersistenceRemoved: false,
			})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	resp, err := cli.UnbindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "reboot") {
		t.Errorf("warnings = %v, want the reboot warning", resp.Warnings)
	}
}

// "Still configured" reported inside a 200 is a failure, not a success
// with a note.
func TestUnbindAddress_TreatsAStillBoundAddressAsAFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/unbind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(UnbindAddressResp{IP: "203.0.113.5", WasBound: true, Removed: false})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	if _, err := cli.UnbindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5")); err == nil {
		t.Fatal("a 200 that says the address is still configured must not read as success")
	}
}

// THE 200 THAT IS NOT A SUCCESS, and the one this package used to let
// through.
//
// The box refuses to remove an address it did not bind — that gate is
// what makes it impossible to delete the relay's own primary address
// over the network — so a live-but-foreign address comes back as
// was_bound=false, removed=false: byte for byte the shape of the
// ordinary "nothing to remove" no-op, with the difference stated only
// in a warning string. Every caller took the `_, err :=` form and threw
// the struct away, and `floating-ip release` then handed the address
// back to the provider's pool while the relay was still answering on
// it. It has to be an error here, where no caller can drop it.
func TestUnbindAddress_TreatsAForeignLiveAddressAsAFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/unbind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(UnbindAddressResp{
				IP: "203.0.113.5", WasBound: false, Removed: false,
				PersistenceRemoved: true, StillConfigured: true,
				Warnings: []string{"203.0.113.5 is configured on eth0 but was not bound by this service"},
			})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	_, err := cli.UnbindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5"))
	if err == nil {
		t.Fatal("a 200 reporting the address is STILL on the interface read as a clean unbind; the caller releases it next")
	}
	if !strings.Contains(err.Error(), "still configured") {
		t.Errorf("the error does not name the state: %v", err)
	}
}

// The ordinary no-op must stay a no-op: the box does not hold the
// address, still_configured is false, and refusing here would strand
// every retried release.
func TestUnbindAddress_TheNoOpStaysASuccess(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := bindingBox(t, pub, map[string]http.HandlerFunc{
		"/unbind-address": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(UnbindAddressResp{
				IP: "203.0.113.5", WasBound: false, Removed: false, PersistenceRemoved: true,
			})
		},
	})
	rec, closeFn := mkLiveRec(t, mux)
	defer closeFn()
	cli, _ := NewClient(rec)
	if _, err := cli.UnbindAddress(context.Background(), rec, priv, net.ParseIP("203.0.113.5")); err != nil {
		t.Fatalf("the idempotent no-op must not be an error: %v", err)
	}
}

// --- capability detection ------------------------------------------

func TestBoxCapabilities_BindAddressFallsOutOfTheWireFormat(t *testing.T) {
	// An old box's `{"ok":true}`.
	old := &BoxCapabilities{OK: true}
	if old.Has(CapBindAddress) {
		t.Error("a box that advertises nothing must not read as capable")
	}
	// THE TOKEN IS THE ONLY SIGNAL, unlike every other capability here.
	// Address binding needs CAP_NET_ADMIN, which the box's systemd unit
	// may not grant, so a relay can be running the right binary and
	// still be unable to configure an address. A version fallback would
	// assert a capability that does not exist and move the failure into
	// the middle of a swap.
	byVersion := &BoxCapabilities{OK: true, MgmtAPIVersion: MgmtAPIVersionAddressBinding}
	if byVersion.Has(CapBindAddress) {
		t.Error("a version number must NOT imply address binding: the capability depends on the box's runtime privileges, not on which binary it runs")
	}
	v2 := &BoxCapabilities{OK: true, MgmtAPIVersion: MgmtAPIVersionSplitRotation}
	if v2.Has(CapBindAddress) {
		t.Error("a v2 box cannot bind addresses")
	}
	if !v2.Has(CapRotateTLSScoped) {
		t.Error("v2 still implies the split-rotation verbs")
	}
	// The token alone is sufficient too.
	byToken := &BoxCapabilities{OK: true, Capabilities: []string{CapBindAddress}}
	if !byToken.Has(CapBindAddress) {
		t.Error("an explicit token must be honoured")
	}
}

func TestMintToken_KnowsTheAddressVerbs(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, op := range []string{"bind-address", "unbind-address"} {
		tok, err := MintToken(priv, op, time.Now())
		if err != nil {
			t.Fatalf("MintToken(%s): %v", op, err)
		}
		if _, _, gotOp, _, err := ParseToken(tok); err != nil || gotOp != op {
			t.Errorf("token op = %q (%v), want %q", gotOp, err, op)
		}
	}
}

// The box distinguishes "binary too old" from "binary fine, launched
// without CAP_NET_ADMIN" in capability_notes, and those have different
// fixes. A struct in the middle that drops the field turns a precise
// diagnosis into a generic one — the same silent-drop that made
// cover_sni inert on the provision path.
func TestUnsupportedCapabilityError_QuotesTheRelaysOwnDiagnosis(t *testing.T) {
	caps := &BoxCapabilities{
		OK:              true,
		MgmtAPIVersion:  MgmtAPIVersionSplitRotation,
		Capabilities:    []string{CapRotateCredentialsScoped, CapRotateTLSScoped},
		CapabilityNotes: []string{"address binding unavailable: CAP_NET_ADMIN not in this unit's bounding set"},
	}
	err := UnsupportedCapabilityError(caps, CapBindAddress)
	if !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "CAP_NET_ADMIN") {
		t.Errorf("the relay's own diagnosis was dropped: %v", err)
	}
	if !strings.Contains(err.Error(), "Re-release daal-relay-mgmt") {
		t.Errorf("the generic remediation is missing: %v", err)
	}
}

// The whole advertisement decodes, including the field the box added
// after this struct was written.
func TestBoxCapabilities_DecodesCapabilityNotes(t *testing.T) {
	var got BoxCapabilities
	body := `{"ok":true,"mgmt_api_version":2,"capabilities":["rotate-tls-scoped"],` +
		`"capability_notes":["address binding unavailable: no CAP_NET_ADMIN"]}`
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.CapabilityNotes) != 1 {
		t.Fatalf("capability_notes = %v — a value the box sends and the publisher needs must be declared on the struct in the middle", got.CapabilityNotes)
	}
}
