package relaypack

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/provider"
)

// The test vector, computed independently (Python hashlib + a
// hand-written Crockford encoder) so the Go code is not checked against
// itself: salt = 00 01 .. 0b, address 203.0.113.20.
const (
	vecSaltB64 = "AAECAwQFBgcICQoL"
	vecIP      = "203.0.113.20"
	vecCommit  = "oLKATgHpOx6iddfCqnGCuDAi1XSE7ysXDZ1tUmE5HHY="
	vecKey     = "000G40 R40M3 0E209 185WP 03H2G"
)

func vecStandby(mode string) *provider.StandbyAddress {
	return &provider.StandbyAddress{FloatingIPID: "77", IP: net.ParseIP(vecIP), Mode: mode, Salt: vecSaltB64}
}

// The format is bundle's; this pins the publisher's use of it to a
// vector computed outside Go.
func TestStandbyVector(t *testing.T) {
	key, err := standbyKeyOf(vecStandby(provider.StandbySealed))
	if err != nil {
		t.Fatal(err)
	}
	if got := bundle.StandbyCommit(key); got != vecCommit {
		t.Errorf("commit = %s, want %s", got, vecCommit)
	}
	if got := key.Text(); got != vecKey {
		t.Errorf("key = %q, want %q", got, vecKey)
	}
	back, err := bundle.ParseStandbyKeyText(strings.ToLower(strings.ReplaceAll(vecKey, " ", "-")))
	if err != nil || back != key {
		t.Fatalf("parse(%q) = %x, %v", vecKey, back, err)
	}
	if back.Address() != vecIP {
		t.Errorf("address in key = %s", back.Address())
	}
	c, err := StandbyCommitmentFor(vecStandby(provider.StandbySealed), "5.75.0.1")
	if err != nil || !c.Matches(key) {
		t.Fatalf("commitment %+v does not match its own key (%v)", c, err)
	}
}

func TestNewStandbySalt(t *testing.T) {
	a, err := NewStandbySalt()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewStandbySalt()
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(raw) != bundle.StandbySaltLen || a == b {
		t.Fatalf("salt %q / %q: %v", a, b, err)
	}
}

func standbyRec(t *testing.T, sb *provider.StandbyAddress) *provider.OperatorRecord {
	rec := minimalRec(t)
	rec.Candidates = append(rec.Candidates, provider.CandidateMeta{
		Family: "shadowsocks", ExposureMode: "direct_vps",
		FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 8388,
		PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:tcp8388"},
		OriginRiskTags: []string{},
	})
	rec.Standby = sb
	return rec
}

func standbyOpts() BindOpts {
	o := defaultOpts()
	o.Endpoint = &EndpointMaterial{SSMethod: "2022-blake3-aes-128-gcm", SSServerKeySHA256: bundle.SSServerKeyDigest("c2VydmVya2V5c2VydmVya2V5")}
	return o
}

func routesOf(t *testing.T, sbp []byte) []bundle.RouteManifestEntry {
	t.Helper()
	parsed, err := bundle.ParseSBP(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	return parsed.Manifest.Routes
}

// Sealed: every route but shadowsocks carries the same commitment
// inside the signed manifest; no route carries the address.
func TestBindAndSign_SealedStandby(t *testing.T) {
	_, priv := fixedKey(t, 0x42)
	plain, err := BindAndSign(standbyRec(t, nil), priv, standbyOpts())
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	res, err := BindAndSign(standbyRec(t, vecStandby(provider.StandbySealed)), priv, standbyOpts())
	if err != nil {
		t.Fatalf("sealed: %v", err)
	}
	if plain.RelayPackID != res.RelayPackID {
		t.Error("a standby changed the relay pack id")
	}
	carried := 0
	for _, r := range routesOf(t, res.SBPBytes) {
		if bytes.Contains(r.FamilySpecificConfig, []byte(vecIP)) {
			t.Errorf("route %s names the sealed standby address", r.ID)
		}
		var fc map[string]json.RawMessage
		if err := json.Unmarshal(r.FamilySpecificConfig, &fc); err != nil {
			t.Fatal(err)
		}
		raw, has := fc[StandbyKey]
		if r.TransportFamily == string(bundle.TransportShadowsocks) {
			if has {
				t.Errorf("shadowsocks route %s carries _standby", r.ID)
			}
			continue
		}
		if !has {
			t.Errorf("route %s (%s) has no _standby", r.ID, r.TransportFamily)
			continue
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if len(m) != 3 || m["v"] != float64(1) || m["mode"] != "sealed" || m["commit"] != vecCommit {
			t.Errorf("route %s _standby = %s", r.ID, raw)
		}
		// What a recipient reads: the route rules accept it, and the
		// key sent later opens it.
		ep, err := bundle.ParseEndpoint(r.FamilySpecificConfig)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := bundle.StandbyForRoute(r.TransportFamily, r.FamilySpecificConfig, ep)
		if err != nil {
			t.Fatalf("route %s: recipient side refuses the signed _standby: %v", r.ID, err)
		}
		key, _ := bundle.ParseStandbyKeyText(vecKey)
		if addr, ok := sb.DialAddress(&key); !ok || addr != vecIP {
			t.Errorf("route %s: the key opens %q, %v", r.ID, addr, ok)
		}
		carried++
	}
	if carried != 2 {
		t.Errorf("%d routes carry _standby, want 2", carried)
	}
	for _, r := range routesOf(t, plain.SBPBytes) {
		if bytes.Contains(r.FamilySpecificConfig, []byte(StandbyKey)) {
			t.Errorf("plain pack route %s carries _standby", r.ID)
		}
	}
}

func TestBindAndSign_OpenStandby(t *testing.T) {
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(standbyRec(t, vecStandby(provider.StandbyOpen)), priv, standbyOpts())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, r := range routesOf(t, res.SBPBytes) {
		var fc map[string]json.RawMessage
		_ = json.Unmarshal(r.FamilySpecificConfig, &fc)
		raw, has := fc[StandbyKey]
		if r.TransportFamily == string(bundle.TransportShadowsocks) {
			if has {
				t.Errorf("shadowsocks route carries _standby")
			}
			continue
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if len(m) != 3 || m["mode"] != "open" || m["server"] != vecIP {
			t.Errorf("route %s _standby = %s", r.ID, raw)
		}
	}
}

func TestBindAndSign_RefusesAStandbyItCannotSign(t *testing.T) {
	_, priv := fixedKey(t, 0x42)
	for name, sb := range map[string]*provider.StandbyAddress{
		"same as endpoint": {IP: net.ParseIP("5.75.0.1"), Mode: "sealed", Salt: vecSaltB64},
		"private":          {IP: net.ParseIP("10.0.0.5"), Mode: "sealed", Salt: vecSaltB64},
		"ipv6":             {IP: net.ParseIP("2001:db8::1"), Mode: "open", Salt: vecSaltB64},
		"short salt":       {IP: net.ParseIP(vecIP), Mode: "sealed", Salt: "AAEC"},
		"unknown mode":     {IP: net.ParseIP(vecIP), Mode: "loud", Salt: vecSaltB64},
	} {
		if _, err := BindAndSign(standbyRec(t, sb), priv, standbyOpts()); !errors.Is(err, ErrBadStandby) {
			t.Errorf("%s: err = %v, want ErrBadStandby", name, err)
		}
	}
}

func TestStandbyEligibleRecord(t *testing.T) {
	rec := minimalRec(t)
	if !StandbyEligibleRecord(rec) {
		t.Error("a vless-reality relay is eligible")
	}
	rec.Candidates = []provider.CandidateMeta{{Family: "shadowsocks", ExposureMode: "direct_vps"}}
	if StandbyEligibleRecord(rec) {
		t.Error("a shadowsocks-only relay must not be offered a standby")
	}
	rec.Candidates = []provider.CandidateMeta{{Family: "vless-reality", ExposureMode: "cdn_fronted"}}
	if StandbyEligibleRecord(rec) {
		t.Error("a CDN-only relay must not be offered a standby")
	}
}

func TestStandbyKeyText(t *testing.T) {
	got, err := StandbyKeyText(vecStandby(provider.StandbySealed))
	if err != nil || got != vecKey {
		t.Fatalf("StandbyKeyText = %q, %v", got, err)
	}
	if _, err := StandbyKeyText(nil); err == nil {
		t.Error("no standby, no key")
	}
}
