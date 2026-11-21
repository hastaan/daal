package relaypackvalidate

import (
	"encoding/base64"
	"errors"
	"testing"

	"daal/bundle-go/bundle"
)

func signingCDN() bundle.CDNEndpoint {
	return bundle.CDNEndpoint{
		V: 1, Server: "e.example.com", Port: 443, ServerName: "e.example.com", CDN: bundle.CDNCloudflare,
		EdgeSeeds:      []string{"104.16.0.0/13"},
		ECHConfig:      base64.StdEncoding.EncodeToString([]byte{0, 2, 1, 2}),
		TLSRootsSHA256: []string{base64.StdEncoding.EncodeToString(make([]byte, 32))},
	}
}

func signingDirectEP(server string) bundle.Endpoint {
	return bundle.Endpoint{V: 1, Server: server, Port: 443, ServerName: "cover.example", RealityPublicKey: "k"}
}

var signingKey = func() bundle.StandbyKeyBytes {
	var k bundle.StandbyKeyBytes
	copy(k[12:], []byte{203, 0, 113, 20})
	return k
}()

func signingPack(t *testing.T, cdnExtras, r1Extras, r2Extras map[string]any) *bundle.Bundle {
	t.Helper()
	return bundleWith([]bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), r1Extras)},
		{ID: "r2", TransportFamily: "vless-reality", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), r2Extras)},
		{ID: "r3", TransportFamily: "websocket-tls", FamilySpecificConfig: packEntry(t, minimalCDN(), cdnExtras)},
	}, &bundle.RelayPack{RelayPackID: "rp-test"})
}

func expectSigning(t *testing.T, b *bundle.Bundle, want Code) {
	t.Helper()
	err := ValidateForSigning(b)
	if want == "" {
		if err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
		return
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Code != want {
		t.Fatalf("expected %s, got %v", want, err)
	}
}

func TestValidateForSigning(t *testing.T) {
	sb := bundle.SealedStandby(signingKey)
	direct := func(extra map[string]any) map[string]any {
		m := map[string]any{bundle.EndpointKey: signingDirectEP("198.51.100.10")}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	withSB := direct(map[string]any{bundle.StandbyKey: sb})
	good := signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN()}, withSB, withSB)
	expectSigning(t, good, "")
	// The recipient-side validator is unaffected by these members.
	expectOK(t, good, ValidateOpts{Phase: PhaseV16})

	noECH := signingCDN()
	noECH.ECHConfig = ""
	plain := noECH
	plain.PlainFallback = true
	future := map[string]any{"v": 2}
	cases := map[string]struct {
		b    *bundle.Bundle
		want Code
	}{
		"no _cdn_endpoint":       {signingPack(t, nil, direct(nil), direct(nil)), CodeRP026},
		"cdn beside _endpoint":   {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN(), bundle.EndpointKey: signingDirectEP("5.75.0.1")}, direct(nil), direct(nil)), CodeRP026},
		"cdn on a direct route":  {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN()}, direct(map[string]any{bundle.CDNEndpointKey: signingCDN()}), direct(nil)), CodeRP026},
		"never dialable":         {signingPack(t, map[string]any{bundle.CDNEndpointKey: noECH}, direct(nil), direct(nil)), CodeRP026},
		"plain allowed is fine":  {signingPack(t, map[string]any{bundle.CDNEndpointKey: plain}, direct(nil), direct(nil)), ""},
		"future cdn shape":       {signingPack(t, map[string]any{bundle.CDNEndpointKey: future}, direct(nil), direct(nil)), CodeRP026},
		"malformed standby":      {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN()}, direct(map[string]any{bundle.StandbyKey: map[string]any{"v": 1}}), direct(nil)), CodeRP027},
		"standby, no _endpoint":  {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN(), bundle.StandbyKey: sb}, withSB, withSB), CodeRP027},
		"standby differs":        {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN()}, withSB, direct(map[string]any{bundle.StandbyKey: bundle.OpenStandby("203.0.113.20")})), CodeRP027},
		"one route lacks it":     {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN()}, withSB, direct(nil)), CodeRP027},
		"open = endpoint server": {signingPack(t, map[string]any{bundle.CDNEndpointKey: signingCDN()}, direct(map[string]any{bundle.StandbyKey: bundle.OpenStandby("198.51.100.10")}), direct(map[string]any{bundle.StandbyKey: bundle.OpenStandby("198.51.100.10")})), CodeRP027},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { expectSigning(t, c.b, c.want) })
	}
	// Shadowsocks never carries one.
	ss := bundleWith([]bundle.RouteManifestEntry{
		{ID: "r1", TransportFamily: "shadowsocks", FamilySpecificConfig: packEntry(t, minimalDirectVPS(), map[string]any{
			bundle.EndpointKey: bundle.Endpoint{V: 1, Server: "198.51.100.10", Port: 8388, SSMethod: "2022-blake3-aes-128-gcm",
				SSServerKeySHA256: bundle.SSServerKeyDigest("k")},
			bundle.StandbyKey: sb})},
	}, &bundle.RelayPack{RelayPackID: "rp-test"})
	expectSigning(t, ss, CodeRP027)
	// A future shape on a recipient: Validate still accepts the pack.
	expectOK(t, signingPack(t, map[string]any{bundle.CDNEndpointKey: future}, direct(map[string]any{bundle.StandbyKey: future}), direct(nil)), ValidateOpts{Phase: PhaseV16})
}
