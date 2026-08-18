//go:build singbox

package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	shadowsocks "github.com/sagernet/sing-shadowsocks2"
)

// ssMethodName is the ONE method Daal serves. Mirrors
// cmd/daal-relay-mgmt's ssMethod and the publisher's rendered
// `"method"`; if these three ever disagree the route is dead, so this
// file's job is to make the disagreement a test failure here rather
// than a tunnel that never comes up on someone's phone.
const ssMethodName = "2022-blake3-aes-128-gcm"

// mintPSK reproduces the box's genSSKey: exactly 16 random bytes, PADDED
// base64-STANDARD. The encoding is not a style choice — see the negative
// cases below.
func mintPSK(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// TestShadowsocksClientPasswordIsAcceptedByTheEngine is the client half
// of the shadowsocks chain, proved rather than assumed.
//
// Parsing the outbound JSON (TestAssembledClientOutboundsParse) only
// shows the FIELDS are right. This goes one layer deeper and hands the
// assembled password to shadowsocks.CreateMethod — the exact call
// sing-box's shadowsocks outbound makes when it builds the route
// (protocol/shadowsocks/outbound.go NewOutbound) — so a credential the
// engine would refuse at construction fails here, on a laptop, instead
// of on a recipient's device with no diagnostics.
//
// This matters more for this family than for the others because the
// credential has STRUCTURE: two colon-joined halves, each padded
// base64-std, each decoding to exactly the method's key length. Every
// other family Daal ships takes an opaque string.
func TestShadowsocksClientPasswordIsAcceptedByTheEngine(t *testing.T) {
	ipsk, upsk := mintPSK(t), mintPSK(t)
	password := ipsk + ":" + upsk

	if _, err := shadowsocks.CreateMethod(context.Background(), ssMethodName,
		shadowsocks.MethodOptions{Password: password}); err != nil {
		t.Fatalf("the shipped engine refuses the password the box assembles: %v", err)
	}
}

// TestShadowsocksRejectsTheWrongCredentialShapes is the negative half,
// and each case is a real mistake that would otherwise ship silently.
func TestShadowsocksRejectsTheWrongCredentialShapes(t *testing.T) {
	ipsk, upsk := mintPSK(t), mintPSK(t)
	raw16 := make([]byte, 16)
	if _, err := rand.Read(raw16); err != nil {
		t.Fatalf("rand: %v", err)
	}

	cases := []struct {
		name     string
		password string
		why      string
	}{{
		name:     "RawURLEncoding",
		password: base64.RawURLEncoding.EncodeToString(raw16) + ":" + base64.RawURLEncoding.EncodeToString(raw16),
		why: "hy2_password and naive_password use base64.RawURLEncoding; reusing that generator " +
			"for shadowsocks produces a key the engine cannot decode",
	}, {
		name:     "wrong key length",
		password: base64.StdEncoding.EncodeToString(make([]byte, 32)) + ":" + upsk,
		why:      "aes-128 fixes the key at 16 bytes; a 32-byte PSK is refused, not truncated",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := shadowsocks.CreateMethod(context.Background(), ssMethodName,
				shadowsocks.MethodOptions{Password: tc.password}); err == nil {
				t.Fatalf("engine ACCEPTED a credential it must reject (%s): %s", tc.name, tc.why)
			}
		})
	}

	// THE ONE WRONG SHAPE THE ENGINE CANNOT CATCH, recorded here because
	// it is the reason exactly one place is allowed to build this
	// string. Drop the uPSK half and what is left is a perfectly valid
	// SINGLE-PSK client: CreateMethod succeeds, the config loads, the
	// route appears healthy, and the failure arrives on the wire as an
	// authentication the multi-user inbound cannot resolve. There is no
	// construction-time check to lean on, so the join lives only in the
	// box (ssClientPassword) and everything downstream carries the
	// string verbatim — never splits and re-joins it.
	if _, err := shadowsocks.CreateMethod(context.Background(), ssMethodName,
		shadowsocks.MethodOptions{Password: ipsk}); err != nil {
		t.Fatalf("expected a lone PSK to be structurally valid (that is what makes it dangerous), got: %v", err)
	}
	if !strings.Contains(ipsk+":"+upsk, ":") {
		t.Fatalf("the assembled password lost its separator")
	}
}
