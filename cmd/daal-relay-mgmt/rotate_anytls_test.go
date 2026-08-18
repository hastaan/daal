package main

import (
	"reflect"
	"testing"
)

// WAVE-5 REPAIR REGRESSION.
//
// rotateRecipientCreds had a `case` for every family the box serves
// EXCEPT anytls, while `res := &credRotation{Creds: fresh}` echoed the
// whole freshly minted credential set. The result was the worst
// possible combination: the publisher was handed an anytls password the
// box had never stored (so the route died on the first dial after any
// rotation), and the SEIZED password was never retired (so the thing
// the rotation existed to revoke stayed live on 8447 forever).
//
// Two assertions, because either alone passes with half the bug.
func TestRotateCreds_AnyTLSRowIsRotatedAndEchoedTruthfully(t *testing.T) {
	orig, err := mintCreds("r1", 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"inbounds": []any{
		map[string]any{
			"type": "vless", "tag": tagVLESS, "listen_port": 443,
			"users": []any{map[string]any{"uuid": orig.VLESSUUID, "name": "r1"}},
		},
	}}
	if err := appendAnyTLSUser(doc, orig); err != nil {
		t.Fatal(err)
	}
	if orig.AnyTLSPassword == "" {
		t.Fatal("mintCreds produced no anytls password; the rest of this test proves nothing")
	}

	fresh, err := mintCreds("r1", 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rotateRecipientCreds(doc, "r1", fresh)
	if err != nil {
		t.Fatal(err)
	}

	// 1. What the box now authenticates must equal what the publisher
	//    is told. Before the repair these were the FRESH and the
	//    ORIGINAL password respectively.
	in := findInboundByTag(doc, tagAnyTLS)
	u := findUserRow(in, "name", "r1")
	if u == nil {
		t.Fatal("anytls-in lost r1")
	}
	onBox, _ := u["password"].(string)
	if onBox == orig.AnyTLSPassword {
		t.Errorf("anytls password was not rotated on the box: still %q", onBox)
	}
	if res.Creds.AnyTLSPassword != onBox {
		t.Errorf("echoed %q but the box authenticates %q — the publisher would mint a route that cannot connect",
			res.Creds.AnyTLSPassword, onBox)
	}

	// 2. The seized credential must be retired, not merely replaced —
	//    `retire` is what proves it is gone from the whole document.
	if !containsString(res.retired, orig.AnyTLSPassword) {
		t.Errorf("the old anytls password was not retired (retired=%v); a scoped rotation that revokes nothing is not a rotation", res.retired)
	}

	// 3. The caller must be told anytls-in moved, or cli_rotate's
	//    "did not report which inbounds it rewrote" warning cannot fire.
	if !containsString(res.Inbounds, tagAnyTLS) {
		t.Errorf("updated inbounds = %v, missing %q", res.Inbounds, tagAnyTLS)
	}
}

// The other half of the same defect, stated as an invariant rather than
// as one family's test: a rotation must NEVER echo a credential for a
// family whose row it did not actually rewrite. This is what makes the
// publisher's "empty means this relay does not serve it" signal true,
// and it is the assertion that will catch the NEXT field added to
// userCreds without a case in rotateRecipientCreds.
func TestRotateCreds_UnrotatedFamiliesEchoNothing(t *testing.T) {
	orig, err := mintCreds("r1", 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	// A box serving ONLY vless: no ss-in, no anytls-in, no tuic-in.
	doc := map[string]any{"inbounds": []any{
		map[string]any{
			"type": "vless", "tag": tagVLESS, "listen_port": 443,
			"users": []any{map[string]any{"uuid": orig.VLESSUUID, "name": "r1"}},
		},
	}}
	fresh, err := mintCreds("r1", 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rotateRecipientCreds(doc, "r1", fresh)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got string }{
		{"anytls_password", res.Creds.AnyTLSPassword},
		{"ss_password", res.Creds.SSPassword},
		{"ss_method", res.Creds.SSMethod},
		{"tuic_uuid", res.Creds.TUICUUID},
		{"tuic_password", res.Creds.TUICPassword},
	} {
		if c.got != "" {
			t.Errorf("%s = %q on a relay that serves no such inbound; the publisher would mint an undialable route from it", c.name, c.got)
		}
	}
	if want := []string{tagVLESS}; !reflect.DeepEqual(res.Inbounds, want) {
		t.Errorf("updated inbounds = %v, want %v", res.Inbounds, want)
	}
}
