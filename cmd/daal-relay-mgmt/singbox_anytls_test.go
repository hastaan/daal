package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// baseDocForAnyTLS is the minimal live config shape addUserToSingbox
// works against: a vless-in inbound is always present on a real box.
func baseDocForAnyTLS() map[string]any {
	return map[string]any{
		"inbounds": []any{
			map[string]any{
				"type": "vless", "tag": tagVLESS, "listen_port": 443,
				"users": []any{},
				"tls": map[string]any{
					"enabled": true, "server_name": "cdn.example-host.net",
					"reality": map[string]any{"enabled": true, "short_id": []any{}},
				},
			},
		},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}
}

func mustMint(t *testing.T, name string) userCreds {
	t.Helper()
	c, err := mintCreds(name, 1750000000)
	if err != nil {
		t.Fatalf("mintCreds(%s): %v", name, err)
	}
	return c
}

func anytlsInbound(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	in := findInboundByTag(doc, tagAnyTLS)
	if in == nil {
		t.Fatal("no anytls-in inbound")
	}
	return in
}

// TestAnyTLSPerRecipientCredentialsAreDistinct is the credential half of
// "per-recipient", and it is the property that makes a single recipient
// revocable. If two recipients shared a password, revoking one would
// either revoke both or revoke neither, and a leaked pack would be
// indistinguishable from any other.
func TestAnyTLSPerRecipientCredentialsAreDistinct(t *testing.T) {
	doc := baseDocForAnyTLS()
	seen := map[string]string{}
	for _, name := range []string{"r1", "r2", "r3", "r4"} {
		c := mustMint(t, name)
		if c.AnyTLSPassword == "" {
			t.Fatalf("%s: mintCreds produced no anytls password", name)
		}
		if prev, dup := seen[c.AnyTLSPassword]; dup {
			t.Fatalf("%s and %s were minted the same anytls password", name, prev)
		}
		seen[c.AnyTLSPassword] = name
		if err := appendAnyTLSUser(doc, c); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}
	users, _ := anytlsInbound(t, doc)["users"].([]any)
	if len(users) != 4 {
		t.Fatalf("users = %d, want 4 (one shared inbound, one row per recipient)", len(users))
	}
	// And the rows on the box carry those same distinct passwords.
	onBox := map[string]bool{}
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		pw, _ := u["password"].(string)
		if onBox[pw] {
			t.Fatal("two rows in anytls-in share a password")
		}
		onBox[pw] = true
	}
}

// TestAnyTLSInboundIsIdempotentAndDropsWithLastUser mirrors the naive-in
// lifecycle: created with its first user, never left empty.
func TestAnyTLSInboundIsIdempotentAndDropsWithLastUser(t *testing.T) {
	doc := baseDocForAnyTLS()
	c := mustMint(t, "r1")
	for i := 0; i < 3; i++ {
		if err := appendAnyTLSUser(doc, c); err != nil {
			t.Fatalf("append #%d: %v", i, err)
		}
	}
	users, _ := anytlsInbound(t, doc)["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("re-provisioning the same name produced %d rows, want 1", len(users))
	}
	if !removeAnyTLSUser(doc, "r1") {
		t.Fatal("remove reported nothing removed")
	}
	if findInboundByTag(doc, tagAnyTLS) != nil {
		t.Fatal("anytls-in survived its last user; an inbound nobody can authenticate to only serves probes")
	}
	if removeAnyTLSUser(doc, "r1") {
		t.Fatal("removing a second time reported a removal")
	}
}

// TestAnyTLSMissingPasswordSkipsFamilyWithoutFailingProvision pins the
// fail-soft-on-box half of the interlock.
//
// addUserToSingbox is all-or-nothing across every inbound, so an error
// here would cost the recipient vless-reality, hysteria2, naive, ws and
// shadowsocks over one absent anytls credential. The family goes
// missing; the recipient does not. The publisher then sees an empty
// password and declines to mint the route — that is where it fails
// closed.
func TestAnyTLSMissingPasswordSkipsFamilyWithoutFailingProvision(t *testing.T) {
	doc := baseDocForAnyTLS()
	c := mustMint(t, "r1")
	c.AnyTLSPassword = ""
	if err := appendAnyTLSUser(doc, c); err != nil {
		t.Fatalf("a missing anytls password must not fail the whole provision: %v", err)
	}
	if findInboundByTag(doc, tagAnyTLS) != nil {
		t.Fatal("an anytls inbound was created with no credential")
	}
}

// TestAnyTLSInboundShape checks the inbound against
// option.AnyTLSInboundOptions, whose fields are:
//
//	Users         []AnyTLSUser               `json:"users,omitempty"`
//	PaddingScheme badoption.Listable[string] `json:"padding_scheme,omitempty"`
//
// plus ListenOptions and InboundTLSOptionsContainer. A `multiplex` key
// would be a fatal `json: unknown field` at boot — i.e. a relay that
// does not come up — which is why the renderer must never add one.
func TestAnyTLSInboundShape(t *testing.T) {
	doc := baseDocForAnyTLS()
	if err := appendAnyTLSUser(doc, mustMint(t, "r1")); err != nil {
		t.Fatal(err)
	}
	in := anytlsInbound(t, doc)
	if in["type"] != "anytls" {
		t.Errorf("type = %v", in["type"])
	}
	if in["listen_port"] != anytlsListenPort {
		t.Errorf("listen_port = %v, want %d (must equal relayports.For(\"anytls\").Port)",
			in["listen_port"], anytlsListenPort)
	}
	if _, bad := in["multiplex"]; bad {
		t.Error("anytls inbound carries multiplex; sing-box has no such field and would FATAL at boot")
	}
	tls, _ := in["tls"].(map[string]any)
	if tls == nil || tls["certificate_path"] != tlsCertPath || tls["key_path"] != tlsKeyPath {
		t.Errorf("anytls inbound must serve the box data-plane leaf, got %v", in["tls"])
	}
	// padding_scheme must be an ARRAY of lines. A single newline-joined
	// string also decodes (Listable accepts a bare string) but as ONE
	// line, which then fails to parse into a scheme and takes the relay
	// down at boot.
	if _, ok := in["padding_scheme"].([]string); !ok {
		t.Fatalf("padding_scheme must be a []string of lines, got %T", in["padding_scheme"])
	}
	// It must survive a JSON round trip as an array, since that is how
	// it reaches sing-box.
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["padding_scheme"].([]any); !ok {
		t.Errorf("padding_scheme did not round-trip as a JSON array: %T", back["padding_scheme"])
	}
}

// TestPaddingSchemeIsValidAndPerRelay is the load-bearing test for the
// padding choice.
//
// Validity first, because the failure is severe: sing-anytls'
// NewPaddingFactory returns nil for a scheme whose `stop` does not parse,
// and a nil factory is a FATAL at sing-box start — a relay that never
// comes up. Then per-relay-ness, because a scheme every Daal relay
// shares would only trade the library's global constant for a fleet-wide
// one, which is exactly the failure the Wave-2 cover-SNI work removed on
// the SNI axis.
func TestPaddingSchemeIsValidAndPerRelay(t *testing.T) {
	const runs = 24
	seen := map[string]bool{}
	for i := 0; i < runs; i++ {
		lines, err := generatePaddingScheme()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		scheme := strings.Join(lines, "\n")
		seen[scheme] = true

		// Parse it the way sing-anytls/padding.NewPaddingFactory does.
		kv := map[string]string{}
		for _, ln := range lines {
			k, v, ok := strings.Cut(ln, "=")
			if !ok {
				t.Fatalf("line %q is not key=value", ln)
			}
			if _, dup := kv[k]; dup {
				t.Fatalf("duplicate key %q: a map cannot hold both and one silently wins", k)
			}
			kv[k] = v
		}
		stopRaw, ok := kv["stop"]
		if !ok {
			t.Fatal("no stop= line; NewPaddingFactory returns nil and the relay FATALs at boot")
		}
		stop, err := strconv.Atoi(stopRaw)
		if err != nil {
			t.Fatalf("stop=%q does not parse as an int; the relay FATALs at boot", stopRaw)
		}
		if stop < paddingSchemeStopMin || stop > paddingSchemeStopMax {
			t.Fatalf("stop=%d outside [%d,%d]", stop, paddingSchemeStopMin, paddingSchemeStopMax)
		}
		// Every packet index below stop must be present, and every range
		// must satisfy what GenerateRecordPayloadSizes needs: min<=max
		// and both > 0 (a non-positive bound is skipped, silently
		// yielding no padding for that packet).
		for i := 0; i < stop; i++ {
			v, ok := kv[strconv.Itoa(i)]
			if !ok {
				t.Fatalf("no entry for packet %d (< stop=%d): that packet gets no padding", i, stop)
			}
			for _, seg := range strings.Split(v, ",") {
				if seg == "c" {
					continue
				}
				lo, hi, ok := strings.Cut(seg, "-")
				if !ok {
					t.Fatalf("segment %q in %q is neither a range nor a check mark", seg, v)
				}
				loN, err1 := strconv.Atoi(lo)
				hiN, err2 := strconv.Atoi(hi)
				if err1 != nil || err2 != nil {
					t.Fatalf("segment %q does not parse", seg)
				}
				if loN <= 0 || hiN <= 0 {
					t.Fatalf("segment %q has a non-positive bound; the padder skips it", seg)
				}
				if loN > hiN {
					t.Fatalf("segment %q has min > max", seg)
				}
			}
		}
		// A "c" check mark only means anything between two ranges.
		if strings.HasPrefix(kv["2"], "c,") || strings.HasSuffix(kv["2"], ",c") {
			t.Fatalf("packet 2 scheme %q has a dangling check mark", kv["2"])
		}
	}

	// PER-RELAY. Not a strict inequality on every pair — that would be a
	// flaky assertion about randomness — but 24 independent relays
	// producing fewer than 20 distinct schemes would mean the generator
	// is effectively a constant, which is the thing this must not be.
	if len(seen) < 20 {
		t.Fatalf("only %d distinct schemes in %d relays: the scheme is close to a fleet-wide constant, "+
			"which is exactly what a per-relay scheme exists to avoid", len(seen), runs)
	}

	// And it must never BE the sing-anytls default, whose md5 every
	// unconfigured anytls deployment on earth shares — the first thing
	// an analyst characterises.
	defaultScheme := "stop=8\n0=30-30\n1=100-400\n" +
		"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n" +
		"3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
	if seen[defaultScheme] {
		t.Fatal("generated the library default padding scheme")
	}
}

// TestReadAnyTLSPasswordReflectsDiskNotIntent pins the direction of the
// publisher's only signal that this relay serves the family.
//
// The provision handler overwrites the minted password with whatever is
// actually in the live config, so "the box did not report one" always
// means "there is no inbound row here", never "the write was attempted".
// An inferred value would make the interlock lie.
func TestReadAnyTLSPasswordReflectsDiskNotIntent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	doc := baseDocForAnyTLS()
	c := mustMint(t, "r1")

	// No anytls inbound on disk yet => empty, regardless of what was minted.
	writeDoc(t, path, doc)
	if got := readAnyTLSPassword(path, "r1"); got != "" {
		t.Fatalf("password reported for a box with no anytls-in: %q", got)
	}

	if err := appendAnyTLSUser(doc, c); err != nil {
		t.Fatal(err)
	}
	writeDoc(t, path, doc)
	if got := readAnyTLSPassword(path, "r1"); got != c.AnyTLSPassword {
		t.Fatalf("password = %q, want the row actually on disk (%q)", got, c.AnyTLSPassword)
	}
	// A name that was never provisioned reads empty rather than
	// borrowing another recipient's row.
	if got := readAnyTLSPassword(path, "r99"); got != "" {
		t.Fatalf("unprovisioned name got a password: %q", got)
	}
}

func writeDoc(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	if err := writeSingboxDoc(path, doc, nil); err != nil {
		t.Fatal(err)
	}
}
