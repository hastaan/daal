package relaypack

import (
	"bytes"
	"testing"

	"daal/bundle-go/bundle"
)

// The carriers member rides beside the secret, outside the manifest; a
// reused input never carries it into another file.
func TestRewrite_WritesTheCarriersOutsideTheManifest(t *testing.T) {
	in := buildStubPack(t, []string{"vless-reality", "hysteria2"})
	sec := &bundle.UpdateSecret{Audience: bundle.AudiencePeople,
		Secret: bundle.DeriveUpdateSecret([]byte("root"), "rp-1", bundle.AudiencePeople)}
	car := &bundle.UpdateCarriers{GitTag: &bundle.GitTagCarrier{Owner: "quiet-owner", Repo: "notes"},
		DNS: &bundle.DNSCarrier{Zone: "n.example.org"}}
	out, _, err := RewriteProfilesForRecipientWithMembers(in, fullParams(), sec, car)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bundle.ReadUpdateCarriers(out)
	if err != nil || *got.GitTag != *car.GitTag || *got.DNS != *car.DNS {
		t.Fatalf("member: %v", err)
	}
	if _, err := bundle.ReadUpdateSecret(out); err != nil {
		t.Fatalf("secret: %v", err)
	}
	b, err := bundle.ParseSBP(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundle(b); err != nil {
		t.Fatalf("the signature no longer verifies: %v", err)
	}
	manifest, _ := bundle.CanonicalManifestJSON(b.Manifest)
	if bytes.Contains(manifest, []byte("quiet-owner")) || bytes.Contains(manifest, []byte("n.example.org")) {
		t.Fatal("the carriers are in the signed manifest")
	}
	again, _, err := RewriteProfilesForRecipientWithSecret(out, fullParams(), sec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ReadUpdateCarriers(again); err != bundle.ErrNoUpdateCarriers {
		t.Fatalf("carriers rode through a reused input: %v", err)
	}
	if _, _, err := RewriteProfilesForRecipientWithMembers(in, fullParams(), sec,
		&bundle.UpdateCarriers{DNS: &bundle.DNSCarrier{Zone: "bad zone"}}); err == nil {
		t.Fatal("a bad member was written")
	}
}
