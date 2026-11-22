package relaypack

import (
	"bytes"
	"testing"

	"daal/bundle-go/bundle"
)

// The update secret rides in the per-recipient half: an archive member
// beside the profiles, never in the signed manifest, and the signature
// still verifies.
func TestRewrite_WritesTheUpdateSecretOutsideTheManifest(t *testing.T) {
	in := buildStubPack(t, []string{"vless-reality", "hysteria2"})
	sec := &bundle.UpdateSecret{Audience: bundle.AudiencePeople,
		Secret: bundle.DeriveUpdateSecret([]byte("root"), "rp-1", bundle.AudiencePeople)}
	out, _, err := RewriteProfilesForRecipientWithSecret(in, fullParams(), sec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bundle.ReadUpdateSecret(out)
	if err != nil || *got != *sec {
		t.Fatalf("member: %v", err)
	}
	b, err := bundle.ParseSBP(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundle(b); err != nil {
		t.Fatalf("the signature no longer verifies: %v", err)
	}
	manifest, _ := bundle.CanonicalManifestJSON(b.Manifest)
	member, _ := bundle.MarshalUpdateSecret(*sec)
	secretB64 := member[bytes.Index(member, []byte(`"secret":"`))+10 : len(member)-2]
	if bytes.Contains(manifest, secretB64) {
		t.Fatal("the secret is in the signed manifest")
	}

	// A reused input never carries a secret into another file.
	again, _, err := RewriteProfilesForRecipient(out, fullParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ReadUpdateSecret(again); err != bundle.ErrNoUpdateSecret {
		t.Fatalf("a secret rode through a reused input: %v", err)
	}
}
