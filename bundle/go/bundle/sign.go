package bundle

import (
	"crypto/ed25519"
)

func SignManifest(manifest Manifest, private ed25519.PrivateKey) ([]byte, error) {
	canonical, err := CanonicalManifestJSON(manifest)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(private, canonical), nil
}

func VerifyManifest(manifest Manifest, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrInvalidPublisherKey
	}
	canonical, err := CanonicalManifestJSON(manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return ErrInvalidSignature
	}
	return nil
}
