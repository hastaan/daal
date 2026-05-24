package bootstrap

import (
	"daal/bundle-go/bundle"
)

// importSBPFingerprint is a tiny test helper that returns the publisher
// fingerprint hex string of a parsed .sbp body. It is in its own _test.go
// file so it does not bloat the production package.
func importSBPFingerprint(body []byte) (string, error) {
	parsed, err := bundle.ParseSBP(bytesReader(body), int64(len(body)))
	if err != nil {
		return "", err
	}
	return bundle.PublisherFingerprint(parsed.PublisherPub).Hex, nil
}
