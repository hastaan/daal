package relaypack

import (
	"crypto/sha256"
	"encoding/base64"
)

// A relay's non-secret connection material, as a provisioned
// OperatorRecord carries it. Every test record that is bound into a
// pack needs it: a route with no signed endpoint is a route no
// recipient can use, and a pack with none at all is not signed.
const fixtureRealityPub = "Zml4dHVyZS1yZWFsaXR5LXB1YmxpYy1rZXktMzJieXRlcw"

var fixtureTLSPin = func() string {
	sum := sha256.Sum256([]byte("fixture data-plane SubjectPublicKeyInfo"))
	return base64.StdEncoding.EncodeToString(sum[:])
}()
