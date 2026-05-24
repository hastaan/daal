# Lifecycle Test Vectors

Lifecycle vectors describe Route and Publisher state transitions.

Initial scenarios:

- unknown publisher first seen
- TOFU publisher trusted
- one-bundle-only import
- trusted publisher expires
- trusted publisher rotates key with valid chain
- trusted publisher changes key without chain
- trusted publisher revoked
- route expired
- route revoked
- authentication failure does not trigger censorship cooldown
