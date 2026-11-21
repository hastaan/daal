//go:build singbox && cgo

package abi

// protectCallsHost: in a singbox+cgo build engine.ProtectFD calls the
// registered address as a C function, so a test must never register a
// fake one.
const protectCallsHost = true
