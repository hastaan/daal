// Package ipfs reserves the IPFS pinning surface for the FRP-8
// freshness endpoint. Disabled at FRP-8 ship: every Put returns
// ErrReserved. The phase doc marks IPFS "reserved/disabled until
// a maintained pinning surface stabilises"; the wizard refuses
// to pick this backend in production builds and surfaces the
// reservation note instead.
//
// No network surface is opened in this build, so this file does
// NOT need an opsec-test allowlist entry.

package ipfs

import (
	"context"
	"errors"
)

// ErrReserved is returned by every Backend method.
var ErrReserved = errors.New("freshness/ipfs: reserved/disabled at FRP-8")

// Config is the placeholder config; populated when the backend
// activates.
type Config struct{}

// Backend is the disabled stub.
type Backend struct{}

// New returns a stub that errors on every operation.
func New(_ Config) *Backend { return &Backend{} }

// PublicURL returns the empty string (no publish URL while
// reserved).
func (*Backend) PublicURL() string { return "" }

// Put always returns ErrReserved.
func (*Backend) Put(_ context.Context, _ []byte) error { return ErrReserved }
