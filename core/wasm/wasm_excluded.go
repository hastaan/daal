//go:build no_wasm

// Phase 3E. `-tags no_wasm` excluder twin. Distributors that
// cannot ship the wazero vendor tree pass `no_wasm`; the
// `wasm_compiled_in` diagnostic flips false; the engine's
// transport_module family handler refuses to load any module.
//
// This file replaces the wasm.go implementation entirely under
// the build tag. The exported surface mirrors the un-excluded
// version closely enough that the abi + path manager packages
// compile against either build with no #ifdef-style code.

package wasm

import (
	"context"
	"errors"
	"time"
)

const (
	FamilyID             = "transport_module"
	Compiled             = false
	MaxModuleBytes       = 4 * 1024 * 1024
	MaxBundleModuleBytes = 16 * 1024 * 1024
	MaxModuleMemoryBytes = 16 * 1024 * 1024
	FuelPerDial          = uint64(1_000_000_000)
	DialTimeout          = 5 * time.Second
	LoadTimeout          = 5 * time.Second
	MaxInstancesPerRoute = 1
)

type DialOutcome string

const (
	OutcomeOK                DialOutcome = "ok"
	OutcomeFuelExhausted     DialOutcome = "fuel_exhausted"
	OutcomeMemoryCap         DialOutcome = "memory_cap"
	OutcomeDialTimeout       DialOutcome = "dial_timeout"
	OutcomeHostCallbackError DialOutcome = "host_callback_error"
)

func AllOutcomes() []DialOutcome {
	return []DialOutcome{
		OutcomeOK, OutcomeFuelExhausted, OutcomeMemoryCap,
		OutcomeDialTimeout, OutcomeHostCallbackError,
	}
}

func IsKnownOutcome(out string) bool {
	for _, o := range AllOutcomes() {
		if string(o) == out {
			return true
		}
	}
	return false
}

type HostDialer func(ctx context.Context, addr string) (HostConn, error)

type HostConn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

type ModuleSpec struct {
	Slug             string
	SHA256Hex        string
	WASMBytes        []byte
	MinEngineVersion string
}

type LoadedModule struct {
	Slug      string
	SHA256Hex string
	LoadedAt  time.Time
}

func (m *LoadedModule) Close() error { return nil }

var (
	ErrModuleOversize       = errors.New("wasm: module exceeds 4 MiB cap")
	ErrHashMismatch         = errors.New("wasm: sha256 hash mismatch")
	ErrModuleKilled         = errors.New("wasm: module is on the kill-switch list")
	ErrLoadTimeout          = errors.New("wasm: module load timeout")
	ErrDialTimeout          = errors.New("wasm: module dial timeout")
	ErrFuelExhausted        = errors.New("wasm: fuel cap exhausted")
	ErrMemoryCap            = errors.New("wasm: memory cap exceeded")
	ErrHostCallbackError    = errors.New("wasm: host callback returned an error")
	ErrInvalidSlug          = errors.New("wasm: invalid module slug")
	ErrCompiledOut          = errors.New("wasm: vendor tree excluded by -tags no_wasm")
	ErrPort443Only          = errors.New("wasm: dial address must be host:443")
	ErrModuleEntryMalformed = errors.New("wasm: module entry malformed")
)

// VerifyHash is provided in both builds so the bundle parser
// can call it without conditional compilation.
func VerifyHash(body []byte, wantHex string) error {
	// Re-implementing crypto/sha256 vs duplicating the import
	// is a wash; the bundle module already imports
	// crypto/sha256 directly so this excluder twin can stay
	// bytes-only.
	return verifyHashImpl(body, wantHex)
}

// Loader under -tags no_wasm is a no-op shim that always
// refuses to load with ErrCompiledOut.
type Loader struct{}

func NewLoader() *Loader { return &Loader{} }

func (l *Loader) MarkKilled(string)    {}
func (l *Loader) IsKilled(string) bool { return false }
func (l *Loader) Load(context.Context, ModuleSpec, HostDialer) (*LoadedModule, error) {
	return nil, ErrCompiledOut
}

func Dial(context.Context, *LoadedModule, HostDialer, string) (DialOutcome, error) {
	return OutcomeHostCallbackError, ErrCompiledOut
}

// Context decoration helpers exist under both builds so
// callers compile uniformly.

func WithConnTable(ctx context.Context) context.Context               { return ctx }
func WithLogHook(ctx context.Context, _ func(string)) context.Context { return ctx }
func WithClock(ctx context.Context, _ func() time.Time) context.Context {
	return ctx
}
func WithRandFill(ctx context.Context, _ func([]byte)) context.Context { return ctx }
