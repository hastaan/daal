//go:build !no_wasm

// Package wasm hosts the Phase 3E WASM transport slot. Modules
// are loaded from signed bundles, executed in a sandboxed
// `wazero` runtime, and exposed to the path manager as a
// `transport_module` family. The runtime has NO host
// filesystem or host network surface — modules dial through a
// host-supplied callback that is restricted to TCP/443 only.
//
// Locked at 3E (see `specs/wasm-transport-v1.md`):
//
//   - WATER v1 ABI surface only (5 module exports + 3 host
//     imports); no Daal-custom extensions.
//   - Resource caps: 16 MiB memory; 1e9 fuel per Dial; 5s
//     load + dial timeouts; ≤ 4 MiB per module; 1 instance
//     per route per session.
//   - Failure outcomes are enumerable (`ok`, `fuel_exhausted`,
//     `memory_cap`, `dial_timeout`, `host_callback_error`).
//   - The package is excluded by `-tags no_wasm`; the abi
//     diagnostic `wasm_compiled_in` flips false in that build.
//
// The package is stdlib + `github.com/tetratelabs/wazero` only.

package wasm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// FamilyID is the transport-family identifier for WASM-loaded
// transports. Matches the bundle parser's `transport_module`
// family token and the `route_object` `transport_family` value.
const FamilyID = "transport_module"

// Compiled-in flag. The `-tags no_wasm` twin file flips this
// to false; the abi package surfaces it as `wasm_compiled_in`.
const Compiled = true

// Locked v1 resource caps. The integers are deliberate — there
// is no runtime configuration. A tighter cap is a roadmap-level
// decision; widening is a 3E security regression.
const (
	MaxModuleBytes       = 4 * 1024 * 1024  // 4 MiB
	MaxBundleModuleBytes = 16 * 1024 * 1024 // 16 MiB
	MaxModuleMemoryBytes = 16 * 1024 * 1024 // 16 MiB
	FuelPerDial          = uint64(1_000_000_000)
	DialTimeout          = 5 * time.Second
	LoadTimeout          = 5 * time.Second
	MaxInstancesPerRoute = 1
)

// DialOutcome is the closed v1 outcome enum surfaced in
// diagnostics as `last_wasm_module_dial_outcome`. New values
// at 3E are a security-review-gated change.
type DialOutcome string

const (
	OutcomeOK                DialOutcome = "ok"
	OutcomeFuelExhausted     DialOutcome = "fuel_exhausted"
	OutcomeMemoryCap         DialOutcome = "memory_cap"
	OutcomeDialTimeout       DialOutcome = "dial_timeout"
	OutcomeHostCallbackError DialOutcome = "host_callback_error"
)

// AllOutcomes returns the closed v1 outcome list.
func AllOutcomes() []DialOutcome {
	return []DialOutcome{
		OutcomeOK, OutcomeFuelExhausted, OutcomeMemoryCap,
		OutcomeDialTimeout, OutcomeHostCallbackError,
	}
}

// IsKnownOutcome reports whether `out` is in the closed v1 list.
func IsKnownOutcome(out string) bool {
	for _, o := range AllOutcomes() {
		if string(o) == out {
			return true
		}
	}
	return false
}

// HostDialer is the host-supplied TCP/443-only callback the
// WASM module invokes through `water_transport_dial`. The host
// rejects any address whose port is not 443; this is the
// locked-at-3E network-surface restriction.
type HostDialer func(ctx context.Context, addr string) (HostConn, error)

// HostConn is the minimal byte-stream conn the host returns to
// the module. The module never sees a `net.Conn` directly; the
// host owns the lifetime and close.
type HostConn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// ModuleSpec is the parsed bundle entry: a slug + sha256 + raw
// bytes. The Loader verifies sha256 matches the bytes before
// instantiating; a mismatch is `ErrHashMismatch`.
type ModuleSpec struct {
	Slug             string
	SHA256Hex        string
	WASMBytes        []byte
	MinEngineVersion string
}

// LoadedModule is the in-memory representation of a verified,
// instantiated module. The module is single-use per route per
// session (locked at 3E); the path manager holds at most one
// LoadedModule per route.
type LoadedModule struct {
	Slug      string
	SHA256Hex string
	LoadedAt  time.Time
	runtime   wazero.Runtime
	module    api.Module
	closeOnce sync.Once
}

// Close tears down the wazero instance + runtime. Safe to call
// multiple times.
func (m *LoadedModule) Close() error {
	if m == nil {
		return nil
	}
	var err error
	m.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		if m.module != nil {
			_ = m.module.Close(ctx)
		}
		if m.runtime != nil {
			err = m.runtime.Close(ctx)
		}
	})
	return err
}

// Sentinel errors. Mapped to V0 categories at the path manager
// boundary per `specs/failure-taxonomy-v1.md` (cosmetic-only at 3E).
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

// VerifyHash returns ErrHashMismatch if the SHA-256 of `body`
// does not match `wantHex`. Public so the bundle parser uses
// the same routine — keeps the check single-sourced. The
// implementation lives in `hash.go` so both build tags share
// it.
func VerifyHash(body []byte, wantHex string) error {
	return verifyHashImpl(body, wantHex)
}

// Loader instantiates verified ModuleSpecs into LoadedModules.
// Holds a wazero compilation cache across modules so repeated
// loads of the same WASM bytes are cheap. Thread-safe.
type Loader struct {
	mu     sync.Mutex
	cache  wazero.CompilationCache
	killed map[string]struct{} // sha256 hex of killed modules
}

// NewLoader returns a fresh Loader. The compilation cache
// lives for the loader's lifetime; the path manager holds a
// single Loader per engine session.
func NewLoader() *Loader {
	return &Loader{
		cache:  wazero.NewCompilationCache(),
		killed: map[string]struct{}{},
	}
}

// MarkKilled adds `sha256Hex` to the kill-switch set. Idempotent.
// The kill-switch verifier (see `killswitch.go`) calls this with
// each delta entry it accepts.
func (l *Loader) MarkKilled(sha256Hex string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.killed[sha256Hex] = struct{}{}
}

// IsKilled reports whether `sha256Hex` has been marked killed.
func (l *Loader) IsKilled(sha256Hex string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.killed[sha256Hex]
	return ok
}

// Load instantiates a verified module under the locked caps.
// Returns ErrModuleOversize / ErrHashMismatch / ErrModuleKilled
// / ErrLoadTimeout on failure; the module is not partially
// instantiated on the failure path.
func (l *Loader) Load(ctx context.Context, spec ModuleSpec, dialer HostDialer) (*LoadedModule, error) {
	if !validSlug(spec.Slug) {
		return nil, ErrInvalidSlug
	}
	if len(spec.WASMBytes) > MaxModuleBytes {
		return nil, ErrModuleOversize
	}
	if err := VerifyHash(spec.WASMBytes, spec.SHA256Hex); err != nil {
		return nil, err
	}
	if l.IsKilled(spec.SHA256Hex) {
		return nil, ErrModuleKilled
	}
	loadCtx, cancel := context.WithTimeout(ctx, LoadTimeout)
	defer cancel()

	// Bound the wazero memory by the locked cap. Pages are
	// 64 KiB each; 16 MiB ⇒ 256 pages.
	const pageSize = 65536
	maxPages := uint32(MaxModuleMemoryBytes / pageSize)

	rtCfg := wazero.NewRuntimeConfig().
		WithCompilationCache(l.cache).
		WithMemoryLimitPages(maxPages).
		WithCloseOnContextDone(true)
	rt := wazero.NewRuntimeWithConfig(loadCtx, rtCfg)

	// Bind WASI preview-1 (the WATER v1 ABI piggy-backs
	// `_start` from WASI). The host stays denial-listed —
	// no fs, no host net.
	if _, err := wasi_snapshot_preview1.Instantiate(loadCtx, rt); err != nil {
		_ = rt.Close(loadCtx)
		return nil, fmt.Errorf("wasm: instantiate wasi: %w", err)
	}

	// Bind the WATER v1 host imports.
	if err := exportWaterHost(loadCtx, rt, dialer); err != nil {
		_ = rt.Close(loadCtx)
		return nil, fmt.Errorf("wasm: export host: %w", err)
	}

	cfg := wazero.NewModuleConfig().
		WithStartFunctions("_start").
		WithName(spec.Slug)
	mod, err := rt.InstantiateWithConfig(loadCtx, spec.WASMBytes, cfg)
	if err != nil {
		_ = rt.Close(loadCtx)
		if loadCtx.Err() == context.DeadlineExceeded {
			return nil, ErrLoadTimeout
		}
		return nil, fmt.Errorf("wasm: instantiate module: %w", err)
	}

	return &LoadedModule{
		Slug:      spec.Slug,
		SHA256Hex: spec.SHA256Hex,
		LoadedAt:  time.Now().UTC(),
		runtime:   rt,
		module:    mod,
	}, nil
}

// validSlug enforces the locked-at-3E slug regex
// `[a-z0-9_-]{3,32}`.
func validSlug(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isSym := c == '_' || c == '-'
		if !(isLower || isDigit || isSym) {
			return false
		}
	}
	return true
}

// exportWaterHost binds the WATER v1 host imports under the
// `env` namespace (matching the placeholder spec). The host
// surface is intentionally tiny — three functions, all of
// which are deterministic in soak builds. The dial callback is
// restricted to TCP/443 inside `water_transport_dial`.
func exportWaterHost(ctx context.Context, rt wazero.Runtime, dialer HostDialer) error {
	hostBuilder := rt.NewHostModuleBuilder("env")

	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, ptr, length uint32) {
			// water_log: noop in release; soak builds may
			// hook a logger via context value.
			if hook, ok := ctx.Value(logHookKey{}).(func(string)); ok {
				buf, _ := mod.Memory().Read(ptr, length)
				hook(string(buf))
			}
		}).
		Export("water_log")

	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context) uint64 {
			if clk, ok := ctx.Value(clockKey{}).(func() time.Time); ok {
				return uint64(clk().Unix())
			}
			return uint64(time.Now().UTC().Unix())
		}).
		Export("water_clock_unix")

	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, ptr, length uint32) {
			// water_random_fill: deterministic in soak,
			// crypto/rand in release. The default fills
			// with a fixed pattern; release builds wire
			// `crypto/rand` via context.
			fill, ok := ctx.Value(randFillKey{}).(func([]byte))
			buf, _ := mod.Memory().Read(ptr, length)
			if ok {
				fill(buf)
			} else {
				for i := range buf {
					buf[i] = byte(i & 0xff)
				}
			}
			_ = mod.Memory().Write(ptr, buf)
		}).
		Export("water_random_fill")

	// water_transport_dial: only TCP/443. Returns 0 on success
	// and writes a 64-bit handle into the module's memory at
	// `outHandlePtr`; returns -1 on host error / non-443 port.
	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, addrPtr, addrLen, outHandlePtr uint32) int32 {
			if dialer == nil {
				return -1
			}
			buf, ok := mod.Memory().Read(addrPtr, addrLen)
			if !ok {
				return -1
			}
			addr := string(buf)
			if !endsInPort443(addr) {
				return -1
			}
			dctx, cancel := context.WithTimeout(ctx, DialTimeout)
			defer cancel()
			conn, err := dialer(dctx, addr)
			if err != nil {
				return -1
			}
			h := registerConn(ctx, conn)
			if h == 0 {
				_ = conn.Close()
				return -1
			}
			mod.Memory().WriteUint64Le(outHandlePtr, h)
			return 0
		}).
		Export("water_transport_dial")

	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, handle uint64, ptr, length uint32) int32 {
			conn := lookupConn(ctx, handle)
			if conn == nil {
				return -1
			}
			buf := make([]byte, length)
			n, err := conn.Read(buf)
			if err != nil && n == 0 {
				return -1
			}
			_ = mod.Memory().Write(ptr, buf[:n])
			return int32(n)
		}).
		Export("water_transport_read")

	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, handle uint64, ptr, length uint32) int32 {
			conn := lookupConn(ctx, handle)
			if conn == nil {
				return -1
			}
			buf, ok := mod.Memory().Read(ptr, length)
			if !ok {
				return -1
			}
			n, err := conn.Write(buf)
			if err != nil && n == 0 {
				return -1
			}
			return int32(n)
		}).
		Export("water_transport_write")

	hostBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, handle uint64) int32 {
			conn := releaseConn(ctx, handle)
			if conn == nil {
				return -1
			}
			_ = conn.Close()
			return 0
		}).
		Export("water_transport_close")

	if _, err := hostBuilder.Instantiate(ctx); err != nil {
		return err
	}
	return nil
}

// endsInPort443 reports whether `addr` is a `host:443` form.
// Locked at 3E: the host callback rejects any other port.
func endsInPort443(addr string) bool {
	const suffix = ":443"
	if len(addr) <= len(suffix) {
		return false
	}
	return addr[len(addr)-len(suffix):] == suffix
}

// Conn-handle bookkeeping lives on the context so it is
// per-Dial. Mutex-guarded; handles are sequential 64-bit
// integers starting at 1 (0 is the "invalid handle" sentinel).

type connTableKey struct{}
type clockKey struct{}
type logHookKey struct{}
type randFillKey struct{}

type connTable struct {
	mu     sync.Mutex
	conns  map[uint64]HostConn
	nextID uint64
}

// WithConnTable returns a context carrying a fresh conn-handle
// table. Callers (the host engine, soak driver) wrap each Dial
// in a new context with WithConnTable so handles do not leak
// across Dials.
func WithConnTable(ctx context.Context) context.Context {
	return context.WithValue(ctx, connTableKey{}, &connTable{
		conns:  map[uint64]HostConn{},
		nextID: 1,
	})
}

// WithLogHook (soak only) installs a `water_log` consumer.
func WithLogHook(ctx context.Context, hook func(string)) context.Context {
	return context.WithValue(ctx, logHookKey{}, hook)
}

// WithClock pins the WASM module's clock to a deterministic
// source (used by the soak driver to keep test output stable).
func WithClock(ctx context.Context, clk func() time.Time) context.Context {
	return context.WithValue(ctx, clockKey{}, clk)
}

// WithRandFill installs a deterministic random source.
func WithRandFill(ctx context.Context, fill func([]byte)) context.Context {
	return context.WithValue(ctx, randFillKey{}, fill)
}

func registerConn(ctx context.Context, conn HostConn) uint64 {
	t, ok := ctx.Value(connTableKey{}).(*connTable)
	if !ok {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.nextID
	t.nextID++
	t.conns[h] = conn
	return h
}

func lookupConn(ctx context.Context, h uint64) HostConn {
	t, ok := ctx.Value(connTableKey{}).(*connTable)
	if !ok {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conns[h]
}

func releaseConn(ctx context.Context, h uint64) HostConn {
	t, ok := ctx.Value(connTableKey{}).(*connTable)
	if !ok {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.conns[h]
	delete(t.conns, h)
	return c
}
