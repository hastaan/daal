package abi

import "daal/core/engine"

// newEngineDriver is the single constructor call site for the engine
// driver (Phase 45 invariant 1): the `singbox` build tag selects the
// real in-process driver via engine.NewDefaultDriver, absent tag keeps
// the stub. It is a variable only so singbox-tagged *test* builds can
// pin the stub back in (driver_singbox_stub_test.go) — unit tests
// always target the stub; the real driver is exercised on-device.
var newEngineDriver = engine.NewDefaultDriver
