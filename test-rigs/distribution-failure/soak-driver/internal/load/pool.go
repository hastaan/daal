// Package load is the Phase 2G synthetic-client harness. It
// spawns N soak-engine subprocesses with bounded concurrency so a
// 1000-client / 30-day soak fits in a developer-laptop process
// budget.
//
// The pool is back-pressured: at most ConcurrencyLimit subprocesses
// are alive simultaneously. Spawn blocks until a slot is available;
// callers use the pool's Spawn / Shutdown lifecycle.
//
// Stdlib only — the soak driver as a whole has no third-party
// dependencies.
package load

import (
	"fmt"
	"path/filepath"
	"sync"

	"daal/soak-driver/internal/client"
)

// Pool spawns and manages a fleet of soak-engine subprocesses.
type Pool struct {
	ConcurrencyLimit int    // default 64
	Engine           string // path to daal-soak-engine -tags soak binary
	StateDirRoot     string

	mu      sync.Mutex
	clients []*client.Client
	sem     chan struct{}
}

// Spawn creates exactly n synthetic clients. State directories are
// `<StateDirRoot>/c-NNNN/`. Returns the slice of clients in
// deterministic ID order.
//
// On any spawn failure, all already-spawned clients are torn down
// before the error returns; the caller never observes a partial
// fleet.
func (p *Pool) Spawn(n int) ([]*client.Client, error) {
	if p.ConcurrencyLimit <= 0 {
		p.ConcurrencyLimit = 64
	}
	p.mu.Lock()
	if p.sem == nil {
		p.sem = make(chan struct{}, p.ConcurrencyLimit)
	}
	p.mu.Unlock()

	out := make([]*client.Client, 0, n)
	for i := 0; i < n; i++ {
		// Acquire a slot. Buffered channel so the first
		// ConcurrencyLimit spawns proceed without waiting.
		p.sem <- struct{}{}
		dir := filepath.Join(p.StateDirRoot, fmt.Sprintf("c-%04d", i+1))
		c, err := client.Spawn(fmt.Sprintf("c-%04d", i+1), p.Engine, dir)
		if err != nil {
			// Tear down whatever we spawned, then propagate.
			for _, prev := range out {
				_ = prev.Close()
			}
			<-p.sem
			return nil, fmt.Errorf("load.Pool.Spawn[%d]: %w", i, err)
		}
		out = append(out, c)
	}
	p.mu.Lock()
	p.clients = append(p.clients, out...)
	p.mu.Unlock()
	return out, nil
}

// Shutdown closes every client the pool has spawned. Idempotent.
// Returns the first error observed; later errors are swallowed.
func (p *Pool) Shutdown() error {
	p.mu.Lock()
	clients := p.clients
	p.clients = nil
	p.mu.Unlock()
	var firstErr error
	for _, c := range clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		// Release the semaphore slot. Non-blocking since each
		// successful Spawn pushed exactly one token.
		select {
		case <-p.sem:
		default:
		}
	}
	return firstErr
}
