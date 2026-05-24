package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// recordingCounter implements Counter and records every Add call.
type recordingCounter struct {
	mu       sync.Mutex
	records  []record
	limit    uint64 // ErrExhausted once total exceeds limit; 0 == no limit
	consumed uint64
}

type record struct {
	RouteID string
	N       uint64
}

func (c *recordingCounter) Add(routeID string, n uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record{routeID, n})
	c.consumed += n
	if c.limit > 0 && c.consumed > c.limit {
		return errors.New("budget: hourly cap exhausted")
	}
	return nil
}

func (c *recordingCounter) Total() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consumed
}

func TestPipeChargesEveryWrite(t *testing.T) {
	src := strings.NewReader("hello, world")
	var dst bytes.Buffer
	c := &recordingCounter{}
	if err := Pipe(context.Background(), &dst, src, "r1", c, PipeOptions{}); err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	if dst.String() != "hello, world" {
		t.Errorf("dst = %q", dst.String())
	}
	if c.Total() != uint64(len("hello, world")) {
		t.Errorf("Total = %d", c.Total())
	}
}

func TestPipeExhaustedReturnsSentinel(t *testing.T) {
	src := strings.NewReader(strings.Repeat("x", 10000))
	var dst bytes.Buffer
	c := &recordingCounter{limit: 100}
	err := Pipe(context.Background(), &dst, src, "r1", c, PipeOptions{BufSize: 64})
	if err != ErrExhausted {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	// Some bytes were copied before exhaustion.
	if dst.Len() == 0 {
		t.Errorf("expected partial dst write, got 0 bytes")
	}
}

func TestPipeCounterRequired(t *testing.T) {
	if err := Pipe(context.Background(), io.Discard, strings.NewReader("x"), "r1", nil, PipeOptions{}); err == nil {
		t.Fatalf("expected error when counter is nil")
	}
}

func TestPipeRouteIDRequired(t *testing.T) {
	if err := Pipe(context.Background(), io.Discard, strings.NewReader("x"), "", &recordingCounter{}, PipeOptions{}); err == nil {
		t.Fatalf("expected error when routeID is empty")
	}
}

func TestPipeAuthGuardedSkipsBudgetOnAuthFailed(t *testing.T) {
	c := &recordingCounter{}
	preflight := AuthFailed(errors.New("rejected"))
	src := strings.NewReader("would-have-been-charged")
	err := PipeAuthGuarded(context.Background(), io.Discard, src, "r1", c, PipeOptions{}, preflight)
	if !IsAuthFailed(err) {
		t.Fatalf("expected auth-failed err, got %v", err)
	}
	if c.Total() != 0 {
		t.Errorf("auth-failed bytes were charged: total=%d", c.Total())
	}
}

func TestPipeAuthGuardedRunsWhenPreflightOK(t *testing.T) {
	c := &recordingCounter{}
	src := strings.NewReader("ok")
	if err := PipeAuthGuarded(context.Background(), io.Discard, src, "r1", c, PipeOptions{}, nil); err != nil {
		t.Fatalf("PipeAuthGuarded: %v", err)
	}
	if c.Total() != 2 {
		t.Errorf("Total = %d, want 2", c.Total())
	}
}

func TestPipeContextCancelStops(t *testing.T) {
	r, w := io.Pipe()
	c := &recordingCounter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Pipe(ctx, io.Discard, r, "r1", c, PipeOptions{})
	}()
	// Write a chunk then cancel.
	go func() {
		_, _ = w.Write([]byte("chunk"))
		cancel()
		_ = w.Close()
	}()
	err := <-done
	if err == nil {
		t.Fatalf("expected non-nil error after cancel")
	}
}
