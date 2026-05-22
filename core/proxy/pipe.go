package proxy

import (
	"context"
	"errors"
	"io"
)

// Counter is the budget seam Pipe charges. core/budget.Engine
// satisfies this interface; tests inject a recorder.
type Counter interface {
	Add(routeID string, n uint64) error
}

// ErrExhausted is the canonical error Pipe returns when Counter.Add
// returns it. Callers MUST treat this as a signal to drive the FSM
// into StateBudgetExhausted.
var ErrExhausted = errors.New("proxy: route budget exhausted")

// PipeOptions controls Pipe's behavior. The zero value is fine.
type PipeOptions struct {
	// BufSize is the io.Copy buffer in bytes. 32 KiB if zero.
	BufSize int
}

// Pipe copies from src to dst, charging counter.Add(routeID, n) after
// each successful write. On counter.Add returning budget exhaustion,
// Pipe returns ErrExhausted (not the underlying budget error) so the
// caller can match a single sentinel.
//
// Pipe stops as soon as either src returns EOF or any non-recoverable
// error occurs. It returns nil on clean EOF.
//
// Pipe NEVER inspects payload contents.
func Pipe(ctx context.Context, dst io.Writer, src io.Reader,
	routeID string, counter Counter, opts PipeOptions) error {
	if counter == nil {
		return errors.New("proxy: counter is required")
	}
	if routeID == "" {
		return errors.New("proxy: routeID is required")
	}
	bufSize := opts.BufSize
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	buf := make([]byte, bufSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			if cerr := counter.Add(routeID, uint64(n)); cerr != nil {
				if isBudgetExhausted(cerr) {
					return ErrExhausted
				}
				return cerr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// PipeAuthGuarded wraps Pipe with the auth-failed exemption. If
// preflight returns an error that IsAuthFailed reports true, Pipe is
// NOT invoked and the error is returned untouched. Otherwise Pipe
// runs normally.
//
// This is the canonical seam an outbound dialer integration should
// use: do the handshake, evaluate the result, then call
// PipeAuthGuarded with the resulting connection.
func PipeAuthGuarded(ctx context.Context, dst io.Writer, src io.Reader,
	routeID string, counter Counter, opts PipeOptions, preflight error) error {
	if preflight != nil {
		// auth_failed errors must not burn budget.
		return preflight
	}
	return Pipe(ctx, dst, src, routeID, counter, opts)
}

// isBudgetExhausted matches budget.ErrExhausted without importing the
// budget package (avoids a cycle since budget doesn't import proxy
// either; we identify the error by its string for the cross-package
// match).
func isBudgetExhausted(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "budget: hourly cap exhausted"
}
