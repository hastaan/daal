//go:build unix

package provjournal

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockExclusive takes a non-blocking exclusive flock on f. The kernel
// drops it when the last descriptor closes — including when the process
// is killed — so a dead run can never leave the journal locked.
func lockExclusive(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrBusy
		}
		return fmt.Errorf("provjournal: lock: %w", err)
	}
	return nil
}
