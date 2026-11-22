package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The app's Cancel writes a file next to the setup journal; the run's
// context ends once it appears, so the provider rolls back.
func TestWatchCancelFileCancelsWhenTheFileAppears(t *testing.T) {
	old := cancelFilePoll
	cancelFilePoll = 5 * time.Millisecond
	t.Cleanup(func() { cancelFilePoll = old })
	path := filepath.Join(t.TempDir(), "7.cancel")

	ctx, stop := watchCancelFile(context.Background(), path)
	defer stop()
	select {
	case <-ctx.Done():
		t.Fatal("cancelled before the file existed")
	case <-time.After(30 * time.Millisecond):
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the cancel file did not cancel the run")
	}
}

func TestWatchCancelFileEmptyPathWatchesNothing(t *testing.T) {
	ctx, stop := watchCancelFile(context.Background(), "")
	select {
	case <-ctx.Done():
		t.Fatal("an empty path cancelled the run")
	case <-time.After(20 * time.Millisecond):
	}
	stop()
	if ctx.Err() == nil {
		t.Fatal("stop did not release the context")
	}
}
