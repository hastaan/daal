package ipfs

import (
	"context"
	"errors"
	"testing"
)

func TestReserved(t *testing.T) {
	b := New(Config{})
	if b.PublicURL() != "" {
		t.Errorf("PublicURL should be empty while reserved")
	}
	if err := b.Put(context.Background(), []byte("x")); !errors.Is(err, ErrReserved) {
		t.Errorf("want ErrReserved, got %v", err)
	}
}
