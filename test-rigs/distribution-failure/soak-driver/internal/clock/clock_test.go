package clock

import (
	"testing"
	"time"
)

func TestAdvance(t *testing.T) {
	c := New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	c.Advance(24 * time.Hour)
	if got, want := c.Now(), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("Now=%v want %v", got, want)
	}
}

func TestAdvanceNegativePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on negative advance")
		}
	}()
	c := Default()
	c.Advance(-time.Second)
}

func TestAdvanceToRewindPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on rewind")
		}
	}()
	c := Default()
	c.AdvanceTo(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
}
