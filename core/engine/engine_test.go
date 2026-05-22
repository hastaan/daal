package engine

import (
	"context"
	"errors"
	"testing"
)

func TestStubRoundTrip(t *testing.T) {
	s := NewStub()
	ch := make(chan Event, 4)
	s.Subscribe(ch)
	if err := s.Start(context.Background(), []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	if !s.Connected() {
		t.Fatal("expected connected")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	close(ch)
	gotConn, gotDisc := false, false
	for ev := range ch {
		if ev.State == "Connected" {
			gotConn = true
		}
		if ev.State == "Disconnected" {
			gotDisc = true
		}
	}
	if !gotConn || !gotDisc {
		t.Fatalf("missed events: conn=%v disc=%v", gotConn, gotDisc)
	}
}

func TestStubInjectedFailureClassifies(t *testing.T) {
	s := NewStub()
	ch := make(chan Event, 4)
	s.Subscribe(ch)
	s.InjectFailure(errors.New("read tcp 198.51.100.1: connection reset by peer"))
	if err := s.Start(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected error")
	}
	got := <-ch
	if got.Type != "failure" || got.Category != "tcp_reset" {
		t.Fatalf("classified wrong: %+v", got)
	}
}
