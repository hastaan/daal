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
	gotVerifying, gotConn, gotDisc := false, false, false
	for ev := range ch {
		switch ev.State {
		case StateVerifying:
			gotVerifying = true
		case StateConnected:
			gotConn = true
		case StateDisconnected:
			gotDisc = true
		}
	}
	// A driver that has started knows nothing about the route yet: it
	// says "Verifying". "Connected" is the ABI's to publish, after a
	// proof (rig finding CEN-1) — a driver that says it on Start is the
	// defect.
	if !gotVerifying || !gotDisc {
		t.Fatalf("missed events: verifying=%v disc=%v", gotVerifying, gotDisc)
	}
	if gotConn {
		t.Fatal("Start published \"Connected\": an engine instance that started has proved nothing about its route")
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
