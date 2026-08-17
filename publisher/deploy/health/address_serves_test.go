package health

import (
	"errors"
	"net"
	"testing"
	"time"
)

// The 2026-08-17 hardware finding: an assign can report success, the
// provider can show the address attached with both ownership labels, and
// the box can still not answer on it. rotation.CheckAddressMoved passes in
// that state; this must not.
func TestAddressServes_RefusesAnAddressNothingAnswersOn(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3: routable-looking, guaranteed dead.
	if err := AddressServes(net.ParseIP("203.0.113.7"), 443, 300*time.Millisecond); !errors.Is(err, ErrAddressUnreachable) {
		t.Fatalf("want ErrAddressUnreachable, got %v", err)
	}
}

func TestAddressServes_AcceptsAnAddressThatAnswers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if err := AddressServes(net.ParseIP("127.0.0.1"), ln.Addr().(*net.TCPAddr).Port, 2*time.Second); err != nil {
		t.Fatalf("a listening address must pass: %v", err)
	}
}

func TestAddressServes_EmptyAddressIsRefused(t *testing.T) {
	if err := AddressServes(nil, 443, time.Second); !errors.Is(err, ErrAddressUnreachable) {
		t.Fatalf("want ErrAddressUnreachable, got %v", err)
	}
}
