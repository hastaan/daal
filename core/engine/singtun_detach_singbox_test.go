//go:build singbox && with_gvisor

package engine

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

// detachRecorder is a link endpoint that only remembers what it was
// attached to.
type detachRecorder struct {
	stack.LinkEndpoint
	calls    int
	lastNil  bool
	attached bool
}

func (d *detachRecorder) Attach(dispatcher stack.NetworkDispatcher) {
	d.calls++
	d.lastNil = dispatcher == nil
	d.attached = dispatcher != nil
}

// A sing-box instance that is closed must stop reading its TUN.
// sing-tun closes its stack with endpoint.Attach(nil) and the fd
// endpoint stops its packet readers only when it is handed exactly
// nil. sing-tun 0.8.9 wrapped the nil in a filter on the way, so the
// reader of every closed instance lived on: on a TUN kept across a
// route switch it took about half of the new instance's packets while
// the engine said Connected (end-to-end rig finding SW-2).
//
// This pins the sing-tun this module LINKS (third_party/sing-tun via
// the `replace` in go.mod). It fails against upstream 0.8.9, and so in
// any module that builds the engine without the replace.
func TestSingTunDetachReachesTheEndpoint(t *testing.T) {
	inner := &detachRecorder{}
	filter := &tun.LinkEndpointFilter{LinkEndpoint: inner}

	filter.Attach(stubDispatcher{})
	if !inner.attached {
		t.Fatalf("attach did not reach the wrapped endpoint")
	}
	filter.Attach(nil)
	if inner.calls != 2 || !inner.lastNil {
		t.Fatalf("Attach(nil) reached the wrapped endpoint as a non-nil dispatcher (calls=%d): "+
			"a closed instance keeps reading the TUN. Is the sing-tun replace in go.mod missing?", inner.calls)
	}
}

type stubDispatcher struct{ stack.NetworkDispatcher }
