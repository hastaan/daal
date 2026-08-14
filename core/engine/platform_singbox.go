//go:build singbox

package engine

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	boxoption "github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

// androidPlatform is the adapter.PlatformInterface the singBox driver
// injects into the box context. Despite the name it is host-agnostic:
// the two live paths — TUN-fd injection via OpenInterface and upstream
// socket protection via AutoDetectInterfaceControl — read the state the
// ABI layer pushed into platform.go's atomics, which the Android
// VpnService and (later, Part 4) the Linux tun-helper both feed through
// the same engine_set_tun_fd / engine_register_protect_callback ABI.
//
// Everything else on the interface is answered "not provided by the
// platform" so sing-box falls back to its own implementations. The
// interface monitor is the one exception: once a PlatformInterface is
// present, sing-box's NetworkManager unconditionally asks it for a
// DefaultInterfaceMonitor (route/network.go), so we hand back a static
// no-op monitor. That is correct for the VpnService topology: socket
// protection — not interface binding — is what keeps upstream traffic
// out of the TUN, and network-change reactions are daal's pathmanager's
// job, not sing-box's.
type androidPlatform struct {
	bytesIn  int64 // reserved for the stats follow-up phase
	bytesOut int64
}

func newAndroidPlatform() *androidPlatform { return &androidPlatform{} }

var _ adapter.PlatformInterface = (*androidPlatform)(nil)

func (p *androidPlatform) Initialize(networkManager adapter.NetworkManager) error { return nil }

func (p *androidPlatform) UsePlatformAutoDetectInterfaceControl() bool {
	return CurrentProtectCallback() != 0
}

func (p *androidPlatform) AutoDetectInterfaceControl(fd int) error {
	return invokeProtect(fd)
}

func (p *androidPlatform) UsePlatformInterface() bool { return true }

// OpenInterface hands sing-tun the host-supplied TUN fd. With
// FileDescriptor set, sing-tun skips device creation and route setup —
// the VpnService Builder (or the privileged tun-helper on desktop)
// already owns both.
func (p *androidPlatform) OpenInterface(options *tun.Options, platformOptions boxoption.TunPlatformOptions) (tun.Tun, error) {
	fd := CurrentTunFD()
	if fd < 0 {
		return nil, errors.New("engine: TUN fd not set; host must call engine_set_tun_fd before engine_set_route")
	}
	options.FileDescriptor = fd
	return tun.New(*options)
}

func (p *androidPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }

func (p *androidPlatform) CreateDefaultInterfaceMonitor(_ logger.Logger) tun.DefaultInterfaceMonitor {
	return &staticInterfaceMonitor{}
}

func (p *androidPlatform) UsePlatformNetworkInterfaces() bool { return false }

func (p *androidPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }

func (p *androidPlatform) UnderNetworkExtension() bool { return false }

func (p *androidPlatform) NetworkExtensionIncludeAllNetworks() bool { return false }

func (p *androidPlatform) ClearDNSCache() {}

func (p *androidPlatform) RequestPermissionForWIFIState() error { return nil }

func (p *androidPlatform) ReadWIFIState() adapter.WIFIState { return adapter.WIFIState{} }

func (p *androidPlatform) SystemCertificates() []string { return nil }

func (p *androidPlatform) UsePlatformConnectionOwnerFinder() bool { return false }

func (p *androidPlatform) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errors.New("engine: connection owner lookup not provided")
}

func (p *androidPlatform) UsePlatformWIFIMonitor() bool { return false }

func (p *androidPlatform) UsePlatformNotification() bool { return false }

func (p *androidPlatform) SendNotification(notification *adapter.Notification) error { return nil }

func (p *androidPlatform) MyInterfaceAddress() []netip.Addr { return nil }

// staticInterfaceMonitor satisfies tun.DefaultInterfaceMonitor without
// watching anything. DefaultInterface() == nil means "unknown", which
// sing-box's NetworkManager handles (DefaultNetworkInterface returns
// nil); upstream sockets are excluded from the TUN via protect(), not
// via bind-to-interface, so the default interface is never needed.
type staticInterfaceMonitor struct {
	mu          sync.Mutex
	callbacks   list.List[tun.DefaultInterfaceUpdateCallback]
	myInterface string
}

var _ tun.DefaultInterfaceMonitor = (*staticInterfaceMonitor)(nil)

func (m *staticInterfaceMonitor) Start() error { return nil }

func (m *staticInterfaceMonitor) Close() error { return nil }

func (m *staticInterfaceMonitor) DefaultInterface() *control.Interface { return nil }

func (m *staticInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (m *staticInterfaceMonitor) AndroidVPNEnabled() bool { return false }

func (m *staticInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *staticInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(element)
}

func (m *staticInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.myInterface = interfaceName
}

func (m *staticInterfaceMonitor) MyInterface() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.myInterface
}
