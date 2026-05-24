// Package origin runs the fake remote endpoints the soak's clients
// reach when the censor isn't blocking them. Everything binds to
// loopback. No external network is touched.
//
// Six origin kinds, each on its own random loopback port:
//
//   - subscription: serves a fixed URI-list subscription body
//   - revocation:   serves a SignedRevocation JSON
//   - directory:    serves a Tier-3 directory .sbp
//   - ipfs:         serves a directory .sbp through an IPFS-gateway-like URL
//   - telegram:     serves a stub channel listing (used to model "Telegram channel" channel)
//   - github:       serves a stub releases listing (used to model "GitHub" channel)
//
// Each origin can be in one of three states:
//
//   - allow: respond normally
//   - drop:  TCP-accept then immediately RST (models tcp_reset)
//   - timeout: TCP-accept then keep the connection idle (models tcp_connect_timeout-ish)
//
// The driver flips per-channel state through Set(channel, state).
package origin

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

type State int

const (
	StateAllow State = iota
	StateDrop
	StateTimeout
)

func (s State) String() string {
	switch s {
	case StateAllow:
		return "allow"
	case StateDrop:
		return "drop"
	case StateTimeout:
		return "timeout"
	default:
		return "?"
	}
}

// Channel is one of the six kinds enumerated above.
type Channel string

const (
	ChannelSubscription Channel = "subscription"
	ChannelRevocation   Channel = "revocation"
	ChannelDirectory    Channel = "directory"
	ChannelIPFS         Channel = "ipfs"
	ChannelTelegram     Channel = "telegram"
	ChannelGitHub       Channel = "github"
)

// AllChannels enumerates the channels in stable order (used for resets,
// snapshot artifacts, and CLI parsing).
func AllChannels() []Channel {
	return []Channel{
		ChannelSubscription,
		ChannelRevocation,
		ChannelDirectory,
		ChannelIPFS,
		ChannelTelegram,
		ChannelGitHub,
	}
}

// Server holds one HTTP listener per channel. It is intentionally
// thread-safe and minimal — the soak driver instantiates a single
// Server, shares it across all clients, and toggles channel states
// with Set().
type Server struct {
	mu        sync.Mutex
	listeners map[Channel]*channelServer
	bodies    map[Channel][]byte
}

type channelServer struct {
	listener net.Listener
	state    atomic.Int32
	url      string
}

// New constructs a Server with each channel listening on a random
// loopback port. The body of each channel must be set with SetBody
// before the soak begins.
func New() (*Server, error) {
	s := &Server{
		listeners: map[Channel]*channelServer{},
		bodies:    map[Channel][]byte{},
	}
	for _, ch := range AllChannels() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("origin: listen %s: %w", ch, err)
		}
		cs := &channelServer{
			listener: ln,
			url:      "http://" + ln.Addr().String() + "/",
		}
		cs.state.Store(int32(StateAllow))
		s.listeners[ch] = cs
		go s.serve(ch, cs)
	}
	return s, nil
}

// Set switches the state of a single channel. It is safe to call from
// multiple goroutines.
func (s *Server) Set(ch Channel, state State) {
	s.mu.Lock()
	cs := s.listeners[ch]
	s.mu.Unlock()
	if cs != nil {
		cs.state.Store(int32(state))
	}
}

// SetAll switches every channel to the same state.
func (s *Server) SetAll(state State) {
	for _, ch := range AllChannels() {
		s.Set(ch, state)
	}
}

// SetBody updates the body served by a channel when its state is
// StateAllow.
func (s *Server) SetBody(ch Channel, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dup := make([]byte, len(body))
	copy(dup, body)
	s.bodies[ch] = dup
}

// URL returns the http://127.0.0.1:port/ URL for a channel.
func (s *Server) URL(ch Channel) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cs, ok := s.listeners[ch]; ok {
		return cs.url
	}
	return ""
}

// Close shuts down all channel listeners.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cs := range s.listeners {
		_ = cs.listener.Close()
	}
	s.listeners = nil
}

func (s *Server) serve(ch Channel, cs *channelServer) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch State(cs.state.Load()) {
		case StateDrop:
			// Hijack and close the conn to model an RST.
			h, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			conn, _, _ := h.Hijack()
			if conn != nil {
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0) // forces RST on close
				}
				_ = conn.Close()
			}
		case StateTimeout:
			h, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusGatewayTimeout)
				return
			}
			conn, _, _ := h.Hijack()
			if conn != nil {
				// Idle this conn forever; the client's per-attempt
				// timeout will catch it.
				select {}
			}
		default:
			s.mu.Lock()
			body := s.bodies[ch]
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}
	})
	srv := &http.Server{Handler: mux}
	_ = srv.Serve(cs.listener)
}
