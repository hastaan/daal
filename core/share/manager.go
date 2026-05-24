// Package share owns the device-side lifecycle of route-sharing sessions:
// constructing a signed friend-share .sbp from on-device routes, holding
// the PIN+TLS material for the LAN transport, and driving the fountain QR
// codec for animated transfers. All UI surfaces in the engine ABI delegate
// here.
//
// CC.6 invariants:
//   - HTTPS server binds only to non-loopback private addresses.
//   - The mDNS instance name carries no device hostname.
//   - Bundle bytes and PINs are wiped on session end.
package share

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	bundleshare "daal/bundle-go/share"
)

// Session is a single in-flight share operation.
type Session struct {
	ID            string
	Pin           string // 6-digit
	BundleBytes   []byte
	StaticQRBytes []byte
	StaticQRURI   string
	LANAddrs      []string // https URLs (private addresses only)
	LANToken      string   // HKDF(pin, session_id) base64; transport only
	mDNSStop      func()
	httpStop      func()
	createdAt     time.Time
}

// Manager tracks live sessions and exposes lifecycle helpers used by the
// engine ABI.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	identity bundleshare.PublisherIdentity
	now      func() time.Time

	// Hooks, swapped out in tests.
	encodeQR func(uri string, sizePx int) ([]byte, error)
	listen   func(addrs []string, token string, body []byte) (urls []string, stop func(), err error)
	advert   func(serviceName string, port int, txt map[string]string) (stop func(), err error)
}

// NewManager constructs a manager that uses the supplied identity for all
// outgoing share bundles. Pass `now` for deterministic tests.
func NewManager(ident bundleshare.PublisherIdentity, now func() time.Time) *Manager {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{
		sessions: map[string]*Session{},
		identity: ident,
		now:      now,
		encodeQR: bundleshare.EncodeStaticQR,
		listen:   defaultListen,    // implemented in lan_sender.go
		advert:   defaultAdvertise, // implemented in lan_sender.go
	}
}

// EnsureIdentity creates and returns a fresh ed25519 sharing identity if
// one wasn't supplied. Callers persist the resulting (pub, priv) outside
// this package (typically in the secrets KV).
func EnsureIdentity(displayName string, now time.Time) (bundleshare.PublisherIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return bundleshare.PublisherIdentity{}, err
	}
	return bundleshare.PublisherIdentity{
		DisplayName:  displayName,
		PublicKey:    pub,
		PrivateKey:   priv,
		TrustClass:   "tofu_friend",
		KeyCreatedAt: now,
	}, nil
}

// BeginInput is what the engine ABI passes to BeginShare.
type BeginInput struct {
	Routes      []bundleshare.ExportInput
	StartLAN    bool
	StaticQRURI string // pre-baked single-URI QR; if empty, QR is omitted
	QRSizePx    int
}

// BeginShare builds the .sbp, optionally starts the LAN transport, and
// returns a session handle the caller can then expose to UI.
func (m *Manager) BeginShare(in BeginInput) (*Session, error) {
	body, err := bundleshare.BuildShareBundle(in.Routes, m.identity, m.now())
	if err != nil {
		return nil, err
	}
	pin, err := generatePIN()
	if err != nil {
		return nil, err
	}
	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	tok := DeriveBearerToken(pin, id)
	sess := &Session{
		ID:          id,
		Pin:         pin,
		BundleBytes: body,
		LANToken:    tok,
		createdAt:   m.now(),
	}
	if in.StaticQRURI != "" {
		png, err := m.encodeQR(in.StaticQRURI, in.QRSizePx)
		if err == nil {
			sess.StaticQRBytes = png
			sess.StaticQRURI = in.StaticQRURI
		}
	}
	if in.StartLAN {
		addrs, err := DetectPrivateAddrs()
		if err != nil {
			return nil, fmt.Errorf("share: no private interfaces: %w", err)
		}
		urls, stopHTTP, err := m.listen(addrs, tok, body)
		if err != nil {
			return nil, fmt.Errorf("share: lan start: %w", err)
		}
		sess.LANAddrs = urls
		sess.httpStop = stopHTTP
		port := portFromURL(urls[0])
		stopAdv, err := m.advert(id, port, map[string]string{
			"v":    "1",
			"name": "share",
		})
		if err == nil {
			sess.mDNSStop = stopAdv
		}
	}
	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()
	return sess, nil
}

// EndShare stops the LAN listeners, removes the mDNS advertisement, and
// wipes the bundle bytes from RAM.
func (m *Manager) EndShare(id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("share: unknown session")
	}
	if sess.mDNSStop != nil {
		sess.mDNSStop()
	}
	if sess.httpStop != nil {
		sess.httpStop()
	}
	zero(sess.BundleBytes)
	zero([]byte(sess.Pin))
	zero([]byte(sess.LANToken))
	return nil
}

// Lookup returns a session by ID (used by the receiver-side helpers in
// tests and by the ABI when re-entering an existing session).
func (m *Manager) Lookup(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

func generatePIN() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(b[:]) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

func generateSessionID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("s-%x", b), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
