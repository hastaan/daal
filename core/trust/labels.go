// FRP-11 trust label store — engine-side, encrypted-at-rest, never
// serialised into bundles or diagnostics.
//
// Trust labels (e.g. "family", "friends", "org-X") are local-only
// per supplement §17.1 + FRP-11 locked answer #4. They live in
// `core/trust/` keystore alongside the existing publisher TOFU pin
// because the recipient UI on multiple surfaces (Android, desktop)
// must read consistent values, and because plaintext storage would
// reveal social structure.
//
// Storage shape: an in-memory KV (FRP-11 lands the contract; the
// V008 wizard SQL migration commit (8) lands the persistent backing
// table). The `LabelStore` interface is what the importer + UI
// consume. AES-GCM ciphertext is the on-disk form; the in-memory
// cache holds plaintext labels keyed by cell-id-fingerprint.
package trust

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// ErrLabelNotFound is returned by Get when no label exists for the
// supplied cell-id-fingerprint. Callers MUST distinguish this from
// "label is empty string" (an explicit unlabel).
var ErrLabelNotFound = errors.New("trust label store: no label for this cell")

// LabelStore is the locked-at-FRP-11 contract for cell trust labels.
type LabelStore interface {
	Get(cellIDFPHex string) (string, error)
	Set(cellIDFPHex, label string) error
	Delete(cellIDFPHex string) error
	// SerializedCiphertext returns the on-disk encrypted bytes
	// for the supplied cell. UI/wizard code never calls this;
	// it exists for the V008 migration in commit 8 to read
	// labels through the same interface.
	SerializedCiphertext(cellIDFPHex string) ([]byte, error)
}

// MemoryLabelStore is the FRP-11 reference implementation. It
// keeps plaintext in memory and emits AES-GCM ciphertext on
// demand. The trust-keystore-key is supplied at construction; the
// wizard's encrypted keystore owns key persistence.
type MemoryLabelStore struct {
	mu     sync.RWMutex
	labels map[string]string
	gcm    cipher.AEAD
}

// NewMemoryLabelStore wraps the supplied AES key (32 bytes for
// AES-256). The label store NEVER logs or returns the key; it is
// kept inside the AEAD instance.
func NewMemoryLabelStore(aesKey []byte) (*MemoryLabelStore, error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("trust label store: AES key must be 32 bytes, got %d", len(aesKey))
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("trust label store: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("trust label store: cipher.NewGCM: %w", err)
	}
	return &MemoryLabelStore{
		labels: map[string]string{},
		gcm:    gcm,
	}, nil
}

// Get returns the plaintext label or ErrLabelNotFound.
func (s *MemoryLabelStore) Get(cellIDFPHex string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.labels[cellIDFPHex]
	if !ok {
		return "", ErrLabelNotFound
	}
	return v, nil
}

// Set writes a plaintext label. An empty label is permitted (the
// recipient UI's "no label" affordance) and is distinct from
// Delete.
func (s *MemoryLabelStore) Set(cellIDFPHex, label string) error {
	if cellIDFPHex == "" {
		return errors.New("trust label store: cellIDFPHex empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels[cellIDFPHex] = label
	return nil
}

// Delete removes a label entry entirely.
func (s *MemoryLabelStore) Delete(cellIDFPHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.labels, cellIDFPHex)
	return nil
}

// SerializedCiphertext returns nonce||ciphertext||tag for the
// stored label, suitable for persisting to the wizard's V008
// label_ciphertext column. Returns ErrLabelNotFound if the cell
// has no label.
func (s *MemoryLabelStore) SerializedCiphertext(cellIDFPHex string) ([]byte, error) {
	s.mu.RLock()
	v, ok := s.labels[cellIDFPHex]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrLabelNotFound
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("trust label store: nonce: %w", err)
	}
	out := s.gcm.Seal(nil, nonce, []byte(v), []byte(cellIDFPHex))
	return append(nonce, out...), nil
}

// LoadCiphertext decrypts and stores a label loaded from disk
// under cellIDFPHex. Used by the V008 migration restore path.
func (s *MemoryLabelStore) LoadCiphertext(cellIDFPHex string, ciphertext []byte) error {
	if len(ciphertext) < s.gcm.NonceSize()+s.gcm.Overhead() {
		return errors.New("trust label store: ciphertext too short")
	}
	nonce := ciphertext[:s.gcm.NonceSize()]
	body := ciphertext[s.gcm.NonceSize():]
	plain, err := s.gcm.Open(nil, nonce, body, []byte(cellIDFPHex))
	if err != nil {
		return fmt.Errorf("trust label store: AES-GCM open: %w", err)
	}
	s.mu.Lock()
	s.labels[cellIDFPHex] = string(plain)
	s.mu.Unlock()
	return nil
}
