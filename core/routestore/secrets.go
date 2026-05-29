package routestore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// PutSecret stores plaintext under key, encrypted with the store's age
// identity. The plaintext is overwritten in memory once encryption returns.
func (s *Store) PutSecret(key string, plaintext []byte) error {
	if s.db == nil {
		return errors.New("routestore: closed")
	}
	id, err := identityFromKey(s.key)
	if err != nil {
		return err
	}
	recip := id.Recipient()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recip)
	if err != nil {
		return err
	}
	if _, err := w.Write(plaintext); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	zero(plaintext)
	_, err = s.db.Exec(`INSERT INTO secrets_kv (k, v) VALUES (?, ?)
ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, buf.Bytes())
	return err
}

// GetSecret returns the decrypted bytes under key, or error.
func (s *Store) GetSecret(key string) ([]byte, error) {
	if s.db == nil {
		return nil, errors.New("routestore: closed")
	}
	row := s.db.QueryRow(`SELECT v FROM secrets_kv WHERE k = ?`, key)
	var ct []byte
	if err := row.Scan(&ct); err != nil {
		return nil, err
	}
	id, err := identityFromKey(s.key)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		return nil, fmt.Errorf("routestore: decrypt: %w", err)
	}
	return io.ReadAll(r)
}

// DeleteSecret removes a secret by key.
func (s *Store) DeleteSecret(key string) error {
	_, err := s.db.Exec(`DELETE FROM secrets_kv WHERE k = ?`, key)
	return err
}

// ListSecretKeys returns the secret-KV keys whose name starts with
// prefix, sorted lexicographically. Used by per-network memory
// (Phase 2C) to enumerate the namespace it owns. The KEYS are
// returned, not the (encrypted) values; nothing is decrypted.
func (s *Store) ListSecretKeys(prefix string) ([]string, error) {
	if s.db == nil {
		return nil, errors.New("routestore: closed")
	}
	rows, err := s.db.Query(
		`SELECT k FROM secrets_kv WHERE k LIKE ? ORDER BY k ASC`,
		prefix+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// loadOrCreateKey reads or creates the age X25519 identity used to encrypt
// the secrets KV. The on-disk file is mode 0600.
func loadOrCreateKey(path string) ([]byte, error) {
	if body, err := os.ReadFile(path); err == nil {
		// Validate by parsing.
		if _, perr := age.ParseX25519Identity(string(bytes.TrimSpace(body))); perr != nil {
			return nil, fmt.Errorf("routestore: secrets key invalid")
		}
		return body, nil
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("routestore: generate key: %w", err)
	}
	body := []byte(id.String() + "\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return body, nil
}

func identityFromKey(b []byte) (*age.X25519Identity, error) {
	if len(b) == 0 {
		return nil, errors.New("routestore: closed")
	}
	return age.ParseX25519Identity(string(bytes.TrimSpace(b)))
}
