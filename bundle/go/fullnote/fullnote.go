// Package fullnote seals and opens the FULL update note
// (specs/update-ladder-v2.md §4.4; docs/update-ladder-v2.md §3.3):
//
//	sealed = nonce(24) ‖ XChaCha20-Poly1305(key(c, e), nonce, pad(container), aad = "")
//
// with key(c, e) = bundle.NoteKey, the padding bundle.PadFullNote
// (uint32be length ‖ container ‖ zeros to 4, 16 or 64 KiB) and a fresh
// random nonce per seal.
//
// It is its own package, not part of daal/bundle-go/bundle, because it
// needs golang.org/x/crypto (already in this module's graph through
// filippo.io/age), and modules that import only package bundle (the
// end-to-end rig's driver) do not carry x/crypto in their go.sum.
//
// THE SEAL ADDS SECRECY, NEVER TRUST. What Open returns is a
// daal-refresh-v2 container to be parsed with its slot set to
// bundle.NoteName(u, c, e) and verified exactly as a container from any
// mirror: signature chain, sequence high-water mark, not_after, pack hash.
package fullnote

import (
	"errors"
	"fmt"
	"io"
	"time"

	"daal/bundle-go/bundle"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrOpen: no held secret at any reader epoch opens the note (filler,
// another relay's note, a corrupted or planted value). "Nothing new".
var ErrOpen = errors.New("fullnote: no held secret opens this note")

// Seal is the full note of container for carrier c at epoch e under the
// audience secret u. rnd supplies the nonce (crypto/rand.Reader).
func Seal(u [bundle.UpdateSecretLen]byte, c string, e uint64, container []byte, rnd io.Reader) ([]byte, error) {
	key, err := bundle.NoteKey(u, c, e)
	if err != nil {
		return nil, err
	}
	defer zero(key[:])
	plain, err := bundle.PadFullNote(container)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, bundle.FullNoteNonceLen, bundle.FullNoteNonceLen+len(plain)+bundle.FullNoteTagLen)
	if _, err := io.ReadFull(rnd, out); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[:bundle.FullNoteNonceLen], plain, nil), nil
}

// OpenWith opens a sealed note with key(c, e) of one secret, at one
// epoch: the container, or ErrOpen.
func OpenWith(u [bundle.UpdateSecretLen]byte, c string, e uint64, sealed []byte) ([]byte, error) {
	if !bundle.FullNoteSealedLenOK(len(sealed)) {
		return nil, fmt.Errorf("%w: not a sealed note's size", bundle.ErrNoteMalformed)
	}
	key, err := bundle.NoteKey(u, c, e)
	if err != nil {
		return nil, err
	}
	defer zero(key[:])
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, sealed[:bundle.FullNoteNonceLen], sealed[bundle.FullNoteNonceLen:], nil)
	if err != nil {
		return nil, ErrOpen
	}
	return bundle.UnpadFullNote(plain)
}

// Opened is what Open found.
type Opened struct {
	Container []byte               // the daal-refresh-v2 container bytes
	Slot      string               // bundle.NoteName(u, c, e): the slot the container must name
	Epoch     uint64               // the epoch that opened it
	Secret    *bundle.UpdateSecret // the held secret that opened it
}

// Open tries each held secret (newest first) at each reader epoch of c
// at now (bundle.NoteReaderEpochs) and returns the first that opens the
// note. ErrOpen when none does; bundle.ErrNoteMalformed when the bytes
// are not a sealed note's size.
func Open(c string, now time.Time, sealed []byte, secrets []*bundle.UpdateSecret) (*Opened, error) {
	if !bundle.FullNoteSealedLenOK(len(sealed)) {
		return nil, fmt.Errorf("%w: not a sealed note's size", bundle.ErrNoteMalformed)
	}
	for _, u := range secrets {
		if u == nil {
			continue
		}
		for _, e := range bundle.NoteReaderEpochs(c, now) {
			got, err := OpenWith(u.Secret, c, e, sealed)
			if err != nil {
				continue
			}
			slot, err := bundle.NoteName(u.Secret, c, e)
			if err != nil {
				continue
			}
			return &Opened{Container: got, Slot: slot, Epoch: e, Secret: u}, nil
		}
	}
	return nil, ErrOpen
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
