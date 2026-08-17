// directory_rotation.go gives the pointer-rotation envelope the two
// callers it has never had, and gives core/refresh the archive reader
// it needs for the signed mirror set.
//
// WHY THIS MATTERS FOR STEP 8. The freshness path is N endpoints
// inside a signed pack. When all N are blocked, nothing inside that
// pack can help: replacing the endpoint set requires a channel that
// does not depend on the endpoint set. The bootstrap pointers are that
// channel — a project-root-signed list of directory URLs, embedded in
// the build, and themselves replaceable at runtime by a
// project-root-signed rotation envelope. A directory fetched through
// them carries routes, and those routes carry a freshness slot, so the
// pointer layer is how a recipient learns about endpoints its pack
// never mentioned.
//
// The envelope rides INSIDE the directory .sbp, at the archive path
// named by `manifest.bundle.pointer_rotation_ref.path`. It is not
// covered by the manifest signature and does not need to be: every
// PointerSet inside it carries its own project-root signature, which
// VerifyPointerRotation checks, and PersistPointerRotation refuses
// anything that does not extend the validity window it already has. A
// tampered envelope is therefore a silent no-op rather than a
// downgrade — which is why extracting it from an unsigned archive slot
// is safe, and why extracting it from a slot whose PATH comes out of
// the same untrusted archive still needs the path itself to be
// sanitised before use.

package bootstrap

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/routestore"
)

// maxArchiveEntryBytes bounds any single entry we read out of an .sbp
// by hand. Both callers read small JSON documents; a multi-megabyte
// entry at these paths is either corruption or an attempt to make a
// phone allocate.
const maxArchiveEntryBytes = 256 * 1024

// ArchiveEntry reads one named entry out of an .sbp (a zip) without
// going through the bundle parser, which surfaces only the entries it
// knows about. Returns false when the archive is unreadable or the
// entry is absent.
//
// Exported because core/refresh needs the same primitive for
// trust/freshness-mirrors.json, and duplicating a zip reader per
// package is how two subtly different path-sanitising rules end up in
// one binary.
func ArchiveEntry(body []byte, name string) ([]byte, bool) {
	if !safeArchivePath(name) {
		return nil, false
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, false
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, false
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, maxArchiveEntryBytes+1))
		_ = rc.Close()
		if readErr != nil || len(data) > maxArchiveEntryBytes {
			return nil, false
		}
		return data, true
	}
	return nil, false
}

// safeArchivePath refuses traversal, absolute paths and anything
// outside the trust/ prefix. The path we act on is read out of the
// same archive we do not trust, so it is input, not configuration.
func safeArchivePath(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	if !strings.HasPrefix(name, "trust/") {
		return false
	}
	return len(name) > len("trust/")
}

// ExtractPointerRotation pulls the rotation envelope out of a
// directory .sbp, following the manifest's pointer_rotation_ref. It
// performs NO signature checking — that is
// VerifyPointerRotation/PersistPointerRotation's job, and keeping the
// two apart means the verification cannot be accidentally skipped by a
// caller that already "parsed" the envelope.
func ExtractPointerRotation(body []byte, m bundle.Manifest) (PointerRotation, bool) {
	if m.Bundle.PointerRotation == nil {
		return PointerRotation{}, false
	}
	raw, ok := ArchiveEntry(body, m.Bundle.PointerRotation.Path)
	if !ok {
		return PointerRotation{}, false
	}
	var rot PointerRotation
	if err := json.Unmarshal(raw, &rot); err != nil {
		return PointerRotation{}, false
	}
	return rot, true
}

// ApplyDirectoryPointerRotation extracts, verifies and persists the
// rotation envelope carried by a fetched directory bundle. Returns
// true when the persisted pointer set actually changed.
//
// Errors from the persist step are returned but are never fatal to the
// directory refresh that produced them: a device that fetched a
// directory successfully has already improved its position, and losing
// the (opportunistic) pointer upgrade must not undo that.
func ApplyDirectoryPointerRotation(store *routestore.Store, body []byte,
	m bundle.Manifest, embedded *Manifest, now time.Time) (bool, error) {

	if store == nil || embedded == nil || len(embedded.ProjectRootPub) == 0 {
		return false, errors.New("pointer_rotation: missing store, manifest or root key")
	}
	rot, ok := ExtractPointerRotation(body, m)
	if !ok {
		return false, nil
	}
	return PersistPointerRotation(store, rot, embedded.ProjectRootPub, embedded, now)
}
