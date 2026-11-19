package routestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var recoverNow = time.Date(2026, 11, 19, 10, 37, 12, 0, time.UTC)

func damagedFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), damagedInfix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// A file that is not a database at all.
func TestOpenOrRecover_GarbageFileIsSetAsideNotDeleted(t *testing.T) {
	dir := t.TempDir()
	garbage := bytes.Repeat([]byte("this is not a database. "), 400)
	dbPath := filepath.Join(dir, "daal.db")
	if err := os.WriteFile(dbPath, garbage, 0o600); err != nil {
		t.Fatal(err)
	}

	// Plain Open refuses, says why in a way a caller can test, and
	// touches nothing.
	if _, err := Open(dir); !errors.Is(err, ErrDamaged) {
		t.Fatalf("Open on a garbage file: err = %v, want ErrDamaged", err)
	}
	if got, _ := os.ReadFile(dbPath); !bytes.Equal(got, garbage) {
		t.Fatal("Open modified the damaged file")
	}
	if n := damagedFiles(t, dir); len(n) != 0 {
		t.Fatalf("Open set files aside by itself: %v", n)
	}

	s, aside, err := OpenOrRecover(dir, recoverNow)
	if err != nil {
		t.Fatalf("OpenOrRecover: %v", err)
	}
	defer s.Close()
	want := dbPath + ".damaged-20261119T10Z"
	if len(aside) != 1 || aside[0] != want {
		t.Fatalf("set aside %v, want [%s]", aside, want)
	}
	if got, err := os.ReadFile(want); err != nil || !bytes.Equal(got, garbage) {
		t.Fatalf("the set-aside file does not hold the original bytes (err %v)", err)
	}
	if !s.RecoveryPending() {
		t.Fatal("RecoveryPending is false right after a recovery")
	}
	// The new store is empty and works.
	rows, err := s.ListRoutes()
	if err != nil || len(rows) != 0 {
		t.Fatalf("new store: %d routes, err %v", len(rows), err)
	}
	seedRoutes(t, s, 1)
	if _, err := s.GetRoute("r1"); err != nil {
		t.Fatalf("new store is not usable: %v", err)
	}

	// The marker survives a restart and goes when acknowledged; the
	// set-aside file stays either way.
	s.Close()
	s2, aside2, err := OpenOrRecover(dir, recoverNow)
	if err != nil || len(aside2) != 0 {
		t.Fatalf("reopen after recovery: aside %v err %v", aside2, err)
	}
	defer s2.Close()
	if !s2.RecoveryPending() {
		t.Fatal("RecoveryPending did not survive a restart")
	}
	s2.ClearRecoveryPending()
	if s2.RecoveryPending() {
		t.Fatal("ClearRecoveryPending left the marker")
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("the set-aside file is gone: %v", err)
	}
	if _, err := s2.GetRoute("r1"); err != nil {
		t.Fatalf("route imported after the recovery was lost on reopen: %v", err)
	}
}

// A real database with ONE table's root page overwritten: the header
// and the schema are intact, so the file opens and the schema applies —
// and every read of that table would fail for the life of the install.
// Only the integrity check at open finds it.
func TestOpenOrRecover_CorruptTablePageIsDamage(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedRoutes(t, s, 40)
	var root, pageSize int
	if err := s.db.QueryRow(`SELECT rootpage FROM sqlite_master WHERE type='table' AND name='routes'`).Scan(&root); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if root < 2 {
		t.Fatalf("routes root page = %d", root)
	}
	dbPath := filepath.Join(dir, "daal.db")
	body, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	off := (root - 1) * pageSize
	if off+pageSize > len(body) {
		t.Fatalf("page %d is outside the %d-byte file", root, len(body))
	}
	for i := off; i < off+pageSize; i++ {
		body[i] = 0xA5
	}
	if err := os.WriteFile(dbPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); !errors.Is(err, ErrDamaged) {
		t.Fatalf("Open with a wrecked table page: err = %v, want ErrDamaged", err)
	}
	s, aside, err := OpenOrRecover(dir, recoverNow)
	if err != nil {
		t.Fatalf("OpenOrRecover: %v", err)
	}
	defer s.Close()
	if len(aside) == 0 {
		t.Fatal("nothing was set aside")
	}
	if got, _ := os.ReadFile(aside[0]); !bytes.Equal(got, body) {
		t.Fatal("the set-aside file does not hold the damaged bytes")
	}
	if rows, err := s.ListRoutes(); err != nil || len(rows) != 0 {
		t.Fatalf("new store: %d routes, err %v", len(rows), err)
	}
}

// A healthy store is opened as it is: nothing renamed, nothing lost,
// no marker.
func TestOpenOrRecover_HealthyStoreIsUntouched(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedRoutes(t, s, 3)
	s.Close()
	before, _ := os.ReadFile(filepath.Join(dir, "daal.db"))

	s, aside, err := OpenOrRecover(dir, recoverNow)
	if err != nil {
		t.Fatalf("OpenOrRecover: %v", err)
	}
	if len(aside) != 0 || len(damagedFiles(t, dir)) != 0 {
		t.Fatalf("a healthy store was set aside: %v / %v", aside, damagedFiles(t, dir))
	}
	if s.RecoveryPending() {
		t.Fatal("RecoveryPending on a healthy store")
	}
	rows, err := s.ListRoutes()
	if err != nil || len(rows) != 3 {
		t.Fatalf("healthy store lost routes: %d, err %v", len(rows), err)
	}
	if _, err := s.GetSecret("route:r2"); err != nil {
		t.Fatalf("healthy store lost a profile: %v", err)
	}
	s.Close()
	after, _ := os.ReadFile(filepath.Join(dir, "daal.db"))
	if !bytes.Equal(before, after) {
		t.Fatal("opening a healthy store rewrote the database file")
	}
}

// An error that is not about the file's contents is NOT damage: the
// file stays where it is and the error is returned.
func TestOpenOrRecover_OrdinaryErrorsAreNotDamage(t *testing.T) {
	t.Run("cannot open", func(t *testing.T) {
		dir := t.TempDir()
		// A directory where the database file should be: SQLite cannot
		// open it. Nothing about that says "damaged database".
		if err := os.Mkdir(filepath.Join(dir, "daal.db"), 0o700); err != nil {
			t.Fatal(err)
		}
		s, aside, err := OpenOrRecover(dir, recoverNow)
		if err == nil {
			s.Close()
			t.Fatal("OpenOrRecover succeeded on an unopenable path")
		}
		if errors.Is(err, ErrDamaged) {
			t.Fatalf("an open failure was classed as damage: %v", err)
		}
		if len(aside) != 0 || len(damagedFiles(t, dir)) != 0 {
			t.Fatalf("files were set aside for an open failure: %v", aside)
		}
	})
	t.Run("no permission", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file modes")
		}
		dir := t.TempDir()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		seedRoutes(t, s, 1)
		s.Close()
		dbPath := filepath.Join(dir, "daal.db")
		if err := os.Chmod(dbPath, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dbPath, 0o600)
		s, aside, err := OpenOrRecover(dir, recoverNow)
		if err == nil {
			s.Close()
			t.Fatal("OpenOrRecover succeeded on an unreadable file")
		}
		if errors.Is(err, ErrDamaged) {
			t.Fatalf("a permission error was classed as damage: %v", err)
		}
		if len(aside) != 0 || len(damagedFiles(t, dir)) != 0 {
			t.Fatalf("a healthy but unreadable database was set aside: %v", aside)
		}
	})
	t.Run("invalid secrets key", func(t *testing.T) {
		dir := t.TempDir()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		if err := os.WriteFile(filepath.Join(dir, "secrets.key"), []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, aside, err := OpenOrRecover(dir, recoverNow)
		if err == nil || errors.Is(err, ErrDamaged) {
			t.Fatalf("a bad key: err = %v, want an ordinary error", err)
		}
		if len(aside) != 0 || len(damagedFiles(t, dir)) != 0 {
			t.Fatal("the database was set aside because of the key")
		}
	})
}

// Two recoveries in the same hour keep both files, and a leftover
// journal does not stay beside the new database.
func TestOpenOrRecover_NeverOverwritesAnEarlierSetAside(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "daal.db")
	for i, content := range []string{"first garbage first garbage", "second garbage second garbage"} {
		if err := os.WriteFile(dbPath, bytes.Repeat([]byte(content), 100), 0o600); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if err := os.WriteFile(dbPath+"-journal", []byte("stale journal"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		s, _, err := OpenOrRecover(dir, recoverNow)
		if err != nil {
			t.Fatalf("recovery %d: %v", i+1, err)
		}
		s.Close()
	}
	first, err1 := os.ReadFile(dbPath + ".damaged-20261119T10Z")
	second, err2 := os.ReadFile(dbPath + ".damaged-20261119T10Z.1")
	if err1 != nil || err2 != nil {
		t.Fatalf("set-aside files: %v / %v (have %v)", err1, err2, damagedFiles(t, dir))
	}
	if !bytes.HasPrefix(first, []byte("first")) || !bytes.HasPrefix(second, []byte("second")) {
		t.Fatal("a later recovery overwrote an earlier set-aside file")
	}
	// The stale journal must not sit beside the NEW database, where it
	// could be replayed into it. (SQLite discards a journal it cannot
	// use while it examines the damaged file; if it had survived that,
	// it would have been set aside with the database.)
	if j, err := os.ReadFile(dbPath + "-journal"); err == nil && string(j) == "stale journal" {
		t.Fatal("the stale journal was left beside the new database")
	}
}

// The panic wipe removes set-aside files too: they hold what the store
// held.
func TestPanicWipeRemovesSetAsideDatabases(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "daal.db"), bytes.Repeat([]byte("garbage "), 200), 0o600); err != nil {
		t.Fatal(err)
	}
	s, aside, err := OpenOrRecover(dir, recoverNow)
	if err != nil || len(aside) != 1 {
		t.Fatalf("OpenOrRecover: aside %v err %v", aside, err)
	}
	if err := s.PanicWipe(); err != nil {
		t.Fatalf("PanicWipe: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("left behind after a panic wipe: %s", e.Name())
	}
}
