package publisher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoNetworkCallSites grep-asserts that the publisher package and
// daal-publish CLI never reference network call sites.
func TestNoNetworkCallSites(t *testing.T) {
	roots := []string{
		filepath.Join("..", "publisher"),
		filepath.Join("..", "cmd", "daal-publish"),
	}
	forbidden := []string{
		"net.Dial",
		"http.Get",
		"http.Post",
		"http.Client",
		"http.NewRequest",
		"net/http",
	}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, bad := range forbidden {
				if strings.Contains(string(body), bad) {
					t.Fatalf("%s contains forbidden network call site %q", path, bad)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestPrivateKeyBytesNeverInErrors ensures that a forced bad-length private
// key file produces an error message that does not leak any byte from the
// file.
func TestPrivateKeyBytesNeverInErrors(t *testing.T) {
	tmp := t.TempDir()
	bad := []byte{0xde, 0xad, 0xbe, 0xef, 0xfe}
	path := filepath.Join(tmp, "bad.priv")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPriv(path)
	if err == nil {
		t.Fatal("expected error on bad-length key")
	}
	for _, b := range bad {
		if strings.ContainsRune(err.Error(), rune(b)) {
			t.Fatalf("error message contains a private byte: %q", err.Error())
		}
	}
}
